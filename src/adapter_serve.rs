//! `igris serve` — filtering reverse proxy. PHASE-2B.
//!
//! hyper server → reqwest upstream. Scans the last inbound message and the
//! buffered outbound response (incl. SSE, replayed byte-identical on pass).
//! Block → provider-shaped error. FailMode::Close. Forwards auth headers verbatim;
//! igris never holds the upstream key.

use crate::config::Config;
use crate::engine::Engine;
use crate::{Action, FailMode, Trust};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{self, HeaderName};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::convert::Infallible;
use std::fs::OpenOptions;
use std::sync::Arc;
use tokio::net::TcpListener;

pub async fn run(cfg: Config) -> i32 {
    let listen = cfg.serve.listen.clone();
    let listener = match TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("igris: serve: bind {listen}: {e}");
            return 1;
        }
    };
    serve(listener, cfg).await;
    0
}

/// Accept loop over an already-bound listener. Split out from [`run`] so tests
/// can bind an ephemeral port themselves (`TcpListener::bind("127.0.0.1:0")`)
/// and read back the real address instead of racing a port number.
pub async fn serve(listener: TcpListener, cfg: Config) {
    let engine = Arc::new(Engine::new(cfg));
    let client = reqwest::Client::new();
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let io = TokioIo::new(stream);
        let engine = engine.clone();
        let client = client.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| handle(req, engine.clone(), client.clone()));
            let _ = http1::Builder::new().serve_connection(io, svc).await;
        });
    }
}

async fn handle(
    req: Request<Incoming>,
    engine: Arc<Engine>,
    client: reqwest::Client,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let cfg = engine.config();

    // Readiness must remain reachable when client auth itself is misconfigured,
    // otherwise an orchestrator only sees the auth guard's generic 503.
    if req.method() == Method::GET && req.uri().path() == "/ready" {
        return Ok(readiness_response(cfg));
    }

    if !cfg.serve.auth_token_env.is_empty() {
        let expected = std::env::var(&cfg.serve.auth_token_env).unwrap_or_default();
        // Misconfig guard: auth is configured but the token is empty/unset. Fail
        // closed — never accept an empty "Bearer " that a caller could guess.
        if expected.is_empty() {
            return Ok(json_response(
                503,
                json!({"error": "auth misconfigured: token env is empty"}),
            ));
        }
        let got = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !constant_time_eq(got.as_bytes(), format!("Bearer {expected}").as_bytes()) {
            return Ok(json_response(401, json!({"error": "unauthorized"})));
        }
    }

    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return Ok(json_response(400, json!({"error": "bad request body"}))),
    };

    let path = parts.uri.path().to_string();
    let is_post = parts.method == Method::POST;

    // Direct classification, for callers that are not proxying an LLM API at all:
    // any harness can POST text here and act on the verdict itself, instead of
    // spawning `igris scan` per item. Intercepted before forwarding so it is never
    // mistaken for an upstream route.
    if is_post && path == "/scan" {
        return Ok(scan_endpoint(&engine, &body_bytes).await);
    }
    if parts.method == Method::GET && path == "/health" {
        return Ok(json_response(
            200,
            json!({"status": "ok", "version": env!("CARGO_PKG_VERSION")}),
        ));
    }

    let is_messages_route = is_post && path == "/v1/messages";
    let is_chat_route = is_post && path.ends_with("/chat/completions");
    // Legacy generation routes (Anthropic /v1/complete, OpenAI /v1/completions)
    // must be scanned too — otherwise a client pointed at a legacy endpoint
    // bypasses the firewall entirely.
    let is_legacy_route =
        is_post && (path == "/v1/complete" || path.ends_with("/completions")) && !is_chat_route;
    let is_special = is_messages_route || is_chat_route || is_legacy_route;
    // Response shape follows the request family (Anthropic vs OpenAI).
    let anthropic_shape = is_messages_route || path == "/v1/complete";

    if is_special {
        let text = serde_json::from_slice::<Value>(&body_bytes)
            .map(|v| extract_inbound_text(&v))
            .unwrap_or_default();
        let verdict = engine.scan(&text, "serve:inbound", FailMode::Close).await;
        if verdict.action == Action::Block {
            return Ok(json_response(
                403,
                provider_error_body(anthropic_shape, "request blocked by igris guardian"),
            ));
        }
    }

    // Forward to upstream, stripping hop-by-hop headers. authorization/x-api-key
    // pass through untouched here — igris never inspects or stores them.
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let target = format!(
        "{}{}",
        cfg.serve.upstream.trim_end_matches('/'),
        path_and_query
    );

    let mut rb = client.request(parts.method.clone(), &target);
    for (name, value) in parts.headers.iter() {
        if is_hop_by_hop(name) || name == header::HOST {
            continue;
        }
        rb = rb.header(name, value);
    }
    rb = rb.body(body_bytes);

    let upstream_resp = match rb.send().await {
        Ok(r) => r,
        Err(_) => return Ok(json_response(502, json!({"error": "upstream unreachable"}))),
    };

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let content_type = resp_headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let resp_bytes = match upstream_resp.bytes().await {
        Ok(b) => b,
        Err(_) => return Ok(json_response(502, json!({"error": "upstream read failed"}))),
    };

    if !is_special {
        // Transparent passthrough: no shape known to scan, forward verbatim.
        return Ok(build_response(status, &resp_headers, resp_bytes));
    }

    if resp_bytes.len() > cfg.max_scan_bytes {
        return Ok(json_response(
            502,
            provider_error_body(anthropic_shape, "response too large to scan"),
        ));
    }

    let text = if content_type.contains("text/event-stream") {
        extract_sse_text(&resp_bytes, anthropic_shape)
    } else {
        serde_json::from_slice::<Value>(&resp_bytes)
            .map(|v| extract_response_text(&v, anthropic_shape))
            .unwrap_or_default()
    };

    let verdict = engine.scan(&text, "serve:outbound", FailMode::Close).await;
    if verdict.action == Action::Block {
        return Ok(json_response(
            502,
            provider_error_body(anthropic_shape, "response blocked by igris guardian"),
        ));
    }

    // Pass: replay upstream bytes/status/headers byte-identical.
    Ok(build_response(status, &resp_headers, resp_bytes))
}

fn readiness_response(cfg: &Config) -> Response<Full<Bytes>> {
    let audit = OpenOptions::new()
        .create(true)
        .append(true)
        .open(cfg.audit_path());
    let auth_enabled = !cfg.serve.auth_token_env.is_empty();
    let auth_ready = !auth_enabled
        || std::env::var(&cfg.serve.auth_token_env).is_ok_and(|token| !token.is_empty());
    let ready = audit.is_ok() && auth_ready;

    let mut audit_check = json!({"ready": audit.is_ok()});
    if let Err(error) = audit {
        audit_check["reason"] = json!(error.to_string());
    }
    let mut auth_check = json!({"enabled": auth_enabled, "ready": auth_ready});
    if !auth_ready {
        auth_check["reason"] = json!("configured token environment variable is missing or empty");
    }

    json_response(
        if ready { 200 } else { 503 },
        json!({
            "status": if ready { "ready" } else { "not_ready" },
            "checks": {
                "audit_log": audit_check,
                "auth": auth_check,
                "stage2": {"enabled": cfg.stage2.enabled}
            }
        }),
    )
}

/// `POST /scan` — classify a body of text and return the verdict verbatim.
///
/// Request:  `{"text": "...", "source": "optional-label"}`
/// Response: the [`crate::Verdict`] JSON, always 200 — a verdict of "block" is a
/// successful classification, not a request error, so callers can parse one shape.
/// Over-cap bodies are rejected rather than silently truncated, matching the
/// proxy's refusal to render a verdict on text it did not fully read.
async fn scan_endpoint(engine: &Engine, body: &Bytes) -> Response<Full<Bytes>> {
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        return json_response(400, json!({"error": "body must be JSON"}));
    };
    let Some(text) = v.get("text").and_then(|t| t.as_str()) else {
        return json_response(400, json!({"error": "missing string field: text"}));
    };
    if text.len() > engine.config().max_scan_bytes {
        return json_response(413, json!({"error": "text exceeds max_scan_bytes"}));
    }
    let source = v
        .get("source")
        .and_then(|s| s.as_str())
        .unwrap_or("serve:scan");
    // Callers that can distinguish their own operator's input from retrieved
    // content should say so; defaulting to untrusted keeps the safe answer for
    // callers that cannot.
    let trust = match v.get("trust").and_then(|t| t.as_str()) {
        Some("user") => Trust::User,
        _ => Trust::Untrusted,
    };

    let verdict = engine
        .scan_trusted(text, source, trust, FailMode::Close)
        .await;
    json_response(200, serde_json::to_value(&verdict).unwrap_or_default())
}

/// Length-independent, short-circuit-free byte comparison for the bearer token.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn build_response(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
    body: Bytes,
) -> Response<Full<Bytes>> {
    let mut builder = Response::builder().status(status);
    for (name, value) in headers.iter() {
        if is_hop_by_hop(name) {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder
        .body(Full::new(body))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

fn json_response(status: u16, body: Value) -> Response<Full<Bytes>> {
    let bytes = Bytes::from(serde_json::to_vec(&body).unwrap_or_default());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(bytes))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

fn provider_error_body(is_messages_route: bool, message: &str) -> Value {
    if is_messages_route {
        json!({"type": "error", "error": {"type": "invalid_request_error", "message": message}})
    } else {
        json!({"error": {"message": message, "type": "invalid_request_error", "code": null}})
    }
}

/// Inbound scannable text. Chat/messages routes: the last message's content
/// (string, text blocks, or nested tool_result blocks). Legacy completion routes:
/// the top-level `prompt` (string or array of strings).
fn extract_inbound_text(body: &Value) -> String {
    if let Some(msgs) = body.get("messages").and_then(|m| m.as_array()) {
        if let Some(last) = msgs.last() {
            return extract_content_text(last.get("content").unwrap_or(&Value::Null));
        }
    }
    // Legacy /v1/complete (Anthropic) and /v1/completions (OpenAI): `prompt`.
    match body.get("prompt") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn extract_content_text(content: &Value) -> String {
    match content {
        Value::String(s) => s.clone(),
        Value::Array(blocks) => blocks
            .iter()
            .map(|b| {
                if let Some(t) = b.get("text").and_then(|t| t.as_str()) {
                    t.to_string()
                } else if let Some(nested) = b.get("content") {
                    extract_content_text(nested)
                } else {
                    String::new()
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// Non-stream outbound body text: Anthropic `content[].text` / OpenAI
/// `choices[].message.content`.
fn extract_response_text(v: &Value, is_messages_route: bool) -> String {
    if is_messages_route {
        // Modern: content[].text. Legacy /v1/complete: top-level `completion`.
        if let Some(c) = v.get("completion").and_then(|t| t.as_str()) {
            return c.to_string();
        }
        v.get("content")
            .and_then(|c| c.as_array())
            .map(|blocks| {
                blocks
                    .iter()
                    .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default()
    } else {
        // Modern chat: choices[].message.content. Legacy /v1/completions: choices[].text.
        v.get("choices")
            .and_then(|c| c.as_array())
            .map(|choices| {
                choices
                    .iter()
                    .filter_map(|c| {
                        c.get("message")
                            .and_then(|m| m.get("content"))
                            .and_then(|t| t.as_str())
                            .or_else(|| c.get("text").and_then(|t| t.as_str()))
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default()
    }
}

/// SSE outbound text: concatenated `content_block_delta` text deltas
/// (Anthropic) / `choices[].delta.content` (OpenAI).
fn extract_sse_text(bytes: &[u8], is_messages_route: bool) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    for line in text.lines() {
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        let data = data.trim();
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(data) else {
            continue;
        };
        if is_messages_route {
            if let Some(t) = v
                .get("delta")
                .and_then(|d| d.get("text"))
                .and_then(|t| t.as_str())
            {
                out.push_str(t);
            }
        } else if let Some(first) = v
            .get("choices")
            .and_then(|c| c.as_array())
            .and_then(|a| a.first())
        {
            // Modern chat: choices[0].delta.content. Legacy: choices[0].text.
            if let Some(t) = first
                .get("delta")
                .and_then(|d| d.get("content"))
                .and_then(|t| t.as_str())
                .or_else(|| first.get("text").and_then(|t| t.as_str()))
            {
                out.push_str(t);
            }
        }
    }
    out
}
