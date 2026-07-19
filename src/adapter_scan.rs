//! `igris scan [TEXT]` — stdin/arg → one-line JSON verdict. PHASE-1C.
//! Exit 0 pass/warn, exit 2 block. FailMode::Close.

use crate::config::Config;
use crate::engine::Engine;
use crate::{Action, FailMode, Trust};
use std::io::Read;

pub async fn run(cfg: Config, text_arg: Option<String>, trust: Trust) -> i32 {
    // Read text from arg or stdin.
    let text = if let Some(arg) = text_arg {
        arg
    } else {
        let mut buf = String::new();
        if std::io::stdin().read_to_string(&mut buf).is_err() {
            eprintln!("igris: error reading stdin");
            return 2;
        }
        buf
    };

    let engine = Engine::new(cfg);
    let verdict = engine
        .scan_trusted(&text, "stdin", trust, FailMode::Close)
        .await;

    // Print JSON verdict.
    if let Ok(json) = serde_json::to_string(&verdict) {
        println!("{}", json);
    } else {
        eprintln!("igris: error serializing verdict");
        return 2;
    }

    // Exit code: 2 if Block, else 0.
    match verdict.action {
        Action::Block => 2,
        _ => 0,
    }
}
