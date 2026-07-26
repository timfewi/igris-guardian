export const Igris = async () => ({
  "tool.execute.after": async (input, output) => {
    if (!output.output || output.output.length < 20) return

    const headers = { "content-type": "application/json" }
    if (process.env.IGRIS_AUTH_TOKEN) {
      headers.authorization = `Bearer ${process.env.IGRIS_AUTH_TOKEN}`
    }

    let response
    try {
      response = await fetch(
        `${(process.env.IGRIS_URL || "http://127.0.0.1:8787").replace(/\/$/, "")}/scan`,
        {
          method: "POST",
          headers,
          body: JSON.stringify({
            text: output.output,
            source: `opencode:${input.tool}`,
          }),
        },
      )
    } catch {
      throw new Error("Igris scan unavailable")
    }

    if (!response.ok) throw new Error(`Igris scan failed (${response.status})`)
    const verdict = await response.json().catch(() => null)
    if (!["pass", "warn", "block"].includes(verdict?.action)) {
      throw new Error("Igris returned a malformed verdict")
    }
    if (verdict.action === "block") {
      throw new Error(
        `Igris blocked tool output (score ${verdict.score}): ${(verdict.reasons || []).join(", ")}`,
      )
    }
  },
})
