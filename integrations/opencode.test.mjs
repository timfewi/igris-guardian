import assert from "node:assert/strict"
import { readFile } from "node:fs/promises"
import test from "node:test"

const source = await readFile(new URL("./opencode.js", import.meta.url), "utf8")
const { Igris } = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`)
const after = (await Igris())["tool.execute.after"]
const input = { tool: "read" }
const output = { title: "file", output: "ordinary tool output long enough to scan", metadata: {} }

test("OpenCode adapter preserves output and fails closed", async () => {
  for (const action of ["pass", "warn"]) {
    globalThis.fetch = async () => ({
      ok: true,
      json: async () => ({ action, score: action === "warn" ? 50 : 0, reasons: [] }),
    })
    const before = structuredClone(output)
    await after(input, output)
    assert.deepEqual(output, before)
  }

  globalThis.fetch = async () => ({
    ok: true,
    json: async () => ({ action: "block", score: 100, reasons: ["injection"] }),
  })
  await assert.rejects(after(input, output), /Igris blocked/)

  globalThis.fetch = async () => ({ ok: true, json: async () => ({ nope: true }) })
  await assert.rejects(after(input, output), /malformed verdict/)

  globalThis.fetch = async () => {
    throw new Error("offline")
  }
  await assert.rejects(after(input, output), /scan unavailable/)
})
