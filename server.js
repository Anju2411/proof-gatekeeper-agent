// Host entry for free Node hosting (Render/Railway/any Node PaaS) and VPS.
// Uses the IN-PROCESS SnarkjsProver — no snarkjs CLI binary needed on the
// host (measured 0.86 s/proof on a weak shared VM, 2026-11-15). The shared
// agent core is identical to the local + Worker builds.
//
// Env:
//   PORT                       listen port (the host sets this)
//   AGENT_PATH                 handler path (default /agent)
//   AGENT_GAMES_HMAC_SECRET    required — from the platform dashboard,
//                              shown once when the agent is created
//   AGENT_GAMES_HMAC_SECRET_FORMAT  optional: hex | utf8 | base64
//   SEEN_STORE_PATH            state file (default ./data/seen.json;
//                              ephemeral on free tiers — a restart only
//                              degrades PROOF_REUSED detection until the
//                              seen-set rebuilds)
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createAgent, SIGNATURE_HEADER } from "./src/core.js";
import { SnarkjsProver } from "./src/prover.js";
import { FileStore } from "./src/store.js";

const dir = dirname(fileURLToPath(import.meta.url));
const secret = process.env.AGENT_GAMES_HMAC_SECRET;
if (!secret) {
  console.error("AGENT_GAMES_HMAC_SECRET is not set — set it in the host's env settings.");
  process.exit(1);
}
const prover = new SnarkjsProver({
  wasm: readFileSync(resolve(dir, "circuits/gatekeeper.wasm")),
  zkey: readFileSync(resolve(dir, "circuits/gatekeeper_final.zkey")),
});
const store = new FileStore(process.env.SEEN_STORE_PATH || resolve(dir, "data/seen.json"));
const agent = await createAgent({
  secret,
  secretFormat: process.env.AGENT_GAMES_HMAC_SECRET_FORMAT,
  prover,
  store,
});
const agentPath = process.env.AGENT_PATH || "/agent";
const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://localhost");
    if (url.pathname !== agentPath) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "not_found" }));
      return;
    }
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const result = await agent.handle({
      method: req.method,
      rawBody: Buffer.concat(chunks),
      signature: req.headers[SIGNATURE_HEADER],
    });
    res.writeHead(result.status, result.headers);
    res.end(result.body);
  } catch (err) {
    console.error("[host] unhandled error:", err);
    res.writeHead(500, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: false, error: "internal_error" }));
  }
});
const port = Number(process.env.PORT || 8787);
server.listen(port, () => console.log(`[host] proof-gatekeeper agent on :${port}${agentPath}`));
