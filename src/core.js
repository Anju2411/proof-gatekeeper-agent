// Runtime-agnostic Gatekeeper agent core, shared by the Node server and the
// Cloudflare Worker entry. One entry point:
//
//   const agent = await createAgent({ secret, prover, store });
//   const res = await agent.handle({ method, rawBody, signature });
//   // res = { status, body /*string*/, headers /*object*/ }
//
// Protocol flow (PROTOCOL.md):
//   1. Verify x-agent-games-signature over the RAW body BEFORE parsing.
//      Bad/missing signature -> 401, fail closed, nothing is processed.
//   2. Preflight envelope -> { ok: true, protocolVersion: "v1" }, signed.
//   3. Gatekeeper task -> deterministic decision (§decide.js). Every provable
//      task gets a Groth16 proof; PROOF_REUSED is answered without one.
//      The response body is signed; proof_tx is echoed as the audit pointer.
//   4. task_id is an idempotency key: a retried delivery returns the cached
//      response bytes instead of re-deciding (its proof_tx is already in the
//      seen-set by then and must NOT be mistaken for a reuse trap).

import { importHmacKey, signBodyHex, verifyBodyHex } from "./hmac.js";
import { buildCircuitInput, mapTaskInput, randomSalt } from "./fields.js";
import { decideTask, firstCircuitTrap } from "./decide.js";

export const SIGNATURE_HEADER = "x-agent-games-signature";
const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
const PREFLIGHT_TYPE = "agent-games.preflight.v1";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export async function createAgent({ secret, secretFormat, prover, store, log } = {}) {
  if (!prover) throw new Error("createAgent needs a prover");
  if (!store) throw new Error("createAgent needs a store");
  const hmacKey = await importHmacKey(secret, secretFormat);
  const logger = log ?? ((...args) => console.log("[agent]", ...args));

  async function signedOk(bodyString) {
    const signature = await signBodyHex(hmacKey, textEncoder.encode(bodyString));
    return {
      status: 200,
      body: bodyString,
      headers: { "content-type": "application/json", [SIGNATURE_HEADER]: signature },
    };
  }

  function plain(status, obj) {
    return {
      status,
      body: JSON.stringify(obj),
      headers: { "content-type": "application/json" },
    };
  }

  async function handle({ method, rawBody, signature }) {
    if (method === "GET") {
      // Own monitoring only — the platform specifies no health endpoint (§12).
      return plain(200, { ok: true, service: "proof-gatekeeper-agent" });
    }
    if (method !== "POST") return plain(405, { ok: false, error: "method_not_allowed" });

    const bodyBytes =
      rawBody instanceof Uint8Array ? rawBody : textEncoder.encode(String(rawBody ?? ""));

    // 1. Authenticate BEFORE parsing. Fail closed on any mismatch.
    const ok = await verifyBodyHex(hmacKey, signature, bodyBytes);
    if (!ok) {
      logger("rejected request: bad or missing signature");
      return plain(401, { ok: false, error: "bad_signature" });
    }

    let envelope;
    try {
      envelope = JSON.parse(textDecoder.decode(bodyBytes));
    } catch {
      return plain(400, { ok: false, error: "invalid_json" });
    }

    // 2. Preflight handshake.
    if (envelope?.type === PREFLIGHT_TYPE) {
      return signedOk(JSON.stringify({ ok: true, protocolVersion: "v1" }));
    }

    if (envelope?.type !== TASK_TYPE) {
      return plain(400, { ok: false, error: "unknown_envelope_type" });
    }

    return handleTask(envelope);
  }

  async function handleTask(envelope) {
    const taskId = envelope.task_id;
    const proofTx = envelope?.input?.proof_tx;
    if (typeof taskId !== "string" || typeof proofTx !== "string") {
      return plain(400, { ok: false, error: "malformed_task" });
    }

    // Idempotent retry: return the original response bytes verbatim.
    const cached = await store.getResponse(taskId);
    if (cached !== undefined) {
      const signature = await signBodyHex(hmacKey, textEncoder.encode(cached));
      return {
        status: 200,
        body: cached,
        headers: { "content-type": "application/json", [SIGNATURE_HEADER]: signature },
      };
    }

    let mapped;
    try {
      mapped = await mapTaskInput(envelope);
    } catch (err) {
      logger(`task ${taskId}: field mapping failed: ${err.message}`);
      return plain(400, { ok: false, error: "malformed_task_input" });
    }

    const isReused = await store.hasSeen(proofTx);
    let outcome = decideTask(mapped, isReused);
    const response = {
      decision: outcome.decision,
      reason_code: outcome.reason_code,
      proof_tx: proofTx,
    };

    if (outcome.provable) {
      const proved = await proveWithFallback(mapped, outcome, taskId);
      if (proved) {
        response.proof = proved.proof;
        response.public_signals = proved.publicSignals;
        if (proved.flipped) {
          response.decision = "REJECT";
          response.reason_code = proved.flippedReason;
        }
      } else {
        // Proving failed outright. Fail closed: never let an unproven
        // APPROVE stand — flip to REJECT (a wrong REJECT costs -3, a wrong
        // APPROVE -6, and an unproven answer forfeits the proof bonus
        // either way). A REJECT keeps its decision and just loses the proof.
        logger(`task ${taskId}: proving failed; answering without proof`);
        if (response.decision === "APPROVE") {
          response.decision = "REJECT";
          response.reason_code = firstCircuitTrap(mapped) ?? "VK_SUBSTITUTION";
        }
      }
    }

    // Record every proof_tx in the seen-set (after deciding, so the current
    // task is never its own reuse trap) and cache the response for retries.
    await store.addSeen(proofTx);
    const bodyString = JSON.stringify(response);
    await store.putResponse(taskId, bodyString);
    return signedOk(bodyString);
  }

  /**
   * Prove the decided outcome. On failure: one retry; if an APPROVE cannot
   * be proven, ask the circuit-order re-evaluation which trap it sees and
   * prove that REJECT instead. Returns { proof, publicSignals, flipped?,
   * flippedReason? } or null when no proof could be produced at all.
   */
  async function proveWithFallback(mapped, outcome, taskId) {
    const decisionBit = outcome.decision === "APPROVE" ? 1 : 0;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const input = buildCircuitInput(mapped, decisionBit, randomSalt());
        return await prover.prove(input);
      } catch (err) {
        logger(`task ${taskId}: prove attempt ${attempt + 1} failed: ${err.message}`);
      }
    }
    if (decisionBit === 1) {
      const trap = firstCircuitTrap(mapped);
      if (trap) {
        try {
          const input = buildCircuitInput(mapped, 0, randomSalt());
          const proved = await prover.prove(input);
          return { ...proved, flipped: true, flippedReason: trap };
        } catch (err) {
          logger(`task ${taskId}: fallback REJECT prove failed: ${err.message}`);
        }
      }
    }
    return null;
  }

  return { handle };
}
