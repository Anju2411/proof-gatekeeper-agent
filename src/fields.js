// Mapping from task-envelope values to BN254 field elements for the
// gatekeeper circuit (PROTOCOL.md §9). All circuit inputs are single field
// elements; snarkjs receives them as decimal strings.
//
// CONFIRMED by the spec: minimum / public_balance / amount / max_transfer are
// decimal strings used as-is; expiry_block / current_block are numbers;
// recipient / condition_recipient are addresses used as their integer value;
// decision is 1 = APPROVE, 0 = REJECT.
//
// UNCONFIRMED (§16.2 / §16.3) — the two functions below are the spec's best
// determination, isolated here so practice mode can pin the real mapping with
// a one-function change:
//   * vkHashToField: a VK is a 0x-hex 256-bit value; the circuit needs one
//     field element, so we reduce mod p. If the platform already emits
//     field-sized hashes the reduction is the identity.
//   * taskIdToField: task_id is a string like "gk_8d31_..."; no derivation is
//     documented. We accept 0x-hex / decimal verbatim, else use the hex
//     suffix after the last "_", else SHA-256 of the string — all mod p.

export const BN254_P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export function modP(x) {
  const r = x % BN254_P;
  return r >= 0n ? r : r + BN254_P;
}

/** 0x-hex (or bare hex) string -> field element (mod p). */
export function hexToField(hex) {
  if (typeof hex !== "string") throw new Error(`expected hex string, got ${typeof hex}`);
  const s = hex.trim().toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]+$/.test(s)) throw new Error(`invalid hex value: ${hex}`);
  return modP(BigInt("0x" + s));
}

/** VK hash from the envelope -> circuit field element. See header (§16.3). */
export function vkHashToField(vk) {
  return hexToField(vk);
}

/** Ethereum address -> field element (160-bit value, always < p). */
export function addressToField(address) {
  return hexToField(address);
}

/** Decimal string (or number) from the envelope -> field element. */
export function decimalToField(value) {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`invalid integer field value: ${value}`);
    }
    return BigInt(value);
  }
  if (typeof value !== "string" || !/^\d+$/.test(value.trim())) {
    throw new Error(`invalid decimal field value: ${value}`);
  }
  return modP(BigInt(value.trim()));
}

/** Block height (number in the envelope) -> field element. */
export function blockToField(value) {
  return decimalToField(value);
}

/**
 * task_id string -> circuit field element. UNCONFIRMED mapping (§16.2) —
 * see header. Async only because of the SHA-256 fallback.
 */
export async function taskIdToField(taskId) {
  const s = String(taskId).trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return modP(BigInt(s));
  if (/^\d+$/.test(s)) return modP(BigInt(s));
  const suffix = s.split("_").pop();
  if (/^[0-9a-fA-F]+$/.test(suffix) && /\d/.test(suffix)) {
    return modP(BigInt("0x" + suffix));
  }
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(s),
  );
  let v = 0n;
  for (const b of new Uint8Array(digest)) v = (v << 8n) | BigInt(b);
  return modP(v);
}

/** Random field element for the circuit's private `salt` input. */
export function randomSalt() {
  const bytes = new Uint8Array(31); // 248 bits — always < p
  crypto.getRandomValues(bytes);
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

/**
 * Map a parsed Gatekeeper task envelope to circuit field values.
 * Returns BigInt field elements keyed by circuit input name (minus
 * decision/salt, which the caller supplies).
 */
export async function mapTaskInput(envelope) {
  const input = envelope.input;
  if (!input || typeof input !== "object") {
    throw new Error("task envelope is missing `input`");
  }
  return {
    registeredVkHash: vkHashToField(input.registered_vk),
    proofVkHash: vkHashToField(input.proof_vk),
    minimum: decimalToField(input.minimum),
    publicBalance: decimalToField(input.public_balance),
    expiryBlock: blockToField(input.expiry_block),
    currentBlock: blockToField(input.current_block),
    recipient: addressToField(input.recipient),
    conditionRecipient: addressToField(input.condition_recipient),
    amount: decimalToField(input.amount),
    maxTransfer: decimalToField(input.max_transfer),
    taskId: await taskIdToField(envelope.task_id),
  };
}

/** Build the snarkjs input object (decimal strings) for one prove call. */
export function buildCircuitInput(mapped, decisionBit, salt) {
  return {
    registeredVkHash: mapped.registeredVkHash.toString(),
    proofVkHash: mapped.proofVkHash.toString(),
    minimum: mapped.minimum.toString(),
    publicBalance: mapped.publicBalance.toString(),
    expiryBlock: mapped.expiryBlock.toString(),
    currentBlock: mapped.currentBlock.toString(),
    recipient: mapped.recipient.toString(),
    conditionRecipient: mapped.conditionRecipient.toString(),
    amount: mapped.amount.toString(),
    maxTransfer: mapped.maxTransfer.toString(),
    decision: String(decisionBit),
    taskId: mapped.taskId.toString(),
    salt: salt.toString(),
  };
}
