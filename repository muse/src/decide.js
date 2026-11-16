// Deterministic Gatekeeper decision logic (PROTOCOL.md §4).
//
// Check order is the one mandated for this build (reason-code precedence is
// not documented publicly — §16.4 — so a fixed order is chosen and kept
// stable):
//   1. proof_vk != registered_vk        -> REJECT / VK_SUBSTITUTION
//   2. public_balance < minimum         -> REJECT / THRESHOLD_MISMATCH
//   3. proof_tx already in seen-set     -> REJECT / PROOF_REUSED  (no proof)
//   4. current_block >= expiry_block    -> REJECT / EXPIRED_CONDITION
//      (the circuit treats currentBlock == expiryBlock as expired: it proves
//       currentBlock < expiryBlock for approvals — PROTOCOL.md §9)
//   5. recipient != condition_recipient -> REJECT / RECIPIENT_MISMATCH
//   6. amount > max_transfer            -> REJECT / AMOUNT_OVERFLOW
//   otherwise                           -> APPROVE / VALID_CONDITION
//
// All comparisons run on the circuit field values (BigInt) so the decision
// can never disagree with what the circuit will assert: the circuit
// recomputes exactly checks 1, 2, 4, 5, 6 (as field equalities/inequalities)
// and asserts `decision` equals its own evaluation. Check 3 (reuse) is
// agent-side state only and is excluded from proving by the rules.

export function decideTask(mapped, isReused) {
  if (mapped.proofVkHash !== mapped.registeredVkHash) {
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION", provable: true };
  }
  if (mapped.publicBalance < mapped.minimum) {
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH", provable: true };
  }
  if (isReused) {
    return { decision: "REJECT", reason_code: "PROOF_REUSED", provable: false };
  }
  if (mapped.currentBlock >= mapped.expiryBlock) {
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION", provable: true };
  }
  if (mapped.recipient !== mapped.conditionRecipient) {
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH", provable: true };
  }
  if (mapped.amount > mapped.maxTransfer) {
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW", provable: true };
  }
  return { decision: "APPROVE", reason_code: "VALID_CONDITION", provable: true };
}

/**
 * Circuit-order re-evaluation used ONLY as a proving fallback: if proving the
 * decided outcome fails (e.g. a field-mapping surprise), find the first trap
 * the circuit itself would see, in circuit-check order. Returns a reason_code
 * or null when the condition is circuit-valid.
 */
export function firstCircuitTrap(mapped) {
  if (mapped.proofVkHash !== mapped.registeredVkHash) return "VK_SUBSTITUTION";
  if (mapped.publicBalance < mapped.minimum) return "THRESHOLD_MISMATCH";
  if (mapped.currentBlock >= mapped.expiryBlock) return "EXPIRED_CONDITION";
  if (mapped.recipient !== mapped.conditionRecipient) return "RECIPIENT_MISMATCH";
  if (mapped.amount > mapped.maxTransfer) return "AMOUNT_OVERFLOW";
  return null;
}
