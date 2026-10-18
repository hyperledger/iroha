/** Exact literals only; these checks do not derive IDs or authenticate a proposal. */
export function requireMultisigId(value, label = "proposalId") {
  if (typeof value !== "string" || (!/^[0-9a-f]{64}$/u.test(value) || /^0+$/u.test(value))) throw new TypeError(`${label} must be nonzero exact lowercase 32-byte hex`);
  return value;
}
export function requireMultisigNonce(value) {
  return requireMultisigId(value, "proposalNonce");
}
