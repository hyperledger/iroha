import { defaultNativeRuntime, resolveNativeRuntimeBinding } from "./nativeRuntime.js";
import { networkIdBytes } from "./networkId.js";

/** Native occurrence identity. Never used by the portable browser transport. */
export function deriveMultisigProposalId(networkId, accountId, proposalNonce) {
  networkIdBytes(networkId, "networkId");
  if (typeof proposalNonce !== "string" || !/^[0-9a-f]{64}$/u.test(proposalNonce) || /^0+$/u.test(proposalNonce)) throw new TypeError("proposalNonce must be nonzero canonical 32-byte hex");
  if (typeof accountId !== "string" || accountId.length === 0 || accountId.trim() !== accountId) throw new TypeError("exact accountId required");
  const native = resolveNativeRuntimeBinding(defaultNativeRuntime);
  if (typeof native?.deriveMultisigProposalIdJson !== "function") throw new Error("current native multisig occurrence constructor is unavailable");
  const result = native.deriveMultisigProposalIdJson(JSON.stringify({network_id: networkId.toString(), account_id: accountId, proposal_nonce: proposalNonce}));
  if (typeof result !== "string" || !/^[0-9a-f]{64}$/u.test(result)) throw new TypeError("invalid native proposal identity");
  return result;
}
