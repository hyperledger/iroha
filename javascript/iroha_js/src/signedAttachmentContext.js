/** Payload-derived attachment context from the authenticated canonical Rust owner. */
import { Buffer } from "buffer";
import { blake3 } from "@noble/hashes/blake3";
import { blake2b } from "@noble/hashes/blake2b";
import { defaultNativeRuntime, resolveNativeRuntimeBinding } from "./nativeRuntime.js";
import { decodeSignedAttachmentsV1 } from "./signedAttachments.js";
import { inspectSignedAttachmentProofBindingsV1 } from "./signedAttachmentProofs.js";
import { u64ToLittleEndianBuffer, validateNoritoFrame } from "./noritoValueCodecs.js";

const MAX_PAYLOAD = 10 * 1024 * 1024;
function byteCopy(value, maximum, name, exact = false) {
  if (!(value instanceof Uint8Array) || value.length === 0 || value.length > maximum || (exact && value.length !== maximum)) {
    throw new TypeError(`${name} has an invalid byte length or representation`);
  }
  return Uint8Array.from(value);
}
function inspect(runtime, payloadBytes, expected) {
  if (!expected || typeof expected !== "object" || Array.isArray(expected)
      || Object.keys(expected).length !== 2 || !Object.hasOwn(expected, "networkId") || !Object.hasOwn(expected, "authority")) {
    throw new TypeError("attachment context requires exactly networkId and authority");
  }
  const payload = byteCopy(payloadBytes, MAX_PAYLOAD, "payloadBytes");
  const network = byteCopy(expected.networkId, 32, "networkId", true);
  if (typeof expected.authority !== "string" || expected.authority.length === 0 || expected.authority.length > 4096 || expected.authority.trim() !== expected.authority) {
    throw new TypeError("attachment context authority must be a bounded exact account literal");
  }
  const binding = resolveNativeRuntimeBinding(runtime);
  if (typeof binding.inspectTransactionAttachmentContextV1 !== "function") {
    throw new Error("authenticated native binding lacks canonical attachment context inspection");
  }
  const result = binding.inspectTransactionAttachmentContextV1(payload, network, expected.authority);
  const hash = byteCopy(result.payloadHash, 32, "native payloadHash", true);
  const actualPayloadHash = Buffer.from(blake2b(payload, { dkLen: 32 }));
  actualPayloadHash[31] |= 1;
  if (!actualPayloadHash.equals(Buffer.from(hash))) throw new TypeError("native payload hash differs from the exact input");
  const intent = byteCopy(result.orderedIntentDigest, 32, "native orderedIntentDigest", true);
  const projection = byteCopy(result.orderedIntentProjection, MAX_PAYLOAD + 64, "native orderedIntentProjection");
  const decoded = validateNoritoFrame(projection, {
    expectedTypeName: "iroha_data_model::transaction::signed::model::TransactionPayload",
    expectedPaddingLength: 0,
  });
  if (decoded.flags !== 2) throw new TypeError("native intent projection has noncanonical flags");
  const calculated = blake3(Buffer.concat([Buffer.from("iroha.transaction.ordered-intent-digest.v1", "ascii"), u64ToLittleEndianBuffer(projection.length), Buffer.from(projection)]));
  if (!Buffer.from(calculated).equals(Buffer.from(intent))) throw new TypeError("native intent projection digest mismatch");
  if (!Array.isArray(result.statementDigests) || result.statementDigests.length > 16) throw new TypeError("native statement digest count exceeds its bound");
  const statements = result.statementDigests.map((value) => byteCopy(value, 32, "native statement digest", true));
  let attachmentFrame = null;
  if (result.attachmentFrame !== null && result.attachmentFrame !== undefined) {
    attachmentFrame = byteCopy(result.attachmentFrame, 9 * 1024 * 1024 + 64 * 1024, "native attachment frame");
    const descriptor = decodeSignedAttachmentsV1(attachmentFrame);
    inspectSignedAttachmentProofBindingsV1(descriptor, intent);
    if (statements.length !== descriptor.actions.length || descriptor.actions.some((a, i) => !Buffer.from(a.statementDigest).equals(Buffer.from(statements[i])))) {
      throw new TypeError("native statement list differs from the actual attachment descriptor");
    }
  } else if (statements.length !== 0) throw new TypeError("native absent attachments have nonempty statements");
  return { payloadHash: hash, orderedIntentDigest: intent, orderedIntentProjection: projection, attachmentFrame, statementDigests: statements };
}

/** Inspect exact canonical unsigned bytes against an explicit network and authority.
 * Uses the authenticated Rust decoder for registered operations, executable
 * targets, carrier uniqueness, actual carrier metadata, statement bindings and
 * complete per-submission privacy normalization. No JS or unauthenticated fallback.
 * The 10 MiB local inspection bound is separate from chain configuration.
 * This does not verify signatures/proofs, execute instructions or admit chain state.
 */
export function inspectCanonicalTransactionAttachmentContextV1(payloadBytes, expected) {
  return inspect(defaultNativeRuntime, payloadBytes, expected);
}

/** @internal Dependency-bound fixture facade, absent from package exports. */
export function _createSignedAttachmentContextApi(runtime) {
  return Object.freeze({ inspectCanonicalTransactionAttachmentContextV1: (payloadBytes, expected) => inspect(runtime, payloadBytes, expected) });
}
