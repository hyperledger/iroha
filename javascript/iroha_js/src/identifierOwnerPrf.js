import { NetworkId } from "./networkId.js";
import { ensureCanonicalAccountId } from "./normalizers.js";
import { blake2b256 } from "./blake2b.js";

function fail(context, message) {
  throw new TypeError(`${context} ${message}`);
}
function exactObject(value, keys, context, optional = []) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(context, "must be an object");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== null && prototype !== Object.prototype) fail(context, "must be plain");
  if (Object.keys(value).some((key) => !keys.includes(key) && !optional.includes(key))
      || keys.some((key) => !Object.hasOwn(value, key))) fail(context, "has missing or unsupported fields");
  return value;
}
function exactString(value, context) {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
    fail(context, "must be an exact nonempty string");
  }
  return value;
}
export function requireOwnerProgram(value, context) {
  const name = exactString(value, context);
  if (Buffer.byteLength(name, "utf8") > 255 || name.normalize("NFC") !== name
      || /[\p{Cc}\p{White_Space}@#$\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(name)
      || /[\uD800-\uDFFF]/u.test(name.replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]/gu, ""))) {
    fail(context, "must be an exact Iroha Name");
  }
  return name;
}
function unsignedInteger(value, context) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    fail(context, "must be a positive safe JSON integer");
  }
  return value;
}
function exactHex(value, context, uppercase, bytes = null, maxBytes = null) {
  const pattern = uppercase ? /^(?:[0-9A-F]{2})+$/u : /^(?:[0-9a-f]{2})+$/u;
  if (typeof value !== "string" || !pattern.test(value)
      || (bytes !== null && value.length !== bytes * 2)
      || (maxBytes !== null && value.length > maxBytes * 2)) fail(context, "has invalid exact hex grammar or width");
  return value;
}
function signature(value, context) {
  const result = exactHex(value, context, true, null, 16384);
  if (/^0+$/u.test(result)) fail(context, "must contain nonzero signature bytes");
  // A public key's genuine algorithm verifier owns canonical signature admission.
  return result;
}
function checkedHash(value, context) {
  try { return NetworkId.parse(value).literal; } catch { fail(context, "must be an exact checked Hash literal"); }
}
export function checkedHashRaw(value, context) {
  return Buffer.from(NetworkId.parse(checkedHash(value, context)).toBytes()).toString("hex");
}
function markedRawHash(value, context) {
  const literal = exactHex(value, context, false, 32);
  if ((Number.parseInt(literal.slice(-2), 16) & 1) !== 1) fail(context, "must be a marked raw32 Hash");
  return literal;
}
export function requireOwnerNetwork(value, context) {
  if (!(value instanceof NetworkId)) fail(context, "must be the independently selected NetworkId");
  return value;
}
export function requireOwnerInput(value, context) {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") < 1
      || Buffer.byteLength(value, "utf8") > 512
      || /[\uD800-\uDFFF]/u.test(value.replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]/gu, ""))) {
    fail(context, "must contain 1..512 valid UTF-8 bytes");
  }
  return value;
}
export function requireOwnerInputNonce(value, context) {
  const nonce = exactHex(value, context, false, 32);
  if (/^0+$/u.test(nonce)) fail(context, "must be a nonzero private input nonce");
  return nonce;
}
export function assertOwnerReceiptNetwork(raw, expectedNetwork, context) {
  const expected = requireOwnerNetwork(expectedNetwork, context);
  const network = markedRawHash(raw, context);
  if (network !== Buffer.from(expected.toBytes()).toString("hex")) fail(context, "differs from the independently selected network");
  return network;
}
function programObject(value, context) {
  const record = exactObject(value, ["name"], context);
  return Object.freeze({ name: requireOwnerProgram(record.name, `${context}.name`) });
}
function policyObject(value, context) {
  const record = exactObject(value, ["kind", "business_rule"], context);
  return Object.freeze({ kind: requireOwnerProgram(record.kind, `${context}.kind`), business_rule: requireOwnerProgram(record.business_rule, `${context}.business_rule`) });
}
function originalLease(opened, expiry, context) {
  const start = unsignedInteger(opened, `${context}.opened_at_ms`);
  const end = unsignedInteger(expiry, `${context}.expires_at_ms`);
  if (end <= start || end - start > 120000) fail(context, "requires the original positive lease of at most 120000ms");
  return [start, end];
}
export function normalizeTypedOriginalOpening(value, context) {
  const envelope = exactObject(value, ["payload", "signature"], context);
  const record = exactObject(envelope.payload, ["program_id", "input_ciphertext_hash", "output_ciphertext_hash", "parameter_digest", "evaluation_key_digest", "opened_output_hash", "opened_at_ms", "expires_at_ms"], `${context}.payload`);
  const [opened, expiry] = originalLease(record.opened_at_ms, record.expires_at_ms, `${context}.payload`);
  return Object.freeze({ payload: Object.freeze({
    program_id: programObject(record.program_id, `${context}.payload.program_id`),
    input_ciphertext_hash: checkedHash(record.input_ciphertext_hash, `${context}.payload.input_ciphertext_hash`),
    output_ciphertext_hash: checkedHash(record.output_ciphertext_hash, `${context}.payload.output_ciphertext_hash`),
    parameter_digest: checkedHash(record.parameter_digest, `${context}.payload.parameter_digest`),
    evaluation_key_digest: checkedHash(record.evaluation_key_digest, `${context}.payload.evaluation_key_digest`),
    opened_output_hash: checkedHash(record.opened_output_hash, `${context}.payload.opened_output_hash`),
    opened_at_ms: opened, expires_at_ms: expiry,
  }), signature: signature(envelope.signature, `${context}.signature`) });
}
function exactAccount(value, context) {
  const literal = exactString(value, context);
  if (ensureCanonicalAccountId(literal, context) !== literal) fail(context, "must be canonical I105");
  return literal;
}
function exactUaid(value, context) {
  if (typeof value !== "string" || !value.startsWith("uaid:")) fail(context, "must be an exact public UAID");
  return `uaid:${markedRawHash(value.slice(5), context)}`;
}
export function normalizeTypedPhonePayload(value, context, expectedNetwork) {
  const record = exactObject(value, ["network_id", "policy_id", "program_id", "input_ciphertext_hash", "output_ciphertext_hash", "opened_output_hash", "canonical_phone_nullifier", "uaid", "account_id", "issued_at_ms", "expires_at_ms"], context);
  const network = NetworkId.parse(checkedHash(record.network_id, `${context}.network_id`));
  if (!network.equals(requireOwnerNetwork(expectedNetwork, `${context}.expectedNetwork`))) fail(context, "differs from the independently selected network");
  if (!Array.isArray(record.uaid) || record.uaid.length !== 1) fail(context, "requires the original one-field UAID tuple");
  const [issued, expiry] = originalLease(record.issued_at_ms, record.expires_at_ms, context);
  const policy = policyObject(record.policy_id, `${context}.policy_id`);
  const program = programObject(record.program_id, `${context}.program_id`);
  if (policy.kind !== "phone" || policy.business_rule !== "retail" || program.name !== "phone_retail") fail(context, "requires exactly phone#retail/phone_retail");
  return Object.freeze({ network_id: network.literal, policy_id: policy, program_id: program,
    input_ciphertext_hash: checkedHash(record.input_ciphertext_hash, `${context}.input_ciphertext_hash`),
    output_ciphertext_hash: checkedHash(record.output_ciphertext_hash, `${context}.output_ciphertext_hash`),
    opened_output_hash: checkedHash(record.opened_output_hash, `${context}.opened_output_hash`),
    canonical_phone_nullifier: checkedHash(record.canonical_phone_nullifier, `${context}.canonical_phone_nullifier`),
    uaid: Object.freeze([checkedHash(record.uaid[0], `${context}.uaid[0]`)]),
    account_id: exactAccount(record.account_id, `${context}.account_id`),
    issued_at_ms: issued, expires_at_ms: expiry,
  });
}
export function normalizeTypedPhoneAttestation(value, context, expectedNetwork) {
  const record = exactObject(value, ["payload", "signature"], context);
  return Object.freeze({ payload: normalizeTypedPhonePayload(record.payload, `${context}.payload`, expectedNetwork), signature: signature(record.signature, `${context}.signature`) });
}
function assertPhoneOriginal(statement, opening, context, account = null, uaid = null) {
  const original = opening.payload;
  for (const field of ["input_ciphertext_hash", "output_ciphertext_hash", "opened_output_hash"]) {
    if (statement[field] !== original[field]) fail(context, "changed an original opening commitment");
  }
  if (statement.program_id.name !== original.program_id.name
      || statement.canonical_phone_nullifier !== original.opened_output_hash
      || statement.issued_at_ms !== original.opened_at_ms
      || statement.expires_at_ms !== original.expires_at_ms
      || (account !== null && statement.account_id !== account)
      || (uaid !== null && checkedHashRaw(statement.uaid[0], context) !== exactUaid(uaid, context).slice(5))) fail(context, "changed original program, output, lease or beneficiary");
}
export function buildOwnerIdentifierRequest(record, phase, context, expectedNetwork) {
  if (phase !== "prepare" && phase !== "claim") fail(context, "requires the current prepare or claim phase");
  exactObject(record, ["policyId", "normalizedInput", "inputNonce"], context, phase === "claim" ? ["outputOpening", "phoneRetailCanonicality"] : []);
  const policyParts = exactString(record.policyId, `${context}.policyId`).split("#");
  if (policyParts.length !== 2) fail(context, "requires exactly kind#business_rule");
  const policy = `${requireOwnerProgram(policyParts[0], `${context}.policyId.kind`)}#${requireOwnerProgram(policyParts[1], `${context}.policyId.business_rule`)}`;
  requireOwnerNetwork(expectedNetwork, `${context}.networkId`);
  const request = { phase, policy_id: policy, normalized_input: requireOwnerInput(record.normalizedInput, `${context}.normalizedInput`), input_nonce: requireOwnerInputNonce(record.inputNonce, `${context}.inputNonce`) };
  if (phase === "claim") {
    request.output_opening = normalizeTypedOriginalOpening(record.outputOpening, `${context}.outputOpening`);
    const phoneLike = policy.split("#")[0] === "phone" || request.output_opening.payload.program_id.name === "phone_retail";
    if (phoneLike) {
      if (policy !== "phone#retail") fail(context, "requires exactly phone#retail");
      request.phone_retail_canonicality = normalizeTypedPhoneAttestation(record.phoneRetailCanonicality, `${context}.phoneRetailCanonicality`, expectedNetwork);
      assertPhoneOriginal(request.phone_retail_canonicality.payload, request.output_opening, context);
    } else if (record.phoneRetailCanonicality !== undefined) fail(context, "accepts phone canonicality only for phone#retail");
  }
  return request;
}
export function normalizeOwnerPrepareResponse(value, context, expectedNetwork, expectedPolicy, expectedAccount) {
  const record = exactObject(value, ["network_id", "policy_id", "account_id", "uaid", "output_opening"], context, ["phone_retail_canonicality_payload"]);
  const network = assertOwnerReceiptNetwork(record.network_id, expectedNetwork, `${context}.network_id`);
  if (record.policy_id !== expectedPolicy || record.account_id !== expectedAccount) fail(context, "changed requested policy or beneficiary");
  const opening = normalizeTypedOriginalOpening(record.output_opening, `${context}.output_opening`);
  const phoneLike = expectedPolicy.split("#")[0] === "phone" || opening.payload.program_id.name === "phone_retail";
  const result = { network_id: network, policy_id: exactString(record.policy_id, `${context}.policy_id`), account_id: exactAccount(record.account_id, `${context}.account_id`), uaid: exactUaid(record.uaid, `${context}.uaid`), output_opening: opening };
  if (phoneLike) {
    if (expectedPolicy !== "phone#retail") fail(context, "requires exactly phone#retail");
    result.phone_retail_canonicality_payload = normalizeTypedPhonePayload(record.phone_retail_canonicality_payload, `${context}.phone_retail_canonicality_payload`, expectedNetwork);
    assertPhoneOriginal(result.phone_retail_canonicality_payload, opening, context, result.account_id, result.uaid);
  } else if (record.phone_retail_canonicality_payload !== undefined) fail(context, "unexpected phone canonicality projection");
  // The unsigned phone projection is an independent attestor input, never proof.
  return Object.freeze(result);
}
export function flattenOriginalOpening(value, context) {
  const opening = normalizeTypedOriginalOpening(value, context);
  const p = opening.payload;
  return { payload: { program_id: p.program_id.name, input_ciphertext_hash: checkedHashRaw(p.input_ciphertext_hash, context), output_ciphertext_hash: checkedHashRaw(p.output_ciphertext_hash, context), parameter_digest: checkedHashRaw(p.parameter_digest, context), evaluation_key_digest: checkedHashRaw(p.evaluation_key_digest, context), opened_output_hash: checkedHashRaw(p.opened_output_hash, context), opened_at_ms: p.opened_at_ms, expires_at_ms: p.expires_at_ms }, signature: opening.signature.toLowerCase() };
}
export function assertOwnerClaimResponse(receipt, request, context, account = null) {
  const execution = receipt.payload.execution;
  const original = request.output_opening.payload;
  if (execution.backend !== "hkdf-sha3-512-prf-v1" || execution.verification_mode !== "signed"
      || receipt.attestation.kind !== "signed" || execution.program_id !== original.program_id.name
      || execution.output_hash !== checkedHashRaw(original.opened_output_hash, context)
      || execution.output_ciphertext_hash !== execution.output_hash
      || execution.input_ciphertext_hash !== checkedHashRaw(original.input_ciphertext_hash, context)
      || execution.parameter_digest !== checkedHashRaw(original.parameter_digest, context)
      || execution.evaluation_key_digest !== checkedHashRaw(original.evaluation_key_digest, context)
      || execution.executed_at_ms !== original.opened_at_ms || execution.expires_at_ms !== original.expires_at_ms) fail(context, "changed original current signed HKDF execution metadata");
  if (receipt.payload.policy_id !== request.policy_id
      || (account !== null && receipt.payload.account_id !== account)
      || JSON.stringify(receipt.payload.opening) !== JSON.stringify(flattenOriginalOpening(request.output_opening, context))) fail(context, "changed the requested policy, beneficiary or original opening");
  if (request.phone_retail_canonicality !== undefined) {
    if (JSON.stringify(receipt.phone_retail_canonicality) !== JSON.stringify(request.phone_retail_canonicality)) fail(context, "changed the independent original phone attestation");
    assertPhoneOriginal(request.phone_retail_canonicality.payload, request.output_opening, context, receipt.payload.account_id, receipt.payload.uaid);
  } else if (receipt.phone_retail_canonicality !== undefined) fail(context, "unexpected independent phone attestation");
  return receipt;
}
function markedHash(parts) {
  const result = Buffer.from(blake2b256(Buffer.concat(parts.map((part) => Buffer.from(part)))));
  result[result.length - 1] |= 1;
  return result;
}
export function ownerExecuteHashData(programOriginalData, opaqueOutput) {
  // DATA hashing does not decode or invent a ProgramId frame or grant authority.
  const output = markedHash([Buffer.from("iroha.ram_lfe.output_hash.v1", "utf8"), opaqueOutput]);
  const opaque = markedHash([Buffer.from("iroha.ram_lfe.identifier.opaque_hash.v1", "utf8"), programOriginalData, output]);
  const receipt = markedHash([Buffer.from("iroha.ram_lfe.identifier.receipt_hash.v1", "utf8"), programOriginalData, output, opaque]);
  return { output_hash: output.toString("hex"), opaque_hash: opaque.toString("hex"), receipt_hash: receipt.toString("hex"), associated_data_hash: markedHash([programOriginalData]).toString("hex") };
}
export function assertOwnerExecuteConsistency(response, expectedProgram, context) {
  const programOriginal = exactHex(response.program_id_canonical, `${context}.program_id_canonical`, true, null, 4096);
  const opaqueOutput = exactHex(response.opaque_output, `${context}.opaque_output`, true, 32);
  const hashes = ownerExecuteHashData(Buffer.from(programOriginal, "hex"), Buffer.from(opaqueOutput, "hex"));
  if (response.program_id !== expectedProgram || response.backend !== "hkdf-sha3-512-prf-v1"
      || response.verification_mode !== "signed" || response.receipt.attestation.kind !== "signed") fail(context, "differs from the requested signed native HKDF program");
  const p = response.receipt.payload;
  if (p.output_ciphertext_hash !== response.output_hash || p.executed_at_ms !== response.executed_at_ms
      || p.expires_at_ms !== response.expires_at_ms) fail(context, "changed original execution metadata");
  originalLease(response.executed_at_ms, response.expires_at_ms, context);
  for (const field of Object.keys(hashes)) {
    if (markedRawHash(response[field], `${context}.${field}`) !== hashes[field]) fail(context, "changed the original native output or canonical program DATA binding");
  }
  return response;
}
