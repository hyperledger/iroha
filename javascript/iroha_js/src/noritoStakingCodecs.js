import { Buffer } from "buffer";
import { NetworkId } from "./networkId.js";

// These are canonical bare values, not authorization proofs or signed instructions.
const fields = (text) => text.split(" ").map((field) => field.split(":"));
const schemas = Object.freeze({
  PrepareRegistration: fields("validator:account peer_id:PeerId amount:quantity candidate:bool"),
  PrepareBond: fields("validator:account staker:account amount:quantity"),
  PrepareUnbond: fields("validator:account staker:account request_id:hash"),
  PrepareClaim: fields("recipient:account"),
  PreparationRequest: fields("lane_id:lane valid_for_blocks:u64 operation:PreparationOperation"),
  PreparationBalance: fields("asset:AssetId balance:quantity stake_reserved:quantity rewards_reserved:quantity"),
  Preparation: fields("request:PreparationRequest network_id:network observed_height:u64 observed_block_hash:hash observed_ledger_time_ms:u64 assumed_execution_height:u64 xor_asset_definition_id:definition plan:PreparedPlan balances:PreparationBalances"),
  AssetId: fields("account:account definition:definition scope:AssetScope"),
  PeerId: fields("public_key:key"),
  MonetaryRegistration: fields("activation_height:u64"),
  MonetaryBond: fields("activation_height:u64 peer_id:PeerId"),
  MonetaryUnbond: fields("activation_height:u64 request_hash:hash"),
  MonetarySlash: fields("activation_height:u64 slashable_exposure:quantity"),
  MonetaryPlan: fields("network_scope:MonetaryScope valid_until_height:u64 source_asset:AssetId destination_asset:AssetId amount:quantity precondition:MonetaryPrecondition"),
  FeeRewardClaim: fields("lifecycle_seal:bytes32 beneficiary_id:account beneficiary_revision:u64 source_asset:AssetId destination_asset:AssetId amount:quantity expected_claim_sequence:u64"),
  RewardClaimPlan: fields("network_scope:MonetaryScope valid_until_height:u64 fee_claim:FeeRewardClaim"),
  ValidatorGeneration: fields("network_id:network generation:u64 validators:Validators"),
  InstalledBeacon: fields("session_id:bytes32 transcript_hash:bytes32"),
  EpochAuthorization: fields("version:u16 network_id:network epoch:u64 first_height:u64 last_height:u64 authority_generation:u64 authority_id:bytes32 beacon:BeaconBinding previous_authorization_id:bytes32 transition_id:bytes32 decision:EpochDecision"),
});
const variants = Object.freeze({
  PreparationOperation: [["registration", "PrepareRegistration"], ["bond", "PrepareBond"], ["finalize_unbond", "PrepareUnbond"], ["claim_rewards", "PrepareClaim"]],
  PreparedPlan: [["monetary", "MonetaryPlan"], ["claim", "RewardClaimPlan"]],
  MonetaryScope: [["genesis", null], ["network", "network"]],
  AssetScope: [["global", null], ["dataspace", "u64"]],
  MonetaryPrecondition: [["registration", "MonetaryRegistration"], ["bond", "MonetaryBond"], ["unbond", "MonetaryUnbond"], ["slash", "MonetarySlash"]],
  BeaconBinding: [["bootstrap", null], ["installed", "InstalledBeacon"]],
  EpochDecision: [["genesis", null], ["activate", null], ["retain", null], ["retain_and_cancel", null]],
});
const vectors = Object.freeze({ PreparationBalances: ["PreparationBalance", 2], Validators: ["PeerId", 31] });
function exact(value, names, label) {
  if (!value || typeof value !== "object" || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new TypeError(`${label} requires exact native fields`);
  const keys = Reflect.ownKeys(value);
  if (keys.length !== names.length || names.some((name) => !keys.includes(name))) throw new TypeError(`${label} requires exact native fields`);
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) throw new TypeError(`${label}.${name} must be a data field`);
  }
}
function unsigned(value, bits, context) {
  if (!(typeof value === "bigint" || typeof value === "number" && Number.isSafeInteger(value) || typeof value === "string" && /^(?:0|[1-9][0-9]*)$/u.test(value))) throw new TypeError(`${context} requires an exact unsigned integer`);
  const result = BigInt(value);
  if (result < 0n || result >= 1n << BigInt(bits)) throw new RangeError(`${context} exceeds u${bits}`);
  return result;
}
function compareParts(left, right) {
  for (let i = 0; i < Math.min(left.length, right.length); i += 1) {
    const result = Buffer.compare(left[i], right[i]);
    if (result !== 0) return result;
  }
  return left.length - right.length;
}
/** Compose staking values using the single existing Norito primitive owner. */
export function createNoritoStakingCodecs(h) {
  function accountOrder(account) {
    const payload = h.encodeAccountIdValue(account, "staking account order");
    const tag = payload.readUInt32LE();
    const part = h.decodeStructFields(payload.subarray(4), "controller", ["value"]).value;
    if (tag === 0) return [Buffer.of(0), h.decodeConstVecU8Value(part, "controller key")];
    const policy = h.decodeStructFields(part, "policy", ["version", "threshold", "members"]);
    const threshold = Buffer.alloc(2); threshold.writeUInt16BE(h.decodeU16Value(policy.threshold, "threshold"));
    const members = h.decodeNoritoVec(policy.members, (bytes) => {
      const member = h.decodeStructFields(bytes, "member", ["key", "weight"]);
      const weight = Buffer.alloc(2); weight.writeUInt16BE(h.decodeU16Value(member.weight, "weight"));
      return [h.decodeConstVecU8Value(member.key, "member key"), weight];
    }, "members");
    return [Buffer.of(1), policy.version, threshold, ...members.flat()];
  }
  function assetOrder(left, right) {
    const account = compareParts(accountOrder(left.account), accountOrder(right.account));
    if (account) return account;
    const definition = Buffer.compare(h.encodeAssetDefinitionIdValue(left.definition, "definition"), h.encodeAssetDefinitionIdValue(right.definition, "definition"));
    if (definition) return definition;
    if (left.scope.kind !== right.scope.kind) return left.scope.kind === "global" ? -1 : 1;
    if (left.scope.kind === "global") return 0;
    const a = unsigned(left.scope.value, 64, "scope"), b = unsigned(right.scope.value, 64, "scope");
    return a < b ? -1 : a > b ? 1 : 0;
  }
  function sameAsset(left, right) {
    return encode("definition", left.definition).equals(encode("definition", right.definition)) && encode("AssetScope", left.scope).equals(encode("AssetScope", right.scope));
  }
  const positive = (value) => BigInt(h.decodeQuantityValue(h.encodeQuantityValue(value, "quantity"), "quantity").replace(".", "")) > 0n;
  function validate(name, value) {
    if (name === "PreparationRequest" && BigInt(value.valid_for_blocks) === 0n) throw new TypeError("preparation expiry offset must be positive");
    if (["PrepareRegistration", "PrepareBond"].includes(name) && !positive(value.amount)) throw new TypeError("preparation amount must be positive");
    if (name === "MonetaryPlan" && (BigInt(value.valid_until_height) === 0n || !positive(value.amount) || !sameAsset(value.source_asset, value.destination_asset))) throw new TypeError("invalid staking monetary plan");
    if (name === "FeeRewardClaim" && (!Buffer.from(value.lifecycle_seal).some((byte) => byte !== 0) || !positive(value.amount) || value.source_asset.scope.kind !== "global" || value.destination_asset.scope.kind !== "global" || !sameAsset(value.source_asset, value.destination_asset))) throw new TypeError("invalid fee reward custody or amount");
    if (name === "RewardClaimPlan") {
      if (BigInt(value.valid_until_height) === 0n) throw new TypeError("reward expiry must be positive");
    }
    if (name === "ValidatorGeneration") {
      if (value.validators.length < 4 || (value.validators.length - 1) % 3 !== 0) throw new TypeError("invalid validator-generation geometry");
      let previous = null;
      for (const validator of value.validators) {
        const { curve, publicKey } = h.parsePublicKeyLiteral(validator.public_key, "validator generation key");
        if (curve !== h.curveIdFromAlgorithm("bls_normal") || publicKey.length !== 48) throw new TypeError("validator generation requires BLS-normal public keys");
        if (previous && Buffer.compare(previous, publicKey) >= 0) throw new TypeError("validator generation requires strictly ordered unique keys");
        previous = publicKey;
      }
    }
    if (name === "EpochAuthorization" && (Number(value.version) !== 1 || BigInt(value.first_height) === 0n || BigInt(value.last_height) < BigInt(value.first_height))) throw new TypeError("invalid epoch authorization");
  }
  function encode(name, value, context = name) {
    if (schemas[name]) {
      const schema = schemas[name]; exact(value, schema.map(([field]) => field), context);
      const result = h.encodeStructValue(schema.map(([field, type]) => [encode(type, value[field], `${context}.${field}`)]));
      validate(name, value); return result;
    }
    if (variants[name]) {
      exact(value, ["kind", "value"], context);
      const tag = variants[name].findIndex(([kind]) => kind === value.kind);
      if (tag < 0) throw new TypeError(`${context} has unknown variant`);
      const type = variants[name][tag][1];
      if (!type && value.value !== null) throw new TypeError(`${context} unit requires explicit null`);
      return h.encodeEnumTagValue(tag, type ? () => encode(type, value.value, context) : undefined);
    }
    if (vectors[name]) {
      const [type, limit] = vectors[name];
      if (!Array.isArray(value) || value.length > limit) throw new RangeError(`${context} exceeds ${limit} entries`);
      return h.encodeNoritoVec(value, (item) => encode(type, item, context));
    }
    if (name.startsWith("?")) {
      if (value === undefined) throw new TypeError(`${context} requires explicit null or value`);
      return h.encodeOptionValue(value, (item) => encode(name.slice(1), item, context), context);
    }
    switch (name) {
      case "lane": return h.encodeStructValue([[h.encodeU32Value(unsigned(value, 32, context), context)]]);
      case "bool": return h.encodeBoolValue(value, context);
      case "u16": return h.encodeU16Value(unsigned(value, 16, context), context);
      case "u64": return h.encodeU64Value(unsigned(value, 64, context), context);
      case "network": if (!(value instanceof NetworkId)) throw new TypeError(`${context} requires NetworkId`); return Buffer.from(value.toBytes());
      case "bytes32": return h.encodeFixedBytesValue(value, 32, context);
      case "hash": return h.encodeEscrowIdValue(value, context);
      case "account": return h.encodeAccountIdValue(value, context);
      case "definition": return h.encodeAssetDefinitionIdValue(value, context);
      case "key": return h.encodePublicKeyValue(h.parsePublicKeyLiteral(value, context), context);
      case "quantity": return h.encodeQuantityValue(value, context);
      default: throw new TypeError(`unknown staking value ${name}`);
    }
  }
  function decode(name, payload, context = name) {
    if (schemas[name]) {
      const schema = schemas[name], parts = h.decodeStructFields(payload, context, schema.map(([field]) => field));
      const value = Object.fromEntries(schema.map(([field, type]) => [field, decode(type, parts[field], `${context}.${field}`)]));
      validate(name, value); return value;
    }
    if (variants[name]) {
      if (payload.length < 4) throw new TypeError(`${context} truncated variant`);
      const entry = variants[name][payload.readUInt32LE()];
      if (!entry) throw new TypeError(`${context} unknown variant`);
      const [kind, type] = entry;
      if (!type) { if (payload.length !== 4) throw new TypeError(`${context} unit has trailing data`); return { kind, value: null }; }
      const part = h.decodeStructFields(payload.subarray(4), context, ["value"]).value;
      return { kind, value: decode(type, part, context) };
    }
    if (vectors[name]) { const [type, limit] = vectors[name]; return h.decodeNoritoVec(payload, (item) => decode(type, item, context), context, limit); }
    if (name.startsWith("?")) return h.decodeOptionValue(payload, (item) => decode(name.slice(1), item, context), context);
    switch (name) {
      case "lane": return h.decodeU32Value(h.decodeStructFields(payload, context, ["value"]).value, context);
      case "bool": return h.decodeBoolValue(payload, context);
      case "u16": return h.decodeU16Value(payload, context);
      case "u64": return BigInt(h.decodeU64Value(payload, context));
      case "network": return NetworkId.fromBytes(payload);
      case "bytes32": return h.decodeFixedBytesValue(payload, 32, context);
      case "hash": return h.decodeEscrowIdValue(payload, context);
      case "account": return h.decodeAccountIdValue(payload, context);
      case "definition": return h.decodeAssetDefinitionIdValue(payload, context);
      case "key": { const key = h.decodePublicKeyValue(payload, context); return h.publicKeyLiteralFromParts(key.curve, key.publicKey, context); }
      case "quantity": return h.decodeQuantityValue(payload, context);
      default: throw new TypeError(`unknown staking value ${name}`);
    }
  }
  function validatePreparation(prepared, request, networkId, xorDefinition) {
    encode("Preparation", prepared); encode("PreparationRequest", request);
    const fail = (field) => { throw new TypeError(`staking preparation response binding: ${field}`); };
    const equal = (name, left, right) => encode(name, left).equals(encode(name, right));
    if (!(networkId instanceof NetworkId)) throw new TypeError("staking preparation requires an exact NetworkId pin");
    encode("definition", xorDefinition);
    if (!equal("PreparationRequest", prepared.request, request)) fail("request");
    if (!prepared.network_id.equals(networkId)) fail("network_id");
    if (!equal("definition", prepared.xor_asset_definition_id, xorDefinition)) fail("xor_asset_definition_id");
    const height = BigInt(prepared.observed_height), expiry = height + BigInt(request.valid_for_blocks);
    if (height === 0n || height + 1n !== BigInt(prepared.assumed_execution_height) || expiry >= 1n << 64n) fail("height");
    const plan = prepared.plan.value, intent = request.operation.value;
    if (plan.network_scope.kind !== "network" || !plan.network_scope.value.equals(networkId) || BigInt(plan.valid_until_height) !== expiry) fail("plan_scope_or_expiry");
    const assets = [];
    if (prepared.plan.kind === "monetary") {
      const matches = request.operation.kind === "registration" && plan.precondition.kind === "registration" && equal("account", plan.source_asset.account, intent.validator) && equal("quantity", plan.amount, intent.amount)
        || request.operation.kind === "bond" && plan.precondition.kind === "bond" && equal("account", plan.source_asset.account, intent.staker) && equal("quantity", plan.amount, intent.amount)
        || request.operation.kind === "finalize_unbond" && plan.precondition.kind === "unbond" && equal("account", plan.destination_asset.account, intent.staker);
      if (!matches || BigInt(plan.precondition.value.activation_height) === 0n) fail("monetary_intent");
      assets.push(plan.source_asset, plan.destination_asset);
    } else {
      if (request.operation.kind !== "claim_rewards") fail("reward_intent");
      if (!equal("account", plan.fee_claim.destination_asset.account, intent.recipient)) fail("reward_recipient");
      assets.push(plan.fee_claim.source_asset, plan.fee_claim.destination_asset);
    }
    assets.sort(assetOrder);
    const unique = assets.filter((asset, index) => index === 0 || assetOrder(assets[index - 1], asset) !== 0);
    if (prepared.balances.length !== unique.length || prepared.balances.some((row, index) => !equal("AssetId", row.asset, unique[index]))) fail("balances");
    if (unique.some((asset) => asset.scope.kind !== "global" || !equal("definition", asset.definition, xorDefinition))) fail("global_xor");
    return prepared;
  }
  return Object.freeze({ encode, decode, validatePreparation });
}
