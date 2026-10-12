import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { build } from "esbuild";
import { NetworkId } from "../src/networkId.js";
import { requestNativeMultisigViaTransport as requestNative, inspectNativeMultisigPrepareViaTransport as prepareNative, inspectNativeMultisigSignedViaTransport as signNative, queryNativeMultisigFinalityViaTransport as finalityNative, queryNativeMultisigProposalFinalityViaTransport as proposalFinalityNative } from "../src/nativeMultisigTransport.js";

const hash = value => createHash("sha256").update(value).digest("hex");
const b64 = value => Buffer.from(value).toString("base64");
const sort = value => Array.isArray(value) ? value.map(sort) : value && typeof value === "object"
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, sort(value[key])])) : value;
const canonical = value => JSON.stringify(sort(value));
const contract = { requestSchema: "native.request.v1", prepareSchema: "native.prepare.v1", signedSchema: "native.signed.v1" };
const call = { requestId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", nonce: "a1".repeat(32) };
const input = { ...call, actionId: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", context: {
  networkId: NetworkId.fromBytes(new Uint8Array(32).fill(1)), actorAccountId: "opaque-actor", actorPublicKeyHex: "a2".repeat(32),
  deviceId: "device-1", portalOrigin: "https://portal.example", operatorBaseUrl: "https://core.example/operator",
  toriiBaseUrl: "https://torii.example", physicalDataspaceId: "123", laneId: 5,
}, intent: { action: "propose", operation: { amount: "25" } } };

function fixture(edit = () => {}) {
  const now = Date.now() - 10, expiresAtMs = String(now + 90_000), path = "/v1/multisig/propose";
  const original = canonical({ multisig_account_id: "opaque-multisig", signer_account_id: "opaque-actor", fee_payment: { payer: "authority" }, instructions: ["opaque-native"] });
  const calls = [];
  const transport = async request => {
    calls.push(request);
    const body = JSON.parse(request.body);
    const result = request.stage === "request" ? { stage: "request", path, requestBytesBase64: b64(original),
      requestBytesSha256: hash(original), proposalId: "b3".repeat(32), instructionsHash: "a3".repeat(32), expiresAtMs }
      : request.stage === "prepare" ? { stage: "prepared", admissionId: input.actionId, path,
        requestBytesSha256: hash(original), prepareBytesSha256: hash(Buffer.from(body.prepareBytesBase64, "base64")),
        payloadBase64: b64("native-payload"), payloadSha256: hash("native-payload"),
        signingMessageBase64: b64(new Uint8Array(32).fill(2)), signingMessageSha256: hash(new Uint8Array(32).fill(2)),
        proposalId: "b3".repeat(32), instructionsHash: "a3".repeat(32), creationTimeMs: String(now), payloadExpiresAtMs: String(now + 100_000), expiresAtMs,
        feePayment: { payer: "authority" } }
      : { stage: "signed", admissionId: input.actionId, path, submitBytesBase64: body.signedRequestBytesBase64,
        submitBytesSha256: hash(Buffer.from(body.signedRequestBytesBase64, "base64")), signedTransactionBytesBase64: b64("native-signed-wire"),
        transactionHashHex: "a4".repeat(32), expiresAtMs };
    const response = { schema: contract[`${request.stage}Schema`], requestId: body.requestId, nonce: body.nonce, actionId: body.actionId,
      requestSha256: hash(request.body), context: body.context, intentSha256: hash(`${canonical(input.intent)}\n`), result };
    edit(response, request.stage);
    return response;
  };
  return { transport, calls };
}
const prepareInput = () => ({ ...call, prepareBytes: new TextEncoder().encode('{"native":"response"}') });
const signedInput = () => ({ ...call, signature: new Uint8Array(64).fill(7) });

test("native transport binds all stages to original intent, payload and signature without codecs", async () => {
  const {transport, calls} = fixture();
  const request = await requestNative(input, transport, contract);
  const prepared = await prepareNative(request, prepareInput());
  const signed = await signNative(prepared, signedInput());
  assert.equal(calls.length, 3);
  assert.ok(calls.every(Object.isFrozen));
  assert.ok(Object.isFrozen(prepared) && Object.isFrozen(prepared.feePayment));
  const submitted = JSON.parse(Buffer.from(signed.submitBytesBase64, "base64"));
  assert.equal(submitted.public_key_hex, input.context.actorPublicKeyHex);
  assert.equal(submitted.signature_b64, b64(new Uint8Array(64).fill(7)));
  assert.equal(submitted.creation_time_ms, Number(prepared.creationTimeMs));
  assert.equal(signed.transactionHashHex, "a4".repeat(32));
  await assert.rejects(prepareNative({...request}, prepareInput()), /not admitted/u);
  await assert.rejects(signNative({...prepared}, signedInput()), /not admitted/u);
});

test("rejects every common response substitution, closed-shape violation and replay", async () => {
  for (const field of ["schema", "requestId", "nonce", "actionId", "requestSha256", "intentSha256"]) {
    const {transport} = fixture(response => { response[field] = "changed"; });
    await assert.rejects(requestNative(input, transport, contract));
  }
  for (const edit of [r => { r.context.deviceId = "another-device"; }, r => { r.extra = true; },
    r => { Object.defineProperty(r, "nonce", { get() { throw new Error("getter ran"); } }); }]) {
    const {transport} = fixture(edit);
    await assert.rejects(requestNative(input, transport, contract));
  }
});

test("refuses substituted request bytes, prepare prehash, deadlines and signed originals", async () => {
  for (const [stage, field, value] of [
    ["request", "path", "/v1/multisig/approve"], ["request", "requestBytesSha256", "00".repeat(32)],
    ["request", "expiresAtMs", "1"], ["prepare", "instructionsHash", "00".repeat(32)], ["prepare", "proposalId", "a3".repeat(32)],
    ["prepare", "signingMessageSha256", "00".repeat(32)], ["prepare", "prepareBytesSha256", "00".repeat(32)],
    ["prepare", "admissionId", call.requestId], ["prepare", "expiresAtMs", String(Date.now() + 1_000_000)],
    ["prepare", "creationTimeMs", "01"], ["signed", "submitBytesBase64", b64("other")],
    ["signed", "submitBytesSha256", "00".repeat(32)], ["signed", "transactionHashHex", "A1".repeat(32)],
    ["signed", "expiresAtMs", String(Date.now() + 1_000_000)],
  ]) {
    const {transport} = fixture((r, current) => { if (current === stage) r.result[field] = value; });
    await assert.rejects(async () => {
      const request = await requestNative(input, transport, contract);
      const prepared = await prepareNative(request, prepareInput());
      await signNative(prepared, signedInput());
    }, undefined, `${stage}.${field}`);
  }
});

test("rejects unsafe semantic JSON and snapshots mutable inputs before awaiting transport", async () => {
  for (const operation of [{ amount: NaN }, { amount: 1.5 }, { amount: 2 ** 53 }, { amount: undefined }]) {
    await assert.rejects(requestNative({...input, intent: {...input.intent, operation}}, async () => assert.fail("transport called"), contract));
  }
  const mutable = {...input, context: {...input.context}, intent: {...input.intent, operation: {...input.intent.operation}}};
  const {transport} = fixture();
  const request = await requestNative(mutable, async req => {
    mutable.context.deviceId = "changed"; mutable.intent.operation.amount = "500";
    return transport(req);
  }, contract);
  await prepareNative(request, prepareInput());
});

test("browser build does not import any native or account/transaction codec", async () => {
  const result = await build({entryPoints: ["src/nativeMultisigTransport.js"], bundle: true, platform: "browser", format: "esm", write: false, metafile: true});
  assert.ok(!Object.keys(result.metafile.inputs).some(path => /(?:native(?:\.browser)?\.js|address\.js|transactionCodec|node:)/u.test(path)));
});

test("rooted finality query binds retained action without preparing or signing after expiry", async () => {
  const query = {...input, admissionId: input.actionId, transactionHashHex: "a4".repeat(32)};
  const transport = async ({stage, body}) => {
    assert.equal(stage, "finality");
    const call = JSON.parse(body);
    assert.deepEqual(Object.keys(call).sort(), ["actionId", "admissionId", "context", "nonce", "requestId"]);
    return {schema: "native.finality.v1", requestId: call.requestId, nonce: call.nonce, actionId: call.actionId,
      requestSha256: hash(body), context: call.context, intentSha256: hash(`${canonical(input.intent)}\n`), result: {
        stage: "finality", admissionId: call.actionId, participationCommitted: true, businessExecuted: true, cancellationCommitted: false, subjectCanceled: false,
        transactionHashHex: query.transactionHashHex, executedTransactionHashHex: "a5".repeat(32), blockHeight: "12", blockHash: "a6".repeat(32),
      }};
  };
  const result = await finalityNative(query, transport, {finalitySchema: "native.finality.v1"});
  assert.equal(result.businessExecuted, true);
  for (const edit of [r => {r.result.transactionHashHex = "a7".repeat(32);}, r => {r.result.cancellationCommitted = true;},
    r => {delete r.result.subjectCanceled;}, r => {r.result.subjectCanceled = true;},
    r => {r.result.blockHeight = "0";}, r => {r.result.businessExecuted = false;}, r => {r.context.deviceId = "changed";}]) {
    await assert.rejects(finalityNative(query, async call => { const result = await transport(call); edit(result); return result; }, {finalitySchema: "native.finality.v1"}));
  }
});

test("shared proposal finality binds exact semantic lookup without local signing originals", async () => {
  const query = {...call, lookupId: input.actionId, context: input.context,
    intent: {multisigAccountId: "bank", proposalId: "b9".repeat(32), instructionsHash: "a9".repeat(32), operation: {kind: "mint", amount: "1"}, targetProposalId: null, targetInstructionsHash: null}};
  const transport = async ({stage, body}) => {
    assert.equal(stage, "proposal-finality");
    const offered = JSON.parse(body);
    return {schema: "native.proposal-finality.v1", requestId: offered.requestId, nonce: offered.nonce, lookupId: offered.lookupId,
      requestSha256: hash(body), context: offered.context, intentSha256: hash(`${canonical(offered.intent)}\n`), result: {
        stage: "proposal-finality", businessExecuted: true, cancellationCommitted: false, subjectCanceled: false,
        executedTransactionHashHex: "ab".repeat(32), blockHeight: "7", blockHash: "ac".repeat(32),
      }};
  };
  const contract = {proposalFinalitySchema: "native.proposal-finality.v1"};
  assert.equal((await proposalFinalityNative(query, transport, contract)).businessExecuted, true);
  for (const edit of [r => {r.lookupId = call.requestId;}, r => {r.result.cancellationCommitted = true;},
    r => {delete r.result.subjectCanceled;}, r => {r.result.subjectCanceled = true;},
    r => {r.intentSha256 = "00".repeat(32);}, r => {r.result.blockHeight = "0";}, r => {r.context.actorAccountId = "different";},
    r => {r.result.businessExecuted = false;}, r => {r.actionId = query.lookupId;}]) {
    await assert.rejects(proposalFinalityNative(query, async call => {const result = await transport(call); edit(result); return result;}, contract));
  }
  const canceledTransport = async call => {
    const response = await transport(call);
    response.result = {...response.result, businessExecuted: false, subjectCanceled: true,
      executedTransactionHashHex: null, blockHeight: null, blockHash: null};
    return response;
  };
  assert.equal((await proposalFinalityNative(query, canceledTransport, contract)).subjectCanceled, true);
  const wrapper = {...query, intent: {...query.intent, targetProposalId: "bd".repeat(32), targetInstructionsHash: "ad".repeat(32)}};
  assert.equal((await proposalFinalityNative(wrapper, canceledTransport, contract)).subjectCanceled, true);
  await assert.rejects(proposalFinalityNative(wrapper, async call => {
    const response = await transport(call);
    Object.assign(response.result, {businessExecuted: false, subjectCanceled: true, cancellationCommitted: true});
    return response;
  }, contract), /differs from exact reviewed operation/);
});
