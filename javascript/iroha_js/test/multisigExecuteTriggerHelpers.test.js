"use strict";

import test from "node:test";
import assert from "node:assert/strict";
import { ed25519 } from "@noble/curves/ed25519";

import {
  buildExecuteTriggerInstruction,
  buildExecuteTriggerNorito,
  buildMultisigTriggerArgs,
  isMultisigSignerAuthorized,
  buildMultisigExecuteTriggerInstruction,
  buildProposeMultisigExecuteTriggerInstruction,
  buildMultisigContractCallProposeRequest,
  buildMultisigContractCallApproveRequest,
  ValidationError,
  ValidationErrorCode,
} from "../src/index.js";
import { MultisigSpecBuilder } from "../src/multisig.js";
import { AccountAddress } from "../src/address.js";
import { noritoDecodeInstruction } from "../src/norito.js";

const deterministicPublicKey = (seedByte) =>
  Buffer.from(ed25519.getPublicKey(Buffer.alloc(32, seedByte)));
const ALICE_KEY = deterministicPublicKey(0x11);
const BOB_KEY = deterministicPublicKey(0x22);
const CAROL_KEY = deterministicPublicKey(0x33);
const CONTROLLER_KEY = deterministicPublicKey(0x44);

const ALICE_ID = AccountAddress.fromAccount({ publicKey: ALICE_KEY }).toI105();
const BOB_ID = AccountAddress.fromAccount({ publicKey: BOB_KEY }).toI105();
const CAROL_ID = AccountAddress.fromAccount({ publicKey: CAROL_KEY }).toI105();
const CONTROLLER_ID = AccountAddress.fromAccount({ publicKey: CONTROLLER_KEY }).toI105();

function canonicalSignatureBase64Fixture() {
  return Buffer.alloc(64, 0x01).toString("base64");
}

function authorityFeePayment(gasLimit = null) {
  return {
    payer: "authority",
    value: { charge_limits: [], gas_limit: gasLimit },
  };
}

function noncanonicalStandardBase64PadBitAlias(encoded) {
  assert.equal(encoded.endsWith("=="), true);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const chars = [...encoded];
  const index = chars.length - 3;
  const value = alphabet.indexOf(chars[index]);
  assert.notEqual(value, -1);
  chars[index] = alphabet[value ^ 0x01];
  return chars.join("");
}

function sampleSpec() {
  return new MultisigSpecBuilder()
    .setQuorum(2)
    .setTransactionTtlMs(60_000)
    .addSignatory(ALICE_ID, 1)
    .addSignatory(BOB_ID, 1)
    .build();
}

test("buildExecuteTriggerInstruction and buildExecuteTriggerNorito round-trip canonically", () => {
  const instruction = buildExecuteTriggerInstruction("staged_mint_request_hbl", {
    action: "create",
    request_id: "mr1",
  });
  assert.deepEqual(instruction, {
    ExecuteTrigger: {
      trigger: "staged_mint_request_hbl",
      args: {
        action: "create",
        request_id: "mr1",
      },
    },
  });

  const encoded = buildExecuteTriggerNorito("staged_mint_request_hbl", 753, {
    action: "create",
    request_id: "mr1",
  });
  assert.deepEqual(noritoDecodeInstruction(encoded, 753), instruction);
});

test("buildMultisigTriggerArgs normalizes lifecycle and lookup presets", () => {
  assert.deepEqual(
    buildMultisigTriggerArgs("lifecycle", {
      action: "create",
      requestId: "req-1",
      fiId: "banka",
      toAccountId: ALICE_ID,
      amountI64: "42",
      requestedByActorId: { account: BOB_ID },
      createdAtMs: 1,
      expiresAtMs: 2,
    }),
    {
      action: "create",
      request_id: "req-1",
      fi_id: "banka",
      to_account_id: ALICE_ID,
      amount_i64: 42,
      requested_by_actor_id: { account: BOB_ID },
      created_at_ms: 1,
      expires_at_ms: 2,
    },
  );

  assert.deepEqual(
    buildMultisigTriggerArgs("lookup", {
      requestId: "req-2",
      requestedByActorId: { account: ALICE_ID },
    }),
    {
      request_id: "req-2",
      requested_by_actor_id: { account: ALICE_ID },
    },
  );
});

test("isMultisigSignerAuthorized recognizes configured signers", () => {
  const spec = sampleSpec();
  assert.equal(isMultisigSignerAuthorized(spec, ALICE_ID), true);
  assert.equal(isMultisigSignerAuthorized(spec, CAROL_ID), false);
});

test("buildMultisigExecuteTriggerInstruction enforces strict signer checks when requested", () => {
  const spec = sampleSpec();
  assert.deepEqual(
    buildMultisigExecuteTriggerInstruction({
      trigger: "staged_mint_request_hbl",
      argPreset: "lookup",
      argInput: { requestId: "req-3" },
      signerAccountId: ALICE_ID,
      multisigSpec: spec,
      strictSignerCheck: true,
    }),
    {
      ExecuteTrigger: {
        trigger: "staged_mint_request_hbl",
        args: {
          request_id: "req-3",
        },
      },
    },
  );

  assert.throws(
    () =>
      buildMultisigExecuteTriggerInstruction({
        trigger: "staged_mint_request_hbl",
        argPreset: "lookup",
        argInput: { requestId: "req-4" },
        signerAccountId: CAROL_ID,
        multisigSpec: spec,
        strictSignerCheck: true,
      }),
    (error) =>
      error instanceof ValidationError &&
      error.code === ValidationErrorCode.INVALID_ACCOUNT_ID &&
      /not present in multisigSpec\.signatories/.test(error.message),
  );
});

test("buildProposeMultisigExecuteTriggerInstruction wraps a single ExecuteTrigger proposal", () => {
  const spec = sampleSpec();
  const payload = buildProposeMultisigExecuteTriggerInstruction({
    proposalNonce: "12".repeat(32),
    accountId: CONTROLLER_ID,
    trigger: "staged_mint_request_hbl",
    argPreset: "lookup",
    argInput: { requestId: "req-5" },
    signerAccountId: BOB_ID,
    spec,
    strictSignerCheck: true,
    transactionTtlMs: 45_000,
  });

  assert.deepEqual(payload, {
    Custom: {
      payload: {
        Propose: {
          account: CONTROLLER_ID,
          proposal_nonce: "12".repeat(32),
          instructions: [
            {
              ExecuteTrigger: {
                trigger: "staged_mint_request_hbl",
                args: {
                  request_id: "req-5",
                },
              },
            },
          ],
          transaction_ttl_ms: 45_000,
        },
      },
    },
  });
});

test("buildMultisigContractCallProposeRequest builds normalized Torii payloads", () => {
  const spec = sampleSpec();
  const payload = buildMultisigContractCallProposeRequest({
    proposalNonce: "12".repeat(32),
    multisigAccountAlias: "mintops@banka",
    signerAccountId: ALICE_ID,
    contractAlias: "apps_review::universal",
    entrypoint: "execute",
    trigger: "staged_mint_request_hbl",
    argPreset: "lifecycle",
    argInput: {
      action: "create",
      requestId: "req-6",
      toAccountId: BOB_ID,
      amountI64: 10,
    },
    multisigSpec: spec,
    strictSignerCheck: true,
    feePayment: authorityFeePayment(5),
  });

  assert.deepEqual(payload, {
    multisig_account_alias: "mintops@banka",
    proposal_nonce: "12".repeat(32),
    signer_account_id: ALICE_ID,
    contract_alias: "apps_review::universal",
    entrypoint: "execute",
    payload: {
      trigger: "staged_mint_request_hbl",
      args: {
        action: "create",
        request_id: "req-6",
        to_account_id: BOB_ID,
        amount_i64: 10,
      },
    },
    fee_payment: authorityFeePayment(5),
  });
});

test("contract-call propose builder rejects address-only targets and scalar payloads", () => {
  const request = {
    proposalNonce: "12".repeat(32),
    multisigAccountAlias: "mintops@banka",
    signerAccountId: ALICE_ID,
    contractAlias: "apps_review::universal",
    entrypoint: "execute",
    trigger: "review",
    args: { probe: true },
    feePayment: authorityFeePayment(5),
  };
  assert.throws(
    () => buildMultisigContractCallProposeRequest({ ...request, contractAlias: null }),
    /exact contractAlias/,
  );
  assert.throws(
    () => buildMultisigContractCallProposeRequest({ ...request, payload: "scalar" }),
    /payload/,
  );
});

test("buildMultisigContractCallApproveRequest normalizes selector and lookup keys", () => {
  const payload = buildMultisigContractCallApproveRequest({
    multisigAccountId: CONTROLLER_ID,
    signerAccountId: BOB_ID,
    proposalId: "12".repeat(32),
    instructionsHash: "aa".repeat(32),
    signatureB64: "AQ==",
    contract_alias: "apps_mint_request::sbp",
    entrypoint: "create_mint_request",
    payload: { amount: 111 },
    feePayment: authorityFeePayment(),
  });

  assert.deepEqual(payload, {
    multisig_account_id: CONTROLLER_ID,
    signer_account_id: BOB_ID,
    proposal_id: "12".repeat(32),
    instructions_hash: "aa".repeat(32),
    signature_b64: "AQ==",
    contract_alias: "apps_mint_request::sbp",
    entrypoint: "create_mint_request",
    payload: { amount: 111 },
    fee_payment: authorityFeePayment(),
  });
});

test("multisig contract-call request builders reject noncanonical signatureB64", () => {
  const canonicalSignature = canonicalSignatureBase64Fixture();
  for (const signatureB64 of [
    ` ${canonicalSignature} `,
    canonicalSignature.replace(/=+$/u, ""),
    noncanonicalStandardBase64PadBitAlias(canonicalSignature),
  ]) {
    assert.throws(
      () =>
        buildMultisigContractCallProposeRequest({
    proposalNonce: "12".repeat(32),
          multisigAccountAlias: "mintops@banka",
          signerAccountId: ALICE_ID,
          contractAlias: "apps_mint_request::sbp",
          entrypoint: "execute",
          trigger: "staged_mint_request_hbl",
          args: { request_id: "req-signature" },
          signatureB64,
          feePayment: authorityFeePayment(5),
        }),
      /exact standard-base64/,
    );
    assert.throws(
      () =>
        buildMultisigContractCallApproveRequest({
          multisigAccountId: CONTROLLER_ID,
          signerAccountId: BOB_ID,
          proposalId: "12".repeat(32),
    instructionsHash: "aa".repeat(32),
          signatureB64,
          feePayment: authorityFeePayment(),
        }),
      /exact standard-base64/,
    );
  }
});

test("multisig request builders reject inline private-key fields", () => {
  for (const field of [
    "privateKey",
    "private_key",
    "privateKeyHex",
    "private_key_bytes",
    "privateKeyMultihash",
    "private_key_algorithm",
  ]) {
    assert.throws(
      () =>
        buildMultisigContractCallProposeRequest({
    proposalNonce: "12".repeat(32),
          multisigAccountId: CONTROLLER_ID,
          signerAccountId: ALICE_ID,
          contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
          entrypoint: "execute",
          trigger: "staged_mint_request_hbl",
          args: { request_id: "req-7" },
          feePayment: authorityFeePayment(5),
          [field]: "secret",
        }),
      /does not accept private-key fields/,
    );
    assert.throws(
      () =>
        buildMultisigContractCallApproveRequest({
          multisig_account_id: CONTROLLER_ID,
          signer_account_id: BOB_ID,
          instructions_hash: "AA".repeat(32),
          fee_payment: authorityFeePayment(),
          [field]: "secret",
        }),
      /does not accept private-key fields/,
    );
  }
});
