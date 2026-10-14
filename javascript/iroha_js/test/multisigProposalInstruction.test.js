"use strict";

import test from "node:test";
import assert from "node:assert/strict";
import { ed25519 } from "@noble/curves/ed25519";

import {
  buildProposeMultisigInstruction,
  ValidationError,
  ValidationErrorCode,
} from "../src/index.js";
import { MultisigSpecBuilder } from "../src/multisig.js";
import { AccountAddress } from "../src/address.js";

const DOMAIN = "wonderland";
const deterministicPublicKey = (seedByte) =>
  Buffer.from(ed25519.getPublicKey(Buffer.alloc(32, seedByte)));
const ALICE_KEY = deterministicPublicKey(0x11);
const BOB_KEY = deterministicPublicKey(0x22);
const CONTROLLER_KEY = deterministicPublicKey(0x44);
const ALICE_ID = AccountAddress.fromAccount({ publicKey: ALICE_KEY }).toI105();
const BOB_ID = AccountAddress.fromAccount({ publicKey: BOB_KEY }).toI105();
const CONTROLLER_ID = AccountAddress.fromAccount({ publicKey: CONTROLLER_KEY,
}).toI105();

const sampleSpec = () =>
  new MultisigSpecBuilder()
    .setQuorum(2)
    .setTransactionTtlMs(60_000)
    .addSignatory(ALICE_ID, 1)
    .addSignatory(BOB_ID, 1)
    .build();

test("multisig propose builder enforces TTL cap", () => {
  const spec = sampleSpec();
  assert.throws(
    () =>
      buildProposeMultisigInstruction({
    proposalNonce: "12".repeat(32),
        accountId: CONTROLLER_ID,
        instructions: [{ Log: { Level: "INFO", message: "hello" } }],
        spec,
        transactionTtlMs: 120_000,
      }),
    (error) => error instanceof RangeError && /policy cap 60000/.test(error.message),
  );
});

test("multisig propose builder accepts TTL at or below cap", () => {
  const spec = sampleSpec();
  const payload = buildProposeMultisigInstruction({
    proposalNonce: "12".repeat(32),
    accountId: CONTROLLER_ID,
    instructions: [{ Log: { Level: "INFO", message: "hello" } }],
    spec,
    transactionTtlMs: 30_000,
  });

  assert.deepEqual(payload, {
    Custom: {
      payload: {
        Propose: {
          account: CONTROLLER_ID,
          proposal_nonce: "12".repeat(32),
          instructions: [{ Log: { Level: "INFO", message: "hello" } }],
          transaction_ttl_ms: 30_000,
        },
      },
    },
  });
});

test("multisig propose builder requires instructions", () => {
  const spec = sampleSpec();
  assert.throws(
    () =>
      buildProposeMultisigInstruction({
    proposalNonce: "12".repeat(32),
        accountId: CONTROLLER_ID,
        instructions: [],
        spec,
      }),
    (error) => error instanceof TypeError && /instructions/.test(error.message),
  );
});

test("multisig propose builder propagates domain drift", () => {
  const spec = new MultisigSpecBuilder()
    .setQuorum(2)
    .setTransactionTtlMs(60_000)
    .addSignatory(`${ALICE_ID}@banka.dataspace`, 1)
    .addSignatory(`${BOB_ID}@banka.dataspace`, 1)
    .build();
  assert.throws(
    () =>
      buildProposeMultisigInstruction({
    proposalNonce: "12".repeat(32),
        accountId: `${CONTROLLER_ID}@banka.dataspace`,
        instructions: [{ Log: { Level: "INFO", message: "hello" } }],
        spec,
      }),
    (error) =>
      error instanceof ValidationError &&
      error.code === ValidationErrorCode.INVALID_ACCOUNT_ID &&
      /must not include '@domain'/i.test(error.message),
  );
});
