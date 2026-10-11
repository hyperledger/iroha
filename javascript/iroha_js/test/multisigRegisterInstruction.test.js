"use strict";

import test from "node:test";
import assert from "node:assert/strict";
import { ed25519 } from "@noble/curves/ed25519";

import {
  buildRegisterMultisigInstruction,
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

test("multisig register builder accepts encoded-only controller/signatory ids", () => {
  const spec = new MultisigSpecBuilder()
    .setQuorum(2)
    .setTransactionTtlMs(60_000)
    .addSignatory(ALICE_ID, 1)
    .addSignatory(BOB_ID, 1)
    .build();

  const payload = buildRegisterMultisigInstruction({
    accountId: CONTROLLER_ID,
    spec,
  });

  assert.deepEqual(payload, {
    Custom: {
      payload: {
        Register: {
          account: CONTROLLER_ID,
          spec: spec.toPayload(),
          uaid: null,
        },
      },
    },
  });
});

test("multisig register builder rejects domain-qualified account literals", () => {
  const spec = new MultisigSpecBuilder()
    .setQuorum(1)
    .setTransactionTtlMs(10_000)
    .addSignatory(`${ALICE_ID}@banka.dataspace`, 1)
    .build();

  assert.throws(
    () =>
      buildRegisterMultisigInstruction({
        accountId: `${CONTROLLER_ID}@banka.dataspace`,
        spec,
      }),
    (error) =>
      error instanceof ValidationError &&
      error.code === ValidationErrorCode.INVALID_ACCOUNT_ID &&
      /must not include '@domain'/i.test(error.message),
  );
});
