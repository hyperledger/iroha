import test from "node:test";
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";

import { AccountAddress } from "../src/address.js";
import { isCanonicalGovernanceSelectorV1 } from "../src/governanceSelector.js";
import { _createNoritoInstructionApi } from "../src/norito.js";
import { createNativeRuntime } from "../src/nativeRuntime.js";
import { nativeBinding } from "./helpers/native.js";

const TEST_ACCOUNT = AccountAddress.fromAccount({
  publicKey: Buffer.from(
    "CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
    "hex",
  ),
}).toI105(0x2f1);

const VALID_SELECTORS = ["a", "a".repeat(128)];
const INVALID_SELECTORS = [
  ["empty", ""],
  ["dot segment", "."],
  ["leading dot", ".hidden"],
  ["slash", "a/b"],
  ["percent escape", "a%2Fb"],
  ["whitespace", "a b"],
  ["control", "a\0b"],
  ["Unicode", "投票"],
  ["129 bytes", "a".repeat(129)],
];

function proofAttachment(name) {
  return {
    backend: "pipa-r/pasta",
    proof: { backend: "pipa-r/pasta", bytes: [1] },
    vk_ref: { backend: "pipa-r/pasta", name },
    vk_commitment: null,
    envelope_hash: null,
    lane_privacy: null,
  };
}

const SELECTOR_INSTRUCTIONS = [
  [
    "CastZkBallot",
    (selector) => ({
      CastZkBallot: {
        election_id: selector,
        proof_b64: "AQ==",
        public_inputs_json: "{}",
      },
    }),
  ],
  [
    "CastPlainBallot",
    (selector) => ({
      CastPlainBallot: {
        referendum_id: selector,
        owner: TEST_ACCOUNT,
        amount: "1",
        duration_blocks: 1,
        direction: 0,
      },
    }),
  ],
  [
    "UpdatePlainConviction",
    (selector) => ({
      UpdatePlainConviction: {
        referendum_id: selector,
        owner: TEST_ACCOUNT,
        amount: "1",
        duration_blocks: 1,
      },
    }),
  ],
  [
    "CreateElection",
    (selector) => ({
      zk: {
        CreateElection: {
          election_id: selector,
          options: 2,
          eligible_root: new Array(32).fill(0x11),
          start_ts: 1,
          end_ts: 2,
          vk_ballot: { backend: "pipa-r/pasta", name: "vk_ballot" },
          vk_tally: { backend: "pipa-r/pasta", name: "vk_tally" },
          domain_tag: "governance",
        },
      },
    }),
  ],
  [
    "SubmitBallot",
    (selector) => ({
      zk: {
        SubmitBallot: {
          election_id: selector,
          ciphertext: [1],
          ballot_proof: proofAttachment("vk_ballot"),
          nullifier: new Array(32).fill(0x22),
        },
      },
    }),
  ],
  [
    "FinalizeElection",
    (selector) => ({
      zk: {
        FinalizeElection: {
          election_id: selector,
          tally: [1, 0],
          tally_proof: proofAttachment("vk_tally"),
        },
      },
    }),
  ],
];

function instructionEncoder(binding) {
  return _createNoritoInstructionApi(
    createNativeRuntime(binding),
  ).noritoEncodeInstruction;
}

test("governance selector grammar accepts 1 and 128 ASCII bytes", () => {
  for (const selector of VALID_SELECTORS) {
    assert.equal(isCanonicalGovernanceSelectorV1(selector), true, selector.length);
  }
  for (const [label, selector] of INVALID_SELECTORS) {
    assert.equal(isCanonicalGovernanceSelectorV1(selector), false, label);
  }
});

test("raw governance instructions reject noncanonical selectors before dispatch", () => {
  for (const nativeMode of ["accepting owner", "rejecting owner"]) {
    let nativeCalls = 0;
    const binding = {
      noritoEncodeInstruction() {
        nativeCalls += 1;
        if (nativeMode === "rejecting owner") {
          throw new Error("unsupported instruction");
        }
        return Buffer.from([0]);
      },
    };
    const noritoEncodeInstruction = instructionEncoder(binding);
    for (const [instructionName, instruction] of SELECTOR_INSTRUCTIONS) {
      for (const [selectorLabel, selector] of INVALID_SELECTORS) {
        for (const representation of ["object", "JSON text"]) {
          const payload = instruction(selector);
          const input = representation === "object" ? payload : JSON.stringify(payload);
          assert.throws(
            () => noritoEncodeInstruction(input, 753),
            /must be 1-128 RFC 3986 unreserved ASCII characters/u,
            `${nativeMode} ${instructionName} ${selectorLabel} ${representation}`,
          );
          assert.equal(
            nativeCalls,
            0,
            `${nativeMode} dispatched ${instructionName} ${selectorLabel} ${representation}`,
          );
        }
      }
    }
  }
});

test("valid selector boundary lengths reach the selected native owner", () => {
  let nativeCalls = 0;
  const noritoEncodeInstruction = instructionEncoder(
    {
      noritoEncodeInstruction(json, prefix) {
        nativeCalls += 1;
        assert.equal(prefix, 753);
        return Buffer.from(json);
      },
    },
  );
  for (const selector of VALID_SELECTORS) {
    for (const [instructionName, instruction] of SELECTOR_INSTRUCTIONS) {
      const encoded = noritoEncodeInstruction(instruction(selector), 753);
      assert.ok(encoded.length > 0, `${instructionName} ${selector.length}`);
    }
  }
  assert.equal(nativeCalls, VALID_SELECTORS.length * SELECTOR_INSTRUCTIONS.length);
});

test("raw conviction updates reject an injected choice before native dispatch", () => {
  let nativeCalls = 0;
  const encode = instructionEncoder({
    noritoEncodeInstruction() {
      nativeCalls += 1;
      return Buffer.from([0]);
    },
  });
  const update = SELECTOR_INSTRUCTIONS.find(([name]) => name === "UpdatePlainConviction")[1]("ref-2");
  update.UpdatePlainConviction.direction = 1;
  for (const input of [update, JSON.stringify(update)]) {
    assert.throws(() => encode(input, 753), /UpdatePlainConviction.*direction/u);
  }
  assert.equal(nativeCalls, 0);
});

// Native ProofAttachment JSON is a complete six-field record. An absent
// optional value is explicit null; omitting the field is not another shape.
test("raw election proofs require every nullable attachment field", () => {
  for (const name of ["SubmitBallot", "FinalizeElection"]) {
    const instruction = SELECTOR_INSTRUCTIONS.find(([key]) => key === name)[1];
    const proofField = name === "SubmitBallot" ? "ballot_proof" : "tally_proof";
    for (const field of ["vk_commitment", "envelope_hash", "lane_privacy"]) {
      const payload = instruction("a");
      delete payload.zk[name][proofField][field];
      assert.throws(
        () => nativeBinding.noritoEncodeInstruction(JSON.stringify(payload), 753),
        { name: "Error", message: `JSON error: missing field \`${field}\`` },
        `${name}.${proofField}.${field}`,
      );
    }
  }
});
