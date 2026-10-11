import { test as baseTest } from "node:test";
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import {
  buildRegisterAssetDefinitionInstruction,
} from "../src/instructionBuilders.js";
import * as instructionBuilderExports from "../src/instructionBuilders.js";
import { AccountAddress } from "../src/address.js";
import {
  noritoDecodeInstruction,
  noritoEncodeInstruction,
} from "../src/norito.js";
import {
  makeNativeTest,
  nativeBinding,
  noritoRequiredMethods,
} from "./helpers/native.js";
import { withNativeInstructionCodec } from "./helpers/instructionCodec.js";

const test = makeNativeTest(baseTest, { require: noritoRequiredMethods });
const descriptorTest = baseTest;
const SORA_I105_DISCRIMINANT = 0x2f1;
const ACCOUNT_SIGNATORY =
  "ED0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03";
const ACCOUNT_ADDRESS = AccountAddress.fromAccount({
  publicKey: Buffer.from(ACCOUNT_SIGNATORY.slice(6), "hex"),
});
const ACCOUNT_ID_INPUT = ACCOUNT_ADDRESS.toI105(SORA_I105_DISCRIMINANT);
const ASSET_DEFINITION_ID = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
const RETIRED_GENERIC_CONFIDENTIAL_VARIANTS = Object.freeze([
  ["Shi", "eld"].join(""),
  ["Zk", "Transfer"].join(""),
  ["Un", "shield"].join(""),
]);

function proofAttachment(verifyingKeyName) {
  return {
    backend: "pipa-r/pasta",
    proof: {
      backend: "pipa-r/pasta",
      bytes: Array.from(Buffer.from("proof")),
    },
    vk_ref: { backend: "pipa-r/pasta", name: verifyingKeyName },
  };
}

function retiredInstruction(variant) {
  let payload;
  switch (variant) {
    case RETIRED_GENERIC_CONFIDENTIAL_VARIANTS[0]:
      payload = {
        asset: ASSET_DEFINITION_ID,
        from: ACCOUNT_ID_INPUT,
        amount: "1",
        note_commitment: Array(32).fill(0x11),
        enc_payload: {
          version: 1,
          ephemeral_pubkey: Array(32).fill(0x22),
          nonce: Array(24).fill(0x33),
          ciphertext: Buffer.from("ciphertext").toString("base64"),
        },
      };
      break;
    case RETIRED_GENERIC_CONFIDENTIAL_VARIANTS[1]:
      payload = {
        asset: ASSET_DEFINITION_ID,
        inputs: [Array(32).fill(0x44)],
        outputs: [Array(32).fill(0x55)],
        proof: proofAttachment("vk_transfer"),
        root_hint: null,
      };
      break;
    case RETIRED_GENERIC_CONFIDENTIAL_VARIANTS[2]:
      payload = {
        asset: ASSET_DEFINITION_ID,
        to: ACCOUNT_ID_INPUT,
        public_amount: "1",
        inputs: [Array(32).fill(0x66)],
        proof: proofAttachment("vk_unshield"),
        root_hint: null,
      };
      break;
    default:
      throw new Error(`unknown retired confidential instruction ${variant}`);
  }
  return { zk: { [variant]: payload } };
}

function namedImportDataUrl(builderName) {
  const moduleUrl = new URL("../src/instructionBuilders.js", import.meta.url).href;
  const source = `import { ${builderName} } from ${JSON.stringify(moduleUrl)};`;
  return `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
}

function assertRetiredInstructionRejected(operation, variant) {
  assert.throws(operation, (error) => {
    assert.equal(error?.name, "TypeError", variant);
    assert.equal(
      error?.message,
      `zk.${variant} is retired in ABI V1`,
      variant,
    );
    return true;
  });
}

function canonicalizeValue(value) {
  if (Array.isArray(value)) return value.map(canonicalizeValue);
  if (value && typeof value === "object") {
    if ("Zk" in value && !("zk" in value)) {
      value.zk = canonicalizeValue(value.Zk);
      delete value.Zk;
    }
    for (const key of Object.keys(value)) value[key] = canonicalizeValue(value[key]);
  }
  return value;
}

function canonicalizeClone(value) {
  return canonicalizeValue(JSON.parse(JSON.stringify(value)));
}

function encodeAndDecode(instruction) {
  return canonicalizeValue(
    noritoDecodeInstruction(noritoEncodeInstruction(instruction, 753), 753),
  );
}

const LEGACY_UNSHIELD_WITH_OUTPUT_WIRE_BASE64 = [
  "TlJUMAAAhip9dwddTSP/bBJh2wJ4EQCxAQAAAAAAACBu70EtkU8QAiQjaXJvaGFfZGF0YV9tb2RlbDo6aXNpOjp6",
  "azo6VW5zaGllbGSKA4IBAAAAAAAATlJUMAAAHLVezH/ZJiWyvuM+SRpKDABSAQAAAAAAAGVNTsPtTT6lAgAAAAAA",
  "AAAAIAFoAXIBRQFOAZwBBAFGAUEBqgFYAR4BxQHzAYABFgEZTwAAAABKIQAAAAAAAAABAAHOAX8BpAFsAZ0BzgF+",
  "AaQBsQElAeIB4wFrAdsBYwHqATMBBwE+AXUBkAGsAZIBgQFqAeEB6AFhAbcBBAGLAQMLBQEAAAABBAAAAABJAQAA",
  "AAAAAABAAREBEQERAREBEQERAREBEQERAREBEQERAREBEQERAREBEQERAREBEQERAREBEQERAREBEQERAREBEQER",
  "AREBEQERAREBEUkBAAAAAAAAAEABIgEiASIBIgEiASIBIgEiASIBIgEiASIBIgEiASIBIgEiASIBIgEiASIBIgEi",
  "ASIBIgEiASIBIgEiASIBIgEiASIBIgEiPgoJaGFsbzIvaXBhGQoJaGFsbzIvaXBhDQUAAAAAAAAAcHJvb2YYCglo",
  "YWxvMi9pcGEMC3ZrX3Vuc2hpZWxkAQA=",
].join("");
test("buildRegisterAssetDefinitionInstruction preserves alias metadata", () => {
  const instruction = buildRegisterAssetDefinitionInstruction({
    assetDefinitionId: ASSET_DEFINITION_ID,
    name: "demo",
    description: "Demo settlement PoC asset",
    alias: "demo#settlement.main",
    scale: 2,
    metadata: { purpose: "poc" },
    owningDomain: null,
    balanceScopePolicy: "Global",
  });
  assert.deepEqual(instruction, {
    Register: {
      AssetDefinition: {
        id: ASSET_DEFINITION_ID,
        name: "demo",
        description: "Demo settlement PoC asset",
        alias: "demo#settlement.main",
        spec: { scale: 2 },
        mintable: "Infinitely",
        logo: null,
        metadata: { purpose: "poc" },
        balance_scope_policy: "Global",
        owning_domain: null,
      },
    },
  });
  assert.deepEqual(encodeAndDecode(instruction), canonicalizeClone(instruction));
  assert.equal(
    buildRegisterAssetDefinitionInstruction({
      assetDefinitionId: ASSET_DEFINITION_ID,
      name: "é".repeat(64),
      owningDomain: null,
      balanceScopePolicy: "Global",
    }).Register.AssetDefinition.name,
    "é".repeat(64),
  );
  for (const name of [
    undefined,
    "",
    " demo ",
    "demo#settlement",
    "demo@settlement",
    "demo\nsettlement",
    "é".repeat(65),
  ]) {
    assert.throws(
      () =>
        buildRegisterAssetDefinitionInstruction({
          assetDefinitionId: ASSET_DEFINITION_ID,
          name,
          owningDomain: null,
          balanceScopePolicy: "Global",
        }),
      /registerAssetDefinition\.name must /u,
    );
  }
  assert.throws(
    () =>
      buildRegisterAssetDefinitionInstruction({
        assetDefinitionId: ASSET_DEFINITION_ID,
        name: "\uD800",
        owningDomain: null,
        balanceScopePolicy: "Global",
      }),
    /unpaired UTF-16 surrogates/u,
  );
  assert.throws(
    () =>
      buildRegisterAssetDefinitionInstruction({
        assetDefinitionId: ASSET_DEFINITION_ID,
      }),
    /owningDomain is required/u,
  );
  assert.throws(
    () =>
      buildRegisterAssetDefinitionInstruction({
        assetDefinitionId: ASSET_DEFINITION_ID,
        owningDomain: null,
      }),
    /balanceScopePolicy is required/u,
  );
  assert.throws(
    () =>
      buildRegisterAssetDefinitionInstruction({
        assetDefinitionId: ASSET_DEFINITION_ID,
        name: "demo",
        owningDomain: null,
        balanceScopePolicy: "Global",
        confidentialPolicy: { mode: "TransparentOnly" },
      }),
    /cannot carry confidential policy/u,
  );
});

descriptorTest("retired confidential builders are absent from runtime and declarations", async () => {
  const declarations = readFileSync(new URL("../index.d.ts", import.meta.url), "utf8");
  const noritoSource = readFileSync(new URL("../src/norito.js", import.meta.url), "utf8");

  for (const variant of RETIRED_GENERIC_CONFIDENTIAL_VARIANTS) {
    const builderName = ["build", variant, "Instruction"].join("");
    const inputTypeName = [variant, "InstructionInput"].join("");
    const wireId = ["iroha_data_model::isi::zk::", variant].join("");
    assert.equal(
      Object.hasOwn(instructionBuilderExports, builderName),
      false,
      `${builderName} runtime export`,
    );
    assert.doesNotMatch(
      declarations,
      new RegExp(`\\bexport\\s+function\\s+${builderName}\\b`, "u"),
      `${builderName} declaration`,
    );
    assert.doesNotMatch(
      declarations,
      new RegExp(`\\bexport\\s+(?:interface|type)\\s+${inputTypeName}\\b`, "u"),
      `${inputTypeName} declaration`,
    );
    assert.equal(noritoSource.includes(wireId), false, `${wireId} codec discriminant`);

    await assert.rejects(import(namedImportDataUrl(builderName)), (error) => {
      assert.equal(error?.name, "SyntaxError", builderName);
      assert.match(String(error?.message), /does not provide an export named/u, builderName);
      assert.match(String(error?.message), new RegExp(`\\b${builderName}\\b`, "u"));
      return true;
    });
  }
});

descriptorTest("public native instruction adapters reject every retired confidential instruction", () => {
  for (const variant of RETIRED_GENERIC_CONFIDENTIAL_VARIANTS) {
    const instruction = retiredInstruction(variant);
    assertRetiredInstructionRejected(
      () => noritoEncodeInstruction(instruction, 753),
      variant,
    );
    assertRetiredInstructionRejected(
      () => withNativeInstructionCodec(({ noritoEncodeInstruction }) =>
        noritoEncodeInstruction(instruction, 753)),
      variant,
    );
  }

  assert.throws(
    () =>
      withNativeInstructionCodec(({ noritoDecodeInstruction }) =>
        noritoDecodeInstruction(
          Buffer.from(LEGACY_UNSHIELD_WITH_OUTPUT_WIRE_BASE64, "base64"), 753,
        ),
      ),
    { message: "length mismatch" },
  );
});

test("native codec rejects every retired confidential instruction", () => {
  for (const variant of RETIRED_GENERIC_CONFIDENTIAL_VARIANTS) {
    assert.throws(
      () =>
        nativeBinding.noritoEncodeInstruction(
          JSON.stringify(retiredInstruction(variant)), 753,
        ),
      /unsupported zk instruction variant/u,
      variant,
    );
  }
  assert.throws(
    () =>
      nativeBinding.noritoDecodeInstruction(
        Buffer.from(LEGACY_UNSHIELD_WITH_OUTPUT_WIRE_BASE64, "base64"), 753,
      ),
    /decode|canonical|trailing|field|length mismatch|not registered|unknown instruction/u,
  );
});
