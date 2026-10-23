"use strict";

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  AccountAddress,
  AccountAddressError,
  AccountAddressErrorCode,
  curveIdFromAlgorithm,
  decodeI105AccountAddress,
  encodeI105AccountAddress,
  inspectAccountId,
} from "../src/address.js";
import * as sourceAddressModule from "../src/address.js";
import {
  AccountAddress as DistAccountAddress,
  AccountAddressError as DistAccountAddressError,
  AccountAddressErrorCode as DistAccountAddressErrorCode,
} from "../dist/address.js";
import * as distAddressModule from "../dist/address.js";
import * as sourceCurveRegistry from "../src/curveRegistry.js";
import * as distCurveRegistry from "../dist/curveRegistry.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIXTURE_PATH = path.resolve(__dirname, "../../../fixtures/account/address_vectors.json");
const ML_DSA_FIXTURE_PATH = path.resolve(
  __dirname,
  "../../../fixtures/account/ml_dsa_public_key.hex",
);
const GOST256_FIXTURE_PATH = path.resolve(
  __dirname,
  "../../../fixtures/account/gost256a_public_key.hex",
);
const SECP256K1_FIXTURE_PATH = path.resolve(
  __dirname,
  "../../../fixtures/account/secp256k1_public_key.hex",
);
const BLS_NORMAL_FIXTURE_PATH = path.resolve(
  __dirname,
  "../../../fixtures/account/bls_normal_public_key.hex",
);
const BLS_SMALL_FIXTURE_PATH = path.resolve(
  __dirname,
  "../../../fixtures/account/bls_small_public_key.hex",
);

function hexToBytes(hex) {
  const body = hex.replace(/^0x/i, "");
  if (body.length % 2 !== 0) {
    throw new TypeError("hex string must have even length");
  }
  if (!/^[0-9a-fA-F]*$/.test(body)) {
    throw new TypeError("hex string must use [0-9a-fA-F] characters");
  }
  const out = new Uint8Array(body.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = parseInt(body.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}

const DEFAULT_PUBLIC_KEY = hexToBytes(
  "641297079357229F295938A4B5A333DE35069BF47B9D0704E45805713D13C201",
);
const DEFAULT_PUBLIC_KEY_I105 =
  "sorauﾛ1P5ﾁXEｴﾕGjgﾕﾚﾎﾕｸﾁEtﾀ3ﾂｺ2gALｺﾒefﾍ8DLgｾoCVGUYHS5";
const AMBIGUOUS_ED25519_PUBLIC_KEY = hexToBytes(
  "BC717326224E4B4119298E7B1DB8133CB27D6CDF6B3E04D75A6D27B29A34C1CF",
);
const AMBIGUOUS_ED25519_I105 =
  "sorauﾛ1PﾜdﾎｼﾋﾉNｸdﾁﾑkiﾇ3ｵﾓaPBQDTｲKqｼqｵrﾗｶwSQ1ﾌﾅQU61Y7";
const INVALID_I105_CHAR_LITERAL = `${DEFAULT_PUBLIC_KEY_I105.slice(0, -1)}!`;
const ALT_PUBLIC_KEY = hexToBytes(
  "3B77A042F1DE02F6D5F418F36A20FD68C8329FE3BBFBECD26A2D72878CD827F8",
);
const ML_DSA_PUBLIC_KEY = hexToBytes(fs.readFileSync(ML_DSA_FIXTURE_PATH, "utf8").trim());
const GOST256_PUBLIC_KEY = hexToBytes(fs.readFileSync(GOST256_FIXTURE_PATH, "utf8").trim());
const SECP256K1_PUBLIC_KEY = hexToBytes(fs.readFileSync(SECP256K1_FIXTURE_PATH, "utf8").trim());
const BLS_NORMAL_PUBLIC_KEY = hexToBytes(fs.readFileSync(BLS_NORMAL_FIXTURE_PATH, "utf8").trim());
const BLS_SMALL_PUBLIC_KEY = hexToBytes(fs.readFileSync(BLS_SMALL_FIXTURE_PATH, "utf8").trim());
const SM2_PUBLIC_KEY = hexToBytes(
  "04361255A512347E76EA947EBB416C12D4C07E30B150C0EC2047ECC5E142907499B8D99C4C5CF69BFF6527E7B67396B55E42EF98625B339696DBEF9A3AABBFC06F",
);
const MULTISIG_CANONICAL_HEX =
  "0x0a010100030003010001002068f4b6017d0f876a55c80a82b8388a54aad264d367269e2de8be079c935b5f9601000100207ea0e3bd52e207c9d3b0eba65c0704e66fca2d8e165a175218b174fc4160e4130100020020884b8857f4eaa1613c61504db34d4beaf346517a0e31de3cddd4d9b4201d9d0b";
const MULTISIG_CANONICAL_BYTES = hexToBytes(MULTISIG_CANONICAL_HEX);
const WRONG_CLASS_SINGLE_I105 =
  "sora3uｵﾔDﾗﾎmXヱ5uxbｻAｸiRB1vﾚｾｿvSHﾅﾕgﾚｼUFPPﾜinｳﾆﾓRSJS4M";

function singleKeyCanonicalBytes(tag, curve, publicKey, declaredLength = publicKey.length) {
  const lengthBytes =
    tag === 0x00
      ? [declaredLength]
      : [(declaredLength >> 8) & 0xff, declaredLength & 0xff];
  return Buffer.concat([
    Buffer.from([0x02, tag, curve, ...lengthBytes]),
    Buffer.from(publicKey),
  ]);
}

function oneMemberMultisigCanonicalBytes(curve, publicKey) {
  const length = publicKey.length;
  return Buffer.concat([
    Buffer.from([
      0x0a,
      0x01,
      0x01,
      0x00,
      0x01,
      0x00,
      0x01,
      curve,
      0x00,
      0x01,
      (length >> 8) & 0xff,
      length & 0xff,
    ]),
    Buffer.from(publicKey),
  ]);
}

test("the complete V1 curve registry is deterministic and has no mutable gate", () => {
  for (const registry of [sourceCurveRegistry, distCurveRegistry]) {
    assert.equal("CURVE_PUBLIC_KEY_LENGTH" in registry, false);
    assert.equal(Object.isFrozen(registry.CURVE_REGISTRY), true);
    assert.equal(
      registry.CURVE_REGISTRY.every((entry) => Object.isFrozen(entry)),
      true,
    );
  }
  for (const addressModule of [sourceAddressModule, distAddressModule]) {
    assert.equal("configureCurveSupport" in addressModule, false);
    const singleMlDsaAddress = addressModule.AccountAddress.fromAccount({
      publicKey: ML_DSA_PUBLIC_KEY,
      algorithm: "ml-dsa",
    });
    assert.ok(singleMlDsaAddress.toI105().startsWith("sora"));
    const mlDsaAddress = new addressModule.AccountAddress(
      { version: 0, classId: 1, normVersion: 1, extFlag: false },
      {
        tag: 1,
        version: 1,
        threshold: 1,
        members: [
          { curve: addressModule.curveIdFromAlgorithm("ml-dsa"), weight: 1, publicKey: ML_DSA_PUBLIC_KEY },
        ],
      },
    );
    assert.ok(mlDsaAddress.toI105().startsWith("sora"));
  }
});

test("ML-DSA single-key controllers use the canonical extended wire form", () => {
  for (const [label, addressModule] of [
    ["src", sourceAddressModule],
    ["dist", distAddressModule],
  ]) {
      const address = addressModule.AccountAddress.fromAccount({
        publicKey: ML_DSA_PUBLIC_KEY,
        algorithm: "ml-dsa",
      });
      const canonical = Buffer.from(address.canonicalBytes());
      assert.deepEqual(
        Array.from(canonical.subarray(0, 5)),
        [0x02, 0x02, 0x02, 0x07, 0xa0],
        `${label} emits header, extended tag, ML-DSA curve, and u16 length`,
      );
      assert.equal(canonical.length, 5 + ML_DSA_PUBLIC_KEY.length, `${label} wire length`);
      assert.deepEqual(
        canonical.subarray(5),
        Buffer.from(ML_DSA_PUBLIC_KEY),
        `${label} preserves the public key`,
      );

      const decoded = addressModule.AccountAddress.fromCanonicalBytes(canonical);
      assert.deepEqual(
        Buffer.from(decoded.canonicalBytes()),
        canonical,
        `${label} canonical round-trip`,
      );
      const i105 = address.toI105();
      const decodedI105 = addressModule.AccountAddress.fromI105(i105);
      assert.deepEqual(
        Buffer.from(decodedI105.canonicalBytes()),
        canonical,
        `${label} I105 canonical round-trip`,
      );
      assert.equal(decodedI105.toI105(), i105, `${label} I105 text round-trip`);
  }
});

test("canonical decoding rejects reserved headers and controller class mismatches", () => {
  for (const [label, addressModule] of [
    ["src", sourceAddressModule],
    ["dist", distAddressModule],
  ]) {
    const compactSingle = Buffer.from(
      addressModule.AccountAddress.fromAccount({ publicKey: DEFAULT_PUBLIC_KEY }).canonicalBytes(),
    );
    for (let version = 1; version <= 0b111; version += 1) {
      const reserved = Buffer.from(compactSingle);
      reserved[0] = (version << 5) | 0x02;
      assert.throws(
        () => addressModule.AccountAddress.fromCanonicalBytes(reserved),
        (error) =>
          error instanceof addressModule.AccountAddressError &&
          error.code === addressModule.AccountAddressErrorCode.INVALID_HEADER_VERSION,
        `${label} rejects reserved address version ${version}`,
      );
    }
    for (const normVersion of [0, 2, 3]) {
      const reserved = Buffer.from(compactSingle);
      reserved[0] = normVersion << 1;
      assert.throws(
        () => addressModule.AccountAddress.fromCanonicalBytes(reserved),
        (error) =>
          error instanceof addressModule.AccountAddressError &&
          error.code === addressModule.AccountAddressErrorCode.INVALID_NORM_VERSION,
        `${label} rejects reserved normalization version ${normVersion}`,
      );
    }

    const compactWrongClass = Buffer.from(compactSingle);
    compactWrongClass[0] = 0x0a;
    const multisigWrongClass = Buffer.from(MULTISIG_CANONICAL_BYTES);
    multisigWrongClass[0] = 0x02;
    for (const [name, canonical] of [
      ["compact single", compactWrongClass],
      ["multisig", multisigWrongClass],
    ]) {
      assert.throws(
        () => addressModule.AccountAddress.fromCanonicalBytes(canonical),
        (error) =>
          error instanceof addressModule.AccountAddressError &&
          error.code === addressModule.AccountAddressErrorCode.UNSUPPORTED_ADDRESS_FORMAT,
        `${label} rejects ${name} header/controller mismatch`,
      );
    }

      const extendedWrongClass = Buffer.from(
        addressModule.AccountAddress.fromAccount({
          publicKey: ML_DSA_PUBLIC_KEY,
          algorithm: "ml-dsa",
        }).canonicalBytes(),
      );
      extendedWrongClass[0] = 0x0a;
      assert.throws(
        () => addressModule.AccountAddress.fromCanonicalBytes(extendedWrongClass),
        (error) =>
          error instanceof addressModule.AccountAddressError &&
          error.code === addressModule.AccountAddressErrorCode.UNSUPPORTED_ADDRESS_FORMAT,
        `${label} rejects extended ML-DSA header/controller mismatch`,
      );

    assert.throws(
      () => addressModule.AccountAddress.fromI105(WRONG_CLASS_SINGLE_I105, 753),
      (error) =>
        error instanceof addressModule.AccountAddressError &&
        error.code === addressModule.AccountAddressErrorCode.UNSUPPORTED_ADDRESS_FORMAT,
      `${label} rejects checksum-valid wrong-class I105`,
    );

    assert.throws(
      () => new addressModule.AccountAddress(
        { version: 1, classId: 0, normVersion: 1, extFlag: false },
        { tag: 0, curve: 1, publicKey: DEFAULT_PUBLIC_KEY },
      ),
      (error) =>
        error instanceof addressModule.AccountAddressError &&
        error.code === addressModule.AccountAddressErrorCode.INVALID_HEADER_VERSION,
      `${label} public constructor cannot emit a reserved header`,
    );
  }
});

test("ML-DSA key validation rejects non-protocol shapes at shared address boundaries", () => {
  const invalidLengths = [32, 1_312, 1_951, 1_953, 2_592];
  for (const [label, addressModule] of [
    ["src", sourceAddressModule],
    ["dist", distAddressModule],
  ]) {
      for (const length of invalidLengths) {
        const publicKey = new Uint8Array(length).fill(0x5a);
        assert.throws(
          () =>
            addressModule.AccountAddress.fromAccount({
              publicKey,
              algorithm: "ml-dsa",
            }),
          (error) =>
            error instanceof addressModule.AccountAddressError &&
            error.code === addressModule.AccountAddressErrorCode.INVALID_PUBLIC_KEY,
          `${label} construction rejects ${length}-byte ML-DSA`,
        );

        const tag = length <= 0xff ? 0x00 : 0x02;
        const canonical = singleKeyCanonicalBytes(tag, 0x02, publicKey);
        assert.throws(
          () => addressModule.AccountAddress.fromCanonicalBytes(canonical),
          (error) =>
            error instanceof addressModule.AccountAddressError &&
            error.code === addressModule.AccountAddressErrorCode.INVALID_PUBLIC_KEY,
          `${label} decode rejects ${length}-byte ML-DSA`,
        );
      }

      const allZero = new Uint8Array(ML_DSA_PUBLIC_KEY.length);
      for (const [boundary, action] of [
        [
          "construction",
          () =>
            addressModule.AccountAddress.fromAccount({
              publicKey: allZero,
              algorithm: "ml-dsa",
            }),
        ],
        [
          "decode",
          () =>
            addressModule.AccountAddress.fromCanonicalBytes(
              singleKeyCanonicalBytes(0x02, 0x02, allZero),
            ),
        ],
        [
          "shared validator",
          () => addressModule.validatePublicKeyForCurve(0x02, allZero, "test public key"),
        ],
      ]) {
        assert.throws(
          action,
          (error) =>
            error instanceof addressModule.AccountAddressError &&
            error.code === addressModule.AccountAddressErrorCode.INVALID_PUBLIC_KEY &&
            /all-zero/u.test(error.message),
          `${label} ${boundary} rejects all-zero ML-DSA`,
        );
      }
  }
});

test("single-key and multisig wire decoders enforce canonical ML-DSA shapes", () => {
  for (const [label, addressModule] of [
    ["src", sourceAddressModule],
    ["dist", distAddressModule],
  ]) {
      const compactEd25519 = singleKeyCanonicalBytes(0x00, 0x01, DEFAULT_PUBLIC_KEY);
      assert.deepEqual(
        Buffer.from(
          addressModule.AccountAddress.fromCanonicalBytes(compactEd25519).canonicalBytes(),
        ),
        compactEd25519,
        `${label} retains the compact single-key form`,
      );

      const shortExtended = singleKeyCanonicalBytes(0x02, 0x01, DEFAULT_PUBLIC_KEY);
      assert.throws(
        () => addressModule.AccountAddress.fromCanonicalBytes(shortExtended),
        (error) =>
          error instanceof addressModule.AccountAddressError &&
          error.code === addressModule.AccountAddressErrorCode.INVALID_LENGTH &&
          /must exceed 255 bytes/u.test(error.message),
        `${label} rejects a short key encoded with the extended tag`,
      );

      const validMultisig = oneMemberMultisigCanonicalBytes(0x02, ML_DSA_PUBLIC_KEY);
      assert.deepEqual(
        Buffer.from(
          addressModule.AccountAddress.fromCanonicalBytes(validMultisig).canonicalBytes(),
        ),
        validMultisig,
        `${label} accepts a nonzero ML-DSA multisig member`,
      );

      const allZeroMultisig = oneMemberMultisigCanonicalBytes(
        0x02,
        new Uint8Array(ML_DSA_PUBLIC_KEY.length),
      );
      assert.throws(
        () => addressModule.AccountAddress.fromCanonicalBytes(allZeroMultisig),
        (error) =>
          error instanceof addressModule.AccountAddressError &&
          error.code === addressModule.AccountAddressErrorCode.INVALID_PUBLIC_KEY &&
          /all-zero/u.test(error.message),
        `${label} rejects an all-zero ML-DSA multisig member`,
      );
  }
});

test("multisig policies enforce core validation rules", () => {
  const mutateAndExpect = (mutator, expectedPolicyError) => {
    const mutated = Uint8Array.from(MULTISIG_CANONICAL_BYTES);
    mutator(mutated);
    assert.throws(
      () => AccountAddress.fromCanonicalBytes(mutated),
      (error) => {
        assert(error instanceof AccountAddressError);
        assert.equal(error.code, AccountAddressErrorCode.INVALID_MULTISIG_POLICY);
        assert.equal(error.details?.policyError, expectedPolicyError);
        return true;
      },
    );
  };

  mutateAndExpect((bytes) => {
    bytes[2] = 0x02;
  }, "UnsupportedVersion");

  mutateAndExpect((bytes) => {
    bytes[3] = 0x00;
    bytes[4] = 0x00;
  }, "ZeroThreshold");

  mutateAndExpect((bytes) => {
    bytes[8] = 0x00;
    bytes[9] = 0x00;
  }, "MemberWeightZero");

  mutateAndExpect((bytes) => {
    bytes[3] = 0x00;
    bytes[4] = 0x05;
  }, "ThresholdExceedsTotal");

  mutateAndExpect((bytes) => {
    bytes.set(bytes.subarray(49, 81), 86);
  }, "DuplicateMember");
});

test("account address golden vectors round-trip", () => {
  const address = AccountAddress.fromAccount({ publicKey: DEFAULT_PUBLIC_KEY,
  });

  const canonical = address.canonicalHex();
  const i105 = address.toI105();

  assert.equal(
    canonical,
    "0x02000120641297079357229f295938a4b5a333de35069bf47b9d0704e45805713d13c201",
  );
  assert.equal(i105, DEFAULT_PUBLIC_KEY_I105);

  const { address: parsedI105 } = AccountAddress.parseEncoded(i105, 753);
  assert.deepEqual(Buffer.from(parsedI105.canonicalBytes()), Buffer.from(address.canonicalBytes()));

  const { address: parsedAuto } = AccountAddress.parseEncoded(i105);
  assert.deepEqual(
    Buffer.from(parsedAuto.canonicalBytes()),
    Buffer.from(address.canonicalBytes()),
  );
});

test("decodeI105AccountAddress accepts live canonical I105 literals", () => {
  const address = AccountAddress.fromAccount({ publicKey: DEFAULT_PUBLIC_KEY,
  });
  const decoded = decodeI105AccountAddress(DEFAULT_PUBLIC_KEY_I105, {
    expectDiscriminant: 753,
  });
  assert.deepEqual(Buffer.from(decoded), Buffer.from(address.canonicalBytes()));
  const parsed = AccountAddress.fromI105(DEFAULT_PUBLIC_KEY_I105, 753);
  assert.equal(parsed.toI105(), DEFAULT_PUBLIC_KEY_I105);
});

test("mixed canonical I105 literals round-trip to the original ed25519 payload", () => {
  const address = AccountAddress.fromAccount({ publicKey: AMBIGUOUS_ED25519_PUBLIC_KEY,
  });
  assert.equal(address.canonicalHex(), "0x02000120bc717326224e4b4119298e7b1db8133cb27d6cdf6b3e04d75a6d27b29a34c1cf");
  assert.equal(address.toI105(), AMBIGUOUS_ED25519_I105);

  const decoded = decodeI105AccountAddress(AMBIGUOUS_ED25519_I105, {
    expectDiscriminant: 753,
  });
  assert.deepEqual(Buffer.from(decoded), Buffer.from(address.canonicalBytes()));

  const parsed = AccountAddress.fromI105(AMBIGUOUS_ED25519_I105, 753);
  assert.equal(parsed.toI105(), AMBIGUOUS_ED25519_I105);
});

test("parseEncoded rejects fullwidth-sentinel i105 literals", () => {
  const noncanonical = DEFAULT_PUBLIC_KEY_I105.replace(/^sora/, "ｓｏｒａ");
  assert.throws(
    () => AccountAddress.parseEncoded(noncanonical, 753),
    (error) =>
      error instanceof AccountAddressError &&
      error.code === AccountAddressErrorCode.UNSUPPORTED_ADDRESS_FORMAT,
  );
  assert.throws(
    () => decodeI105AccountAddress(noncanonical, { expectDiscriminant: 753 }),
    (error) =>
      error instanceof AccountAddressError &&
      error.code === AccountAddressErrorCode.UNSUPPORTED_ADDRESS_FORMAT,
  );
});

test("i105 format rejects noncanonical fullwidth kana payloads", () => {
  const noncanonical = DEFAULT_PUBLIC_KEY_I105.replace("ﾛ", "ロ");
  assert.throws(
    () => AccountAddress.fromI105(noncanonical, 753),
    (error) =>
      error instanceof AccountAddressError &&
      error.code === AccountAddressErrorCode.INVALID_I105_CHAR,
  );
});

test("account address rejects extension flag", () => {
  const address = AccountAddress.fromAccount({ publicKey: DEFAULT_PUBLIC_KEY,
  });
  const bytes = Uint8Array.from(address.canonicalBytes());
  bytes[0] |= 0x01;
  assert.throws(
    () => AccountAddress.fromCanonicalBytes(bytes),
    (error) => {
      assert(error instanceof AccountAddressError);
      assert.equal(error.code, AccountAddressErrorCode.UNEXPECTED_EXTENSION_FLAG);
      return true;
    },
  );
});

test("canonical address bytes honor binary views without coercing array entries", () => {
  const address = AccountAddress.fromAccount({ publicKey: DEFAULT_PUBLIC_KEY });
  const canonical = address.canonicalBytes();
  const arrayBuffer = canonical.buffer.slice(
    canonical.byteOffset,
    canonical.byteOffset + canonical.byteLength,
  );
  assert.equal(
    AccountAddress.fromCanonicalBytes(arrayBuffer).canonicalHex(),
    address.canonicalHex(),
  );

  const padded = new Uint8Array(canonical.length + 2);
  padded.set(canonical, 1);
  const view = new DataView(padded.buffer, 1, canonical.length);
  assert.equal(
    AccountAddress.fromCanonicalBytes(view).canonicalHex(),
    address.canonicalHex(),
  );

  assert.throws(
    () => AccountAddress.fromCanonicalBytes(Array.from(canonical, String)),
    /byte array entries must be integers between 0 and 255/,
  );
  assert.throws(
    () => AccountAddress.fromCanonicalBytes(address.canonicalHex()),
    /canonical address bytes must be binary data/,
  );
});

test("selector-prefixed noncanonical payloads are rejected", () => {
  const selectorFree = AccountAddress.fromAccount({ publicKey: DEFAULT_PUBLIC_KEY,
  });
  const baseCanonical = Array.from(selectorFree.canonicalBytes());
  const prefixedLocal = [baseCanonical[0], 0x01];
  for (let index = 0; index < 12; index += 1) {
    prefixedLocal.push(index + 1);
  }
  prefixedLocal.push(...baseCanonical.slice(1));

  assert.throws(
    () => AccountAddress.fromCanonicalBytes(Uint8Array.from(prefixedLocal)),
    (error) =>
      error instanceof AccountAddressError &&
      error.code === AccountAddressErrorCode.UNKNOWN_CURVE,
  );

  const literal = `0x${Buffer.from(prefixedLocal).toString("hex")}`;
  assert.throws(
    () => inspectAccountId(literal),
    (error) =>
      error instanceof AccountAddressError &&
      error.code === AccountAddressErrorCode.UNSUPPORTED_ADDRESS_FORMAT,
  );
});

test("parseEncoded rejects non-string address literals", () => {
  for (const input of [null, undefined, 42, {}, []]) {
    assert.throws(
      () => AccountAddress.parseEncoded(input),
      (error) =>
        error instanceof TypeError &&
        /address literal must be a string/.test(error.message),
    );
  }
});

test("parseEncoded rejects canonical hex literals", () => {
  const address = AccountAddress.fromAccount({ publicKey: DEFAULT_PUBLIC_KEY,
  });
  const canonical = address.canonicalHex();
  const rawHex = canonical.replace(/^0x/i, "");
  for (const literal of [canonical, rawHex, rawHex.toUpperCase()]) {
    assert.throws(
      () => AccountAddress.parseEncoded(literal),
      (error) =>
        error instanceof AccountAddressError &&
        error.code === AccountAddressErrorCode.UNSUPPORTED_ADDRESS_FORMAT,
    );
  }
});

test("displayFormats exposes immutable i105 UI hints", () => {
  const address = AccountAddress.fromAccount({
    publicKey: DEFAULT_PUBLIC_KEY,
  });
  const formats = address.displayFormats();
  assert.equal(formats.chainDiscriminant, 753);
  assert.equal(formats.i105, address.toI105(753));
  assert.equal(formats.i105Warning.length > 0, true);
  assert.throws(
    () => {
      formats.i105 = "mutated";
    },
    TypeError,
  );
});

test("fromAccount rejects unsupported domain and registryId options", () => {
  for (const unsupportedOptions of [
    { domain: "default", publicKey: DEFAULT_PUBLIC_KEY },
    { domain: "wonderland", publicKey: DEFAULT_PUBLIC_KEY },
    { registryId: 1, publicKey: DEFAULT_PUBLIC_KEY },
  ]) {
    assert.throws(
      () => AccountAddress.fromAccount(unsupportedOptions),
      (error) =>
        error instanceof TypeError &&
        /unsupported fields/.test(error.message),
    );
  }
});

test("AccountAddress exposes no domain-normalization compatibility API", () => {
  for (const addressModule of [sourceAddressModule, distAddressModule]) {
    assert.equal("canonicalizeDomainLabel" in addressModule, false);
    assert.equal("INVALID_DOMAIN_LABEL" in addressModule.AccountAddressErrorCode, false);
  }
});

test("fromAccount rejects control and Unicode-confusable curve algorithm aliases in src and dist", () => {
  const sdkVariants = [
    {
      AccountAddress,
      AccountAddressError,
      AccountAddressErrorCode,
    },
    {
      AccountAddress: DistAccountAddress,
      AccountAddressError: DistAccountAddressError,
      AccountAddressErrorCode: DistAccountAddressErrorCode,
    },
  ];
  const algorithms = [
    "",
    "   ",
    " ed25519",
    "ed25519 ",
    "\u00A0ed25519",
    "ed25519\u00A0",
    "\u2003ed25519",
    "ed25519\u2003",
    "future-curve",
    "ed 25519",
    "ed\t25519",
    "ed.25519",
    "ed/25519",
    "ed@25519",
    "ed#25519",
    "ed\u200B25519",
    "\u0435d25519",
    "secp256\u212A1",
    "ml\uFF0Ddsa",
    "MLDSA44",
    "MLDSA87",
    "gost256\u0430",
  ];

  for (const sdk of sdkVariants) {
    for (const algorithm of algorithms) {
      assert.throws(
        () => sdk.AccountAddress.fromAccount({ publicKey: DEFAULT_PUBLIC_KEY, algorithm }),
        (error) =>
          error instanceof sdk.AccountAddressError &&
          error.code === sdk.AccountAddressErrorCode.UNKNOWN_ALGORITHM,
      );
    }
  }
});

test("curve registry accepts only exact canonical V1 algorithm labels in src and dist", () => {
  for (const addressModule of [sourceAddressModule, distAddressModule]) {
    for (const [algorithm, curveId] of [
      ["ed25519", 1],
      ["ml-dsa", 2],
      ["bls_normal", 3],
      ["secp256k1", 4],
      ["bls_small", 5],
      ["gost3410-2012-256-paramset-a", 10],
      ["gost3410-2012-256-paramset-b", 11],
      ["gost3410-2012-256-paramset-c", 12],
      ["gost3410-2012-512-paramset-a", 13],
      ["gost3410-2012-512-paramset-b", 14],
      ["sm2", 15],
    ]) {
      assert.equal(addressModule.curveIdFromAlgorithm(algorithm), curveId);
      assert.equal(addressModule.curveIdToAlgorithm(curveId), algorithm);
    }
    for (const algorithm of [
      "ED25519",
      "ed-25519",
      "secp",
      "SECP256K1",
      "bls-normal",
      "BLS_NORMAL",
      "mldsa",
      "ml_dsa",
      "mldsa65",
      "ML-DSA-65",
      "gost256a",
      "gost512b",
      "GOST3410-2012-256-PARAMSET-A",
      "sm-2",
      "SM2",
    ]) {
      assert.throws(
        () => addressModule.curveIdFromAlgorithm(algorithm),
        (error) =>
          error instanceof addressModule.AccountAddressError &&
          error.code === addressModule.AccountAddressErrorCode.UNKNOWN_ALGORITHM,
        algorithm,
      );
    }
  }
});

test("fromAccount accepts buffer sources and rejects invalid hex strings", () => {
  const base = AccountAddress.fromAccount({ publicKey: DEFAULT_PUBLIC_KEY,
  });
  const arrayBuffer = DEFAULT_PUBLIC_KEY.buffer.slice(
    DEFAULT_PUBLIC_KEY.byteOffset,
    DEFAULT_PUBLIC_KEY.byteOffset + DEFAULT_PUBLIC_KEY.byteLength,
  );
  const asArrayBuffer = AccountAddress.fromAccount({ publicKey: arrayBuffer,
  });
  assert.deepEqual(
    Buffer.from(asArrayBuffer.canonicalBytes()),
    Buffer.from(base.canonicalBytes()),
  );
  const dataView = new DataView(arrayBuffer);
  const asDataView = AccountAddress.fromAccount({ publicKey: dataView,
  });
  assert.deepEqual(Buffer.from(asDataView.canonicalBytes()), Buffer.from(base.canonicalBytes()));

  for (const invalid of ["abc", "zz", "0x123g"]) {
    assert.throws(
      () =>
        AccountAddress.fromAccount({ publicKey: invalid,
        }),
      (error) => error instanceof TypeError && /hex string inputs/.test(error.message),
    );
  }
});

test("fromAccount rejects numeric arrays with out-of-range bytes", () => {
  const mutateAndExpect = (mutator) => {
    const bytes = Array(32).fill(1);
    mutator(bytes);
    assert.throws(
      () =>
        AccountAddress.fromAccount({ publicKey: bytes,
        }),
      (error) =>
        error instanceof TypeError &&
        /byte array entries must be integers between 0 and 255/.test(error.message),
    );
  };

  mutateAndExpect((bytes) => {
    bytes[0] = -1;
  });
  mutateAndExpect((bytes) => {
    bytes[0] = 256;
  });
  mutateAndExpect((bytes) => {
    bytes[0] = 1.5;
  });
  mutateAndExpect((bytes) => {
    bytes[0] = Number.NaN;
  });
  mutateAndExpect((bytes) => {
    // N.B. string inputs previously coerced to NaN; keep explicit coverage.
    bytes[0] = "a";
  });
});

test("displayFormats validates chain discriminant input", () => {
  const address = AccountAddress.fromAccount({ publicKey: DEFAULT_PUBLIC_KEY,
  });
  const coerced = address.displayFormats("753");
  assert.equal(coerced.chainDiscriminant, 753);
  assert.equal(coerced.i105, address.toI105(753));
  assert.throws(
    () => address.displayFormats("not-a-number"),
    (error) => {
      assert(error instanceof AccountAddressError);
      assert.equal(error.code, AccountAddressErrorCode.INVALID_I105_DISCRIMINANT);
      return true;
    },
  );
  assert.throws(
    () => address.displayFormats(null),
    (error) => error instanceof AccountAddressError &&
      error.code === AccountAddressErrorCode.INVALID_I105_DISCRIMINANT,
  );
});

test("every V1 curve round-trips without process-wide configuration", () => {
  for (const [algorithm, publicKey] of [
    ["secp256k1", SECP256K1_PUBLIC_KEY],
    ["gost3410-2012-256-paramset-a", GOST256_PUBLIC_KEY],
    ["sm2", SM2_PUBLIC_KEY],
    ["bls_normal", BLS_NORMAL_PUBLIC_KEY],
    ["bls_small", BLS_SMALL_PUBLIC_KEY],
  ]) {
    const address = AccountAddress.fromAccount({ publicKey, algorithm });
    const encoded = address.toI105();
    const { address: parsed } = AccountAddress.parseEncoded(encoded);
    assert.deepEqual(
      Buffer.from(parsed.canonicalBytes()),
      Buffer.from(address.canonicalBytes()),
      algorithm,
    );
  }
});

test("i105 helper exports mirror instance methods", () => {
  const address = AccountAddress.fromAccount({ publicKey: ALT_PUBLIC_KEY,
  });
  const canonicalBytes = address.canonicalBytes();
  const encoded = encodeI105AccountAddress(canonicalBytes);

  assert.equal(encoded, address.toI105());

  const decoded = decodeI105AccountAddress(encoded);

  assert.deepEqual(Buffer.from(decoded), Buffer.from(canonicalBytes));
});

test("decodeI105AccountAddress enforces string input", () => {
  for (const value of [null, undefined, 42, {}, [], Buffer.from("not-a-string")]) {
    assert.throws(
      () => decodeI105AccountAddress(value),
      (error) =>
        error instanceof TypeError &&
        /i105 address must be a string/.test(error.message),
    );
  }
});

test("encodeI105AccountAddress rejects invalid options", () => {
  const address = AccountAddress.fromAccount({ publicKey: DEFAULT_PUBLIC_KEY,
  });
  const canonicalBytes = address.canonicalBytes();
  for (const value of [null, [], "full"]) {
    assert.throws(
      () => encodeI105AccountAddress(canonicalBytes, value),
      (error) => error instanceof TypeError && /options must be an object/.test(error.message),
    );
  }
  assert.throws(
    () => encodeI105AccountAddress(canonicalBytes, { extra: true }),
    (error) =>
      error instanceof TypeError && /unsupported fields: extra/.test(error.message),
  );
  const rendered = encodeI105AccountAddress(canonicalBytes);
  assert.equal(rendered, address.toI105());
});

test("i105 prefix mismatch raises", () => {
  const address = AccountAddress.fromAccount({ publicKey: DEFAULT_PUBLIC_KEY,
  });
  const i105 = address.toI105(5);
  assert.throws(
    () => AccountAddress.parseEncoded(i105, 10),
    (error) => {
      assert(error instanceof AccountAddressError);
      assert.equal(error.code, AccountAddressErrorCode.UNEXPECTED_NETWORK_PREFIX);
      return true;
    },
  );
});

test("toI105 enforces prefix bounds and type", () => {
  const address = AccountAddress.fromAccount({ publicKey: ALT_PUBLIC_KEY,
  });
  for (const value of [-1, 0x1_0000, ""]) {
    assert.throws(
      () => address.toI105(value),
      (error) => error instanceof AccountAddressError &&
        error.code === AccountAddressErrorCode.INVALID_I105_DISCRIMINANT,
    );
  }
  assert.throws(
    () => address.toI105({ bad: true }),
    (error) => error instanceof AccountAddressError &&
      error.code === AccountAddressErrorCode.INVALID_I105_DISCRIMINANT,
  );
});

test("i105 format rejects characters outside the i105 alphabet", () => {
  assert.throws(
    () => AccountAddress.fromI105(INVALID_I105_CHAR_LITERAL),
    (error) =>
      error instanceof AccountAddressError &&
      error.code === AccountAddressErrorCode.INVALID_I105_CHAR,
  );
});

test("native codec propagates i105 errors", () => {
  assert.throws(
    () => AccountAddress.fromI105(INVALID_I105_CHAR_LITERAL),
    (error) => {
      assert(error instanceof AccountAddressError);
      assert.equal(error.code, AccountAddressErrorCode.INVALID_I105_CHAR);
      return true;
    },
  );
});

test("parseEncoded rejects malformed i105 literals", () => {
  const literal = INVALID_I105_CHAR_LITERAL;
  assert.throws(
    () => AccountAddress.parseEncoded(literal),
    (error) =>
      error instanceof AccountAddressError &&
      error.code === AccountAddressErrorCode.INVALID_I105_CHAR,
  );
});

test("inspectAccountId enforces option shape", () => {
  const address = AccountAddress.fromAccount({ publicKey: ALT_PUBLIC_KEY,
  });
  const literal = address.toI105();
  for (const options of [null, [], "prefix"]) {
    assert.throws(
      () => inspectAccountId(literal, options),
      (error) => error instanceof TypeError && /options must be an object/.test(error.message),
    );
  }
  assert.throws(
    () => inspectAccountId(literal, { foo: true }),
    (error) =>
      error instanceof TypeError &&
      /unsupported fields: foo/.test(error.message),
  );
  const inspected = inspectAccountId(literal, { expectDiscriminant: 753, chainDiscriminant: 753 });
  assert.equal(inspected.i105.chainDiscriminant, 753);
  assert.throws(
    () => inspectAccountId(literal, { chainDiscriminant: "bad" }),
    (error) =>
      error instanceof AccountAddressError &&
      error.code === AccountAddressErrorCode.INVALID_I105_DISCRIMINANT,
  );
});

test("inspectAccountId rejects invalid expectDiscriminant values", () => {
  const address = AccountAddress.fromAccount({ publicKey: ALT_PUBLIC_KEY,
  });
  const literal = address.toI105();
  for (const value of ["abc", [], {}, -1, 0x1_0000]) {
    assert.throws(
      () => inspectAccountId(literal, { expectDiscriminant: value }),
      (error) =>
        error instanceof AccountAddressError &&
        error.code === AccountAddressErrorCode.INVALID_I105_DISCRIMINANT,
    );
  }
  const inspected = inspectAccountId(literal, { expectDiscriminant: 753 });
  assert.equal(inspected.i105.chainDiscriminant, 753);
});

test("inspectAccountId preserves detected i105 prefix when rendering outputs", () => {
  const address = AccountAddress.fromAccount({ publicKey: ALT_PUBLIC_KEY,
  });
  const literal = address.toI105(7);
  const summary = inspectAccountId(literal);
  assert.equal(summary.i105.chainDiscriminant, 7);
  assert.equal(summary.i105.value, literal);

  const overridden = inspectAccountId(literal, { chainDiscriminant: 99 });
  assert.equal(overridden.i105.chainDiscriminant, 99);
  assert.equal(overridden.i105.value, address.toI105(99));
});

test("fromI105 normalizes expectedPrefix inputs", () => {
  const address = AccountAddress.fromAccount({ publicKey: ALT_PUBLIC_KEY,
  });
  const i105 = address.toI105(8);

  const parsedFromString = AccountAddress.fromI105(i105, "8");
  assert.equal(parsedFromString.toI105(8), i105);

  const { address: parsedFromBigint } = AccountAddress.parseEncoded(i105, 8n);
  assert.equal(parsedFromBigint.toI105(8), i105);

  assert.throws(
    () => AccountAddress.parseEncoded(i105, "9"),
    (error) =>
      error instanceof AccountAddressError &&
      error.code === AccountAddressErrorCode.UNEXPECTED_NETWORK_PREFIX,
  );
});

test("fromAccountId parses canonical account ids with an expected prefix", () => {
  const address = AccountAddress.fromAccount({ publicKey: ALT_PUBLIC_KEY,
  });
  const accountId = address.toI105(8);

  const parsed = AccountAddress.fromAccountId(accountId, "8");
  assert.equal(parsed.toI105(8), accountId);

  assert.throws(
    () => AccountAddress.fromAccountId(accountId, 9),
    (error) =>
      error instanceof AccountAddressError &&
      error.code === AccountAddressErrorCode.UNEXPECTED_NETWORK_PREFIX,
  );
});

test("account address compliance vectors", () => {
  const fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
  assert.equal(fixture.format_version, 1, "fixture format version");

  for (const vector of fixture.cases.positive) {
    const caseId = vector.case_id;
    const i105Vector = vector.encodings.i105;
    assert.ok(i105Vector, `${caseId}: missing i105 encoding fixture`);
    const fixtureI105Literal = i105Vector.string;
    let canonical;
    try {
      canonical = AccountAddress.fromI105(fixtureI105Literal, i105Vector.prefix);
    } catch (error) {
      if (
        error instanceof AccountAddressError &&
        vector.category === "multisig" &&
        error.code === AccountAddressErrorCode.INVALID_MULTISIG_POLICY
      ) {
        continue;
      }
      throw error;
    }
    const canonicalBytes = Buffer.from(canonical.canonicalBytes());
    const fixtureCanonicalBytes = Buffer.from(hexToBytes(vector.encodings.canonical_hex));
    assert.deepEqual(
      canonicalBytes,
      fixtureCanonicalBytes,
      `${caseId}: canonical fixture mismatch`,
    );

    // i105 round-trip
    assert.deepEqual(
      Buffer.from(canonical.canonicalBytes()),
      canonicalBytes,
      `${caseId}: i105 canonical mismatch`,
    );
    const { address: parsedI105 } = AccountAddress.parseEncoded(
      fixtureI105Literal,
      i105Vector.prefix,
    );
    assert.deepEqual(
      Buffer.from(parsedI105.canonicalBytes()),
      canonicalBytes,
      `${caseId}: i105 parse canonical mismatch`,
    );

    const decoded = AccountAddress.fromI105(fixtureI105Literal);
    assert.deepEqual(
      Buffer.from(decoded.canonicalBytes()),
      canonicalBytes,
      `${caseId}: i105 canonical mismatch`,
    );
    const { address: parsedCompressed } = AccountAddress.parseEncoded(fixtureI105Literal);
    assert.deepEqual(
      Buffer.from(parsedCompressed.canonicalBytes()),
      canonicalBytes,
      `${caseId}: i105 parse canonical mismatch`,
    );

    // Rendering parity
    assert.equal(
      canonical.toI105(i105Vector.prefix),
      fixtureI105Literal,
      `${caseId}: i105 re-encode mismatch`,
    );
    assert.equal(
      canonical.toI105(),
      fixtureI105Literal,
      `${caseId}: i105 re-encode mismatch`,
    );
    assert.equal(
      canonical.canonicalHex().toLowerCase(),
      vector.encodings.canonical_hex.toLowerCase(),
      `${caseId}: canonical hex re-encode mismatch`,
    );

    if (vector.controller?.kind === "multisig") {
      const info = canonical.multisigPolicyInfo();
      assert.ok(info, `${caseId}: expected multisig policy info`);
      if (vector.controller.digest_blake2b256_hex) {
        assert.ok(info.digestBlake2b256Hex, `${caseId}: expected multisig digest`);
        assert.equal(
          info.digestBlake2b256Hex.replace(/^0x/i, "").toUpperCase(),
          vector.controller.digest_blake2b256_hex.replace(/^0x/i, "").toUpperCase(),
          `${caseId}: controller digest mismatch`,
        );
      } else {
        assert.equal(
          info.digestBlake2b256Hex,
          null,
          `${caseId}: unexpected multisig digest present`,
        );
      }
    }
  }

  for (const vector of fixture.cases.negative) {
    const caseId = vector.case_id;
    switch (vector.format) {
      case "i105": {
        assert.throws(
          () => AccountAddress.fromI105(vector.input, vector.expected_prefix ?? fixture.default_network_prefix),
          (error) => matchesExpectedError(error, vector.expected_error, caseId),
        );
        break;
      }
      case "i105": {
        assert.throws(
          () => AccountAddress.fromI105(vector.input),
          (error) => matchesExpectedError(error, vector.expected_error, caseId),
        );
        break;
      }
      case "canonical_hex": {
        assert.throws(
          () => AccountAddress.parseEncoded(vector.input),
          (error) => matchesExpectedError(error, vector.expected_error, caseId),
        );
        break;
      }
      default:
        throw new Error(`${caseId}: unsupported negative format ${vector.format}`);
    }
  }
});

function matchesExpectedError(error, expected, caseId) {
  assert(error instanceof AccountAddressError, `${caseId}: unexpected error type ${error}`);
  const normalized = normalizeError(error);
  assert.equal(
    normalized.kind,
    expected.kind,
    `${caseId}: error kind mismatch (${normalized.kind} vs ${expected.kind})`,
  );
  if (normalized.kind === "UnexpectedNetworkPrefix") {
    if (normalized.expected !== undefined) {
      assert.equal(
        normalized.expected,
        expected.expected,
        `${caseId}: expected prefix mismatch`,
      );
    }
    if (normalized.found !== undefined) {
      assert.equal(normalized.found, expected.found, `${caseId}: found prefix mismatch`);
    }
  }
  if (normalized.kind === "InvalidMultisigPolicy") {
    assert.equal(
      normalized.policyError,
      expected.policy_error,
      `${caseId}: multisig policy error mismatch`,
    );
  }
  if (normalized.kind === "InvalidI105Char") {
    assert.equal(normalized.char, expected.char, `${caseId}: invalid character mismatch`);
  }
  return true;
}

function normalizeError(error) {
  switch (error.code) {
    case AccountAddressErrorCode.CHECKSUM_MISMATCH:
      return { kind: "ChecksumMismatch" };
    case AccountAddressErrorCode.INVALID_LENGTH:
      return { kind: "InvalidLength" };
    case AccountAddressErrorCode.INVALID_I105_CHAR:
      return { kind: "InvalidI105Char", char: error.details?.char };
    case AccountAddressErrorCode.UNEXPECTED_NETWORK_PREFIX:
      return {
        kind: "UnexpectedNetworkPrefix",
        expected: error.details?.expected,
        found: error.details?.found,
      };
    case AccountAddressErrorCode.UNSUPPORTED_ADDRESS_FORMAT:
      return { kind: "UnsupportedAddressFormat" };
    case AccountAddressErrorCode.UNEXPECTED_TRAILING_BYTES:
      return { kind: "UnexpectedTrailingBytes" };
    case AccountAddressErrorCode.INVALID_MULTISIG_POLICY:
      return { kind: "InvalidMultisigPolicy", policyError: error.details?.policyError };
    case AccountAddressErrorCode.UNKNOWN_CURVE:
      return { kind: "UnknownCurve" };
    default:
      throw new Error(`unhandled AccountAddressError code: ${error.code}`);
  }
}
