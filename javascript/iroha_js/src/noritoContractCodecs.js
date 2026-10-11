import { normalizeContractEventsV1 } from "./contractDeclarations.js";
import { normalizeEntrypointAuthorizationV1, normalizeContractPermissionsV1, validateManifestEntrypointIdentityV1, validateManifestDeclarationsV1 } from "./contractManifestRules.js";
import { normalizeContractErrorTypeV1, normalizeContractErrorMessagesV1, normalizeContractEnumTypeV1, normalizeContractEnumTypesV1, validateManifestErrorTypeBindingsV1 } from "./contractErrorTypes.js";
import { createNoritoRecordDecoder, createNoritoRecordEncoder } from "./noritoRecordDecoder.js";
import { rejectError, rejectRange, rejectType } from "./validationThrow.js";
import { Buffer } from "buffer";
import {
  BASE64_ENCODING,
  HEX_ENCODING,
  JS_TYPE_STRING,
} from "./commonLiterals.js";
import { analyzeEntrypointValueTypeV1, MAX_ENTRYPOINT_CALL_TABLE_WORDS_V1 } from "./entrypointSchema.js";

/** Bind Merkle proof codecs independently of confidential memo envelopes. */
export function createNoritoMerkleProofCodecs(
  LANE_PRIVACY_MERKLE_MAX_DEPTH, decodeHashValue, decodeNoritoVec,
  decodeOptionValue, decodeTupleFields, decodeU32Value, encodeHashLiteralBytes,
  encodeNoritoVec, encodeOptionValue, encodeTupleValue, encodeU32Value,
) {
  function encodeMerkleProofValue(value, context) {
    return encodeTupleValue([
      encodeU32Value(value.leaf_index ?? value.leafIndex, `${context}.leaf_index`),
      encodeNoritoVec(value.audit_path ?? value.auditPath ?? [], (entry, index) =>
        encodeOptionValue(
          entry,
          encodeHashLiteralBytes,
          `${context}.audit_path[${index}]`,
        ),
      ),
    ]);
  }

  function decodeMerkleProofValue(payload, context) {
    const fields = decodeTupleFields(payload, context, ["leaf_index", "audit_path"]);
    return {
      leaf_index: decodeU32Value(fields.leaf_index, `${context}.leaf_index`),
      audit_path: decodeNoritoVec(
        fields.audit_path,
        (entry, index) =>
          decodeOptionValue(
            entry,
            decodeHashValue,
            `${context}.audit_path[${index}]`,
          ),
        `${context}.audit_path`,
        LANE_PRIVACY_MERKLE_MAX_DEPTH,
      ),
    };
  }

  return [encodeMerkleProofValue, decodeMerkleProofValue];
}

/** Bind confidential memo codecs independently of instruction proofs. */
export function createNoritoConfidentialMemoCodecs(
  BufferReader, decodeUnsignedLeb128, encodeCompactLength, encodeFixedBytesValue,
  encodeU8Value, isPlainObject, normalizeFlexibleBytes,
) {
  const CONFIDENTIAL_MEMO_WIRE_MAGIC_V1 = Buffer.from([
    0x49, 0x52, 0x48, 0x43, 0x4d, 0x31, 0xa5, 0x5a,
  ]);
  const CONFIDENTIAL_MEMO_RECIPIENT_SLOTS_V1 = 8;
  const CONFIDENTIAL_MEMO_NONCE_BYTES_V1 = 24;
  const CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1 = 48;
  const CONFIDENTIAL_MEMO_TAG_BYTES_V1 = 16;
  const CONFIDENTIAL_MEMO_MAX_CIPHERTEXT_BYTES_V1 = 64 * 1024;
  const CONFIDENTIAL_MEMO_SUITES_V1 = Object.freeze({
    "ml-kem-768-xchacha20-poly1305-v1": Object.freeze({
      tag: 0,
      encapsulationBytes: 1088,
    }),
    "ml-kem-1024-xchacha20-poly1305-v1": Object.freeze({
      tag: 1,
      encapsulationBytes: 1568,
    }),
  });

  function assertExactObjectKeys(value, expected, context) {
    if (!isPlainObject(value)) {
      rejectType(`${context} must be an object`);
    }
    const expectedSet = new Set(expected);
    for (const key of Object.keys(value)) {
      if (!expectedSet.has(key)) {
        rejectType(`${context} contains unknown field ${key}`);
      }
    }
    for (const key of expected) {
      if (!Object.prototype.hasOwnProperty.call(value, key)) {
        rejectType(`${context}.${key} is required`);
      }
    }
  }

  function requireNonzero(bytes, context) {
    if (bytes.every((byte) => byte === 0)) {
      rejectError(`${context} must not be all zero`);
    }
    return bytes;
  }

  function confidentialMemoSuite(label, context) {
    if (typeof label !== JS_TYPE_STRING) {
      rejectType(`${context} must be a canonical confidential memo suite label`);
    }
    const suite = CONFIDENTIAL_MEMO_SUITES_V1[label];
    if (suite === undefined) {
      rejectError(`${context} uses unsupported confidential memo suite ${label}`);
    }
    return suite;
  }

  function confidentialMemoSuiteFromTag(tag, context) {
    for (const [label, suite] of Object.entries(CONFIDENTIAL_MEMO_SUITES_V1)) {
      if (suite.tag === tag) {
        return [label, suite];
      }
    }
    rejectError(`${context} uses unsupported confidential memo suite tag ${tag}`);
  }

  function encodeConfidentialMemoEnvelopeV1Value(value, context) {
    assertExactObjectKeys(value, ["slots", "payload_nonce", "ciphertext"], context);
    if (!Array.isArray(value.slots) || value.slots.length !== CONFIDENTIAL_MEMO_RECIPIENT_SLOTS_V1) {
      rejectRange(`${context}.slots must contain exactly ${CONFIDENTIAL_MEMO_RECIPIENT_SLOTS_V1} entries`);
    }

    const encodedSlots = value.slots.map((slot, index) => {
      const slotContext = `${context}.slots[${index}]`;
      assertExactObjectKeys(
        slot,
        ["suite", "encapsulation", "wrap_nonce", "wrapped_memo_key"],
        slotContext,
      );
      const suite = confidentialMemoSuite(slot.suite, `${slotContext}.suite`);
      const encapsulation = requireNonzero(
        Buffer.from(
          normalizeFlexibleBytes(slot.encapsulation, `${slotContext}.encapsulation`),
        ),
        `${slotContext}.encapsulation`,
      );
      if (encapsulation.length !== suite.encapsulationBytes) {
        rejectRange(`${slotContext}.encapsulation must be exactly ${suite.encapsulationBytes} bytes`);
      }
      const wrapNonce = requireNonzero(
        encodeFixedBytesValue(
          slot.wrap_nonce,
          CONFIDENTIAL_MEMO_NONCE_BYTES_V1,
          `${slotContext}.wrap_nonce`,
        ),
        `${slotContext}.wrap_nonce`,
      );
      const wrappedMemoKey = requireNonzero(
        encodeFixedBytesValue(
          slot.wrapped_memo_key,
          CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1,
          `${slotContext}.wrapped_memo_key`,
        ),
        `${slotContext}.wrapped_memo_key`,
      );
      return Buffer.concat([
        encodeU8Value(suite.tag, `${slotContext}.suite`),
        encapsulation,
        wrapNonce,
        wrappedMemoKey,
      ]);
    });
    const seenSlots = new Set();
    for (const [index, slot] of encodedSlots.entries()) {
      const identity = slot.toString(HEX_ENCODING);
      if (seenSlots.has(identity)) {
        rejectError(`${context}.slots[${index}] duplicates an earlier slot`);
      }
      seenSlots.add(identity);
    }

    const payloadNonce = requireNonzero(
      encodeFixedBytesValue(
        value.payload_nonce,
        CONFIDENTIAL_MEMO_NONCE_BYTES_V1,
        `${context}.payload_nonce`,
      ),
      `${context}.payload_nonce`,
    );
    const ciphertext = Buffer.from(
      normalizeFlexibleBytes(value.ciphertext, `${context}.ciphertext`),
    );
    if (
      ciphertext.length < CONFIDENTIAL_MEMO_TAG_BYTES_V1 ||
      ciphertext.length > CONFIDENTIAL_MEMO_MAX_CIPHERTEXT_BYTES_V1
    ) {
      rejectRange(`${context}.ciphertext must be ${CONFIDENTIAL_MEMO_TAG_BYTES_V1}..${CONFIDENTIAL_MEMO_MAX_CIPHERTEXT_BYTES_V1} bytes`);
    }
    return Buffer.concat([
      CONFIDENTIAL_MEMO_WIRE_MAGIC_V1,
      ...encodedSlots,
      payloadNonce,
      encodeCompactLength(ciphertext.length),
      ciphertext,
    ]);
  }

  function decodeConfidentialMemoEnvelopeV1Value(payload, context) {
    const reader = new BufferReader(payload, context);
    const magic = reader.readBytes(
      CONFIDENTIAL_MEMO_WIRE_MAGIC_V1.length,
      "wire_magic",
    );
    if (!magic.equals(CONFIDENTIAL_MEMO_WIRE_MAGIC_V1)) {
      rejectError(`${context} has invalid confidential memo V1 wire magic`);
    }
    const slots = [];
    const encodedSlotIdentities = new Set();
    for (let index = 0; index < CONFIDENTIAL_MEMO_RECIPIENT_SLOTS_V1; index += 1) {
      const slotContext = `${context}.slots[${index}]`;
      const tag = reader.readU8(`${slotContext}.suite`);
      const [suiteLabel, suite] = confidentialMemoSuiteFromTag(tag, `${slotContext}.suite`);
      const encapsulation = requireNonzero(
        reader.readBytes(suite.encapsulationBytes, `${slotContext}.encapsulation`),
        `${slotContext}.encapsulation`,
      );
      const wrapNonce = requireNonzero(
        reader.readBytes(CONFIDENTIAL_MEMO_NONCE_BYTES_V1, `${slotContext}.wrap_nonce`),
        `${slotContext}.wrap_nonce`,
      );
      const wrappedMemoKey = requireNonzero(
        reader.readBytes(
          CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1,
          `${slotContext}.wrapped_memo_key`,
        ),
        `${slotContext}.wrapped_memo_key`,
      );
      const identity = Buffer.concat([
        Buffer.from([tag]),
        encapsulation,
        wrapNonce,
        wrappedMemoKey,
      ]).toString(HEX_ENCODING);
      if (encodedSlotIdentities.has(identity)) {
        rejectError(`${slotContext} duplicates an earlier slot`);
      }
      encodedSlotIdentities.add(identity);
      slots.push({
        suite: suiteLabel,
        encapsulation: Buffer.from(encapsulation).toString(BASE64_ENCODING),
        wrap_nonce: Array.from(wrapNonce),
        wrapped_memo_key: Array.from(wrappedMemoKey),
      });
    }
    const payload_nonce = Array.from(
      requireNonzero(
        reader.readBytes(CONFIDENTIAL_MEMO_NONCE_BYTES_V1, "payload_nonce"),
        `${context}.payload_nonce`,
      ),
    );
    const [ciphertextLength, lengthBytes] = decodeUnsignedLeb128(
      payload,
      reader.offset,
      `${context}.ciphertext.length`,
    );
    if (
      ciphertextLength < CONFIDENTIAL_MEMO_TAG_BYTES_V1 ||
      ciphertextLength > CONFIDENTIAL_MEMO_MAX_CIPHERTEXT_BYTES_V1
    ) {
      rejectRange(`${context}.ciphertext must be ${CONFIDENTIAL_MEMO_TAG_BYTES_V1}..${CONFIDENTIAL_MEMO_MAX_CIPHERTEXT_BYTES_V1} bytes`);
    }
    reader.offset += lengthBytes;
    const ciphertext = reader.readBytes(ciphertextLength, "ciphertext");
    reader.assertEof();
    return {
      slots,
      payload_nonce,
      ciphertext: Buffer.from(ciphertext).toString(BASE64_ENCODING),
    };
  }

  return [
    encodeConfidentialMemoEnvelopeV1Value,
    decodeConfidentialMemoEnvelopeV1Value,
  ];
}

/**
 * Bind contract-manifest, entrypoint-schema, and related codecs to the shared
 * Norito wire primitives. The one-way dependency keeps initialization acyclic.
 *
 * @returns {Function[]}
 */
export function createNoritoContractCodecs(
  contractDeclarationCodecsV1,
  assertNonEmptyString,
  assertOnlyObjectKeys,
  decodeConstVecU8Value,
  decodeHashValue,
  decodeNoritoVec,
  decodePublicKeyValue,
  decodeStringValue,
  decodeStructFields,
  decodeU32Value,
  decodeU64NumberValue,
  encodeConstVecU8Value,
  encodeHashValue,
  encodeNoritoStringValue,
  encodeNoritoVec,
  encodeOptionValue,
  encodePublicKeyValue,
  encodeStringValue,
  encodeStructValue,
  encodeU32Value,
  encodeU64NumberValue,
  parsePublicKeyLiteral,
  publicKeyLiteralFromParts,
) {
  const {
    decodeRecordFields,
    assertPlainObjectValue,
    assertArrayValue,
    encodeEntrypointDescriptorValue,
    decodeEntrypointDescriptorValue,
    encodeContractPermissionsValue,
    decodeContractPermissionsValue,
    encodeContractErrorTypeDescriptorsValue,
    decodeContractErrorTypeDescriptorsValue,
    encodeContractEnumTypeDescriptorsValue,
    decodeContractEnumTypeDescriptorsValue,
    encodeContractEventsValue,
    decodeContractEventsValue,
    encodeRequiredRecordString,
    encodeCanonicalRecordFields,
  } = contractDeclarationCodecsV1;

  const CONTRACT_MANIFEST_KEYS = Object.freeze([
    "seiyaku_name",
    "code_hash",
    "abi_hash",
    "compiler_fingerprint",
    "features_bitmap",
    "access_set_hints",
    "permissions",
    "events",
    "entrypoints",
    "states",
    "error_types",
    "enum_types",
    "error_messages",
    "kotoba",
    "provenance",
  ]);

  function contractManifestSignatureFields(value, context) {
    assertPlainObjectValue(value, context);
    assertOnlyObjectKeys(value, CONTRACT_MANIFEST_KEYS, context);
    validateManifestDeclarationsV1(value, context);
    validateManifestErrorTypeBindingsV1(value, context);
    normalizeContractErrorMessagesV1(value.error_messages, value.error_types, `${context}.error_messages`);
    return [
      [encodeOptionValue(value.seiyaku_name, encodeNoritoStringValue, `${context}.seiyaku_name`)],
      [encodeOptionValue(value.code_hash, encodeHashValue, `${context}.code_hash`)],
      [encodeOptionValue(value.abi_hash, encodeHashValue, `${context}.abi_hash`)],
      [encodeOptionValue(value.compiler_fingerprint, encodeNoritoStringValue, `${context}.compiler_fingerprint`)],
      [encodeOptionValue(value.features_bitmap, encodeU64NumberValue, `${context}.features_bitmap`)],
      [encodeOptionValue(value.access_set_hints, encodeAccessSetHintsValue, `${context}.access_set_hints`)],
      [encodeContractPermissionsValue(value.permissions, `${context}.permissions`)],
      [encodeContractEventsValue(value.events, `${context}.events`)],
      [
        encodeOptionValue(
          value.entrypoints ?? null,
          encodeEntrypointDescriptorsValue,
          `${context}.entrypoints`,
        ),
      ],
      [
        encodeOptionValue(
          value.states ?? null,
          encodeStateDescriptorsValue,
          `${context}.states`,
        ),
      ],
      [
        encodeOptionValue(
          value.error_types ?? null,
          encodeContractErrorTypeDescriptorsValue,
          `${context}.error_types`,
        ),
      ],
      [encodeContractEnumTypeDescriptorsValue(value.enum_types, `${context}.enum_types`)],
      [
        encodeOptionValue(
          value.error_messages ?? null,
          encodeContractErrorMessagesValue,
          `${context}.error_messages`,
        ),
      ],
      [
        encodeOptionValue(
          value.kotoba ?? null,
          encodeKotobaTranslationEntriesValue,
          `${context}.kotoba`,
        ),
      ],
    ];
  }

  function encodeContractManifestSignaturePayloadValue(value, context) {
    return encodeStructValue(contractManifestSignatureFields(value, context));
  }

  function encodeContractManifestValue(value, context) {
    return encodeStructValue([
      ...contractManifestSignatureFields(value, context),
      [
        encodeOptionValue(
          value.provenance ?? null,
          encodeManifestProvenanceValue,
          `${context}.provenance`,
        ),
      ],
    ]);
  }

  const ContractManifestValueFields = [
    ["seiyaku_name", decodeStringValue, 1],
    ["code_hash", decodeHashValue, 1],
    ["abi_hash", decodeHashValue, 1],
    ["compiler_fingerprint", decodeStringValue, 1],
    ["features_bitmap", decodeU64NumberValue, 1],
    ["access_set_hints", decodeAccessSetHintsValue, 1],
    ["permissions", decodeContractPermissionsValue, 0],
    ["events", decodeContractEventsValue, 0],
    ["entrypoints", decodeEntrypointDescriptorsValue, 1],
    ["states", decodeStateDescriptorsValue, 1],
    ["error_types", decodeContractErrorTypeDescriptorsValue, 1],
    ["enum_types", decodeContractEnumTypeDescriptorsValue, 0],
    ["error_messages", decodeContractErrorMessagesValue, 1],
    ["kotoba", decodeKotobaTranslationEntriesValue, 1],
    ["provenance", decodeManifestProvenanceValue, 1],
  ];

  function decodeContractManifestValue(payload, context) {
    const value = decodeRecordFields(payload, context, ContractManifestValueFields);
    validateManifestDeclarationsV1(value, context);
    validateManifestErrorTypeBindingsV1(value, context);
    normalizeContractErrorMessagesV1(value.error_messages, value.error_types, `${context}.error_messages`);
    return value;
  }

  function encodeAccessSetHintsValue(value, context) {
    assertPlainObjectValue(value, context);
    assertOnlyObjectKeys(value, [
      "read_keys",
      "write_keys",
      "dynamic_reads",
      "dynamic_writes",
    ], context);
    return encodeCanonicalRecordFields(value, context, AccessSetHintsValueFields);
  }

  const AccessSetHintsValueFields = [
    ["read_keys", decodeStringValue, 2, encodeRequiredRecordString, 3],
    ["write_keys", decodeStringValue, 2, encodeRequiredRecordString, 3],
    ["dynamic_reads", decodeDynamicAccessHintValue, 2, encodeDynamicAccessHintValue, 3],
    ["dynamic_writes", decodeDynamicAccessHintValue, 2, encodeDynamicAccessHintValue, 3],
  ];

  function decodeAccessSetHintsValue(payload, context) {
    return decodeRecordFields(payload, context, AccessSetHintsValueFields);
  }

  function encodeDynamicAccessHintValue(value, context) {
    assertPlainObjectValue(value, context);
    assertOnlyObjectKeys(value, ["base_key", "key_type", "bound_kind", "max_keys"], context);
    return encodeCanonicalRecordFields(value, context, DynamicAccessHintValueFields);
  }

  const DynamicAccessHintValueFields = [
    ["base_key", decodeStringValue, 0, encodeRequiredRecordString, 0],
    ["key_type", decodeStringValue, 0, encodeRequiredRecordString, 0],
    ["bound_kind", decodeStringValue, 0, encodeRequiredRecordString, 0],
    ["max_keys", decodeU32Value, 0, encodeU32Value, 0],
  ];

  function decodeDynamicAccessHintValue(payload, context) {
    return decodeRecordFields(payload, context, DynamicAccessHintValueFields);
  }

  function encodeEntrypointDescriptorsValue(value, context) {
    assertArrayValue(value, context);
    return encodeNoritoVec(value, (entry, index) =>
      encodeEntrypointDescriptorValue(entry, `${context}[${index}]`),
    );
  }

  function decodeEntrypointDescriptorsValue(payload, context) {
    return decodeNoritoVec(
      payload,
      (entry, index) => decodeEntrypointDescriptorValue(entry, `${context}[${index}]`),
      context,
    );
  }

  function encodeStateDescriptorsValue(value, context) {
    assertArrayValue(value, context);
    return encodeNoritoVec(value, (entry, index) =>
      encodeStateDescriptorValue(entry, `${context}[${index}]`),
    );
  }

  function decodeStateDescriptorsValue(payload, context) {
    return decodeNoritoVec(
      payload,
      (entry, index) => decodeStateDescriptorValue(entry, `${context}[${index}]`),
      context,
    );
  }

  function encodeStateDescriptorValue(value, context) {
    assertPlainObjectValue(value, context);
    assertOnlyObjectKeys(value, ["name", "type_name"], context);
    return encodeCanonicalRecordFields(value, context, StateDescriptorValueFields);
  }

  const StateDescriptorValueFields = [
    ["name", decodeStringValue, 0, encodeRequiredRecordString, 0],
    ["type_name", decodeStringValue, 0, encodeRequiredRecordString, 0],
  ];

  function decodeStateDescriptorValue(payload, context) {
    return decodeRecordFields(payload, context, StateDescriptorValueFields);
  }

  function encodeContractErrorMessagesValue(value, context) {
    assertArrayValue(value, context);
    return encodeNoritoVec(value, (entry, index) => {
      const label = `${context}[${index}]`;
      assertOnlyObjectKeys(entry, ["error_type", "code", "message"], label);
      return encodeStructValue([
        [encodeNoritoStringValue(entry.error_type)],
        [encodeU32Value(entry.code, `${label}.code`)],
        [encodeNoritoStringValue(entry.message)],
      ]);
    });
  }

  function decodeContractErrorMessagesValue(payload, context) {
    return decodeNoritoVec(payload, (entry, index) => {
      const label = `${context}[${index}]`;
      const fields = decodeStructFields(entry, label, ["error_type", "code", "message"]);
      return { error_type: decodeStringValue(fields.error_type, `${label}.error_type`),
        code: decodeU32Value(fields.code, `${label}.code`), message: decodeStringValue(fields.message, `${label}.message`) };
    }, context);
  }

  function encodeKotobaTranslationEntriesValue(value, context) {
    assertArrayValue(value, context);
    return encodeNoritoVec(value, (entry, index) =>
      encodeKotobaTranslationEntryValue(entry, `${context}[${index}]`),
    );
  }

  function decodeKotobaTranslationEntriesValue(payload, context) {
    return decodeNoritoVec(
      payload,
      (entry, index) => decodeKotobaTranslationEntryValue(entry, `${context}[${index}]`),
      context,
    );
  }

  function encodeKotobaTranslationEntryValue(value, context) {
    assertPlainObjectValue(value, context);
    assertOnlyObjectKeys(value, ["msg_id", "translations"], context);
    return encodeCanonicalRecordFields(value, context, KotobaTranslationEntryValueFields);
  }

  const KotobaTranslationEntryValueFields = [
    ["msg_id", decodeStringValue, 0, encodeRequiredRecordString, 0],
    ["translations", decodeKotobaTranslationValue, 2, encodeKotobaTranslationValue, 3],
  ];

  function decodeKotobaTranslationEntryValue(payload, context) {
    return decodeRecordFields(payload, context, KotobaTranslationEntryValueFields);
  }

  function encodeKotobaTranslationValue(value, context) {
    assertPlainObjectValue(value, context);
    assertOnlyObjectKeys(value, ["lang", "text"], context);
    return encodeCanonicalRecordFields(value, context, KotobaTranslationValueFields);
  }

  const KotobaTranslationValueFields = [
    ["lang", decodeStringValue, 0, encodeRequiredRecordString, 0],
    ["text", decodeStringValue, 0, encodeStringValue, 0],
  ];

  function decodeKotobaTranslationValue(payload, context) {
    return decodeRecordFields(payload, context, KotobaTranslationValueFields);
  }

  function encodeManifestProvenanceValue(value, context) {
    assertPlainObjectValue(value, context);
    assertOnlyObjectKeys(value, ["signer", "signature"], context);
    const signer = parsePublicKeyLiteral(value.signer, `${context}.signer`);
    const signatureLiteral = assertNonEmptyString(value.signature, `${context}.signature`);
    if (
      signatureLiteral.length % 2 !== 0 ||
      !/^[0-9A-Fa-f]+$/u.test(signatureLiteral)
    ) {
      rejectError(`${context}.signature must be an even-length hexadecimal string`);
    }
    const signature = Buffer.from(signatureLiteral, HEX_ENCODING);
    validateManifestSignatureBytes(signature, `${context}.signature`);
    return encodeStructValue([
      [encodePublicKeyValue(signer, `${context}.signer`)],
      [encodeConstVecU8Value(signature)],
    ]);
  }

  function decodeManifestProvenanceValue(payload, context) {
    const fields = decodeStructFields(payload, context, ["signer", "signature"]);
    const signer = decodePublicKeyValue(fields.signer, `${context}.signer`);
    const signature = decodeConstVecU8Value(fields.signature, `${context}.signature`);
    validateManifestSignatureBytes(signature, `${context}.signature`);
    return {
      signer: publicKeyLiteralFromParts(
        signer.curve,
        signer.publicKey,
        `${context}.signer`,
      ),
      signature: signature.toString(HEX_ENCODING).toUpperCase(),
    };
  }

  function validateManifestSignatureBytes(signature, context) {
    if (signature.length === 0) {
      rejectError(`${context} must not be empty`);
    }
    if (signature.every((byte) => byte === 0)) {
      rejectError(`${context} must not be all zero`);
    }
  }

return [
    encodeContractManifestSignaturePayloadValue,
    encodeContractManifestValue,
    decodeContractManifestValue,
    encodeManifestProvenanceValue,
    decodeManifestProvenanceValue,

  ];
}

/** Bind authenticated contract declaration codecs independently of manifest provenance. */
export function createNoritoContractMetadataCodecs(
  BufferReader,
  assertNonEmptyString,
  assertOnlyObjectKeys,
  decodeAccountIdValue,
  decodeBoolValue,
  decodeEventFilterBoxFramePayload,
  decodeMetadataValue,
  decodeNameValue,
  decodeNoritoVec,
  decodeOptionValue,
  decodeStringValue,
  decodeStructFields,
  decodeU16Value,
  decodeU32Value,
  decodeU8Value,
  encodeAccountIdValue,
  encodeBoolValue,
  encodeEnumTagValue,
  encodeEventFilterBoxFramePayload,
  encodeMetadataValue,
  encodeNameValue,
  encodeNoritoStringValue,
  encodeNoritoVec,
  encodeOptionValue,
  encodeStructValue,
  encodeU16Value,
  encodeU32Value,
  encodeU8Value,
  isPlainObject,
  readNoritoField,
) {
  const decodeRecordFields = /* @__PURE__ */ createNoritoRecordDecoder(
    decodeStructFields, decodeOptionValue, decodeNoritoVec,
  );

  function assertPlainObjectValue(value, context) {
    if (!isPlainObject(value)) {
      rejectType(`${context} must be an object`);
    }
  }

  function assertArrayValue(value, context) {
    if (!Array.isArray(value)) {
      rejectType(`${context} must be an array`);
    }
  }

  function validateEntrypointReturnDescriptor(value, context) {
    if (typeof value.return_type !== "string" || value.return_schema == null) {
      throw new TypeError(`${context} requires return_type and return_schema, including () and Unit`);
    }
    const analysis = analyzeEntrypointValueTypeV1(value.return_schema, `${context}.return_schema`);
    if (analysis.canonicalName !== value.return_type || analysis.wordCount > MAX_ENTRYPOINT_CALL_TABLE_WORDS_V1) {
      throw new TypeError(`${context}.return_schema must match return_type within the 8192-word result table`);
    }
  }

  function encodeEntrypointDescriptorValue(value, context) {
    assertPlainObjectValue(value, context);
    validateEntrypointReturnDescriptor(value, context);
    validateManifestEntrypointIdentityV1(value.name, typeof value.kind === "string" ? value.kind : value.kind.kind, normalizeEntrypointAuthorizationV1(value.authorization, `${context}.authorization`), context);
    assertOnlyObjectKeys(value, [
      "name",
      "kind",
      "params",
      "argument_schema",
      "return_type",
      "return_schema",
      "authorization",
      "read_keys",
      "write_keys",
      "access_hints_complete",
      "access_hints_skipped",
      "triggers",
    ], context);
    const triggers = value.triggers ?? [];
    assertArrayValue(triggers, `${context}.triggers`);
    return encodeStructValue([
      [encodeNoritoStringValue(assertNonEmptyString(value.name, `${context}.name`))],
      [encodeEntryPointKindValue(value.kind, `${context}.kind`)],
      [
        encodeNoritoVec(value.params ?? [], (param, index) =>
          encodeEntrypointParamDescriptorValue(param, `${context}.params[${index}]`),
        ),
      ],
      [
        encodeOptionValue(
          value.argument_schema ?? null,
          encodeEntrypointArgumentSchemaValue,
          `${context}.argument_schema`,
        ),
      ],
      [
        encodeOptionValue(
          value.return_type ?? null,
          encodeNoritoStringValue,
          `${context}.return_type`,
        ),
      ],
      [
        encodeOptionValue(
          value.return_schema ?? null,
          encodeEntrypointValueTypeValue,
          `${context}.return_schema`,
        ),
      ],
      [encodeEntrypointAuthorizationValue(value.authorization, `${context}.authorization`)],
      [
        encodeNoritoVec(value.read_keys ?? [], (entry, index) =>
          encodeNoritoStringValue(
            assertNonEmptyString(entry, `${context}.read_keys[${index}]`),
          ),
        ),
      ],
      [
        encodeNoritoVec(value.write_keys ?? [], (entry, index) =>
          encodeNoritoStringValue(
            assertNonEmptyString(entry, `${context}.write_keys[${index}]`),
          ),
        ),
      ],
      [
        encodeOptionValue(
          value.access_hints_complete ?? null,
          encodeBoolValue,
          `${context}.access_hints_complete`,
        ),
      ],
      [
        encodeNoritoVec(
          value.access_hints_skipped ?? [],
          (entry, index) =>
            encodeNoritoStringValue(
              assertNonEmptyString(entry, `${context}.access_hints_skipped[${index}]`),
            ),
        ),
      ],
      [
        encodeNoritoVec(triggers, (entry, index) =>
          encodeManifestTriggerDescriptorValue(entry, `${context}.triggers[${index}]`),
        ),
      ],
    ]);
  }

  const EntrypointDescriptorValueFields = [
    ["name", decodeStringValue, 0],
    ["kind", decodeEntryPointKindValue, 0],
    ["params", decodeEntrypointParamDescriptorValue, 2],
    ["argument_schema", decodeEntrypointArgumentSchemaValue, 1],
    ["return_type", decodeStringValue, 1],
    ["return_schema", decodeEntrypointValueTypeValue, 1],
    ["authorization", decodeEntrypointAuthorizationValue, 0],
    ["read_keys", decodeStringValue, 2],
    ["write_keys", decodeStringValue, 2],
    ["access_hints_complete", decodeBoolValue, 1],
    ["access_hints_skipped", decodeStringValue, 2],
    ["triggers", decodeManifestTriggerDescriptorValue, 2],
  ];

  function decodeEntrypointDescriptorValue(payload, context) {
    const value = decodeRecordFields(payload, context, EntrypointDescriptorValueFields);
    validateEntrypointReturnDescriptor(value, context);
    validateManifestEntrypointIdentityV1(value.name, typeof value.kind === "string" ? value.kind : value.kind.kind, normalizeEntrypointAuthorizationV1(value.authorization, `${context}.authorization`), context);
    return value;
  }

  function encodeEntrypointAuthorizationValue(value, context) {
    const authorization = normalizeEntrypointAuthorizationV1(value, context);
    switch (authorization.kind) {
      case "Anyone": return encodeEnumTagValue(0);
      case "Permission": return encodeEnumTagValue(1, () => encodeNameValue(authorization.value, `${context}.value`));
      case "RuntimeLifecycle": return encodeEnumTagValue(2);
    }
  }

  function decodeEntrypointAuthorizationValue(payload, context) {
    const reader = new BufferReader(payload, context);
    const tag = reader.readU32LE("tag");
    if (tag === 1) return { kind: "Permission", value: decodeStringValue(readSingleEnumPayload(reader, context), `${context}.value`) };
    reader.assertEof();
    if (tag === 0) return { kind: "Anyone", value: null };
    if (tag === 2) return { kind: "RuntimeLifecycle", value: null };
    rejectError(`${context} uses unsupported authorization tag ${tag}`);
  }

  function encodeContractPermissionsValue(value, context) {
    return encodeNoritoVec(normalizeContractPermissionsV1(value, context), (entry, index) => {
      const path = `${context}[${index}]`;
      const scope = entry.scope.kind === "Instance"
        ? encodeEnumTagValue(0)
        : encodeEnumTagValue(1, () => encodeNameValue(entry.scope.value.permission_name, `${path}.scope.value.permission_name`));
      return encodeStructValue([[encodeNameValue(entry.name, `${path}.name`)], [scope]]);
    });
  }

  function decodeContractPermissionsValue(payload, context) {
    const values = decodeNoritoVec(payload, (entry, index) => decodeRecordFields(entry, `${context}[${index}]`, [
      ["name", decodeStringValue, 0], ["scope", decodeContractPermissionScopeValue, 0],
    ]), context);
    return normalizeContractPermissionsV1(values, context);
  }

  function decodeContractPermissionScopeValue(payload, context) {
    const reader = new BufferReader(payload, context);
    const tag = reader.readU32LE("tag");
    if (tag === 1) return { kind: "Chain", value: { permission_name: decodeStringValue(readSingleEnumPayload(reader, context), `${context}.value.permission_name`) } };
    reader.assertEof();
    if (tag === 0) return { kind: "Instance", value: null };
    rejectError(`${context} uses unsupported permission scope tag ${tag}`);
  }

  function encodeEntryPointKindValue(value, context) {
    const kind = typeof value === JS_TYPE_STRING ? value : value?.kind;
    const normalized = assertNonEmptyString(kind, context).toLowerCase();
    switch (normalized) {
      case "kotoage":
        return encodeEnumTagValue(0);
      case "view":
        return encodeEnumTagValue(1);
      case "hajimari":
        return encodeEnumTagValue(2);
      case "kaizen":
        return encodeEnumTagValue(3);
      default:
        rejectError(`${context} must be Kotoage, View, Hajimari, or Kaizen`);
    }
  }

  function decodeEntryPointKindValue(payload, context) {
    const reader = new BufferReader(payload, context);
    const tag = reader.readU32LE("tag");
    reader.assertEof();
    switch (tag) {
      case 0:
        return { kind: "Kotoage", value: null };
      case 1:
        return { kind: "View", value: null };
      case 2:
        return { kind: "Hajimari", value: null };
      case 3:
        return { kind: "Kaizen", value: null };
      default:
        rejectError(`${context} uses unsupported entrypoint kind ${tag}`);
    }
  }

  function encodeEntrypointParamDescriptorValue(value, context) {
    assertPlainObjectValue(value, context);
    assertOnlyObjectKeys(value, ["name", "type_name"], context);
    return encodeCanonicalRecordFields(value, context, EntrypointParamDescriptorValueFields);
  }

  const EntrypointParamDescriptorValueFields = [
    ["name", decodeStringValue, 0, encodeRequiredRecordString, 0],
    ["type_name", decodeStringValue, 0, encodeRequiredRecordString, 0],
  ];

  function decodeEntrypointParamDescriptorValue(payload, context) {
    return decodeRecordFields(payload, context, EntrypointParamDescriptorValueFields);
  }

  function encodeEntrypointArgumentSchemaValue(value, context) {
    if (!isPlainObject(value) || !Array.isArray(value.fields)) {
      rejectType(`${context} must contain a fields array`);
    }
    assertOnlyObjectKeys(value, ["fields"], context);
    return encodeCanonicalRecordFields(value, context, EntrypointArgumentSchemaValueFields);
  }

  const EntrypointArgumentSchemaValueFields = [
    ["fields", decodeEntrypointArgumentFieldValue, 2, encodeEntrypointArgumentFieldValue, 2],
  ];

  function decodeEntrypointArgumentSchemaValue(payload, context) {
    return decodeRecordFields(payload, context, EntrypointArgumentSchemaValueFields);
  }

  function encodeEntrypointArgumentFieldValue(value, context) {
    assertPlainObjectValue(value, context);
    assertOnlyObjectKeys(value, ["name", "ty"], context);
    return encodeCanonicalRecordFields(value, context, EntrypointArgumentFieldValueFields);
  }

  const EntrypointArgumentFieldValueFields = [
    ["name", decodeStringValue, 0, encodeRequiredRecordString, 0],
    ["ty", decodeEntrypointValueTypeValue, 0, encodeEntrypointValueTypeValue, 0],
  ];

  function decodeEntrypointArgumentFieldValue(payload, context) {
    return decodeRecordFields(payload, context, EntrypointArgumentFieldValueFields);
  }

  function encodeEntrypointValueTypeValue(value, context) {
    if (!isPlainObject(value) || !Array.isArray(value.nodes)) {
      rejectType(`${context} must contain a nodes array`);
    }
    assertOnlyObjectKeys(value, ["nodes"], context);
    analyzeEntrypointValueTypeV1(value, context);
    return encodeCanonicalRecordFields(value, context, CanonicalEncodingFields5);
  }

  function decodeEntrypointValueTypeValue(payload, context, keyOnly = false) {
    const fields = decodeStructFields(payload, context, ["nodes"]);
    const value = {
      nodes: decodeNoritoVec(
        fields.nodes,
        (node, index) =>
          decodeEntrypointValueTypeNodeValue(node, `${context}.nodes[${index}]`, keyOnly),
        `${context}.nodes`,
      ),
    };
    analyzeEntrypointValueTypeV1(value, context);
    return value;
  }

  function taggedEnumParts(value, context) {
    if (!isPlainObject(value)) {
      rejectType(`${context} must be a tagged object`);
    }
    assertOnlyObjectKeys(value, ["kind", "value"], context);
    return {
      kind: assertNonEmptyString(value.kind, `${context}.kind`),
      value: value.value ?? null,
    };
  }

  function encodeEntrypointValueTypeNodeValue(value, context) {
    const tagged = taggedEnumParts(value, context);
    switch (tagged.kind) {
      case "Struct":
        return encodeEnumTagValue(0, () =>
          encodeEntrypointStructTypeNodeValue(tagged.value, `${context}.value`),
        );
      case "Tuple":
        return encodeEnumTagValue(1, () =>
          encodeU16Value(tagged.value, `${context}.value`),
        );
      case "Option":
        requireNullEnumPayload(tagged.value, context);
        return encodeEnumTagValue(2);
      case "Result":
        requireNullEnumPayload(tagged.value, context);
        return encodeEnumTagValue(3);
      case "List":
        return encodeEnumTagValue(4, () =>
          encodeEntrypointListTypeNodeValue(tagged.value, `${context}.value`),
        );
      case "Leaf":
        return encodeEnumTagValue(5, () =>
          encodeEntrypointValueKindValue(tagged.value, `${context}.value`),
        );
      case "Unit":
        requireNullEnumPayload(tagged.value, context);
        return encodeEnumTagValue(6);
      case "StateCursor":
        return encodeEnumTagValue(8, () => encodeEntrypointValueTypeValue(tagged.value, `${context}.value`));
      case "Error":
        return encodeEnumTagValue(7, () => encodeContractErrorTypeDescriptorValue(tagged.value, `${context}.value`));
      case "Enum":
        return encodeEnumTagValue(9, () => encodeContractEnumTypeDescriptorValue(tagged.value, `${context}.value`));
      default:
        rejectError(`${context}.kind uses unsupported value-type node ${tagged.kind}`);
    }
  }

  function decodeEntrypointValueTypeNodeValue(payload, context, keyOnly = false) {
    const reader = new BufferReader(payload, context);
    const tag = reader.readU32LE("tag");
    if (keyOnly && tag !== 1 && tag !== 5) rejectError(`${context} requires scalar or tuple key nodes`);
    switch (tag) {
      case 0:
        return {
          kind: "Struct",
          value: decodeEntrypointStructTypeNodeValue(
            readSingleEnumPayload(reader, context),
            `${context}.value`,
          ),
        };
      case 1:
        return {
          kind: "Tuple",
          value: decodeU16Value(readSingleEnumPayload(reader, context), `${context}.value`),
        };
      case 2:
        reader.assertEof();
        return { kind: "Option", value: null };
      case 3:
        reader.assertEof();
        return { kind: "Result", value: null };
      case 4:
        return {
          kind: "List",
          value: decodeEntrypointListTypeNodeValue(
            readSingleEnumPayload(reader, context),
            `${context}.value`,
          ),
        };
      case 5:
        return {
          kind: "Leaf",
          value: decodeEntrypointValueKindValue(
            readSingleEnumPayload(reader, context),
            `${context}.value`,
          ),
        };
      case 6:
        reader.assertEof();
        return { kind: "Unit", value: null };
      case 7:
        return { kind: "Error", value: decodeContractErrorTypeDescriptorValue(readSingleEnumPayload(reader, context), `${context}.value`) };
      case 8:
        return { kind: "StateCursor", value: decodeEntrypointValueTypeValue(readSingleEnumPayload(reader, context), `${context}.value`, true) };
      case 9:
        return { kind: "Enum", value: decodeContractEnumTypeDescriptorValue(readSingleEnumPayload(reader, context), `${context}.value`) };
      default:
        rejectError(`${context} uses unsupported value-type node tag ${tag}`);
    }
  }

  function readSingleEnumPayload(reader, _context) {
    const value = readNoritoField(reader, "value");
    reader.assertEof();
    return value;
  }

  function requireNullEnumPayload(value, context) {
    if (value !== null && value !== undefined) {
      rejectType(`${context}.value must be null for a unit variant`);
    }
  }

  function encodeEntrypointStructTypeNodeValue(value, context) {
    if (!isPlainObject(value) || !Array.isArray(value.fields)) {
      rejectType(`${context} must contain a fields array`);
    }
    assertOnlyObjectKeys(value, ["name", "fields"], context);
    return encodeCanonicalRecordFields(value, context, EntrypointStructTypeNodeValueFields);
  }

  const EntrypointStructTypeNodeValueFields = [
    ["name", decodeStringValue, 0, encodeRequiredRecordString, 0],
    ["fields", decodeStringValue, 2, encodeRequiredRecordString, 2],
  ];

  function decodeEntrypointStructTypeNodeValue(payload, context) {
    return decodeRecordFields(payload, context, EntrypointStructTypeNodeValueFields);
  }

  function encodeEntrypointListTypeNodeValue(value, context) {
    assertPlainObjectValue(value, context);
    assertOnlyObjectKeys(value, ["capacity"], context);
    return encodeCanonicalRecordFields(value, context, EntrypointListTypeNodeValueFields);
  }

  const EntrypointListTypeNodeValueFields = [
    ["capacity", decodeU8Value, 0, encodeU8Value, 0],
  ];

  function decodeEntrypointListTypeNodeValue(payload, context) {
    return decodeRecordFields(payload, context, EntrypointListTypeNodeValueFields);
  }

  const ENTRYPOINT_VALUE_KIND_NAMES = Object.freeze([
    "Int",
    "Decimal",
    "Quantity",
    "Bool",
    "String",
    "Json",
    "Name",
    "AccountId",
    "AssetDefinitionId",
    "AssetId",
    "DomainId",
    "NftId",
    "DataSpaceId",
    "Blob",
  ]);

  function encodeEntrypointValueKindValue(value, context) {
    const tagged = taggedEnumParts(value, context);
    requireNullEnumPayload(tagged.value, context);
    const tag = ENTRYPOINT_VALUE_KIND_NAMES.indexOf(tagged.kind);
    if (tag < 0) {
      rejectError(`${context}.kind uses unsupported value kind ${tagged.kind}`);
    }
    return encodeEnumTagValue(tag);
  }

  function decodeEntrypointValueKindValue(payload, context) {
    const reader = new BufferReader(payload, context);
    const tag = reader.readU32LE("tag");
    reader.assertEof();
    const kind = ENTRYPOINT_VALUE_KIND_NAMES[tag];
    if (kind === undefined) {
      rejectError(`${context} uses unsupported value-kind tag ${tag}`);
    }
    return { kind, value: null };
  }

  function encodeContractErrorTypeDescriptorsValue(value, context) {
    assertArrayValue(value, context);
    return encodeNoritoVec(value, (entry, index) =>
      encodeContractErrorTypeDescriptorValue(entry, `${context}[${index}]`),
    );
  }

  function decodeContractErrorTypeDescriptorsValue(payload, context) {
    return decodeNoritoVec(
      payload,
      (entry, index) =>
        decodeContractErrorTypeDescriptorValue(entry, `${context}[${index}]`),
      context,
    );
  }

  function encodeContractErrorTypeDescriptorValue(value, context) {
    const descriptor = normalizeContractErrorTypeV1(value, context);
    return encodeStructValue([
      [encodeNoritoStringValue(descriptor.identity)],
      [encodeNoritoVec(descriptor.variants, (variant, index) => encodeStructValue([
        [encodeNoritoStringValue(variant.name)],
        [encodeU32Value(variant.code, `${context}.variants[${index}].code`)],
      ]))],
    ]);
  }

  function decodeContractErrorTypeDescriptorValue(payload, context) {
    const fields = decodeStructFields(payload, context, ["identity", "variants"]);
    return normalizeContractErrorTypeV1({
      identity: decodeStringValue(fields.identity, `${context}.identity`),
      variants: decodeNoritoVec(fields.variants, (payload, index) => {
        const label = `${context}.variants[${index}]`;
        const variant = decodeStructFields(payload, label, ["name", "code"]);
        return { name: decodeStringValue(variant.name, `${label}.name`), code: decodeU32Value(variant.code, `${label}.code`) };
      }, `${context}.variants`),
    }, context);
  }

  function encodeContractEnumTypeDescriptorsValue(value, context) {
    const catalog = normalizeContractEnumTypesV1(value, context);
    return boundedDeclarationTable(encodeNoritoVec(catalog, (entry, index) =>
      encodeContractEnumTypeDescriptorValue(entry, `${context}[${index}]`),
    ), context);
  }

  function decodeContractEnumTypeDescriptorsValue(payload, context) {
    boundedDeclarationTable(payload, context);
    return normalizeContractEnumTypesV1(decodeNoritoVec(
      payload,
      (entry, index) =>
        decodeContractEnumTypeDescriptorValue(entry, `${context}[${index}]`),
      context,
    ), context);
  }

  function encodeContractEnumTypeDescriptorValue(value, context) {
    const descriptor = normalizeContractEnumTypeV1(value, context);
    return encodeStructValue([
      [encodeNoritoStringValue(descriptor.identity)],
      [encodeNoritoVec(descriptor.variants, (variant, index) => encodeStructValue([
        [encodeNoritoStringValue(variant.name)],
        [encodeU32Value(variant.code, `${context}.variants[${index}].code`)],
      ]))],
    ]);
  }

  function decodeContractEnumTypeDescriptorValue(payload, context) {
    const fields = decodeStructFields(payload, context, ["identity", "variants"]);
    return normalizeContractEnumTypeV1({
      identity: decodeStringValue(fields.identity, `${context}.identity`),
      variants: decodeNoritoVec(fields.variants, (payload, index) => {
        const label = `${context}.variants[${index}]`;
        const variant = decodeStructFields(payload, label, ["name", "code"]);
        return { name: decodeStringValue(variant.name, `${label}.name`), code: decodeU32Value(variant.code, `${label}.code`) };
      }, `${context}.variants`),
    }, context);
  }

  function boundedDeclarationTable(payload, context) {
    // Canonical V1 uncompressed frames have the fixed 40-byte header and no padding.
    if (payload.length + 40 > 64 * 1024) rejectRange(`${context} exceeds the canonical 64-KiB declaration frame`);
    return payload;
  }

  function encodeContractEventsValue(value, context) {
    const declarations = normalizeContractEventsV1(value, context);
    return boundedDeclarationTable(encodeNoritoVec(declarations, (event, index) => encodeStructValue([
      [encodeNameValue(event.name, `${context}[${index}].name`)],
      [encodeEntrypointValueTypeValue(event.payload_type, `${context}[${index}].payload_type`)],
    ])), context);
  }

  function decodeContractEventsValue(payload, context) {
    boundedDeclarationTable(payload, context);
    const declarations = decodeNoritoVec(payload, (item, index) => {
      const label = `${context}[${index}]`;
      const fields = decodeStructFields(item, label, ["name", "payload_type"]);
      return { name: decodeNameValue(fields.name, `${label}.name`), payload_type: decodeEntrypointValueTypeValue(fields.payload_type, `${label}.payload_type`) };
    }, context);
    return normalizeContractEventsV1(declarations, context);
  }

  function encodeManifestTriggerDescriptorValue(value, context) {
    assertPlainObjectValue(value, context);
    assertOnlyObjectKeys(value, [
      "id",
      "repeats",
      "filter",
      "authority",
      "metadata",
      "callback",
    ], context);
    return encodeStructValue([
      [encodeTriggerIdValue(value.id, `${context}.id`)],
      [encodeTriggerRepeatsValue(value.repeats, `${context}.repeats`)],
      [encodeEventFilterBoxFramePayload(value.filter, `${context}.filter`)],
      [
        encodeOptionValue(
          value.authority ?? null,
          encodeAccountIdValue,
          `${context}.authority`,
        ),
      ],
      [encodeMetadataValue(value.metadata ?? {}, `${context}.metadata`)],
      [encodeTriggerCallbackValue(value.callback, `${context}.callback`)],
    ]);
  }

  const ManifestTriggerDescriptorValueFields = [
    ["id", decodeTriggerIdValue, 0],
    ["repeats", decodeTriggerRepeatsValue, 0],
    ["filter", decodeEventFilterBoxFramePayload, 0],
    ["authority", decodeAccountIdValue, 1],
    ["metadata", decodeMetadataValue, 0],
    ["callback", decodeTriggerCallbackValue, 0],
  ];

  function decodeManifestTriggerDescriptorValue(payload, context) {
    return decodeRecordFields(payload, context, ManifestTriggerDescriptorValueFields);
  }

  function encodeTriggerIdValue(value, context) {
    return encodeStructValue([
      [encodeNameValue(assertNonEmptyString(value, context), `${context}.name`)],
    ]);
  }

  function decodeTriggerIdValue(payload, context) {
    const fields = decodeStructFields(payload, context, ["name"]);
    return decodeNameValue(fields.name, `${context}.name`);
  }

  function encodeTriggerRepeatsValue(value, context) {
    if (!isPlainObject(value)) {
      rejectType(`${context} must be {Indefinitely:null} or {Exactly:<u32>}`);
    }
    const keys = Object.keys(value);
    if (keys.length !== 1) {
      rejectType(`${context} must contain exactly one repeat variant`);
    }
    if (keys[0] === "Indefinitely") {
      requireNullEnumPayload(value.Indefinitely, context);
      return encodeEnumTagValue(0);
    }
    if (keys[0] === "Exactly") {
      return encodeEnumTagValue(1, () =>
        encodeU32Value(value.Exactly, `${context}.Exactly`),
      );
    }
    rejectError(`${context} uses unsupported repeat variant ${keys[0]}`);
  }

  function decodeTriggerRepeatsValue(payload, context) {
    const reader = new BufferReader(payload, context);
    const tag = reader.readU32LE("tag");
    if (tag === 0) {
      reader.assertEof();
      return { Indefinitely: null };
    }
    if (tag === 1) {
      return {
        Exactly: decodeU32Value(
          readSingleEnumPayload(reader, context),
          `${context}.Exactly`,
        ),
      };
    }
    rejectError(`${context} uses unsupported repeat tag ${tag}`);
  }

  function encodeTriggerCallbackValue(value, context) {
    assertPlainObjectValue(value, context);
    assertOnlyObjectKeys(value, ["namespace", "entrypoint"], context);
    return encodeStructValue([
      [
        encodeOptionValue(
          value.namespace ?? null,
          encodeNoritoStringValue,
          `${context}.namespace`,
        ),
      ],
      [
        encodeNoritoStringValue(
          assertNonEmptyString(value.entrypoint, `${context}.entrypoint`),
        ),
      ],
    ]);
  }

  const TriggerCallbackValueFields = [
    ["namespace", decodeStringValue, 1],
    ["entrypoint", decodeStringValue, 0],
  ];

  function decodeTriggerCallbackValue(payload, context) {
    return decodeRecordFields(payload, context, TriggerCallbackValueFields);
  }

  function encodeRequiredRecordString(value, context) { return encodeNoritoStringValue(assertNonEmptyString(value, context)); }

  const encodeCanonicalRecordFields = /* @__PURE__ */ createNoritoRecordEncoder(
  encodeStructValue, encodeOptionValue, encodeNoritoVec,
);

  const CanonicalEncodingFields5 = [
  ["nodes", , , encodeEntrypointValueTypeNodeValue, 2],
];

  return {
    decodeRecordFields,
    assertPlainObjectValue,
    assertArrayValue,
    encodeEntrypointDescriptorValue,
    decodeEntrypointDescriptorValue,
    encodeContractPermissionsValue,
    decodeContractPermissionsValue,
    encodeContractErrorTypeDescriptorsValue,
    decodeContractErrorTypeDescriptorsValue,
    encodeContractEnumTypeDescriptorsValue,
    decodeContractEnumTypeDescriptorsValue,
    encodeContractEventsValue,
    decodeContractEventsValue,
    encodeRequiredRecordString,
    encodeCanonicalRecordFields,
    values: Object.freeze({
      entrypoint: [encodeEntrypointDescriptorValue, decodeEntrypointDescriptorValue],
      value_type: [encodeEntrypointValueTypeValue, decodeEntrypointValueTypeValue],
      enum_type: [encodeContractEnumTypeDescriptorValue, decodeContractEnumTypeDescriptorValue],
      error_type: [encodeContractErrorTypeDescriptorValue, decodeContractErrorTypeDescriptorValue],
      permissions: [encodeContractPermissionsValue, decodeContractPermissionsValue],
      events: [encodeContractEventsValue, decodeContractEventsValue],
      enum_types: [encodeContractEnumTypeDescriptorsValue, decodeContractEnumTypeDescriptorsValue],
      error_types: [encodeContractErrorTypeDescriptorsValue, decodeContractErrorTypeDescriptorsValue],
    }),
  };
}
