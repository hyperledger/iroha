import { normalizeContractEventsV1 } from "./contractDeclarations.js";
import { normalizeEntrypointAuthorizationV1, normalizeContractPermissionsV1, validateManifestDeclarationsV1, validateManifestEntrypointIdentityV1, validateManifestFieldsV1 } from "./contractManifestRules.js";
import { normalizeContractErrorMessagesV1, normalizeContractErrorTypeV1, normalizeContractEnumTypeV1, normalizeContractEnumTypesV1, normalizeContractErrorTypesV1, validateManifestErrorTypeBindingsV1 } from "./contractErrorTypes.js";
import { Buffer } from "buffer";
import { analyzeEntrypointValueTypeV1, analyzeStateKeyTypeV1, MAX_ENTRYPOINT_CALL_TABLE_WORDS_V1 } from "./entrypointSchema.js";
import { assertString, parseHashLiteralToBuffer } from "./instructionBuilderPrimitives.js";
import { canonicalizeMultihashHex } from "./normalizers.js";
import { getCurveEntryByPublicKeyMulticodec } from "./curveRegistry.js";
import { isCanonicalKotodamaIdentifier } from "./kotodamaIdentifiers.js";
import { isCanonicalKotodamaStateTypeName } from "./kotodamaIdentifiers.js";
import { normalizeAccountId } from "./normalizers.js";
import { validatePublicKeyForCurve } from "./address.js";

/** Bind contract manifest normalization to the shared instruction validation primitives. */
export function createContractManifestNormalizer(
  TEXT_MUST_BE,
  TEXT_MUST_BE_A,
  TEXT_MUST_BE_AN,
  TEXT_MUST_CONTAIN,
  TEXT_MUST_CONTAIN_EXACTLY,
  V_CODE_INVALID_HEX,
  V_CODE_INVALID_MULTIHASH,
  V_CODE_INVALID_OBJECT,
  V_CODE_INVALID_STRING,
  V_CODE_VALUE_OUT_OF_RANGE,
  asByte,
  asNonNegativeInteger,
  assertPlainObject,
  fail,
  normalizeAccessSetHints,
  normalizeByteArray,
  normalizeJsonValue,
  normalizeOptionalExactBase64String,
  normalizeOptionalHash,
  selectEqualManifestAlias,
  validateManifestDynamicAccessHintStateMaps,
) {
  const TEXT_ARGUMENT_SCHEMA = ".argument_schema";
  const TEXT_ARGUMENT_SCHEMA_FIELDS = ".argument_schema.fields[";
  function normalizeManifestTypeDeclarationIdentifier(value, name) {
    const identifier = assertString(value, name);
    if (!isCanonicalKotodamaIdentifier(identifier, { typeDeclaration: true })) {
      fail(
        V_CODE_INVALID_STRING,
        `${name}${TEXT_MUST_BE_A}canonical Kotodama V1 type declaration identifier`,
        name,
      );
    }
    return identifier;
  }

  function normalizeManifestStateTypeName(value, name) {
    const typeName = assertString(value, name);
    if (!isCanonicalKotodamaStateTypeName(typeName)) {
      fail(
        V_CODE_INVALID_STRING,
        `${name}${TEXT_MUST_BE_A}canonical Kotodama V1 state type`,
        name,
      );
    }
    return typeName;
  }

  function normalizeManifestFeaturesBitmap(value, name) {
    if (value === undefined || value === null) {
      return null;
    }
    const normalized = asNonNegativeInteger(value, name);
    if (normalized > 3) {
      fail(
        V_CODE_VALUE_OUT_OF_RANGE,
        `${name} contains unsupported Kotodama V1 feature bits`,
        name,
      );
    }
    return normalized;
  }

  function normalizeManifestHash(value, name) {
    if (value === undefined || value === null) return null;
    // Snapshot binary caller storage once before either validation or encoding.
    const input = typeof value === "string" ? value : normalizeByteArray(value, name);
    const normalized = normalizeOptionalHash(input, name);
    const bytes = typeof input === "string"
      ? input.trim().startsWith("hash:")
        ? parseHashLiteralToBuffer(input, name)
        : Buffer.from(input.trim(), "hex")
      : input;
    if ((bytes[31] & 1) !== 1) {
      fail(V_CODE_INVALID_HEX, `${name} must set the Iroha Hash marker bit`, name);
    }
    return normalized;
  }

  function normalizeContractManifest(manifest) {
    const source = assertPlainObject(manifest, "manifest");
    validateManifestFieldsV1(source, "manifest", (message) =>
      fail(V_CODE_INVALID_OBJECT, message, "manifest"),
    );
    const seiyakuName = source.seiyaku_name ?? source.seiyakuName;
    const compilerFingerprint = source.compiler_fingerprint ?? source.compilerFingerprint;
    const featuresBitmap = source.features_bitmap ?? source.featuresBitmap;
    const entrypoints = source.entrypoints ?? source.entryPoints;
    const normalized = {
      seiyaku_name:
        seiyakuName === undefined || seiyakuName === null
          ? null
          : normalizeManifestTypeDeclarationIdentifier(
              seiyakuName,
              "manifest.seiyakuName",
            ),
      code_hash: normalizeManifestHash(
        source.code_hash ?? source.codeHash,
        "manifest.codeHash",
      ),
      abi_hash: normalizeManifestHash(
        source.abi_hash ?? source.abiHash,
        "manifest.abiHash",
      ),
      compiler_fingerprint:
        compilerFingerprint === undefined || compilerFingerprint === null
          ? null
          : assertString(
              compilerFingerprint,
              "manifest.compilerFingerprint",
            ),
      features_bitmap: normalizeManifestFeaturesBitmap(
        featuresBitmap,
        "manifest.featuresBitmap",
      ),
      access_set_hints: normalizeAccessSetHints(
        source.access_set_hints ?? source.accessSetHints,
        "manifest.accessSetHints",
      ),
      permissions: normalizeContractPermissionsV1(source.permissions, "manifest.permissions"),
      events: normalizeContractEventsV1(source.events, "manifest.events"),
      enum_types: normalizeContractEnumTypesV1(source.enum_types ?? source.enumTypes, "manifest.enum_types"),
      entrypoints: normalizeEntrypoints(entrypoints, "manifest.entrypoints"),
      states: normalizeManifestStates(source.states, "manifest.states"),
      error_types: normalizeManifestErrorTypes(
        source.error_types ?? source.errorTypes,
        "manifest.errorTypes",
      ),
      error_messages: normalizeContractErrorMessagesV1(source.error_messages ?? source.errorMessages, source.error_types ?? source.errorTypes, "manifest.errorMessages"),
      kotoba:
        source.kotoba === undefined || source.kotoba === null
          ? null
          : normalizeContractKotobaEntries(source.kotoba, "manifest.kotoba"),
      provenance:
        source.provenance === undefined || source.provenance === null
          ? null
          : normalizeManifestProvenance(source.provenance, "manifest.provenance"),
    };
    validateManifestDeclarationsV1(normalized, "manifest");
    validateManifestErrorTypeBindingsV1(normalized);
    validateManifestDynamicAccessHintStateMaps(normalized);
    return normalized;
  }

  function normalizeContractKotobaEntries(value, name) {
    if (!Array.isArray(value)) {
      fail(
        V_CODE_INVALID_OBJECT,
        `${name}${TEXT_MUST_BE_AN}array of translation entries`,
        name,
      );
    }
    return value.map((entry, index) => {
      const normalizedEntry = assertPlainObject(entry, `${name}[${index}]`);
      return {
        msg_id: assertString(
          normalizedEntry.msg_id ?? normalizedEntry.msgId,
          `${name}[${index}].msg_id`,
        ),
        translations: normalizeContractKotobaTranslations(
          normalizedEntry.translations,
          `${name}[${index}].translations`,
        ),
      };
    });
  }

  function normalizeContractKotobaTranslations(value, name) {
    if (!Array.isArray(value)) {
      fail(
        V_CODE_INVALID_OBJECT,
        `${name}${TEXT_MUST_BE_AN}array of translations`,
        name,
      );
    }
    return value.map((translation, index) => {
      const source = assertPlainObject(translation, `${name}[${index}]`);
      return {
        lang: assertString(source.lang, `${name}[${index}].lang`),
        text: assertString(source.text, `${name}[${index}].text`),
      };
    });
  }

  function decodeManifestVarint(buffer, startIndex, context) {
    let value = 0n;
    let shift = 0n;
    let index = startIndex;
    while (index < buffer.length) {
      const byte = BigInt(buffer[index]);
      value |= (byte & 0x7fn) << shift;
      index += 1;
      if ((byte & 0x80n) === 0n) {
        if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
          fail(
            V_CODE_INVALID_MULTIHASH,
            `${context} contains an oversized multihash varint`,
            context,
          );
        }
        return { value: Number(value), nextIndex: index };
      }
      shift += 7n;
      if (shift > 63n) {
        fail(
          V_CODE_INVALID_MULTIHASH,
          `${context} contains an invalid multihash varint`,
          context,
        );
      }
    }
    fail(
      V_CODE_INVALID_MULTIHASH,
      `${context} contains a truncated multihash varint`,
      context,
    );
  }

  function normalizeManifestPublicKeyLiteral(value, name) {
    const literal = assertString(value, name).trim();
    let prefixedAlgorithm = null;
    let multihashLiteral = literal;
    const separator = literal.indexOf(":");
    if (separator > 0) {
      prefixedAlgorithm = literal.slice(0, separator).trim().toLowerCase();
      multihashLiteral = literal.slice(separator + 1);
    }
    const canonical = canonicalizeMultihashHex(multihashLiteral, name);
    const bytes = Buffer.from(canonical, "hex");
    const functionCode = decodeManifestVarint(bytes, 0, name);
    const digestLength = decodeManifestVarint(bytes, functionCode.nextIndex, name);
    const payload = bytes.subarray(digestLength.nextIndex);
    if (payload.length !== digestLength.value) {
      fail(
        V_CODE_INVALID_MULTIHASH,
        `${name} multihash payload length does not match its digest header`,
        name,
      );
    }
    const entry = getCurveEntryByPublicKeyMulticodec(functionCode.value);
    if (!entry) {
      fail(
        V_CODE_INVALID_MULTIHASH,
        `${name} uses unsupported multihash code 0x${functionCode.value.toString(16)}`,
        name,
      );
    }
    if (
      prefixedAlgorithm &&
      prefixedAlgorithm !== entry.algorithm &&
      !(prefixedAlgorithm === "mldsa" && entry.algorithm === "ml-dsa")
    ) {
      fail(
        V_CODE_INVALID_MULTIHASH,
        `${name} algorithm prefix does not match the multihash payload`,
        name,
      );
    }
    validatePublicKeyForCurve(entry.id, payload, name);
    const fnHex = bytes.subarray(0, functionCode.nextIndex).toString("hex");
    const lenHex = bytes.subarray(functionCode.nextIndex, digestLength.nextIndex).toString("hex");
    const payloadHex = payload.toString("hex").toUpperCase();
    return `${fnHex}${lenHex}${payloadHex}`;
  }

  function normalizeManifestSignatureLiteral(value, name) {
    let body;
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
      body = Buffer.from(value).toString("hex");
    } else if (Array.isArray(value)) {
      body = Buffer.from(normalizeByteArray(value, name)).toString("hex");
    } else {
      const literal = assertString(value, name).trim();
      body =
        literal.includes(":") && literal.indexOf(":") > 0
          ? literal.slice(literal.indexOf(":") + 1)
          : literal;
    }
    if (body.length === 0 || body.length % 2 !== 0 || !/^[0-9A-Fa-f]+$/u.test(body)) {
      fail(
        V_CODE_INVALID_HEX,
        `${name}${TEXT_MUST_BE_AN}even-length hexadecimal string`,
        name,
      );
    }
    const canonical = body.toUpperCase();
    if (/^0+$/u.test(canonical)) {
      fail(
        V_CODE_INVALID_HEX,
        `${name} must not be all zero`,
        name,
      );
    }
    return canonical;
  }

  function normalizeManifestProvenance(value, name) {
    const source = assertPlainObject(value, name);
    return {
      signer: normalizeManifestPublicKeyLiteral(source.signer, `${name}.signer`),
      signature: normalizeManifestSignatureLiteral(source.signature, `${name}.signature`),
    };
  }

  function normalizeEntrypoints(value, name) {
    if (value === undefined || value === null) {
      return null;
    }
    if (!Array.isArray(value)) {
      fail(
        V_CODE_INVALID_OBJECT,
        `${name}${TEXT_MUST_BE_AN}array of entrypoint descriptors`,
        name,
      );
    }
    if (value.length === 0) {
      return [];
    }
    return value.map((entry, index) => normalizeEntrypoint(entry, `${name}[${index}]`));
  }

  function normalizeEntrypoint(entry, name) {
    const source = assertPlainObject(entry, name);
    const entrypointName = assertString(source.name, `${name}.name`);
    if (!entrypointName) {
      fail(
        V_CODE_INVALID_STRING,
        `${name}.name${TEXT_MUST_BE}a non-empty string`,
        `${name}.name`,
      );
    }
    if (Object.hasOwn(source, "permission")) throw new TypeError(`${name}.permission is retired; use authorization`);
    const authorization = normalizeEntrypointAuthorizationV1(source.authorization, `${name}.authorization`);
    const kind = normalizeEntrypointKind(
      source.kind,
      `${name}.kind`,
    );
    validateManifestEntrypointIdentityV1(entrypointName, kind.kind, authorization, name);
    const params = normalizeEntrypointParams(source.params, `${name}.params`);
    const argumentSchema = normalizeEntrypointArgumentSchema(
      source.argument_schema ?? source.argumentSchema,
      `${name}${TEXT_ARGUMENT_SCHEMA}`,
    );
    const returnType = normalizeOptionalManifestString(
      source.return_type ?? source.returnType,
      `${name}.return_type`,
    );
    const returnSchema = normalizeEntrypointValueType(
      source.return_schema ?? source.returnSchema,
      `${name}.return_schema`,
    );
    validateEntrypointSchemaBindings(
      params,
      argumentSchema,
      returnType,
      returnSchema,
      name,
    );
    return {
      name: entrypointName,
      kind,
      params,
      argument_schema: argumentSchema,
      return_type: returnType,
      return_schema: returnSchema,
      authorization,
      read_keys: normalizeManifestStringArray(
        source.read_keys ?? source.readKeys,
        `${name}.read_keys`,
      ),
      write_keys: normalizeManifestStringArray(
        source.write_keys ?? source.writeKeys,
        `${name}.write_keys`,
      ),
      access_hints_complete: normalizeOptionalManifestBoolean(
        source.access_hints_complete ?? source.accessHintsComplete,
        `${name}.access_hints_complete`,
      ),
      access_hints_skipped: normalizeManifestStringArray(
        source.access_hints_skipped ?? source.accessHintsSkipped,
        `${name}.access_hints_skipped`,
      ),
      triggers: normalizeManifestTriggers(source.triggers, `${name}.triggers`),
    };
  }

  function validateEntrypointSchemaBindings(
    params,
    argumentSchema,
    returnType,
    returnSchema,
    name,
  ) {
    const paramNames = new Set();
    params.forEach((param, index) => {
      if (
        !isCanonicalKotodamaIdentifier(param.name) ||
        paramNames.has(param.name)
      ) {
        fail(
          V_CODE_INVALID_STRING,
          `${name}.params[${index}].name${TEXT_MUST_BE}unique and canonical`,
          `${name}.params[${index}].name`,
        );
      }
      paramNames.add(param.name);
    });
    if (params.length === 0) {
      if (argumentSchema !== null) {
        fail(
          V_CODE_INVALID_OBJECT,
          `${name}.argument_schema${TEXT_MUST_BE}null without parameters`,
          `${name}${TEXT_ARGUMENT_SCHEMA}`,
        );
      }
    } else if (argumentSchema === null) {
      fail(
        V_CODE_INVALID_OBJECT,
        `${name}.argument_schema is required for declared parameters`,
        `${name}${TEXT_ARGUMENT_SCHEMA}`,
      );
    } else {
      if (
        argumentSchema.fields.length === 0 ||
        argumentSchema.fields.length > MAX_ENTRYPOINT_CALL_TABLE_WORDS_V1 ||
        argumentSchema.fields.length !== params.length
      ) {
        fail(
          V_CODE_INVALID_OBJECT,
          `${name}.argument_schema.fields must exactly match 1..8192 declared parameters`,
          `${name}.argument_schema.fields`,
        );
      }
      const fieldNames = new Set();
      let argumentWords = 0;
      argumentSchema.fields.forEach((field, index) => {
        if (
          !isCanonicalKotodamaIdentifier(field.name) ||
          fieldNames.has(field.name)
        ) {
          fail(
            V_CODE_INVALID_STRING,
            `${name}${TEXT_ARGUMENT_SCHEMA_FIELDS}${index}].name${TEXT_MUST_BE}unique and canonical`,
            `${name}${TEXT_ARGUMENT_SCHEMA_FIELDS}${index}].name`,
          );
        }
        fieldNames.add(field.name);
        const analysis = analyzeEntrypointValueTypeV1(
          field.ty,
          `${name}${TEXT_ARGUMENT_SCHEMA_FIELDS}${index}].ty`,
        );
        argumentWords += analysis.wordCount;
        if (
          field.name !== params[index].name ||
          analysis.canonicalName !== params[index].type_name
        ) {
          fail(
            V_CODE_INVALID_OBJECT,
            `${name}${TEXT_ARGUMENT_SCHEMA_FIELDS}${index}] does not match its declared parameter`,
            `${name}${TEXT_ARGUMENT_SCHEMA_FIELDS}${index}]`,
          );
        }
      });
      if (argumentWords > MAX_ENTRYPOINT_CALL_TABLE_WORDS_V1) {
        fail(
          V_CODE_VALUE_OUT_OF_RANGE,
          `${name}.argument_schema exceeds the V1 8192-word argument table`,
          `${name}${TEXT_ARGUMENT_SCHEMA}`,
        );
      }
    }
    if (returnType === null || returnSchema === null) {
      fail(
        V_CODE_INVALID_OBJECT,
        `${name}.return_type and return_schema${TEXT_MUST_BE}present together`,
        name,
      );
    }
    if (returnSchema !== null) {
      const analysis = analyzeEntrypointValueTypeV1(
        returnSchema,
        `${name}.return_schema`,
      );
      if (analysis.canonicalName !== returnType) {
        fail(
          V_CODE_INVALID_OBJECT,
          `${name}.return_schema does not match return_type`,
          `${name}.return_schema`,
        );
      }
      if (analysis.wordCount > MAX_ENTRYPOINT_CALL_TABLE_WORDS_V1) {
        fail(
          V_CODE_VALUE_OUT_OF_RANGE,
          `${name}.return_schema exceeds the V1 8192-word result table`,
          `${name}.return_schema`,
        );
      }
    }
  }

  function normalizeEntrypointKind(value, name) {
    const raw =
      value !== null && typeof value === "object" && !Array.isArray(value)
        ? value.kind
        : value;
    const normalized = String(raw ?? "")
      .trim()
      .toLowerCase();
    switch (normalized) {
      case "kotoage":
        return { kind: "Kotoage", value: null };
      case "view":
        return { kind: "View", value: null };
      case "hajimari":
        return { kind: "Hajimari", value: null };
      case "kaizen":
        return { kind: "Kaizen", value: null };
      default:
        fail(
          V_CODE_INVALID_STRING,
          `${name}${TEXT_MUST_BE}one of 'Kotoage', 'View', 'Hajimari', or 'Kaizen'`,
          name,
        );
    }
  }

  function normalizeOptionalManifestString(value, name) {
    if (value === undefined || value === null) {
      return null;
    }
    const normalized = assertString(value, name).trim();
    if (normalized.length === 0) {
      fail(V_CODE_INVALID_STRING, `${name} must not be empty`, name);
    }
    return normalized;
  }

  function normalizeOptionalManifestBoolean(value, name) {
    if (value === undefined || value === null) {
      return null;
    }
    if (typeof value !== "boolean") {
      fail(V_CODE_INVALID_OBJECT, `${name}${TEXT_MUST_BE_A}boolean`, name);
    }
    return value;
  }

  function normalizeManifestStringArray(value, name) {
    if (value === undefined || value === null) {
      return [];
    }
    if (!Array.isArray(value)) {
      fail(V_CODE_INVALID_OBJECT, `${name}${TEXT_MUST_BE_AN}array`, name);
    }
    return value.map((entry, index) => {
      const normalized = assertString(entry, `${name}[${index}]`).trim();
      if (normalized.length === 0) {
        fail(
          V_CODE_INVALID_STRING,
          `${name}[${index}] must not be empty`,
          `${name}[${index}]`,
        );
      }
      return normalized;
    });
  }

  function normalizeEntrypointParams(value, name) {
    if (value === undefined || value === null) {
      return [];
    }
    if (!Array.isArray(value)) {
      fail(V_CODE_INVALID_OBJECT, `${name}${TEXT_MUST_BE_AN}array`, name);
    }
    return value.map((param, index) => {
      const source = assertPlainObject(param, `${name}[${index}]`);
      return {
        name: normalizeRequiredManifestString(source.name, `${name}[${index}].name`),
        type_name: normalizeRequiredManifestString(
          selectEqualManifestAlias(
            source,
            "type_name",
            "typeName",
            `${name}[${index}].type_name`,
          ),
          `${name}[${index}].type_name`,
        ),
      };
    });
  }

  function normalizeRequiredManifestString(value, name) {
    const normalized = assertString(value, name).trim();
    if (normalized.length === 0) {
      fail(V_CODE_INVALID_STRING, `${name} must not be empty`, name);
    }
    return normalized;
  }

  function normalizeEntrypointArgumentSchema(value, name) {
    if (value === undefined || value === null) {
      return null;
    }
    const source = assertPlainObject(value, name);
    if (!Array.isArray(source.fields)) {
      fail(V_CODE_INVALID_OBJECT, `${name}.fields${TEXT_MUST_BE}an array`, name);
    }
    return {
      fields: source.fields.map((field, index) => {
        const fieldSource = assertPlainObject(field, `${name}.fields[${index}]`);
        return {
          name: normalizeRequiredManifestString(
            fieldSource.name,
            `${name}.fields[${index}].name`,
          ),
          ty: normalizeRequiredEntrypointValueType(
            fieldSource.ty,
            `${name}.fields[${index}].ty`,
          ),
        };
      }),
    };
  }

  function normalizeEntrypointValueType(value, name) {
    if (value === undefined || value === null) {
      return null;
    }
    return normalizeRequiredEntrypointValueType(value, name);
  }

  function normalizeRequiredEntrypointValueType(value, name) {
    const source = assertPlainObject(value, name);
    if (!Array.isArray(source.nodes)) {
      fail(V_CODE_INVALID_OBJECT, `${name}.nodes${TEXT_MUST_BE}an array`, name);
    }
    const normalized = {
      nodes: source.nodes.map((node, index) =>
        normalizeEntrypointValueTypeNode(node, `${name}.nodes[${index}]`),
      ),
    };
    analyzeEntrypointValueTypeV1(normalized, name);
    return normalized;
  }

  function normalizeEntrypointValueTypeNode(value, name) {
    const source = assertPlainObject(value, name);
    const kind = normalizeRequiredManifestString(source.kind, `${name}.kind`);
    switch (kind) {
      case "Struct": {
        const struct = assertPlainObject(source.value, `${name}.value`);
        return {
          kind,
          value: {
            name: normalizeRequiredManifestString(struct.name, `${name}.value.name`),
            fields: normalizeManifestStringArray(struct.fields, `${name}.value.fields`),
          },
        };
      }
      case "Tuple":
        return { kind, value: normalizeU16(source.value, `${name}.value`) };
      case "Unit":
      case "Option":
      case "Result":
        requireManifestNull(source.value, `${name}.value`);
        return { kind, value: null };
      case "List": {
        const list = assertPlainObject(source.value, `${name}.value`);
        const keys = Object.keys(list);
        if (keys.length !== 1 || keys[0] !== "capacity") {
          fail(
            V_CODE_INVALID_OBJECT,
            `${name}.value${TEXT_MUST_CONTAIN}only capacity; the element subtree follows in the enclosing node tape`,
            `${name}.value`,
          );
        }
        const capacity = asByte(list.capacity, `${name}.value.capacity`);
        if (capacity < 1 || capacity > 64) {
          fail(
            V_CODE_VALUE_OUT_OF_RANGE,
            `${name}.value.capacity${TEXT_MUST_BE}in 1..64`,
            `${name}.value.capacity`,
          );
        }
        return {
          kind,
          value: { capacity },
        };
      }
      case "Error":
        return { kind, value: normalizeContractErrorTypeV1(source.value, `${name}.value`) };
      case "Enum":
        return { kind, value: normalizeContractEnumTypeV1(source.value, `${name}.value`) };
      case "StateCursor":
        analyzeStateKeyTypeV1(source.value, `${name}.value`);
        return { kind, value: normalizeRequiredEntrypointValueType(source.value, `${name}.value`) };
      case "Leaf":
        return {
          kind,
          value: normalizeEntrypointValueKind(source.value, `${name}.value`),
        };
      default:
        fail(
          V_CODE_INVALID_STRING,
          `${name}.kind is not a V1 entrypoint value-type node`,
          `${name}.kind`,
        );
    }
  }

  function normalizeEntrypointValueKind(value, name) {
    const source = assertPlainObject(value, name);
    const kind = normalizeRequiredManifestString(source.kind, `${name}.kind`);
    const allowed = new Set([
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
    if (!allowed.has(kind)) {
      fail(
        V_CODE_INVALID_STRING,
        `${name}.kind is not a V1 entrypoint value kind`,
        `${name}.kind`,
      );
    }
    requireManifestNull(source.value, `${name}.value`);
    return { kind, value: null };
  }

  function normalizeU16(value, name) {
    const normalized = asNonNegativeInteger(value, name);
    if (normalized > 0xffff) {
      fail(V_CODE_VALUE_OUT_OF_RANGE, `${name} must fit in u16`, name);
    }
    return normalized;
  }

  function requireManifestNull(value, name) {
    if (value !== undefined && value !== null) {
      fail(V_CODE_INVALID_OBJECT, `${name}${TEXT_MUST_BE}null`, name);
    }
  }

  function normalizeManifestStates(value, name) {
    if (value === undefined || value === null) {
      return null;
    }
    if (!Array.isArray(value)) {
      fail(V_CODE_INVALID_OBJECT, `${name}${TEXT_MUST_BE_AN}array`, name);
    }
    const names = new Set();
    return value.map((state, index) => {
      const source = assertPlainObject(state, `${name}[${index}]`);
      const stateName = normalizeRequiredManifestString(
        source.name,
        `${name}[${index}].name`,
      );
      if (names.has(stateName)) {
        fail(
          V_CODE_INVALID_OBJECT,
          `${name} contains duplicate state name ${stateName}`,
          name,
        );
      }
      names.add(stateName);
      return {
        name: stateName,
        type_name: normalizeManifestStateTypeName(
          selectEqualManifestAlias(
            source,
            "type_name",
            "typeName",
            `${name}[${index}].type_name`,
          ),
          `${name}[${index}].type_name`,
        ),
      };
    });
  }

  function normalizeManifestErrorTypes(value, context) {
    return normalizeContractErrorTypesV1(value, context);
  }

  function normalizeManifestTriggers(value, name) {
    if (value === undefined || value === null) {
      return [];
    }
    if (!Array.isArray(value)) {
      fail(V_CODE_INVALID_OBJECT, `${name}${TEXT_MUST_BE_AN}array`, name);
    }
    return value.map((trigger, index) => {
      const source = assertPlainObject(trigger, `${name}[${index}]`);
      const callback = assertPlainObject(
        source.callback,
        `${name}[${index}].callback`,
      );
      const metadata = source.metadata ?? {};
      if (metadata === null || typeof metadata !== "object" || Array.isArray(metadata)) {
        fail(
          V_CODE_INVALID_OBJECT,
          `${name}[${index}].metadata${TEXT_MUST_BE}an object`,
          `${name}[${index}].metadata`,
        );
      }
      return {
        id: normalizeRequiredManifestString(source.id, `${name}[${index}].id`),
        repeats: normalizeManifestTriggerRepeats(
          source.repeats,
          `${name}[${index}].repeats`,
        ),
        filter: normalizeOptionalExactBase64String(
          source.filter,
          `${name}[${index}].filter`,
        ),
        authority:
          source.authority === undefined || source.authority === null
            ? null
            : normalizeAccountId(source.authority, `${name}[${index}].authority`),
        metadata: normalizeJsonValue(metadata, `${name}[${index}].metadata`),
        callback: {
          namespace: normalizeOptionalManifestString(
            callback.namespace,
            `${name}[${index}].callback.namespace`,
          ),
          entrypoint: normalizeRequiredManifestString(
            callback.entrypoint,
            `${name}[${index}].callback.entrypoint`,
          ),
        },
      };
    });
  }

  function normalizeManifestTriggerRepeats(value, name) {
    const source = assertPlainObject(value, name);
    const keys = Object.keys(source);
    if (keys.length !== 1) {
      fail(
        V_CODE_INVALID_OBJECT,
        `${name}${TEXT_MUST_CONTAIN_EXACTLY}one repeat variant`,
        name,
      );
    }
    if (keys[0] === "Indefinitely") {
      requireManifestNull(source.Indefinitely, `${name}.Indefinitely`);
      return { Indefinitely: null };
    }
    if (keys[0] === "Exactly") {
      const count = asNonNegativeInteger(source.Exactly, `${name}.Exactly`);
      if (count > 0xffff_ffff) {
        fail(
          V_CODE_VALUE_OUT_OF_RANGE,
          `${name}.Exactly must fit in u32`,
          `${name}.Exactly`,
        );
      }
      return { Exactly: count };
    }
    fail(
      V_CODE_INVALID_STRING,
      `${name}${TEXT_MUST_BE}Indefinitely or Exactly`,
      name,
    );
  }

  return [normalizeContractManifest, normalizeManifestProvenance];
}
