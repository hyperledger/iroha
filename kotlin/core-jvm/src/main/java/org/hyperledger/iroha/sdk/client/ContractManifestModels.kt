package org.hyperledger.iroha.sdk.client

import java.math.BigInteger
import org.hyperledger.iroha.sdk.core.model.NetworkId
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.Collections
import java.util.LinkedHashMap
import org.hyperledger.iroha.sdk.address.requireCanonicalI105Address
import org.hyperledger.iroha.sdk.crypto.IrohaHash

/** Branded Kotodama V1 entrypoint categories carried by contract manifests. */
enum class ContractEntrypointKind {
    KOTOAGE,
    VIEW,
    HAJIMARI,
    KAIZEN,
}

/** Scalar and pointer leaves supported by an exact Kotodama V1 boundary schema. */
enum class EntrypointValueKindV1 {
    INT,
    DECIMAL,
    QUANTITY,
    BOOL,
    STRING,
    JSON,
    NAME,
    ACCOUNT_ID,
    ASSET_DEFINITION_ID,
    ASSET_ID,
    DOMAIN_ID,
    NFT_ID,
    DATA_SPACE_ID,
    BLOB,
}

/** Tree-node categories encoded on an exact flat preorder Kotodama V1 schema tape. */
enum class EntrypointValueTypeNodeKindV1 {
    STRUCT,
    TUPLE,
    OPTION,
    RESULT,
    LIST,
    LEAF,
    UNIT,
    ERROR,
    STATE_CURSOR,
    ENUM,
}

/** Named product metadata for one exact boundary-schema node. */
class EntrypointStructTypeNodeV1(
    @JvmField val name: String,
    fields: List<String>,
) {
    @JvmField val fields: List<String> = Collections.unmodifiableList(ArrayList(fields))
}

/** Bounded-list metadata; its element subtree immediately follows in the enclosing node tape. */
class EntrypointListTypeNodeV1(
    @JvmField val capacity: Int,
)

/** One validated preorder node in an exact Kotodama V1 boundary schema. */
class EntrypointValueTypeNodeV1(
    @JvmField val kind: EntrypointValueTypeNodeKindV1,
    @JvmField val structValue: EntrypointStructTypeNodeV1? = null,
    @JvmField val tupleArity: Int? = null,
    @JvmField val listValue: EntrypointListTypeNodeV1? = null,
    @JvmField val leafKind: EntrypointValueKindV1? = null,
    @JvmField val errorType: ContractErrorTypeDescriptor? = null,
    @JvmField val enumType: ContractEnumTypeDescriptor? = null,
    @JvmField val cursorKeySchema: EntrypointValueTypeV1? = null,
)

/** Exact flat preorder value schema used at a Kotodama V1 public boundary. */
class EntrypointValueTypeV1 internal constructor(
    nodes: List<EntrypointValueTypeNodeV1>,
    @JvmField val wordCount: Int,
    @JvmField val canonicalTypeName: String,
) {
    @JvmField val nodes: List<EntrypointValueTypeNodeV1> =
        Collections.unmodifiableList(ArrayList(nodes))
}

/** One named field in a canonical V1 entrypoint argument record. */
class EntrypointArgumentFieldV1(
    @JvmField val name: String,
    @JvmField val valueType: EntrypointValueTypeV1,
)

/** Exact canonical V1 schema for one public entrypoint argument record. */
class EntrypointArgumentSchemaV1(
    fields: List<EntrypointArgumentFieldV1>,
    @JvmField val wordCount: Int,
) {
    @JvmField val fields: List<EntrypointArgumentFieldV1> =
        Collections.unmodifiableList(ArrayList(fields))
}

/** One public parameter advertised by a Kotodama manifest. */
class ContractEntrypointParameter(
    @JvmField val name: String,
    @JvmField val typeName: String,
)

/** One compiler-advertised bounded dynamic state access. */
class ContractDynamicAccessHint(
    @JvmField val baseKey: String,
    @JvmField val keyType: String,
    @JvmField val boundKind: String,
    @JvmField val maxKeys: Long,
)

/** Static and bounded-dynamic scheduler hints in a contract manifest. */
class ContractAccessSetHints(
    readKeys: List<String>,
    writeKeys: List<String>,
    dynamicReads: List<ContractDynamicAccessHint>,
    dynamicWrites: List<ContractDynamicAccessHint>,
) {
    @JvmField val readKeys: List<String> = Collections.unmodifiableList(ArrayList(readKeys))
    @JvmField val writeKeys: List<String> = Collections.unmodifiableList(ArrayList(writeKeys))
    @JvmField val dynamicReads: List<ContractDynamicAccessHint> =
        Collections.unmodifiableList(ArrayList(dynamicReads))
    @JvmField val dynamicWrites: List<ContractDynamicAccessHint> =
        Collections.unmodifiableList(ArrayList(dynamicWrites))
}

/** Trigger repetition policy encoded by the Rust `Repeats` enum. */
enum class ContractTriggerRepeatsKind {
    INDEFINITELY,
    EXACTLY,
}

/** Exact trigger repetition policy in a manifest entrypoint descriptor. */
class ContractTriggerRepeats(
    @JvmField val kind: ContractTriggerRepeatsKind,
    @JvmField val exactly: Long?,
)

/** Callback target for a manifest trigger. */
class ContractTriggerCallback(
    @JvmField val namespace: String?,
    @JvmField val entrypoint: String,
)

/** Complete trigger metadata attached to one manifest entrypoint. */
class ContractTriggerDescriptor(
    @JvmField val id: String,
    @JvmField val repeats: ContractTriggerRepeats,
    @JvmField val filterBase64: String,
    @JvmField val authority: String?,
    metadata: Map<String, Any?>,
    @JvmField val callback: ContractTriggerCallback,
) {
    @JvmField val metadata: Map<String, Any?> = immutableJsonObject(metadata)
}

/** Closed caller authorization carried by every entrypoint. */
sealed class EntrypointAuthorizationV1 {
    /** Any caller may invoke this entrypoint. */
    object Anyone : EntrypointAuthorizationV1()
    /** The caller must hold this declared permission. */
    class Permission(@JvmField val name: String) : EntrypointAuthorizationV1()
    /** The exact runtime lifecycle token authorizes this hook. */
    object RuntimeLifecycle : EntrypointAuthorizationV1()
}

/** Scope of a declared contract permission. */
sealed class ContractPermissionScopeV1 {
    /** The grant binds one contract address and declaration name. */
    object Instance : ContractPermissionScopeV1()
    /** An explicit import of an exact chain-wide null-payload permission. */
    class Chain(@JvmField val permissionName: String) : ContractPermissionScopeV1()
}

/** One signed permission declaration in canonical name order. */
class ContractPermissionDescriptorV1(
    @JvmField val name: String,
    @JvmField val scope: ContractPermissionScopeV1,
)

/** Exact public interface metadata for one Kotodama entrypoint. */
class ContractEntrypointDescriptor(
    @JvmField val name: String,
    @JvmField val kind: ContractEntrypointKind,
    parameters: List<ContractEntrypointParameter>,
    @JvmField val argumentSchema: EntrypointArgumentSchemaV1?,
    @JvmField val returnType: String?,
    @JvmField val returnSchema: EntrypointValueTypeV1?,
    @JvmField val authorization: EntrypointAuthorizationV1,
    readKeys: List<String>,
    writeKeys: List<String>,
    @JvmField val accessHintsComplete: Boolean?,
    accessHintsSkipped: List<String>,
    triggers: List<ContractTriggerDescriptor>,
) {
    @JvmField val parameters: List<ContractEntrypointParameter> =
        Collections.unmodifiableList(ArrayList(parameters))
    @JvmField val readKeys: List<String> = Collections.unmodifiableList(ArrayList(readKeys))
    @JvmField val writeKeys: List<String> = Collections.unmodifiableList(ArrayList(writeKeys))
    @JvmField val accessHintsSkipped: List<String> =
        Collections.unmodifiableList(ArrayList(accessHintsSkipped))
    @JvmField val triggers: List<ContractTriggerDescriptor> =
        Collections.unmodifiableList(ArrayList(triggers))
}

/** One durable state slot advertised by a Kotodama seiyaku. */
class ContractStateDescriptor(
    @JvmField val name: String,
    @JvmField val typeName: String,
)

/** One nonzero enum-local variant in a finite nominal error type. */
class ContractErrorVariantDescriptor(
    @JvmField val name: String,
    @JvmField val code: Long,
)

/** Stable package/unit/enum identity and exact ordered variant schema. */
class ContractErrorTypeDescriptor(
    @JvmField val identity: String,
    variants: List<ContractErrorVariantDescriptor>,
) {
    @JvmField val variants: List<ContractErrorVariantDescriptor> =
        Collections.unmodifiableList(ArrayList(variants))
}

/** One nonzero enum-local variant in a finite nominal ordinary enum type. */
class ContractEnumVariantDescriptor(
    @JvmField val name: String,
    @JvmField val code: Long,
)

/** Stable package/unit/enum identity and exact ordered variant schema. */
class ContractEnumTypeDescriptor(
    @JvmField val identity: String,
    variants: List<ContractEnumVariantDescriptor>,
) {
    @JvmField val variants: List<ContractEnumVariantDescriptor> =
        Collections.unmodifiableList(ArrayList(variants))
}

/** Authenticated source event with its complete durable public payload schema. */
class ContractEventDescriptor(
    @JvmField val name: String,
    @JvmField val payloadType: EntrypointValueTypeV1,
)

/** Authenticated static presentation text for a declared nominal error variant. */
class ContractErrorMessage(
    @JvmField val errorType: String,
    @JvmField val code: Long,
    @JvmField val message: String,
)

/** One localized text in a `kotoba` manifest table. */
class ContractKotobaTranslation(
    @JvmField val language: String,
    @JvmField val text: String,
)

/** One stable message identifier and all of its localized texts. */
class ContractKotobaTranslationEntry(
    @JvmField val messageId: String,
    translations: List<ContractKotobaTranslation>,
) {
    @JvmField val translations: List<ContractKotobaTranslation> =
        Collections.unmodifiableList(ArrayList(translations))
}

/** Signature metadata binding a manifest to its approved signer. */
class ContractManifestProvenance(
    @JvmField val signer: String,
    @JvmField val signature: String,
)

/** Full on-chain `ContractManifest` returned by Torii. */
class ContractManifest(
    @JvmField val seiyakuName: String?,
    @JvmField val codeHashHex: String?,
    @JvmField val abiHashHex: String?,
    @JvmField val compilerFingerprint: String?,
    @JvmField val featuresBitmap: BigInteger?,
    @JvmField val accessSetHints: ContractAccessSetHints?,
    permissions: List<ContractPermissionDescriptorV1>,
    events: List<ContractEventDescriptor>,
    entrypoints: List<ContractEntrypointDescriptor>?,
    states: List<ContractStateDescriptor>?,
    errorTypes: List<ContractErrorTypeDescriptor>?,
    enumTypes: List<ContractEnumTypeDescriptor>,
    errorMessages: List<ContractErrorMessage>?,
    kotoba: List<ContractKotobaTranslationEntry>?,
    @JvmField val provenance: ContractManifestProvenance?,
) {
    @JvmField val permissions: List<ContractPermissionDescriptorV1> = Collections.unmodifiableList(ArrayList(permissions))
    @JvmField val events: List<ContractEventDescriptor> = Collections.unmodifiableList(ArrayList(events))
    @JvmField val enumTypes: List<ContractEnumTypeDescriptor> = Collections.unmodifiableList(ArrayList(enumTypes))
    @JvmField val entrypoints: List<ContractEntrypointDescriptor>? = entrypoints?.let {
        Collections.unmodifiableList(ArrayList(it))
    }
    @JvmField val states: List<ContractStateDescriptor>? = states?.let {
        Collections.unmodifiableList(ArrayList(it))
    }
    @JvmField val errorTypes: List<ContractErrorTypeDescriptor>? = errorTypes?.let {
        Collections.unmodifiableList(ArrayList(it))
    }
    @JvmField val errorMessages: List<ContractErrorMessage>? = errorMessages?.let {
        Collections.unmodifiableList(ArrayList(it))
    }
    @JvmField val kotoba: List<ContractKotobaTranslationEntry>? = kotoba?.let {
        Collections.unmodifiableList(ArrayList(it))
    }
}

/** Authenticated response from one exact dataspace artifact registry. */
class ContractManifestRecord(
    @JvmField val networkId: NetworkId,
    @JvmField val artifactId: ContractArtifactId,
    @JvmField val manifest: ContractManifest,
    @JvmField val codeHashHex: String?,
    @JvmField val abiHashHex: String?,
    /** Optional complete artifact bytes in canonical base64, verified against the artifact ID. */
    @JvmField val codeBytes: String?,
) {
    init {
        require(codeHashHex == artifactId.codeHashHex && codeHashHex == manifest.codeHashHex) {
            "record code hash must equal the artifact identity and manifest"
        }
        require(abiHashHex == manifest.abiHashHex) {
            "record ABI hash must equal the manifest"
        }
        if (codeBytes != null) {
            val maximum = 16 * 1024 * 1024
            require(codeBytes.length <= ((maximum + 2) / 3) * 4) { "code_bytes exceeds the artifact limit" }
            val bytes = Base64.getDecoder().decode(codeBytes)
            require(bytes.isNotEmpty() && bytes.size <= maximum && Base64.getEncoder().encodeToString(bytes) == codeBytes) {
                "code_bytes must be bounded canonical base64"
            }
            val digest = IrohaHash.prehash("iroha:ivm:contract-artifact:v1\u0000".toByteArray(StandardCharsets.UTF_8) + bytes)
            require(digest.joinToString("") { "%02x".format(it.toInt() and 0xff) } == artifactId.codeHashHex) {
                "code_bytes must match the complete artifact hash"
            }
        }
    }
}

/** Strict parser for the full Rust `ContractManifest` JSON shape. */
object ContractManifestJsonParser {
    private const val CALL_TABLE_WORD_LIMIT_V1 = 8_192

    private val maxU64 = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)
    // BEGIN GENERATED: kotodama-v1-validator-policy
    private val reservedIdentifiers = setOf(
        "as",
        "permission",
        "authorize",
        "break",
        "const",
        "continue",
        "else",
        "enum",
        "error",
        "export",
        "false",
        "fn",
        "for",
        "hajimari",
        "始まり",
        "if",
        "import",
        "in",
        "include",
        "kaizen",
        "改善",
        "kotoage",
        "言挙げ",
        "let",
        "match",
        "module",
        "return",
        "seiyaku",
        "誓約",
        "state",
        "struct",
        "event",
        "emit",
        "trigger",
        "true",
        "var",
        "view",
        "Amount",
    )
    private val reservedDeclarationNames = setOf(
        "int",
        "decimal",
        "quantity",
        "bool",
        "string",
        "bytes",
        "Json",
        "AccountId",
        "AssetDefinitionId",
        "AssetId",
        "DomainId",
        "Name",
        "NftId",
        "DataSpaceId",
        "Option",
        "Result",
        "List",
        "ListError",
        "NumericError",
        "StateMap",
        "StateCursor",
        "StatePage",
        "Secret",
        "AccountView",
        "AssetView",
        "AssetDefinitionView",
        "DomainView",
        "NftView",
        "QueryPage",
        "AxtDescriptor",
        "AxtAnchoredSpendV1",
        "ProofBlob",
        "SoracloudRequest",
        "SoracloudResponse",
        "state_map_get",
        "__kotodama_state_page",
        "__kotodama_state_take",
        "__kotodama_list_len",
        "__kotodama_list_get",
        "__kotodama_list_set",
        "__kotodama_list_push",
        "__kotodama_list_try_set",
        "__kotodama_list_try_push",
        "__kotodama_list_pop",
        "__kotodama_list_contains",
        "__kotodama_list_take",
        "__kotodama_list_enumerate",
        "__kotodama_decimal_div_round",
        "__kotodama_decimal_mul_div_round",
        "__kotodama_quantity_mul_div_round",
        "__kotodama_quantity_div_round",
        "__kotodama_quantity_ratio_round",
        "__kotodama_decimal_to_int_trunc",
        "__kotodama_decimal_to_int_round",
        "__kotodama_option_ok_or",
        "__kotodama_result_or_err",
    )
    private val retiredNumericTypeNames = setOf(
        "i8",
        "i16",
        "i32",
        "i64",
        "i128",
        "isize",
        "u8",
        "u16",
        "u32",
        "u64",
        "u128",
        "usize",
        "num",
        "Int",
        "Integer",
        "float",
        "f32",
        "f64",
        "Decimal",
        "Fixed",
        "FixedPoint",
        "Amount",
        "amount",
        "money",
        "Quantity",
        "number",
    )
    private val stateMapKeyTypeNames = setOf(
        "int",
        "decimal",
        "quantity",
        "bool",
        "string",
        "bytes",
        "DataSpaceId",
        "AccountId",
        "AssetDefinitionId",
        "AssetId",
        "NftId",
        "DomainId",
        "Name",
    )
    private val dynamicAccessBoundKinds = setOf(
        "page",
        "take",
    )
    private val maxDynamicAccessKeys = BigInteger.valueOf(64)
    // END GENERATED: kotodama-v1-validator-policy
    private val stateScalarTypeNames = setOf(
        "int", "decimal", "quantity", "bool", "string", "bytes", "DataSpaceId",
        "AccountId", "AssetDefinitionId", "AssetId", "NftId", "DomainId", "Name", "Json",
    )
    private const val maxStateTypeDepth = 256
    private const val maxStateTypeNodes = 256
    private val valueKindByWire = mapOf(
        "Int" to EntrypointValueKindV1.INT,
        "Decimal" to EntrypointValueKindV1.DECIMAL,
        "Quantity" to EntrypointValueKindV1.QUANTITY,
        "Bool" to EntrypointValueKindV1.BOOL,
        "String" to EntrypointValueKindV1.STRING,
        "Json" to EntrypointValueKindV1.JSON,
        "Name" to EntrypointValueKindV1.NAME,
        "AccountId" to EntrypointValueKindV1.ACCOUNT_ID,
        "AssetDefinitionId" to EntrypointValueKindV1.ASSET_DEFINITION_ID,
        "AssetId" to EntrypointValueKindV1.ASSET_ID,
        "DomainId" to EntrypointValueKindV1.DOMAIN_ID,
        "NftId" to EntrypointValueKindV1.NFT_ID,
        "DataSpaceId" to EntrypointValueKindV1.DATA_SPACE_ID,
        "Blob" to EntrypointValueKindV1.BLOB,
    )

    /** Parse and validate one complete Torii contract-manifest record. */
    @JvmStatic
    fun parseRecord(payload: ByteArray): ContractManifestRecord {
        val root = objectValue(parse(payload, "contract manifest response"), "contract manifest response")
        exactKeys(root, setOf("network_id", "artifact_id", "manifest", "code_hash", "abi_hash", "code_bytes"), "contract manifest response")
        val networkId = try {
            NetworkId.parse(exactString(required(root, "network_id", "contract manifest response"), "network_id"))
        } catch (error: IllegalArgumentException) {
            throw IllegalStateException("contract manifest response.network_id is not canonical", error)
        }
        val artifact = objectValue(required(root, "artifact_id", "contract manifest response"), "artifact_id")
        exactKeys(artifact, setOf("dataspace_id", "code_hash"), "artifact_id")
        val artifactId = try {
            ContractArtifactId(
                unsignedInteger(required(artifact, "dataspace_id", "artifact_id"), maxU64, "artifact_id.dataspace_id"),
                exactString(required(artifact, "code_hash", "artifact_id"), "artifact_id.code_hash"),
            )
        } catch (error: IllegalArgumentException) {
            throw IllegalStateException("contract manifest response.artifact_id is not canonical", error)
        }
        val manifest = parseManifest(
            objectValue(required(root, "manifest", "contract manifest response"), "contract manifest response.manifest"),
        )
        required(root, "code_hash", "contract manifest response")
        required(root, "abi_hash", "contract manifest response")
        val codeHash = optionalConvenienceHash(root, "code_hash", "contract manifest response.code_hash")
        val abiHash = optionalConvenienceHash(root, "abi_hash", "contract manifest response.abi_hash")
        check(codeHash == manifest.codeHashHex) {
            "contract manifest response.code_hash must exactly match manifest.code_hash"
        }
        check(abiHash == manifest.abiHashHex) {
            "contract manifest response.abi_hash must exactly match manifest.abi_hash"
        }
        check(codeHash == artifactId.codeHashHex) {
            "contract manifest response artifact_id must exactly match manifest.code_hash"
        }
        val codeBytes = root["code_bytes"]?.let { exactString(it, "contract manifest response.code_bytes") }
        return try {
            ContractManifestRecord(networkId, artifactId, manifest, codeHash, abiHash, codeBytes)
        } catch (error: IllegalArgumentException) {
            throw IllegalStateException("contract manifest response contains invalid code_bytes", error)
        }
    }

    /** Parse and validate one full Rust `ContractManifest` object. */
    @JvmStatic
    fun parseManifest(root: Map<String, Any?>): ContractManifest {
        exactKeys(
            root,
            setOf(
                "seiyaku_name", "code_hash", "abi_hash", "compiler_fingerprint",
                "features_bitmap", "access_set_hints", "permissions", "events", "entrypoints", "states", "error_types", "enum_types",
                "error_messages", "kotoba", "provenance",
            ),
            "manifest",
        )
        val seiyakuName = optionalExactString(root, "seiyaku_name", "manifest.seiyaku_name")
        if (seiyakuName != null) {
            check(canonicalTypeDeclarationIdentifier(seiyakuName)) {
                "manifest.seiyaku_name must be a canonical Kotodama identifier"
            }
        }
        val codeHash = optionalManifestHash(root, "code_hash", "manifest.code_hash")
        val abiHash = optionalManifestHash(root, "abi_hash", "manifest.abi_hash")
        val compilerFingerprint = optionalExactString(
            root,
            "compiler_fingerprint",
            "manifest.compiler_fingerprint",
        )
        val featuresBitmap = if (!root.containsKey("features_bitmap") || root["features_bitmap"] == null) {
            null
        } else {
            unsignedInteger(root["features_bitmap"], maxU64, "manifest.features_bitmap")
        }
        check(featuresBitmap == null || featuresBitmap <= BigInteger.valueOf(3)) {
            "manifest.features_bitmap contains unsupported Kotodama V1 bits"
        }
        val accessSetHints = optionalObject(root, "access_set_hints", "manifest.access_set_hints")
            ?.let(::parseAccessSetHints)
        val permissions = objectList(required(root, "permissions", "manifest"), "manifest.permissions", ::parsePermissionDeclaration)
        requireUnique(permissions.map { it.name }, "manifest.permissions")
        check(permissions.zipWithNext().all { (left, right) -> compareUtf8(left.name, right.name) < 0 }) {
            "manifest.permissions must be sorted and unique by name"
        }
        val entrypoints = optionalObjectList(root, "entrypoints", "manifest.entrypoints", ::parseEntrypoint)
        val states = optionalObjectList(root, "states", "manifest.states", ::parseState)
        val errorTypes = optionalObjectList(root, "error_types", "manifest.error_types", ::parseErrorType)
        val enumTypes = objectList(required(root, "enum_types", "manifest"), "manifest.enum_types", ::parseEnumType)
        val events = objectList(required(root, "events", "manifest"), "manifest.events", ::parseEvent)
        for ((label, names) in listOf("enum_types" to enumTypes.map { it.identity }, "events" to events.map { it.name })) {
            check(names.size <= 256 && names.zipWithNext().all { (left, right) -> compareUtf8(left, right) < 0 }) {
                "manifest.$label must contain at most 256 sorted unique declarations"
            }
        }
        val errorMessages = optionalObjectList(root, "error_messages", "manifest.error_messages", ::parseErrorMessage)
        val kotoba = optionalObjectList(root, "kotoba", "manifest.kotoba", ::parseKotobaEntry)
        val provenance = optionalObject(root, "provenance", "manifest.provenance")?.let(::parseProvenance)

        entrypoints?.let {
            val declaredPermissions = permissions.map { permission -> permission.name }.toSet()
            check(it.all { descriptor ->
                val authorization = descriptor.authorization
                authorization !is EntrypointAuthorizationV1.Permission || authorization.name in declaredPermissions
            }) { "entrypoint authorization refers to an undeclared permission" }
            val names = it.map { descriptor -> descriptor.name }
            requireUnique(names, "manifest.entrypoints")
            check(it.count { descriptor -> descriptor.kind == ContractEntrypointKind.HAJIMARI } <= 1) {
                "manifest.entrypoints must not declare multiple hajimari entrypoints"
            }
            check(it.count { descriptor -> descriptor.kind == ContractEntrypointKind.KAIZEN } <= 1) {
                "manifest.entrypoints must not declare multiple kaizen entrypoints"
            }
            val declared = it.associate { descriptor -> descriptor.name to descriptor.kind }
            val triggerIds = mutableSetOf<String>()
            it.flatMap { descriptor -> descriptor.triggers }.forEach { trigger ->
                check(triggerIds.add(trigger.id)) { "manifest trigger ids must be globally unique" }
                check(
                    trigger.callback.namespace != null ||
                        declared[trigger.callback.entrypoint] == ContractEntrypointKind.KOTOAGE,
                ) {
                    "manifest local trigger callback must name a declared kotoage entrypoint"
                }
            }
        }
        states?.let { requireUnique(it.map { descriptor -> descriptor.name }, "manifest.states") }
        validateDynamicAccessHintStateMaps(accessSetHints, states.orEmpty())
        errorTypes?.let {
            check(it.size <= 256) { "manifest.error_types exceeds 256 types" }
            requireUnique(it.map { descriptor -> descriptor.identity }, "manifest.error_types")
        }
        val errorCatalog = errorTypes.orEmpty().associateBy { it.identity }
        val enumCatalog = enumTypes.associateBy { it.identity }
        check(errorCatalog.keys.intersect(enumCatalog.keys).isEmpty()) { "enum_types and error_types identities must not overlap" }
        states.orEmpty().forEach { state ->
            check(StateTypeNameParser(state.typeName, errorCatalog.keys + enumCatalog.keys).parse()) {
                "manifest state nominal identity is not declared in an enum or error catalog"
            }
        }
        val schemas = events.map { it.payloadType } + entrypoints.orEmpty().flatMap { entrypoint ->
            entrypoint.argumentSchema?.fields.orEmpty().map { it.valueType } + listOfNotNull(entrypoint.returnSchema)
        }
        for (node in schemas.flatMap { it.nodes }) {
            if (node.kind == EntrypointValueTypeNodeKindV1.ERROR) {
                val descriptor = checkNotNull(node.errorType)
                val declared = errorCatalog[descriptor.identity]
                check(declared != null && declared.variants.map { it.name to it.code } == descriptor.variants.map { it.name to it.code }) {
                    "manifest boundary error schema does not match its error_types catalog"
                }
            }
            if (node.kind == EntrypointValueTypeNodeKindV1.ENUM) {
                val descriptor = checkNotNull(node.enumType)
                val declared = enumCatalog[descriptor.identity]
                check(declared != null && declared.variants.map { it.name to it.code } == descriptor.variants.map { it.name to it.code }) {
                    "manifest boundary enum schema does not match its enum_types catalog"
                }
            }
        }
        var previousMessage: ContractErrorMessage? = null
        for (entry in errorMessages.orEmpty()) {
            val error = errorTypes.orEmpty().find { it.identity == entry.errorType }
            check(error != null && error.variants.any { it.code == entry.code }) {
                "error message must reference a declared nominal error variant"
            }
            previousMessage?.let { previous ->
                val left = previous.errorType.toByteArray(StandardCharsets.UTF_8)
                val right = entry.errorType.toByteArray(StandardCharsets.UTF_8)
                var order = 0
                for (index in 0 until minOf(left.size, right.size)) {
                    order = (left[index].toInt() and 255) - (right[index].toInt() and 255)
                    if (order != 0) break
                }
                if (order == 0) order = left.size - right.size
                check(order < 0 || (order == 0 && previous.code < entry.code)) {
                    "error messages must be sorted and unique by identity and code"
                }
            }
            previousMessage = entry
        }
        kotoba?.let { requireUnique(it.map { entry -> entry.messageId }, "manifest.kotoba") }

        return ContractManifest(
            seiyakuName,
            codeHash,
            abiHash,
            compilerFingerprint,
            featuresBitmap,
            accessSetHints,
            permissions,
            events,
            entrypoints,
            states,
            errorTypes,
            enumTypes,
            errorMessages,
            kotoba,
            provenance,
        )
    }

    private fun parseAccessSetHints(root: Map<String, Any?>): ContractAccessSetHints {
        exactKeys(root, setOf("read_keys", "write_keys", "dynamic_reads", "dynamic_writes"), "manifest.access_set_hints")
        return ContractAccessSetHints(
            stringList(required(root, "read_keys", "manifest.access_set_hints"), "manifest.access_set_hints.read_keys"),
            stringList(required(root, "write_keys", "manifest.access_set_hints"), "manifest.access_set_hints.write_keys"),
            objectList(root["dynamic_reads"] ?: emptyList<Any?>(), "manifest.access_set_hints.dynamic_reads", ::parseDynamicHint),
            objectList(root["dynamic_writes"] ?: emptyList<Any?>(), "manifest.access_set_hints.dynamic_writes", ::parseDynamicHint),
        )
    }

    private fun parseDynamicHint(root: Map<String, Any?>): ContractDynamicAccessHint {
        exactKeys(root, setOf("base_key", "key_type", "bound_kind", "max_keys"), "dynamic access hint")
        val baseKey = exactString(required(root, "base_key", "dynamic access hint"), "dynamic access hint.base_key")
        val stateName = baseKey.removePrefix("state:")
        check(baseKey.startsWith("state:") && canonicalDeclarationIdentifier(stateName)) {
            "dynamic access hint.base_key must be state: followed by one canonical state declaration identifier"
        }
        val keyType = exactString(
            required(root, "key_type", "dynamic access hint"),
            "dynamic access hint.key_type",
        )
        check(canonicalKeyTypeName(keyType)) {
            "dynamic access hint.key_type must be an exact canonical StateMap key type"
        }
        val boundKind = exactString(
            required(root, "bound_kind", "dynamic access hint"),
            "dynamic access hint.bound_kind",
        )
        check(boundKind in dynamicAccessBoundKinds) {
            "dynamic access hint.bound_kind must be `take` or `page`"
        }
        val maxKeys = unsignedInteger(
            required(root, "max_keys", "dynamic access hint"),
            maxDynamicAccessKeys,
            "dynamic access hint.max_keys",
        ).longValueExact()
        check(maxKeys > 0) { "dynamic access hint.max_keys must be in 1..64" }
        return ContractDynamicAccessHint(
            baseKey,
            keyType,
            boundKind,
            maxKeys,
        )
    }

    private fun validateDynamicAccessHintStateMaps(
        accessSetHints: ContractAccessSetHints?,
        states: List<ContractStateDescriptor>,
    ) {
        if (accessSetHints == null) return

        val stateMapKeyTypes = states.mapNotNull { state ->
            topLevelStateMapKeyType(state.typeName)?.let { keyType -> state.name to keyType }
        }.toMap()
        listOf(
            "manifest.access_set_hints.dynamic_reads" to accessSetHints.dynamicReads,
            "manifest.access_set_hints.dynamic_writes" to accessSetHints.dynamicWrites,
        ).forEach { (field, hints) ->
            val unique = HashSet<List<Any>>()
            hints.forEach { hint ->
                check(unique.add(listOf(hint.baseKey, hint.keyType, hint.boundKind, hint.maxKeys))) {
                    "$field must not contain duplicate hints for `${hint.baseKey}`"
                }
                val stateName = hint.baseKey.removePrefix("state:")
                val expectedKeyType = stateMapKeyTypes[stateName]
                check(expectedKeyType != null) {
                    "$field hint `${hint.baseKey}` must reference a declared top-level StateMap"
                }
                check(hint.keyType == expectedKeyType) {
                    "$field hint `${hint.baseKey}` declares key_type `${hint.keyType}` " +
                        "but its StateMap key type is `$expectedKeyType`"
                }
            }
        }
    }

    private class KeyTypeNameParser(private val value: String, start: Int = 0) {
        var cursor = start; private set
        var nodes = 0; private set
        var maxDepth = 0; private set
        fun parse(depth: Int = 1): Boolean {
            nodes += 1; maxDepth = maxOf(maxDepth, depth)
            if (nodes > 256 || depth > 256) return false
            if (value.startsWith("(", cursor)) {
                cursor += 1
                if (!parse(depth + 1) || !consume(", ") || !parse(depth + 1)) return false
                while (consume(", ")) if (!parse(depth + 1)) return false
                return consume(")")
            }
            val start = cursor
            while (cursor < value.length && (value[cursor].isLetterOrDigit() || value[cursor] == '_')) cursor += 1
            return value.substring(start, cursor) in stateMapKeyTypeNames
        }
        private fun consume(text: String): Boolean {
            if (!value.startsWith(text, cursor)) return false
            cursor += text.length; return true
        }
    }
    private fun canonicalKeyTypeName(value: String): Boolean {
        val parser = KeyTypeNameParser(value)
        return parser.parse() && parser.cursor == value.length
    }
    private fun topLevelStateMapKeyType(typeName: String): String? {
        val prefix = "StateMap<"
        if (!typeName.startsWith(prefix)) return null
        val parser = KeyTypeNameParser(typeName, prefix.length)
        return if (parser.parse() && typeName.startsWith(", ", parser.cursor)) typeName.substring(prefix.length, parser.cursor) else null
    }

    private fun parseEntrypoint(root: Map<String, Any?>): ContractEntrypointDescriptor {
        exactKeys(
            root,
            setOf(
                "name", "kind", "params", "argument_schema", "return_type", "return_schema",
                "authorization", "read_keys", "write_keys", "access_hints_complete",
                "access_hints_skipped", "triggers",
            ),
            "entrypoint descriptor",
        )
        val name = exactString(required(root, "name", "entrypoint descriptor"), "entrypoint descriptor.name")
        check(canonicalEntrypointName(name)) {
            "entrypoint descriptor.name must be a canonical Kotodama identifier or branded lifecycle selector"
        }
        val kind = parseEntrypointKind(
            objectValue(required(root, "kind", "entrypoint descriptor"), "entrypoint descriptor.kind"),
        )
        check(
            (kind == ContractEntrypointKind.HAJIMARI && (name == "hajimari" || name == "始まり")) ||
                (kind == ContractEntrypointKind.KAIZEN && (name == "kaizen" || name == "改善")) ||
                (kind != ContractEntrypointKind.HAJIMARI && kind != ContractEntrypointKind.KAIZEN &&
                    name != "hajimari" && name != "始まり" && name != "kaizen" && name != "改善")
        ) { "entrypoint descriptor kind does not match its branded selector" }
        val parameters = objectList(root["params"] ?: emptyList<Any?>(), "entrypoint descriptor.params", ::parseParameter)
        check(parameters.size <= CALL_TABLE_WORD_LIMIT_V1) { "entrypoint descriptor.params exceeds the V1 argument limit" }
        requireUnique(parameters.map { it.name }, "entrypoint descriptor.params")
        val argumentSchema = optionalObject(root, "argument_schema", "entrypoint descriptor.argument_schema")
            ?.let(::parseArgumentSchema)
        check(
            (parameters.isEmpty() && argumentSchema == null) ||
                (parameters.isNotEmpty() && argumentSchema != null &&
                    parameters.size == argumentSchema.fields.size &&
                    parameters.indices.all { index ->
                        parameters[index].name == argumentSchema.fields[index].name &&
                            parameters[index].typeName == argumentSchema.fields[index].valueType.canonicalTypeName
                    })
        ) { "entrypoint descriptor argument schema does not exactly match params" }
        val returnType = optionalExactString(root, "return_type", "entrypoint descriptor.return_type")
            ?.let { currentTypeName(it, "entrypoint descriptor.return_type") }
        val returnSchema = optionalObject(root, "return_schema", "entrypoint descriptor.return_schema")
            ?.let(::parseValueType)
        check(returnType != null && returnSchema != null) {
            "entrypoint descriptor must declare return_type and return_schema, including Unit"
        }
        check(returnSchema.wordCount <= CALL_TABLE_WORD_LIMIT_V1 && returnSchema.canonicalTypeName == returnType) {
            "entrypoint descriptor return schema does not exactly match return_type"
        }
        val authorization = parseAuthorization(objectValue(required(root, "authorization", "entrypoint descriptor"), "entrypoint authorization"))
        val lifecycle = kind == ContractEntrypointKind.HAJIMARI || kind == ContractEntrypointKind.KAIZEN
        check(lifecycle == (authorization === EntrypointAuthorizationV1.RuntimeLifecycle)) {
            "entrypoint authorization must use RuntimeLifecycle exactly for lifecycle hooks"
        }
        val readKeys = stringList(root["read_keys"] ?: emptyList<Any?>(), "entrypoint descriptor.read_keys")
        val writeKeys = stringList(root["write_keys"] ?: emptyList<Any?>(), "entrypoint descriptor.write_keys")
        val complete = optionalBoolean(root, "access_hints_complete", "entrypoint descriptor.access_hints_complete")
        val skipped = stringList(root["access_hints_skipped"] ?: emptyList<Any?>(), "entrypoint descriptor.access_hints_skipped")
        check(complete != true || skipped.isEmpty()) {
            "complete access hints must not contain skipped reasons"
        }
        check(complete != false || skipped.isNotEmpty()) {
            "incomplete access hints must contain a skipped reason"
        }
        val triggers = objectList(root["triggers"] ?: emptyList<Any?>(), "entrypoint descriptor.triggers", ::parseTrigger)
        return ContractEntrypointDescriptor(
            name,
            kind,
            parameters,
            argumentSchema,
            returnType,
            returnSchema,
            authorization,
            readKeys,
            writeKeys,
            complete,
            skipped,
            triggers,
        )
    }

    private fun compareUtf8(left: String, right: String): Int {
        val a = left.toByteArray(StandardCharsets.UTF_8)
        val b = right.toByteArray(StandardCharsets.UTF_8)
        for (index in 0 until minOf(a.size, b.size)) {
            val order = (a[index].toInt() and 255) - (b[index].toInt() and 255)
            if (order != 0) return order
        }
        return a.size - b.size
    }

    private fun parseAuthorization(root: Map<String, Any?>): EntrypointAuthorizationV1 {
        exactKeys(root, setOf("kind", "value"), "entrypoint authorization")
        check(root.containsKey("value")) { "entrypoint authorization.value is required" }
        return when (exactString(required(root, "kind", "entrypoint authorization"), "entrypoint authorization.kind")) {
            "Anyone" -> { check(root["value"] == null); EntrypointAuthorizationV1.Anyone }
            "RuntimeLifecycle" -> { check(root["value"] == null); EntrypointAuthorizationV1.RuntimeLifecycle }
            "Permission" -> {
                val name = exactString(required(root, "value", "entrypoint authorization"), "entrypoint authorization.value")
                check(canonicalSourceIdentifier(name)) { "permission alias must be a canonical identifier" }
                EntrypointAuthorizationV1.Permission(name)
            }
            else -> error("unsupported entrypoint authorization")
        }
    }

    private fun parsePermissionDeclaration(root: Map<String, Any?>): ContractPermissionDescriptorV1 {
        exactKeys(root, setOf("name", "scope"), "permission declaration")
        val name = exactString(required(root, "name", "permission declaration"), "permission declaration.name")
        check(canonicalSourceIdentifier(name)) { "permission alias must be a canonical identifier" }
        val scope = objectValue(required(root, "scope", "permission declaration"), "permission declaration.scope")
        exactKeys(scope, setOf("kind", "value"), "permission declaration.scope")
        check(scope.containsKey("value")) { "permission scope.value is required" }
        val parsed = when (exactString(required(scope, "kind", "permission scope"), "permission scope.kind")) {
            "Instance" -> { check(scope["value"] == null); ContractPermissionScopeV1.Instance }
            "Chain" -> {
                val value = objectValue(scope["value"], "chain permission")
                exactKeys(value, setOf("permission_name"), "chain permission")
                val chainName = exactString(required(value, "permission_name", "chain permission"), "chain permission.permission_name")
                check(chainName.none { it.isWhitespace() }) { "chain permission must be an exact name" }
                ContractPermissionScopeV1.Chain(chainName)
            }
            else -> error("unsupported permission scope")
        }
        return ContractPermissionDescriptorV1(name, parsed)
    }

    private fun parseEntrypointKind(root: Map<String, Any?>): ContractEntrypointKind {
        exactKeys(root, setOf("kind", "value"), "entrypoint descriptor.kind")
        check(root.containsKey("value") && root["value"] == null) {
            "entrypoint descriptor.kind.value must be null"
        }
        return when (exactString(required(root, "kind", "entrypoint descriptor.kind"), "entrypoint descriptor.kind.kind")) {
            "Kotoage" -> ContractEntrypointKind.KOTOAGE
            "View" -> ContractEntrypointKind.VIEW
            "Hajimari" -> ContractEntrypointKind.HAJIMARI
            "Kaizen" -> ContractEntrypointKind.KAIZEN
            else -> error("unsupported branded Kotodama entrypoint kind")
        }
    }

    private fun parseParameter(root: Map<String, Any?>): ContractEntrypointParameter {
        exactKeys(root, setOf("name", "type_name"), "entrypoint parameter")
        val name = exactString(required(root, "name", "entrypoint parameter"), "entrypoint parameter.name")
        check(canonicalSourceIdentifier(name)) { "entrypoint parameter.name must be a canonical Kotodama identifier" }
        return ContractEntrypointParameter(
            name,
            currentTypeName(
                exactString(required(root, "type_name", "entrypoint parameter"), "entrypoint parameter.type_name"),
                "entrypoint parameter.type_name",
            ),
        )
    }

    private fun parseArgumentSchema(root: Map<String, Any?>): EntrypointArgumentSchemaV1 {
        exactKeys(root, setOf("fields"), "entrypoint argument schema")
        val fields = objectList(required(root, "fields", "entrypoint argument schema"), "entrypoint argument schema.fields", ::parseArgumentField)
        check(fields.isNotEmpty() && fields.size <= CALL_TABLE_WORD_LIMIT_V1) {
            "entrypoint argument schema must contain 1..8192 fields"
        }
        requireUnique(fields.map { it.name }, "entrypoint argument schema.fields")
        val words = fields.fold(0) { total, field -> total + field.valueType.wordCount }
        check(words <= CALL_TABLE_WORD_LIMIT_V1) { "entrypoint argument schema exceeds the V1 call table" }
        return EntrypointArgumentSchemaV1(fields, words)
    }

    private fun parseArgumentField(root: Map<String, Any?>): EntrypointArgumentFieldV1 {
        exactKeys(root, setOf("name", "ty"), "entrypoint argument field")
        val name = exactString(required(root, "name", "entrypoint argument field"), "entrypoint argument field.name")
        check(canonicalSourceIdentifier(name)) { "entrypoint argument field.name must be a canonical Kotodama identifier" }
        return EntrypointArgumentFieldV1(
            name,
            parseValueType(objectValue(required(root, "ty", "entrypoint argument field"), "entrypoint argument field.ty")),
        )
    }

    private fun parseValueType(root: Map<String, Any?>): EntrypointValueTypeV1 {
        exactKeys(root, setOf("nodes"), "entrypoint value type")
        val nodes = objectList(required(root, "nodes", "entrypoint value type"), "entrypoint value type.nodes", ::parseValueTypeNode)
        check(nodes.isNotEmpty() && nodes.size <= 256) { "entrypoint value type must contain 1..256 nodes" }
        val analysis = analyzeValueType(nodes)
        check(
            analysis.nextIndex == nodes.size &&
                analysis.nodeCount <= 256 &&
                validateReservedNominalShapes(nodes),
        ) {
            "entrypoint value type is not one canonical flat preorder V1 schema"
        }
        return EntrypointValueTypeV1(nodes, analysis.wordCount, analysis.typeName)
    }

    private fun parseValueTypeNode(root: Map<String, Any?>): EntrypointValueTypeNodeV1 {
        exactKeys(root, setOf("kind", "value"), "entrypoint value type node")
        check(root.containsKey("value")) { "entrypoint value type node.value is required" }
        return when (exactString(required(root, "kind", "entrypoint value type node"), "entrypoint value type node.kind")) {
            "Struct" -> EntrypointValueTypeNodeV1(
                EntrypointValueTypeNodeKindV1.STRUCT,
                structValue = parseStructNode(objectValue(root["value"], "entrypoint struct node")),
            )
            "Tuple" -> {
                val arity = unsignedInteger(root["value"], BigInteger.valueOf(0xffff), "entrypoint tuple arity").intValueExact()
                check(arity >= 2) { "entrypoint tuple arity must be in 2..65535" }
                EntrypointValueTypeNodeV1(EntrypointValueTypeNodeKindV1.TUPLE, tupleArity = arity)
            }
            "Option" -> {
                check(root["value"] == null) { "entrypoint Option node.value must be null" }
                EntrypointValueTypeNodeV1(EntrypointValueTypeNodeKindV1.OPTION)
            }
            "Result" -> {
                check(root["value"] == null) { "entrypoint Result node.value must be null" }
                EntrypointValueTypeNodeV1(EntrypointValueTypeNodeKindV1.RESULT)
            }
            "List" -> EntrypointValueTypeNodeV1(
                EntrypointValueTypeNodeKindV1.LIST,
                listValue = parseListNode(objectValue(root["value"], "entrypoint list node")),
            )
            "Unit" -> {
                check(root["value"] == null) { "entrypoint Unit node.value must be null" }
                EntrypointValueTypeNodeV1(EntrypointValueTypeNodeKindV1.UNIT)
            }
            "Error" -> EntrypointValueTypeNodeV1(
                EntrypointValueTypeNodeKindV1.ERROR,
                errorType = parseErrorType(objectValue(root["value"], "entrypoint error type")),
            )
            "Enum" -> EntrypointValueTypeNodeV1(EntrypointValueTypeNodeKindV1.ENUM, enumType = parseEnumType(objectValue(root["value"], "entrypoint enum type")))
            "StateCursor" -> {
                val key = parseKeySchema(objectValue(root["value"], "state cursor key schema"))
                EntrypointValueTypeNodeV1(EntrypointValueTypeNodeKindV1.STATE_CURSOR, cursorKeySchema = key)
            }
            "Leaf" -> EntrypointValueTypeNodeV1(
                EntrypointValueTypeNodeKindV1.LEAF,
                leafKind = parseLeafKind(objectValue(root["value"], "entrypoint value kind")),
            )
            else -> error("unsupported Kotodama boundary type node")
        }
    }

    private fun parseKeySchema(root: Map<String, Any?>): EntrypointValueTypeV1 {
        val raw = listValue(required(root, "nodes", "state key schema"), "state key schema.nodes")
        check(raw.isNotEmpty() && raw.size <= 256) { "state key schema exceeds its node budget" }
        raw.forEach { value ->
            val node = objectValue(value, "state key node")
            check(node["kind"] == "Leaf" || node["kind"] == "Tuple") { "state keys permit only scalar leaves and tuples" }
        }
        val key = parseValueType(root)
        check(key.nodes.none { it.leafKind == EntrypointValueKindV1.JSON }) { "Json is not a state key leaf" }
        return key
    }

    private fun parseStructNode(root: Map<String, Any?>): EntrypointStructTypeNodeV1 {
        exactKeys(root, setOf("name", "fields"), "entrypoint struct node")
        val name = exactString(required(root, "name", "entrypoint struct node"), "entrypoint struct node.name")
        val fields = stringList(required(root, "fields", "entrypoint struct node"), "entrypoint struct node.fields")
        check(
            (
                canonicalUserStructIdentifier(name) ||
                    name == "kotodama::QueryPage" || name == "kotodama::StatePage" ||
                    isCoreQueryViewName(name)
            ) &&
                fields.all(::canonicalSourceIdentifier),
        ) {
            "entrypoint struct node must use canonical Kotodama identifiers"
        }
        requireUnique(fields, "entrypoint struct node.fields")
        return EntrypointStructTypeNodeV1(name, fields)
    }

    private fun parseListNode(root: Map<String, Any?>): EntrypointListTypeNodeV1 {
        exactKeys(root, setOf("capacity"), "entrypoint list node")
        val capacity = unsignedInteger(
            required(root, "capacity", "entrypoint list node"),
            BigInteger.valueOf(64),
            "entrypoint list node.capacity",
        ).intValueExact()
        check(capacity >= 1) { "entrypoint list node.capacity must be in 1..64" }
        return EntrypointListTypeNodeV1(capacity)
    }

    private fun parseLeafKind(root: Map<String, Any?>): EntrypointValueKindV1 {
        exactKeys(root, setOf("kind", "value"), "entrypoint value kind")
        check(root.containsKey("value") && root["value"] == null) {
            "entrypoint value kind.value must be null"
        }
        val label = exactString(required(root, "kind", "entrypoint value kind"), "entrypoint value kind.kind")
        return valueKindByWire[label] ?: error("unsupported Kotodama boundary value kind")
    }

    private data class TypeAnalysis(
        val nextIndex: Int,
        val nodeCount: Int,
        val wordCount: Int,
        val maxDepth: Int,
        val typeName: String,
    )

    private data class TraversalFrame(
        var remaining: Int,
        val suppressWords: Boolean,
    )

    private data class RenderedType(
        val typeName: String,
        val coreViewName: String? = null,
        val listElementCoreViewName: String? = null,
    )

    private fun analyzeValueType(nodes: List<EntrypointValueTypeNodeV1>): TypeAnalysis {
        val frames = ArrayList<TraversalFrame>()
        var words = 0
        var maxDepth = 0
        var totalNodes = nodes.size
        nodes.forEachIndexed { index, node ->
            while (frames.lastOrNull()?.remaining == 0) {
                frames.removeAt(frames.lastIndex)
            }
            val suppressWords = if (index == 0) {
                false
            } else {
                val parent = frames.lastOrNull()
                check(parent != null && parent.remaining > 0) {
                    "entrypoint value type contains a trailing preorder node"
                }
                parent.remaining -= 1
                parent.suppressWords
            }
            val depth = frames.size + 1
            check(depth <= 256) { "entrypoint value type exceeds the V1 nesting depth" }
            maxDepth = maxOf(maxDepth, depth)
            node.cursorKeySchema?.let { key ->
                check(node.kind == EntrypointValueTypeNodeKindV1.STATE_CURSOR) { "cursor schema on a non-cursor node" }
                val analysis = analyzeValueType(key.nodes)
                totalNodes += analysis.nodeCount
                maxDepth = maxOf(maxDepth, depth + analysis.maxDepth)
                check(totalNodes <= 256 && maxDepth <= 256) { "cursor key exceeds enclosing schema budget" }
            }

            val handle = node.kind == EntrypointValueTypeNodeKindV1.OPTION ||
                node.kind == EntrypointValueTypeNodeKindV1.RESULT ||
                node.kind == EntrypointValueTypeNodeKindV1.LIST
            if (!suppressWords && (handle || nodeChildCount(node) == 0)) {
                words += 1
            }
            val children = nodeChildCount(node)
            if (children != 0) {
                frames.add(TraversalFrame(children, suppressWords || handle))
            }
        }
        while (frames.lastOrNull()?.remaining == 0) {
            frames.removeAt(frames.lastIndex)
        }
        check(frames.isEmpty()) { "entrypoint value type ends before its preorder tree is complete" }

        val rendered = ArrayList<RenderedType>()
        nodes.asReversed().forEach { node ->
            val childCount = nodeChildCount(node)
            check(rendered.size >= childCount) {
                "entrypoint value type ends before its preorder tree is complete"
            }
            val children = ArrayList<RenderedType>(childCount)
            repeat(childCount) { children.add(rendered.removeAt(rendered.lastIndex)) }
            val value = when (node.kind) {
                EntrypointValueTypeNodeKindV1.STRUCT -> {
                    val struct = checkNotNull(node.structValue) { "missing struct node metadata" }
                    when {
                        struct.name == "kotodama::StatePage" -> {
                            val body = children[0].typeName.removePrefix("List<(").removeSuffix(">")
                            val split = body.lastIndexOf("), ")
                            check(split >= 0) { "invalid StatePage items" }
                            RenderedType("StatePage<${body.substring(0, split)}, ${body.substring(split + 3)}>")
                        }
                        struct.name == "kotodama::QueryPage" -> children.firstOrNull()?.listElementCoreViewName
                            ?.let { RenderedType("QueryPage<$it>") }
                            ?: RenderedType("struct QueryPage")
                        isCoreQueryViewName(struct.name) ->
                            RenderedType(struct.name.removePrefix("kotodama::"), coreViewName = struct.name.removePrefix("kotodama::"))
                        else -> RenderedType("struct ${struct.name}")
                    }
                }
                EntrypointValueTypeNodeKindV1.TUPLE ->
                    RenderedType("(${children.joinToString(", ") { it.typeName }})")
                EntrypointValueTypeNodeKindV1.OPTION ->
                    RenderedType("Option<${children.single().typeName}>")
                EntrypointValueTypeNodeKindV1.RESULT ->
                    RenderedType("Result<${children[0].typeName}, ${children[1].typeName}>")
                EntrypointValueTypeNodeKindV1.LIST -> {
                    val list = checkNotNull(node.listValue) { "missing list node metadata" }
                    val child = children.single()
                    RenderedType(
                        "List<${child.typeName}, ${list.capacity}>",
                        listElementCoreViewName = child.coreViewName,
                    )
                }
                EntrypointValueTypeNodeKindV1.STATE_CURSOR -> RenderedType("StateCursor<${checkNotNull(node.cursorKeySchema).canonicalTypeName}>")
                EntrypointValueTypeNodeKindV1.UNIT -> RenderedType("()")
                EntrypointValueTypeNodeKindV1.ERROR -> RenderedType(checkNotNull(node.errorType).identity)
                EntrypointValueTypeNodeKindV1.ENUM -> RenderedType(checkNotNull(node.enumType).identity)
                EntrypointValueTypeNodeKindV1.LEAF ->
                    RenderedType(canonicalLeafName(checkNotNull(node.leafKind) { "missing leaf kind" }))
            }
            rendered.add(value)
        }
        check(rendered.size == 1) { "entrypoint value type is not one canonical preorder tree" }
        return TypeAnalysis(nodes.size, totalNodes, words, maxDepth, rendered.single().typeName)
    }

    private fun isCoreQueryViewName(name: String): Boolean = name in setOf(
        "kotodama::AccountView",
        "kotodama::AssetView",
        "kotodama::AssetDefinitionView",
        "kotodama::DomainView",
        "kotodama::NftView",
    )

    private fun nodeChildCount(node: EntrypointValueTypeNodeV1): Int = when (node.kind) {
        EntrypointValueTypeNodeKindV1.STRUCT -> checkNotNull(node.structValue).fields.size
        EntrypointValueTypeNodeKindV1.TUPLE -> checkNotNull(node.tupleArity)
        EntrypointValueTypeNodeKindV1.OPTION, EntrypointValueTypeNodeKindV1.LIST -> 1
        EntrypointValueTypeNodeKindV1.RESULT -> 2
        EntrypointValueTypeNodeKindV1.LEAF, EntrypointValueTypeNodeKindV1.UNIT, EntrypointValueTypeNodeKindV1.ERROR, EntrypointValueTypeNodeKindV1.ENUM, EntrypointValueTypeNodeKindV1.STATE_CURSOR -> 0
    }

    private fun subtreeEnd(nodes: List<EntrypointValueTypeNodeV1>, start: Int): Int? {
        var index = start
        var pending = 1
        while (pending != 0) {
            val node = nodes.getOrNull(index) ?: return null
            index += 1
            pending = pending - 1 + nodeChildCount(node)
        }
        return index
    }

    private data class CoreViewRange(val end: Int)

    private fun coreQueryViewShape(name: String): List<Pair<String, String>>? = when (name) {
        "kotodama::AccountView" -> listOf("id" to "AccountId", "metadata" to "Json")
        "kotodama::AssetView" -> listOf("id" to "AssetId", "amount" to "quantity")
        "kotodama::DomainView" -> listOf("id" to "DomainId", "owned_by" to "AccountId", "metadata" to "Json")
        "kotodama::NftView" -> listOf("id" to "NftId", "owned_by" to "AccountId", "content" to "Json")
        "kotodama::AssetDefinitionView" -> listOf(
            "id" to "AssetDefinitionId", "name" to "string", "description" to "Option<string>",
            "owned_by" to "AccountId", "total_quantity" to "quantity", "numeric_scale" to "Option<int>", "metadata" to "Json",
        )
        else -> null
    }

    private fun coreQueryViewRange(nodes: List<EntrypointValueTypeNodeV1>, start: Int): CoreViewRange? {
        val root = nodes.getOrNull(start)
        if (root?.kind != EntrypointValueTypeNodeKindV1.STRUCT) return null
        val struct = root.structValue ?: return null
        val expected = coreQueryViewShape(struct.name) ?: return null
        if (struct.fields != expected.map { it.first }) return null
        var cursor = start + 1
        for ((_, type) in expected) {
            val leaf = if (type.startsWith("Option<")) {
                if (nodes.getOrNull(cursor++)?.kind != EntrypointValueTypeNodeKindV1.OPTION) return null
                type.substring(7, type.length - 1)
            } else type
            val node = nodes.getOrNull(cursor++) ?: return null
            if (node.kind != EntrypointValueTypeNodeKindV1.LEAF || node.leafKind?.let(::canonicalLeafName) != leaf) return null
        }
        return if (subtreeEnd(nodes, start) == cursor) CoreViewRange(cursor) else null
    }

    private fun exactDurableBuiltinProduct(name: String, fields: List<String>, types: List<String>): Boolean {
        coreQueryViewShape(name)?.let { return fields == it.map { item -> item.first } && types == it.map { item -> item.second } }
        if (name != "kotodama::QueryPage") return !name.startsWith("kotodama::")
        if (fields != listOf("items", "next_offset") || types.size != 2 || types[1] != "Option<int>") return false
        // Recursive parsing has already validated the exact nested view shape.
        val item = types[0]
        val brace = item.indexOf('{')
        return item.startsWith("List<") && brace > 5 && coreQueryViewShape(item.substring(5, brace)) != null && item.endsWith("}, 64>")
    }

    private fun leafAt(
        nodes: List<EntrypointValueTypeNodeV1>,
        index: Int,
        kind: EntrypointValueKindV1,
    ): Boolean = nodes.getOrNull(index)?.let { node ->
        node.kind == EntrypointValueTypeNodeKindV1.LEAF && node.leafKind == kind
    } == true

    private fun validateReservedNominalShapes(nodes: List<EntrypointValueTypeNodeV1>): Boolean {
        nodes.forEachIndexed { start, node ->
            if (node.kind != EntrypointValueTypeNodeKindV1.STRUCT) return@forEachIndexed
            val struct = node.structValue ?: return false
            if (isCoreQueryViewName(struct.name)) {
                if (coreQueryViewRange(nodes, start) == null) return false
                return@forEachIndexed
            }
            if (struct.name == "kotodama::StatePage") {
                if (struct.fields != listOf("items", "next")) return false
                val list = nodes.getOrNull(start + 1) ?: return false
                if (list.kind != EntrypointValueTypeNodeKindV1.LIST || list.listValue?.capacity !in 1..64) return false
                if (nodes.getOrNull(start + 2)?.kind != EntrypointValueTypeNodeKindV1.TUPLE || nodes[start + 2].tupleArity != 2) return false
                val keyEnd = subtreeEnd(nodes, start + 3) ?: return false
                val end = subtreeEnd(nodes, keyEnd) ?: return false
                val cursor = nodes.getOrNull(end + 1) ?: return false
                val key = cursor.cursorKeySchema ?: return false
                val actual = nodes.subList(start + 3, keyEnd)
                if (actual.size != key.nodes.size || actual.zip(key.nodes).any { (left, right) ->
                    left.kind != right.kind || left.tupleArity != right.tupleArity || left.leafKind != right.leafKind
                }) return false
                if (nodes.getOrNull(end)?.kind != EntrypointValueTypeNodeKindV1.OPTION || cursor.kind != EntrypointValueTypeNodeKindV1.STATE_CURSOR || subtreeEnd(nodes, start) != end + 2) return false
                return@forEachIndexed
            }
            if (struct.name != "kotodama::QueryPage") return@forEachIndexed
            if (struct.fields != listOf("items", "next_offset")) return false
            val rootEnd = subtreeEnd(nodes, start) ?: return false
            val listStart = start + 1
            val listNode = nodes.getOrNull(listStart) ?: return false
            if (
                listNode.kind != EntrypointValueTypeNodeKindV1.LIST ||
                listNode.listValue?.capacity != 64
            ) {
                return false
            }
            val view = coreQueryViewRange(nodes, listStart + 1) ?: return false
            if (subtreeEnd(nodes, listStart) != view.end) return false
            val nextOffset = view.end
            if (
                nodes.getOrNull(nextOffset)?.kind != EntrypointValueTypeNodeKindV1.OPTION ||
                !leafAt(nodes, nextOffset + 1, EntrypointValueKindV1.INT) ||
                subtreeEnd(nodes, nextOffset) != nextOffset + 2 ||
                rootEnd != nextOffset + 2
            ) {
                return false
            }
        }
        return true
    }

    private fun canonicalLeafName(kind: EntrypointValueKindV1): String = when (kind) {
        EntrypointValueKindV1.INT -> "int"
        EntrypointValueKindV1.DECIMAL -> "decimal"
        EntrypointValueKindV1.QUANTITY -> "quantity"
        EntrypointValueKindV1.BOOL -> "bool"
        EntrypointValueKindV1.STRING -> "string"
        EntrypointValueKindV1.JSON -> "Json"
        EntrypointValueKindV1.NAME -> "Name"
        EntrypointValueKindV1.ACCOUNT_ID -> "AccountId"
        EntrypointValueKindV1.ASSET_DEFINITION_ID -> "AssetDefinitionId"
        EntrypointValueKindV1.ASSET_ID -> "AssetId"
        EntrypointValueKindV1.DOMAIN_ID -> "DomainId"
        EntrypointValueKindV1.NFT_ID -> "NftId"
        EntrypointValueKindV1.DATA_SPACE_ID -> "DataSpaceId"
        EntrypointValueKindV1.BLOB -> "bytes"
    }

    private fun parseTrigger(root: Map<String, Any?>): ContractTriggerDescriptor {
        exactKeys(root, setOf("id", "repeats", "filter", "authority", "metadata", "callback"), "trigger descriptor")
        val id = exactString(required(root, "id", "trigger descriptor"), "trigger descriptor.id")
        check(canonicalDeclarationIdentifier(id)) {
            "trigger descriptor.id must be a canonical Kotodama declaration identifier"
        }
        val repeats = parseRepeats(objectValue(required(root, "repeats", "trigger descriptor"), "trigger descriptor.repeats"))
        val filter = canonicalBase64(required(root, "filter", "trigger descriptor"), "trigger descriptor.filter")
        val authority = optionalExactString(root, "authority", "trigger descriptor.authority")?.let {
            try {
                requireCanonicalI105Address(it, "trigger descriptor.authority")
            } catch (error: IllegalArgumentException) {
                throw IllegalStateException("trigger descriptor.authority must be a canonical I105 account id", error)
            }
        }
        val metadata = objectValue(required(root, "metadata", "trigger descriptor"), "trigger descriptor.metadata")
        val callback = parseCallback(objectValue(required(root, "callback", "trigger descriptor"), "trigger descriptor.callback"))
        return ContractTriggerDescriptor(id, repeats, filter, authority, metadata, callback)
    }

    private fun parseRepeats(root: Map<String, Any?>): ContractTriggerRepeats {
        check(root.size == 1) { "trigger descriptor.repeats must contain exactly one enum variant" }
        return when {
            root.containsKey("Indefinitely") -> {
                check(root["Indefinitely"] == null) { "Repeats.Indefinitely value must be null" }
                ContractTriggerRepeats(ContractTriggerRepeatsKind.INDEFINITELY, null)
            }
            root.containsKey("Exactly") -> ContractTriggerRepeats(
                ContractTriggerRepeatsKind.EXACTLY,
                unsignedInteger(root["Exactly"], BigInteger.valueOf(0xffff_ffffL), "Repeats.Exactly").longValueExact(),
            )
            else -> error("unsupported trigger repetition policy")
        }
    }

    private fun parseCallback(root: Map<String, Any?>): ContractTriggerCallback {
        exactKeys(root, setOf("namespace", "entrypoint"), "trigger callback")
        val namespace = optionalExactString(root, "namespace", "trigger callback.namespace")
        check(namespace == null || canonicalTypeDeclarationIdentifier(namespace)) {
            "trigger callback.namespace must be a canonical Kotodama type-declaration identifier"
        }
        val entrypoint = exactString(required(root, "entrypoint", "trigger callback"), "trigger callback.entrypoint")
        check(canonicalEntrypointName(entrypoint)) { "trigger callback.entrypoint must be a canonical Kotodama selector" }
        return ContractTriggerCallback(namespace, entrypoint)
    }

    private fun parseState(root: Map<String, Any?>): ContractStateDescriptor {
        exactKeys(root, setOf("name", "type_name"), "state descriptor")
        val name = exactString(required(root, "name", "state descriptor"), "state descriptor.name")
        check(canonicalDeclarationIdentifier(name)) { "state descriptor.name must be a canonical Kotodama identifier" }
        val typeName = exactString(required(root, "type_name", "state descriptor"), "state descriptor.type_name")
        check(StateTypeNameParser(typeName).parse()) {
            "state descriptor.type_name must be a canonical Kotodama V1 state type"
        }
        return ContractStateDescriptor(name, typeName)
    }

    private fun parseErrorType(root: Map<String, Any?>): ContractErrorTypeDescriptor {
        exactKeys(root, setOf("identity", "variants"), "error type descriptor")
        val identity = exactString(required(root, "identity", "error type descriptor"), "error type descriptor.identity")
        check(identity.toByteArray(StandardCharsets.UTF_8).size <= 1024 &&
            identity.matches(Regex("[\\p{L}\\p{N}_:/@.-]+")) && !identity.contains("__kotodama_link_")) {
            "error type identity must be a stable package/unit/enum identity"
        }
        val variants = objectList(required(root, "variants", "error type descriptor"), "error type descriptor.variants") { variant ->
            exactKeys(variant, setOf("name", "code"), "error variant")
            val name = exactString(required(variant, "name", "error variant"), "error variant.name")
            check(canonicalSourceIdentifier(name) || (name.any { it.code > 127 } && name.matches(Regex("[\\p{L}_][\\p{L}\\p{N}_]*")))) {
                "error variant name must be a canonical identifier"
            }
            val code = unsignedInteger(required(variant, "code", "error variant"), BigInteger.valueOf(0xffff_ffffL), "error variant.code").longValueExact()
            check(code > 0) { "error variant.code must be a non-zero u32" }
            ContractErrorVariantDescriptor(name, code)
        }
        check(variants.size in 1..256) { "error type must contain 1..256 variants" }
        requireUnique(variants.map { it.name }, "error variant names")
        check(variants.zipWithNext().all { (left, right) -> left.code < right.code }) { "error variant codes must be strictly increasing" }
        return ContractErrorTypeDescriptor(identity, variants)
    }

    private fun parseEnumType(root: Map<String, Any?>): ContractEnumTypeDescriptor {
        exactKeys(root, setOf("identity", "variants"), "enum type descriptor")
        val identity = exactString(required(root, "identity", "enum type descriptor"), "enum type descriptor.identity")
        check(identity.toByteArray(StandardCharsets.UTF_8).size <= 1024 &&
            identity.matches(Regex("[\\p{L}\\p{N}_:/@.-]+")) && !identity.contains("__kotodama_link_")) {
            "enum type identity must be a stable package/unit/enum identity"
        }
        val variants = objectList(required(root, "variants", "enum type descriptor"), "enum type descriptor.variants") { variant ->
            exactKeys(variant, setOf("name", "code"), "enum variant")
            val name = exactString(required(variant, "name", "enum variant"), "enum variant.name")
            check(canonicalSourceIdentifier(name) || (name.any { it.code > 127 } && name.matches(Regex("[\\p{L}_][\\p{L}\\p{N}_]*")))) {
                "enum variant name must be a canonical identifier"
            }
            val code = unsignedInteger(required(variant, "code", "enum variant"), BigInteger.valueOf(0xffff_ffffL), "enum variant.code").longValueExact()
            check(code > 0) { "enum variant.code must be a non-zero u32" }
            ContractEnumVariantDescriptor(name, code)
        }
        check(variants.size in 1..256) { "enum type must contain 1..256 variants" }
        requireUnique(variants.map { it.name }, "enum variant names")
        check(variants.zipWithNext().all { (left, right) -> left.code < right.code }) { "enum variant codes must be strictly increasing" }
        return ContractEnumTypeDescriptor(identity, variants)
    }

    /** Decode one closed native event definition with the same schema policy as a manifest. */
    @JvmStatic
    fun parseEventDescriptor(payload: ByteArray): ContractEventDescriptor =
        parseEvent(objectValue(parse(payload, "event declaration"), "event declaration"))

    private fun parseEvent(root: Map<String, Any?>): ContractEventDescriptor {
        exactKeys(root, setOf("name", "payload_type"), "event declaration")
        val name = exactString(required(root, "name", "event declaration"), "event declaration.name")
        check(canonicalSourceIdentifier(name)) { "event name must be a canonical identifier" }
        val schema = parseValueType(objectValue(required(root, "payload_type", "event declaration"), "event payload type"))
        val first = schema.nodes.first()
        check(first.kind == EntrypointValueTypeNodeKindV1.STRUCT && first.structValue?.name?.substringAfterLast("::") == name) {
            "event payload must be a named struct matching the event name"
        }
        check(schema.nodes.none { it.kind == EntrypointValueTypeNodeKindV1.STATE_CURSOR || (it.kind == EntrypointValueTypeNodeKindV1.LEAF && it.leafKind == EntrypointValueKindV1.JSON) }) {
            "event payload cannot contain Json or StateCursor"
        }
        return ContractEventDescriptor(name, schema)
    }

    // Unicode White_Space, matching Rust str::trim rather than JVM isWhitespace.
    private fun isErrorMessageWhitespace(character: Char): Boolean =
        character in '\u0009'..'\u000d' || character == '\u0020' || character == '\u0085'
            || character == '\u00a0' || character == '\u1680' || character in '\u2000'..'\u200a'
            || character == '\u2028' || character == '\u2029' || character == '\u202f'
            || character == '\u205f' || character == '\u3000'

    private fun parseErrorMessage(root: Map<String, Any?>): ContractErrorMessage {
        exactKeys(root, setOf("error_type", "code", "message"), "error message")
        val identity = exactString(required(root, "error_type", "error message"), "error message.error_type")
        val code = unsignedInteger(required(root, "code", "error message"), BigInteger.valueOf(0xffff_ffffL), "error message.code").longValueExact()
        val message = required(root, "message", "error message")
        check(code > 0 && message is String && message.any { !isErrorMessageWhitespace(it) }
            && StandardCharsets.UTF_8.newEncoder().canEncode(message)
            && message.toByteArray(StandardCharsets.UTF_8).size <= 4096) {
            "error message requires a nonzero u32 and 1..4096 UTF-8 bytes of nonblank text"
        }
        return ContractErrorMessage(identity, code, message)
    }

    private fun parseKotobaEntry(root: Map<String, Any?>): ContractKotobaTranslationEntry {
        exactKeys(root, setOf("msg_id", "translations"), "kotoba translation entry")
        val messageId = exactString(required(root, "msg_id", "kotoba translation entry"), "kotoba translation entry.msg_id")
        val translations = objectList(
            required(root, "translations", "kotoba translation entry"),
            "kotoba translation entry.translations",
            ::parseKotobaTranslation,
        )
        requireUnique(translations.map { it.language }, "kotoba translation entry.translations")
        return ContractKotobaTranslationEntry(messageId, translations)
    }

    private fun parseKotobaTranslation(root: Map<String, Any?>): ContractKotobaTranslation {
        exactKeys(root, setOf("lang", "text"), "kotoba translation")
        val text = required(root, "text", "kotoba translation")
        check(text is String) { "kotoba translation.text must be a string" }
        return ContractKotobaTranslation(
            exactString(required(root, "lang", "kotoba translation"), "kotoba translation.lang"),
            text,
        )
    }

    private fun parseProvenance(root: Map<String, Any?>): ContractManifestProvenance {
        exactKeys(root, setOf("signer", "signature"), "manifest.provenance")
        return ContractManifestProvenance(
            exactString(required(root, "signer", "manifest.provenance"), "manifest.provenance.signer"),
            exactString(required(root, "signature", "manifest.provenance"), "manifest.provenance.signature"),
        )
    }

    private fun parse(payload: ByteArray?, context: String): Any? {
        check(payload != null && payload.isNotEmpty()) { "$context returned an empty payload" }
        val json = String(payload, StandardCharsets.UTF_8)
        check(json.isNotBlank()) { "$context returned a blank payload" }
        return JsonParser.parse(json)
    }

    private fun required(root: Map<String, Any?>, name: String, context: String): Any? {
        check(root.containsKey(name)) { "$context.$name is required" }
        return root[name]
    }

    private fun optionalObject(root: Map<String, Any?>, name: String, path: String): Map<String, Any?>? {
        if (!root.containsKey(name) || root[name] == null) return null
        return objectValue(root[name], path)
    }

    private fun optionalExactString(root: Map<String, Any?>, name: String, path: String): String? {
        if (!root.containsKey(name) || root[name] == null) return null
        return exactString(root[name], path)
    }

    private fun optionalBoolean(root: Map<String, Any?>, name: String, path: String): Boolean? {
        if (!root.containsKey(name) || root[name] == null) return null
        val value = root[name]
        check(value is Boolean) { "$path must be a boolean" }
        return value
    }

    private fun optionalManifestHash(root: Map<String, Any?>, name: String, path: String): String? {
        if (!root.containsKey(name) || root[name] == null) return null
        return manifestHash(root[name], path)
    }

    private fun optionalConvenienceHash(root: Map<String, Any?>, name: String, path: String): String? {
        if (!root.containsKey(name) || root[name] == null) return null
        val value = root[name]
        check(value is String && value.matches(Regex("^[0-9a-f]{64}$"))) {
            "$path must be canonical lowercase 64-hex"
        }
        check(markerBitIsSet(value)) { "$path must set the Iroha Hash marker bit" }
        return value
    }

    private fun manifestHash(value: Any?, path: String): String {
        check(value is String) { "$path must be a canonical checksummed Norito Hash literal" }
        val match = Regex("^hash:([0-9A-F]{64})#([0-9A-F]{4})$").matchEntire(value)
            ?: error("$path must be a canonical checksummed Norito Hash literal")
        val body = match.groupValues[1]
        val supplied = match.groupValues[2].toInt(16)
        check(supplied == crc16("hash:$body".toByteArray(StandardCharsets.US_ASCII))) {
            "$path has an invalid Norito Hash checksum"
        }
        val normalized = body.lowercase(java.util.Locale.ROOT)
        check(markerBitIsSet(normalized)) { "$path must set the Iroha Hash marker bit" }
        return normalized
    }

    private fun crc16(bytes: ByteArray): Int {
        var crc = 0xffff
        for (byte in bytes) {
            crc = crc xor ((byte.toInt() and 0xff) shl 8)
            repeat(8) {
                crc = if (crc and 0x8000 != 0) ((crc shl 1) xor 0x1021) and 0xffff else (crc shl 1) and 0xffff
            }
        }
        return crc
    }

    private fun markerBitIsSet(hex: String): Boolean =
        hex.substring(hex.length - 2).toInt(16) and 1 == 1

    private fun canonicalBase64(value: Any?, path: String): String {
        val text = exactString(value, path)
        val bytes = try {
            Base64.getDecoder().decode(text)
        } catch (error: IllegalArgumentException) {
            throw IllegalStateException("$path must be canonical base64", error)
        }
        check(bytes.isNotEmpty() && Base64.getEncoder().encodeToString(bytes) == text) {
            "$path must be non-empty canonical base64"
        }
        return text
    }

    private fun exactString(value: Any?, path: String): String {
        check(value is String && value.isNotBlank()) { "$path must be a non-empty string" }
        check(value.trim() == value) { "$path must not contain surrounding whitespace" }
        check(value.none { it.isISOControl() }) { "$path must not contain control characters" }
        return value
    }

    private fun stringList(value: Any?, path: String): List<String> =
        listValue(value, path).mapIndexed { index, item -> exactString(item, "$path[$index]") }

    private fun <T> optionalObjectList(
        root: Map<String, Any?>,
        name: String,
        path: String,
        parser: (Map<String, Any?>) -> T,
    ): List<T>? {
        if (!root.containsKey(name) || root[name] == null) return null
        return objectList(root[name], path, parser)
    }

    private fun <T> objectList(value: Any?, path: String, parser: (Map<String, Any?>) -> T): List<T> =
        listValue(value, path).mapIndexed { index, item -> parser(objectValue(item, "$path[$index]")) }

    private fun listValue(value: Any?, path: String): List<Any?> {
        check(value is List<*>) { "$path must be an array" }
        return value
    }

    @Suppress("UNCHECKED_CAST")
    private fun objectValue(value: Any?, path: String): Map<String, Any?> {
        check(value is Map<*, *>) { "$path must be an object" }
        check(value.keys.all { it is String }) { "$path must use string object keys" }
        return value as Map<String, Any?>
    }

    private fun exactKeys(root: Map<String, Any?>, allowed: Set<String>, path: String) {
        val unknown = root.keys.firstOrNull { it !in allowed }
        check(unknown == null) { "$path contains unknown field `$unknown`" }
    }

    private fun unsignedInteger(value: Any?, maximum: BigInteger, path: String): BigInteger {
        val integer = when (value) {
            is BigInteger -> value
            is Byte -> BigInteger.valueOf(value.toLong())
            is Short -> BigInteger.valueOf(value.toLong())
            is Int -> BigInteger.valueOf(value.toLong())
            is Long -> BigInteger.valueOf(value)
            else -> error("$path must be an unsigned integer")
        }
        check(integer.signum() >= 0 && integer <= maximum) { "$path is outside its unsigned integer range" }
        return integer
    }

    private fun canonicalIdentifierSyntax(value: String): Boolean {
        if (value.isEmpty() || !(value[0] == '_' || value[0] in 'A'..'Z' || value[0] in 'a'..'z')) return false
        return value.drop(1).all { it == '_' || it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' }
    }

    private fun canonicalSourceIdentifier(value: String): Boolean =
        canonicalIdentifierSyntax(value) && value !in reservedIdentifiers

    private fun canonicalDeclarationIdentifier(value: String): Boolean =
        canonicalSourceIdentifier(value) &&
            value !in reservedDeclarationNames &&
            !value.startsWith("__kotodama_link_")

    private fun canonicalTypeDeclarationIdentifier(value: String): Boolean =
        canonicalDeclarationIdentifier(value) && value !in retiredNumericTypeNames

    private fun canonicalQualifiedStructIdentifier(value: String): Boolean {
        if (value.length > 1024 || value.any { it.code > 127 } || value.contains("__kotodama_link_")) return false
        val parts = value.split("::")
        if (parts.size == 2) {
            if (parts[0] == "kotodama") return isCoreQueryViewName(value) || value == "kotodama::QueryPage" || value == "kotodama::StatePage"
            return parts.all(::canonicalTypeDeclarationIdentifier)
        }
        if (parts.size == 4 && parts[0] == "local") {
            return parts[1].length == 64 && parts[1].all { it in '0'..'9' || it in 'a'..'f' } &&
                canonicalTypeDeclarationIdentifier(parts[2]) && canonicalTypeDeclarationIdentifier(parts[3])
        }
        if (parts.size != 3 || !canonicalTypeDeclarationIdentifier(parts[1]) || !canonicalTypeDeclarationIdentifier(parts[2])) return false
        fun component(part: String): Boolean = part.isNotEmpty() &&
            (part[0] in 'A'..'Z' || part[0] in 'a'..'z' || part[0] in '0'..'9' || part[0] == '_') &&
            part.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '_' || it == '.' || it == '-' }
        val lockedPackage = parts[0].split('@')
        return lockedPackage.size in 1..2 && lockedPackage[0].split('/').all(::component) &&
            (lockedPackage.size == 1 || component(lockedPackage[1]))
    }

    private fun canonicalUserStructIdentifier(value: String): Boolean =
        value.length <= 1024 && canonicalQualifiedStructIdentifier(value)

    private class StateTypeNameParser(private val value: String, private val errorIdentities: Set<String>? = null) {
        private var cursor = 0
        private var nodes = 0

        fun parse(): Boolean =
            value.isNotEmpty() &&
                parseType(allowStateMap = true, depth = 1) != null &&
                cursor == value.length

        private fun parseType(allowStateMap: Boolean, depth: Int): String? {
            nodes += 1
            if (depth > maxStateTypeDepth || nodes > maxStateTypeNodes) return null

            if (consume("()")) return "unit"
            val errorIdentity = Regex("[\\p{L}\\p{N}_:/@.-]+").find(value, cursor)?.takeIf { it.range.first == cursor }?.value
            val qualifiedStructName = errorIdentity?.takeIf {
                value.getOrNull(cursor + it.length) == '{' && canonicalQualifiedStructIdentifier(it)
            }
            if (qualifiedStructName != null) {
                cursor += qualifiedStructName.length
            } else if (errorIdentity != null && errorIdentity.contains("::") &&
                errorIdentity.toByteArray(StandardCharsets.UTF_8).size <= 1024 && !errorIdentity.contains("__kotodama_link_")) {
                if (errorIdentities != null && errorIdentity !in errorIdentities) return null
                cursor += errorIdentity.length
                return "error"
            }
            if (consume("(")) {
                if (parseType(allowStateMap = false, depth = depth + 1) == null || !consume(", ")) return null
                if (parseType(allowStateMap = false, depth = depth + 1) == null) return null
                while (consume(", ")) {
                    if (parseType(allowStateMap = false, depth = depth + 1) == null) return null
                }
                return if (consume(")")) aggregateType else null
            }

            val name = qualifiedStructName ?: identifier() ?: return null
            if (name in stateScalarTypeNames) return name
            when (name) {
                "Option" -> {
                    if (!consume("<") || parseType(false, depth + 1) == null || !consume(">")) return null
                    return aggregateType
                }
                "Result" -> {
                    if (
                        !consume("<") ||
                        parseType(false, depth + 1) == null ||
                        !consume(", ") ||
                        parseType(false, depth + 1) == null ||
                        !consume(">")
                    ) return null
                    return aggregateType
                }
                "List" -> {
                    if (
                        !consume("<") ||
                        parseType(false, depth + 1) == null ||
                        !consume(", ") ||
                        !listCapacity() ||
                        !consume(">")
                    ) return null
                    return aggregateType
                }
                "StateCursor" -> {
                    if (!consume("<")) return null
                    return if (parseKey(depth + 1) != null && consume(">")) aggregateType else null
                }
                "StateMap" -> {
                    if (!allowStateMap || !consume("<")) return null
                    // Keys have their own schema budget; both schemas share the CNTR depth bound.
                    val valueNodes = nodes - 1
                    nodes = 0
                    if (parseKey(depth + 1) == null) return null
                    nodes = valueNodes
                    if (!consume(", ") || parseType(false, depth + 1) == null || !consume(">")) return null
                    return aggregateType
                }
            }

            if (name == "kotodama::StatePage") {
                nodes += 4 // List, Tuple, Option, StateCursor; both key occurrences count separately.
                if (nodes > maxStateTypeNodes || depth + 3 > maxStateTypeDepth || !consume("{items: List<(")) return null
                val key = parseKey(depth + 3) ?: return null
                if (!consume(", ") || parseType(false, depth + 3) == null ||
                    !consume("), ") || !listCapacity() || !consume(">, next: Option<StateCursor<")) return null
                return if (parseKey(depth + 3) == key && consume(">>}")) aggregateType else null
            }
            if (!canonicalUserStructIdentifier(name) || !consume("{")) return null
            // Empty products retain their validated nominal name and have no fields.
            if (consume("}")) return if (exactDurableBuiltinProduct(name, emptyList(), emptyList())) aggregateType else null
            val fields = mutableListOf<String>()
            val types = mutableListOf<String>()
            while (true) {
                val field = identifier()
                if (
                    field == null ||
                    !canonicalSourceIdentifier(field) ||
                    field.startsWith("__kotodama_link_") ||
                    field in fields ||
                    !consume(": ")
                ) return null
                fields.add(field)
                val childStart = cursor
                if (parseType(false, depth + 1) == null) return null
                types.add(value.substring(childStart, cursor))
                if (consume("}")) return if (exactDurableBuiltinProduct(name, fields, types)) aggregateType else null
                if (!consume(", ")) return null
            }
        }

        private fun parseKey(depth: Int): String? {
            val start = cursor
            val key = KeyTypeNameParser(value, start)
            if (!key.parse() || depth + key.maxDepth - 1 > maxStateTypeDepth || nodes + key.nodes > maxStateTypeNodes) return null
            nodes += key.nodes; cursor = key.cursor
            return value.substring(start, cursor)
        }

        private fun consume(literal: String): Boolean {
            if (!value.startsWith(literal, cursor)) return false
            cursor += literal.length
            return true
        }

        private fun identifier(): String? {
            if (cursor >= value.length || !isAsciiIdentifierStart(value[cursor])) return null
            val start = cursor
            cursor += 1
            while (cursor < value.length && isAsciiIdentifierPart(value[cursor])) {
                cursor += 1
            }
            return value.substring(start, cursor)
        }

        private fun listCapacity(): Boolean {
            val start = cursor
            var capacity = 0
            while (cursor < value.length && value[cursor] in '0'..'9') {
                capacity = minOf(65, capacity * 10 + (value[cursor] - '0'))
                cursor += 1
            }
            if (cursor == start || (cursor - start > 1 && value[start] == '0')) return false
            return capacity in 1..64
        }

        private companion object {
            const val aggregateType = "aggregate"
        }
    }

    private fun currentTypeName(value: String, path: String): String {
        val braceGenericDepths = ArrayList<Int>()
        var genericDepth = 0
        var index = 0
        while (index < value.length) {
            when {
                value[index] == '{' -> {
                    braceGenericDepths.add(genericDepth)
                    index += 1
                }
                value[index] == '}' -> {
                    if (braceGenericDepths.isNotEmpty()) {
                        braceGenericDepths.removeAt(braceGenericDepths.lastIndex)
                    }
                    index += 1
                }
                value[index] == '<' -> {
                    genericDepth += 1
                    index += 1
                }
                value[index] == '>' -> {
                    genericDepth = maxOf(0, genericDepth - 1)
                    index += 1
                }
                isAsciiIdentifierStart(value[index]) -> {
                    var qualifiedEnd = index
                    while (qualifiedEnd < value.length &&
                        (isAsciiIdentifierPart(value[qualifiedEnd]) || value[qualifiedEnd] in ":/@.-")) qualifiedEnd += 1
                    if (canonicalQualifiedStructIdentifier(value.substring(index, qualifiedEnd))) {
                        index = qualifiedEnd
                        continue
                    }
                    val start = index
                    index += 1
                    while (index < value.length && isAsciiIdentifierPart(value[index])) {
                        index += 1
                    }
                    val identifier = value.substring(start, index)
                    var next = index
                    while (next < value.length && value[next].isWhitespace()) {
                        next += 1
                    }
                    var afterColon = next + 1
                    while (afterColon < value.length && value[afterColon].isWhitespace()) {
                        afterColon += 1
                    }
                    var previous = start - 1
                    while (previous >= 0 && value[previous].isWhitespace()) {
                        previous -= 1
                    }
                    val isStructField =
                        braceGenericDepths.lastOrNull() == genericDepth &&
                            previous >= 0 &&
                            (value[previous] == '{' || value[previous] == ',') &&
                            next < value.length &&
                            value[next] == ':' &&
                            (afterColon >= value.length || value[afterColon] != ':')
                    check(isStructField || identifier !in retiredNumericTypeNames) {
                        "$path must not use retired Kotodama numeric type name `$identifier`"
                    }
                }
                else -> {
                    index += 1
                }
            }
        }
        return value
    }

    private fun isAsciiIdentifierStart(value: Char): Boolean =
        value == '_' || value in 'A'..'Z' || value in 'a'..'z'

    private fun isAsciiIdentifierPart(value: Char): Boolean =
        isAsciiIdentifierStart(value) || value in '0'..'9'

    private fun canonicalEntrypointName(value: String): Boolean =
        value == "hajimari" || value == "始まり" || value == "kaizen" || value == "改善" || canonicalDeclarationIdentifier(value)

    private fun requireUnique(values: List<String>, path: String) {
        check(values.toSet().size == values.size) { "$path must not contain duplicate identifiers" }
    }
}

private fun immutableJsonObject(source: Map<String, Any?>): Map<String, Any?> {
    val copy = LinkedHashMap<String, Any?>(source.size)
    source.forEach { (key, value) -> copy[key] = immutableJsonValue(value) }
    return Collections.unmodifiableMap(copy)
}

private fun immutableJsonValue(value: Any?): Any? = when (value) {
    is Map<*, *> -> {
        val copy = LinkedHashMap<String, Any?>(value.size)
        value.forEach { (key, nested) ->
            check(key is String) { "metadata JSON objects must use string keys" }
            copy[key] = immutableJsonValue(nested)
        }
        Collections.unmodifiableMap(copy)
    }
    is List<*> -> Collections.unmodifiableList(value.map(::immutableJsonValue))
    else -> value
}
