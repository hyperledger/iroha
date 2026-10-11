package org.hyperledger.iroha.sdk.client

import java.net.URI
import java.math.BigInteger
import org.hyperledger.iroha.sdk.testing.TestNetworkIds
import java.nio.charset.StandardCharsets
import java.util.concurrent.CompletableFuture
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import java.util.concurrent.CompletionException
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse

class ContractManifestTest {
    @Test
    fun durableBuiltinProductsRequireExactShapes() {
        val directory = generateSequence(java.io.File(System.getProperty("user.dir"))) { it.parentFile }
            .map { java.io.File(it, "fixtures/kotodama") }.first { it.isDirectory }
        val vectors = JsonParser.parse(java.io.File(directory, "durable_builtin_shapes_v1.json").readText()) as Map<*, *>
        fun decode(type: String) = parseManifestFixture("""{"manifest":{"permissions":[],"events":[],"enum_types":[],"states":[{"name":"stored","type_name":"$type"}]}}""".toByteArray(StandardCharsets.UTF_8)).manifest
        for (item in vectors["valid"] as List<*>) assertEquals(item, decode(item as String).states!!.single().typeName)
        for (item in vectors["invalid"] as List<*>) assertFailsWith<IllegalStateException>(item as String) { decode(item) }
    }

    @Test
    fun tupleCursorSchemasBindCompleteKeysAndShareOuterBounds() {
        fun node(kind: String, value: Any? = null) = mapOf("kind" to kind, "value" to value)
        fun leaf(kind: String) = node("Leaf", node(kind))
        fun cursor(keys: List<Map<String, Any?>>) = node("StateCursor", mapOf("nodes" to keys))
        val keys = listOf(node("Tuple", 2), leaf("Int"), node("Tuple", 2), leaf("Name"), leaf("Bool"))
        val keyName = "(int, (Name, bool))"
        fun parse(nodes: List<Map<String, Any?>>, type: String) = ContractManifestJsonParser.parseManifest(mapOf(
            "permissions" to emptyList<Any>(), "events" to emptyList<Any>(), "enum_types" to emptyList<Any>(),
            "entrypoints" to listOf(mapOf("name" to "page", "kind" to node("View"),
                "authorization" to node("Anyone"), "return_type" to type, "return_schema" to mapOf("nodes" to nodes))),
        )).entrypoints!!.single().returnSchema!!
        fun parseMap(hintKey: String) = ContractManifestJsonParser.parseManifest(mapOf(
            "permissions" to emptyList<Any>(), "events" to emptyList<Any>(), "enum_types" to emptyList<Any>(),
            "states" to listOf(mapOf("name" to "stored", "type_name" to "StateMap<$keyName, bool>")),
            "access_set_hints" to mapOf("read_keys" to emptyList<Any>(), "write_keys" to emptyList<Any>(),
                "dynamic_reads" to listOf(mapOf("base_key" to "state:stored", "key_type" to hintKey, "bound_kind" to "page", "max_keys" to 8)),
                "dynamic_writes" to emptyList<Any>()),
        ))
        assertEquals(keyName, parseMap(keyName).accessSetHints!!.dynamicReads.single().keyType)
        assertFailsWith<IllegalStateException> { parseMap("(int, (Name, int))") }
        val decoded = parse(listOf(cursor(keys)), "StateCursor<$keyName>")
        assertEquals(keyName, decoded.nodes.single().cursorKeySchema!!.canonicalTypeName)
        assertEquals(1, decoded.wordCount)
        val page = listOf(node("Struct", mapOf("name" to "kotodama::StatePage", "fields" to listOf("items", "next"))),
            node("List", mapOf("capacity" to 8)), node("Tuple", 2)) + keys + listOf(leaf("Bool"), node("Option"), cursor(keys))
        assertEquals(2, parse(page, "StatePage<$keyName, bool, 8>").wordCount)
        assertFailsWith<IllegalStateException> {
            parse(page.dropLast(1) + cursor(keys.dropLast(1) + leaf("Int")), "StatePage<$keyName, bool, 8>")
        }
        for (invalid in listOf(listOf(leaf("Json")), listOf(cursor(keys)), listOf(node("Tuple", 1), leaf("Int")))) {
            assertFailsWith<IllegalStateException> { parse(listOf(cursor(invalid)), "StateCursor<int>") }
        }
        assertFailsWith<IllegalStateException> { parse(listOf(node("StateCursor", node("Int"))), "StateCursor<int>") }
        val smallKey = listOf(node("Tuple", 2), leaf("Int"), leaf("Bool"))
        for (count in listOf(63, 64)) {
            val nodes = listOf(node("Tuple", count)) + List(count) { cursor(smallKey) }
            val name = List(count) { "StateCursor<(int, bool)>" }.joinToString(", ", "(", ")")
            if (count == 63) assertEquals(count, parse(nodes, name).wordCount)
            else assertFailsWith<IllegalStateException> { parse(nodes, name) }
        }
        for (count in listOf(254, 255)) {
            val nodes = List(count) { node("Option") } + cursor(listOf(leaf("Int")))
            val name = "Option<".repeat(count) + "StateCursor<int>" + ">".repeat(count)
            if (count == 254) assertEquals(1, parse(nodes, name).wordCount)
            else assertFailsWith<IllegalStateException> { parse(nodes, name) }
        }
    }

    @Test
    fun ordinaryEnumsAndEventsBindExactNominalSchemas() {
        val text = """{"permissions":[],"enum_types":[{"identity":"Demo::Status","variants":[{"name":"Pending","code":1},{"name":"Done","code":7}]}],"events":[{"name":"Changed","payload_type":{"nodes":[{"kind":"Struct","value":{"name":"Demo::Changed","fields":["status"]}},{"kind":"Enum","value":{"identity":"Demo::Status","variants":[{"name":"Pending","code":1},{"name":"Done","code":7}]}}]}}],"states":[{"name":"status","type_name":"Demo::Status"}]}"""
        @Suppress("UNCHECKED_CAST")
        fun parse(value: String) = ContractManifestJsonParser.parseManifest(JsonParser.parse(value) as Map<String, Any?>)
        val parsed = parse(text)
        assertEquals(7L, parsed.enumTypes.single().variants[1].code)
        assertEquals(EntrypointValueTypeNodeKindV1.ENUM, parsed.events.single().payloadType.nodes[1].kind)
        assertEquals("Demo::Status", parsed.events.single().payloadType.nodes[1].enumType!!.identity)
        assertEquals(1, parsed.events.single().payloadType.wordCount)
        for (invalid in listOf(
            text.replace("\"enum_types\":", "\"retired_enum_types\":"),
            text.replace("\"events\":", "\"retired_events\":"),
            text.replace("\"code\":1", "\"code\":0"),
            text.replace("\"kind\":\"Enum\"", "\"kind\":\"Error\""),
            text.replaceFirst("\"code\":7", "\"code\":8"),
            text.replaceFirst("\"name\":\"Changed\"", "\"name\":\"Other\""),
            text.replace("\"kind\":\"Enum\",\"value\":{\"identity\":\"Demo::Status\",\"variants\":[{\"name\":\"Pending\",\"code\":1},{\"name\":\"Done\",\"code\":7}]}", "\"kind\":\"Leaf\",\"value\":{\"kind\":\"Json\",\"value\":null}"),
        )) assertFailsWith<IllegalStateException> { parse(invalid) }
    }

    @Test
    fun authorizationRequiresDeclaredCanonicalPermissionScopes() {
        val instance = mapOf("kind" to "Instance", "value" to null)
        val shared = mapOf("kind" to "Chain", "value" to mapOf("permission_name" to "SharedOperators"))
        val declarations = listOf(mapOf("name" to "Admin", "scope" to instance), mapOf("name" to "Operator", "scope" to shared))
        fun descriptor(authorization: Any?) = mapOf(
            "name" to "inspect", "kind" to mapOf("kind" to "View", "value" to null),
            "return_type" to "()", "return_schema" to mapOf("nodes" to listOf(mapOf("kind" to "Unit", "value" to null))),
            "authorization" to authorization,
        )
        fun parse(permissions: Any?, authorization: Any?) = ContractManifestJsonParser.parseManifest(mapOf(
            "events" to emptyList<Any>(), "enum_types" to emptyList<Any>(), "permissions" to permissions, "entrypoints" to listOf(descriptor(authorization)),
        ))
        val role = mapOf("kind" to "Permission", "value" to "Admin")
        val parsed = parse(declarations, role)
        assertTrue(parsed.permissions[0].scope === ContractPermissionScopeV1.Instance)
        assertEquals("SharedOperators", (parsed.permissions[1].scope as ContractPermissionScopeV1.Chain).permissionName)
        assertEquals("Admin", (parsed.entrypoints!!.single().authorization as EntrypointAuthorizationV1.Permission).name)
        parse(emptyList<Any?>(), mapOf("kind" to "Anyone", "value" to null))
        assertFails { parse(null, role) }
        assertFails { parse(emptyList<Any?>(), role) }
        assertFails { parse(declarations.reversed(), role) }
        assertFails { parse(declarations + declarations[0], role) }
        assertFails { parse(declarations, null) }
        assertFails { parse(declarations, "Admin") }
        assertFails { parse(declarations, mapOf("kind" to "RuntimeLifecycle", "value" to null)) }
        assertFails { ContractManifestJsonParser.parseManifest(mapOf("events" to emptyList<Any>(), "enum_types" to emptyList<Any>(), "permissions" to declarations, "entrypoints" to listOf(descriptor(role) + ("permission" to "Admin")))) }
    }

    @Test
    fun staticErrorMessagesBindDeclaredVariants() {
        fun decode(code: Int = 1, message: String = "残高が不足しています", duplicate: Boolean = false): ContractManifest {
            val entry = """{"error_type":"Vault::Failure","code":$code,"message":"$message"}"""
            val messages = if (duplicate) "$entry,$entry" else entry
            return parseManifestFixture(
                """{"manifest":{"events":[],"enum_types":[],"permissions":[],"error_types":[{"identity":"Vault::Failure","variants":[{"name":"Missing","code":1}]}],"error_messages":[$messages]}}""".toByteArray(StandardCharsets.UTF_8),
            ).manifest
        }
        assertEquals("残高が不足しています", decode().errorMessages!!.single().message)
        assertEquals("\u001c", decode(message = "\\u001c").errorMessages!!.single().message)
        assertEquals(" 😀 ", decode(message = " 😀 ").errorMessages!!.single().message)
        assertFailsWith<IllegalStateException> { decode(message = "\u0085\u00a0") }
        assertFailsWith<IllegalStateException> { decode(message = "\\ud800") }
        assertFailsWith<IllegalStateException> { decode(code = 2) }
        assertFailsWith<IllegalStateException> { decode(message = " ") }
        assertFailsWith<IllegalStateException> { decode(message = "é".repeat(2049)) }
        assertFailsWith<IllegalStateException> { decode(duplicate = true) }
    }

    @Test
    fun durableEmptyProductsPreserveNominalNamesAndExactGrammar() {
        fun decode(typeName: String) = parseManifestFixture(
            """{"manifest":{"events":[],"enum_types":[],"permissions":[],"states":[{"name":"Stored","type_name":"$typeName"}]}}"""
                .toByteArray(StandardCharsets.UTF_8),
        ).manifest
        for (typeName in listOf(
            "Fixture::Empty{}", "Fixture::Other{}", "Fixture::Transfer{}", "List<Fixture::Empty{}, 2>", "List<List<Fixture::Empty{}, 2>, 2>",
            "Fixture::Envelope{empty: Fixture::Empty{}}", "StateMap<int, Fixture::Empty{}>",
            "std/math@1.0.0::Math::Empty{}",
        )) assertEquals(typeName, decode(typeName).states!!.single().typeName)
        for (typeName in listOf(
            "{}", "Fixture::Empty{", "Fixture::Empty{ }", "Fixture::Empty{,}", "Fixture::Empty{: int}",
            "Fixture::Empty{field: int, }", "Fixture::Empty{}trailing", "List<Fixture::Empty{},2>",
            "List<Fixture::Empty{}, 0>", "Fixture::Envelope{empty: Fixture::Empty{}, empty: Fixture::Empty{}}",
            "StatePage{}", "Option{}", "int{}",
        )) assertFailsWith<IllegalStateException>(typeName) { decode(typeName) }
    }

    @Test
    fun exportedStructIdentitySurvivesPublicAndDurableSchemas() {
        val directory = generateSequence(java.io.File(".").absoluteFile) { it.parentFile }
            .map { java.io.File(it, "fixtures/kotodama") }
            .first { java.io.File(it, "exported_structs_v1.json").isFile }
        val payload = java.io.File(directory, "exported_structs_v1.json").readText(Charsets.UTF_8)
        val vectors = JsonParser.parse(java.io.File(directory, "exported_struct_names_v1.json").readText(Charsets.UTF_8)) as Map<*, *>
        val identity = "std/math@1.0.0::Math::Receipt"
        for (name in vectors["valid"] as List<*>) {
            val manifest = parseManifestFixture(payload.replace(identity, name as String).toByteArray(StandardCharsets.UTF_8)).manifest
            val entrypoint = manifest.entrypoints!!.first()
            assertEquals("struct $name", entrypoint.returnSchema!!.canonicalTypeName)
            assertEquals("struct $name", entrypoint.argumentSchema!!.fields.first().valueType.canonicalTypeName)
            assertTrue(manifest.states!!.first().typeName.contains("$name{"))
        }
        for (name in vectors["invalid"] as List<*>) {
            val root = JsonParser.parse(payload.replace(identity, name as String)) as Map<*, *>
            val manifest = root["manifest"] as Map<*, *>
            for (removed in listOf("states", "entrypoints")) {
                val isolated = manifest.filterKeys { it != removed }
                assertFailsWith<IllegalStateException>("invalid $removed-independent struct identity: $name") {
                    parseManifestFixture(JsonEncoder.encode(mapOf("manifest" to isolated)).toByteArray(StandardCharsets.UTF_8))
                }
            }
        }
    }

    @Test
    fun everyPublicEntrypointRequiresAnExplicitReturnSchema() {
        fun response(returns: String) = """{"manifest":{"events":[],"enum_types":[],"permissions":[],"entrypoints":[{"name":"done","kind":{"kind":"View","value":null},"authorization":{"kind":"Anyone","value":null},"params":[]$returns}]}}"""
        for (returns in listOf(
            "",
            ""","return_type":null,"return_schema":null""",
            ",\"return_type\":\"()\"",
            ""","return_schema":{"nodes":[{"kind":"Unit","value":null}]}""",
        )) {
            assertFailsWith<IllegalStateException> {
                parseManifestFixture(response(returns).toByteArray(StandardCharsets.UTF_8))
            }
        }
        val unit = parseManifestFixture(response(
            ""","return_type":"()","return_schema":{"nodes":[{"kind":"Unit","value":null}]}""",
        ).toByteArray(StandardCharsets.UTF_8)).manifest.entrypoints!!.single()
        assertEquals("()", unit.returnType)
        assertEquals(1, unit.returnSchema!!.wordCount)
    }

    @Test
    fun publicManifestUsesTheV1CallTableInsteadOfTheRetiredRegisterWindow() {
        val parameters = (0 until 14).joinToString(",") { index ->
            """{"name":"p$index","type_name":"int"}"""
        }
        val fields = (0 until 14).joinToString(",") { index ->
            """{"name":"p$index","ty":{"nodes":[${leafNode("Int")}]}}"""
        }
        val returnNodes = (listOf("""{"kind":"Tuple","value":14}""") +
            List(14) { leafNode("Int") }).joinToString(",")
        val payload =
            """{"manifest":{"events":[],"enum_types":[],"permissions":[],"entrypoints":[{"name":"wide","kind":{"kind":"View","value":null},"authorization":{"kind":"Anyone","value":null},"params":[$parameters],"argument_schema":{"fields":[$fields]},"return_type":"${wideTupleType(14)}","return_schema":{"nodes":[$returnNodes]}}]}}"""
        val entrypoint = parseManifestFixture(payload.toByteArray(StandardCharsets.UTF_8))
            .manifest.entrypoints!!.single()
        assertEquals(14, entrypoint.parameters.size)
        assertEquals(14, entrypoint.argumentSchema!!.wordCount)
        assertEquals(14, entrypoint.returnSchema!!.wordCount)

        val overLimitParameters = (0..8_192).joinToString(",") { index ->
            """{"name":"p$index","type_name":"int"}"""
        }
        val overLimit =
            """{"manifest":{"events":[],"enum_types":[],"permissions":[],"entrypoints":[{"name":"wide","kind":{"kind":"View","value":null},"authorization":{"kind":"Anyone","value":null},"params":[$overLimitParameters],"return_type":"()","return_schema":{"nodes":[{"kind":"Unit","value":null}]}}]}}"""
        val error = assertFailsWith<IllegalStateException> {
            parseManifestFixture(overLimit.toByteArray(StandardCharsets.UTF_8))
        }
        assertTrue(error.message!!.contains("V1 argument limit"))
    }

    @Test
    fun nominalErrorFixtureBindsUnitAndJapaneseVariants() {
        val file = generateSequence(java.io.File(".").absoluteFile) { it.parentFile }
            .map { java.io.File(it, "fixtures/kotodama/nominal_errors_v1.json") }.first { it.isFile }
        val payload = file.readText(Charsets.UTF_8)
        val manifest = parseManifestFixture(payload.toByteArray(StandardCharsets.UTF_8)).manifest
        val schema = manifest.entrypoints!!.first().returnSchema!!
        assertEquals("Result<(), example/vault@1.0.0::金庫::拒否>", schema.canonicalTypeName)
        assertEquals(1, schema.wordCount)
        assertEquals(EntrypointValueTypeNodeKindV1.UNIT, schema.nodes[1].kind)
        assertEquals("不足", schema.nodes[2].errorType!!.variants[0].name)
        assertEquals(2, manifest.errorTypes!!.size)
        val cursor = manifest.entrypoints[1].returnSchema!!
        assertEquals("Option<StateCursor<int>>", cursor.canonicalTypeName)
        assertEquals(EntrypointValueTypeNodeKindV1.STATE_CURSOR, cursor.nodes[1].kind)
        assertEquals(EntrypointValueKindV1.INT, cursor.nodes[1].cursorKeySchema!!.nodes[0].leafKind)
        assertEquals(1, cursor.wordCount)
        assertEquals("StatePage<int, bool, 8>", manifest.entrypoints[2].returnSchema!!.canonicalTypeName)
        assertEquals(2, manifest.entrypoints[2].returnSchema!!.wordCount)
        assertFailsWith<IllegalStateException> {
            parseManifestFixture(payload.replaceFirst("CapacityExceeded", "DifferentMeaning").toByteArray(StandardCharsets.UTF_8))
        }
        assertFailsWith<IllegalStateException> {
            parseManifestFixture(payload.replaceFirst("\"code\": 1", "\"code\": 0").toByteArray(StandardCharsets.UTF_8))
        }
        val stateOnlyUnknown = payload.replace(
            "\"type_name\": \"Result<(), example/vault@1.0.0::金庫::拒否>\"",
            "\"type_name\": \"Result<(), missing/vault@1.0.0::金庫::拒否>\"",
        )
        val stateError = assertFailsWith<IllegalStateException> {
            parseManifestFixture(stateOnlyUnknown.toByteArray(StandardCharsets.UTF_8))
        }
        assertTrue(stateError.message!!.contains("enum or error catalog"))
        for (forged in listOf("kotodama::StatePage{anything: int}", "kotodama::StatePage{items: List<(int, bool), 8>, next: Option<StateCursor<bool>>}")) {
            assertFailsWith<IllegalStateException> {
                parseManifestFixture(payload.replace(
                    "kotodama::StatePage{items: List<(int, bool), 8>, next: Option<StateCursor<int>>}", forged,
                ).toByteArray(StandardCharsets.UTF_8))
            }
        }
    }

    @Test
    fun fullManifestPreservesExactKotodamaV1Interface() {
        val record = ContractJsonParser.parseManifestRecord(fullResponse().toByteArray(StandardCharsets.UTF_8))
        val manifest = record.manifest

        assertEquals("Ledger", manifest.seiyakuName)
        assertEquals("b".repeat(64), manifest.codeHashHex)
        assertEquals("d".repeat(64), manifest.abiHashHex)
        val accessSetHints = manifest.accessSetHints ?: error("missing access-set hints")
        assertEquals(64, accessSetHints.dynamicReads.single().maxKeys)
        assertEquals("AccountId", accessSetHints.dynamicReads.single().keyType)
        val entrypoint = manifest.entrypoints!!.single()
        assertEquals(ContractEntrypointKind.KOTOAGE, entrypoint.kind)
        val argumentSchema = entrypoint.argumentSchema ?: error("missing argument schema")
        val returnSchema = entrypoint.returnSchema ?: error("missing return schema")
        assertEquals(2, argumentSchema.fields.first().valueType.wordCount)
        assertEquals("struct Fixture::Transfer", argumentSchema.fields.first().valueType.canonicalTypeName)
        val tagsType = argumentSchema.fields.last().valueType
        assertEquals(2, tagsType.nodes.size)
        assertEquals(64, tagsType.nodes.first().listValue!!.capacity)
        assertEquals("List<Name, 64>", tagsType.canonicalTypeName)
        assertEquals(1, returnSchema.wordCount)
        assertEquals("Result<(bool, decimal), string>", returnSchema.canonicalTypeName)
        assertEquals(ContractTriggerRepeatsKind.INDEFINITELY, entrypoint.triggers.single().repeats.kind)
        assertNull(entrypoint.triggers.single().repeats.exactly)
        assertEquals("transfer", entrypoint.triggers.single().callback.entrypoint)
        assertEquals("daily-settlement", entrypoint.triggers.single().metadata["purpose"])
        assertEquals("StateMap<AccountId, quantity>", manifest.states!!.single().typeName)
        assertEquals(1001, manifest.errorTypes!!.single().variants.single().code)
        assertEquals("ja", manifest.kotoba!!.single().translations.last().language)
        assertEquals("ed25519:fixture", manifest.provenance!!.signer)
    }

    @Test
    fun triggerBoundariesRejectExactAmountSourceFormOnly() {
        val retired = listOf(
            fullResponse().replaceFirst("\"id\":\"settle\"", "\"id\":\"Amount\""),
            fullResponse().replaceFirst("\"namespace\":null", "\"namespace\":\"Amount\""),
        )
        retired.forEach { payload ->
            assertFailsWith<IllegalStateException>(payload) {
                ContractJsonParser.parseManifestRecord(payload.toByteArray(StandardCharsets.UTF_8))
            }
        }

        val lowercase = fullResponse()
            .replaceFirst("\"id\":\"settle\"", "\"id\":\"amount\"")
            .replaceFirst("\"namespace\":null", "\"namespace\":\"RemoteLedger\"")
        val trigger = ContractJsonParser.parseManifestRecord(
            lowercase.toByteArray(StandardCharsets.UTF_8),
        ).manifest.entrypoints!!.single().triggers.single()
        assertEquals("amount", trigger.id)
        assertEquals("RemoteLedger", trigger.callback.namespace)
    }

    @Test
    fun manifestRejectsUnknownEnglishAndNoncanonicalShapes() {
        val invalid = listOf(
            fullResponse().replaceFirst("\"seiyaku_name\"", "\"contract_name\""),
            fullResponse().replaceFirst("\"Kotoage\"", "\"Public\""),
            fullResponse().replaceFirst("\"Kotoage\"", "\"View\""),
            fullResponse().replaceFirst("\"capacity\":64", "\"capacity\":65"),
            fullResponse().replaceFirst("\"name\":\"request\",\"ty\"", "\"name\":\"wrong\",\"ty\""),
            fullResponse().replaceFirst("#ABA2", "#0000"),
            fullResponse().replaceFirst("\"seiyaku_name\":\"Ledger\"", "\"seiyaku_name\":\"match\""),
            fullResponse().replaceFirst("\"seiyaku_name\":\"Ledger\"", "\"seiyaku_name\":\"Option\""),
            fullResponse().replaceFirst("\"seiyaku_name\":\"Ledger\"", "\"seiyaku_name\":\"Amount\""),
            fullResponse().replaceFirst("\"seiyaku_name\":\"Ledger\"", "\"seiyaku_name\":\"amount\""),
            fullResponse().replaceFirst("\"name\":\"transfer\"", "\"name\":\"Amount\""),
            fullResponse().replaceFirst("\"name\":\"request\",\"type_name\"", "\"name\":\"Amount\",\"type_name\""),
            fullResponse().replaceFirst("\"fields\":[\"amount\",\"memo\"]", "\"fields\":[\"Amount\",\"memo\"]"),
            fullResponse().replaceFirst("\"name\":\"Balances\",\"type_name\"", "\"name\":\"Amount\",\"type_name\""),
            fullResponse().replaceFirst("\"name\":\"InsufficientFunds\",\"code\"", "\"name\":\"Amount\",\"code\""),
            fullResponse().replaceFirst("\"base_key\":\"state:Balances\"", "\"base_key\":\"state:Amount\""),
            fullResponse().replaceFirst("\"seiyaku_name\":\"Ledger\"", "\"seiyaku_name\":\"__kotodama_link_private\""),
            fullResponse().replaceFirst("\"seiyaku_name\":\"Ledger\"", "\"seiyaku_name\":\"state_map_get\""),
            fullResponse().replaceFirst(
                "\"seiyaku_name\":\"Ledger\"",
                "\"seiyaku_name\":\"__kotodama_quantity_ratio_round\"",
            ),
            fullResponse().replaceFirst(
                "\"seiyaku_name\":\"Ledger\"",
                "\"seiyaku_name\":\"__kotodama_decimal_to_int_trunc\"",
            ),
            fullResponse().replaceFirst(
                "\"seiyaku_name\":\"Ledger\"",
                "\"seiyaku_name\":\"__kotodama_decimal_to_int_round\"",
            ),
            fullResponse().replaceFirst("\"kind\":\"Quantity\"", "\"kind\":\"Amount\""),
            fullResponse().replaceFirst("\"kind\":\"Decimal\"", "\"kind\":\"U128\""),
            fullResponse().replaceFirst("\"identity\":\"Ledger::TransferError\"", "\"identity\":\"Error<Injected>\""),
            fullResponse().replaceFirst("\"features_bitmap\":0", "\"features_bitmap\":4"),
            fullResponse().replaceFirst("\"dynamic_writes\":[]", "\"dynamic_writes\":[],\"unknown\":true"),
            fullResponse().replaceFirst(
                "\"repeats\":{\"Indefinitely\":null}",
                "\"repeats\":{\"kind\":\"Indefinitely\",\"value\":null}",
            ),
            fullResponse().replaceFirst("\"code_hash\":\"${"b".repeat(64)}\"", "\"code_hash\":\"${"f".repeat(64)}\""),
        )

        invalid.forEachIndexed { index, payload ->
            assertFailsWith<IllegalStateException>("invalid[$index] mutation was accepted: $payload") {
                ContractJsonParser.parseManifestRecord(payload.toByteArray(StandardCharsets.UTF_8))
            }
        }
    }

    @Test
    fun retiredNumericTypeNamesAreRejectedOnlyInTypePositions() {
        fun statePayload(typeName: String): String =
            """{"manifest":{"events":[],"enum_types":[],"permissions":[],"states":[{"name":"Balances","type_name":"$typeName"}]},"code_hash":null,"abi_hash":null}"""

        val maximumDepth = "Option<".repeat(255) + "int" + ">".repeat(255)
        val maximumMapDepth = "Option<".repeat(254) + "int" + ">".repeat(254)
        listOf(
            "quantity",
            "(int, decimal)",
            "Option<Result<quantity, string>>",
            "List<Fixture::Transfer{amount: quantity}, 64>",
            "StateMap<AccountId, Fixture::Transfer{amount: quantity, memo: Option<string>}>",
            "List<Fixture::Envelope{items: List<Fixture::Transfer{amount: quantity}, 64>}, 1>",
            maximumDepth,
            wideTupleType(255),
            "StateMap<AccountId, ${wideTupleType(255)}>",
            "StateMap<AccountId, $maximumMapDepth>",
        ).forEach { legalType ->
            val legal = statePayload(legalType)
            assertEquals(
                legalType,
                parseManifestFixture(legal.toByteArray(StandardCharsets.UTF_8))
                    .manifest.states!!.single().typeName,
            )
        }

        listOf(
            "Amount",
            "amount",
            "Foo{Amount: quantity}",
            "Foo{Amount:quantity}",
            "StateMap<AccountId, int>",
            "Аmount",
        ).forEach { invalidHint ->
            val payload = fullResponse().replace(
                "\"key_type\":\"AccountId\"",
                "\"key_type\":\"$invalidHint\"",
            )
            assertFailsWith<IllegalStateException> {
                parseManifestFixture(payload.toByteArray(StandardCharsets.UTF_8))
            }
        }

        listOf(
            "Amount",
            "amount",
            "Amount: quantity",
            "Option<Amount>",
            "List<amount, 1>",
            "StateMap<AccountId, Amount>",
            "StateMap<AccountId, Amount: quantity>",
            "Fixture::Transfer{amount: amount}",
            "Fixture::Transfer{amount:: quantity}",
            "Fixture::Transfer{Amount: quantity}",
            "Amount{amount: quantity}",
            "Fixture::Transfer{amount: quantity, amount: int}",
            "Fixture::Transfer{ }",
            "Option<StateMap<AccountId, quantity>>",
            "StateMap<Json, quantity>",
            "(int)",
            "Result<int,string>",
            "List<quantity, 0>",
            "List<quantity, 65>",
            "List<quantity, 01>",
            "Transfer {amount: quantity}",
            "Fixture::Transfer{amount: quantity, memo:string}",
            "Fixture::Transfer{amøunt: quantity}",
            "Tránsfer{amount: quantity}",
            "Fixture::Transfer{__kotodama_link_private: quantity}",
            "Option<".repeat(256) + "int" + ">".repeat(256),
            wideTupleType(256),
            "StateMap<AccountId, ${wideTupleType(256)}>",
            "StateMap<AccountId, $maximumDepth>",
        ).forEach { retiredType ->
            val payload = statePayload(retiredType)
            assertFailsWith<IllegalStateException> {
                parseManifestFixture(payload.toByteArray(StandardCharsets.UTF_8))
            }
        }
    }

    @Test
    fun dynamicAccessHintsEnforceTheExactV1Policy() {
        fun parse(payload: String): ContractDynamicAccessHint {
            val manifest =
                parseManifestFixture(payload.toByteArray(StandardCharsets.UTF_8))
                    .manifest
            val accessSetHints = manifest.accessSetHints ?: error("missing access-set hints")
            return accessSetHints.dynamicReads.single()
        }

        val keyTypes = listOf(
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
        keyTypes.forEach { keyType ->
            val payload = fullResponse().replaceFirst(
                "\"key_type\":\"AccountId\"",
                "\"key_type\":\"$keyType\"",
            ).replaceFirst(
                "StateMap<AccountId, quantity>",
                "StateMap<$keyType, quantity>",
            )
            assertEquals(keyType, parse(payload).keyType)
        }

        listOf("page", "take").forEach { boundKind ->
            val payload = fullResponse().replaceFirst(
                "\"bound_kind\":\"take\"",
                "\"bound_kind\":\"$boundKind\"",
            )
            assertEquals(boundKind, parse(payload).boundKind)
        }
        listOf("state:Balances", "state:amount").forEach { baseKey ->
            var payload = fullResponse().replaceFirst(
                "\"base_key\":\"state:Balances\"",
                "\"base_key\":\"$baseKey\"",
            )
            if (baseKey == "state:amount") {
                payload = payload.replaceFirst(
                    "\"name\":\"Balances\",\"type_name\":\"StateMap<AccountId, quantity>\"",
                    "\"name\":\"amount\",\"type_name\":\"StateMap<AccountId, quantity>\"",
                )
            }
            assertEquals(baseKey, parse(payload).baseKey)
        }
        listOf(1, 64).forEach { maxKeys ->
            val payload = fullResponse().replaceFirst("\"max_keys\":64", "\"max_keys\":$maxKeys")
            assertEquals(maxKeys.toLong(), parse(payload).maxKeys)
        }

        listOf(
            "",
            "state:",
            "state:*",
            "state:Balances.more",
            "state:Balances:Other",
            "state:state:Balances",
            "state:match",
            "state:StateMap",
            "state:__kotodama_link_Balances",
            "state: Balances",
            "state:Balances ",
            "state:Бalances",
            "states:Balances",
            "Balances",
            "state:amount.more",
        ).forEach { baseKey ->
            val payload = fullResponse().replaceFirst(
                "\"base_key\":\"state:Balances\"",
                "\"base_key\":\"$baseKey\"",
            )
            assertFailsWith<IllegalStateException>("accepted base_key `$baseKey`") { parse(payload) }
        }
        listOf(
            "",
            "Json",
            "Int",
            "Amount",
            "amount",
            "AccountID",
            "Transfer",
            "StateMap",
            "StateMap<AccountId, quantity>",
            " AccountId",
            "AccountId ",
            "АccountId",
        ).forEach { keyType ->
            val payload = fullResponse().replaceFirst(
                "\"key_type\":\"AccountId\"",
                "\"key_type\":\"$keyType\"",
            )
            assertFailsWith<IllegalStateException>("accepted key_type `$keyType`") { parse(payload) }
        }
        listOf("", "range", "Range", "Take", "all", "prefix", "range ", " take").forEach { boundKind ->
            val payload = fullResponse().replaceFirst(
                "\"bound_kind\":\"take\"",
                "\"bound_kind\":\"$boundKind\"",
            )
            val failure = assertFailsWith<IllegalStateException>("accepted bound_kind `$boundKind`") {
                parse(payload)
            }
            if (boundKind == "range") {
                assertEquals("dynamic access hint.bound_kind must be `take` or `page`", failure.message)
            }
        }
        listOf("0", "65", "4294967295", "-1", "1.0", "\"1\"").forEach { maxKeys ->
            val payload = fullResponse().replaceFirst("\"max_keys\":64", "\"max_keys\":$maxKeys")
            assertFailsWith<IllegalStateException>("accepted max_keys `$maxKeys`") { parse(payload) }
        }
        listOf(
            fullResponse().replaceFirst(
                "\"max_keys\":64",
                "\"max_keys\":64,\"unknown\":true",
            ),
            fullResponse().replaceFirst("\"base_key\":\"state:Balances\"", "\"base_key\":null"),
            fullResponse().replaceFirst("\"key_type\":\"AccountId\"", "\"key_type\":false"),
            fullResponse().replaceFirst("\"bound_kind\":\"take\"", "\"bound_kind\":1"),
            fullResponse().replaceFirst("\"max_keys\":64", "\"max_keys\":null"),
        ).forEach { payload ->
            assertFailsWith<IllegalStateException> { parse(payload) }
        }
    }

    @Test
    fun dynamicAccessHintsResolveExactDeclaredStateMaps() {
        fun hint(
            baseKey: String = "state:Balances",
            keyType: String = "AccountId",
        ): String =
            """{"base_key":"$baseKey","key_type":"$keyType","bound_kind":"take","max_keys":1}"""

        fun payload(
            dynamicReads: List<String>,
            dynamicWrites: List<String>,
            stateName: String = "Balances",
            stateType: String = "StateMap<AccountId, quantity>",
        ): String =
            """
            {
              "manifest":{"events":[],"enum_types":[],"permissions":[],
                "access_set_hints":{
                  "read_keys":[],
                  "write_keys":[],
                  "dynamic_reads":[${dynamicReads.joinToString(",")}],
                  "dynamic_writes":[${dynamicWrites.joinToString(",")}]
                },
                "states":[{"name":"$stateName","type_name":"$stateType"}]
              },
              "code_hash":null,
              "abi_hash":null
            }
            """.trimIndent()

        fun parse(value: String): ManifestFixture =
            parseManifestFixture(value.toByteArray(StandardCharsets.UTF_8))

        val canonical = hint()
        listOf(
            payload(listOf(canonical, canonical), emptyList()),
            payload(emptyList(), listOf(canonical, canonical)),
            payload(listOf(hint(baseKey = "state:Missing")), emptyList()),
            payload(listOf(canonical), emptyList(), stateType = "quantity"),
            payload(listOf(hint(keyType = "Name")), emptyList()),
        ).forEach { malformed ->
            assertFailsWith<IllegalStateException> { parse(malformed) }
        }

        val amount = hint(baseKey = "state:amount")
        val accepted = parse(
            payload(
                dynamicReads = listOf(amount),
                dynamicWrites = listOf(amount),
                stateName = "amount",
            ),
        )
        val acceptedHints = accepted.manifest.accessSetHints ?: error("missing access-set hints")
        assertEquals("state:amount", acceptedHints.dynamicReads.single().baseKey)
        assertEquals("state:amount", acceptedHints.dynamicWrites.single().baseKey)
    }

    @Test
    fun manifestEndpointValidatesPathAndParsesFullRecord() {
        val executor = ManifestExecutor(fullResponse().toByteArray(StandardCharsets.UTF_8))
        val transport = HttpClientTransport(
            executor,
            ClientConfig.builder().setBaseUri(URI.create("https://torii.example/api"))
                .setLocalSigningContext(LocalSigningContext(TestNetworkIds.canonical())).build(),
        )

        val artifact = ContractArtifactId(BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE),
            "hash:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB#ABA2")
        val record = transport.getContractManifest(artifact, applicationAuth()).join()
        assertEquals(artifact, record.artifactId)
        assertEquals(TestNetworkIds.canonical(), record.networkId)

        assertEquals("Ledger", record.manifest.seiyakuName)
        assertEquals(
            "https://torii.example/api/v1/contracts/artifacts/${artifact.dataspaceId}/${"b".repeat(64)}",
            executor.lastRequest.uri.toString(),
        )
        val requests = executor.requestCount
        assertFailsWith<IllegalArgumentException> { ContractArtifactId(BigInteger.ZERO, "abc") }
        assertFailsWith<IllegalArgumentException> { ContractArtifactId(BigInteger.ZERO, "0x${"b".repeat(64)}") }
        assertEquals(requests, executor.requestCount)
        assertTrue(executor.lastRequest.headers.containsKey(CanonicalRequestSigner.HEADER_ACCOUNT))
        assertTrue(executor.lastRequest.headers.containsKey(CanonicalRequestSigner.HEADER_SIGNATURE))
    }

    @Test
    fun optionalArtifactBytesAreCanonicalBoundedAndDigestBound() {
        val digest = org.hyperledger.iroha.sdk.crypto.IrohaHash.prehash(
            "iroha:ivm:contract-artifact:v1\u0000".toByteArray(StandardCharsets.UTF_8) + byteArrayOf(0),
        )
        val literal = org.hyperledger.iroha.sdk.core.util.HashLiteral.canonicalize(digest)
        val hash = digest.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        val response = fullResponse()
            .replace("hash:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB#ABA2", literal)
            .replace("b".repeat(64), hash).trimEnd().removeSuffix("}")
        fun decode(suffix: String) = ContractManifestJsonParser.parseRecord(
            "$response$suffix}".toByteArray(StandardCharsets.UTF_8),
        )
        assertNull(decode("").codeBytes)
        assertNull(decode(",\"code_bytes\":null").codeBytes)
        assertEquals("AA==", decode(",\"code_bytes\":\"AA==\"").codeBytes)
        for (invalid in listOf("AB==", "AA", "AAAA", "", " AA==", "A".repeat(((16 * 1024 * 1024 + 2) / 3) * 4))) {
            assertFails { decode(",\"code_bytes\":\"$invalid\"") }
        }
        assertFails { decode(",\"code_bytes\":1") }
    }

    @Test
    fun artifactIdentityAndEnvelopeRejectRetiredAndForeignScopes() {
        val hash = "hash:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB#ABA2"
        val maximum = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)
        assertEquals(maximum, ContractArtifactId(maximum, hash).dataspaceId)
        for (invalid in listOf(BigInteger.valueOf(-1), maximum.add(BigInteger.ONE))) {
            assertFailsWith<IllegalArgumentException> { ContractArtifactId(invalid, hash) }
        }
        for (replacement in listOf("-1", "18446744073709551616", "\"17\"", "1.0")) {
            assertFails { ContractJsonParser.parseManifestRecord(
                fullResponse().replace("18446744073709551615", replacement).toByteArray(StandardCharsets.UTF_8)) }
        }
        val response = fullResponse()
        val malformed = listOf(
            response.replaceFirst("\"network_id\"", "\"retired_network\""),
            response.replaceFirst("\"artifact_id\"", "\"retired_artifact\""),
            response.replaceFirst(hash, "hash:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD#F071"),
        )
        malformed.forEach { payload -> assertFails { ContractJsonParser.parseManifestRecord(payload.toByteArray(StandardCharsets.UTF_8)) } }
        val artifact = ContractArtifactId(maximum, hash)
        for (payload in listOf(
            response.replace(TestNetworkIds.canonical().literal, TestNetworkIds.fromSeed(97).literal),
            response.replace("18446744073709551615", "17"),
        )) {
            val transport = HttpClientTransport(ManifestExecutor(payload.toByteArray(StandardCharsets.UTF_8)),
                ClientConfig.builder().setBaseUri(URI.create("https://torii.example"))
                    .setLocalSigningContext(LocalSigningContext(TestNetworkIds.canonical())).build())
            assertFailsWith<CompletionException> { transport.getContractManifest(artifact, applicationAuth()).join() }
        }
        val executor = ManifestExecutor(response.toByteArray(StandardCharsets.UTF_8))
        val unsigned = HttpClientTransport(executor,
            ClientConfig.builder().setBaseUri(URI.create("https://torii.example")).build())
        assertFailsWith<IllegalStateException> { unsigned.getContractManifest(artifact, applicationAuth()) }
        assertEquals(0, executor.requestCount)
    }

    @Test
    fun flatListTapeEnforcesTheExactV1DepthBoundary() {
        val listNode = """{"kind":"List","value":{"capacity":1}},"""
        val leafNode = """{"kind":"Leaf","value":{"kind":"Int","value":null}}"""
        val validNodes = listNode.repeat(255) + leafNode
        var validTypeName = "int"
        repeat(255) { validTypeName = "List<$validTypeName, 1>" }

        val valid = parseBoundarySchema(validNodes, validTypeName)
        assertEquals(256, valid.nodes.size)
        assertEquals(1, valid.wordCount)
        assertEquals(validTypeName, valid.canonicalTypeName)

        val malformed = listOf(
            listNode.dropLast(1),
            "$leafNode,$leafNode",
            """{"kind":"List","value":{"capacity":1,"element":{"nodes":[$leafNode]}}},$leafNode""",
            """{"kind":"List","value":{"capacity":0}},$leafNode""",
            """{"kind":"List","value":{"capacity":65}},$leafNode""",
            optionNode,
            """{"kind":"Result","value":null},$leafNode""",
            """{"kind":"Tuple","value":2},$leafNode""",
            listNode.repeat(256) + leafNode,
        )
        malformed.forEach { nodes ->
            assertFailsWith<IllegalStateException> {
                parseBoundarySchema(nodes, "int")
            }
        }
    }

    @Test
    fun reservedQueryNominalsRequireTheirExactFlatShape() {
        val nodes =
            """{"kind":"Struct","value":{"name":"kotodama::QueryPage","fields":["items","next_offset"]}},""" +
                """{"kind":"List","value":{"capacity":64}},""" +
                """{"kind":"Struct","value":{"name":"kotodama::AccountView","fields":["id","metadata"]}},""" +
                """{"kind":"Leaf","value":{"kind":"AccountId","value":null}},""" +
                """{"kind":"Leaf","value":{"kind":"Json","value":null}},""" +
                """{"kind":"Option","value":null},""" +
                """{"kind":"Leaf","value":{"kind":"Int","value":null}}"""

        val schema = parseBoundarySchema(nodes, "QueryPage<AccountView>")
        assertEquals("QueryPage<AccountView>", schema.canonicalTypeName)

        listOf(
            nodes.replaceFirst("\"capacity\":64", "\"capacity\":63"),
            nodes.replaceFirst("\"kind\":\"Json\"", "\"kind\":\"String\""),
        ).forEach { forged ->
            assertFailsWith<IllegalStateException> {
                parseBoundarySchema(forged, "QueryPage<AccountView>")
            }
        }
    }

    @Test
    fun everyReservedProjectionAndPageHasAnExactNominalName() {
        val pair = listOf(
            structNode("Fixture::Pair", "left", "right"),
            leafNode("Int"),
            leafNode("Bool"),
        )
        assertEquals(
            "struct Fixture::Pair",
            parseBoundarySchema(pair.joinToString(","), "struct Fixture::Pair").canonicalTypeName,
        )

        coreViewNames.forEach { viewName ->
            val view = coreViewNodes(viewName)
            assertEquals(
                viewName,
                parseBoundarySchema(view.joinToString(","), viewName).canonicalTypeName,
            )
            val pageName = "QueryPage<$viewName>"
            assertEquals(
                pageName,
                parseBoundarySchema(queryPageNodes(view).joinToString(","), pageName).canonicalTypeName,
            )
        }
    }

    @Test
    fun everyReservedProjectionAndPageRejectsForgedStructure() {
        val forgedViews = listOf(
            "AccountView" to listOf(
                structNode("AccountView", "id", "metadata"),
                leafNode("AccountId"),
                leafNode("Bool"),
            ),
            "AssetView" to listOf(
                structNode("AssetView", "id", "amount"),
                leafNode("AssetId"),
                leafNode("Decimal"),
            ),
            "AssetDefinitionView" to listOf(
                structNode(
                    "AssetDefinitionView",
                    "id",
                    "name",
                    "description",
                    "owned_by",
                    "total_quantity",
                    "numeric_scale",
                    "metadata",
                ),
                leafNode("AssetDefinitionId"),
                leafNode("String"),
                optionNode,
                leafNode("Bool"),
                leafNode("AccountId"),
                leafNode("Quantity"),
                optionNode,
                leafNode("Int"),
                leafNode("Json"),
            ),
            "DomainView" to listOf(
                structNode("DomainView", "id", "owned_by", "metadata"),
                leafNode("DomainId"),
                leafNode("DomainId"),
                leafNode("Json"),
            ),
            "NftView" to listOf(
                structNode("NftView", "id", "owned_by", "content"),
                leafNode("NftId"),
                leafNode("AccountId"),
                leafNode("String"),
            ),
        )
        forgedViews.forEach { (typeName, nodes) ->
            assertCanonicalSchemaFailure(typeName, nodes)
        }

        val account = coreViewNodes("AccountView")
        val page = queryPageNodes(account)
        assertCanonicalSchemaFailure(
            "QueryPage<AccountView>",
            page.mapIndexed { index, node -> if (index == 1) listNode(63) else node },
        )
        assertCanonicalSchemaFailure(
            "QueryPage<AccountView>",
            page.mapIndexed { index, node ->
                if (index == page.lastIndex) leafNode("Bool") else node
            },
        )
        assertCanonicalSchemaFailure(
            "QueryPage<AccountView>",
            listOf(structNode("QueryPage", "next_offset", "items")) + page.drop(1),
        )
        assertCanonicalSchemaFailure(
            "struct QueryPage",
            listOf(
                structNode("QueryPage", "items", "next_offset"),
                listNode(64),
                structNode("Fixture::Pair", "left", "right"),
                leafNode("Int"),
                leafNode("Bool"),
                optionNode,
                leafNode("Int"),
            ),
        )
    }

    @Test
    fun assetDefinitionPrecisionMustBeAnOptionalInteger() {
        val valid = coreViewNodes("AssetDefinitionView")
        val retired = listOf(
            structNode("AssetDefinitionView", "id", "name", "description", "owned_by", "total_quantity", "metadata"),
        ) + valid.subList(1, 7) + valid.last()
        val required = valid.filterIndexed { index, _ -> index != 7 }
        val decimal = valid.mapIndexed { index, node -> if (index == 8) leafNode("Decimal") else node }
        for (nodes in listOf(retired, required, decimal)) {
            assertCanonicalSchemaFailure("AssetDefinitionView", nodes)
            assertCanonicalSchemaFailure("QueryPage<AssetDefinitionView>", queryPageNodes(nodes))
        }
    }

    private class ManifestExecutor(private val payload: ByteArray) : HttpTransportExecutor {
        lateinit var lastRequest: TransportRequest
        var requestCount = 0

        override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> {
            requestCount += 1
            lastRequest = request
            return CompletableFuture.completedFuture(
                TransportResponse.builder().setStatusCode(200).setBody(payload).build(),
            )
        }
    }

    private class ManifestFixture(val manifest: ContractManifest)

    companion object {
        @Suppress("UNCHECKED_CAST")
        private fun parseManifestFixture(payload: ByteArray): ManifestFixture {
            val root = JsonParser.parse(String(payload, StandardCharsets.UTF_8)) as Map<String, Any?>
            return ManifestFixture(ContractManifestJsonParser.parseManifest(root["manifest"] as Map<String, Any?>))
        }

        private val triggerFilter =
            "TlJUMAAAl9+YQQ4oJZjALRf6FAto0QAKAAAAAAAAANzCjydU9+jNAgIAAAAFBAAAAAA="

        private fun wideTupleType(elements: Int): String = buildString(elements * 5 + 2) {
            append('(')
            repeat(elements) { index ->
                if (index > 0) append(", ")
                append("int")
            }
            append(')')
        }

        private fun parseBoundarySchema(
            nodes: String,
            typeName: String,
        ): EntrypointValueTypeV1 {
            val payload =
                """{"manifest":{"events":[],"enum_types":[],"permissions":[],"entrypoints":[{"name":"inspect","kind":{"kind":"View","value":null},"authorization":{"kind":"Anyone","value":null},"params":[{"name":"value","type_name":"$typeName"}],"argument_schema":{"fields":[{"name":"value","ty":{"nodes":[$nodes]}}]},"return_type":"()","return_schema":{"nodes":[{"kind":"Unit","value":null}]}}]}}"""
            return parseManifestFixture(payload.toByteArray(StandardCharsets.UTF_8))
                .manifest.entrypoints!!.single().argumentSchema!!.fields.single().valueType
        }

        private val coreViewNames = listOf(
            "AccountView",
            "AssetView",
            "AssetDefinitionView",
            "DomainView",
            "NftView",
        )

        private const val optionNode = """{"kind":"Option","value":null}"""

        private fun listNode(capacity: Int): String =
            """{"kind":"List","value":{"capacity":$capacity}}"""

        private fun leafNode(kind: String): String =
            """{"kind":"Leaf","value":{"kind":"$kind","value":null}}"""

        private fun structNode(sourceName: String, vararg fields: String): String {
            val name = if (sourceName in setOf("AccountView", "AssetView", "AssetDefinitionView", "DomainView", "NftView", "QueryPage", "StatePage")) "kotodama::$sourceName" else sourceName
            val fieldJson = fields.joinToString(",") { "\"$it\"" }
            return """{"kind":"Struct","value":{"name":"$name","fields":[$fieldJson]}}"""
        }

        private fun coreViewNodes(name: String): List<String> = when (name) {
            "AccountView" -> listOf(
                structNode(name, "id", "metadata"),
                leafNode("AccountId"),
                leafNode("Json"),
            )
            "AssetView" -> listOf(
                structNode(name, "id", "amount"),
                leafNode("AssetId"),
                leafNode("Quantity"),
            )
            "AssetDefinitionView" -> listOf(
                structNode(name, "id", "name", "description", "owned_by", "total_quantity", "numeric_scale", "metadata"),
                leafNode("AssetDefinitionId"),
                leafNode("String"),
                optionNode,
                leafNode("String"),
                leafNode("AccountId"),
                leafNode("Quantity"),
                optionNode,
                leafNode("Int"),
                leafNode("Json"),
            )
            "DomainView" -> listOf(
                structNode(name, "id", "owned_by", "metadata"),
                leafNode("DomainId"),
                leafNode("AccountId"),
                leafNode("Json"),
            )
            "NftView" -> listOf(
                structNode(name, "id", "owned_by", "content"),
                leafNode("NftId"),
                leafNode("AccountId"),
                leafNode("Json"),
            )
            else -> error("unsupported test view $name")
        }

        private fun queryPageNodes(view: List<String>): List<String> =
            listOf(structNode("QueryPage", "items", "next_offset"), listNode(64)) +
                view +
                listOf(optionNode, leafNode("Int"))

        private fun assertCanonicalSchemaFailure(typeName: String, nodes: List<String>) {
            val error = assertFailsWith<IllegalStateException> {
                parseBoundarySchema(nodes.joinToString(","), typeName)
            }
            assertTrue(error.message.orEmpty().contains("canonical flat preorder"), error.message)
        }

        private fun fullResponse(): String =
            """
            {
              "network_id":"${TestNetworkIds.canonical()}",
              "artifact_id":{"dataspace_id":18446744073709551615,"code_hash":"hash:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB#ABA2"},
              "manifest":{
                "events":[],"enum_types":[],"permissions":[{"name":"TransferAsset","scope":{"kind":"Instance","value":null}}],
                "seiyaku_name":"Ledger",
                "code_hash":"hash:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB#ABA2",
                "abi_hash":"hash:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD#F071",
                "compiler_fingerprint":"kotodama_lang",
                "features_bitmap":0,
                "access_set_hints":{
                  "read_keys":["state:Balances"],
                  "write_keys":["state:Balances"],
                  "dynamic_reads":[{
                    "base_key":"state:Balances",
                    "key_type":"AccountId",
                    "bound_kind":"take",
                    "max_keys":64
                  }],
                  "dynamic_writes":[]
                },
                "entrypoints":[{
                  "name":"transfer",
                  "kind":{"kind":"Kotoage","value":null},
                  "params":[
                    {"name":"request","type_name":"struct Fixture::Transfer"},
                    {"name":"tags","type_name":"List<Name, 64>"}
                  ],
                  "argument_schema":{"fields":[
                    {"name":"request","ty":{"nodes":[
                      {"kind":"Struct","value":{"name":"Fixture::Transfer","fields":["amount","memo"]}},
                      {"kind":"Leaf","value":{"kind":"Quantity","value":null}},
                      {"kind":"Option","value":null},
                      {"kind":"Leaf","value":{"kind":"String","value":null}}
                    ]}},
                    {"name":"tags","ty":{"nodes":[
                      {"kind":"List","value":{"capacity":64}},
                      {"kind":"Leaf","value":{"kind":"Name","value":null}}
                    ]}}
                  ]},
                  "return_type":"Result<(bool, decimal), string>",
                  "return_schema":{"nodes":[
                    {"kind":"Result","value":null},
                    {"kind":"Tuple","value":2},
                    {"kind":"Leaf","value":{"kind":"Bool","value":null}},
                    {"kind":"Leaf","value":{"kind":"Decimal","value":null}},
                    {"kind":"Leaf","value":{"kind":"String","value":null}}
                  ]},
                  "authorization":{"kind":"Permission","value":"TransferAsset"},
                  "read_keys":["state:Balances"],
                  "write_keys":["state:Balances"],
                  "access_hints_complete":true,
                  "access_hints_skipped":[],
                  "triggers":[{
                    "id":"settle",
                    "repeats":{"Indefinitely":null},
                    "filter":"$triggerFilter",
                    "authority":null,
                    "metadata":{"purpose":"daily-settlement","round":7},
                    "callback":{"namespace":null,"entrypoint":"transfer"}
                  }]
                }],
                "states":[{"name":"Balances","type_name":"StateMap<AccountId, quantity>"}],
                "error_types":[{"identity":"Ledger::TransferError","variants":[{"name":"InsufficientFunds","code":1001}]}],
                "kotoba":[{
                  "msg_id":"transfer.denied",
                  "translations":[
                    {"lang":"en","text":"Transfer denied"},
                    {"lang":"ja","text":"送金は拒否されました"}
                  ]
                }],
                "provenance":{"signer":"ed25519:fixture","signature":"fixture-signature"}
              },
              "code_hash":"${"b".repeat(64)}",
              "abi_hash":"${"d".repeat(64)}"
            }
            """.trimIndent()
    }
}
