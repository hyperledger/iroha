package org.hyperledger.iroha.sdk.client

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** Public schema consumers use the same V1 table bounds as the compiler and node. */
class KotodamaCallTableTest {
    @Test
    fun wideArgumentsAndReturnsUseTableWords() {
        val entry = parse(List(64) { boolean }, tuple(64))
        assertEquals(64, entry.argumentSchema!!.wordCount)
        assertEquals(64, entry.returnSchema!!.wordCount)
    }

    @Test
    fun argumentFieldCountHasAnInclusive8192Bound() {
        assertEquals(8192, parse(List(8192) { boolean }).argumentSchema!!.wordCount)
        assertFailsWith<IllegalStateException> { parse(List(8193) { boolean }) }
    }

    @Test
    fun argumentLimitCountsFlattenedWordsAcrossFields() {
        val fields = List(64) { tuple(128) }
        assertEquals(8192, parse(fields).argumentSchema!!.wordCount)
        assertFailsWith<IllegalStateException> { parse(fields + boolean) }
    }

    @Test
    fun tableCallingDoesNotRelaxTheTypeSchemaNodeBound() {
        assertEquals(255, parse(emptyList(), tuple(255)).returnSchema!!.wordCount)
        assertFailsWith<IllegalStateException> { parse(emptyList(), tuple(256)) }
    }

    @Test
    fun emptyNamedProductsKeepNominalIdentityAndOneWord() {
        val empty = "struct Fixture::Empty" to listOf(mapOf<String, Any?>(
            "kind" to "Struct", "value" to mapOf("name" to "Fixture::Empty", "fields" to emptyList<String>()),
        ))
        val list = "List<struct Fixture::Empty, 2>" to
            (listOf(mapOf<String, Any?>("kind" to "List", "value" to mapOf("capacity" to 2))) + empty.second)
        val value = parse(listOf(empty), list)
        assertEquals(1, value.argumentSchema!!.wordCount)
        assertEquals(1, value.returnSchema!!.wordCount)
        assertEquals(empty.first, value.argumentSchema.fields.single().valueType.canonicalTypeName)
    }

    private fun parse(
        fields: List<Pair<String, List<Map<String, Any?>>>>,
        returns: Pair<String, List<Map<String, Any?>>> = unit,
    ): ContractEntrypointDescriptor {
        val descriptor = linkedMapOf<String, Any?>(
            "name" to "inspect",
            "authorization" to mapOf("kind" to "Anyone", "value" to null),
            "kind" to mapOf("kind" to "View", "value" to null),
            "params" to fields.mapIndexed { index, type ->
                mapOf("name" to "arg_$index", "type_name" to type.first)
            },
            "argument_schema" to fields.takeIf { it.isNotEmpty() }?.let {
                mapOf("fields" to it.mapIndexed { index, type ->
                    mapOf("name" to "arg_$index", "ty" to mapOf("nodes" to type.second))
                })
            },
            "return_type" to returns.first,
            "return_schema" to mapOf("nodes" to returns.second),
        )
        return ContractManifestJsonParser.parseManifest(mapOf(
            "permissions" to emptyList<Any?>(),
            "enum_types" to emptyList<Any?>(),
            "events" to emptyList<Any?>(),
            "entrypoints" to listOf(descriptor),
        ))
            .entrypoints!!.single()
    }

    private fun tuple(width: Int): Pair<String, List<Map<String, Any?>>> =
        List(width) { "bool" }.joinToString(", ", "(", ")") to
            (listOf(mapOf<String, Any?>("kind" to "Tuple", "value" to width)) +
                List(width) { boolean.second.single() })

    private val boolean = "bool" to listOf(mapOf<String, Any?>(
        "kind" to "Leaf", "value" to mapOf("kind" to "Bool", "value" to null),
    ))
    private val unit = "()" to listOf(mapOf<String, Any?>("kind" to "Unit", "value" to null))
}
