package org.hyperledger.iroha.sdk.client.collections

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import org.hyperledger.iroha.sdk.json.Json
import org.hyperledger.iroha.sdk.json.JsonObject

/** Native event rows retain signed definitions and reject retired synthetic projections. */
class ContractEventRowTest {
    private fun fixture(): JsonObject = Json.parse("""{
      "schema_version":1,"block_height":9,"block_hash_hex":"block",
      "event_id":"block:2:0","execution_hash_hex":"execution","output_index":2,"emission_index":0,
      "provenance":"emitted","result_ok":true,"authority":"alice","contract_address":"contract",
      "event_kind":"Changed","payload":{},"emission":{
        "contract":"contract","code_hash":"code","entrypoint":0,"event":0,"caller":"alice",
        "definition":{"name":"Changed","payload_type":{"nodes":[{"kind":"Struct","value":{"name":"Demo::Changed","fields":[]}}]}},
        "payload":{"schema_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"atoms":[]}
      }
    }""") as JsonObject

    @Test fun nativeOriginAndExactPositionAreRequired() {
        val row = ContractEventRow(fixture())
        assertEquals("execution", row.executionHashHex)
        assertEquals("Changed", row.emission.definition.name)
        assertEquals(0, row.emission.payload.atoms.size)
        for ((field, value) in listOf("provenance" to Json.of("derived"), "module" to Json.of("router"), "block_index" to Json.of(0),
            "tx_hash_hex" to Json.of("old"), "event_id" to Json.of("block:1:0"), "authority" to Json.of("other"),
            "event_kind" to Json.of("Other"), "result_ok" to Json.of(false))) {
            assertFails(field) { ContractEventRow(JsonObject(fixture().members + (field to value))) }
        }
        for (field in listOf("emission", "payload", "output_index", "emission_index", "execution_hash_hex")) {
            assertFails(field) { ContractEventRow(JsonObject(fixture().members - field)) }
        }
    }

    @Test fun atomTagsAndSchemaHashesAreClosed() {
        for (literal in listOf("""{"kind":"EnumCode","value":0}""", """{"kind":"Tag","value":1}""",
            """{"kind":"Unit","value":false}""", """{"kind":"Unknown","value":null}""")) {
            assertFails { ContractValueAtomV1(Json.parse(literal) as JsonObject) }
        }
        assertFails { ContractValueRecordV1(Json.parse("""{"schema_hash":[],"atoms":[]}""") as JsonObject) }
    }
}
