package org.hyperledger.iroha.sdk.client

import org.hyperledger.iroha.sdk.client.collections.AccountHistoryRow
import org.hyperledger.iroha.sdk.json.Json
import org.hyperledger.iroha.sdk.json.JsonObject
import org.hyperledger.iroha.sdk.query.Page
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class AccountHistoryRowContractTest {
    @Test fun currentAccountMovementKeepsExactAmountAndLedgerCoordinates() {
        // collection_sources.rs / account_history_projections_to_json, not a raw transaction DTO.
        val page = Page.fromJson(Json.parse("""{"items":[{"id":"transaction:account:2","source":"transaction","type":"TRANSFER","account_id":"account","counterparty_account_id":"recipient","block_height":7,"block_index":3,"movement_index":2,"direction":"outgoing","amount":"12345678901234567890.123456","tx_hash":"transaction","result_ok":true}],"next_cursor":"opaque+/cursor"}"""))
        val row = AccountHistoryRow.fromJson(page.items.single() as JsonObject)
        assertEquals("12345678901234567890.123456", row.amount)
        assertEquals(7, row.blockHeight); assertEquals(3, row.blockIndex); assertEquals(2, row.movementIndex)
        assertEquals("transaction:account:2", row.id); assertEquals("recipient", row.counterpartyAccountId)
        assertEquals("opaque+/cursor", page.nextCursor)
    }

    @Test fun genericRowCannotAcquireMonetaryFieldsFromArbitraryMetadata() {
        val row = AccountHistoryRow.fromJson(Json.parse("""{"id":"activity","block_height":1,"block_index":0,"movement_index":0,"metadata":{"amount":"999","asset_id":"asset","counterparty_account_id":"recipient"}}""") as JsonObject)
        assertNull(row.amount); assertNull(row.assetId); assertNull(row.counterpartyAccountId)
    }

    @Test fun missingPositionsAndWrongMonetaryTypesAreRejectedAtSharedBoundary() {
        for (row in listOf(
            """{"id":"activity","block_height":1,"block_index":0}""",
            """{"id":"activity","block_height":1,"block_index":0,"movement_index":-1}""",
            """{"id":"activity","block_height":1,"block_index":0,"movement_index":0,"amount":true}""",
            """{"id":"activity","block_height":1,"block_index":0,"movement_index":0,"counterparty_account_id":42}""",
        )) assertFailsWith<IllegalArgumentException> { AccountHistoryRow.fromJson(Json.parse(row) as JsonObject) }
    }
}
