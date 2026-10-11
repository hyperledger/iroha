// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.release

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.hyperledger.iroha.sdk.address.AccountAddress
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/** Original public ledger bytes compared with the mandatory native account admission. */
@RunWith(AndroidJUnit4::class)
class TairaNativeLedgerWireTest {
    @Test fun liveAccountListI105MatchesNativeCodec() {
        val selector = "${TairaQualificationArguments.WIRE_CLASS}/liveAccountListI105MatchesNativeCodec"
        val evidence = TairaQualificationEvidence.current(selector)
        evidence.arguments.requireNative()
        val directory = evidence.caseDirectory(selector)
        val wire = TairaOriginalHttpWire(evidence, directory)
        val literal = TairaOriginalHttpWire.firstAccount(wire.get(TairaOriginalHttpWire.ACCOUNT_LIST_URL))
        retain(evidence, wire, directory, selector, literal, "$.items[0].id")
    }

    @Test fun liveAccountDetailI105MatchesNativeCodec() {
        val selector = "${TairaQualificationArguments.WIRE_CLASS}/liveAccountDetailI105MatchesNativeCodec"
        val evidence = TairaQualificationEvidence.current(selector)
        evidence.arguments.requireNative()
        val directory = evidence.caseDirectory(selector)
        val wire = TairaOriginalHttpWire(evidence, directory)
        val listed = TairaOriginalHttpWire.firstAccount(wire.get(TairaOriginalHttpWire.ACCOUNT_LIST_URL))
        val detail = wire.get(TairaOriginalHttpWire.detailUrl(listed))
        val literal = detail["account_id"] as? String ?: error("Account detail has no account_id string")
        assertEquals("Detail must return the exact account selected by the list response", listed, literal)
        retain(evidence, wire, directory, selector, literal, "$.account_id")
    }

    private fun retain(
        evidence: TairaQualificationEvidence,
        wire: TairaOriginalHttpWire,
        directory: String,
        selector: String,
        literal: String,
        fieldPath: String,
    ) {
        // No fallback or alternative codec: fromI105 invokes the Rust ABI-29 validator.
        val native = AccountAddress.fromI105(literal, TAIRA_DISCRIMINANT).toI105(TAIRA_DISCRIMINANT)
        val ledgerBytes = TairaQualificationEvidence.utf8(literal)
        val nativeBytes = TairaQualificationEvidence.utf8(native)
        val ledgerClaim = evidence.write("$directory/ledger-wire.utf8", ledgerBytes)
        val nativeClaim = evidence.write("$directory/native-wire.utf8", nativeBytes)
        val origin = evidence.writeJson("$directory/origin.json", mapOf(
            "encoding" to "UTF-8", "fieldPath" to fieldPath,
            "chainDiscriminant" to TAIRA_DISCRIMINANT,
        ))
        val request = wire.requestWrapper()
        val response = wire.responseWrapper(origin)
        assertArrayEquals("Ledger account UTF-8 differs from mandatory native codec", ledgerBytes, nativeBytes)
        evidence.retainCase(selector, mapOf(
            "testName" to selector, "request" to request, "response" to response,
            "nativeWire" to nativeClaim, "ledgerWire" to ledgerClaim,
        ))
    }

    companion object { private const val TAIRA_DISCRIMINANT = 369 }
}
