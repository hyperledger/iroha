package org.hyperledger.iroha.sdk.tx.norito

import org.hyperledger.iroha.sdk.address.AccountAddress
import org.hyperledger.iroha.sdk.core.model.FeePaymentIntent
import org.hyperledger.iroha.sdk.core.model.FeeSponsorProgramId
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.norito.SchemaHash
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs

class FeePaymentArchiveTest {
    private val codec = NoritoJavaCodecAdapter(AccountAddress.DEFAULT_I105_DISCRIMINANT)

    @Test fun authorityArchiveHasTheCurrentSchemaAndCompactFeeFields() {
        val archive = codec.encodeFeePaymentIntent(FeePaymentIntent.Authority(emptyList()))
        val decoded = NoritoHeader.decode(archive, null)
        assertContentEquals(SchemaHash.hash16("iroha_data_model::transaction::signed::model::FeePaymentIntent"), decoded.header.schemaHash)
        assertEquals(NoritoHeader.COMPACT_LEN, decoded.header.flags)
        // Authority tag; eleven-byte variant; empty charge vector; absent optional gas.
        assertContentEquals("000000000b0800000000000000000100".chunked(2).map { it.toInt(16).toByte() }.toByteArray(), decoded.payload)
        decoded.header.validateChecksum(decoded.payload)
        assertFalse(archive.contentEquals(codec.encodeFeePaymentIntent(FeePaymentIntent.Authority(emptyList(), 9))))
    }

    @Test fun payerSelectionPreservesSponsorRevisionAndGasWithoutAliasing() {
        val account = AccountAddress.fromAccount(byteArrayOf(0x58) + ByteArray(31) { 0x66 }, "ed25519").toI105Default()
        val original = FeePaymentIntent.Sponsor(FeeSponsorProgramId(account, "fees"), 7, emptyList(), 42)
        val selected = assertIs<FeePaymentIntent.Sponsor>(original.payerSelection())
        assertEquals(original.programId, selected.programId)
        assertEquals(7L, selected.programRevision)
        assertEquals(42L, selected.gasLimit)
        assertEquals(emptyList(), selected.chargeLimits)
        assertContentEquals(codec.encodeFeePaymentIntent(original), codec.encodeFeePaymentIntent(selected))
        assertFalse(codec.encodeFeePaymentIntent(selected).contentEquals(
            codec.encodeFeePaymentIntent(FeePaymentIntent.Sponsor(original.programId, 8, emptyList(), 42))))
        assertIs<FeePaymentIntent.Authority>(FeePaymentIntent.Authority(emptyList(), 42).payerSelection())
    }
}
