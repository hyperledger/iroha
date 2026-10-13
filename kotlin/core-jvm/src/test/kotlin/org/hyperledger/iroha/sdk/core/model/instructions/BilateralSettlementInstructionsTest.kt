package org.hyperledger.iroha.sdk.core.model.instructions

import java.nio.file.Files
import java.nio.file.Paths
import java.util.Base64
import java.util.Properties
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import org.hyperledger.iroha.sdk.address.AccountAddress
import org.hyperledger.iroha.sdk.core.model.WirePayload

class BilateralSettlementInstructionsTest {
    @Test
    fun `DvP and PvP match shared Rust-compatible all-or-nothing fixtures`() {
        val fixtures = fixtures()
        val dvp = dvp()
        val pvp = pvp()

        assertWireFixture(dvp.toInstructionBox(), "iroha.settlement", fixtures.getProperty("dvp.payload_base64"))
        assertContentEquals(hex(fixtures.getProperty("dvp.intent_hash_hex")), dvp.intentHash())
        assertEquals("ALL_OR_NOTHING", dvp.arguments.getValue("atomicity"))

        assertWireFixture(pvp.toInstructionBox(), "iroha.settlement", fixtures.getProperty("pvp.payload_base64"))
        assertContentEquals(hex(fixtures.getProperty("pvp.intent_hash_hex")), pvp.intentHash())
        assertEquals("ALL_OR_NOTHING", pvp.arguments.getValue("atomicity"))
    }

    @Test
    fun `repo and reverse repo match shared Rust fixtures and exact consent hashes`() {
        val fixtures = fixtures()
        val repo = repo()

        assertWireFixture(repo.toInstructionBox(), "iroha.repo", fixtures.getProperty("repo.payload_base64"))
        assertEquals(BilateralSettlementInstructions.SettlementId(REPO_INITIATOR, "daily_repo"), repo.settlementId())
        assertContentEquals(
            hex(fixtures.getProperty("repo.initiation_intent_hash_hex")),
            repo.initiationIntentHash(),
        )
        assertContentEquals(
            hex(fixtures.getProperty("repo.maturity_intent_hash_hex")),
            repo.maturityIntentHash(),
        )
        assertWireFixture(
            BilateralSettlementInstructions.ReverseRepo("daily_repo").toInstructionBox(),
            "iroha.repo",
            fixtures.getProperty("reverse_repo.payload_base64"),
        )
    }

    @Test
    fun `early repayment opt-in is bound into both repo consent hashes`() {
        val fixed = repo()
        val early = repo(allowEarlyRepayment = true)
        assertEquals(true, early.governance.allowEarlyRepayment)
        assertEquals(false, fixed.governance.allowEarlyRepayment)
        assertEquals(false, fixed.initiationIntentHash().contentEquals(early.initiationIntentHash()))
        assertEquals(false, fixed.maturityIntentHash().contentEquals(early.maturityIntentHash()))
    }

    @Test
    fun `typed constructors reject ambiguous or unsafe economic terms`() {
        val sameControllerOtherDiscriminant = AccountAddress.fromI105(ALICE, null).toI105(1)
        assertFailsWith<IllegalArgumentException> {
            BilateralSettlementInstructions.SettlementLeg(
                BOND,
                "1",
                ALICE,
                sameControllerOtherDiscriminant,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            BilateralSettlementInstructions.SettlementLeg(BOND, "0", ALICE, BOB)
        }
        assertFailsWith<IllegalArgumentException> {
            BilateralSettlementInstructions.Dvp(
                BilateralSettlementInstructions.SettlementId(ALICE, "not_reciprocal"),
                BilateralSettlementInstructions.SettlementLeg(BOND, "1", ALICE, BOB),
                BilateralSettlementInstructions.SettlementLeg(USD, "1", ALICE, BOB),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            BilateralSettlementInstructions.RepoGovernance(10_001, 1, false)
        }
        assertFailsWith<IllegalArgumentException> {
            BilateralSettlementInstructions.Repo(
                "repo",
                ALICE,
                BOB,
                ALICE,
                BilateralSettlementInstructions.RepoCashLeg(USD, "1"),
                BilateralSettlementInstructions.RepoCollateralLeg(BOND, "1"),
                0,
                1,
                BilateralSettlementInstructions.RepoGovernance(0, 0, false),
            )
        }
    }

    @Test
    fun `settlement identity retains owner and rejects bare or alternate text`() {
        val id = BilateralSettlementInstructions.SettlementId(ALICE, "payment-42")
        assertEquals(id, BilateralSettlementInstructions.SettlementId.parse(id.toString()))
        assertNotEquals(id, BilateralSettlementInstructions.SettlementId(BOB, "payment-42"))
        val alternate = AccountAddress.fromI105(ALICE, null).toI105(1)
        assertEquals(id, BilateralSettlementInstructions.SettlementId(alternate, "payment-42"))
        for (invalid in listOf("payment-42", "payment-42\$", "\$$ALICE", "payment-42\$$alternate")) {
            assertFailsWith<IllegalArgumentException> {
                BilateralSettlementInstructions.SettlementId.parse(invalid)
            }
        }
        for (reference in listOf("payment\u00a042", "payment\u200742", "payment\u202f42", "e\u0301")) {
            assertFailsWith<IllegalArgumentException> {
                BilateralSettlementInstructions.SettlementId(ALICE, reference)
            }
        }
        assertFailsWith<IllegalArgumentException> {
            BilateralSettlementInstructions.Dvp(
                BilateralSettlementInstructions.SettlementId(REPO_CUSTODIAN, "not-a-payer"),
                dvp().deliveryLeg,
                dvp().paymentLeg,
            )
        }
        val otherOwner = BilateralSettlementInstructions.Dvp(
            BilateralSettlementInstructions.SettlementId(BOB, "dvp_trade_1"),
            dvp().deliveryLeg,
            dvp().paymentLeg,
        )
        assertNotEquals(dvp().intentHash().toList(), otherOwner.intentHash().toList())
    }

    private fun dvp(): BilateralSettlementInstructions.Dvp =
        BilateralSettlementInstructions.Dvp(
            BilateralSettlementInstructions.SettlementId(ALICE, "dvp_trade_1"),
            BilateralSettlementInstructions.SettlementLeg(BOND, "1000", ALICE, BOB),
            BilateralSettlementInstructions.SettlementLeg(USD, "1005", BOB, ALICE),
            BilateralSettlementInstructions.ExecutionOrder.DELIVERY_THEN_PAYMENT,
        )

    private fun pvp(): BilateralSettlementInstructions.Pvp =
        BilateralSettlementInstructions.Pvp(
            BilateralSettlementInstructions.SettlementId(ALICE, "pvp_fx_1"),
            BilateralSettlementInstructions.SettlementLeg(USD, "1000", ALICE, BOB),
            BilateralSettlementInstructions.SettlementLeg(EUR, "920", BOB, ALICE),
            BilateralSettlementInstructions.ExecutionOrder.PAYMENT_THEN_DELIVERY,
        )

    private fun repo(allowEarlyRepayment: Boolean = false): BilateralSettlementInstructions.Repo =
        BilateralSettlementInstructions.Repo(
            "daily_repo",
            REPO_INITIATOR,
            REPO_COUNTERPARTY,
            REPO_CUSTODIAN,
            BilateralSettlementInstructions.RepoCashLeg(USD, "1000"),
            BilateralSettlementInstructions.RepoCollateralLeg(BOND, "1100"),
            250,
            1_735_086_400_000,
            BilateralSettlementInstructions.RepoGovernance(1_500, 86_400, allowEarlyRepayment),
        )

    private fun assertWireFixture(
        box: org.hyperledger.iroha.sdk.core.model.InstructionBox,
        wireName: String,
        encoded: String,
    ) {
        val wire = assertIs<WirePayload>(box.payload)
        assertEquals(wireName, wire.wireName)
        assertContentEquals(Base64.getDecoder().decode(encoded), wire.payloadBytes)
    }

    private fun fixtures(): Properties {
        val candidates = listOf(
            Paths.get("../../fixtures/norito_rpc/bilateral_settlement_sdk_wire.properties"),
            Paths.get("../fixtures/norito_rpc/bilateral_settlement_sdk_wire.properties"),
            Paths.get("fixtures/norito_rpc/bilateral_settlement_sdk_wire.properties"),
        )
        val path = candidates.firstOrNull { Files.isRegularFile(it) }
            ?: error("missing shared bilateral settlement wire fixture")
        return Properties().also { properties ->
            Files.newInputStream(path).use { input -> properties.load(input) }
        }
    }

    private fun hex(value: String): ByteArray =
        ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private companion object {
        const val ALICE = "sorauﾛ1NｲﾘｳdPBeｼRoｸQ2ﾔgｼQqeｶﾍｽﾁhRW2ｺｿZ9ﾕｦUﾅRX5NJYH53"
        const val BOB = "sorauﾛ1P58ﾊt2MaｺxhpﾄｽﾅｲｼKヰkDﾑｱjｴｴ9GFﾉﾌkrｽRzﾑﾌxKBMEBH"
        const val BOND = "7cgpbDVabB1g8uax9JkhGckEHwfe"
        const val USD = "4eaant86faGEgeH21U4qTTfpvwSb"
        const val EUR = "5n4HJrqdiJkuFTa2Kmx2DvXnBkos"
        const val REPO_INITIATOR = ALICE
        const val REPO_COUNTERPARTY = BOB
        const val REPO_CUSTODIAN = "sorauﾛ1Q3ﾘヰｴﾀknﾀﾏｾｳﾚﾒﾎvﾘEPｶﾉPmｼMﾘｱﾂSNFsｶヱeﾒyヰﾜPD63RA"
    }
}
