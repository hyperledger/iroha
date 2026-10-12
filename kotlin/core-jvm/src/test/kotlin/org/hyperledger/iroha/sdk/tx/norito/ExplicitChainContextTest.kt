package org.hyperledger.iroha.sdk.tx.norito

import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.hyperledger.iroha.sdk.address.AccountAddress
import org.hyperledger.iroha.sdk.client.TairaTestnetProfile
import org.hyperledger.iroha.sdk.core.model.Executable
import org.hyperledger.iroha.sdk.core.model.FeePaymentIntent
import org.hyperledger.iroha.sdk.core.model.JsonValue
import org.hyperledger.iroha.sdk.core.model.NetworkId
import org.hyperledger.iroha.sdk.core.model.TransactionPayload
import org.hyperledger.iroha.sdk.core.model.WirePayload
import org.hyperledger.iroha.sdk.core.model.instructions.RegisterZkAssetInstruction
import org.hyperledger.iroha.sdk.core.model.instructions.TransferWirePayloadEncoder
import org.hyperledger.iroha.sdk.crypto.NativeSignerBridge
import org.hyperledger.iroha.sdk.crypto.SigningAlgorithm
import org.hyperledger.iroha.sdk.norito.NoritoCodec
import org.hyperledger.iroha.sdk.norito.NoritoDecoder
import org.hyperledger.iroha.sdk.norito.NoritoEncoder
import org.hyperledger.iroha.sdk.testing.JvmApiInventory
import org.hyperledger.iroha.sdk.testing.TestEd25519Keys
import org.hyperledger.iroha.sdk.testing.TestNetworkIds
import org.hyperledger.iroha.sdk.tx.SignedTransaction
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** Adversarial coverage for the caller-owned I105 chain context. */
class ExplicitChainContextTest {

    @Test
    fun `adapters require bounded explicit context and reject mismatched prefixes`() {
        assertFalse(
            JvmApiInventory.read(NoritoJavaCodecAdapter::class.java).methods.any {
                it.name == "<init>" && it.isPublic && it.parameterTypes.isEmpty()
            },
            "the codec must not expose a context-free constructor",
        )
        assertFailsWith<IllegalArgumentException> { NoritoJavaCodecAdapter(-1) }
        assertFailsWith<IllegalArgumentException> { NoritoJavaCodecAdapter(0x1_0000) }

        val tairaAuthority = account(0x41, TAIRA)
        val otherAuthority = account(0x41, OTHER)
        val tairaPayload = payload(tairaAuthority)
        val otherPayload = payload(otherAuthority)
        val tairaAdapter = NoritoJavaCodecAdapter(TAIRA)
        val otherAdapter = NoritoJavaCodecAdapter(OTHER)

        val tairaBytes = tairaAdapter.encodeTransaction(tairaPayload)
        val otherBytes = otherAdapter.encodeTransaction(otherPayload)
        assertContentEquals(
            tairaBytes,
            otherBytes,
            "the chain context changes only the authenticated I105 projection",
        )
        assertEquals(tairaAuthority, tairaAdapter.decodeTransaction(tairaBytes).authority)
        assertEquals(otherAuthority, otherAdapter.decodeTransaction(tairaBytes).authority)
        assertNotEquals(tairaAuthority, otherAdapter.decodeTransaction(tairaBytes).authority)
        assertFailsWith<NoritoException> { otherAdapter.encodeTransaction(tairaPayload) }
        assertFailsWith<NoritoException> { tairaAdapter.encodeTransaction(otherPayload) }
    }

    @Test
    fun `concurrent adapters do not leak chain context`() {
        val tairaAdapter = NoritoJavaCodecAdapter(TAIRA)
        val otherAdapter = NoritoJavaCodecAdapter(OTHER)
        val tairaPayload = payload(account(0x42, TAIRA))
        val otherPayload = payload(account(0x43, OTHER))
        val start = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(2)
        try {
            val tairaFuture = executor.submit(
                Callable {
                    start.await()
                    repeat(250) {
                        assertEquals(
                            tairaPayload.authority,
                            tairaAdapter
                                .decodeTransaction(tairaAdapter.encodeTransaction(tairaPayload))
                                .authority,
                        )
                    }
                },
            )
            val otherFuture = executor.submit(
                Callable {
                    start.await()
                    repeat(250) {
                        assertEquals(
                            otherPayload.authority,
                            otherAdapter
                                .decodeTransaction(otherAdapter.encodeTransaction(otherPayload))
                                .authority,
                        )
                    }
                },
            )
            start.countDown()
            tairaFuture.get(30, TimeUnit.SECONDS)
            otherFuture.get(30, TimeUnit.SECONDS)
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun `transfer decoder projects only the caller selected chain`() {
        val owner = account(0x44, TAIRA)
        val destination = account(0x45, TAIRA)
        val assetId = "$DS_ASSET_DEFINITION_ID#$owner"
        val instruction = TransferWirePayloadEncoder.encodeAssetTransfer(
            assetId,
            "10",
            destination,
        )
        val wire = assertIs<WirePayload>(instruction.payload).payloadBytes

        val taira = TransferWirePayloadEncoder.decodeAssetTransferPayload(wire, TAIRA)
        val adversarial = TransferWirePayloadEncoder.decodeAssetTransferPayload(wire, OTHER)

        assertEquals(assetId, taira.assetId)
        assertEquals(destination, taira.destinationAccountId)
        assertEquals(TAIRA, AccountAddress.detectI105Discriminant(taira.destinationAccountId))
        assertEquals(OTHER, AccountAddress.detectI105Discriminant(adversarial.destinationAccountId))
        assertNotEquals(taira.destinationAccountId, adversarial.destinationAccountId)
        assertNotEquals(taira.assetId, adversarial.assetId)
    }

    @Test
    fun `signed envelopes preserve canonical payload and reject all noncanonical inner forms`() {
        val adapter = NoritoJavaCodecAdapter(TAIRA)
        val payload = TransactionPayload(
            networkId = TestNetworkIds.canonical(),
            authority = account(0x46, TAIRA),
            creationTimeMs = 1_735_369_000_000L,
            executable = Executable.ivm(byteArrayOf(0x01)),
            feePayment = FeePaymentIntent.authority(emptyList(), 1L),
            metadata = linkedMapOf(
                "b" to JsonValue.string("two"),
                "a" to JsonValue.string("one"),
            ),
        )
        val canonicalPayload = adapter.encodeTransaction(payload)
        val noncanonicalPayload = swapMetadataEntries(canonicalPayload)
        val trailingPayload = canonicalPayload + byteArrayOf(0)
        val malformedPayload = byteArrayOf(0x01, 0x02, 0x03)

        assertFalse(canonicalPayload.contentEquals(noncanonicalPayload))
        assertEquals(
            payload.authority,
            adapter.decodeTransaction(noncanonicalPayload).authority,
        )

        val canonicalSigned = signed(canonicalPayload, adapter.schemaName())
        val canonicalEnvelope = SignedTransactionEncoder.encode(canonicalSigned)
        assertContentEquals(
            canonicalPayload,
            SignedTransactionEncoder.decode(canonicalEnvelope).encodedPayload(),
        )

        listOf(malformedPayload, trailingPayload, noncanonicalPayload).forEach { rejected ->
            assertFailsWith<NoritoException> {
                SignedTransactionEncoder.encode(signed(rejected, adapter.schemaName()))
            }
            assertFailsWith<NoritoException> {
                SignedTransactionEncoder.decode(
                    replaceSizedField(canonicalEnvelope, 1, rejected),
                )
            }
        }
    }

    @Test
    fun `native account entry points expose an explicit chain argument`() {
        assertAllMethodOverloadsHaveIntParameter(
            NativeSignerBridge::class.java,
            "encodeRegisterZkAssetSignedTransaction",
            2,
        )
        assertMethodHasIntParameter(
            NativeSignerBridge::class.java,
            "nativeEncodeRegisterZkAssetSignedTransaction",
            2,
        )

    }

    @Test
    fun jniTransactionBridgeRequiresExactNetworkIdBytes() {
        val managed = JvmApiInventory.read(NativeSignerBridge::class.java).methods.single {
            it.name == "encodeRegisterZkAssetSignedTransaction" &&
                it.isPublic &&
                it.isStatic
        }
        val native = JvmApiInventory.read(NativeSignerBridge::class.java).methods.single {
            it.name == "nativeEncodeRegisterZkAssetSignedTransaction" &&
                it.isNative
        }

        assertEquals("Lorg/hyperledger/iroha/sdk/core/model/NetworkId;", managed.parameterTypes[1])
        assertEquals("[B", native.parameterTypes[1])
        assertEquals(12, native.parameterTypes.size, "retired shield verifier JNI parameters must be absent")
        assertEquals(32, NetworkId.BYTE_LENGTH)
    }

    @Test
    fun `native signer rejects out-of-range chain before native dispatch`() {
        val feePayment = FeePaymentIntent.authority(emptyList())
        val register = assertFailsWith<IllegalArgumentException> {
            NativeSignerBridge.encodeRegisterZkAssetSignedTransaction(
                algorithm = SigningAlgorithm.ED25519,
                networkId = TestNetworkIds.canonical(),
                chainDiscriminant = -1,
                authority = "authority",
                creationTimeMs = 0,
                instruction = null as RegisterZkAssetInstruction?,
                privateKey = byteArrayOf(1),
                feePayment = feePayment,
            )
        }
        assertTrue(register.message.orEmpty().contains("chainDiscriminant"))

        assertTrue(
            NativeSignerBridge.isNativeAvailable(),
            "connect_norito_bridge ABI 29 is required",
        )
        val (privateKey, publicKey) = NativeSignerBridge.keypairFromSeed(
            SigningAlgorithm.ED25519,
            ByteArray(32) { 0x21.toByte() },
        )
        val tairaAuthority = AccountAddress
            .fromAccount(publicKey, "ed25519")
            .toI105(TAIRA)
        val instruction = RegisterZkAssetInstruction.builder()
            .setAsset(DS_ASSET_DEFINITION_ID)
            .build()
        assertFailsWith<IllegalArgumentException> {
            NativeSignerBridge.encodeRegisterZkAssetSignedTransaction(
                algorithm = SigningAlgorithm.ED25519,
                networkId = TestNetworkIds.canonical(),
                chainDiscriminant = OTHER,
                authority = tairaAuthority,
                creationTimeMs = 1_736_000_000_000,
                instruction = instruction,
                privateKey = privateKey,
                feePayment = feePayment,
            )
        }
    }

    private fun payload(authority: String): TransactionPayload = TransactionPayload(
        networkId = TestNetworkIds.canonical(),
        authority = authority,
        creationTimeMs = 1_735_369_000_000L,
        executable = Executable.ivm(byteArrayOf(0x01)),
        feePayment = FeePaymentIntent.authority(emptyList(), 1L),
    )

    private fun signed(payload: ByteArray, schemaName: String): SignedTransaction =
        SignedTransaction(payload, ByteArray(64) { 0x55.toByte() }, ByteArray(0), schemaName)

    private fun swapMetadataEntries(canonicalPayload: ByteArray): ByteArray {
        val fields = decodeSizedFields(canonicalPayload, 9)
        val metadata = NoritoDecoder(fields[7], NoritoCodec.DEFAULT_FLAGS)
        assertEquals(2L, metadata.readLength(false))
        val first = readSizedField(metadata)
        val second = readSizedField(metadata)
        assertEquals(0, metadata.remaining())

        val swapped = NoritoEncoder(NoritoCodec.DEFAULT_FLAGS)
        swapped.writeLength(2, false)
        writeSizedField(swapped, second)
        writeSizedField(swapped, first)
        fields[7] = swapped.toByteArray()
        return encodeSizedFields(fields)
    }

    private fun replaceSizedField(
        encoded: ByteArray,
        fieldIndex: Int,
        replacement: ByteArray,
    ): ByteArray {
        val fields = decodeSizedFields(encoded, 3)
        fields[fieldIndex] = replacement.copyOf()
        return encodeSizedFields(fields)
    }

    private fun decodeSizedFields(encoded: ByteArray, count: Int): Array<ByteArray> {
        val decoder = NoritoDecoder(encoded, NoritoCodec.DEFAULT_FLAGS)
        return Array(count) { readSizedField(decoder) }.also {
            assertEquals(0, decoder.remaining(), "unexpected trailing bytes")
        }
    }

    private fun readSizedField(decoder: NoritoDecoder): ByteArray {
        val length = decoder.readLength(true)
        return decoder.readBytes(Math.toIntExact(length))
    }

    private fun encodeSizedFields(fields: Array<ByteArray>): ByteArray {
        val encoder = NoritoEncoder(NoritoCodec.DEFAULT_FLAGS)
        fields.forEach { writeSizedField(encoder, it) }
        return encoder.toByteArray()
    }

    private fun writeSizedField(encoder: NoritoEncoder, field: ByteArray) {
        encoder.writeLength(field.size.toLong(), true)
        encoder.writeBytes(field)
    }

    private fun account(fill: Int, chainDiscriminant: Int): String = AccountAddress
        .fromAccount(TestEd25519Keys.publicKey(fill), "ed25519")
        .toI105(chainDiscriminant)

    private fun assertAllMethodOverloadsHaveIntParameter(
        type: Class<*>,
        name: String,
        parameterIndex: Int,
    ) {
        val methods = JvmApiInventory.read(type).methods.filter {
            it.name == name && it.isStatic
        }
        assertTrue(methods.isNotEmpty(), "missing method ${type.name}.$name")
        methods.forEach { method ->
            assertTrue(method.parameterTypes.size > parameterIndex)
            assertEquals("I", method.parameterTypes[parameterIndex])
        }
    }

    private fun assertMethodHasIntParameter(
        type: Class<*>,
        name: String,
        parameterIndex: Int,
    ) {
        val method = JvmApiInventory.read(type).methods.firstOrNull { it.name == name }
            ?: error("missing method ${type.name}.$name")
        assertTrue(method.parameterTypes.size > parameterIndex)
        assertEquals("I", method.parameterTypes[parameterIndex])
    }

    private fun assertMethodHasParameterCount(
        type: Class<*>,
        name: String,
        parameterCount: Int,
    ) {
        val method = JvmApiInventory.read(type).methods.firstOrNull { it.name == name }
            ?: error("missing method ${type.name}.$name")
        assertEquals(parameterCount, method.parameterTypes.size)
    }

    private companion object {
        const val TAIRA = TairaTestnetProfile.I105_DISCRIMINANT
        const val OTHER = AccountAddress.DEFAULT_I105_DISCRIMINANT
        // Low-level codecs receive the exact typed ID resolved from the app's `ds#boi.is` selector.
        const val DS_ASSET_DEFINITION_ID = "7ZepsJTHCVLKsrFFNZGSRGZgvBhv"
    }
}
