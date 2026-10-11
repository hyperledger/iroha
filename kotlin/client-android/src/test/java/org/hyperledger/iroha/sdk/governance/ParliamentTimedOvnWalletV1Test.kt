package org.hyperledger.iroha.sdk.governance

import java.io.File
import java.lang.reflect.Modifier
import java.math.BigInteger
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.jupiter.api.Test

class ParliamentTimedOvnWalletV1Test {
    @Test
    fun `JVM declarations pin the ABI 29 proof JNI descriptors`() {
        val nativeClass = Class.forName(
            "org.hyperledger.iroha.sdk.governance.ParliamentTimedOvnNativeEndpointV1",
        )
        val abi = nativeClass.getDeclaredMethod("nativeBridgeAbiVersion")
        val verify = nativeClass.getDeclaredMethod(
            "nativeVerifyCastingProofV1",
            ByteArray::class.java,
            ByteArray::class.java,
            ByteArray::class.java,
            ByteArray::class.java,
        )
        val verifyPage = nativeClass.getDeclaredMethod(
            "nativeVerifyCastingProofPageV1",
            ByteArray::class.java,
            ByteArray::class.java,
            ByteArray::class.java,
            ByteArray::class.java,
        )
        val registration = nativeClass.getDeclaredMethod(
            "nativeRegistrationFromProofV1",
            ByteArray::class.java,
            ByteArray::class.java,
            ByteArray::class.java,
            ByteArray::class.java,
            String::class.java,
            ByteArray::class.java,
        )
        val ballot = nativeClass.getDeclaredMethod(
            "nativeBallotFromProofV1",
            ByteArray::class.java,
            ByteArray::class.java,
            ByteArray::class.java,
            ByteArray::class.java,
            String::class.java,
            ByteArray::class.java,
            Integer.TYPE,
        )

        assertEquals(29, ParliamentTimedOvnWalletV1.REQUIRED_BRIDGE_ABI_VERSION)
        assertEquals(Integer.TYPE, abi.returnType)
        assertEquals(ByteArray::class.java, verify.returnType)
        assertEquals(Array<ByteArray>::class.java, verifyPage.returnType)
        assertEquals(Array<ByteArray>::class.java, registration.returnType)
        assertEquals(Array<ByteArray>::class.java, ballot.returnType)
        for (method in listOf(abi, verifyPage, verify, registration, ballot)) {
            assertTrue(Modifier.isPrivate(method.modifiers))
            assertTrue(Modifier.isStatic(method.modifiers))
            assertTrue(Modifier.isNative(method.modifiers))
        }
        assertFailsWith<NoSuchMethodException> {
            nativeClass.getDeclaredMethod(
                "nativeRegistrationFromSeedV1",
                ByteArray::class.java,
                String::class.java,
                ByteArray::class.java,
            )
        }
    }

    @Test
    fun `Rust JNI exports stay aligned with the bounded fail-closed JVM contract`() {
        val source =
            generateSequence(File(".").canonicalFile) { it.parentFile }
                .map { root ->
                    File(
                        root,
                        "crates/connect_norito_bridge/src/platform_jni/part_3.rs",
                    )
                }
                .firstOrNull(File::isFile)
                ?.readText(Charsets.UTF_8)
                ?: error("cannot locate connect_norito_bridge platform_jni/part_3.rs")
        val symbols = listOf(
            "Java_org_hyperledger_iroha_sdk_governance_ParliamentTimedOvnNativeEndpointV1_nativeBridgeAbiVersion",
            "Java_org_hyperledger_iroha_sdk_governance_ParliamentTimedOvnNativeEndpointV1_nativeVerifyCastingProofPageV1",
            "Java_org_hyperledger_iroha_sdk_governance_ParliamentTimedOvnNativeEndpointV1_nativeVerifyCastingProofV1",
            "Java_org_hyperledger_iroha_sdk_governance_ParliamentTimedOvnNativeEndpointV1_nativeRegistrationFromProofV1",
            "Java_org_hyperledger_iroha_sdk_governance_ParliamentTimedOvnNativeEndpointV1_nativeBallotFromProofV1",
        )
        for (symbol in symbols) {
            val declaration = "pub unsafe extern \"system\" fn $symbol("
            assertEquals(1, source.windowed(declaration.length).count { it == declaration })
        }
        for (requiredSourceContract in listOf(
            "CONNECT_NORITO_BRIDGE_ABI_VERSION as jni::sys::jint",
            "CONNECT_NORITO_PARLIAMENT_TIMED_OVN_CASTING_PROOF_MAX_BYTES_V1",
            "CONNECT_NORITO_PARLIAMENT_TIMED_OVN_CASTING_PROOF_PAGE_SUMMARY_BYTES_V1",
            "CONNECT_NORITO_PARLIAMENT_TIMED_OVN_TRUST_ANCHOR_BYTES_V1",
            "CONNECT_NORITO_PARLIAMENT_TIMED_OVN_SEED_BYTES_V1",
            "AUTHORITY_UTF8_MAX_BYTES_V1",
            "TIMED_OVN_REGISTRATION_RECORD_BYTES_V1",
            "TIMED_OVN_BALLOT_RECORD_BYTES_V1",
            "Zeroizing::new",
            "parliament_jni_components",
            "clear_parliament_jni_exception",
            ".filter(|choice| *choice <= 2)",
            "verified_terminal_casting_proof_v1",
            "verified_casting_proof_page_v1",
            "registration_from_verified_context_v1",
            "ballot_from_verified_context_v1",
        )) {
            assertTrue(
                source.contains(requiredSourceContract),
                "missing JNI source contract: $requiredSourceContract",
            )
        }
        assertFalse(source.contains("nativeRegistrationFromSeedV1"))
        assertFalse(source.contains("nativeBallotFromSeedV1"))
        val proofGate = source.indexOf("verified_terminal_casting_proof_v1(")
        val seedRead = source.indexOf("let seed_bytes = Zeroizing::new(", proofGate)
        assertTrue(proofGate >= 0 && seedRead > proofGate, "proof gate must precede seed copy")
    }

    @Test
    fun `production context and native probes fail closed`() {
        val source =
            generateSequence(File(".").canonicalFile) { it.parentFile }
                .flatMap { root ->
                    sequenceOf(
                        File(
                            root,
                            "src/main/java/org/hyperledger/iroha/sdk/governance/ParliamentTimedOvnWalletV1.kt",
                        ),
                        File(
                            root,
                            "kotlin/client-android/src/main/java/org/hyperledger/iroha/sdk/governance/ParliamentTimedOvnWalletV1.kt",
                        ),
                    )
                }
                .firstOrNull(File::isFile)
                ?.readText(Charsets.UTF_8)
                ?: error("cannot locate ParliamentTimedOvnWalletV1.kt")

        assertTrue(source.contains("context.applicationContext ?: context"))
        assertTrue(source.contains("pageVerifyProbe == null"))
        assertTrue(source.contains("pageVerifyProbe?.forEach { it.fill(0) }"))
        assertTrue(source.contains("registrationProbe?.forEach { it.fill(0) }"))
        assertTrue(source.contains("ballotProbe?.forEach { it.fill(0) }"))
        assertTrue(source.contains("private const val ENVELOPE_VERSION = 2"))
        assertTrue(source.contains("generationId.copyInto(envelope, GENERATION_ID_OFFSET)"))
        assertTrue(source.contains("synchronized(lockForAlias(handle.alias))"))
        assertTrue(source.contains("handle.matchesGenerationId(generationId)"))
        assertTrue(source.contains("cipher.updateAAD(aad)"))
        assertFalse(source.contains("nativeRegistrationFromSeedV1"))
        assertFalse(source.contains("nativeBallotFromSeedV1"))
    }

    @Test
    fun `opaque handle feeds registration and ballot without a public raw-seed API`() {
        val vault = FakeSeedVault()
        val endpoint = FakeEndpoint()
        val wallet = ParliamentTimedOvnWalletV1.withComponentsForTests(vault, endpoint)
        val handle = wallet.createSeedHandle("member-one")

        assertTrue(wallet.isAvailable)
        assertEquals("ParliamentTimedOvnSeedHandleV1(redacted)", handle.toString())
        assertEquals(handle, wallet.seedHandle("member-one"))
        assertContentEquals(
            ByteArray(ParliamentTimedOvnWalletV1.REGISTRATION_RECORD_BYTES) { 0x31.toByte() },
            wallet.registrationFromProofV1(byteArrayOf(1), trustAnchor(), AUTHORITY, handle).record(),
        )
        assertContentEquals(
            ByteArray(ParliamentTimedOvnWalletV1.BALLOT_RECORD_BYTES) { 0x42.toByte() },
            wallet.ballotFromProofV1(
                byteArrayOf(2),
                trustAnchor(),
                AUTHORITY,
                handle,
                ParliamentTimedOvnBallotChoiceV1.ABSTAIN,
            ).record(),
        )
        assertEquals(listOf(2), endpoint.choices)
        assertTrue(vault.lastBorrowedSeedWasCleared)

        val publicMethods = ParliamentTimedOvnWalletV1::class.java.methods
            .filter { it.declaringClass == ParliamentTimedOvnWalletV1::class.java }
        assertTrue(publicMethods.none { method ->
            method.name.contains("rawSeed", ignoreCase = true) ||
                method.name == "seedBytes" ||
                method.name == "importSeed"
        })
    }

    @Test
    fun `unavailable bridge and malformed public inputs fail closed`() {
        val vault = FakeSeedVault()
        val unavailable = ParliamentTimedOvnWalletV1.withComponentsForTests(vault, null)
        val handle = unavailable.createSeedHandle("member-two")
        assertFalse(unavailable.isAvailable)
        assertFailsWith<IllegalStateException> {
            unavailable.registrationFromProofV1(
                byteArrayOf(1),
                trustAnchor(),
                AUTHORITY,
                handle,
            )
        }

        val wallet = ParliamentTimedOvnWalletV1.withComponentsForTests(vault, FakeEndpoint())
        assertFailsWith<IllegalArgumentException> {
            wallet.registrationFromProofV1(ByteArray(0), trustAnchor(), AUTHORITY, handle)
        }
        assertFailsWith<IllegalArgumentException> {
            wallet.registrationFromProofV1(
                byteArrayOf(1),
                trustAnchor(),
                "bad\u0000authority",
                handle,
            )
        }
        assertTrue(wallet.deleteSeedHandle(handle))
        assertNull(wallet.seedHandle("member-two"))
    }

    @Test
    fun `trust anchor is immutable and rejects missing exact anchors`() {
        val network = ByteArray(32) { 1 }
        val context = ByteArray(32) { 3 }
        val ballot = ByteArray(32) { 5 }
        val anchor = ParliamentTimedOvnCastingTrustAnchorV1(network, 7, context, ballot)
        network.fill(9)
        context.fill(9)
        ballot.fill(9)

        val snapshot = anchor.snapshot()
        assertEquals(BigInteger.valueOf(7), anchor.trustedCheckpointHeight)
        assertEquals(BigInteger.valueOf(7), snapshot.trustedCheckpointHeight)

        assertContentEquals(ByteArray(32) { 1 }, snapshot.networkIdBytes())
        assertContentEquals(ByteArray(32) { 3 }, snapshot.checkpointNoritoBytes())
        assertContentEquals(ByteArray(32) { 5 }, snapshot.ballotAttemptIdBytes())
        assertFailsWith<IllegalArgumentException> {
            ParliamentTimedOvnCastingTrustAnchorV1(ByteArray(31), 7, context, ballot)
        }
        assertFailsWith<IllegalArgumentException> {
            ParliamentTimedOvnCastingTrustAnchorV1(network, 0, context, ballot)
        }
        assertFailsWith<IllegalArgumentException> {
            ParliamentTimedOvnCastingTrustAnchorV1(
                network,
                BigInteger.ZERO,
                context,
                ballot,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            ParliamentTimedOvnCastingTrustAnchorV1(
                network,
                BigInteger.ONE.shiftLeft(64),
                context,
                ballot,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            ParliamentTimedOvnCastingTrustAnchorV1(network, 7, context, ByteArray(32))
        }
    }

    @Test
    fun `trust anchor admits max u64 request hint while native calls carry complete checkpoints`() {
        val maximumU64 = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)
        val network = ByteArray(32) { 1 }
        val context = ByteArray(32) { 3 }
        val ballot = ByteArray(32) { 5 }
        val anchor = ParliamentTimedOvnCastingTrustAnchorV1(
            network,
            maximumU64,
            context,
            ballot,
        )

        assertEquals(maximumU64, anchor.trustedCheckpointHeight)
        assertEquals(maximumU64, anchor.snapshot().trustedCheckpointHeight)


        val wallet = ParliamentTimedOvnWalletV1.withComponentsForTests(
            FakeSeedVault(),
            FakeEndpoint(pageResult = pageVerificationBytes(maximumU64, 0x22, 0)),
        )
        val verification = wallet.verifyCastingProofPageV1(byteArrayOf(7), trustAnchor())
        assertEquals(maximumU64, verification.evaluatedBlockHeight)
        val promoted = trustAnchor().promoted(verification)
        assertEquals(maximumU64, promoted.trustedCheckpointHeight)

        assertContentEquals(mockCheckpoint(), promoted.trustedCheckpointNorito())
    }

    @Test
    fun `native page verification requires exact metadata and a complete checkpoint component`() {
        val endpoint = FakeEndpoint(
            pageResult = pageVerificationBytes(70, 0x22, 1),
        )
        val wallet = ParliamentTimedOvnWalletV1.withComponentsForTests(
            FakeSeedVault(),
            endpoint,
        )
        val verification = wallet.verifyCastingProofPageV1(byteArrayOf(7), trustAnchor())

        assertEquals(BigInteger.valueOf(70), verification.evaluatedBlockHeight)
        assertContentEquals(ByteArray(32) { 0x22 }, verification.evaluatedContextId())
        assertTrue(verification.moreAvailable)
        assertEquals(0, endpoint.pageResult!!.count { it != 0.toByte() })

        for (malformed in listOf(
            ByteArray(40),
            pageVerificationBytes(70, 0x22, 2),
            pageVerificationBytes(0, 0x22, 0),
            pageVerificationBytes(70, 0, 0),
        )) {
            val malformedWallet = ParliamentTimedOvnWalletV1.withComponentsForTests(
                FakeSeedVault(),
                FakeEndpoint(pageResult = malformed),
            )
            assertFailsWith<IllegalStateException> {
                malformedWallet.verifyCastingProofPageV1(byteArrayOf(7), trustAnchor())
            }
        }
    }

    @Test
    fun `proof rejection occurs before seed borrow and call arrays are snapshotted`() {
        val rejectedVault = FakeSeedVault()
        val rejectedWallet = ParliamentTimedOvnWalletV1.withComponentsForTests(
            rejectedVault,
            FakeEndpoint(proofAccepted = false),
        )
        val rejectedHandle = rejectedWallet.createSeedHandle("proof-rejected")
        assertFailsWith<IllegalStateException> {
            rejectedWallet.registrationFromProofV1(
                byteArrayOf(7),
                trustAnchor(),
                AUTHORITY,
                rejectedHandle,
            )
        }
        assertEquals(0, rejectedVault.borrowCount)

        val snapshotEndpoint = object : ParliamentTimedOvnWalletV1.Endpoint {
            override fun verifyCastingProof(
                proofResponse: ByteArray,
                trustAnchor: ParliamentTimedOvnCastingTrustAnchorSnapshotV1,
            ): ByteArray? {
                proofResponse.fill(99)
                trustAnchor.networkIdBytes().fill(99)
                return mockCheckpoint()
            }

            override fun registration(
                proofResponse: ByteArray,
                trustAnchor: ParliamentTimedOvnCastingTrustAnchorSnapshotV1,
                authority: String,
                seed: ByteArray,
            ): Array<ByteArray>? {
                assertContentEquals(byteArrayOf(7), proofResponse)
                assertContentEquals(ByteArray(32) { 1 }, trustAnchor.networkIdBytes())
                return arrayOf(ByteArray(ParliamentTimedOvnWalletV1.REGISTRATION_RECORD_BYTES), mockCheckpoint())
            }

            override fun ballot(
                proofResponse: ByteArray,
                trustAnchor: ParliamentTimedOvnCastingTrustAnchorSnapshotV1,
                authority: String,
                seed: ByteArray,
                choice: Int,
            ): Array<ByteArray>? = null
        }
        val snapshotVault = FakeSeedVault()
        val snapshotWallet = ParliamentTimedOvnWalletV1.withComponentsForTests(
            snapshotVault,
            snapshotEndpoint,
        )
        val snapshotHandle = snapshotWallet.createSeedHandle("proof-snapshot")
        val callerProof = byteArrayOf(7)
        snapshotWallet.registrationFromProofV1(
            callerProof,
            trustAnchor(),
            AUTHORITY,
            snapshotHandle,
        )
        assertContentEquals(byteArrayOf(7), callerProof)
        assertEquals(1, snapshotVault.borrowCount)
    }

    @Test
    fun `delete and recreate cannot retarget a stale seed handle`() {
        val vault = FakeSeedVault()
        val wallet = ParliamentTimedOvnWalletV1.withComponentsForTests(vault, FakeEndpoint())
        val stale = wallet.createSeedHandle("rotating-member")

        assertTrue(wallet.deleteSeedHandle(stale))
        val current = wallet.createSeedHandle("rotating-member")
        assertNotEquals(stale, current)
        assertFalse(wallet.deleteSeedHandle(stale))
        val error = assertFailsWith<IllegalStateException> {
            wallet.registrationFromProofV1(byteArrayOf(1), trustAnchor(), AUTHORITY, stale)
        }
        assertEquals("Parliament timed-OVN seed handle is stale", error.message)
        assertContentEquals(
            ByteArray(ParliamentTimedOvnWalletV1.REGISTRATION_RECORD_BYTES) { 0x31.toByte() },
            wallet.registrationFromProofV1(byteArrayOf(1), trustAnchor(), AUTHORITY, current).record(),
        )
    }

    @Test
    fun `delete waits for an in-flight use of the same seed generation`() {
        val vault = FakeSeedVault()
        val endpoint = BlockingEndpoint()
        val wallet = ParliamentTimedOvnWalletV1.withComponentsForTests(vault, endpoint)
        val handle = wallet.createSeedHandle("concurrent-member")
        val executor = Executors.newFixedThreadPool(2)
        try {
            val use = executor.submit<ParliamentTimedOvnPublicRecordV1> {
                wallet.registrationFromProofV1(
                    byteArrayOf(1),
                    trustAnchor(),
                    AUTHORITY,
                    handle,
                )
            }
            assertTrue(endpoint.started.await(5, TimeUnit.SECONDS))

            vault.deleteAttempted = CountDownLatch(1)
            val delete = executor.submit<Boolean> { wallet.deleteSeedHandle(handle) }
            assertTrue(vault.deleteAttempted?.await(5, TimeUnit.SECONDS) == true)
            assertFalse(delete.isDone)

            endpoint.release.countDown()
            assertEquals(
                ParliamentTimedOvnWalletV1.REGISTRATION_RECORD_BYTES,
                use.get(5, TimeUnit.SECONDS).record().size,
            )
            assertTrue(delete.get(5, TimeUnit.SECONDS))
            assertNull(wallet.seedHandle("concurrent-member"))
        } finally {
            endpoint.release.countDown()
            executor.shutdownNow()
        }
    }

    private class FakeSeedVault : ParliamentTimedOvnWalletV1.SeedVault {
        private val aliases = mutableMapOf<String, ByteArray>()
        private val locks = java.util.concurrent.ConcurrentHashMap<String, Any>()
        private var nextGeneration = 1
        var deleteAttempted: CountDownLatch? = null
        var lastBorrowedSeedWasCleared: Boolean = false
            private set
        var borrowCount: Int = 0
            private set

        override fun create(alias: String): ParliamentTimedOvnSeedHandleV1 {
            return synchronized(lock(alias)) {
                check(!aliases.containsKey(alias))
                val generationId = ByteArray(32) { nextGeneration.toByte() }
                nextGeneration += 1
                aliases[alias] = generationId.clone()
                ParliamentTimedOvnSeedHandleV1(alias, generationId)
            }
        }

        override fun open(alias: String): ParliamentTimedOvnSeedHandleV1? =
            synchronized(lock(alias)) {
                aliases[alias]?.let { ParliamentTimedOvnSeedHandleV1(alias, it) }
            }

        override fun delete(handle: ParliamentTimedOvnSeedHandleV1): Boolean {
            deleteAttempted?.countDown()
            return synchronized(lock(handle.alias)) {
                val generationId = aliases[handle.alias] ?: return@synchronized false
                if (!handle.matchesGenerationId(generationId)) return@synchronized false
                aliases.remove(handle.alias)?.fill(0)
                true
            }
        }

        override fun <T> withSeed(
            handle: ParliamentTimedOvnSeedHandleV1,
            operation: (ByteArray) -> T,
        ): T {
            return synchronized(lock(handle.alias)) {
                val generationId = aliases[handle.alias]
                    ?: throw IllegalStateException("Parliament timed-OVN seed handle is unavailable")
                if (!handle.matchesGenerationId(generationId)) {
                    throw IllegalStateException("Parliament timed-OVN seed handle is stale")
                }
                val seed = ByteArray(32) { 7 }
                try {
                    borrowCount += 1
                    operation(seed)
                } finally {
                    seed.fill(0)
                    lastBorrowedSeedWasCleared = seed.all { it == 0.toByte() }
                }
            }
        }

        private fun lock(alias: String): Any {
            val candidate = Any()
            return locks.putIfAbsent(alias, candidate) ?: candidate
        }
    }

    private class FakeEndpoint(
        private val proofAccepted: Boolean = true,
        val pageResult: ByteArray? = pageVerificationBytes(7, 3, 0),
        private val pageCheckpoint: ByteArray = mockCheckpoint(),
        private val recordCheckpoint: ByteArray = mockCheckpoint(),
    ) : ParliamentTimedOvnWalletV1.Endpoint {
        val choices = mutableListOf<Int>()

        override fun verifyCastingProofPage(
            proofResponse: ByteArray,
            trustAnchor: ParliamentTimedOvnCastingTrustAnchorSnapshotV1,
        ): Array<ByteArray>? = pageResult?.let { arrayOf(it, pageCheckpoint.clone()) }

        override fun verifyCastingProof(
            proofResponse: ByteArray,
            trustAnchor: ParliamentTimedOvnCastingTrustAnchorSnapshotV1,
        ): ByteArray? {
            check(proofResponse.isNotEmpty())
            check(trustAnchor.networkIdBytes().size == 32)
            return if (proofAccepted) mockCheckpoint() else null
        }

        override fun registration(
            proofResponse: ByteArray,
            trustAnchor: ParliamentTimedOvnCastingTrustAnchorSnapshotV1,
            authority: String,
            seed: ByteArray,
        ): Array<ByteArray>? {
            check(
                proofResponse.isNotEmpty() &&
                    trustAnchor.trustedCheckpointHeight == BigInteger.valueOf(7) &&
                    authority == AUTHORITY &&
                    seed.size == 32,
            )
            return arrayOf(ByteArray(ParliamentTimedOvnWalletV1.REGISTRATION_RECORD_BYTES) { 0x31.toByte() }, recordCheckpoint)
        }

        override fun ballot(
            proofResponse: ByteArray,
            trustAnchor: ParliamentTimedOvnCastingTrustAnchorSnapshotV1,
            authority: String,
            seed: ByteArray,
            choice: Int,
        ): Array<ByteArray>? {
            check(
                proofResponse.isNotEmpty() &&
                    trustAnchor.trustedCheckpointHeight == BigInteger.valueOf(7) &&
                    authority == AUTHORITY &&
                    seed.size == 32,
            )
            choices += choice
            return arrayOf(ByteArray(ParliamentTimedOvnWalletV1.BALLOT_RECORD_BYTES) { 0x42.toByte() }, recordCheckpoint)
        }
    }

    private class BlockingEndpoint : ParliamentTimedOvnWalletV1.Endpoint {
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)

        override fun verifyCastingProof(
            proofResponse: ByteArray,
            trustAnchor: ParliamentTimedOvnCastingTrustAnchorSnapshotV1,
        ): ByteArray? = mockCheckpoint()

        override fun registration(
            proofResponse: ByteArray,
            trustAnchor: ParliamentTimedOvnCastingTrustAnchorSnapshotV1,
            authority: String,
            seed: ByteArray,
        ): Array<ByteArray>? {
            started.countDown()
            check(release.await(5, TimeUnit.SECONDS))
            return arrayOf(ByteArray(ParliamentTimedOvnWalletV1.REGISTRATION_RECORD_BYTES) { 0x31.toByte() }, mockCheckpoint())
        }

        override fun ballot(
            proofResponse: ByteArray,
            trustAnchor: ParliamentTimedOvnCastingTrustAnchorSnapshotV1,
            authority: String,
            seed: ByteArray,
            choice: Int,
        ): Array<ByteArray>? = null
    }

    @Test
    fun `page metadata alone cannot promote and complete checkpoint is preserved`() {
        val wallet = ParliamentTimedOvnWalletV1.withComponentsForTests(FakeSeedVault(),
            FakeEndpoint(pageCheckpoint = ByteArray(0)))
        assertFailsWith<IllegalStateException> { wallet.verifyCastingProofPageV1(byteArrayOf(7), trustAnchor()) }
        val vault = FakeSeedVault()
        val native = ParliamentTimedOvnWalletV1.withComponentsForTests(vault, FakeEndpoint())
        val result = native.registrationFromProofV1(byteArrayOf(7), trustAnchor(), AUTHORITY,
            native.createSeedHandle("checkpoint-record"))
        assertContentEquals(mockCheckpoint(), result.promotedCheckpointNorito())
        val mutated = result.promotedCheckpointNorito()
        mutated.fill(0)
        assertContentEquals(mockCheckpoint(), result.promotedCheckpointNorito())
    }

    @Test
    fun `wallet refuses a record paired with a different checkpoint promotion`() {
        val vault = FakeSeedVault()
        val wallet = ParliamentTimedOvnWalletV1.withComponentsForTests(vault,
            FakeEndpoint(recordCheckpoint = ByteArray(113) { 0x77 }))
        val handle = wallet.createSeedHandle("checkpoint-substitution")
        assertFailsWith<IllegalStateException> {
            wallet.registrationFromProofV1(byteArrayOf(7), trustAnchor(), AUTHORITY, handle)
        }
        assertEquals(1, vault.borrowCount)
        assertTrue(vault.lastBorrowedSeedWasCleared)
    }

    companion object {
        // Opaque native-endpoint mock output only; never a cryptographic checkpoint fixture.
        private fun mockCheckpoint(): ByteArray = ByteArray(113) { 0x66 }

        private const val AUTHORITY =
            "ed0120aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

        private fun trustAnchor(): ParliamentTimedOvnCastingTrustAnchorV1 =
            ParliamentTimedOvnCastingTrustAnchorV1(
                ByteArray(32) { 1 },
                7,
                ByteArray(32) { 3 },
                ByteArray(32) { 5 },
            )

        private fun pageVerificationBytes(
            height: Long,
            contextByte: Int,
            moreAvailable: Int,
        ): ByteArray = pageVerificationBytes(
            BigInteger.valueOf(height),
            contextByte,
            moreAvailable,
        )

        private fun pageVerificationBytes(
            height: BigInteger,
            contextByte: Int,
            moreAvailable: Int,
        ): ByteArray = ByteArray(41).also { encoded ->
            require(height.signum() >= 0 && height.bitLength() <= 64)
            for (index in 0 until 8) {
                encoded[7 - index] = height.shiftRight(index * 8).toByte()
            }
            encoded.fill(contextByte.toByte(), 8, 40)
            encoded[40] = moreAvailable.toByte()
        }
    }
}
