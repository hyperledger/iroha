package org.hyperledger.iroha.sdk.core.model.zk

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull

class VerifyingKeyRecordDescriptionTest {

    private val validSchemaHash = "a".repeat(64)
    private val validCommitment = "b".repeat(64)
    private val backend = "pipa-r/pasta"
    private val inlineBytes = byteArrayOf(1, 2, 3, 4)

    private fun createWithInlineBytes(
        version: Int = 1,
        circuitId: String = "circuit-1",
        schemaHashHex: String = validSchemaHash,
        gasScheduleId: String = "gas-1",
        inlineKeyBytes: ByteArray = inlineBytes,
    ): VerifyingKeyRecordDescription = VerifyingKeyRecordDescription.create(
        backend = backend,
        version = version,
        circuitId = circuitId,
        schemaHashHex = schemaHashHex,
        gasScheduleId = gasScheduleId,
        backendTag = VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA,
        inlineKeyBytes = inlineKeyBytes,
    )

    private fun createWithCommitment(
        version: Int = 1,
        circuitId: String = "circuit-1",
        schemaHashHex: String = validSchemaHash,
        gasScheduleId: String = "gas-1",
        commitmentHex: String = validCommitment,
        vkLength: Int = 128,
    ): VerifyingKeyRecordDescription = VerifyingKeyRecordDescription.create(
        backend = backend,
        version = version,
        circuitId = circuitId,
        schemaHashHex = schemaHashHex,
        gasScheduleId = gasScheduleId,
        backendTag = VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA,
        commitmentHex = commitmentHex,
        vkLength = vkLength,
    )

    // --- Constructor validation ---

    @Test
    fun `create throws on negative version`() {
        assertFailsWith<IllegalArgumentException> {
            createWithInlineBytes(version = -1)
        }
    }

    @Test
    fun `create throws on blank circuitId`() {
        assertFailsWith<IllegalArgumentException> {
            createWithInlineBytes(circuitId = "  ")
        }
    }

    @Test
    fun `create throws on padded circuitId`() {
        for (circuitId in listOf(" circuit-1", "circuit-1 ")) {
            assertFailsWith<IllegalArgumentException> {
                createWithInlineBytes(circuitId = circuitId)
            }
        }
    }

    @Test
    fun `create throws on invalid schemaHashHex length`() {
        assertFailsWith<IllegalArgumentException> {
            createWithInlineBytes(schemaHashHex = "abcdef")
        }
    }

    @Test
    fun `create throws on non-hex schemaHashHex`() {
        assertFailsWith<IllegalArgumentException> {
            createWithInlineBytes(schemaHashHex = "z".repeat(64))
        }
    }

    @Test
    fun `create throws on padded schemaHashHex`() {
        for (schemaHashHex in listOf(" $validSchemaHash", "$validSchemaHash ")) {
            assertFailsWith<IllegalArgumentException> {
                createWithInlineBytes(schemaHashHex = schemaHashHex)
            }
        }
    }

    @Test
    fun `create throws on padded commitmentHex`() {
        for (commitmentHex in listOf(" $validCommitment", "$validCommitment ")) {
            assertFailsWith<IllegalArgumentException> {
                createWithCommitment(commitmentHex = commitmentHex)
            }
        }
    }

    @Test
    fun `create throws on blank gasScheduleId`() {
        assertFailsWith<IllegalArgumentException> {
            createWithInlineBytes(gasScheduleId = "  ")
        }
    }

    @Test
    fun `create throws on padded gasScheduleId`() {
        for (gasScheduleId in listOf(" gas-1", "gas-1 ")) {
            assertFailsWith<IllegalArgumentException> {
                createWithInlineBytes(gasScheduleId = gasScheduleId)
            }
        }
    }

    @Test
    fun `create rejects unsupported backend and engine mismatch`() {
        for (invalidBackend in listOf("", " halo2/ipa", "halo2/ipa ", "halo2/bn254", "groth16")) {
            assertFailsWith<IllegalArgumentException>(invalidBackend) {
                VerifyingKeyRecordDescription.create(
                    backend = invalidBackend,
                    version = 1,
                    circuitId = "c",
                    schemaHashHex = validSchemaHash,
                    gasScheduleId = "g",
                    backendTag = VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA,
                    inlineKeyBytes = inlineBytes,
                )
            }
        }
        assertFailsWith<IllegalArgumentException> {
            VerifyingKeyRecordDescription.create(
                backend = "stark/fri",
                version = 1,
                circuitId = "c",
                schemaHashHex = validSchemaHash,
                gasScheduleId = "g",
                backendTag = VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA,
                inlineKeyBytes = inlineBytes,
            )
        }
    }

    @Test
    fun `create throws when vkLength is zero`() {
        assertFailsWith<IllegalArgumentException> {
            VerifyingKeyRecordDescription.create(
                backend = backend,
                version = 1,
                circuitId = "c",
                schemaHashHex = validSchemaHash,
                gasScheduleId = "g",
                backendTag = VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA,
                commitmentHex = validCommitment,
                vkLength = 0,
            )
        }
    }

    @Test
    fun `create throws when vkLength is negative`() {
        assertFailsWith<IllegalArgumentException> {
            VerifyingKeyRecordDescription.create(
                backend = backend,
                version = 1,
                circuitId = "c",
                schemaHashHex = validSchemaHash,
                gasScheduleId = "g",
                backendTag = VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA,
                commitmentHex = validCommitment,
                vkLength = -1,
            )
        }
    }

    @Test
    fun `create throws when maxProofBytes is negative`() {
        assertFailsWith<IllegalArgumentException> {
            VerifyingKeyRecordDescription.create(
                backend = backend,
                version = 1,
                circuitId = "c",
                schemaHashHex = validSchemaHash,
                gasScheduleId = "g",
                backendTag = VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA,
                inlineKeyBytes = inlineBytes,
                maxProofBytes = -1,
            )
        }
    }

    @Test
    fun `create throws when activationHeight is negative`() {
        assertFailsWith<IllegalArgumentException> {
            VerifyingKeyRecordDescription.create(
                backend = backend,
                version = 1,
                circuitId = "c",
                schemaHashHex = validSchemaHash,
                gasScheduleId = "g",
                backendTag = VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA,
                inlineKeyBytes = inlineBytes,
                activationHeight = -1,
            )
        }
    }

    @Test
    fun `create throws when withdrawHeight is negative`() {
        assertFailsWith<IllegalArgumentException> {
            VerifyingKeyRecordDescription.create(
                backend = backend,
                version = 1,
                circuitId = "c",
                schemaHashHex = validSchemaHash,
                gasScheduleId = "g",
                backendTag = VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA,
                inlineKeyBytes = inlineBytes,
                withdrawHeight = -1,
            )
        }
    }

    @Test
    fun `create throws when withdrawHeight less than activationHeight`() {
        assertFailsWith<IllegalStateException> {
            VerifyingKeyRecordDescription.create(
                backend = backend,
                version = 1,
                circuitId = "c",
                schemaHashHex = validSchemaHash,
                gasScheduleId = "g",
                backendTag = VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA,
                inlineKeyBytes = inlineBytes,
                activationHeight = 100,
                withdrawHeight = 50,
            )
        }
    }

    @Test
    fun `create throws on padded optional string fields`() {
        val cases: List<() -> VerifyingKeyRecordDescription> = listOf(
            {
                VerifyingKeyRecordDescription.create(
                    backend = backend,
                    version = 1,
                    circuitId = "c",
                    schemaHashHex = validSchemaHash,
                    gasScheduleId = "g",
                    backendTag = VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA,
                    inlineKeyBytes = inlineBytes,
                    curve = " pallas",
                )
            },
            {
                VerifyingKeyRecordDescription.create(
                    backend = backend,
                    version = 1,
                    circuitId = "c",
                    schemaHashHex = validSchemaHash,
                    gasScheduleId = "g",
                    backendTag = VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA,
                    inlineKeyBytes = inlineBytes,
                    curve = "pallas ",
                )
            },
            {
                VerifyingKeyRecordDescription.create(
                    backend = backend,
                    version = 1,
                    circuitId = "c",
                    schemaHashHex = validSchemaHash,
                    gasScheduleId = "g",
                    backendTag = VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA,
                    inlineKeyBytes = inlineBytes,
                    metadataUriCid = " bafy-metadata",
                )
            },
            {
                VerifyingKeyRecordDescription.create(
                    backend = backend,
                    version = 1,
                    circuitId = "c",
                    schemaHashHex = validSchemaHash,
                    gasScheduleId = "g",
                    backendTag = VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA,
                    inlineKeyBytes = inlineBytes,
                    metadataUriCid = "bafy-metadata ",
                )
            },
            {
                VerifyingKeyRecordDescription.create(
                    backend = backend,
                    version = 1,
                    circuitId = "c",
                    schemaHashHex = validSchemaHash,
                    gasScheduleId = "g",
                    backendTag = VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA,
                    inlineKeyBytes = inlineBytes,
                    vkBytesCid = " bafy-vk",
                )
            },
            {
                VerifyingKeyRecordDescription.create(
                    backend = backend,
                    version = 1,
                    circuitId = "c",
                    schemaHashHex = validSchemaHash,
                    gasScheduleId = "g",
                    backendTag = VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA,
                    inlineKeyBytes = inlineBytes,
                    vkBytesCid = "bafy-vk ",
                )
            },
        )

        for (create in cases) {
            assertFailsWith<IllegalArgumentException> {
                create()
            }
        }
    }

    // --- Cross-field validation ---

    @Test
    fun `create throws when no inline bytes and no commitmentHex`() {
        assertFailsWith<IllegalStateException> {
            VerifyingKeyRecordDescription.create(
                backend = backend,
                version = 1,
                circuitId = "c",
                schemaHashHex = validSchemaHash,
                gasScheduleId = "g",
                backendTag = VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA,
                vkLength = 128,
            )
        }
    }

    @Test
    fun `create throws when no inline bytes and no vkLength`() {
        assertFailsWith<IllegalStateException> {
            VerifyingKeyRecordDescription.create(
                backend = backend,
                version = 1,
                circuitId = "c",
                schemaHashHex = validSchemaHash,
                gasScheduleId = "g",
                backendTag = VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA,
                commitmentHex = validCommitment,
            )
        }
    }

    @Test
    fun `create throws when vkLength does not match inline bytes size`() {
        assertFailsWith<IllegalStateException> {
            VerifyingKeyRecordDescription.create(
                backend = backend,
                version = 1,
                circuitId = "c",
                schemaHashHex = validSchemaHash,
                gasScheduleId = "g",
                backendTag = VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA,
                inlineKeyBytes = inlineBytes,
                vkLength = 999,
            )
        }
    }

    @Test
    fun `create sets vkLength to inline bytes size when not explicitly provided`() {
        val desc = createWithInlineBytes()
        assertEquals(inlineBytes.size, desc.vkLength)
    }

    // --- Defensive copy ---

    @Test
    fun `mutating original array does not affect instance`() {
        val original = byteArrayOf(1, 2, 3)
        val desc = createWithInlineBytes(inlineKeyBytes = original)
        original[0] = 99
        assertEquals(1, desc.inlineKeyBytes!![0])
    }

    @Test
    fun `mutating returned array does not affect instance`() {
        val desc = createWithInlineBytes()
        desc.inlineKeyBytes!![0] = 99
        assertEquals(inlineBytes[0], desc.inlineKeyBytes!![0])
    }

    @Test
    fun `inlineKeyBytes returns null when not provided`() {
        val desc = createWithCommitment()
        assertNull(desc.inlineKeyBytes)
    }

    // --- Equality & hashing ---

    @Test
    fun `equal instances have same hashCode`() {
        val a = createWithCommitment()
        val b = createWithCommitment()
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun `different instances are not equal`() {
        val a = createWithCommitment(version = 1)
        val b = createWithCommitment(version = 2)
        assertNotEquals(a, b)
    }

    @Test
    fun `instance does not equal null`() {
        val desc = createWithCommitment()
        assertNotEquals<Any?>(desc, null)
    }

    // --- Required engine and factory defaults ---

    @Test
    fun `explicit backendTag is retained`() {
        val desc = createWithInlineBytes()
        assertEquals(VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA, desc.backendTag)
    }

    @Test
    fun `default curve is unknown`() {
        val desc = createWithInlineBytes()
        assertEquals("unknown", desc.curve)
    }

    @Test
    fun `default status is ACTIVE`() {
        val desc = createWithInlineBytes()
        assertEquals(VerifyingKeyStatus.ACTIVE, desc.status)
    }

    // --- toArguments ---

    @Test
    fun `toArguments includes required fields`() {
        val desc = createWithCommitment()
        val args = desc.toArguments(backend)
        assertEquals("1", args["record.version"])
        assertEquals("circuit-1", args["record.circuit_id"])
        assertEquals(VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA.noritoValue, args["record.backend_tag"])
        assertEquals("gas-1", args["record.gas_schedule_id"])
        assertEquals(VerifyingKeyStatus.ACTIVE.wireName, args["record.status"])
    }

    @Test
    fun `toArguments throws when inline key commitment was computed with different backend`() {
        val desc = createWithInlineBytes()

        assertFailsWith<IllegalArgumentException> {
            desc.toArguments("other-backend")
        }
    }

    @Test
    fun `toArguments omits null optional fields`() {
        val desc = createWithCommitment()
        val args = desc.toArguments(backend)
        assertNull(args["record.metadata_uri_cid"])
        assertNull(args["record.vk_bytes_cid"])
        assertNull(args["record.activation_height"])
        assertNull(args["record.withdraw_height"])
    }

    @Test
    fun `toArguments includes optional fields when set`() {
        val desc = VerifyingKeyRecordDescription.create(
            backend = backend,
            version = 1,
            circuitId = "c",
            schemaHashHex = validSchemaHash,
            gasScheduleId = "g",
            backendTag = VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA,
            commitmentHex = validCommitment,
            vkLength = 128,
            metadataUriCid = "meta-cid",
            vkBytesCid = "vk-cid",
            activationHeight = 10,
            withdrawHeight = 20,
        )
        val args = desc.toArguments(backend)
        assertEquals("meta-cid", args["record.metadata_uri_cid"])
        assertEquals("vk-cid", args["record.vk_bytes_cid"])
        assertEquals("10", args["record.activation_height"])
        assertEquals("20", args["record.withdraw_height"])
    }
}
