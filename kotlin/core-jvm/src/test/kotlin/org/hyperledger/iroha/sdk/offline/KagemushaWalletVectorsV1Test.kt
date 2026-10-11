// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.Signature
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.hyperledger.iroha.sdk.norito.CRC64
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.norito.SchemaHash
import org.hyperledger.iroha.sdk.norito.Varint
import org.junit.jupiter.api.Test

/**
 * Consumes the Rust-written `fixtures/kagemusha/wallet_v1_vectors.json` (wire record
 * `specs/kagemusha_wallet_wire_v1.md` section 5): recomputes every SHA-256 role digest; checks
 * every signature verdict with the raw low-S check before JCA; validates every envelope header,
 * scheme field and per-kind bound against the Kotlin constants and round-trips the strict `kgm1:`
 * text; re-encodes every object frame byte-identically; and re-derives the σ-field element lists
 * of the statements, state, chains, map leaves, `credit_id`, the `P_bytes` packing of both
 * `proof_digest` domains and the Payment digest, and the blacklist, quota-window, sparse-tree and
 * verifying-key allowlist vectors from their transcripts and frames.
 *
 * Poseidon values are computed by the native Rust core, so this consumer checks them only as
 * canonical opaque σ-field values and follows them across the objects that carry them.
 * Typed decoding of message bodies is TODO(G4).
 */
class KagemushaWalletVectorsV1Test {
    @Test fun `bounds prefixes and Norito header facts match the fixture`() {
        val bounds = vectors.obj("bounds")
        // A bound added to or removed from the fixture must be mirrored here first.
        assertEquals(
            setOf(
                "certificate_set_max",
                "credential_max_bytes",
                "credit_opening_siblings_max",
                "fold_record_max_bytes",
                "lineage_max_bytes",
                "message_max_bytes",
                "message_text_max_bytes",
                "payment_fixed_bytes",
                "payment_proof_budget_bytes",
                "proof_caps",
                "session_max_bytes",
                "session_text_max_bytes",
                "text_prefix",
                "verifying_key_allowlist_max_bytes",
                "verifying_key_entries_max",
                "version",
            ),
            bounds.keys,
        )
        assertEquals(KagemushaWalletWireV1.VERSION, bounds.int("version"))
        assertEquals(KagemushaWalletWireV1.TEXT_PREFIX, bounds.text("text_prefix"))
        assertEquals(KagemushaWalletWireV1.SESSION_MAX_BYTES, bounds.int("session_max_bytes"))
        assertEquals(KagemushaWalletWireV1.MESSAGE_MAX_BYTES, bounds.int("message_max_bytes"))
        assertEquals(KagemushaWalletWireV1.SESSION_TEXT_MAX_BYTES, bounds.int("session_text_max_bytes"))
        assertEquals(KagemushaWalletWireV1.MESSAGE_TEXT_MAX_BYTES, bounds.int("message_text_max_bytes"))
        assertEquals(KagemushaWalletMessageKindV1.LINEAGE.maximumFrameBytes, bounds.int("lineage_max_bytes"))
        // σ and Ω caps are the exact lengths of the frozen verifying-key allowlist (owner answer
        // Q6), jointly within the Payment budget (R9); until the artifacts freeze the carrying
        // frame is their only bound, which is what the structural carrier check enforces.
        assertTrue(bounds.text("proof_caps").contains("payment_proof_budget_bytes"), bounds.text("proof_caps"))
        assertEquals(KagemushaWalletWireV1.PAYMENT_FIXED_BYTES, bounds.int("payment_fixed_bytes"))
        assertEquals(KagemushaWalletWireV1.PAYMENT_PROOF_BUDGET_BYTES, bounds.int("payment_proof_budget_bytes"))
        assertEquals(
            KagemushaWalletWireV1.MESSAGE_MAX_BYTES,
            KagemushaWalletWireV1.PAYMENT_FIXED_BYTES + KagemushaWalletWireV1.PAYMENT_PROOF_BUDGET_BYTES,
        )
        assertEquals(KagemushaWalletWireV1.VERIFYING_KEY_ENTRIES_MAX, bounds.int("verifying_key_entries_max"))
        assertEquals(
            KagemushaWalletWireV1.VERIFYING_KEY_ALLOWLIST_MAX_BYTES,
            bounds.int("verifying_key_allowlist_max_bytes"),
        )
        assertEquals(KagemushaWalletWireV1.CREDIT_OPENING_SIBLINGS_MAX, bounds.int("credit_opening_siblings_max"))
        // The standalone credential, fold-record and allowlist caps are the caps of their frames.
        val frameCaps = vectors.array("frames").map { it.jsonObject }
            .associate { it.text("type") to it.int("max_bytes") }
        assertEquals(frameCaps.getValue("KagemushaWalletCredentialV1"), bounds.int("credential_max_bytes"))
        assertEquals(frameCaps.getValue("KagemushaWalletFoldRecordV1"), bounds.int("fold_record_max_bytes"))
        assertEquals(
            frameCaps.getValue("KagemushaWalletVerifyingKeyAllowlistV1"),
            bounds.int("verifying_key_allowlist_max_bytes"),
        )
        assertEquals(KagemushaWalletWireV1.CERTIFICATE_SET_MAX, bounds.int("certificate_set_max"))
        assertEquals(KagemushaWalletWireV1.DIGEST_PREFIX, vectors.text("domain_prefix"))
        assertContentEquals(
            KagemushaWalletWireV1.DIGEST_PREFIX.toByteArray(Charsets.US_ASCII),
            vectors.hex("domain_prefix_hex"),
        )

        val header = vectors.obj("norito_header")
        assertContentEquals(NoritoHeader.MAGIC, header.hex("magic_hex"))
        assertEquals(NoritoHeader.HEADER_LENGTH, header.int("header_bytes"))
        assertEquals(NoritoHeader.MAJOR_VERSION, header.int("major"))
        assertEquals(NoritoHeader.MINOR_VERSION, header.int("minor"))
        assertEquals(NoritoHeader.COMPRESSION_NONE, header.int("compression"))
        assertEquals(8, KagemushaWalletWireV1.ENVELOPE_PADDING_BYTES)
        assertEquals(NoritoHeader.COMPACT_LEN, KagemushaWalletWireV1.ENVELOPE_FLAGS)
    }

    @Test fun `text maxima are the exact kgm1 length of the frame bounds`() {
        assertEquals(5, KagemushaWalletWireV1.textBytesForFrame(0))
        assertEquals(7, KagemushaWalletWireV1.textBytesForFrame(1))
        assertEquals(8, KagemushaWalletWireV1.textBytesForFrame(2))
        assertEquals(9, KagemushaWalletWireV1.textBytesForFrame(3))
        assertEquals(
            KagemushaWalletWireV1.SESSION_TEXT_MAX_BYTES,
            KagemushaWalletWireV1.textBytesForFrame(KagemushaWalletWireV1.SESSION_MAX_BYTES),
        )
        assertEquals(
            KagemushaWalletWireV1.MESSAGE_TEXT_MAX_BYTES,
            KagemushaWalletWireV1.textBytesForFrame(KagemushaWalletWireV1.MESSAGE_MAX_BYTES),
        )
        for (length in listOf(1, 2, 3, 4, 47, 48, 2_048, 9_999, 10_000)) {
            assertEquals(
                KagemushaWalletWireV1.textBytesForFrame(length),
                KagemushaWalletWireV1.encodeText(ByteArray(length) { it.toByte() }).length,
            )
        }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletWireV1.textBytesForFrame(-1) }
        assertFailsWith<IllegalArgumentException> {
            KagemushaWalletWireV1.textBytesForFrame(KagemushaWalletWireV1.MESSAGE_MAX_BYTES + 1)
        }
    }

    @Test fun `message kinds and tags match the Rust enum tags`() {
        val tags = vectors.obj("enum_tags").array("KagemushaWalletMessageV1").map { it.jsonObject }
        assertEquals(KagemushaWalletMessageKindV1.entries.size, tags.size)
        for (entry in tags) {
            val kind = assertNotNull(KagemushaWalletMessageKindV1.fromLabel(entry.text("variant")))
            assertEquals(entry.int("tag"), kind.wireTag)
            assertEquals(kind, KagemushaWalletMessageKindV1.fromWireTag(entry.int("tag")))
        }
        assertEquals(KagemushaWalletMessageKindV1.LINEAGE, KagemushaWalletMessageKindV1.fromWireTag(7))
        assertNull(KagemushaWalletMessageKindV1.fromWireTag(0))
        assertNull(KagemushaWalletMessageKindV1.fromWireTag(8))
        assertNull(KagemushaWalletMessageKindV1.fromLabel("offer"))
        for (kind in KagemushaWalletMessageKindV1.entries) {
            assertEquals(KagemushaWalletWireV1.textBytesForFrame(kind.maximumFrameBytes), kind.maximumTextBytes)
        }
    }

    @Test fun `every digest vector recomputes and every role is covered`() {
        val seen = mutableSetOf<KagemushaWalletDigestRoleV1>()
        for (vector in vectors.array("digests").map { it.jsonObject }) {
            val role = assertNotNull(KagemushaWalletDigestRoleV1.fromLabel(vector.text("role")))
            seen += role
            val body = vector.hex("body_hex")
            val preimage = KagemushaWalletWireV1.preimage(role, body)
            assertContentEquals(vector.hex("preimage_hex"), preimage, vector.text("object"))
            assertContentEquals(vector.hex("digest_hex"), KagemushaWalletWireV1.digest(role, body), vector.text("object"))
            assertContentEquals(sha256(preimage), KagemushaWalletWireV1.digest(role, body))
        }
        assertEquals(KagemushaWalletDigestRoleV1.entries.toSet(), seen)
        // Exactly one vector per role, in the Rust declaration order.
        assertEquals(
            KagemushaWalletDigestRoleV1.entries.map { it.label },
            vectors.array("digests").map { it.jsonObject.text("role") },
        )
        // Superseded roles are gone, not aliased: the pre-split roles, and the SHA-256 roles that
        // owner answers Q1, Q2 and Q9 replaced with Poseidon values (credit_id, both proof_digest
        // domains, the Payment digest, and the blacklist and quota-window trees).
        val superseded = listOf(
            "dependencies",
            "credit-status-statement",
            "credit",
            "proof",
            "step-proof",
            "payment",
            "blacklist-leaf",
            "blacklist-node",
            "quota-window",
            "quota-node",
        )
        for (label in superseded) {
            assertNull(KagemushaWalletDigestRoleV1.fromLabel(label), label)
        }
        assertEquals(55, KagemushaWalletDigestRoleV1.entries.size)
        assertEquals(
            KagemushaWalletDigestRoleV1.entries.size,
            KagemushaWalletDigestRoleV1.entries.map { it.label }.toSet().size,
        )
        assertNull(KagemushaWalletDigestRoleV1.fromLabel("policy-chunk"))
        assertNull(KagemushaWalletDigestRoleV1.fromLabel(""))
    }

    @Test fun `proof digests pack the exact stand-in Ω and σ bytes in their two Poseidon domains`() {
        val lineage = digestVector("lineage")
        assertTrue(lineage.bool("stand_in_proof"), lineage.text("object"))
        val digests = poseidon.array("proof_digests").map { it.jsonObject }
        assertEquals(2, digests.size)
        val (send, receive) = digests
        assertEquals("kgwprf_1", send.text("domain"))
        assertEquals("kgwstep1", receive.text("domain"))

        // Send, Unload and Retiring: `P_bytes(kgwprf_1, LE32 len(Ω) || Ω || LE32 len(σ) || σ)`,
        // Ω being Ω(pred).
        val (omega, sigma) = le32Parts(send.hex("body_hex")).also { assertEquals(2, it.size) }
        assertContentEquals(lineage.hex("body_hex"), omega)
        assertSigmaStandIn(sigma)
        // Every other operation, the σ-only domain: `P_bytes(kgwstep1, LE32 len(σ) || σ)`.
        assertSigmaStandIn(le32Parts(receive.hex("body_hex")).single())
        for (vector in digests) {
            val label = vector.text("object")
            assertEquals(packedElements(vector.hex("body_hex")).size, vector.int("elements"), label)
            assertPoseidonValue(vector.hex("digest_hex"), label)
        }
        val sendProofDigest = send.hex("digest_hex")
        val receiveProofDigest = receive.hex("digest_hex")

        // Each receipt body binds its step's proof_digest; the Send package digest binds it too.
        assertContentEquals(sendProofDigest, receiptField(receiptBody("Send receipt"), RECEIPT_PROOF_DIGEST))
        assertContentEquals(
            receiveProofDigest,
            receiptField(receiptBody("Receive receipt binding the Payment digest"), RECEIPT_PROOF_DIGEST),
        )
        val packageBody = digestVector("package").hex("body_hex")
        assertEquals(96, packageBody.size)
        assertContentEquals(digestVector("statement").hex("digest_hex"), packageBody.copyOfRange(0, 32))
        assertContentEquals(sendProofDigest, packageBody.copyOfRange(32, 64))
        assertContentEquals(digestVector("receipt").hex("digest_hex"), packageBody.copyOfRange(64, 96))
        // The receipt-free Receive output descriptor binds its proof and Payment digests.
        val output = digestVector("output").hex("body_hex")
        assertEquals(97, output.size)
        assertContentEquals(receiveProofDigest, output.copyOfRange(33, 65))
        assertContentEquals(poseidon.obj("payment_digest").hex("digest_hex"), output.copyOfRange(65, 97))

        // Ω bytes are the 320-byte public transcript followed by the transport proof.
        assertTrue(omega.size > LINEAGE_PUBLIC_BYTES)
        val transport = omega.copyOfRange(LINEAGE_PUBLIC_BYTES, omega.size)
        assertTrue(transport.indices.all { index -> unsigned(transport[index]) == (index + 7) % 251 })
        val exposed = Transcript(omega.copyOf(LINEAGE_PUBLIC_BYTES))
        assertEquals(KagemushaWalletWireV1.VERSION.toLong(), exposed.unsigned(2))
        assertContentEquals(digestVector("scheme").hex("digest_hex"), exposed.take(32))
        assertContentEquals(digestVector("relation").hex("digest_hex"), exposed.take(32))
        val head = exposed.take(32)
        assertCanonicalField(head, nonzero = true)
        assertContentEquals(digestVector("wallet-id").hex("digest_hex"), exposed.take(32))
        assertContentEquals(digestVector("credential").hex("digest_hex"), exposed.take(32))
        assertContentEquals(key("payer_payment"), exposed.take(65))
        assertTrue(exposed.unsigned(1) in 1L..2L, "lifecycle Active or Retiring")
        exposed.take(8 + 4) // LE64 policy_epoch, LE32 enabled_controls
        val burned = exposed.take(16)
        val standIns = vectors.obj("stand_ins")
        val pendingRoot = exposed.take(32)
        assertContentEquals(standIns.hex("lineage_pending_outgoing_root_hex"), pendingRoot)
        assertContentEquals(standIns.hex("credit_digest_root_hex"), exposed.take(32))
        exposed.finish()

        // The Send statement consumes this Ω(pred): its predecessor is Ω's head and its lineage
        // fields are Ω's burned total and pending-outgoing root (consumer checks, section 3.2).
        val statement = items(vectors.obj("field_encodings").obj("send_statement"), "items")
        assertElements(listOf(integerElement(burned), pendingRoot, head), statement.subList(13, 16), "Ω(pred) lineage")
    }

    @Test fun `the Lineage envelope and the Payment carry the same Ω bytes`() {
        val lineage = digestVector("lineage")
        // Lineage message `{version, lineage: {public, proof}}`.
        val message = recordFields(envelopeMessage(envelope("Lineage")))
        assertEquals(2, message.size)
        val fromLineage = omegaBytes(message[1])
        assertContentEquals(lineage.hex("body_hex"), fromLineage)
        assertContentEquals(
            lineage.hex("digest_hex"),
            KagemushaWalletWireV1.digest(KagemushaWalletDigestRoleV1.LINEAGE, fromLineage),
        )

        // Payment `{version, request, key, credential digest, send}`; Send package `{version,
        // statement, lineage slot, step proof, receipt}` with the slot Present (tag 1) `{lineage}`.
        val payment = recordFields(envelopeMessage(envelope("Payment")))
        assertEquals(5, payment.size)
        val send = recordFields(payment[4])
        assertEquals(5, send.size)
        val slot = send[2]
        assertEquals(1, readIntLe(slot, 0), "Send package lineage slot is Present")
        val present = recordFields(slot.copyOfRange(4, slot.size)).single()
        assertContentEquals(fromLineage, omegaBytes(present))
        // The Payment's carried payer key and credential digest are Ω's.
        val exposed = recordFields(recordFields(present)[0])
        assertContentEquals(exposed[6], payment[2])
        assertContentEquals(exposed[5], payment[3])
        // A Receive package carries no Ω(pred): its slot is None (tag 0) with no fields.
        val receive = recordFields(objectVector("KagemushaWalletPackageV1", "Receive").let { frame ->
            NoritoHeader.decode(frame, null).payload
        })
        assertContentEquals(byteArrayOf(0, 0, 0, 0), receive[2])
    }

    @Test fun `signed object digests recompute from the signature vectors`() {
        val digests = vectors.array("digests").map { it.jsonObject }
        var matched = 0
        for (vector in vectors.array("signatures").map { it.jsonObject }) {
            val bodyRole = vector.text("role")
            if (!bodyRole.endsWith("-body")) continue
            // Offer, session control and ledger control bodies have no separate object digest role.
            val role = KagemushaWalletDigestRoleV1.fromLabel(bodyRole.removeSuffix("-body")) ?: continue
            val expected = digests.firstOrNull {
                it.text("role") == role.label && it.text("object") == vector.text("object")
            } ?: continue
            val digest = KagemushaWalletWireV1.signedObjectDigest(
                role,
                vector.hex("e_hex"),
                vector.hex("signature_hex"),
            )
            assertContentEquals(expected.hex("digest_hex"), digest, vector.text("object"))
            matched += 1
        }
        assertTrue(matched >= 10, "only $matched signed-object digest vectors matched")

        val first = vectors.array("signatures").first().jsonObject
        assertFailsWith<IllegalArgumentException> {
            KagemushaWalletWireV1.signedObjectDigest(
                KagemushaWalletDigestRoleV1.CERTIFICATE,
                first.hex("e_hex").copyOf(31),
                first.hex("signature_hex"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            KagemushaWalletWireV1.signedObjectDigest(
                KagemushaWalletDigestRoleV1.CERTIFICATE,
                first.hex("e_hex"),
                first.obj("high_s_twin").hex("signature_hex"),
            )
        }
    }

    @Test fun `every signature vector has its codec and verify verdicts`() {
        val signatures = vectors.array("signatures").map { it.jsonObject }
        assertTrue(signatures.isNotEmpty())
        for (vector in signatures) {
            val label = vector.text("object")
            val role = assertNotNull(KagemushaWalletDigestRoleV1.fromLabel(vector.text("role")))
            val preimage = vector.hex("preimage_hex")
            val bodyOffset = KagemushaWalletWireV1.preimage(role, ByteArray(0)).size
            val body = preimage.copyOfRange(bodyOffset, preimage.size)
            assertContentEquals(preimage, KagemushaWalletWireV1.preimage(role, body), label)
            assertContentEquals(vector.hex("e_hex"), KagemushaWalletWireV1.digest(role, body), label)

            val key = vector.hex("public_key_hex")
            val signature = vector.hex("signature_hex")
            assertTrue(vector.bool("codec_ok") && vector.bool("verify_ok"), label)
            assertVerdicts(label, key, preimage, signature, vector.bool("codec_ok"), vector.bool("verify_ok"))

            val twin = vector.obj("high_s_twin")
            val twinRaw = twin.hex("signature_hex")
            assertFalse(twin.bool("codec_ok"), label)
            assertTrue(twin.bool("verify_ok"), label)
            assertVerdicts("$label high-S twin", key, preimage, twinRaw, twin.bool("codec_ok"), twin.bool("verify_ok"))
            assertContentEquals(signature.copyOfRange(0, 32), twinRaw.copyOfRange(0, 32))
            assertEquals(
                P256_ORDER.subtract(BigInteger(1, signature.copyOfRange(32, 64))),
                BigInteger(1, twinRaw.copyOfRange(32, 64)),
            )
            val twinDer = twin.hex("der_hex")
            assertTrue(jcaVerifyDer(key, preimage, twinDer), "JCA accepts the high-S twin of $label")
            val frozen = KagemushaP256Codec.rawLowSFromStrictDer(twinDer)
            assertContentEquals(twin.hex("frozen_signature_hex"), frozen, label)
            assertContentEquals(signature, frozen, label)
            assertTrue(KagemushaP256Codec.verifyRawLowS(key, preimage, frozen), label)
        }
    }

    @Test fun `low-S boundary scalars have their verdicts`() {
        val boundaries = vectors.obj("signature_boundaries")
        val order = BigInteger(boundaries.text("order_hex"), 16)
        assertEquals(P256_ORDER, order)
        assertEquals(order.shiftRight(1), BigInteger(boundaries.text("half_order_hex"), 16))
        assertEquals(order.shiftRight(1).add(BigInteger.ONE), BigInteger(boundaries.text("half_order_plus_one_hex"), 16))

        val role = assertNotNull(KagemushaWalletDigestRoleV1.fromLabel(boundaries.text("role")))
        val body = boundaries.hex("body_hex")
        val preimage = KagemushaWalletWireV1.preimage(role, body)
        assertContentEquals(boundaries.hex("preimage_hex"), preimage)
        assertContentEquals(boundaries.hex("e_hex"), KagemushaWalletWireV1.digest(role, body))

        // The documented derivation: r = x(kG) mod n, s = floor(n/2), d = (s*k - e) * r^-1 mod n.
        val curve = CustomNamedCurves.getByName("secp256r1")
        val k = BigInteger(boundaries.text("k_hex"), 16)
        val r = curve.g.multiply(k).normalize().affineXCoord.toBigInteger().mod(order)
        assertEquals(BigInteger(boundaries.text("r_hex"), 16), r)
        val e = BigInteger(1, sha256(preimage)).mod(order)
        val d = order.shiftRight(1).multiply(k).subtract(e).multiply(r.modInverse(order)).mod(order)
        assertEquals(BigInteger(boundaries.text("d_hex"), 16), d)
        val key = boundaries.hex("public_key_hex")
        assertContentEquals(curve.g.multiply(d).normalize().getEncoded(false), key)

        val cases = boundaries.array("cases").map { it.jsonObject }
        assertEquals(
            setOf("s_half_order", "s_half_order_plus_one_high_s_twin", "r_zero", "s_zero", "r_order", "s_order"),
            cases.map { it.text("name") }.toSet(),
        )
        for (case in cases) {
            assertVerdicts(
                case.text("name"),
                key,
                preimage,
                case.hex("signature_hex"),
                case.bool("codec_ok"),
                case.bool("verify_ok"),
            )
        }
        val accepted = cases.single { it.text("name") == "s_half_order" }.hex("signature_hex")
        assertTrue(KagemushaP256Codec.verifyRawLowS(key, preimage, accepted))
    }

    @Test fun `fixture public keys convert to JCA keys and malformed keys are rejected`() {
        val curve = CustomNamedCurves.getByName("secp256r1")
        val keys = vectors.array("keys").map { it.jsonObject }
        assertTrue(keys.isNotEmpty())
        for (entry in keys) {
            val sec1 = entry.hex("public_key_hex")
            val scalar = BigInteger(entry.text("scalar_hex"), 16)
            assertContentEquals(curve.g.multiply(scalar).normalize().getEncoded(false), sec1, entry.text("name"))
            val key = KagemushaP256Codec.publicKeyFromSec1(sec1)
            assertEquals(BigInteger(1, sec1.copyOfRange(1, 33)), key.w.affineX)
            assertEquals(BigInteger(1, sec1.copyOfRange(33, 65)), key.w.affineY)
            assertEquals(P256_ORDER, key.params.order)
            assertEquals(256, key.params.curve.field.fieldSize)
        }
        val valid = keys.first().hex("public_key_hex")
        val offCurve = valid.copyOf().also { it[64] = (it[64].toInt() xor 1).toByte() }
        val compressedPrefix = valid.copyOf().also { it[0] = 0x02 }
        for (bad in listOf(offCurve, compressedPrefix, valid.copyOf(64), valid + byteArrayOf(0))) {
            assertFailsWith<IllegalArgumentException> { KagemushaP256Codec.publicKeyFromSec1(bad) }
        }
    }

    @Test fun `verifyRawLowS rejects wrong preimages keys and malformed inputs without mutation`() {
        val signatures = vectors.array("signatures").map { it.jsonObject }
        val vector = signatures.first()
        val key = vector.hex("public_key_hex")
        val preimage = vector.hex("preimage_hex")
        val signature = vector.hex("signature_hex")
        val keyCopy = key.copyOf()
        val preimageCopy = preimage.copyOf()
        val signatureCopy = signature.copyOf()
        assertTrue(KagemushaP256Codec.verifyRawLowS(key, preimage, signature))
        assertContentEquals(keyCopy, key)
        assertContentEquals(preimageCopy, preimage)
        assertContentEquals(signatureCopy, signature)

        val otherKey = signatures.map { it.hex("public_key_hex") }.first { !it.contentEquals(key) }
        assertFalse(KagemushaP256Codec.verifyRawLowS(otherKey, preimage, signature))
        assertFalse(KagemushaP256Codec.verifyRawLowS(key, preimage + byteArrayOf(0), signature))
        assertFalse(KagemushaP256Codec.verifyRawLowS(key, preimage, signature.copyOf(63)))
        assertFalse(KagemushaP256Codec.verifyRawLowS(key, preimage, signature + byteArrayOf(0)))
        val flipped = signature.copyOf().also { it[10] = (it[10].toInt() xor 1).toByte() }
        assertFalse(KagemushaP256Codec.verifyRawLowS(key, preimage, flipped))
        val offCurve = key.copyOf().also { it[64] = (it[64].toInt() xor 1).toByte() }
        assertFalse(KagemushaP256Codec.verifyRawLowS(offCurve, preimage, signature))
        assertFalse(KagemushaP256Codec.verifyRawLowS(key.copyOf(33), preimage, signature))
    }

    @Test fun `frame schema hashes recompute from frame names`() {
        val frames = vectors.array("frames").map { it.jsonObject }
        assertTrue(frames.isNotEmpty())
        for (frame in frames) {
            val name = frame.text("frame_name")
            assertTrue(name.endsWith("::" + frame.text("type")), name)
            assertContentEquals(frame.hex("frame_hash_hex"), SchemaHash.hash16(name), name)
        }
        val envelope = frames.single { it.text("type") == "KagemushaWalletEnvelopeV1" }
        assertEquals(KagemushaWalletWireV1.ENVELOPE_FRAME_NAME, envelope.text("frame_name"))
        assertEquals(KagemushaWalletWireV1.MESSAGE_MAX_BYTES, envelope.int("max_bytes"))
        assertContentEquals(KagemushaWalletWireV1.envelopeSchemaHash(), envelope.hex("frame_hash_hex"))
    }

    @Test fun `every envelope vector header and bound validate against the Kotlin constants`() {
        val envelopes = vectors.array("envelopes").map { it.jsonObject }
        val schemeId = vectors.array("digests").map { it.jsonObject }
            .single { it.text("role") == "scheme" }.hex("digest_hex")
        val kinds = mutableSetOf<KagemushaWalletMessageKindV1>()
        for (vector in envelopes) {
            val label = vector.text("variant")
            val frame = vector.hex("canonical_hex")
            assertEquals(KagemushaWalletWireV1.ENVELOPE_FRAME_NAME, vector.text("frame_name"), label)
            val schemaHash = vector.hex("schema_hash_hex")
            assertContentEquals(SchemaHash.hash16(vector.text("frame_name")), schemaHash, label)
            assertContentEquals(KagemushaWalletWireV1.envelopeSchemaHash(), schemaHash, label)
            assertContentEquals(schemeId, vector.hex("scheme_id_hex"), label)

            val envelope = KagemushaWalletWireV1.inspectEnvelope(frame)
            val expectedKind = assertNotNull(KagemushaWalletMessageKindV1.fromLabel(vector.text("kind")), label)
            kinds += expectedKind
            assertEquals(expectedKind, envelope.kind, label)
            // The scheme checked at decode: the body's (Offer, Request), the carried Request's
            // (Payment), Ω's (Lineage) or the message's own field (wire record section 3.4).
            assertContentEquals(schemeId, fieldAt(envelopeMessage(frame), schemePath(expectedKind)), label)
            assertEquals(vector.int("tag"), envelope.kind.wireTag, label)
            assertEquals(vector.int("bound"), envelope.kind.maximumFrameBytes, label)
            assertEquals(vector.int("text_bound"), envelope.kind.maximumTextBytes, label)
            assertEquals(vector.int("flags"), envelope.flags, label)
            assertEquals(vector.int("padding_len"), envelope.paddingLength, label)
            assertEquals(vector.int("payload_len"), envelope.payloadLength, label)
            assertEquals(vector.int("frame_len"), envelope.frameLength, label)
            assertEquals(frame.size, envelope.frameLength, label)
            assertEquals(java.lang.Long.parseUnsignedLong(vector.text("crc64_hex"), 16), envelope.crc64, label)
            assertEquals(CRC64.compute(frame.copyOfRange(48, frame.size)), envelope.crc64, label)
            assertContentEquals(schemaHash, envelope.schemaHash, label)
            assertContentEquals(frame, envelope.frame(), label)
            assertTrue(frame.size <= envelope.kind.maximumFrameBytes, label)

            val text = vector.text("text")
            assertTrue(text.length <= envelope.kind.maximumTextBytes, label)
            assertEquals(KagemushaWalletWireV1.textBytesForFrame(frame.size), text.length, label)
            assertEquals(text, KagemushaWalletWireV1.encodeText(frame), label)
            assertEquals(text, envelope.toText(), label)
            assertContentEquals(frame, KagemushaWalletWireV1.decodeText(text), label)
            val decoded = KagemushaWalletWireV1.decodeEnvelopeText(text)
            assertEquals(expectedKind, decoded.kind, label)
            assertContentEquals(frame, decoded.frame(), label)
        }
        assertEquals(KagemushaWalletMessageKindV1.entries.toSet(), kinds)
    }

    @Test fun `vector Request Payment and Credited envelopes are structurally bound`() {
        val frames = vectors.array("envelopes").associate {
            it.jsonObject.text("variant") to it.jsonObject.hex("canonical_hex")
        }
        val request = frames.getValue("Request")
        val payment = frames.getValue("Payment")
        val receive = frames.getValue("Credited::Receive")
        val status = frames.getValue("Credited::Status")
        KagemushaWalletWireV1.requireExchangeBinding(request, payment)
        KagemushaWalletWireV1.requireExchangeBinding(request, payment, receive)
        KagemushaWalletWireV1.requireExchangeBinding(request, payment, status)
        // The compact Payment carries the Request's signed body, not the whole Request message.
        val signedRequest = recordFields(recordFields(envelopeMessage(payment))[1])
        val requestMessage = recordFields(envelopeMessage(request))
        assertContentEquals(requestMessage[0], signedRequest[0])
        assertContentEquals(requestMessage[4], signedRequest[1])

        val rejected = listOf(
            "kinds swapped" to { KagemushaWalletWireV1.requireExchangeBinding(payment, request) },
            "Credited as Payment" to { KagemushaWalletWireV1.requireExchangeBinding(request, receive) },
            "Offer as Credited" to {
                KagemushaWalletWireV1.requireExchangeBinding(request, payment, frames.getValue("Offer"))
            },
            "Lineage as Credited" to {
                KagemushaWalletWireV1.requireExchangeBinding(request, payment, frames.getValue("Lineage"))
            },
            "truncated Credited" to {
                KagemushaWalletWireV1.requireExchangeBinding(request, payment, receive.copyOf(receive.size - 1))
            },
            // Each mutation keeps the envelope structurally valid (its CRC64 is refreshed).
            "Request with another body" to {
                KagemushaWalletWireV1.requireExchangeBinding(withFlippedField(request, 0), payment)
            },
            "Request with another signature" to {
                KagemushaWalletWireV1.requireExchangeBinding(withFlippedField(request, 4), payment)
            },
            "Payment with another signed Request" to {
                KagemushaWalletWireV1.requireExchangeBinding(request, withFlippedField(payment, 1))
            },
            "Credited under another scheme" to {
                KagemushaWalletWireV1.requireExchangeBinding(request, payment, withFlippedField(receive, 1))
            },
            "Credited::Status under another scheme" to {
                KagemushaWalletWireV1.requireExchangeBinding(request, payment, withFlippedField(status, 1))
            },
        )
        for ((name, attempt) in rejected) {
            assertFailsWith<IllegalArgumentException>(name) { attempt() }
        }
        // The receiver credential, fee schedule and certificates are bound only by digest in the
        // Request body, so changing them in the Request message leaves the structural binding.
        KagemushaWalletWireV1.requireExchangeBinding(withFlippedField(request, 1), payment, receive)
        // Evidence bytes are checked by the wallet's typed decoder (TODO(G4)), not by carriers.
        KagemushaWalletWireV1.requireExchangeBinding(request, payment, withFlippedField(receive, 2))
    }

    @Test fun `every kind accepts its bound and rejects bound plus one`() {
        for (kind in KagemushaWalletMessageKindV1.entries) {
            val atBound = envelopeFrame(kind.wireTag, kind.maximumFrameBytes)
            assertEquals(kind.maximumFrameBytes, atBound.size)
            val accepted = KagemushaWalletWireV1.inspectEnvelope(atBound)
            assertEquals(kind, accepted.kind)
            val text = accepted.toText()
            assertEquals(kind.maximumTextBytes, text.length)
            assertContentEquals(atBound, KagemushaWalletWireV1.decodeEnvelopeText(text).frame())

            val overBound = envelopeFrame(kind.wireTag, kind.maximumFrameBytes + 1)
            assertEquals(kind.maximumFrameBytes + 1, overBound.size)
            val frameError = assertFailsWith<IllegalArgumentException> {
                KagemushaWalletWireV1.inspectEnvelope(overBound)
            }
            assertTrue(frameError.message.orEmpty().contains("exceeds ${kind.maximumFrameBytes} bytes"), frameError.message)
            val overText = KagemushaWalletWireV1.TEXT_PREFIX + base64Url(overBound)
            assertEquals(kind.maximumTextBytes + 1, overText.length)
            assertFailsWith<IllegalArgumentException> { KagemushaWalletWireV1.decodeEnvelopeText(overText) }
        }
        // The session bound is enforced after the header parse, by the kind the payload tag selects.
        val sessionError = assertFailsWith<IllegalArgumentException> {
            KagemushaWalletWireV1.inspectEnvelope(envelopeFrame(1, KagemushaWalletWireV1.SESSION_MAX_BYTES + 1))
        }
        assertTrue(sessionError.message.orEmpty().contains("Offer"), sessionError.message)
        assertEquals(
            KagemushaWalletMessageKindV1.REQUEST,
            KagemushaWalletWireV1.inspectEnvelope(envelopeFrame(2, KagemushaWalletWireV1.SESSION_MAX_BYTES + 1)).kind,
        )
        assertFailsWith<IllegalArgumentException> {
            KagemushaWalletWireV1.inspectEnvelope(ByteArray(KagemushaWalletWireV1.MESSAGE_MAX_BYTES + 1))
        }
    }

    @Test fun `envelope header violations are rejected`() {
        val frame = vectors.array("envelopes").first().jsonObject.hex("canonical_hex")
        KagemushaWalletWireV1.inspectEnvelope(frame)
        val payload = frame.copyOfRange(48, frame.size)
        fun mutated(index: Int, value: Int) = frame.copyOf().also { it[index] = value.toByte() }
        fun reframedPayload(edit: (ByteArray) -> ByteArray) = frameOf(edit(payload.copyOf()))

        val rejected = listOf(
            "empty" to ByteArray(0),
            "header only" to frame.copyOf(48),
            "truncated payload" to frame.copyOf(frame.size - 1),
            "trailing byte" to frame + byteArrayOf(0),
            "magic" to mutated(0, 'X'.code),
            "major" to mutated(4, 1),
            "minor" to mutated(5, 1),
            "schema hash" to mutated(6, frame[6].toInt() xor 1),
            "compression" to mutated(22, 1),
            "payload length" to mutated(23, frame[23].toInt() + 1),
            "payload length high byte" to mutated(30, 1),
            "crc64" to mutated(31, frame[31].toInt() xor 1),
            "flags zero" to mutated(39, 0x00),
            "flags reserved" to mutated(39, 0x03),
            "flags high" to mutated(39, 0x82),
            "padding" to mutated(40, 1),
            "padding last" to mutated(47, 0x80),
            "payload byte" to mutated(frame.size - 1, frame[frame.size - 1].toInt() xor 1),
            "version field length" to reframedPayload { it.also { bytes -> bytes[0] = 3 } },
            "version" to reframedPayload { it.also { bytes -> bytes[1] = 2 } },
            "noncanonical varint" to reframedPayload { byteArrayOf(0x82.toByte(), 0x00) + it.copyOfRange(1, it.size) },
            "tag zero" to reframedPayload { it.also { bytes -> bytes[5] = 0 } },
            "tag eight" to reframedPayload { it.also { bytes -> bytes[5] = 8 } },
            "tag high byte" to reframedPayload { it.also { bytes -> bytes[8] = 1 } },
            "message longer than its field" to reframedPayload { it + byteArrayOf(0) },
            "message shorter than its field" to reframedPayload { it.copyOf(it.size - 1) },
            "variant span" to reframedPayload { bytes ->
                // Shorten the message field by one byte and its length prefix with it, so only
                // the variant length prefix disagrees with the remaining span.
                val shortened = bytes.copyOf(bytes.size - 1)
                val messageLength = Varint.decode(shortened, 3)
                check(messageLength.nextOffset == 5)
                val reencoded = Varint.encode(messageLength.value - 1)
                check(reencoded.size == 2)
                reencoded.copyInto(shortened, 3)
                shortened
            },
        )
        for ((name, bytes) in rejected) {
            assertFailsWith<IllegalArgumentException>(name) { KagemushaWalletWireV1.inspectEnvelope(bytes) }
        }
        // The rebuilt payload is the original vector, so reframing alone is accepted.
        assertContentEquals(frame, frameOf(payload))
    }

    @Test fun `kgm1 text decoding is strict`() {
        val text = vectors.array("envelopes").first().jsonObject.text("text")
        val body = text.removePrefix(KagemushaWalletWireV1.TEXT_PREFIX)
        val rejected = listOf(
            body,
            "KGM1:$body",
            "kgm2:$body",
            "kgm1:",
            "$text=",
            "$text==",
            text.replaceRange(10, 11, "+"),
            text.replaceRange(10, 11, "/"),
            text.replaceRange(10, 11, " "),
            "$text\n",
            " $text",
            text.replaceRange(10, 11, "é"),
            "${text}A",
            "kgm1:A",
            "kgm1:_x",
            "kgm1:AB",
            KagemushaWalletWireV1.TEXT_PREFIX + "A".repeat(13_335),
        )
        for (candidate in rejected) {
            assertFailsWith<IllegalArgumentException>(candidate.take(24)) {
                KagemushaWalletWireV1.decodeText(candidate)
            }
        }
        assertContentEquals(byteArrayOf(0xff.toByte()), KagemushaWalletWireV1.decodeText("kgm1:_w"))
        assertContentEquals(byteArrayOf(0), KagemushaWalletWireV1.decodeText("kgm1:AA"))
        val largest = KagemushaWalletWireV1.TEXT_PREFIX + "A".repeat(13_334)
        assertEquals(KagemushaWalletWireV1.MESSAGE_TEXT_MAX_BYTES, largest.length)
        assertContentEquals(
            ByteArray(KagemushaWalletWireV1.MESSAGE_MAX_BYTES),
            KagemushaWalletWireV1.decodeText(largest),
        )
        assertFailsWith<IllegalArgumentException> { KagemushaWalletWireV1.decodeEnvelopeText(largest) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletWireV1.encodeText(ByteArray(0)) }
        assertFailsWith<IllegalArgumentException> {
            KagemushaWalletWireV1.encodeText(ByteArray(KagemushaWalletWireV1.MESSAGE_MAX_BYTES + 1))
        }
        assertEquals(largest, KagemushaWalletWireV1.encodeText(ByteArray(KagemushaWalletWireV1.MESSAGE_MAX_BYTES)))
    }

    @Test fun `every object vector is a canonical frame of its type that re-encodes byte-identically`() {
        val identities = vectors.array("frames").map { it.jsonObject }.associateBy { it.text("type") }
        val objects = vectors.array("objects").map { it.jsonObject }
        assertTrue(objects.isNotEmpty())
        for (vector in objects) {
            val type = vector.text("type")
            val label = "$type ${vector.text("variant")}"
            val name = vector.text("frame_name")
            val frame = vector.hex("canonical_hex")
            assertEquals(KagemushaWalletWireV1.ENVELOPE_FRAME_NAME.substringBeforeLast("::") + "::" + type, name, label)
            assertEquals(vector.int("frame_len"), frame.size, label)
            identities[type]?.let { identity ->
                assertEquals(identity.text("frame_name"), name, label)
                assertTrue(frame.size <= identity.int("max_bytes"), label)
            }
            val schemaHash = SchemaHash.hash16(name)
            val decoded = NoritoHeader.decode(frame, schemaHash)
            decoded.header.validateChecksum(decoded.payload)
            assertEquals(NoritoHeader.COMPACT_LEN, decoded.header.flags, label)
            assertEquals(NoritoHeader.COMPRESSION_NONE, decoded.header.compression, label)
            val padding = frame.size - NoritoHeader.HEADER_LENGTH - decoded.payload.size
            assertTrue(padding in listOf(0, KagemushaWalletWireV1.ENVELOPE_PADDING_BYTES), "$label padding $padding")
            // The first field of every wallet object is its version or a record that starts
            // with one, so the payload splits into complete compact-length fields.
            assertTrue(recordFields(decoded.payload).isNotEmpty(), label)
            assertContentEquals(frame, frameOf(schemaHash, decoded.payload, padding), label)

            val flipped = frame.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
            assertFailsWith<IllegalArgumentException>(label) {
                NoritoHeader.decode(flipped, schemaHash).let { it.header.validateChecksum(it.payload) }
            }
            assertFailsWith<IllegalArgumentException>(label) {
                NoritoHeader.decode(frame, KagemushaWalletWireV1.envelopeSchemaHash())
            }
        }
        // Local custody records are digested over their complete canonical frames.
        val frameRoles = mapOf(
            "marker" to "KagemushaWalletMarkerV1",
            "capsule" to "KagemushaWalletRecoveryCapsuleV1",
            "completion" to "KagemushaWalletCompletionRecordV1",
            "fold" to "KagemushaWalletFoldRecordV1",
        )
        for ((role, type) in frameRoles) {
            val body = digestVector(role).hex("body_hex")
            assertTrue(
                objects.any { it.text("type") == type && it.hex("canonical_hex").contentEquals(body) },
                "$role digest body is a $type object vector",
            )
        }
    }

    @Test fun `σ-field element vectors follow the element rule`() {
        val encodings = vectors.obj("field_encodings")
        assertContentEquals(fieldBytes(FIELD_MODULUS), encodings.hex("modulus_le_hex"))
        assertContentEquals(KagemushaWalletWireV1.fieldModulus(), encodings.hex("modulus_le_hex"))
        assertTrue(encodings.text("field").endsWith("0x" + FIELD_MODULUS.toString(16)), encodings.text("field"))
        val domains = encodings.array("domains").map { it.jsonObject }
        assertEquals(POSEIDON_DOMAINS, domains.associate { it.text("use") to it.text("ascii") })
        assertEquals(POSEIDON_DOMAINS.values.toList(), domains.map { it.text("ascii") })
        for (domain in domains) {
            val ascii = domain.text("ascii").toByteArray(Charsets.US_ASCII)
            assertEquals(8, ascii.size)
            assertContentEquals(ascii, domain.hex("u64_le_hex"))
        }

        val lists = mapOf(
            "consumed_credit_leaf" to items(encodings, "consumed_credit_leaf"),
            "pending_outgoing_leaf" to items(encodings, "pending_outgoing_leaf"),
            "fee_claim_leaf" to items(encodings, "fee_claim_leaf"),
            "credit_digest_leaf" to items(encodings, "credit_digest_leaf"),
            "send_chain_append_from_empty" to items(encodings, "send_chain_append_from_empty"),
            "recv_chain_append" to items(encodings, "recv_chain_append"),
            "send_statement" to items(encodings.obj("send_statement"), "items"),
            "receive_statement" to items(encodings.obj("receive_statement"), "items"),
            "core" to items(encodings.obj("receive_successor_state"), "core_items"),
            "rest" to items(encodings.obj("receive_successor_state"), "rest_items"),
        )
        val counts = mapOf(
            "consumed_credit_leaf" to 3,
            "pending_outgoing_leaf" to 8,
            "fee_claim_leaf" to 4,
            "credit_digest_leaf" to 3,
            "send_chain_append_from_empty" to 9,
            "recv_chain_append" to 5,
            "send_statement" to 28,
            "receive_statement" to 28,
            "core" to 32,
            "rest" to 13,
        )
        for ((name, list) in lists) {
            assertEquals(counts.getValue(name), list.size, name)
            for (element in list) assertCanonicalField(element, nonzero = false)
        }

        // Statement elements re-derive from the 440-byte statement transcripts.
        val sendTranscript = encodings.obj("send_statement").hex("statement_hex")
        val receiveTranscript = encodings.obj("receive_statement").hex("statement_hex")
        assertContentEquals(digestVector("statement").hex("body_hex"), sendTranscript)
        assertElements(lists.getValue("send_statement"), statementElements(sendTranscript), "send statement")
        assertElements(lists.getValue("receive_statement"), statementElements(receiveTranscript), "receive statement")

        // Core and rest elements re-derive from the canonical state frame.
        val successor = encodings.obj("receive_successor_state")
        val (core, rest) = stateElements(successor.hex("state_hex"))
        assertElements(lists.getValue("core"), core, "core")
        assertElements(lists.getValue("rest"), rest, "rest")

        // Poseidon values the native core computed over these lists are opaque canonical values.
        val poseidonValues = mapOf(
            "send statement digest" to encodings.obj("send_statement").hex("digest_hex"),
            "receive statement digest" to encodings.obj("receive_statement").hex("digest_hex"),
            "rest digest" to successor.hex("rest_digest_hex"),
            "commitment" to successor.hex("commitment_hex"),
            "send_chain append" to encodings.hex("send_chain_append_from_empty_hex"),
            "recv_chain append" to encodings.hex("recv_chain_append_hex"),
        )
        for ((label, value) in poseidonValues) assertPoseidonValue(value, label)
        assertEquals(poseidonValues.size, poseidonValues.values.map { hexText(it) }.toSet().size)

        // SHA-256 digests and identifiers enter as two limbs, Poseidon values (credit_id, the
        // Payment digest, commitments, chains and roots) as one element; shared values agree.
        val send = lists.getValue("send_statement")
        val receive = lists.getValue("receive_statement")
        val creditId = listOf(poseidon.obj("credit_id").obj("poseidon").hex("digest_hex"))
        val pending = lists.getValue("pending_outgoing_leaf")
        assertElements(creditId, send.subList(18, 19), "Send credit_id")
        assertElements(send.subList(18, 26), pending, "pending-outgoing leaf is the Send descriptor")
        assertElements(limbs(digestVector("request").hex("digest_hex")), pending.subList(6, 8), "request digest")
        val sendChain = lists.getValue("send_chain_append_from_empty")
        assertElements(listOf(ByteArray(32)), sendChain.subList(0, 1), "empty send_chain")
        assertElements(pending, sendChain.subList(1, 9), "send_chain entry")
        val recvChain = lists.getValue("recv_chain_append")
        assertStandInField(recvChain[0], 0x2c)
        assertElements(receive.subList(18, 22), recvChain.subList(1, 5), "recv_chain entry")
        assertElements(creditId, receive.subList(18, 19), "Receive credit_id")
        val consumed = lists.getValue("consumed_credit_leaf")
        assertElements(creditId, consumed.subList(0, 1), "consumed credit_id")
        assertElements(receive.subList(21, 22), consumed.subList(1, 2), "consumed amount")
        assertElements(receive.subList(10, 11), consumed.subList(2, 3), "receive sequence")
        val creditDigest = lists.getValue("credit_digest_leaf")
        assertElements(creditId, creditDigest.subList(0, 1), "credit-digest credit_id")
        assertElements(
            listOf(poseidon.obj("payment_digest").hex("digest_hex")),
            creditDigest.subList(1, 2),
            "Payment digest",
        )
        assertTrue(unsignedElement(creditDigest[2]) in 0L..1L, "burned flag")
        val feeClaim = lists.getValue("fee_claim_leaf")
        assertElements(creditId, feeClaim.subList(0, 1), "fee-claim credit_id")
        assertElements(send.subList(23, 24), feeClaim.subList(1, 2), "fee")
        assertElements(limbs(digestVector("fee-schedule").hex("digest_hex")), feeClaim.subList(2, 4), "fee schedule")

        // The successor state agrees with its Receive statement; scheme and asset are core
        // fields (owner answer Q4) and its commitment P(core, P(rest)) is the statement successor.
        assertElements(receive.subList(3, 5), core.subList(1, 3), "scheme")
        assertElements(receive.subList(5, 7), core.subList(3, 5), "asset")
        assertElements(receive.subList(7, 9), core.subList(7, 9), "credential")
        assertElements(receive.subList(9, 10), core.subList(0, 1), "lifecycle")
        assertElements(receive.subList(10, 11), core.subList(11, 12), "sequence")
        assertElements(receive.subList(11, 12), core.subList(13, 14), "next_load")
        assertElements(listOf(successor.hex("commitment_hex")), receive.subList(16, 17), "successor commitment")
        assertElements(limbs(digestVector("scheme").hex("digest_hex")), core.subList(1, 3), "scheme_id")
        // The five map roots and the state nonce are nonzero canonical values (one element each);
        // the enabled controls are within the rest's permitted controls (owner answer Q5 moved the
        // blacklist age bound into the core, beside the list's issue time).
        for (index in listOf(17, 18, 19, 20, 21, 31)) assertCanonicalField(core[index], nonzero = true)
        val enabled = unsignedElement(core[22])
        assertEquals(0L, enabled and unsignedElement(rest[0]).inv(), "enabled controls within permitted")

        // Stand-in field values follow their labelled rule and are canonical.
        val standIns = vectors.obj("stand_ins")
        assertFalse(standIns.containsKey("empty_roots_hex"), "empty map roots are computed, not stand-ins")
        val seeded = listOf(standIns.hex("credit_digest_root_hex"), standIns.hex("lineage_pending_outgoing_root_hex"))
        for (value in seeded) assertStandInField(value, unsigned(value[0]))
        assertFailsWith<AssertionError> { assertCanonicalField(encodings.hex("modulus_le_hex"), nonzero = false) }
        assertFalse(KagemushaWalletWireV1.isCanonicalFieldValue(encodings.hex("modulus_le_hex")))
    }

    @Test fun `controlled state binds every core and rest position to its field`() {
        // Every element of this state is distinct and its fields are named, so the core and rest
        // layouts (owner answers Q3, Q4 and Q5: one load/redeem root, scheme and asset in the core,
        // the blacklist issue time and maximum age beside each other) are pinned by position.
        val controlled = vectors.obj("field_encodings").obj("controlled_state")
        val core = items(controlled, "core_items")
        val rest = items(controlled, "rest_items")
        assertEquals(32, core.size)
        assertEquals(13, rest.size)
        assertEquals(core.size, core.map { hexText(it) }.toSet().size, "distinct core elements")
        assertEquals(rest.size, rest.map { hexText(it) }.toSet().size, "distinct rest elements")
        for (element in core + rest) assertCanonicalField(element, nonzero = false)
        val (frameCore, frameRest) = stateElements(controlled.hex("state_hex"))
        assertElements(core, frameCore, "controlled core")
        assertElements(rest, frameRest, "controlled rest")
        assertPoseidonValue(controlled.hex("rest_digest_hex"), "controlled rest digest")
        assertPoseidonValue(controlled.hex("commitment_hex"), "controlled commitment")

        val coreOrder = listOf(
            "lifecycle" to 'I', "scheme_id" to 'D', "asset_digest" to 'D', "wallet_id" to 'D',
            "credential_digest" to 'D', "balance" to 'I', "burned_total" to 'I', "sequence" to 'I',
            "next_send" to 'I', "next_load" to 'I', "next_redeem" to 'I', "send_chain" to 'F',
            "recv_chain" to 'F', "consumed_credit_root" to 'F', "pending_outgoing_root" to 'F',
            "load_redeem_recovery_root" to 'F', "fee_claim_root" to 'F', "quota_usage_root" to 'F',
            "enabled_controls" to 'I', "quota_windows_root" to 'F', "blacklist_version" to 'I',
            "blacklist_root" to 'F', "blacklist_issued_at_ms" to 'I', "blacklist_max_age_ms" to 'I',
            "lease_expires_at_ms" to 'I', "policy_epoch" to 'I', "accepted_time_floor_ms" to 'I',
            "state_nonce" to 'F',
        )
        val restOrder = listOf(
            "permitted_controls" to 'I', "time_anchor_max_response_ms" to 'I', "scheme_policy" to 'D',
            "fee_schedule" to 'D', "blacklist" to 'D', "quota_share" to 'D', "quota_share_id" to 'I',
            "time_anchor" to 'D',
        )
        fun named(fields: JsonObject, order: List<Pair<String, Char>>): List<ByteArray> {
            assertEquals(order.map { it.first }.toSet(), fields.keys, "named fields")
            return order.flatMap { (name, kind) ->
                when (kind) {
                    'I' -> listOf(fieldBytes(BigInteger(fields.text(name))))
                    'D' -> limbs(fields.hex(name))
                    else -> listOf(fields.hex(name))
                }
            }
        }
        assertEquals(CORE_LAYOUT, coreOrder.map { it.second }.joinToString(""))
        assertEquals(REST_LAYOUT, restOrder.map { it.second }.joinToString(""))
        assertElements(named(controlled.obj("core_fields"), coreOrder), core, "named core fields")
        assertElements(named(controlled.obj("rest_fields"), restOrder), rest, "named rest fields")
    }

    @Test fun `canonical field values are 32 little-endian bytes below p`() {
        val modulus = KagemushaWalletWireV1.fieldModulus()
        assertContentEquals(fieldBytes(FIELD_MODULUS), modulus)
        modulus.fill(0)
        assertContentEquals(fieldBytes(FIELD_MODULUS), KagemushaWalletWireV1.fieldModulus(), "a fresh array")

        val accepted = listOf(
            ByteArray(32),
            fieldBytes(BigInteger.ONE),
            fieldBytes(FIELD_MODULUS.subtract(BigInteger.ONE)),
            fieldBytes(BigInteger.ONE.shiftLeft(254)),
        )
        for (value in accepted) {
            assertTrue(KagemushaWalletWireV1.isCanonicalFieldValue(value), hexText(value))
            val copy = KagemushaWalletWireV1.requireCanonicalFieldValue(value)
            assertContentEquals(value, copy)
            copy.fill(0x11)
            assertFalse(copy.contentEquals(value), "a defensive copy")
        }
        val rejected = listOf(
            fieldBytes(FIELD_MODULUS),
            fieldBytes(FIELD_MODULUS.add(BigInteger.ONE)),
            ByteArray(32) { 0xff.toByte() },
            // 2^255: canonical if misread big-endian, above p as the little-endian encoding.
            ByteArray(32).also { it[31] = 0x80.toByte() },
            ByteArray(31),
            ByteArray(33),
            ByteArray(0),
        )
        for (value in rejected) {
            assertFalse(KagemushaWalletWireV1.isCanonicalFieldValue(value), hexText(value))
            assertFailsWith<IllegalArgumentException> { KagemushaWalletWireV1.requireCanonicalFieldValue(value) }
        }
        // Zero is canonical, but not where a nonzero value (a commitment, root or credit_id) is due.
        KagemushaWalletWireV1.requireCanonicalFieldValue(ByteArray(32), nonzero = false)
        assertFailsWith<IllegalArgumentException> {
            KagemushaWalletWireV1.requireCanonicalFieldValue(ByteArray(32), nonzero = true)
        }
        KagemushaWalletWireV1.requireCanonicalFieldValue(fieldBytes(BigInteger.ONE), nonzero = true)
    }

    @Test fun `Poseidon vectors are canonical opaque values over re-derived element lists`() {
        // One known-answer vector per domain over [1, 2, 3], in domain-table order. Kotlin does
        // not recompute P: the native core does, and these values are checked as encodings only.
        val kats = poseidon.array("kats").map { it.jsonObject }
        assertEquals(POSEIDON_DOMAINS.values.toList(), kats.map { it.text("domain") })
        val oneTwoThree = listOf(1L, 2L, 3L).map { u64Element(it) }
        for (kat in kats) {
            assertElements(oneTwoThree, items(kat, "items"), kat.text("domain"))
            assertPoseidonValue(kat.hex("digest_hex"), kat.text("domain"))
        }
        assertEquals(kats.size, kats.map { it.text("digest_hex") }.toSet().size, "domains separate")

        // P_bytes: [len(b)] then 31-byte little-endian chunks, the last zero-filled (owner answer Q9).
        val packing = poseidon.array("packing").map { it.jsonObject }
        assertEquals(listOf(0, 1, 30, 31, 32, 62, 63), packing.map { it.int("len") })
        for (vector in packing) {
            val bytes = vector.hex("bytes_hex")
            val label = "packing ${bytes.size}"
            assertEquals(vector.int("len"), bytes.size, label)
            assertTrue(bytes.indices.all { unsigned(bytes[it]) == it + 1 }, label)
            val hashed = vector.obj("poseidon")
            assertEquals("kgwstep1", hashed.text("domain"), label)
            val elements = items(hashed, "items")
            assertElements(packedElements(bytes), elements, label)
            assertEquals(1 + (bytes.size + 30) / 31, elements.size, label)
            for (chunk in elements) assertEquals(0, chunk[31].toInt(), "$label chunk below 2^248")
            assertPoseidonValue(hashed.hex("digest_hex"), label)
        }

        // credit_id = P(kgwcrdt1, the 24 request-body elements in transcript order) (owner answer Q1).
        val creditIdVector = poseidon.obj("credit_id")
        val requestBody = creditIdVector.hex("request_body_hex")
        assertContentEquals(digestVector("request-body").hex("body_hex"), requestBody)
        val creditId = creditIdVector.obj("poseidon")
        assertEquals("kgwcrdt1", creditId.text("domain"))
        assertEquals(24, items(creditId, "items").size)
        assertElements(transcriptElements(requestBody, REQUEST_BODY_LAYOUT), items(creditId, "items"), "credit_id")
        val creditIdValue = creditId.hex("digest_hex")
        assertPoseidonValue(creditIdValue, "credit_id")
        // Credited `LE16 version || tag evidence || credit_id || payment_digest || evidence digest`.
        val credited = digestVector("credited").hex("body_hex")
        assertEquals(99, credited.size)
        assertContentEquals(creditIdValue, credited.copyOfRange(3, 35))

        // The Payment digest is P_bytes(kgwpay_1, the 163-byte payment transcript) (owner answer Q9).
        val payment = poseidon.obj("payment_digest")
        assertEquals("kgwpay_1", payment.text("domain"))
        val transcript = Transcript(payment.hex("body_hex"))
        assertEquals(KagemushaWalletWireV1.VERSION.toLong(), transcript.unsigned(2))
        assertContentEquals(digestVector("request").hex("digest_hex"), transcript.take(32))
        assertContentEquals(key("payer_payment"), transcript.take(65))
        assertContentEquals(digestVector("credential").hex("digest_hex"), transcript.take(32))
        assertContentEquals(digestVector("package").hex("digest_hex"), transcript.take(32))
        transcript.finish()
        assertEquals(packedElements(payment.hex("body_hex")).size, payment.int("elements"))
        val paymentDigest = payment.hex("digest_hex")
        assertPoseidonValue(paymentDigest, "Payment digest")
        assertContentEquals(paymentDigest, credited.copyOfRange(35, 67))
        assertContentEquals(
            paymentDigest,
            receiptField(receiptBody("Receive receipt binding the Payment digest"), RECEIPT_PAYMENT_DIGEST),
        )
        assertContentEquals(ByteArray(32), receiptField(receiptBody("Send receipt"), RECEIPT_PAYMENT_DIGEST))

        // Map leaves: domains, keys, element lists and opaque leaf values.
        val leaves = poseidon.obj("leaves")
        val leafDomains = mapOf(
            "consumed_credit" to "kgwccrd1",
            "pending_outgoing" to "kgwpout1",
            "load_recovery" to "kgwload1",
            "redeem_recovery" to "kgwrdm_1",
            "fee_claim" to "kgwfee_1",
            "quota_usage" to "kgwquse1",
        )
        assertEquals(leafDomains.keys, leaves.keys)
        for ((name, domain) in leafDomains) {
            val leaf = leaves.obj(name)
            assertEquals(domain, leaf.text("domain"), name)
            assertCanonicalField(leaf.hex("key_hex"), nonzero = false)
            for (element in items(leaf, "items")) assertCanonicalField(element, nonzero = false)
            assertPoseidonValue(leaf.hex("digest_hex"), name)
        }
        // The credit maps are keyed by credit_id and carry the field_encodings leaf lists.
        val encodings = vectors.obj("field_encodings")
        for (name in listOf("consumed_credit", "pending_outgoing", "fee_claim")) {
            val leaf = leaves.obj(name)
            assertContentEquals(creditIdValue, leaf.hex("key_hex"), name)
            assertElements(items(encodings, "${name}_leaf"), items(leaf, "items"), name)
        }
        // One load/redeem recovery map keyed by kind · 2^128 + ordinal (Load 1, Redeem 2; owner
        // answer Q3).
        val load = leaves.obj("load_recovery")
        val loadItems = items(load, "items")
        assertEquals(4, loadItems.size)
        assertContentEquals(mapKey(1, loadItems[0]), load.hex("key_hex"))
        assertElements(limbs(digestVector("voucher").hex("digest_hex")), loadItems.subList(1, 3), "voucher digest")
        val redeem = leaves.obj("redeem_recovery")
        val redeemItems = items(redeem, "items")
        assertEquals(5, redeemItems.size)
        assertContentEquals(mapKey(2, redeemItems[0]), redeem.hex("key_hex"))
        // The redeem nullifier is H("unload-nullifier", scheme_id || wallet_id || LE128 ordinal).
        val nullifierBody = digestVector("unload-nullifier").hex("body_hex")
        assertEquals(80, nullifierBody.size)
        assertContentEquals(digestVector("scheme").hex("digest_hex"), nullifierBody.copyOfRange(0, 32))
        val nullifier = KagemushaWalletWireV1.digest(
            KagemushaWalletDigestRoleV1.UNLOAD_NULLIFIER,
            nullifierBody.copyOf(64) + redeemItems[0].copyOf(16),
        )
        assertElements(limbs(nullifier), redeemItems.subList(1, 3), "redeem nullifier")
        assertTrue(unsignedElement(redeemItems[4]) <= unsignedElement(redeemItems[3]), "online charge within amount")
        // The quota-usage map is keyed by window kind · 2^128 + window_start_ms.
        val usage = leaves.obj("quota_usage")
        val usageItems = items(usage, "items")
        assertEquals(4, usageItems.size)
        assertContentEquals(mapKey(unsignedElement(usageItems[0]), usageItems[1]), usage.hex("key_hex"))
        assertTrue(unsignedElement(usageItems[1]) < unsignedElement(usageItems[2]), "window start before end")
    }

    @Test fun `sparse-tree and credit-digest openings are compressed by their presence bitmaps`() {
        val tree = poseidon.obj("sparse_tree")
        val emptyLeaf = tree.hex("empty_leaf_hex")
        val defaultHeightOne = tree.hex("default_height_1_hex")
        val emptyRoot = tree.hex("empty_root_hex")
        for (value in listOf(emptyLeaf, defaultHeightOne, emptyRoot)) assertPoseidonValue(value, "sparse default")
        assertEquals(3, listOf(emptyLeaf, defaultHeightOne, emptyRoot).map { hexText(it) }.toSet().size)
        // The wire record (section 3.2) pins the height-256 empty root.
        assertEquals(EMPTY_SPARSE_ROOT_HEX, hexText(emptyRoot))
        val defaults = mapOf(0 to emptyLeaf, 1 to defaultHeightOne)
        val leaves = poseidon.obj("leaves")

        // A one-leaf consumed-credit map: the member opens without siblings; its absent neighbour
        // opens to the empty leaf with the member leaf as its only non-default sibling.
        val member = tree.obj("consumed_credit_membership")
        val consumed = leaves.obj("consumed_credit")
        assertContentEquals(consumed.hex("key_hex"), member.hex("key_hex"))
        assertContentEquals(consumed.hex("digest_hex"), member.hex("leaf_hex"))
        assertTrue(assertOpening(member, null, defaults).isEmpty())
        val absent = tree.obj("consumed_credit_absence")
        assertContentEquals(emptyLeaf, absent.hex("leaf_hex"))
        assertContentEquals(member.hex("root_hex"), absent.hex("root_hex"))
        assertContentEquals(member.hex("leaf_hex"), assertOpening(absent, member.hex("key_hex"), defaults).single())

        // The load/redeem recovery map holding one Load and one Redeem leaf (owner answer Q3).
        val load = tree.obj("load_membership")
        assertContentEquals(leaves.obj("load_recovery").hex("key_hex"), load.hex("key_hex"))
        assertContentEquals(leaves.obj("load_recovery").hex("digest_hex"), load.hex("leaf_hex"))
        assertContentEquals(tree.hex("load_redeem_recovery_root_hex"), load.hex("root_hex"))
        assertEquals(1, assertOpening(load, leaves.obj("redeem_recovery").hex("key_hex"), defaults).size)

        // The credit-digest leaf P(kgwcdig1, [credit_id, payment_digest, burned]) keyed by
        // credit_id in the depth-256 sparse tree (owner answer Q7).
        val creditOpening = poseidon.obj("credit_digest_opening")
        val leaf = creditOpening.obj("leaf")
        val creditId = poseidon.obj("credit_id").obj("poseidon").hex("digest_hex")
        val paymentDigest = poseidon.obj("payment_digest").hex("digest_hex")
        assertEquals("kgwcdig1", leaf.text("domain"))
        assertContentEquals(creditId, leaf.hex("key_hex"))
        assertElements(items(vectors.obj("field_encodings"), "credit_digest_leaf"), items(leaf, "items"), "leaf")
        val opening = creditOpening.obj("opening")
        assertContentEquals(creditId, opening.hex("key_hex"))
        assertContentEquals(leaf.hex("digest_hex"), opening.hex("leaf_hex"))
        val siblings = assertOpening(opening, null, defaults)
        assertTrue(siblings.isNotEmpty())

        // Its `credit-opening` transcript: credit_id || payment_digest || u8 burned ||
        // path_bitmap || LE32 n || siblings.
        val body = Transcript(digestVector("credit-opening").hex("body_hex"))
        assertContentEquals(creditId, body.take(32))
        assertContentEquals(paymentDigest, body.take(32))
        assertEquals(unsignedElement(items(leaf, "items")[2]), body.unsigned(1))
        assertContentEquals(opening.hex("path_bitmap_hex"), body.take(32))
        assertEquals(siblings.size.toLong(), body.unsigned(4))
        for (sibling in siblings) assertContentEquals(sibling, body.take(32))
        body.finish()

        // The Credited::Status envelope carries this opening against Ω(h)'s computed root, and
        // Ω(h) names the Request's receiver by wallet_id and payment key (owner answer Q8).
        val credited = recordFields(envelopeMessage(envelope("Credited::Status")))
        assertEquals(3, credited.size)
        val evidence = credited[2]
        assertEquals(2, readIntLe(evidence, 0), "Credited evidence Status")
        val status = recordFields(recordFields(evidence.copyOfRange(4, evidence.size)).single())
        assertEquals(6, status.size)
        val carried = recordFields(status[5])
        assertEquals(5, carried.size)
        assertContentEquals(creditId, carried[0])
        assertContentEquals(paymentDigest, carried[1])
        assertContentEquals(byteArrayOf(unsignedElement(items(leaf, "items")[2]).toByte()), carried[2])
        assertContentEquals(opening.hex("path_bitmap_hex"), carried[3])
        assertEquals((siblings.size * 32).toLong(), readLongLe(carried[4], 0))
        assertContentEquals(
            siblings.fold(ByteArray(0)) { all, next -> all + next },
            carried[4].copyOfRange(8, carried[4].size),
        )
        val omega = recordFields(recordFields(status[4])[0])
        assertEquals(13, omega.size)
        assertContentEquals(opening.hex("root_hex"), omega[12], "Ω(h) credit_digest_root")
        val requestBody = recordFields(recordFields(envelopeMessage(envelope("Request")))[0])
        assertContentEquals(requestBody[4], omega[4], "Ω(h) wallet is the Request receiver")
        assertContentEquals(key("receiver_payment"), omega[6], "Ω(h) payment key is the receiver's")
        // `credit-status` ends with the digest of its opening.
        val creditStatus = digestVector("credit-status").hex("body_hex")
        assertContentEquals(
            digestVector("credit-opening").hex("digest_hex"),
            creditStatus.copyOfRange(creditStatus.size - 32, creditStatus.size),
        )
    }

    @Test fun `blacklist and quota-window Poseidon trees bind the vectored policy objects`() {
        // Blacklist frame {body, signature, entries: [{account_digest}]}.
        val list = recordFields(objectPayload("KagemushaWalletBlacklistV1", "3 entries"))
        assertEquals(3, list.size)
        val body = recordFields(list[0])
        assertEquals(7, body.size)
        val entries = vecElements(list[2]).map { recordFields(it).single() }
        assertEquals(readIntLe(body[4], 0), entries.size)
        for (index in 1 until entries.size) assertTrue(compareUnsigned(entries[index - 1], entries[index]) < 0)
        val blacklist = poseidon.obj("blacklist")
        val root = blacklist.hex("entries_root_hex")
        assertPoseidonValue(root, "blacklist root")
        assertContentEquals(root, body[5])
        assertContentEquals(root, signedBody("blacklist").copyOfRange(54, 86))

        // Gap leaf i = P(kgwblkl1, limbs(s_i) || limbs(s_(i+1))), sentinel s_0 = 00..00.
        val leaf0 = blacklist.obj("leaf_0")
        assertEquals("kgwblkl1", leaf0.text("domain"))
        assertElements(limbs(ByteArray(32)) + limbs(entries[0]), items(leaf0, "items"), "gap leaf 0")
        assertPoseidonValue(leaf0.hex("digest_hex"), "gap leaf 0")
        val node = blacklist.obj("node_0_1")
        assertEquals("kgwblkn1", node.text("domain"))
        assertEquals(2, items(node, "items").size)
        assertContentEquals(leaf0.hex("digest_hex"), items(node, "items")[0])
        assertPoseidonValue(node.hex("digest_hex"), "blacklist node")

        // A non-membership witness: one gap leaf with lower < x < upper and its 16 siblings.
        val gap = blacklist.obj("gap_opening")
        val account = gap.hex("account_digest_hex")
        assertContentEquals(
            KagemushaWalletWireV1.digest(
                KagemushaWalletDigestRoleV1.ACCOUNT,
                "unlisted".toByteArray(Charsets.US_ASCII),
            ),
            account,
        )
        val index = gap.int("leaf_index")
        assertEquals(1, index)
        assertContentEquals(entries[index - 1], gap.hex("lower_hex"))
        assertContentEquals(entries[index], gap.hex("upper_hex"))
        assertTrue(compareUnsigned(gap.hex("lower_hex"), account) < 0, "lower < account")
        assertTrue(compareUnsigned(account, gap.hex("upper_hex")) < 0, "account < upper")
        val gapSiblings = items(gap, "siblings")
        assertEquals(16, gapSiblings.size)
        for (sibling in gapSiblings) assertPoseidonValue(sibling, "gap sibling")
        assertContentEquals(leaf0.hex("digest_hex"), gapSiblings[0], "gap leaf 1 sits beside leaf 0")
        assertContentEquals(root, gap.hex("root_hex"))

        // Quota share frame {body, windows, signature}; a window is {kind, start_ms, end_ms, limit}.
        val share = recordFields(objectPayload("KagemushaWalletQuotaShareV1", "2 windows"))
        assertEquals(3, share.size)
        val shareBody = recordFields(share[0])
        assertEquals(10, shareBody.size)
        val windows = vecElements(share[1]).map { window -> layoutElements(recordFields(window), "IIII") }
        assertEquals(readIntLe(shareBody[8], 0), windows.size)
        val quota = poseidon.obj("quota_windows")
        val windowsRoot = quota.hex("windows_root_hex")
        assertPoseidonValue(windowsRoot, "quota windows root")
        assertContentEquals(windowsRoot, shareBody[7])
        assertContentEquals(windowsRoot, signedBody("quota share").copyOfRange(122, 154))
        val window0 = quota.obj("window_0")
        assertEquals("kgwqwin1", window0.text("domain"))
        assertElements(windows[0], items(window0, "items"), "window 0")
        assertPoseidonValue(window0.hex("digest_hex"), "window 0")
        assertPoseidonValue(quota.hex("empty_window_hex"), "empty window slot")
        val windowNode = quota.obj("node_0_1")
        assertEquals("kgwqwnd1", windowNode.text("domain"))
        assertContentEquals(window0.hex("digest_hex"), items(windowNode, "items")[0])
        assertEquals(2, items(windowNode, "items").size)
        assertPoseidonValue(windowNode.hex("digest_hex"), "window node")
        // The quota-usage leaf counts against the first window.
        val usage = items(poseidon.obj("leaves").obj("quota_usage"), "items")
        assertElements(windows[0].subList(0, 3), usage.subList(0, 3), "usage window")
        assertTrue(unsignedElement(usage[3]) <= unsignedElement(windows[0][3]), "usage within limit")
    }

    @Test fun `the verifying-key allowlist transcript re-derives from its frame`() {
        // Frame {version, steps: [{kind, enabled_controls, verifying_key_digest, proof_bytes}],
        // lineage_verifying_key_digest, lineage_proof_bytes} (owner answers Q6 and Q11).
        val frame = objectVector("KagemushaWalletVerifyingKeyAllowlistV1", "stand-in keys")
        assertTrue(frame.size <= KagemushaWalletWireV1.VERIFYING_KEY_ALLOWLIST_MAX_BYTES)
        val allowlist = recordFields(objectPayload("KagemushaWalletVerifyingKeyAllowlistV1", "stand-in keys"))
        assertEquals(4, allowlist.size)
        assertContentEquals(byteArrayOf(1, 0), allowlist[0])
        val steps = vecElements(allowlist[1]).map { recordFields(it).also { entry -> assertEquals(4, entry.size) } }
        assertTrue(steps.size <= KagemushaWalletWireV1.VERIFYING_KEY_ENTRIES_MAX)
        val lineageKey = allowlist[2]
        val lineageProofBytes = readIntLe(allowlist[3], 0)

        val transcript = java.io.ByteArrayOutputStream()
        transcript.write(allowlist[0])
        transcript.write(le32(steps.size))
        val selectors = ArrayList<Pair<Int, Int>>()
        val lengths = HashMap<Pair<Int, Int>, Int>()
        val standIns = vectors.obj("stand_ins")
        assertTrue(standIns.text("verifying_key_rule").contains("0x80 | tag << 3 | mask"))
        for (entry in steps) {
            val tag = readIntLe(entry[0], 0)
            val mask = readIntLe(entry[1], 0)
            val proofBytes = readIntLe(entry[3], 0)
            assertTrue(tag in 1..8, "operation tag $tag")
            assertTrue(mask == 0 || tag == SEND_TAG, "a nonzero mask selects only Send")
            assertTrue(proofBytes in 1..KagemushaWalletWireV1.MESSAGE_MAX_BYTES)
            assertTrue(entry[2].all { unsigned(it) == (0x80 or (tag shl 3) or mask) }, "stand-in key $tag/$mask")
            selectors += tag to mask
            lengths[tag to mask] = proofBytes
            transcript.write(byteArrayOf(tag.toByte()))
            transcript.write(entry[1])
            transcript.write(entry[2])
            transcript.write(entry[3])
        }
        transcript.write(lineageKey)
        transcript.write(allowlist[3])
        // Strictly ascending selectors, every operation with the empty mask.
        assertEquals(selectors.sortedWith(compareBy({ it.first }, { it.second })), selectors)
        assertEquals(selectors.size, selectors.toSet().size)
        for (tag in 1..8) assertTrue(selectors.contains(tag to 0), "operation $tag")
        assertTrue(lineageKey.all { unsigned(it) == 0xc4 }, "stand-in Ω transport key")
        val largestSend = selectors.filter { it.first == SEND_TAG }.maxOf { lengths.getValue(it) }
        assertTrue(lineageProofBytes + largestSend <= KagemushaWalletWireV1.PAYMENT_PROOF_BUDGET_BYTES, "R9 budget")

        val vector = poseidon.obj("verifying_key_set")
        assertContentEquals(transcript.toByteArray(), vector.hex("transcript_hex"))
        assertEquals(42 + 41 * steps.size, transcript.size())
        assertContentEquals(digestVector("verifying-key-set").hex("body_hex"), vector.hex("transcript_hex"))
        assertContentEquals(
            KagemushaWalletWireV1.digest(KagemushaWalletDigestRoleV1.VERIFYING_KEY_SET, transcript.toByteArray()),
            vector.hex("digest_hex"),
        )

        // The vectored proofs have exactly their selectors' lengths: σ_send by Ω's mask, σ_recv,
        // and the Ω(pred) transport proof.
        val omega = digestVector("lineage").hex("body_hex")
        val mask = readIntLe(omega, LINEAGE_ENABLED_CONTROLS_OFFSET)
        val (_, sendSigma) = le32Parts(poseidon.array("proof_digests")[0].jsonObject.hex("body_hex"))
        val receiveSigma = le32Parts(poseidon.array("proof_digests")[1].jsonObject.hex("body_hex")).single()
        assertEquals(lengths.getValue(SEND_TAG to mask), sendSigma.size)
        assertEquals(lengths.getValue(RECEIVE_TAG to 0), receiveSigma.size)
        assertEquals(lineageProofBytes, omega.size - LINEAGE_PUBLIC_BYTES)
    }

    private fun assertVerdicts(
        label: String,
        key: ByteArray,
        preimage: ByteArray,
        raw: ByteArray,
        codecOk: Boolean,
        verifyOk: Boolean,
    ) {
        assertEquals(codecOk, codecAccepts(raw), "$label codec_ok")
        assertEquals(verifyOk, jcaVerifyDer(key, preimage, anyDer(raw)), "$label verify_ok")
        assertEquals(codecOk && verifyOk, KagemushaP256Codec.verifyRawLowS(key, preimage, raw), "$label accepted")
    }

    private companion object {
        val P256_ORDER: BigInteger =
            BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

        val vectors: JsonObject by lazy {
            Json.parseToJsonElement(
                String(Files.readAllBytes(fixturePath()), StandardCharsets.UTF_8),
            ).jsonObject
        }

        /** Walks up from the working directory to `fixtures/kagemusha/wallet_v1_vectors.json`. */
        fun fixturePath(): Path {
            var current: Path? = Paths.get("").toAbsolutePath().normalize()
            while (current != null) {
                val candidate = current.resolve("fixtures/kagemusha/wallet_v1_vectors.json")
                if (Files.isRegularFile(candidate)) return candidate
                current = current.parent
            }
            error("fixtures/kagemusha/wallet_v1_vectors.json was not found above the test working directory")
        }

        fun JsonObject.obj(key: String): JsonObject = getValue(key).jsonObject

        fun JsonObject.array(key: String): JsonArray = getValue(key).jsonArray

        fun JsonObject.text(key: String): String = getValue(key).jsonPrimitive.content

        fun JsonObject.int(key: String): Int = getValue(key).jsonPrimitive.int

        fun JsonObject.bool(key: String): Boolean = getValue(key).jsonPrimitive.boolean

        fun JsonObject.hex(key: String): ByteArray = hexBytes(text(key))

        fun hexBytes(text: String): ByteArray {
            require(text.length % 2 == 0) { "odd hex length" }
            return ByteArray(text.length / 2) { index ->
                ((Character.digit(text[2 * index], 16) shl 4) or Character.digit(text[2 * index + 1], 16)).toByte()
            }
        }

        fun unsigned(value: Byte): Int = value.toInt() and 0xff

        fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

        fun base64Url(bytes: ByteArray): String =
            java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        fun codecAccepts(raw: ByteArray): Boolean = try {
            KagemushaP256Codec.requireRawLowSSignature(raw)
            true
        } catch (rejected: IllegalArgumentException) {
            false
        }

        /** DER of arbitrary `r || s` scalars (including zero, `n` and high S) for raw JCA checks. */
        fun anyDer(raw: ByteArray): ByteArray {
            val r = BigInteger(1, raw.copyOfRange(0, 32)).toByteArray()
            val s = BigInteger(1, raw.copyOfRange(32, 64)).toByteArray()
            return byteArrayOf(0x30, (4 + r.size + s.size).toByte(), 0x02, r.size.toByte()) +
                r + byteArrayOf(0x02, s.size.toByte()) + s
        }

        /** Plain JCA ECDSA-P256-SHA256 over DER; it accepts high S, unlike the wallet verifier. */
        fun jcaVerifyDer(key: ByteArray, preimage: ByteArray, der: ByteArray): Boolean = try {
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(KagemushaP256Codec.publicKeyFromSec1(key))
                update(preimage)
                verify(der)
            }
        } catch (rejected: GeneralSecurityException) {
            false
        }

        /** A canonical envelope frame around [payload] with the exact header and padding. */
        fun frameOf(payload: ByteArray): ByteArray =
            NoritoHeader(
                KagemushaWalletWireV1.envelopeSchemaHash(),
                payload.size,
                CRC64.compute(payload),
                NoritoHeader.COMPACT_LEN,
                NoritoHeader.COMPRESSION_NONE,
            ).encode() + ByteArray(KagemushaWalletWireV1.ENVELOPE_PADDING_BYTES) + payload

        /**
         * A structurally valid envelope of exactly [frameLength] bytes whose message tag is [tag]
         * and whose variant field is zero filler; only the header-level checks apply to it.
         */
        fun envelopeFrame(tag: Int, frameLength: Int): ByteArray {
            val overhead = NoritoHeader.HEADER_LENGTH + KagemushaWalletWireV1.ENVELOPE_PADDING_BYTES
            var variantLength = 1
            while (true) {
                val messageLength = 4 + Varint.encode(variantLength.toLong()).size + variantLength
                val total = overhead + 3 + Varint.encode(messageLength.toLong()).size + messageLength
                if (total == frameLength) break
                check(total < frameLength) { "no envelope of exactly $frameLength bytes" }
                variantLength += 1
            }
            val variant = Varint.encode(variantLength.toLong()) + ByteArray(variantLength)
            val message = byteArrayOf(tag.toByte(), 0, 0, 0) + variant
            return frameOf(byteArrayOf(2, 1, 0) + Varint.encode(message.size.toLong()) + message)
        }

        /** A canonical frame of [schemaHash] around [payload] after [padding] zero bytes. */
        fun frameOf(schemaHash: ByteArray, payload: ByteArray, padding: Int): ByteArray =
            NoritoHeader(
                schemaHash,
                payload.size,
                CRC64.compute(payload),
                NoritoHeader.COMPACT_LEN,
                NoritoHeader.COMPRESSION_NONE,
            ).encode() + ByteArray(padding) + payload

        /** Length of the fixed Ω public transcript that opens the Ω bytes. */
        const val LINEAGE_PUBLIC_BYTES = 320

        /** Width of the effect fields after the effect tag in a statement transcript. */
        const val EFFECT_FIELDS_BYTES = 160

        /** Effect elements per statement, zero-filled (the Send effect's ten). */
        const val EFFECT_ELEMENTS = 10

        /** `p` of the σ field, Pasta `Fp` (Vesta scalar field). */
        val FIELD_MODULUS: BigInteger =
            BigInteger("40000000000000000000000000000000224698fc094cf91b992d30ed00000001", 16)

        /** Poseidon domain labels by use, in the order of the wire record table (section 3.2). */
        val POSEIDON_DOMAINS: Map<String, String> = linkedMapOf(
            "core" to "kgwcore1",
            "rest" to "kgwrest1",
            "statement" to "kgwstmt1",
            "credit_id" to "kgwcrdt1",
            "send_chain" to "kgwschn1",
            "recv_chain" to "kgwrchn1",
            "consumed_credit_leaf" to "kgwccrd1",
            "pending_outgoing_leaf" to "kgwpout1",
            "load_recovery_leaf" to "kgwload1",
            "redeem_recovery_leaf" to "kgwrdm_1",
            "fee_claim_leaf" to "kgwfee_1",
            "quota_usage_leaf" to "kgwquse1",
            "credit_digest_leaf" to "kgwcdig1",
            "sparse_empty_leaf" to "kgwsmte1",
            "sparse_node" to "kgwsmtn1",
            "blacklist_leaf" to "kgwblkl1",
            "blacklist_node" to "kgwblkn1",
            "quota_window_leaf" to "kgwqwin1",
            "quota_node" to "kgwqwnd1",
            "proof_digest" to "kgwprf_1",
            "step_proof_digest" to "kgwstep1",
            "payment_digest" to "kgwpay_1",
        )

        /** Height-256 empty root of the sparse trees, pinned by wire record section 3.2. */
        const val EMPTY_SPARSE_ROOT_HEX = "1450223519c41ddd33c971fb997ddca6344588e5f5b7411d310cb55136b4711b"

        /** Operation tags of Send and Receive (wire record section 3.2). */
        const val SEND_TAG = 3
        const val RECEIVE_TAG = 4

        /** Receipt-body offsets of `proof_digest` and `payment_digest` (338-byte transcript). */
        const val RECEIPT_PROOF_DIGEST = 242
        const val RECEIPT_PAYMENT_DIGEST = 306

        /** Offset of `LE32 enabled_controls` in the Ω public transcript. */
        const val LINEAGE_ENABLED_CONTROLS_OFFSET = 236

        /**
         * Effect field layouts after the tag, by effect tag: `D` a SHA-256 digest or identifier
         * (two limbs), `F` a Poseidon value such as `credit_id` (one element), `L` an `LE128`, `Q`
         * an `LE64` and `B` a one-byte tag (one element each).
         */
        val EFFECT_LAYOUTS: Map<Int, String> = mapOf(
            1 to "DD",
            2 to "DLLL",
            3 to "FDLLLDQQ",
            4 to "FDL",
            5 to "FD",
            6 to "DLLLD",
            7 to "BDQ",
            8 to "",
        )

        /**
         * Norito field layouts of the state core and rest: `I` an integer or unit-enum tag (one
         * element), `D` a SHA-256 digest or identifier (two limbs) and `F` a σ-field value (one
         * element). Scheme and asset are core fields and the blacklist age bound joined the core
         * (owner answers Q4 and Q5); the blacklist and quota-window roots are Poseidon values.
         */
        const val CORE_LAYOUT = "IDDDDIIIIIIFFFFFFFIFIFIIIIIF"
        const val REST_LAYOUT = "IIDDDDID"

        /**
         * Request-body transcript layout of the `credit_id` elements: `I<n>` an `n`-byte
         * little-endian integer (one element) and `D` a 32-byte digest or identifier (two limbs).
         */
        const val REQUEST_BODY_LAYOUT = "I2 D D D D I16 D I16 D I16 I8 D I8 D D"

        /** Frame name of the private state, which travels only inside a recovery capsule. */
        const val STATE_FRAME_NAME = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletStateV1"

        /** The single digest vector of [role]. */
        fun digestVector(role: String): JsonObject =
            vectors.array("digests").map { it.jsonObject }.single { it.text("role") == role }

        /** Canonical frame of the envelope vector [variant]. */
        fun envelope(variant: String): ByteArray =
            vectors.array("envelopes").map { it.jsonObject }
                .single { it.text("variant") == variant }.hex("canonical_hex")

        /** Canonical frame of the object vector of [type] and [variant]. */
        fun objectVector(type: String, variant: String): ByteArray = vectors.array("objects").map { it.jsonObject }
            .single { it.text("type") == type && it.text("variant") == variant }.hex("canonical_hex")

        /** SEC1 public key of the fixed key [name]. */
        fun key(name: String): ByteArray =
            vectors.array("keys").map { it.jsonObject }.single { it.text("name") == name }.hex("public_key_hex")

        /** The message record of an envelope frame: `[len] version [len] (tag [len] message)`. */
        fun envelopeMessage(frame: ByteArray): ByteArray {
            val payloadOffset = NoritoHeader.HEADER_LENGTH + KagemushaWalletWireV1.ENVELOPE_PADDING_BYTES
            val payload = frame.copyOfRange(payloadOffset, frame.size)
            var cursor = Varint.decode(payload, 0).nextOffset + 2
            cursor = Varint.decode(payload, cursor).nextOffset + 4
            cursor = Varint.decode(payload, cursor).nextOffset
            return payload.copyOfRange(cursor, payload.size)
        }

        /** The compact-length fields `[len] field` that make up [record] exactly. */
        fun recordFields(record: ByteArray): List<ByteArray> {
            val fields = ArrayList<ByteArray>()
            var offset = 0
            while (offset < record.size) {
                val length = Varint.decode(record, offset)
                check(length.value <= (record.size - length.nextOffset).toLong()) { "field exceeds its record" }
                offset = length.nextOffset + length.value.toInt()
                fields.add(record.copyOfRange(length.nextOffset, offset))
            }
            return fields
        }

        /** The field at record [path] below [record]. */
        fun fieldAt(record: ByteArray, path: List<Int>): ByteArray =
            path.fold(record) { current, index -> recordFields(current)[index] }

        /** Record path of the decode-time scheme below an envelope message of [kind]. */
        fun schemePath(kind: KagemushaWalletMessageKindV1): List<Int> = when (kind) {
            KagemushaWalletMessageKindV1.OFFER, KagemushaWalletMessageKindV1.REQUEST -> listOf(0, 1)
            KagemushaWalletMessageKindV1.PAYMENT -> listOf(1, 0, 1)
            KagemushaWalletMessageKindV1.CREDITED,
            KagemushaWalletMessageKindV1.SESSION_CONTROL,
            KagemushaWalletMessageKindV1.POLICY_DATA,
            -> listOf(1)
            KagemushaWalletMessageKindV1.LINEAGE -> listOf(1, 0, 1)
        }

        /**
         * Copy of envelope [frame] with the last byte of top-level message field [field] flipped and
         * the CRC64 refreshed, so it stays structurally valid.
         */
        fun withFlippedField(frame: ByteArray, field: Int): ByteArray {
            val bytes = frame.copyOf()
            val payloadOffset = NoritoHeader.HEADER_LENGTH + KagemushaWalletWireV1.ENVELOPE_PADDING_BYTES
            var cursor = Varint.decode(bytes, payloadOffset).nextOffset + 2
            cursor = Varint.decode(bytes, cursor).nextOffset + 4
            cursor = Varint.decode(bytes, cursor).nextOffset
            var end = cursor
            for (index in 0..field) {
                val length = Varint.decode(bytes, cursor)
                end = length.nextOffset + length.value.toInt()
                cursor = end
            }
            bytes[end - 1] = (bytes[end - 1].toInt() xor 1).toByte()
            val crc = CRC64.compute(bytes.copyOfRange(payloadOffset, bytes.size))
            for (index in 0 until 8) bytes[31 + index] = (crc ushr (8 * index)).toByte()
            KagemushaWalletWireV1.inspectEnvelope(bytes)
            return bytes
        }

        /**
         * Ω bytes of a Norito `KagemushaWalletLineageV1 {public, proof}` record: the fixed public
         * transcript (the head commitment record unwrapped, the lifecycle enum as its one-byte tag)
         * followed by the transport proof bytes.
         */
        fun omegaBytes(record: ByteArray): ByteArray {
            val (exposed, proof) = recordFields(record).also { check(it.size == 2) }
            val fields = recordFields(exposed)
            check(fields.size == 13)
            val head = recordFields(fields[3]).single()
            check(fields[7].size == 4 && readIntLe(fields[7], 0) in 1..2)
            val transcript = fields[0] + fields[1] + fields[2] + head + fields[4] + fields[5] + fields[6] +
                fields[7].copyOf(1) + fields[8] + fields[9] + fields[10] + fields[11] + fields[12]
            check(transcript.size == LINEAGE_PUBLIC_BYTES)
            // `Vec<u8>` is `LE64 count || bytes`.
            check(proof.size >= 8 && readLongLe(proof, 0) == (proof.size - 8).toLong())
            return transcript + proof.copyOfRange(8, proof.size)
        }

        /** The `LE32 len || bytes` parts that make up [bytes] exactly. */
        fun le32Parts(bytes: ByteArray): List<ByteArray> {
            val parts = ArrayList<ByteArray>()
            var offset = 0
            while (offset < bytes.size) {
                check(offset + 4 <= bytes.size)
                val length = readIntLe(bytes, offset)
                offset += 4
                check(length in 0..(bytes.size - offset))
                parts.add(bytes.copyOfRange(offset, offset + length))
                offset += length
            }
            return parts
        }

        /** A stand-in σ: non-empty, byte `i` is `i mod 251`. */
        fun assertSigmaStandIn(sigma: ByteArray) {
            assertTrue(sigma.isNotEmpty())
            assertTrue(sigma.indices.all { index -> unsigned(sigma[index]) == index % 251 })
        }

        /** [value] is a canonical 32-byte little-endian σ-field value, nonzero when [nonzero]. */
        fun assertCanonicalField(value: ByteArray, nonzero: Boolean) {
            assertEquals(32, value.size)
            val integer = BigInteger(1, value.reversedArray())
            assertTrue(integer < FIELD_MODULUS, "noncanonical σ-field value")
            if (nonzero) assertTrue(integer.signum() != 0, "zero σ-field value")
        }

        /** Little-endian 32-byte encoding of a σ-field value. */
        fun fieldBytes(value: BigInteger): ByteArray =
            ByteArray(32) { index -> value.shiftRight(8 * index).toInt().toByte() }

        /** Element list [key] of [encodings]. */
        fun items(encodings: JsonObject, key: String): List<ByteArray> =
            encodings.array(key).map { hexBytes(it.jsonPrimitive.content) }

        /** One integer element: the little-endian [bytes] zero-extended to 32 bytes. */
        fun integerElement(bytes: ByteArray): ByteArray {
            check(bytes.size in 1..16)
            return ByteArray(32).also { bytes.copyInto(it) }
        }

        /** Two limbs of a 32-byte digest or identifier, low 16 bytes first. */
        fun limbs(digest: ByteArray): List<ByteArray> {
            check(digest.size == 32)
            return listOf(integerElement(digest.copyOfRange(0, 16)), integerElement(digest.copyOfRange(16, 32)))
        }

        /** The small integer an element encodes. */
        fun unsignedElement(element: ByteArray): Long {
            check(element.size == 32 && (8 until 32).all { element[it].toInt() == 0 })
            return readLongLe(element, 0)
        }

        /** σ public-input elements of a 440-byte statement transcript (wire record section 3.2). */
        fun statementElements(transcript: ByteArray): List<ByteArray> {
            val reader = Transcript(transcript)
            val version = reader.take(2)
            val scheme = reader.take(32)
            val relation = reader.take(32)
            val credential = reader.take(32)
            val asset = reader.take(32)
            val lifecycle = reader.take(1)
            val sequence = reader.take(16)
            val nextLoad = reader.take(16)
            val controls = reader.take(4)
            val burned = reader.take(16)
            val lineageRoot = reader.take(32)
            val predecessor = reader.take(32)
            val successor = reader.take(32)
            val tag = reader.take(1)
            val effect = Transcript(reader.take(EFFECT_FIELDS_BYTES))
            reader.finish()
            val elements = ArrayList<ByteArray>()
            elements.add(integerElement(version))
            elements.addAll(limbs(relation))
            elements.addAll(limbs(scheme))
            elements.addAll(limbs(asset))
            elements.addAll(limbs(credential))
            for (integer in listOf(lifecycle, sequence, nextLoad, controls, burned)) {
                elements.add(integerElement(integer))
            }
            elements.addAll(listOf(lineageRoot, predecessor, successor))
            elements.add(integerElement(tag))
            val effectStart = elements.size
            for (field in EFFECT_LAYOUTS.getValue(unsigned(tag[0]))) {
                when (field) {
                    'D' -> elements.addAll(limbs(effect.take(32)))
                    'F' -> elements.add(effect.take(32).also { assertCanonicalField(it, nonzero = true) })
                    'L' -> elements.add(integerElement(effect.take(16)))
                    'Q' -> elements.add(integerElement(effect.take(8)))
                    'B' -> elements.add(integerElement(effect.take(1)))
                    else -> error("unknown effect field $field")
                }
            }
            assertTrue(effect.rest().all { it.toInt() == 0 }, "effect zero fill")
            while (elements.size - effectStart < EFFECT_ELEMENTS) elements.add(ByteArray(32))
            return elements
        }

        /** Core and rest elements of a canonical `KagemushaWalletStateV1` frame `{version, core, rest}`. */
        fun stateElements(frame: ByteArray): Pair<List<ByteArray>, List<ByteArray>> {
            val decoded = NoritoHeader.decode(frame, SchemaHash.hash16(STATE_FRAME_NAME))
            decoded.header.validateChecksum(decoded.payload)
            val state = recordFields(decoded.payload)
            assertEquals(3, state.size)
            assertContentEquals(byteArrayOf(1, 0), state[0])
            val core = layoutElements(recordFields(state[1]), CORE_LAYOUT)
            return core to layoutElements(recordFields(state[2]), REST_LAYOUT)
        }

        /** Elements of record [fields] under [layout] (see [CORE_LAYOUT]). */
        fun layoutElements(fields: List<ByteArray>, layout: String): List<ByteArray> {
            assertEquals(layout.length, fields.size)
            val elements = ArrayList<ByteArray>()
            for ((field, kind) in fields.zip(layout.toList())) {
                when (kind) {
                    'I' -> elements.add(integerElement(field))
                    'D' -> elements.addAll(limbs(field))
                    'F' -> elements.add(field.also { check(it.size == 32) })
                    else -> error("unknown layout field $kind")
                }
            }
            return elements
        }

        /** Element-wise equality of two element lists. */
        fun assertElements(expected: List<ByteArray>, actual: List<ByteArray>, label: String) {
            assertEquals(expected.size, actual.size, label)
            for (index in expected.indices) assertContentEquals(expected[index], actual[index], "$label element $index")
        }

        /** The `poseidon` vector section. */
        val poseidon: JsonObject by lazy { vectors.obj("poseidon") }

        /**
         * [value] is a Poseidon value of the native core: a canonical, nonzero σ-field value by
         * both the test rule and [KagemushaWalletWireV1.requireCanonicalFieldValue]. Kotlin does
         * not recompute it.
         */
        fun assertPoseidonValue(value: ByteArray, label: String) {
            assertCanonicalField(value, nonzero = true)
            assertTrue(KagemushaWalletWireV1.isCanonicalFieldValue(value), label)
            assertContentEquals(value, KagemushaWalletWireV1.requireCanonicalFieldValue(value, nonzero = true), label)
        }

        /** A stand-in field value of seed [seed]: 31 bytes [seed], then `seed & 0x3f`. */
        fun assertStandInField(value: ByteArray, seed: Int) {
            assertEquals(32, value.size)
            assertTrue((0 until 31).all { unsigned(value[it]) == seed }, "stand-in seed")
            assertEquals(seed and 0x3f, unsigned(value[31]))
            assertCanonicalField(value, nonzero = true)
        }

        /** Lowercase hex of [bytes]. */
        fun hexText(bytes: ByteArray): String = bytes.joinToString("") { String.format("%02x", unsigned(it)) }

        /** One integer element of a `u64` value. */
        fun u64Element(value: Long): ByteArray = ByteArray(32).also { element ->
            for (index in 0 until 8) element[index] = (value ushr (8 * index)).toByte()
        }

        /** `LE32` bytes of [value]. */
        fun le32(value: Int): ByteArray = ByteArray(4) { index -> (value ushr (8 * index)).toByte() }

        /**
         * The `P_bytes` element list of [bytes]: the byte length as one element, then the bytes in
         * 31-byte little-endian chunks, the last one zero-filled (wire record section 1).
         */
        fun packedElements(bytes: ByteArray): List<ByteArray> {
            val elements = arrayListOf(u64Element(bytes.size.toLong()))
            var offset = 0
            while (offset < bytes.size) {
                val end = minOf(offset + 31, bytes.size)
                elements.add(ByteArray(32).also { bytes.copyInto(it, 0, offset, end) })
                offset = end
            }
            return elements
        }

        /** Elements of a fixed-layout [transcript] under [layout] (see [REQUEST_BODY_LAYOUT]). */
        fun transcriptElements(transcript: ByteArray, layout: String): List<ByteArray> {
            val reader = Transcript(transcript)
            val elements = ArrayList<ByteArray>()
            for (token in layout.split(' ')) {
                when {
                    token == "D" -> elements.addAll(limbs(reader.take(32)))
                    token.startsWith("I") -> elements.add(integerElement(reader.take(token.substring(1).toInt())))
                    else -> error("unknown transcript token $token")
                }
            }
            reader.finish()
            return elements
        }

        /** Map key `kind · 2^128 + low` of a `u128` element [low] (wire record section 3.2). */
        fun mapKey(kind: Long, low: ByteArray): ByteArray {
            assertTrue((16 until 32).all { low[it].toInt() == 0 }, "map key low part below 2^128")
            assertTrue(kind in 1L..255L)
            return low.copyOf().also { it[16] = kind.toByte() }
        }

        /** Body of the signature vector [objectName]: its preimage without the role prefix. */
        fun signedBody(objectName: String): ByteArray {
            val vector = vectors.array("signatures").map { it.jsonObject }.single { it.text("object") == objectName }
            val role = assertNotNull(KagemushaWalletDigestRoleV1.fromLabel(vector.text("role")))
            val preimage = vector.hex("preimage_hex")
            return preimage.copyOfRange(KagemushaWalletWireV1.preimage(role, ByteArray(0)).size, preimage.size)
        }

        /** The 338-byte receipt body of the signature vector [objectName]. */
        fun receiptBody(objectName: String): ByteArray = signedBody(objectName).also { assertEquals(338, it.size) }

        /** The 32-byte receipt-body field at [offset]. */
        fun receiptField(body: ByteArray, offset: Int): ByteArray = body.copyOfRange(offset, offset + 32)

        /** Payload of the object vector of [type] and [variant]. */
        fun objectPayload(type: String, variant: String): ByteArray {
            val name = KagemushaWalletWireV1.ENVELOPE_FRAME_NAME.substringBeforeLast("::") + "::" + type
            val decoded = NoritoHeader.decode(objectVector(type, variant), SchemaHash.hash16(name))
            decoded.header.validateChecksum(decoded.payload)
            return decoded.payload
        }

        /** Elements of a Norito `Vec<T>` field: `LE64 count` then that many `[len] element`. */
        fun vecElements(field: ByteArray): List<ByteArray> {
            val count = readLongLe(field, 0)
            val elements = recordFields(field.copyOfRange(8, field.size))
            assertEquals(count, elements.size.toLong(), "Vec count")
            return elements
        }

        /** Unsigned lexicographic order of two byte strings of equal length. */
        fun compareUnsigned(left: ByteArray, right: ByteArray): Int {
            check(left.size == right.size)
            for (index in left.indices) {
                val order = unsigned(left[index]).compareTo(unsigned(right[index]))
                if (order != 0) return order
            }
            return 0
        }

        /** Bit [bit] of the little-endian [value]. */
        fun bitAt(value: ByteArray, bit: Int): Int = (unsigned(value[bit / 8]) shr (bit % 8)) and 1

        /** The highest bit where two different keys differ: where their sparse-tree paths split. */
        fun highestDifferingBit(left: ByteArray, right: ByteArray): Int =
            (255 downTo 0).first { bit -> bitAt(left, bit) != bitAt(right, bit) }

        /**
         * Structural checks of one compressed sparse-tree opening: canonical key, leaf and root;
         * one canonical sibling per height marked in the 32-byte presence bitmap, in increasing
         * height, none equal to its known default; and, against the only [other] key of a two-leaf
         * tree, exactly the height where the two paths split. Returns the siblings.
         */
        fun assertOpening(opening: JsonObject, other: ByteArray?, defaults: Map<Int, ByteArray>): List<ByteArray> {
            val key = opening.hex("key_hex")
            assertCanonicalField(key, nonzero = false)
            assertPoseidonValue(opening.hex("leaf_hex"), "opened leaf")
            assertPoseidonValue(opening.hex("root_hex"), "opening root")
            val bitmap = opening.hex("path_bitmap_hex")
            assertEquals(32, bitmap.size)
            val heights = (0 until 256).filter { height -> bitAt(bitmap, height) == 1 }
            val siblings = items(opening, "siblings")
            assertEquals(heights.size, siblings.size, "one sibling per marked height")
            assertTrue(siblings.size <= KagemushaWalletWireV1.CREDIT_OPENING_SIBLINGS_MAX)
            for ((height, sibling) in heights.zip(siblings)) {
                assertPoseidonValue(sibling, "sibling at height $height")
                defaults[height]?.let { assertFalse(it.contentEquals(sibling), "a present sibling is not its default") }
            }
            if (other != null) assertEquals(listOf(highestDifferingBit(key, other)), heights)
            return siblings
        }

        fun readIntLe(bytes: ByteArray, offset: Int): Int =
            (0 until 4).fold(0) { value, index -> value or (unsigned(bytes[offset + index]) shl (8 * index)) }

        fun readLongLe(bytes: ByteArray, offset: Int): Long =
            (0 until 8).fold(0L) { value, index -> value or (unsigned(bytes[offset + index]).toLong() shl (8 * index)) }
    }

    /** Sequential reader over one fixed-layout transcript. */
    private class Transcript(private val bytes: ByteArray) {
        private var offset = 0

        fun take(count: Int): ByteArray {
            check(count in 0..(bytes.size - offset)) { "transcript is truncated" }
            return bytes.copyOfRange(offset, offset + count).also { offset += count }
        }

        /** Little-endian unsigned integer of [count] bytes. */
        fun unsigned(count: Int): Long = readLongLe(take(count).copyOf(8), 0)

        fun rest(): ByteArray = take(bytes.size - offset)

        fun finish() = assertEquals(bytes.size, offset, "transcript has trailing bytes")
    }
}
