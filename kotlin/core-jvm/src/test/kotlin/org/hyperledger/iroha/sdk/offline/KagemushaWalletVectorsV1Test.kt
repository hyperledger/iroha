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
 * `specs/kagemusha_wallet_wire_v1.md` section 5): recomputes every SHA-256 role digest (the 18
 * roles, with every retired role rejected); checks every signature verdict over its 32-byte
 * Poseidon signing message with the raw low-S check before JCA; validates every envelope header,
 * scheme field and per-kind bound against the Kotlin constants and round-trips the strict `kgm1:`
 * text; re-encodes every object frame byte-identically; and re-derives the σ-field element lists
 * of the statements, state, chains, map values, `credit_id` (with the Request account digests),
 * the `P_bytes` packing of every large-input digest and signing message, the depth-32 indexed-tree
 * openings, the limb-ordered blacklist, the quota-window tree and the verifying-key allowlist from
 * their transcripts and frames.
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
                "credit_opening_bytes",
                "credited_receive_fixed_bytes",
                "credited_receive_proof_budget_bytes",
                "credited_status_fixed_bytes",
                "fold_record_max_bytes",
                "indexed_tree_depth",
                "lineage_max_bytes",
                "lineage_proof_cap_bytes",
                "message_max_bytes",
                "message_text_max_bytes",
                "payment_fixed_bytes",
                "payment_proof_budget_bytes",
                "proof_caps",
                "quota_tree_depth",
                "quota_usage_slots",
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
        assertTrue(bounds.text("proof_caps").contains("lineage_proof_cap_bytes"), bounds.text("proof_caps"))
        assertEquals(KagemushaWalletWireV1.PAYMENT_FIXED_BYTES, bounds.int("payment_fixed_bytes"))
        assertEquals(KagemushaWalletWireV1.PAYMENT_PROOF_BUDGET_BYTES, bounds.int("payment_proof_budget_bytes"))
        assertEquals(1_723, KagemushaWalletWireV1.PAYMENT_FIXED_BYTES)
        assertEquals(8_277, KagemushaWalletWireV1.PAYMENT_PROOF_BUDGET_BYTES)
        assertEquals(
            KagemushaWalletWireV1.MESSAGE_MAX_BYTES,
            KagemushaWalletWireV1.PAYMENT_FIXED_BYTES + KagemushaWalletWireV1.PAYMENT_PROOF_BUDGET_BYTES,
        )
        assertEquals(KagemushaWalletWireV1.CREDITED_RECEIVE_FIXED_BYTES, bounds.int("credited_receive_fixed_bytes"))
        assertEquals(
            KagemushaWalletWireV1.CREDITED_RECEIVE_PROOF_BUDGET_BYTES,
            bounds.int("credited_receive_proof_budget_bytes"),
        )
        assertEquals(679, KagemushaWalletWireV1.CREDITED_RECEIVE_FIXED_BYTES)
        assertEquals(9_321, KagemushaWalletWireV1.CREDITED_RECEIVE_PROOF_BUDGET_BYTES)
        assertEquals(
            KagemushaWalletWireV1.MESSAGE_MAX_BYTES,
            KagemushaWalletWireV1.CREDITED_RECEIVE_FIXED_BYTES + KagemushaWalletWireV1.CREDITED_RECEIVE_PROOF_BUDGET_BYTES,
        )
        assertTrue(bounds.text("proof_caps").contains("credited_receive_proof_budget_bytes"))
        // Credited::Status carries Ω(h) and the fixed 32-sibling opening: F_status + Ω cap = 10,000.
        assertEquals(KagemushaWalletWireV1.CREDITED_STATUS_FIXED_BYTES, bounds.int("credited_status_fixed_bytes"))
        assertEquals(KagemushaWalletWireV1.LINEAGE_PROOF_CAP_BYTES, bounds.int("lineage_proof_cap_bytes"))
        assertEquals(7_812, KagemushaWalletWireV1.LINEAGE_PROOF_CAP_BYTES)
        assertEquals(
            KagemushaWalletWireV1.MESSAGE_MAX_BYTES,
            KagemushaWalletWireV1.CREDITED_STATUS_FIXED_BYTES + KagemushaWalletWireV1.LINEAGE_PROOF_CAP_BYTES,
        )
        assertEquals(KagemushaWalletWireV1.VERIFYING_KEY_ENTRIES_MAX, bounds.int("verifying_key_entries_max"))
        assertEquals(16, KagemushaWalletWireV1.VERIFYING_KEY_ENTRIES_MAX)
        assertEquals(
            KagemushaWalletWireV1.VERIFYING_KEY_ALLOWLIST_MAX_BYTES,
            bounds.int("verifying_key_allowlist_max_bytes"),
        )
        // Every map and the credit-digest tree are depth-32 indexed trees (owner answer A2).
        assertEquals(KagemushaWalletWireV1.INDEXED_TREE_DEPTH, bounds.int("indexed_tree_depth"))
        assertEquals(32, KagemushaWalletWireV1.INDEXED_TREE_DEPTH)
        assertEquals(KagemushaWalletWireV1.QUOTA_TREE_DEPTH, bounds.int("quota_tree_depth"))
        assertEquals(KagemushaWalletWireV1.QUOTA_USAGE_SLOTS, bounds.int("quota_usage_slots"))
        assertEquals(KagemushaWalletWireV1.CREDIT_OPENING_BYTES, bounds.int("credit_opening_bytes"))
        assertEquals(1_125, KagemushaWalletWireV1.CREDIT_OPENING_BYTES)
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
        val rows = vectors.array("digests").map { it.jsonObject }
        val seen = mutableSetOf<KagemushaWalletDigestRoleV1>()
        for (vector in rows) {
            val role = assertNotNull(KagemushaWalletDigestRoleV1.fromLabel(vector.text("role")))
            assertTrue(seen.add(role), "one vector per retained H role")
            val body = vector.hex("body_hex")
            val preimage = KagemushaWalletWireV1.preimage(role, body)
            assertContentEquals(vector.hex("preimage_hex"), preimage, vector.text("object"))
            assertContentEquals(vector.hex("digest_hex"), KagemushaWalletWireV1.digest(role, body), vector.text("object"))
            assertContentEquals(sha256(preimage), KagemushaWalletWireV1.digest(role, body))
            assertFalse(KagemushaWalletWireV1.digest(role, body + byteArrayOf(0)).contentEquals(vector.hex("digest_hex")))
            val other = if (role == KagemushaWalletDigestRoleV1.SCHEME) KagemushaWalletDigestRoleV1.RELATION else KagemushaWalletDigestRoleV1.SCHEME
            assertFalse(KagemushaWalletWireV1.digest(other, body).contentEquals(vector.hex("digest_hex")))
        }
        assertEquals(KagemushaWalletDigestRoleV1.entries.toSet(), seen)
        // Exactly one vector per role, in the Rust declaration order.
        assertEquals(
            KagemushaWalletDigestRoleV1.entries.map { it.label },
            vectors.array("digests").map { it.jsonObject.text("role") },
        )
        // Superseded roles are gone, not aliased: the pre-split roles; the SHA-256 roles that owner
        // answers Q1, Q2 and Q9 replaced with Poseidon values (credit_id, both proof_digest domains,
        // the Payment digest, the blacklist and quota-window trees); every signed-body role, now a
        // Poseidon signing message (A1); and the lineage, credit-opening, credit-status and
        // credited digests, now P_bytes values (A3).
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
            "certificate-body",
            "credential-body",
            "scheme-policy-body",
            "fee-schedule-body",
            "blacklist-body",
            "quota-share-body",
            "time-anchor-body",
            "offer-body",
            "session-control-body",
            "request-body",
            "receipt-body",
            "voucher-body",
            "ledger-control-body",
            "artifact-manifest-body",
            "charge-quote-body",
            "renewal-challenge",
            "renewal-key-binding",
            "lineage",
            "credit-opening",
            "credit-status",
            "credited",
            "certificate", "certificate-set", "credential", "scheme-policy", "fee-schedule",
            "blacklist", "quota-share", "time-anchor", "request", "statement", "receipt",
            "package", "operation-id", "voucher", "unload-nullifier", "charge-quote",
        )
        for (label in superseded) {
            assertNull(KagemushaWalletDigestRoleV1.fromLabel(label), label)
            assertTrue(vectors.array("digests").none { it.jsonObject.text("role") == label }, label)
        }
        assertEquals(20, KagemushaWalletDigestRoleV1.entries.size)
        assertEquals(
            KagemushaWalletDigestRoleV1.entries.size,
            KagemushaWalletDigestRoleV1.entries.map { it.label }.toSet().size,
        )
        assertNull(KagemushaWalletDigestRoleV1.fromLabel("policy-chunk"))
        assertNull(KagemushaWalletDigestRoleV1.fromLabel(""))
    }

    @Test fun `large-input digests pack their exact bodies under their Poseidon domains`() {
        // The P_bytes digests over large inputs (owner answer A3): both proof_digest domains, the
        // Payment digest, the lineage digest over Ω, the credit-opening and credit-status digests
        // and the Credited digest of both evidence forms. Kotlin re-derives each packed element
        // count; the values themselves are opaque canonical σ-field values.
        val inputs = poseidon.array("large_input_digests").map { it.jsonObject }
        assertEquals(
            listOf("kgwprf_1", "kgwstep1", "kgwpay_1", "kgwlin_1", "kgwcopn1", "kgwcsts1", "kgwcrdd1", "kgwcrdd1"),
            inputs.map { it.text("domain") },
        )
        for (vector in inputs) {
            val label = vector.text("object")
            assertEquals(packedElements(vector.hex("body_hex")).size, vector.int("elements"), label)
            assertPoseidonValue(vector.hex("digest_hex"), label)
            assertTrue(POSEIDON_DOMAINS.containsValue(vector.text("domain")), label)
        }
        assertEquals(inputs.size, inputs.map { it.text("digest_hex") }.toSet().size, "distinct values")
    }

    @Test fun `proof digests pack the exact stand-in Ω and σ bytes in their two Poseidon domains`() {
        val lineage = largeInput("kgwlin_1")
        val send = largeInput("kgwprf_1")
        val receive = largeInput("kgwstep1")

        // Send, Unload and Retiring: `P_bytes(kgwprf_1, LE32 len(Ω) || Ω || LE32 len(σ) || σ)`,
        // Ω being Ω(pred); the lineage digest is `P_bytes(kgwlin_1, Ω)` over the same bytes.
        val (omega, sigma) = le32Parts(send.hex("body_hex")).also { assertEquals(2, it.size) }
        assertContentEquals(lineage.hex("body_hex"), omega)
        assertSigmaStandIn(sigma)
        // Every other operation, the σ-only domain: `P_bytes(kgwstep1, LE32 len(σ) || σ)`.
        assertSigmaStandIn(le32Parts(receive.hex("body_hex")).single())
        val sendProofDigest = send.hex("digest_hex")
        val receiveProofDigest = receive.hex("digest_hex")

        // Each receipt body binds its step's proof_digest; the Send package digest binds it too.
        assertContentEquals(sendProofDigest, receiptField(receiptBody("Send receipt"), RECEIPT_PROOF_DIGEST))
        assertContentEquals(
            receiveProofDigest,
            receiptField(receiptBody("Receive receipt binding the Payment digest"), RECEIPT_PROOF_DIGEST),
        )
        val packageItems = items(poseidon.obj("package"), "items")
        assertEquals("kgwpkg_1", poseidon.obj("package").text("domain"))
        assertEquals(3, packageItems.size)
        assertContentEquals(vectors.obj("field_encodings").obj("send_statement").hex("digest_hex"), packageItems[0])
        assertContentEquals(sendProofDigest, packageItems[1])
        assertPoseidonValue(packageItems[2], "receipt object digest")
        // The receipt-free Receive output descriptor binds its proof and Payment digests.
        val output = digestVector("output").hex("body_hex")
        assertEquals(97, output.size)
        assertEquals(RECEIVE_TAG, unsigned(output[0]))
        assertContentEquals(vectors.obj("field_encodings").obj("receive_statement").hex("digest_hex"), output.copyOfRange(1, 33))
        assertContentEquals(receiveProofDigest, output.copyOfRange(33, 65))
        assertContentEquals(largeInput("kgwpay_1").hex("digest_hex"), output.copyOfRange(65, 97))

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
        assertContentEquals(items(vectors.obj("field_encodings").obj("send_statement"), "items")[7], exposed.take(32))
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
        assertElements(listOf(integerElement(burned), pendingRoot, head), statement.subList(12, 15), "Ω(pred) lineage")
    }

    @Test fun `the Lineage envelope and the Payment carry the same Ω bytes`() {
        // The lineage digest `P_bytes(kgwlin_1, Ω bytes)` identifies byte-identical reuse.
        val lineage = largeInput("kgwlin_1")
        // Lineage message `{version, lineage: {public, proof}}`.
        val message = recordFields(envelopeMessage(envelope("Lineage")))
        assertEquals(2, message.size)
        val fromLineage = omegaBytes(message[1])
        assertContentEquals(lineage.hex("body_hex"), fromLineage)
        assertEquals(packedElements(fromLineage).size, lineage.int("elements"))
        assertPoseidonValue(lineage.hex("digest_hex"), "lineage digest")

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

    @Test fun `ordinary Load receipt uses an unsigned fixed transcript`() {
        val receipt = vectors.obj("ordinary_load_receipt")
        val transcript = receipt.hex("transcript_hex")
        assertEquals(282, transcript.size)
        assertEquals("kgwolod1", receipt.text("domain_ascii"))
        assertNull(KagemushaWalletSigningDomainV1.fromLabel("kgwolod1"))
        assertElements(packedElements(transcript), items(receipt, "packed_items"), "ordinary receipt packing")
        val load = items(poseidon.obj("map_values").obj("load"), "items")
        assertContentEquals(receipt.hex("digest_hex"), load[1])
        assertPoseidonValue(load[1], "ordinary receipt digest")
    }

    @Test fun `signing domains mirror the Rust table and every vector signs its domain message`() {
        // 16 signing domains, in the Rust declaration order, each with its exact transcript length
        // and the object-digest role of its signed object (owner answer A1, wire record section 1).
        assertEquals(16, KagemushaWalletSigningDomainV1.entries.size)
        assertEquals(
            KagemushaWalletSigningDomainV1.entries.map { it.label },
            POSEIDON_DOMAINS.filterKeys { it.startsWith("signing_") }.values.toList(),
        )
        for (domain in KagemushaWalletSigningDomainV1.entries) {
            assertEquals(8, domain.label.toByteArray(Charsets.US_ASCII).size, domain.label)
            assertEquals(domain, KagemushaWalletSigningDomainV1.fromLabel(domain.label))
        }
        assertNull(KagemushaWalletSigningDomainV1.fromLabel("kgwprf_1"))
        assertTrue(
            vectors.text("signature_rule").startsWith("ECDSA-P256-SHA256 over the 32-byte message_hex"),
            vectors.text("signature_rule"),
        )

        val signatures = vectors.array("signatures").map { it.jsonObject }
        val messages = poseidon.array("signing_messages").map { it.jsonObject }
        assertEquals(17, signatures.size)
        assertEquals(signatures.map { it.text("object") }, messages.map { it.text("object") })
        assertEquals(KagemushaWalletSigningDomainV1.entries.toSet(), signatures.map { signingDomain(it) }.toSet())
        for ((vector, message) in signatures.zip(messages)) {
            val label = vector.text("object")
            val domain = signingDomain(vector)
            val transcript = vector.hex("transcript_hex")
            assertEquals(domain.transcriptBytes, transcript.size, label)
            // m = P_bytes(d, transcript): the packed element count re-derives; m is opaque.
            assertEquals(packedElements(transcript).size, vector.int("elements"), label)
            assertEquals(domain.label, message.text("domain"), label)
            assertContentEquals(transcript, message.hex("body_hex"), label)
            assertEquals(vector.int("elements"), message.int("elements"), label)
            assertContentEquals(vector.hex("message_hex"), message.hex("digest_hex"), label)
            assertEquals(KagemushaWalletWireV1.SIGNING_MESSAGE_BYTES, vector.hex("message_hex").size, label)
            assertPoseidonValue(vector.hex("message_hex"), label)
        }
        assertEquals(signatures.size, signatures.map { it.text("message_hex") }.toSet().size, "distinct messages")
    }

    @Test fun `artifact manifest is the only SHA signed object digest`() {
        val vector = signatureVector("artifact manifest")
        val expected = digestVector("artifact-manifest")
        val message = vector.hex("message_hex")
        val signature = vector.hex("signature_hex")
        assertContentEquals(message + signature, expected.hex("body_hex"))
        assertContentEquals(expected.hex("digest_hex"), KagemushaWalletWireV1.artifactManifestDigest(message, signature))
        for (bad in listOf(message.copyOf(31), message + byteArrayOf(0), fieldBytes(FIELD_MODULUS))) {
            assertFailsWith<IllegalArgumentException> { KagemushaWalletWireV1.artifactManifestDigest(bad, signature) }
        }
        assertFailsWith<IllegalArgumentException> {
            KagemushaWalletWireV1.artifactManifestDigest(message, vector.obj("high_s_twin").hex("signature_hex"))
        }
        // Circuit-visible signed objects have distinct Poseidon domains, never SHA aliases.
        val objectDomains = POSEIDON_DOMAINS.filterKeys { it.startsWith("object_") }
        assertEquals(10, objectDomains.size)
        assertEquals(10, objectDomains.values.toSet().size)
        assertTrue(objectDomains.keys.none { KagemushaWalletDigestRoleV1.fromLabel(it.removePrefix("object_").replace('_', '-')) != null })
    }

    @Test fun `every signature vector has its codec and verify verdicts over its 32-byte message`() {
        val signatures = vectors.array("signatures").map { it.jsonObject }
        assertEquals(17, signatures.size)
        assertEquals(KagemushaWalletSigningDomainV1.entries.toSet(), signatures.map { KagemushaWalletSigningDomainV1.fromLabel(it.text("domain")) }.toSet())
        for (vector in signatures) {
            val label = vector.text("object")
            val message = vector.hex("message_hex")
            val key = vector.hex("public_key_hex")
            val signature = vector.hex("signature_hex")
            assertTrue(vector.bool("codec_ok") && vector.bool("verify_ok"), label)
            assertVerdicts(label, key, message, signature, vector.bool("codec_ok"), vector.bool("verify_ok"))
            assertTrue(KagemushaWalletWireV1.verifySignature(key, message, signature), label)
            // The signature binds m, never the transcript or a SHA-256 preimage of it.
            val transcript = vector.hex("transcript_hex")
            assertFalse(jcaVerifyDer(key, transcript, anyDer(signature)), "$label over its transcript")
            val flipped = message.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
            assertFalse(KagemushaWalletWireV1.verifySignature(key, flipped, signature), label)

            val twin = vector.obj("high_s_twin")
            val twinRaw = twin.hex("signature_hex")
            assertFalse(twin.bool("codec_ok"), label)
            assertTrue(twin.bool("verify_ok"), label)
            assertVerdicts("$label high-S twin", key, message, twinRaw, twin.bool("codec_ok"), twin.bool("verify_ok"))
            assertFalse(KagemushaWalletWireV1.verifySignature(key, message, twinRaw), label)
            assertContentEquals(signature.copyOfRange(0, 32), twinRaw.copyOfRange(0, 32))
            assertEquals(
                P256_ORDER.subtract(BigInteger(1, signature.copyOfRange(32, 64))),
                BigInteger(1, twinRaw.copyOfRange(32, 64)),
            )
            val twinDer = twin.hex("der_hex")
            assertTrue(jcaVerifyDer(key, message, twinDer), "JCA accepts the high-S twin of $label")
            val frozen = KagemushaP256Codec.rawLowSFromStrictDer(twinDer)
            assertContentEquals(twin.hex("frozen_signature_hex"), frozen, label)
            assertContentEquals(signature, frozen, label)
            assertTrue(KagemushaP256Codec.verifyRawLowS(key, message, frozen), label)
        }
    }

    @Test fun `low-S boundary scalars have their verdicts`() {
        val boundaries = vectors.obj("signature_boundaries")
        val order = BigInteger(boundaries.text("order_hex"), 16)
        assertEquals(P256_ORDER, order)
        assertEquals(order.shiftRight(1), BigInteger(boundaries.text("half_order_hex"), 16))
        assertEquals(order.shiftRight(1).add(BigInteger.ONE), BigInteger(boundaries.text("half_order_plus_one_hex"), 16))

        // The boundary signs the receipt-domain message of a fixed 338-byte transcript.
        val domain = assertNotNull(KagemushaWalletSigningDomainV1.fromLabel(boundaries.text("domain")))
        assertEquals(KagemushaWalletSigningDomainV1.RECEIPT, domain)
        assertEquals(domain.transcriptBytes, boundaries.hex("transcript_hex").size)
        val message = boundaries.hex("message_hex")
        assertPoseidonValue(message, "boundary message")
        assertContentEquals(sha256(message), boundaries.hex("e_hex"))

        // The documented derivation: r = x(kG) mod n, s = floor(n/2), d = (s*k - e) * r^-1 mod n,
        // with e = SHA-256(m) mod n.
        val curve = CustomNamedCurves.getByName("secp256r1")
        val k = BigInteger(boundaries.text("k_hex"), 16)
        val r = curve.g.multiply(k).normalize().affineXCoord.toBigInteger().mod(order)
        assertEquals(BigInteger(boundaries.text("r_hex"), 16), r)
        val e = BigInteger(1, sha256(message)).mod(order)
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
            val raw = case.hex("signature_hex")
            assertVerdicts(case.text("name"), key, message, raw, case.bool("codec_ok"), case.bool("verify_ok"))
            assertEquals(
                case.bool("codec_ok") && case.bool("verify_ok"),
                KagemushaWalletWireV1.verifySignature(key, message, raw),
                case.text("name"),
            )
        }
        val accepted = cases.single { it.text("name") == "s_half_order" }.hex("signature_hex")
        assertTrue(KagemushaP256Codec.verifyRawLowS(key, message, accepted))
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
        for (bad in listOf(offCurve, compressedPrefix, compressedPrefix.copyOf(33), valid.copyOf(64), valid + byteArrayOf(0))) {
            assertFailsWith<IllegalArgumentException> { KagemushaP256Codec.publicKeyFromSec1(bad) }
        }
    }

    @Test fun `signature verification rejects wrong messages keys and malformed inputs without mutation`() {
        val signatures = vectors.array("signatures").map { it.jsonObject }
        val vector = signatures.first()
        val key = vector.hex("public_key_hex")
        val message = vector.hex("message_hex")
        val signature = vector.hex("signature_hex")
        val keyCopy = key.copyOf()
        val messageCopy = message.copyOf()
        val signatureCopy = signature.copyOf()
        assertTrue(KagemushaP256Codec.verifyRawLowS(key, message, signature))
        assertTrue(KagemushaWalletWireV1.verifySignature(key, message, signature))
        assertContentEquals(keyCopy, key)
        assertContentEquals(messageCopy, message)
        assertContentEquals(signatureCopy, signature)

        val otherKey = signatures.map { it.hex("public_key_hex") }.first { !it.contentEquals(key) }
        assertFalse(KagemushaP256Codec.verifyRawLowS(otherKey, message, signature))
        assertFalse(KagemushaP256Codec.verifyRawLowS(key, message + byteArrayOf(0), signature))
        assertFalse(KagemushaP256Codec.verifyRawLowS(key, message, signature.copyOf(63)))
        assertFalse(KagemushaP256Codec.verifyRawLowS(key, message, signature + byteArrayOf(0)))
        val flipped = signature.copyOf().also { it[10] = (it[10].toInt() xor 1).toByte() }
        assertFalse(KagemushaP256Codec.verifyRawLowS(key, message, flipped))
        val offCurve = key.copyOf().also { it[64] = (it[64].toInt() xor 1).toByte() }
        assertFalse(KagemushaP256Codec.verifyRawLowS(offCurve, message, signature))
        assertFalse(KagemushaP256Codec.verifyRawLowS(key.copyOf(33), message, signature))

        // The wallet verifier takes exactly one canonical 32-byte message.
        assertFalse(KagemushaWalletWireV1.verifySignature(otherKey, message, signature))
        assertFalse(KagemushaWalletWireV1.verifySignature(key, message.copyOf(31), signature))
        assertFalse(KagemushaWalletWireV1.verifySignature(key, message + byteArrayOf(0), signature))
        assertFalse(KagemushaWalletWireV1.verifySignature(key, fieldBytes(FIELD_MODULUS), signature))
        assertFalse(KagemushaWalletWireV1.verifySignature(key, message, flipped))
        assertFalse(KagemushaWalletWireV1.verifySignature(offCurve, message, signature))
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

    @Test fun `every message kind rejects its own unsupported or malformed version`() {
        val covered = HashSet<KagemushaWalletMessageKindV1>()
        for (vector in vectors.array("envelopes").map { it.jsonObject }) {
            val frame = vector.hex("canonical_hex")
            val kind = assertNotNull(KagemushaWalletMessageKindV1.fromWireTag(vector.int("tag")))
            covered.add(kind)
            val path = versionPath(kind)
            for (version in listOf(0, 2, 65_535)) {
                val changed = withReplacedMessageField(frame, path, le16(version))
                assertRebuiltEnvelopeHeader(changed)
                val rejected = assertFailsWith<IllegalArgumentException>("${vector.text("variant")} version $version") {
                    KagemushaWalletWireV1.inspectEnvelope(changed)
                }
                assertTrue(rejected.message.orEmpty().contains("message version is unsupported"), rejected.message)
            }
            for (length in listOf(0, 1, 3)) {
                val changed = withReplacedMessageField(frame, path, le16(1).copyOf(length))
                assertRebuiltEnvelopeHeader(changed)
                val rejected = assertFailsWith<IllegalArgumentException>("${vector.text("variant")} version length $length") {
                    KagemushaWalletWireV1.inspectEnvelope(changed)
                }
                assertTrue(rejected.message.orEmpty().contains("message version field is not two bytes"), rejected.message)
            }
        }
        assertEquals(KagemushaWalletMessageKindV1.entries.toSet(), covered)
    }

    @Test fun `every message kind rejects malformed decode-time scheme lengths`() {
        val covered = HashSet<KagemushaWalletMessageKindV1>()
        for (vector in vectors.array("envelopes").map { it.jsonObject }) {
            val frame = vector.hex("canonical_hex")
            val kind = assertNotNull(KagemushaWalletMessageKindV1.fromWireTag(vector.int("tag")))
            covered.add(kind)
            val path = schemePath(kind)
            val scheme = fieldAt(envelopeMessage(frame), path)
            assertEquals(32, scheme.size)
            for (length in listOf(0, 31, 33)) {
                val changed = withReplacedMessageField(frame, path, scheme.copyOf(length))
                assertRebuiltEnvelopeHeader(changed)
                val rejected = assertFailsWith<IllegalArgumentException>("${vector.text("variant")} scheme length $length") {
                    KagemushaWalletWireV1.inspectEnvelope(changed)
                }
                assertTrue(rejected.message.orEmpty().contains("decode-time scheme field is not 32 bytes"), rejected.message)
            }
        }
        assertEquals(KagemushaWalletMessageKindV1.entries.toSet(), covered)
    }

    @Test fun `selected message fields reject missing overrun and noncanonical unsigned lengths`() {
        val covered = HashSet<KagemushaWalletMessageKindV1>()
        for (vector in vectors.array("envelopes").map { it.jsonObject }) {
            val frame = vector.hex("canonical_hex")
            val kind = assertNotNull(KagemushaWalletMessageKindV1.fromWireTag(vector.int("tag")))
            covered.add(kind)
            for ((label, path) in listOf("version" to versionPath(kind), "scheme" to schemePath(kind))) {
                val field = fieldAt(envelopeMessage(frame), path)
                val parentPath = path.dropLast(1)
                val index = path.last()
                val parent = fieldAt(envelopeMessage(frame), parentPath)
                val canonicalLength = Varint.encode(field.size.toLong())
                check(canonicalLength.size == 1)
                val malformed = listOf(
                    "noncanonical" to byteArrayOf((canonicalLength[0].toInt() or 0x80).toByte(), 0),
                    // Canonical unsigned 2^63 + field.size. It must not become a negative Long
                    // that passes a one-sided bound and truncates back to the small field size.
                    "unsigned high bit" to byteArrayOf((field.size or 0x80).toByte()) +
                        ByteArray(8) { 0x80.toByte() } + byteArrayOf(1),
                    "record overrun" to Varint.encode(parent.size.toLong() + 1),
                )
                for ((case, prefix) in malformed) {
                    val changed = withReplacedMessageField(frame, path, field, prefix)
                    assertRebuiltEnvelopeHeader(changed)
                    assertFailsWith<IllegalArgumentException>("${vector.text("variant")} $label $case") {
                        KagemushaWalletWireV1.inspectEnvelope(changed)
                    }
                }
                for ((case, suffix) in listOf("missing" to byteArrayOf(), "truncated length" to byteArrayOf(0x80.toByte()))) {
                    val changed = withChangedMessageRecord(frame, parentPath) { record ->
                        encodeRecord(recordFields(record).take(index)) + suffix
                    }
                    assertRebuiltEnvelopeHeader(changed)
                    assertFailsWith<IllegalArgumentException>("${vector.text("variant")} $label $case") {
                        KagemushaWalletWireV1.inspectEnvelope(changed)
                    }
                }
                // Rebuild each intermediate containing record as empty, preserving the outer
                // framing and checksum. Deep Payment/Lineage and Offer/Request paths must fail.
                for (depth in 1 until path.size) {
                    val changed = withChangedMessageRecord(frame, path.take(depth)) { byteArrayOf() }
                    assertRebuiltEnvelopeHeader(changed)
                    assertFailsWith<IllegalArgumentException>("${vector.text("variant")} missing $label ancestor $depth") {
                        KagemushaWalletWireV1.inspectEnvelope(changed)
                    }
                }
            }
        }
        assertEquals(KagemushaWalletMessageKindV1.entries.toSet(), covered)
    }

    @Test fun `carrier version checks do not authenticate unrelated nested credential versions`() {
        // The Request's own body version is checked at (0,0). The receiver credential body
        // version at (1,0,0), its signature and all financial proofs remain typed-wallet scope.
        val changed = withReplacedMessageField(envelope("Request"), listOf(1, 0, 0), le16(2))
        assertRebuiltEnvelopeHeader(changed)
        assertEquals(KagemushaWalletMessageKindV1.REQUEST, KagemushaWalletWireV1.inspectEnvelope(changed).kind)
    }

    @Test fun `exchange record parsing rejects unsigned high-bit lengths beyond inspected paths`() {
        val request = envelope("Request")
        val payment = envelope("Payment")
        val signature = recordFields(envelopeMessage(request))[4]
        assertEquals(64, signature.size)
        val prefix = byteArrayOf(0xc0.toByte()) + ByteArray(8) { 0x80.toByte() } + byteArrayOf(1)
        val changed = withReplacedMessageField(request, listOf(4), signature, prefix)
        assertRebuiltEnvelopeHeader(changed)
        // The selected body version/scheme remain valid; the fixed complete Request record
        // parser must reject the canonical u64 length instead of truncating it to64.
        assertEquals(KagemushaWalletMessageKindV1.REQUEST, KagemushaWalletWireV1.inspectEnvelope(changed).kind)
        assertFailsWith<IllegalArgumentException> { KagemushaWalletWireV1.requireExchangeBinding(changed, payment) }
    }

    @Test fun `Payment display amount is exact unsigned Request DATA and grants no verification`() {
        // These deliberate amount mutations invalidate signatures/proofs. The display codec
        // still reads their DATA; only genuine Native completion can authenticate a receipt.
        for (amount in listOf(BigInteger.ONE, BigInteger.ONE.shiftLeft(127), BigInteger.ONE.shiftLeft(128) - BigInteger.ONE)) {
            val changed = withReplacedMessageField(envelope("Payment"), listOf(1, 0, 9),
                amount.toByteArray().reversedArray().copyOf(16))
            assertEquals(amount, KagemushaWalletWireV1.paymentAmountData(changed))
        }
    }

    @Test fun `Payment display amount rejects noncanonical scalar shape and other message kinds`() {
        for (bytes in listOf(ByteArray(16), ByteArray(15) { 1 }, ByteArray(17) { 1 })) {
            val changed = withReplacedMessageField(envelope("Payment"), listOf(1, 0, 9), bytes)
            assertFailsWith<IllegalArgumentException> { KagemushaWalletWireV1.paymentAmountData(changed) }
        }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletWireV1.paymentAmountData(envelope("Request")) }
        val payment = envelope("Payment")
        assertFailsWith<IllegalArgumentException> { KagemushaWalletWireV1.paymentAmountData(payment.copyOf(payment.size - 1)) }
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

    @Test fun `exchange binding rejects the retired Request body layout before Credited`() {
        val request = recordFields(envelopeMessage(envelope("Request"))).toMutableList()
        val body = recordFields(request[0])
        assertEquals(19, body.size)
        // The removed 17-field form omitted the receiver's recorded blacklist version and root.
        request[0] = encodeRecord(body.filterIndexed { index, _ -> index != 15 && index != 16 })
        val payment = recordFields(envelopeMessage(envelope("Payment"))).toMutableList()
        payment[1] = encodeRecord(listOf(request[0], request[4]))
        val oldRequest = envelopeWithMessage(KagemushaWalletMessageKindV1.REQUEST, encodeRecord(request))
        val oldPayment = envelopeWithMessage(KagemushaWalletMessageKindV1.PAYMENT, encodeRecord(payment))
        assertFailsWith<IllegalArgumentException> { KagemushaWalletWireV1.requireExchangeBinding(oldRequest, oldPayment) }
        assertFailsWith<IllegalArgumentException> {
            KagemushaWalletWireV1.requireExchangeBinding(oldRequest, oldPayment, envelope("Credited::Receive"))
        }
    }

    @Test fun `Request account digests name both credentials inside the credit_id preimage`() {
        // Request body (19 fields, owner answer A5): payer_account_digest and
        // receiver_account_digest, so that the payer's and the receiver's blacklist checks are
        // provable against the same credit_id.
        val request = recordFields(envelopeMessage(envelope("Request")))
        assertEquals(5, request.size)
        val body = recordFields(request[0])
        assertEquals(19, body.size)
        assertContentEquals(signedBody("Request"), body.fold(ByteArray(0)) { all, next -> all + next })
        assertContentEquals(poseidon.obj("credit_id").hex("request_body_hex"), signedBody("Request"))

        // The payer's digest is the Offer credential's, the receiver's the Request credential's.
        val offer = recordFields(envelopeMessage(envelope("Offer")))
        assertEquals(4, offer.size)
        val offerBody = recordFields(offer[0])
        val payerCredential = recordFields(recordFields(offer[1])[0])
        val receiverCredential = recordFields(recordFields(request[1])[0])
        assertContentEquals(offerBody[3], body[REQUEST_PAYER_WALLET])
        assertContentEquals(payerCredential[CREDENTIAL_WALLET], body[REQUEST_PAYER_WALLET])
        assertContentEquals(payerCredential[CREDENTIAL_ACCOUNT], body[REQUEST_PAYER_ACCOUNT])
        assertContentEquals(digestVector("account").hex("digest_hex"), body[REQUEST_PAYER_ACCOUNT])
        assertContentEquals(receiverCredential[CREDENTIAL_WALLET], body[REQUEST_RECEIVER_WALLET])
        assertContentEquals(receiverCredential[CREDENTIAL_ACCOUNT], body[REQUEST_RECEIVER_ACCOUNT])
        assertFalse(body[REQUEST_PAYER_ACCOUNT].contentEquals(body[REQUEST_RECEIVER_ACCOUNT]))
        for (account in listOf(body[REQUEST_PAYER_ACCOUNT], body[REQUEST_RECEIVER_ACCOUNT])) {
            assertEquals(32, account.size)
            assertTrue(account.any { it.toInt() != 0 }, "nonzero account digest")
        }

        // Both digests are limb pairs of the 26 credit_id elements.
        val items = items(poseidon.obj("credit_id").obj("poseidon"), "items")
        assertEquals(26, items.size)
        assertElements(limbs(body[REQUEST_PAYER_ACCOUNT]), items.subList(7, 9), "payer account")
        assertElements(limbs(body[REQUEST_RECEIVER_ACCOUNT]), items.subList(11, 13), "receiver account")
        for (field in listOf(REQUEST_PAYER_ACCOUNT, REQUEST_RECEIVER_ACCOUNT)) {
            assertFailsWith<IllegalArgumentException>("another account in field $field") {
                KagemushaWalletWireV1.requireExchangeBinding(
                    withFlippedMessageField(envelope("Request"), listOf(0, field)),
                    envelope("Payment"),
                )
            }
        }
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
            val namespace = if (type == "KagemushaWalletLoadReceiptV1") {
                "iroha_data_model::isi::kagemusha_wallet::"
            } else {
                KagemushaWalletWireV1.ENVELOPE_FRAME_NAME.substringBeforeLast("::") + "::"
            }
            assertEquals(namespace + type, name, label)
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

    @Test fun `quota refresh retains the canonical full predecessor usage witness`() {
        val type = "KagemushaWalletQuotaRefreshWitnessV1"
        val identity = vectors.array("frames").map { it.jsonObject }.single { it.text("type") == type }
        assertEquals(8_192, identity.int("max_bytes"))
        val witness = vectors.array("objects").map { it.jsonObject }.single { it.text("type") == type }
        assertFalse(witness.bool("stand_in_proof"))
        val original = witness.hex("canonical_hex")
        assertTrue(original.size <= identity.int("max_bytes"))
        val decoded = NoritoHeader.decode(original, SchemaHash.hash16(identity.text("frame_name")))
        decoded.header.validateChecksum(decoded.payload)
        assertEquals(8, original.size - NoritoHeader.HEADER_LENGTH - decoded.payload.size)
        val fields = recordFields(decoded.payload)
        assertEquals(2, fields.size)
        assertContentEquals(le16(1), fields[0])
        // Fixed arrays have exactly 64 length-prefixed Option values, without a Vec count.
        val slots = recordFields(fields[1])
        assertEquals(64, slots.size)
        var previousEnd = 0L
        for ((index, slot) in slots.withIndex()) {
            assertEquals(1, unsigned(slot[0]), "occupied slot $index")
            val leaf = recordFields(recordFields(slot.copyOfRange(1, slot.size)).single())
            assertEquals(listOf(4, 8, 8, 16), leaf.map { it.size })
            val start = readLongLe(leaf[1], 0)
            val end = readLongLe(leaf[2], 0)
            assertTrue(start >= previousEnd && end > start, "ordered window $index")
            assertEquals(100L + index, unsignedElement(integerElement(leaf[3])), "usage $index")
            previousEnd = end
        }
        val role = vectors.obj("enum_tags").array("KagemushaWalletRetainedInputRoleV1")
            .map { it.jsonObject }.single { it.text("variant") == "QuotaRefreshWitness" }
        assertEquals(10, role.int("tag"))
        val capsule = vectors.array("objects").map { it.jsonObject }.single {
            it.text("type") == "KagemushaWalletRecoveryCapsuleV1" &&
                it.text("variant") == "QuotaShare, 64 retained predecessor slots"
        }
        assertTrue(capsule.bool("stand_in_proof"), "structural custody sample is not proof acceptance")
        val capsuleFields = recordFields(objectPayload(capsule.text("type"), capsule.text("variant")))
        assertEquals(14, capsuleFields.size, "capsule field layout is unchanged")
        val retained = vecElements(capsuleFields[12]).map(::recordFields)
        assertEquals(3, retained.size)
        val input = retained.single { readIntLe(it[0], 0) == 10 }
        assertEquals(2, input.size)
        assertEquals(original.size.toLong(), readLongLe(input[1], 0))
        assertContentEquals(original, input[1].copyOfRange(8, input[1].size))
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
            "consumed_credit_value" to items(encodings, "consumed_credit_value"),
            "pending_outgoing_value" to items(encodings, "pending_outgoing_value"),
            "fee_claim_value" to items(encodings, "fee_claim_value"),
            "credit_digest_value" to items(encodings, "credit_digest_value"),
            "send_chain_append_from_empty" to items(encodings, "send_chain_append_from_empty"),
            "recv_chain_append" to items(encodings, "recv_chain_append"),
            "send_statement" to items(encodings.obj("send_statement"), "items"),
            "receive_statement" to items(encodings.obj("receive_statement"), "items"),
            "core" to items(encodings.obj("receive_successor_state"), "core_items"),
            "rest" to items(encodings.obj("receive_successor_state"), "rest_items"),
        )
        val counts = mapOf(
            "consumed_credit_value" to 3,
            "pending_outgoing_value" to 7,
            "fee_claim_value" to 3,
            "credit_digest_value" to 3,
            "send_chain_append_from_empty" to 8,
            "recv_chain_append" to 5,
            "send_statement" to 26,
            "receive_statement" to 26,
            "core" to 33,
            "rest" to 8,
        )
        for ((name, list) in lists) {
            assertEquals(counts.getValue(name), list.size, name)
            for (element in list) assertCanonicalField(element, nonzero = false)
        }

        // Statement elements re-derive from canonical package records, without a parallel transcript.
        val sendRecord = recordFields(recordFields(envelopeMessage(envelope("Payment")))[4])[1]
        val receiveRecord = recordFields(objectPayload("KagemushaWalletPackageV1", "Receive"))[1]
        assertElements(lists.getValue("send_statement"), statementElements(sendRecord), "send statement")
        assertElements(lists.getValue("receive_statement"), statementElements(receiveRecord), "receive statement")

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

        // SHA identities use two limbs; circuit digests and roots use one field element.
        val send = lists.getValue("send_statement")
        val receive = lists.getValue("receive_statement")
        val creditId = poseidon.obj("credit_id").obj("poseidon").hex("digest_hex")
        val pending = lists.getValue("pending_outgoing_value")
        assertContentEquals(creditId, send[17], "Send credit_id")
        assertElements(send.subList(17, 24), pending, "pending-outgoing value is the Send descriptor")
        val paymentBody = largeInput("kgwpay_1").hex("body_hex")
        assertContentEquals(paymentBody.copyOfRange(2, 34), pending[6], "Request object digest")
        val sendChain = lists.getValue("send_chain_append_from_empty")
        assertElements(listOf(ByteArray(32)) + pending, sendChain, "send_chain entry")
        val recvChain = lists.getValue("recv_chain_append")
        assertStandInField(recvChain[0], 0x2c)
        assertElements(receive.subList(17, 21), recvChain.subList(1, 5), "recv_chain entry")
        assertContentEquals(creditId, receive[17], "Receive credit_id")
        assertElements(listOf(creditId, receive[20], receive[9]), lists.getValue("consumed_credit_value"), "consumed credit")
        val creditDigest = lists.getValue("credit_digest_value")
        assertContentEquals(creditId, creditDigest[0])
        assertContentEquals(largeInput("kgwpay_1").hex("digest_hex"), creditDigest[1])
        assertTrue(unsignedElement(creditDigest[2]) in 0L..1L, "burned flag")
        val feeClaim = lists.getValue("fee_claim_value")
        assertElements(listOf(creditId, send[22]), feeClaim.take(2), "fee claim")
        val requestFields = recordFields(recordFields(envelopeMessage(envelope("Request")))[0])
        assertContentEquals(requestFields[10], feeClaim[2], "fee schedule object digest")
        assertElements(receive.subList(3, 5), core.subList(1, 3), "scheme")
        assertElements(receive.subList(5, 7), core.subList(3, 5), "asset")
        assertContentEquals(receive[7], core[7], "credential")
        assertContentEquals(receive[8], core[0], "lifecycle")
        assertContentEquals(receive[9], core[10], "sequence")
        assertContentEquals(receive[10], core[12], "next_load")
        assertContentEquals(receive[11], core[21], "enabled controls")
        assertContentEquals(receive[12], core[9], "burned total")
        assertContentEquals(successor.hex("commitment_hex"), receive[15], "successor commitment")
        assertElements(limbs(digestVector("scheme").hex("digest_hex")), core.subList(1, 3), "scheme_id")
        for (index in listOf(16, 17, 18, 19, 20, 32)) assertCanonicalField(core[index], nonzero = true)
        val enabled = unsignedElement(core[21])
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
        assertEquals(33, core.size)
        assertEquals(8, rest.size)
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
            "credential_digest" to 'F', "balance" to 'I', "burned_total" to 'I', "sequence" to 'I',
            "next_send" to 'I', "next_load" to 'I', "next_redeem" to 'I', "send_chain" to 'F',
            "recv_chain" to 'F', "consumed_credit_root" to 'F', "pending_outgoing_root" to 'F',
            "load_redeem_recovery_root" to 'F', "fee_claim_root" to 'F', "quota_usage_root" to 'F',
            "enabled_controls" to 'I', "quota_windows_root" to 'F', "quota_share_expires_at_ms" to 'I', "blacklist_version" to 'I',
            "blacklist_root" to 'F', "blacklist_issued_at_ms" to 'I', "blacklist_max_age_ms" to 'I',
            "time_anchor_max_response_ms" to 'I', "lease_expires_at_ms" to 'I', "policy_epoch" to 'I', "accepted_time_floor_ms" to 'I',
            "state_nonce" to 'F',
        )
        val restOrder = listOf(
            "permitted_controls" to 'I', "scheme_policy" to 'F', "fee_schedule" to 'F',
            "blacklist" to 'F', "quota_share" to 'F', "quota_share_id" to 'I',
            "time_anchor" to 'F', "blacklist_history_root" to 'F',
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

        // credit_id = P(kgwcrdt1, the 26 request-body elements in transcript order) (owner answers
        // Q1 and A5: the payer and receiver account digests are inside the preimage).
        val creditIdVector = poseidon.obj("credit_id")
        val requestBody = creditIdVector.hex("request_body_hex")
        assertEquals(KagemushaWalletSigningDomainV1.REQUEST.transcriptBytes, requestBody.size)
        assertContentEquals(signedBody("Request"), requestBody)
        val creditId = creditIdVector.obj("poseidon")
        assertEquals("kgwcrdt1", creditId.text("domain"))
        assertEquals(26, items(creditId, "items").size)
        assertElements(transcriptElements(requestBody, REQUEST_BODY_LAYOUT), items(creditId, "items"), "credit_id")
        val creditIdValue = creditId.hex("digest_hex")
        assertPoseidonValue(creditIdValue, "credit_id")

        // The Payment digest is P_bytes(kgwpay_1, the 163-byte payment transcript) (owner answer Q9).
        val payment = largeInput("kgwpay_1")
        val transcript = Transcript(payment.hex("body_hex"))
        assertEquals(KagemushaWalletWireV1.VERSION.toLong(), transcript.unsigned(2))
        assertContentEquals(items(vectors.obj("field_encodings"), "pending_outgoing_value")[6], transcript.take(32))
        assertContentEquals(key("payer_payment"), transcript.take(65))
        assertContentEquals(items(vectors.obj("field_encodings").obj("send_statement"), "items")[7], transcript.take(32))
        assertContentEquals(poseidon.obj("package").hex("digest_hex"), transcript.take(32))
        transcript.finish()
        val paymentDigest = payment.hex("digest_hex")
        assertContentEquals(
            paymentDigest,
            receiptField(receiptBody("Receive receipt binding the Payment digest"), RECEIPT_PAYMENT_DIGEST),
        )
        assertContentEquals(ByteArray(32), receiptField(receiptBody("Send receipt"), RECEIPT_PAYMENT_DIGEST))

        // The Credited digest P_bytes(kgwcrdd1, LE16 version || tag evidence || credit_id ||
        // payment_digest || evidence digest) of both forms (owner answer A3).
        val credited = largeInputs("kgwcrdd1")
        assertEquals(2, credited.size)
        for ((index, form) in credited.withIndex()) {
            val body = form.hex("body_hex")
            assertEquals(99, body.size, form.text("object"))
            assertContentEquals(byteArrayOf(1, 0, (index + 1).toByte()), body.copyOf(3), form.text("object"))
            assertContentEquals(creditIdValue, body.copyOfRange(3, 35), form.text("object"))
            assertContentEquals(paymentDigest, body.copyOfRange(35, 67), form.text("object"))
        }
        // Receive form carries its opaque Poseidon package digest; Kotlin never substitutes SHA.
        assertPoseidonValue(credited[0].hex("body_hex").copyOfRange(67, 99), "Receive package digest")
        // Status form: the evidence digest is the credit-status digest.
        assertContentEquals(largeInput("kgwcsts1").hex("digest_hex"), credited[1].hex("body_hex").copyOfRange(67, 99))

        // Map values: domains, keys, element lists and opaque values.
        val values = poseidon.obj("map_values")
        val valueDomains = mapOf(
            "consumed_credit" to "kgwccrd1",
            "pending_outgoing" to "kgwpout1",
            "load" to "kgwload1",
            "redeem" to "kgwrdm_1",
            "fee_claim" to "kgwfee_1",
        )
        assertEquals(valueDomains.keys, values.keys)
        for ((name, domain) in valueDomains) {
            val value = values.obj(name)
            assertEquals(domain, value.text("domain"), name)
            assertCanonicalField(value.hex("key_hex"), nonzero = true)
            for (element in items(value, "items")) assertCanonicalField(element, nonzero = false)
            assertPoseidonValue(value.hex("digest_hex"), name)
        }
        // The credit maps are keyed by credit_id and carry the field_encodings value lists.
        val encodings = vectors.obj("field_encodings")
        for (name in listOf("consumed_credit", "pending_outgoing", "fee_claim")) {
            val value = values.obj(name)
            assertContentEquals(creditIdValue, value.hex("key_hex"), name)
            assertElements(items(encodings, "${name}_value"), items(value, "items"), name)
        }
        // One load/redeem recovery map keyed by kind · 2^128 + ordinal (Load 1, Redeem 2; owner
        // answer Q3).
        val load = values.obj("load")
        val loadItems = items(load, "items")
        assertEquals(3, loadItems.size)
        assertContentEquals(mapKey(1, loadItems[0]), load.hex("key_hex"))
        assertPoseidonValue(loadItems[1], "ordinary receipt digest")
        val redeem = values.obj("redeem")
        val redeemItems = items(redeem, "items")
        assertEquals(4, redeemItems.size)
        assertContentEquals(mapKey(2, redeemItems[0]), redeem.hex("key_hex"))
        val nullifier = poseidon.obj("unload_nullifier")
        assertEquals("kgwnull1", nullifier.text("domain"))
        val nullifierItems = items(nullifier, "items")
        assertEquals(5, nullifierItems.size)
        assertElements(limbs(digestVector("scheme").hex("digest_hex")), nullifierItems.take(2), "nullifier scheme")
        // The standalone nullifier uses the payer wallet and ordinal 2; recovery uses 0.
        val requestFields = recordFields(recordFields(envelopeMessage(envelope("Request")))[0])
        assertElements(limbs(requestFields[REQUEST_PAYER_WALLET]), nullifierItems.subList(2, 4), "nullifier wallet")
        assertContentEquals(u64Element(2), nullifierItems[4], "standalone unload ordinal")
        assertPoseidonValue(nullifier.hex("digest_hex"), "unload nullifier")
        assertPoseidonValue(redeemItems[1], "recovery nullifier")
        assertTrue(unsignedElement(redeemItems[3]) <= unsignedElement(redeemItems[2]), "online charge within amount")

    }

    @Test fun `indexed-tree insertions openings update and removal link sorted leaves`() {
        // Every map is a depth-32 Poseidon indexed Merkle tree (owner answer A2): sorted linked
        // leaves (key, value, next_key), an empty slot is zero, and the empty tree is the zero
        // sentinel leaf in slot 0.
        val tree = poseidon.obj("indexed_tree")
        assertContentEquals(ByteArray(32), tree.hex("empty_slot_hex"))
        val sentinel = tree.obj("sentinel_leaf")
        assertEquals("kgwimlf1", sentinel.text("domain"))
        assertElements(List(3) { ByteArray(32) }, items(sentinel, "items"), "sentinel leaf")
        assertPoseidonValue(sentinel.hex("digest_hex"), "sentinel leaf")
        val heightOne = tree.obj("empty_subtree_height_1")
        assertEquals("kgwimnd1", heightOne.text("domain"))
        assertElements(List(2) { ByteArray(32) }, items(heightOne, "items"), "empty subtree")
        assertPoseidonValue(heightOne.hex("digest_hex"), "empty subtree of height 1")
        assertPoseidonValue(tree.hex("empty_root_hex"), "empty root")
        val empties = EmptySubtrees(heightOne.hex("digest_hex"))
        val values = poseidon.obj("map_values")

        // Successive insertions write the next free slots 1, 2, 3: the low leaf that brackets the
        // new key is relinked to it, then the new leaf takes the low leaf's old next key.
        val insertions = tree.array("load_redeem_insertions").map { it.jsonObject }
        assertEquals(3, insertions.size)
        var root = tree.hex("empty_root_hex")
        for ((index, insertion) in insertions.withIndex()) {
            val slot = index + 1
            val label = "insertion at slot $slot"
            assertEquals(slot, insertion.int("slot"), label)
            assertContentEquals(root, insertion.hex("old_root_hex"), label)
            val key = insertion.hex("key_hex")
            val low = insertion.obj("low")
            assertContentEquals(root, low.hex("root_hex"), label)
            val lowLeaf = assertLeafOpening(low, slot - 1L, empties, "$label low leaf")
            assertBrackets(lowLeaf, key, label)
            val linked = insertion.obj("linked_low")
            assertContentEquals(lowLeaf.key, linked.hex("key_hex"), label)
            assertContentEquals(lowLeaf.value, linked.hex("value_hex"), label)
            assertContentEquals(key, linked.hex("next_key_hex"), label)
            assertPoseidonValue(linked.hex("leaf_hex"), label)
            assertPoseidonValue(insertion.hex("intermediate_root_hex"), label)
            val empty = insertion.obj("empty_slot_opening")
            val emptySiblings = assertEmptySlotOpening(empty, slot, slot - 1L, empties, label)
            // The relinked low leaf sits beside the written slot when their slots are siblings.
            if (lowLeaf.slot == (slot xor 1)) assertContentEquals(linked.hex("leaf_hex"), emptySiblings[0], label)
            val leaf = insertion.obj("leaf")
            assertContentEquals(key, leaf.hex("key_hex"), label)
            assertContentEquals(insertion.hex("value_hex"), leaf.hex("value_hex"), label)
            assertContentEquals(lowLeaf.nextKey, leaf.hex("next_key_hex"), label)
            assertPoseidonValue(leaf.hex("leaf_hex"), label)
            root = insertion.hex("root_hex")
            assertPoseidonValue(root, label)
        }
        // The recovery map receives the Redeem and Load values of the map_values section.
        assertContentEquals(values.obj("redeem").hex("key_hex"), insertions[0].hex("key_hex"))
        assertContentEquals(values.obj("redeem").hex("digest_hex"), insertions[0].hex("value_hex"))
        assertContentEquals(values.obj("load").hex("key_hex"), insertions[1].hex("key_hex"))
        assertContentEquals(values.obj("load").hex("digest_hex"), insertions[1].hex("value_hex"))
        assertContentEquals(mapKey(1, fieldBytes(BigInteger.ONE)), insertions[2].hex("key_hex"))

        // Membership opens the leaf at its slot; non-membership opens the low leaf whose key and
        // next key bracket the absent key: through the sentinel, an interior leaf and the largest.
        val membership = tree.obj("membership")
        assertContentEquals(root, membership.hex("root_hex"))
        val member = assertLeafOpening(membership, 3L, empties, "membership")
        assertContentEquals(values.obj("load").hex("key_hex"), member.key)
        assertContentEquals(values.obj("load").hex("digest_hex"), member.value)
        val presentKeys = insertions.map { hexText(it.hex("key_hex")) }.toSet()
        val absences = listOf(
            "non_membership_through_sentinel",
            "non_membership_through_interior_low_leaf",
            "non_membership_above_the_largest_key",
        )
        val lows = absences.map { name ->
            val vector = tree.obj(name)
            val absent = vector.hex("absent_key_hex")
            assertFalse(hexText(absent) in presentKeys, name)
            val low = vector.obj("low")
            assertContentEquals(root, low.hex("root_hex"), name)
            assertLeafOpening(low, 3L, empties, name).also { assertBrackets(it, absent, name) }
        }
        assertContentEquals(ByteArray(32), lows[0].key, "the sentinel is the low leaf below every key")
        assertEquals(0, lows[0].slot)
        assertFalse(lows[1].key.all { it.toInt() == 0 } || lows[1].nextKey.all { it.toInt() == 0 }, "interior low leaf")
        assertContentEquals(ByteArray(32), lows[2].nextKey, "the largest key has a zero next key")

        // A removal unlinks the leaf from its predecessor, then clears its slot; slots are not
        // reused, so the next free slot stays above it.
        val removal = tree.obj("pending_outgoing_removal")
        val removedKey = removal.hex("removed_key_hex")
        assertContentEquals(poseidon.obj("credit_id").obj("poseidon").hex("digest_hex"), removedKey)
        val nextFree = removal.int("next_free_slot")
        val predecessorVector = removal.obj("predecessor")
        assertContentEquals(removal.hex("old_root_hex"), predecessorVector.hex("root_hex"))
        val predecessor = assertLeafOpening(predecessorVector, nextFree - 1L, empties, "removal predecessor")
        assertContentEquals(removedKey, predecessor.nextKey)
        val removedVector = removal.obj("removed")
        assertContentEquals(removal.hex("intermediate_root_hex"), removedVector.hex("root_hex"))
        val removed = assertLeafOpening(removedVector, nextFree - 1L, empties, "removed leaf")
        assertContentEquals(removedKey, removed.key)
        assertContentEquals(values.obj("pending_outgoing").hex("digest_hex"), removed.value)
        assertTrue(removed.slot < nextFree && predecessor.slot < nextFree)
        val relinked = removal.obj("relinked_predecessor")
        assertContentEquals(predecessor.key, relinked.hex("key_hex"))
        assertContentEquals(predecessor.value, relinked.hex("value_hex"))
        assertContentEquals(removed.nextKey, relinked.hex("next_key_hex"))
        assertPoseidonValue(removal.hex("root_hex"), "root after removal")

        // Every learned empty subtree is one value per height across all openings.
        assertEquals(KagemushaWalletWireV1.INDEXED_TREE_DEPTH, empties.size, "an empty subtree at every height")
    }

    @Test fun `quota usage charges its aligned depth-six array slot`() {
        val array = poseidon.obj("quota_usage_array")
        assertEquals(6, array.int("depth"))
        assertEquals(64, array.int("slots"))
        val leaves = items(array, "leaf_values")
        assertEquals(64, leaves.size)
        val usage = array.obj("usage")
        val charged = array.obj("charged_usage")
        assertEquals("kgwquse1", usage.text("domain"))
        assertEquals("kgwquse1", charged.text("domain"))
        val before = items(usage, "items")
        val after = items(charged, "items")
        assertEquals(4, before.size)
        assertElements(before.take(3), after.take(3), "window stays fixed")
        assertEquals(unsignedElement(before[3]) + array.text("gross").toLong(), unsignedElement(after[3]))
        val window = items(array.obj("window"), "items")
        assertElements(window.take(3), before.take(3), "usage and window align")
        assertTrue(unsignedElement(after[3]) <= unsignedElement(window[3]))
        assertContentEquals(usage.hex("digest_hex"), leaves[0])
        val padding = array.obj("padding_leaf")
        assertElements(List(4) { ByteArray(32) }, items(padding, "items"), "padding")
        for (leaf in leaves.drop(2)) assertContentEquals(padding.hex("digest_hex"), leaf)
        val node = array.obj("padding_node_height_1")
        assertEquals("kgwqusn1", node.text("domain"))
        assertElements(List(2) { padding.hex("digest_hex") }, items(node, "items"), "padding node")
        for ((name, slot) in listOf("usage_opening" to 0, "window_opening" to 0, "padding_opening" to 63)) {
            val opening = array.obj(name)
            assertEquals(slot, opening.int("slot"))
            val siblings = items(opening, "siblings")
            assertEquals(6, siblings.size)
            for (value in siblings) assertPoseidonValue(value, name)
        }
        for (name in listOf("old_root_hex", "root_hex", "empty_root_hex", "windows_root_hex")) {
            assertPoseidonValue(array.hex(name), name)
        }
        assertFalse(array.hex("old_root_hex").contentEquals(array.hex("root_hex")))
        assertFalse(usage.hex("digest_hex").contentEquals(charged.hex("digest_hex")))
    }

    @Test fun `the CreditStatus credit-digest opening is a fixed 32-sibling leaf opening`() {
        // The credit-digest value P(kgwcdig1, [credit_id, payment_digest, burned]) keyed by
        // credit_id in the depth-32 indexed credit-digest tree (owner answers Q7 and A2).
        val creditOpening = poseidon.obj("credit_digest_opening")
        val creditId = poseidon.obj("credit_id").obj("poseidon").hex("digest_hex")
        val paymentDigest = largeInput("kgwpay_1").hex("digest_hex")
        val value = creditOpening.obj("value")
        assertEquals("kgwcdig1", value.text("domain"))
        assertContentEquals(creditId, value.hex("key_hex"))
        assertElements(items(vectors.obj("field_encodings"), "credit_digest_value"), items(value, "items"), "value")
        assertElements(listOf(creditId, paymentDigest, ByteArray(32)), items(value, "items"), "value elements")
        assertPoseidonValue(value.hex("digest_hex"), "credit-digest value")
        val membership = creditOpening.obj("membership")
        val leaf = assertLeafOpening(membership, null, null, "credit-digest membership")
        assertContentEquals(creditId, leaf.key)
        assertContentEquals(value.hex("digest_hex"), leaf.value)
        assertTrue(leaf.slot >= 1, "slot 0 holds only the sentinel")

        // Its credit-opening transcript (1,125): credit_id || payment_digest || u8 burned ||
        // next_key || LE32 slot || 32 siblings; the credit-opening digest packs it.
        val opening = creditOpening.hex("credit_opening_hex")
        assertEquals(KagemushaWalletWireV1.CREDIT_OPENING_BYTES, opening.size)
        val body = Transcript(opening)
        assertContentEquals(creditId, body.take(32))
        assertContentEquals(paymentDigest, body.take(32))
        assertEquals(unsignedElement(items(value, "items")[2]), body.unsigned(1))
        assertContentEquals(leaf.nextKey, body.take(32))
        assertEquals(leaf.slot.toLong(), body.unsigned(4))
        for (sibling in leaf.siblings) assertContentEquals(sibling, body.take(32))
        body.finish()
        assertContentEquals(opening, largeInput("kgwcopn1").hex("body_hex"))

        // The Credited::Status envelope carries this opening against Ω(h)'s credit_digest_root,
        // and Ω(h) names the Request's receiver by wallet_id and payment key (owner answer Q8).
        val credited = recordFields(envelopeMessage(envelope("Credited::Status")))
        assertEquals(3, credited.size)
        val evidence = credited[2]
        assertEquals(2, readIntLe(evidence, 0), "Credited evidence Status")
        val status = recordFields(recordFields(evidence.copyOfRange(4, evidence.size)).single())
        assertEquals(6, status.size)
        val carried = recordFields(status[5])
        assertEquals(6, carried.size)
        assertContentEquals(creditId, carried[0])
        assertContentEquals(paymentDigest, carried[1])
        assertContentEquals(byteArrayOf(unsignedElement(items(value, "items")[2]).toByte()), carried[2])
        assertContentEquals(leaf.nextKey, carried[3])
        assertEquals(leaf.slot, readIntLe(carried[4], 0))
        assertEquals(4, carried[4].size)
        assertEquals((KagemushaWalletWireV1.INDEXED_TREE_DEPTH * 32).toLong(), readLongLe(carried[5], 0))
        assertContentEquals(
            leaf.siblings.fold(ByteArray(0)) { all, next -> all + next },
            carried[5].copyOfRange(8, carried[5].size),
        )
        val omega = recordFields(recordFields(status[4])[0])
        assertEquals(13, omega.size)
        assertContentEquals(membership.hex("root_hex"), omega[12], "Ω(h) credit_digest_root")
        val requestBody = recordFields(recordFields(envelopeMessage(envelope("Request")))[0])
        assertContentEquals(requestBody[REQUEST_RECEIVER_WALLET], omega[4], "Ω(h) wallet is the Request receiver")
        assertContentEquals(key("receiver_payment"), omega[6], "Ω(h) payment key is the receiver's")
        assertPoseidonValue(status[2], "CreditStatus proof_digest")

        // The credit-status transcript (162): LE16 version || statement_digest || proof_digest ||
        // receipt_digest || lineage_digest || opening_digest; its lineage digest is the P_bytes
        // value of Ω(h)'s bytes and its opening digest the credit-opening digest.
        val creditStatus = Transcript(largeInput("kgwcsts1").hex("body_hex"))
        assertEquals(KagemushaWalletWireV1.VERSION.toLong(), creditStatus.unsigned(2))
        creditStatus.take(32)
        assertContentEquals(status[2], creditStatus.take(32))
        creditStatus.take(32)
        assertPoseidonValue(creditStatus.take(32), "Ω(h) lineage digest")
        assertContentEquals(largeInput("kgwcopn1").hex("digest_hex"), creditStatus.take(32))
        creditStatus.finish()
    }

    @Test fun `blacklist and quota-window Poseidon trees bind the vectored policy objects`() {
        // Blacklist frame {body, signature, entries: [{account_digest}]}.
        val list = recordFields(objectPayload("KagemushaWalletBlacklistV1", "3 entries"))
        assertEquals(3, list.size)
        val body = recordFields(list[0])
        assertEquals(7, body.size)
        val entries = vecElements(list[2]).map { recordFields(it).single() }
        assertEquals(readIntLe(body[4], 0), entries.size)
        // Entries ascend in limb order (owner answer A4), here unlike their unsigned byte order.
        val blacklist = poseidon.obj("blacklist")
        assertTrue(blacklist.text("order").startsWith("limb order"), blacklist.text("order"))
        assertElements(items(blacklist, "entries"), entries, "frame entries in limb order")
        for (index in 1 until entries.size) assertTrue(compareLimbs(entries[index - 1], entries[index]) < 0)
        val byteOrder = items(blacklist, "entries_in_unsigned_byte_order")
        assertElements(entries.sortedWith { left, right -> compareUnsigned(left, right) }, byteOrder, "byte order")
        assertFalse(byteOrder.map { hexText(it) } == entries.map { hexText(it) }, "the orders differ")
        val root = blacklist.hex("entries_root_hex")
        assertPoseidonValue(root, "blacklist root")
        assertContentEquals(root, body[5])
        assertContentEquals(root, signedBody("blacklist").copyOfRange(54, 86))
        assertEquals(entries.size, readIntLe(signedBody("blacklist"), 50))

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

        // A non-membership witness: one gap leaf with lower < x < upper in limb order and its 16
        // siblings. The byte order would not bracket this account.
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
        val lower = gap.hex("lower_hex")
        val upper = gap.hex("upper_hex")
        assertContentEquals(entries[index - 1], lower)
        assertContentEquals(entries[index], upper)
        assertTrue(compareLimbs(lower, account) < 0, "lower < account")
        assertTrue(compareLimbs(account, upper) < 0, "account < upper")
        assertFalse(compareUnsigned(lower, account) < 0 && compareUnsigned(account, upper) < 0, "byte order differs")
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
        // The quota-usage value counts against the first window.
        val usage = items(poseidon.obj("quota_usage_array").obj("usage"), "items")
        assertElements(windows[0].subList(0, 3), usage.subList(0, 3), "usage window")
        assertTrue(unsignedElement(usage[3]) <= unsignedElement(windows[0][3]), "usage within limit")
    }

    @Test fun `the separate lineage proof cap fills the indexed Credited Status frame`() {
        val original = envelope("Credited::Status")
        fun withProofBytes(length: Int): ByteArray {
            val credited = recordFields(envelopeMessage(original)).toMutableList()
            val status = recordFields(recordFields(credited[2].copyOfRange(4, credited[2].size)).single()).toMutableList()
            val lineage = recordFields(status[4]).toMutableList()
            val proofCount = ByteArray(8) { index -> (length.toLong() ushr (8 * index)).toByte() }
            lineage[1] = proofCount + ByteArray(length) { (it % 251).toByte() }
            status[4] = encodeRecord(lineage)
            credited[2] = le32(2) + encodeRecord(listOf(encodeRecord(status)))
            return envelopeWithMessage(KagemushaWalletMessageKindV1.CREDITED, encodeRecord(credited))
        }
        val atCap = withProofBytes(KagemushaWalletWireV1.LINEAGE_PROOF_CAP_BYTES)
        assertEquals(KagemushaWalletWireV1.MESSAGE_MAX_BYTES, atCap.size)
        assertEquals(KagemushaWalletMessageKindV1.CREDITED, KagemushaWalletWireV1.inspectEnvelope(atCap).kind)
        val overCap = withProofBytes(KagemushaWalletWireV1.LINEAGE_PROOF_CAP_BYTES + 1)
        assertEquals(KagemushaWalletWireV1.MESSAGE_MAX_BYTES + 1, overCap.size)
        assertFailsWith<IllegalArgumentException> { KagemushaWalletWireV1.inspectEnvelope(overCap) }
        assertTrue(KagemushaWalletWireV1.LINEAGE_PROOF_CAP_BYTES < KagemushaWalletWireV1.PAYMENT_PROOF_BUDGET_BYTES)
    }


    @Test fun `the verifying-key allowlist binds the manifest and every vectored proof length`() {
        // Frame {version, steps: [{kind, enabled_controls, verifying_key_digest, proof_bytes}],
        // lineage_verifying_key_digest, lineage_proof_bytes} (owner answers Q6 and Q11).
        val frame = objectVector("KagemushaWalletVerifyingKeyAllowlistV1", "stand-in keys")
        assertTrue(frame.size <= KagemushaWalletWireV1.VERIFYING_KEY_ALLOWLIST_MAX_BYTES)
        val allowlist = recordFields(objectPayload("KagemushaWalletVerifyingKeyAllowlistV1", "stand-in keys"))
        assertEquals(4, allowlist.size)
        assertContentEquals(byteArrayOf(1, 0), allowlist[0])
        val steps = vecElements(allowlist[1]).map { recordFields(it).also { entry -> assertEquals(4, entry.size) } }
        assertTrue(steps.size in 8..KagemushaWalletWireV1.VERIFYING_KEY_ENTRIES_MAX)
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
            assertEquals(0, mask and 0b111.inv(), "defined control bits only")
            // A nonzero mask selects Send, or Receive with exactly the blacklist bit.
            assertTrue(
                mask == 0 || tag == SEND_TAG || (tag == RECEIVE_TAG && mask == BLACKLIST_CONTROL),
                "selector $tag/$mask",
            )
            assertTrue(proofBytes in 1..KagemushaWalletWireV1.MESSAGE_MAX_BYTES)
            if (tag == RECEIVE_TAG) {
                assertTrue(proofBytes <= KagemushaWalletWireV1.CREDITED_RECEIVE_PROOF_BUDGET_BYTES)
            }
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
        // Strictly ascending selectors, every operation with the empty mask, and the Receive
        // blacklist selector exactly when some Send mask has the blacklist bit.
        assertEquals(selectors.sortedWith(compareBy({ it.first }, { it.second })), selectors)
        assertEquals(selectors.size, selectors.toSet().size)
        for (tag in 1..8) assertTrue(selectors.contains(tag to 0), "operation $tag")
        assertEquals(
            selectors.any { it.first == SEND_TAG && it.second and BLACKLIST_CONTROL != 0 },
            selectors.contains(RECEIVE_TAG to BLACKLIST_CONTROL),
        )
        assertTrue(lineageKey.all { unsigned(it) == 0xc4 }, "stand-in Ω transport key")
        val largestSend = selectors.filter { it.first == SEND_TAG }.maxOf { lengths.getValue(it) }
        assertTrue(lineageProofBytes + largestSend <= KagemushaWalletWireV1.PAYMENT_PROOF_BUDGET_BYTES, "R9 budget")
        assertTrue(lineageProofBytes in 1..KagemushaWalletWireV1.LINEAGE_PROOF_CAP_BYTES, "Ω cap")

        val vector = poseidon.obj("verifying_key_set")
        assertContentEquals(transcript.toByteArray(), vector.hex("transcript_hex"))
        assertEquals(42 + 41 * steps.size, transcript.size())
        assertContentEquals(digestVector("verifying-key-set").hex("body_hex"), vector.hex("transcript_hex"))
        val setDigest = KagemushaWalletWireV1.digest(KagemushaWalletDigestRoleV1.VERIFYING_KEY_SET, transcript.toByteArray())
        assertContentEquals(setDigest, vector.hex("digest_hex"))

        // The vectors are self-consistent (defect d1): the relation identity and the signed
        // artifact manifest bind this computed digest, so the allowlist decodes against the
        // manifest; no separate stand-in digest exists.
        assertContentEquals(setDigest, vector.hex("manifest_verifying_key_set_digest_hex"))
        assertFalse(standIns.containsKey("verifying_key_set_digest_hex"))
        val relation = digestVector("relation").hex("body_hex")
        assertEquals(162, relation.size)
        assertContentEquals(setDigest, relation.copyOfRange(98, 130), "relation binds the allowlist")
        val manifest = signedBody("artifact manifest")
        assertEquals(KagemushaWalletSigningDomainV1.ARTIFACT_MANIFEST.transcriptBytes, manifest.size)
        assertContentEquals(digestVector("relation").hex("digest_hex"), manifest.copyOfRange(34, 66))
        assertContentEquals(relation.copyOfRange(2, 98), manifest.copyOfRange(66, 162), "manifest bindings")
        assertContentEquals(setDigest, manifest.copyOfRange(162, 194), "manifest binds the allowlist")
        assertContentEquals(relation.copyOfRange(130, 162), manifest.copyOfRange(194, 226), "artifact inventory")
        val manifestFrame = recordFields(recordFields(objectPayload("KagemushaWalletArtifactManifestV1", ""))[0])
        assertContentEquals(setDigest, manifestFrame[6], "manifest frame binds the allowlist")

        // Every vectored package has exactly its selector's σ length, and every Ω(pred) the
        // allowlist's transport length (defect d2): σ_send by Ω's mask, σ_recv by the statement's
        // blacklist bit, every other operation by its tag.
        val payment = recordFields(envelopeMessage(envelope("Payment")))
        val creditedReceive = recordFields(envelopeMessage(envelope("Credited::Receive")))[2]
        val packages = listOf(
            "Payment envelope Send" to payment[4],
            "Credited::Receive" to recordFields(creditedReceive.copyOfRange(4, creditedReceive.size)).single(),
            "Payment object Send" to recordFields(objectPayload("KagemushaWalletPaymentV1", "fee, Ω(pred)"))[4],
            "Receive package object" to objectPayload("KagemushaWalletPackageV1", "Receive"),
            "Unload claim" to recordFields(objectPayload("KagemushaWalletUnloadClaimV1", "quoted"))[2],
            "Close loads Retiring" to recordFields(objectPayload("KagemushaWalletCloseLoadsV1", ""))[3],
            "Fee claim Send" to recordFields(recordFields(objectPayload("KagemushaWalletFeeClaimV1", ""))[1])[4],
            "Activation Bootstrap" to recordFields(objectPayload("KagemushaWalletActivationV1", ""))[3],
        )
        val omegas = ArrayList<Pair<String, ByteArray>>()
        for ((label, record) in packages) {
            val proofs = packageProofs(record)
            assertEquals(lengths[proofs.tag to proofs.mask], proofs.sigma.size, "$label σ")
            assertSigmaStandIn(proofs.sigma)
            assertEquals(proofs.tag in LINEAGE_CONSUMING_TAGS, proofs.omega != null, "$label Ω(pred) slot")
            proofs.omega?.let { omegas += label to it }
        }
        assertEquals(setOf(SEND_TAG, RECEIVE_TAG, 6, 8, 1), packages.map { packageProofs(it.second).tag }.toSet())
        // Ω carried alone: the Lineage message, the fold record and the CreditStatus Ω(h).
        omegas += "Lineage envelope" to omegaBytes(recordFields(envelopeMessage(envelope("Lineage")))[1])
        omegas += "fold record" to omegaBytes(recordFields(objectPayload("KagemushaWalletFoldRecordV1", "payer head 2"))[7])
        val status = recordFields(envelopeMessage(envelope("Credited::Status")))[2]
        val creditStatus = recordFields(recordFields(status.copyOfRange(4, status.size)).single())
        val statusOmega = omegaBytes(creditStatus[4])
        for ((label, omega) in omegas) {
            assertEquals(lineageProofBytes, omega.size - LINEAGE_PUBLIC_BYTES, "$label Ω length")
            val transport = omega.copyOfRange(LINEAGE_PUBLIC_BYTES, omega.size)
            assertTrue(transport.indices.all { unsigned(transport[it]) == (it + 7) % 251 }, "$label Ω rule")
        }
        assertEquals(lineageProofBytes, statusOmega.size - LINEAGE_PUBLIC_BYTES, "CreditStatus Ω(h) length")
        val statusTransport = statusOmega.copyOfRange(LINEAGE_PUBLIC_BYTES, statusOmega.size)
        assertTrue(statusTransport.indices.all { unsigned(statusTransport[it]) == (it + 11) % 251 }, "Ω(h) rule")

        // The large-input proof digests pack these same lengths.
        val (sendOmega, sendSigma) = le32Parts(largeInput("kgwprf_1").hex("body_hex"))
        assertEquals(lineageProofBytes, sendOmega.size - LINEAGE_PUBLIC_BYTES)
        assertEquals(lengths.getValue(SEND_TAG to readIntLe(sendOmega, LINEAGE_ENABLED_CONTROLS_OFFSET)), sendSigma.size)
        val receiveStatement = items(vectors.obj("field_encodings").obj("receive_statement"), "items")
        val receiveMask = unsignedElement(receiveStatement[STATEMENT_ENABLED_CONTROLS]).toInt() and BLACKLIST_CONTROL
        assertEquals(
            lengths.getValue(RECEIVE_TAG to receiveMask),
            le32Parts(largeInput("kgwstep1").hex("body_hex")).single().size,
        )
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

        /** Canonical envelope payload around a complete message record of [kind]. */
        fun envelopeWithMessage(kind: KagemushaWalletMessageKindV1, message: ByteArray): ByteArray {
            val tagged = le32(kind.wireTag) + Varint.encode(message.size.toLong()) + message
            return frameOf(byteArrayOf(2, 1, 0) + Varint.encode(tagged.size.toLong()) + tagged)
        }

        /** Complete compact-length record of [fields], preserving every field's exact bytes. */
        fun encodeRecord(fields: List<ByteArray>): ByteArray =
            fields.fold(ByteArray(0)) { all, field -> all + Varint.encode(field.size.toLong()) + field }

        /**
         * Pad an actual Rust envelope's last top-level message field to [frameLength], retaining
         * its own version and decode-time scheme path. The extra zero bytes are transport-only
         * filler: no typed message, signature or financial proof validity is claimed.
         */
        fun envelopeFrame(tag: Int, frameLength: Int): ByteArray {
            val vector = vectors.array("envelopes").map { it.jsonObject }.first { it.int("tag") == tag }
            val kind = assertNotNull(KagemushaWalletMessageKindV1.fromWireTag(tag))
            val fields = recordFields(envelopeMessage(vector.hex("canonical_hex"))).toMutableList()
            val last = fields.last()
            val overhead = NoritoHeader.HEADER_LENGTH + KagemushaWalletWireV1.ENVELOPE_PADDING_BYTES
            val prefixBytes = fields.dropLast(1).sumOf { Varint.encode(it.size.toLong()).size + it.size }
            var padding = 0
            while (true) {
                val lastLength = last.size + padding
                val variantLength = prefixBytes + Varint.encode(lastLength.toLong()).size + lastLength
                val messageLength = 4 + Varint.encode(variantLength.toLong()).size + variantLength
                val total = overhead + 3 + Varint.encode(messageLength.toLong()).size + messageLength
                if (total == frameLength) break
                check(total < frameLength) { "no envelope of exactly $frameLength bytes" }
                padding += 1
            }
            fields[fields.lastIndex] = last + ByteArray(padding)
            return envelopeWithMessage(kind, encodeRecord(fields))
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

        /** Effect elements per statement, zero-filled (the Send effect's nine). */
        const val EFFECT_ELEMENTS = 9

        /** `p` of the σ field, Pasta `Fp` (Vesta scalar field). */
        val FIELD_MODULUS: BigInteger =
            BigInteger("40000000000000000000000000000000224698fc094cf91b992d30ed00000001", 16)

        /**
         * The 59 Poseidon domain labels, in canonical declaration order: 33 state and protocol
         * domains, 16 signing domains and 10 signed-object domains.
         */
        val POSEIDON_DOMAINS: Map<String, String> = linkedMapOf(
            "core" to "kgwcore1",
            "rest" to "kgwrest1",
            "statement" to "kgwstmt1",
            "credit_id" to "kgwcrdt1",
            "send_chain" to "kgwschn1",
            "recv_chain" to "kgwrchn1",
            "consumed_credit_value" to "kgwccrd1",
            "pending_outgoing_value" to "kgwpout1",
            "load_value" to "kgwload1",
            "load_receipt" to "kgwolod1",
            "redeem_value" to "kgwrdm_1",
            "fee_claim_value" to "kgwfee_1",
            "blacklist_history_value" to "kgwbhst1",
            "certificate_set" to "kgwcset1",
            "package" to "kgwpkg_1",
            "nullifier" to "kgwnull1",
            "credit_digest_value" to "kgwcdig1",
            "indexed_leaf" to "kgwimlf1",
            "indexed_node" to "kgwimnd1",
            "blacklist_leaf" to "kgwblkl1",
            "blacklist_node" to "kgwblkn1",
            "quota_window_leaf" to "kgwqwin1",
            "quota_node" to "kgwqwnd1",
            "quota_usage_leaf" to "kgwquse1",
            "quota_usage_node" to "kgwqusn1",
            "proof_digest" to "kgwprf_1",
            "step_proof_digest" to "kgwstep1",
            "payment_digest" to "kgwpay_1",
            "lineage_digest" to "kgwlin_1",
            "credit_opening_digest" to "kgwcopn1",
            "credit_status_digest" to "kgwcsts1",
            "credited_digest" to "kgwcrdd1",
            "operation_id" to "kgwopid1",
            "signing_certificate" to "kgwcert1",
            "signing_credential" to "kgwcred1",
            "signing_renewal_challenge" to "kgwrnch1",
            "signing_renewal_key_binding" to "kgwrnkb1",
            "signing_artifact_manifest" to "kgwartf1",
            "signing_receipt" to "kgwrcpt1",
            "signing_scheme_policy" to "kgwspol1",
            "signing_fee_schedule" to "kgwfsch1",
            "signing_blacklist" to "kgwblst1",
            "signing_quota_share" to "kgwqshr1",
            "signing_time_anchor" to "kgwtanc1",
            "signing_charge_quote" to "kgwchgq1",
            "signing_offer" to "kgwoffr1",
            "signing_session_control" to "kgwsctl1",
            "signing_request" to "kgwrqst1",
            "signing_ledger_control" to "kgwlctl1",
            "object_certificate" to "kgwocrt1",
            "object_credential" to "kgwocrd1",
            "object_receipt" to "kgworcp1",
            "object_scheme_policy" to "kgwopol1",
            "object_fee_schedule" to "kgwofee1",
            "object_blacklist" to "kgwoblk1",
            "object_quota_share" to "kgwoqsh1",
            "object_time_anchor" to "kgwotim1",
            "object_charge_quote" to "kgwochg1",
            "object_request" to "kgworeq1",
        )

        /** Operation tags of Send and Receive (wire record section 3.2). */
        const val SEND_TAG = 3
        const val RECEIVE_TAG = 4

        /** Operation tags whose packages carry Ω(pred): Send, Unload and Retiring. */
        val LINEAGE_CONSUMING_TAGS: Set<Int> = setOf(SEND_TAG, 6, 8)

        /** Bit 0 of `enabled_controls`: BLACKLIST. */
        const val BLACKLIST_CONTROL = 1

        /** Position of `enabled_controls` among the 26 σ statement elements. */
        const val STATEMENT_ENABLED_CONTROLS = 11

        /** Request body fields (owner answer A5): the wallets and account digests. */
        const val REQUEST_PAYER_WALLET = 3
        const val REQUEST_PAYER_ACCOUNT = 4
        const val REQUEST_RECEIVER_WALLET = 5
        const val REQUEST_RECEIVER_ACCOUNT = 6

        /** Credential body fields: the wallet and the account digest. */
        const val CREDENTIAL_WALLET = 3
        const val CREDENTIAL_ACCOUNT = 4

        /** Receipt-body offsets of `proof_digest` and `payment_digest` (338-byte transcript). */
        const val RECEIPT_PROOF_DIGEST = 242
        const val RECEIPT_PAYMENT_DIGEST = 306

        /** Offset of `LE32 enabled_controls` in the Ω public transcript. */
        const val LINEAGE_ENABLED_CONTROLS_OFFSET = 236

        /**
         * Effect record layouts: `D` a SHA-256 identity (two limbs), `F` a Poseidon value,
         * and `I` an integer or unit-variant tag (one element).
         */
        val EFFECT_LAYOUTS: Map<Int, String> = mapOf(
            1 to "DD",
            2 to "FIII",
            3 to "FDIIIFII",
            4 to "FDI",
            5 to "FF",
            6 to "FIIIF",
            7 to "IFI",
            8 to "",
        )

        /**
         * Norito field layouts of the state core and rest: `I` an integer or unit-enum tag (one
         * element), `D` a SHA-256 digest or identifier (two limbs) and `F` a σ-field value (one
         * element). Scheme and asset are core fields and the blacklist age bound joined the core
         * (owner answers Q4 and Q5); the blacklist and quota-window roots are Poseidon values.
         */
        const val CORE_LAYOUT = "IDDDFIIIIIIFFFFFFFIFIIFIIIIIIF"
        const val REST_LAYOUT = "IFFFFIFF"

        /**
         * Request-body transcript layout of the 26 `credit_id` elements: `I<n>` an `n`-byte
         * little-endian integer (one element) and `D` a 32-byte digest or identifier (two limbs).
         */
        const val REQUEST_BODY_LAYOUT = "I2 D D D D D D I16 F I16 F I16 I8 F I8 I8 F F D"

        /** Frame name of the private state, which travels only inside a recovery capsule. */
        const val STATE_FRAME_NAME = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletStateV1"

        /** The single digest vector of [role]. */
        fun digestVector(role: String): JsonObject =
            vectors.array("digests").map { it.jsonObject }.single { it.text("role") == role }

        /** The large-input `P_bytes` digest vectors under [domain]. */
        fun largeInputs(domain: String): List<JsonObject> =
            poseidon.array("large_input_digests").map { it.jsonObject }.filter { it.text("domain") == domain }

        /** The single large-input `P_bytes` digest vector under [domain]. */
        fun largeInput(domain: String): JsonObject = largeInputs(domain).single()

        /** The signature vector of [objectName]. */
        fun signatureVector(objectName: String): JsonObject =
            vectors.array("signatures").map { it.jsonObject }.single { it.text("object") == objectName }

        /** Signing domain of signature [vector]. */
        fun signingDomain(vector: JsonObject): KagemushaWalletSigningDomainV1 =
            assertNotNull(KagemushaWalletSigningDomainV1.fromLabel(vector.text("domain")), vector.text("domain"))

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

        /** Path of the message's own version; unrelated nested versions stay typed-wallet scope. */
        fun versionPath(kind: KagemushaWalletMessageKindV1): List<Int> = when (kind) {
            KagemushaWalletMessageKindV1.OFFER, KagemushaWalletMessageKindV1.REQUEST -> listOf(0, 0)
            else -> listOf(0)
        }

        /** Confirm the rebuilt header, length and CRC without invoking admission of its message. */
        fun assertRebuiltEnvelopeHeader(frame: ByteArray) {
            val offset = NoritoHeader.HEADER_LENGTH + KagemushaWalletWireV1.ENVELOPE_PADDING_BYTES
            assertContentEquals(frame, frameOf(frame.copyOfRange(offset, frame.size)))
        }

        /** Rebuild enclosing record lengths and the outer CRC after editing a record at [path]. */
        fun withChangedMessageRecord(frame: ByteArray, path: List<Int>, edit: (ByteArray) -> ByteArray): ByteArray {
            fun changed(record: ByteArray, remaining: List<Int>): ByteArray {
                if (remaining.isEmpty()) return edit(record)
                val fields = recordFields(record).toMutableList()
                val index = remaining.first()
                fields[index] = changed(fields[index], remaining.drop(1))
                return encodeRecord(fields)
            }
            val offset = NoritoHeader.HEADER_LENGTH + KagemushaWalletWireV1.ENVELOPE_PADDING_BYTES
            val payload = frame.copyOfRange(offset, frame.size)
            val tagOffset = Varint.decode(payload, Varint.decode(payload, 0).nextOffset + 2).nextOffset
            val kind = assertNotNull(KagemushaWalletMessageKindV1.fromWireTag(readIntLe(payload, tagOffset)))
            return envelopeWithMessage(kind, changed(envelopeMessage(frame), path))
        }

        /** Replace exact field bytes, optionally with a deliberately malformed length prefix.
         * No inspection runs before the caller's expected rejection. */
        fun withReplacedMessageField(
            frame: ByteArray,
            path: List<Int>,
            replacement: ByteArray,
            lengthPrefix: ByteArray = Varint.encode(replacement.size.toLong()),
        ): ByteArray = withChangedMessageRecord(frame, path.dropLast(1)) { record ->
            recordFields(record).foldIndexed(ByteArray(0)) { index, all, field ->
                if (index == path.last()) all + lengthPrefix + replacement
                else all + Varint.encode(field.size.toLong()) + field
            }
        }

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

        /** Flip a nested fixed-length message field and refresh the complete envelope CRC. */
        fun withFlippedMessageField(frame: ByteArray, path: List<Int>): ByteArray {
            fun changed(record: ByteArray, remaining: List<Int>): ByteArray {
                val fields = recordFields(record).map { it.copyOf() }.toMutableList()
                val index = remaining.first()
                fields[index] = if (remaining.size == 1) {
                    fields[index].also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
                } else {
                    changed(fields[index], remaining.drop(1))
                }
                return encodeRecord(fields)
            }
            val bytes = frame.copyOf()
            val message = envelopeMessage(bytes)
            val updated = changed(message, path)
            check(message.size == updated.size)
            updated.copyInto(bytes, bytes.size - message.size)
            val crc = CRC64.compute(bytes.copyOfRange(48, bytes.size))
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

        /** σ public-input elements of a canonical statement record. */
        fun statementElements(record: ByteArray): List<ByteArray> {
            val fields = recordFields(record)
            assertEquals(14, fields.size)
            val elements = ArrayList<ByteArray>()
            elements.addAll(layoutElements(listOf(fields[0], fields[2], fields[1], fields[4], fields[3]), "IDDDF"))
            elements.addAll(layoutElements(fields.subList(5, 11), "IIIIIF"))
            for (commitment in fields.subList(11, 13)) {
                elements.add(recordFields(commitment).single().also { assertCanonicalField(it, nonzero = false) })
            }
            val tag = readIntLe(fields[13], 0)
            elements.add(u64Element(tag.toLong()))
            val effectFields = recordFields(fields[13].copyOfRange(4, fields[13].size))
            val effect = layoutElements(effectFields, EFFECT_LAYOUTS.getValue(tag))
            elements.addAll(effect)
            repeat(EFFECT_ELEMENTS - effect.size) { elements.add(ByteArray(32)) }
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

        /** Exact little-endian u16 version bytes for structural mutations. */
        fun le16(value: Int): ByteArray = ByteArray(2) { index -> (value ushr (8 * index)).toByte() }

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
                    token == "F" -> elements.add(reader.take(32).also { assertCanonicalField(it, nonzero = false) })
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

        /** Signed transcript of the signature vector [objectName], of its domain's exact length. */
        fun signedBody(objectName: String): ByteArray {
            val vector = signatureVector(objectName)
            return vector.hex("transcript_hex").also { assertEquals(signingDomain(vector).transcriptBytes, it.size) }
        }

        /** The exact Receipt transcript (338 bytes). */
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

        /** Limb order of two account digests: `hi · 2^128 + lo`, the 32 bytes read little-endian. */
        fun compareLimbs(left: ByteArray, right: ByteArray): Int {
            check(left.size == 32 && right.size == 32)
            return BigInteger(1, left.reversedArray()).compareTo(BigInteger(1, right.reversedArray()))
        }

        /** The canonical σ-field value [value] as an integer. */
        fun fieldInteger(value: ByteArray): BigInteger {
            assertCanonicalField(value, nonzero = false)
            return BigInteger(1, value.reversedArray())
        }

        /** One opened indexed-tree leaf `(key, value, next_key)` at [slot] with its siblings. */
        class LeafOpening(
            val key: ByteArray,
            val value: ByteArray,
            val nextKey: ByteArray,
            val slot: Int,
            val siblings: List<ByteArray>,
        )

        /** The 32 canonical siblings of an opening `{slot, siblings}`, height 0 first. */
        fun openingSiblings(opening: JsonObject, label: String): List<ByteArray> {
            val siblings = items(opening, "siblings")
            assertEquals(KagemushaWalletWireV1.INDEXED_TREE_DEPTH, siblings.size, "$label sibling count")
            for (sibling in siblings) assertCanonicalField(sibling, nonzero = false)
            return siblings
        }

        /**
         * Structural checks of one indexed-tree leaf opening `{leaf, opening, root_hex,
         * transcript_hex}`: canonical key, value and next key with `next_key = 0` or above the
         * key; a Poseidon leaf and root; exactly 32 siblings; and its transcript `key || value ||
         * next_key || LE32 slot || siblings` (1,124 bytes). With [empties], siblings over subtrees
         * entirely above [occupiedThrough] are the empty subtree of their height.
         */
        fun assertLeafOpening(
            vector: JsonObject,
            occupiedThrough: Long?,
            empties: EmptySubtrees?,
            label: String,
        ): LeafOpening {
            val leaf = vector.obj("leaf")
            val opening = vector.obj("opening")
            val key = leaf.hex("key_hex")
            val value = leaf.hex("value_hex")
            val nextKey = leaf.hex("next_key_hex")
            val next = fieldInteger(nextKey)
            assertTrue(next.signum() == 0 || next > fieldInteger(key), "$label next key above key")
            assertCanonicalField(value, nonzero = false)
            assertPoseidonValue(leaf.hex("leaf_hex"), "$label leaf")
            assertPoseidonValue(vector.hex("root_hex"), "$label root")
            val slot = opening.int("slot")
            val siblings = openingSiblings(opening, label)
            val transcript = Transcript(vector.hex("transcript_hex"))
            assertContentEquals(key, transcript.take(32), label)
            assertContentEquals(value, transcript.take(32), label)
            assertContentEquals(nextKey, transcript.take(32), label)
            assertEquals(slot.toLong(), transcript.unsigned(4), label)
            for (sibling in siblings) assertContentEquals(sibling, transcript.take(32), label)
            transcript.finish()
            assertEquals(LEAF_OPENING_BYTES, vector.hex("transcript_hex").size, label)
            if (empties != null && occupiedThrough != null) empties.check(slot, siblings, occupiedThrough, label)
            return LeafOpening(key, value, nextKey, slot, siblings)
        }

        /**
         * Structural checks of one empty-slot opening `{opening, transcript_hex}` of [slot]: its
         * transcript `LE32 slot || siblings` (1,028 bytes). Returns the siblings.
         */
        fun assertEmptySlotOpening(
            vector: JsonObject,
            slot: Int,
            occupiedThrough: Long,
            empties: EmptySubtrees,
            label: String,
        ): List<ByteArray> {
            val opening = vector.obj("opening")
            assertEquals(slot, opening.int("slot"), label)
            val siblings = openingSiblings(opening, label)
            val transcript = Transcript(vector.hex("transcript_hex"))
            assertEquals(slot.toLong(), transcript.unsigned(4), label)
            for (sibling in siblings) assertContentEquals(sibling, transcript.take(32), label)
            transcript.finish()
            assertEquals(EMPTY_SLOT_OPENING_BYTES, vector.hex("transcript_hex").size, label)
            empties.check(slot, siblings, occupiedThrough, "$label empty slot")
            return siblings
        }

        /** The low leaf [low] brackets the absent [key]: `low.key < key` and (`next = 0` or `key < next`). */
        fun assertBrackets(low: LeafOpening, key: ByteArray, label: String) {
            val absent = fieldInteger(key)
            assertTrue(absent.signum() != 0, "$label nonzero key")
            assertTrue(fieldInteger(low.key) < absent, "$label low key below")
            val next = fieldInteger(low.nextKey)
            assertTrue(next.signum() == 0 || absent < next, "$label next key above")
        }

        /** Exact leaf-opening transcript: key, value and next key, LE32 slot and 32 siblings. */
        const val LEAF_OPENING_BYTES = 3 * 32 + 4 + 32 * 32

        /** Exact empty-slot opening transcript: LE32 slot and 32 siblings. */
        const val EMPTY_SLOT_OPENING_BYTES = 4 + 32 * 32

        /** σ selector, σ bytes and Ω(pred) bytes of one Norito `Package` record. */
        class PackageProofs(val tag: Int, val mask: Int, val sigma: ByteArray, val omega: ByteArray?)

        /**
         * Proofs of a Package `{version, statement, lineage slot, step_proof, receipt}`: the
         * statement's effect tag, its σ selector mask (Send: `enabled_controls`; Receive: the
         * blacklist bit; otherwise 0), σ and Ω(pred) when the slot is Present.
         */
        fun packageProofs(record: ByteArray): PackageProofs {
            val fields = recordFields(record)
            assertEquals(5, fields.size, "package fields")
            val statement = recordFields(fields[1])
            assertEquals(14, statement.size, "statement fields")
            val tag = readIntLe(statement[13], 0)
            val controls = readIntLe(statement[8], 0)
            val slot = fields[2]
            val omega = when (readIntLe(slot, 0)) {
                0 -> null.also { assertEquals(4, slot.size, "None slot") }
                1 -> omegaBytes(recordFields(slot.copyOfRange(4, slot.size)).single())
                else -> error("unknown lineage slot")
            }
            val proof = recordFields(fields[3]).single()
            assertEquals((proof.size - 8).toLong(), readLongLe(proof, 0), "σ byte vector")
            val mask = when (tag) {
                SEND_TAG -> controls
                RECEIVE_TAG -> controls and BLACKLIST_CONTROL
                else -> 0
            }
            return PackageProofs(tag, mask, proof.copyOfRange(8, proof.size), omega)
        }

        fun readIntLe(bytes: ByteArray, offset: Int): Int =
            (0 until 4).fold(0) { value, index -> value or (unsigned(bytes[offset + index]) shl (8 * index)) }

        fun readLongLe(bytes: ByteArray, offset: Int): Long =
            (0 until 8).fold(0L) { value, index -> value or (unsigned(bytes[offset + index]).toLong() shl (8 * index)) }
    }

    /**
     * Empty subtree values learned per height across openings: height 0 is the empty slot (zero),
     * height 1 the vectored empty subtree, and every other height must agree across all openings.
     */
    private class EmptySubtrees(heightOne: ByteArray) {
        private val known = HashMap<Int, String>().apply {
            put(0, hexText(ByteArray(32)))
            put(1, hexText(heightOne))
        }

        /** Heights whose empty subtree is known. */
        val size: Int
            get() = known.size

        /**
         * Siblings of [slot] whose subtree lies entirely above [occupiedThrough] (the highest slot
         * ever written) are the empty subtree of their height.
         */
        fun check(slot: Int, siblings: List<ByteArray>, occupiedThrough: Long, label: String) {
            for ((height, sibling) in siblings.withIndex()) {
                val first = ((slot.toLong() ushr height) xor 1L) shl height
                if (first > occupiedThrough) {
                    val expected = known.getOrPut(height) { hexText(sibling) }
                    assertEquals(expected, hexText(sibling), "$label empty subtree at height $height")
                }
            }
        }
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
