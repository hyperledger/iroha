package org.hyperledger.iroha.sdk.offline.petal

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.hyperledger.iroha.sdk.offline.petal.PetalTestSupport.array
import org.hyperledger.iroha.sdk.offline.petal.PetalTestSupport.hexBytes
import org.hyperledger.iroha.sdk.offline.petal.PetalTestSupport.number
import org.hyperledger.iroha.sdk.offline.petal.PetalTestSupport.text

/** Same-frame averaging and bounded session intake, including independent Rust camera captures. */
class PetalMergeTest {
    private val options = PetalDecodeOptions.DEFAULT
    private fun encoder() = PetalStreamEncoder(PetalTestSupport.payload(700, 2), 2)
    private fun render(encoder: PetalStreamEncoder, frame: Int) = PetalTestSupport.renderLuma(encoder, frame, 768, 2)
    private fun evidence(image: PetalLuma, frame: PetalDecodedFrame) =
        assertNotNull(PetalDecoder.tileEvidence(image, frame, options, PetalWorkspace()))
    private fun merge(captures: Collection<PetalDecoder.TileEvidence>) =
        PetalDecoder.mergeTiles(captures, options, PetalWorkspace())
    private fun withLanes(
        pose: PetalDecodedFrame,
        p: PetalLaneResult? = null,
        k: PetalLaneResult? = null,
        d: PetalLaneResult? = null,
        inferred: Int? = pose.inferredCorner,
    ) = PetalDecodedFrame(pose.homography, pose.rotation, pose.mirrored, p, k, d, inferred)

    @Test
    fun oneCaptureReadsExactlyTheTileLanesTheDecoderRead() {
        val image = render(encoder(), 5)
        val shadow = image.data()
        for (y in 0 until image.height) for (x in image.width * 7 / 20 until image.width * 3 / 5) {
            val at = y * image.width + x
            shadow[at] = Math.round((shadow[at].toInt() and 0xFF) * 0.3).toByte()
        }
        val hidden = image.data()
        val scale = image.width / 1024.0
        for (y in 0 until image.height) for (x in 0 until image.width) {
            val dx = x + 0.5 - PetalLayout.finderCenterX(3) * scale
            val dy = y + 0.5 - PetalLayout.finderCenterY(3) * scale
            if (dx * dx + dy * dy <= 75.0 * scale * 75.0 * scale) hidden[y * image.width + x] = 0
        }
        val mirrored = ByteArray(hidden.size) { at -> hidden[(at / image.width) * image.width + image.width - 1 - at % image.width] }
        for ((name, data) in listOf("clean" to image.data(), "shadow" to shadow, "hidden" to hidden, "mirrored" to mirrored)) {
            val capture = assertNotNull(PetalLuma.fromRaw(image.width, image.height, data))
            val frame = assertNotNull(PetalDecoder.decode(capture).frame, name)
            assertNotNull(frame.p, name)
            assertNotNull(frame.k, name)
            val lanes = merge(listOf(evidence(capture, frame)))
            assertEquals(frame.p, lanes.p, "$name: P, including correction counts")
            assertEquals(frame.k, lanes.k, "$name: K, including correction counts")
        }
    }

    @Test
    fun averagingIndependentNoiseRecoversLanesNoCaptureReadsAlone() {
        val payload = ByteArray(300) { ((it.toLong() * 2_654_435_761L and 0xFFFF_FFFFL) ushr 11).toByte() }
        val encoder = PetalStreamEncoder(payload, 2)
        val image = render(encoder, 5)
        val h = PetalHomography(doubleArrayOf(0.75, 0.0, 0.0, 0.0, 0.75, 0.0, 0.0, 0.0, 1.0))
        val reference = assertNotNull(PetalDecoder.referenceLevels(image, h.m, PetalDecoder.NO_CORNER))
        val workspace = PetalWorkspace()
        PetalDecoder.samplePatches(image, h.m, workspace)
        val rng = PetalXorshift32(9)
        val captures = List(4) {
            val patches = workspace.patches.copyOf()
            for (cell in patches.indices) patches[cell] += (rng.nextByte().toDouble() - 127.5) * 3.0
            PetalDecoder.TileEvidence(patches, reference)
        }
        for (capture in captures) assertNull(merge(listOf(capture)).k, "one noisy capture must lose lane K")
        val lanes = merge(captures)
        assertContentEquals(encoder.laneData(5).p(), assertNotNull(lanes.p).data)
        assertContentEquals(encoder.laneData(5).k(), assertNotNull(lanes.k).data)
    }

    @Test
    fun evidenceRejectsUnusableImagesAndUnknownCornersAndOwnsItsScratch() {
        val image = render(encoder(), 5)
        val frame = assertNotNull(PetalDecoder.decode(image).frame)
        val workspace = PetalWorkspace()
        assertNull(PetalDecoder.tileEvidence(PetalLuma(20, 20), frame, options, workspace))
        assertNull(PetalDecoder.tileEvidence(PetalLuma(image.width, image.height), frame, options, workspace))
        for (corner in listOf(-1, 4, 255)) assertNull(PetalDecoder.tileEvidence(image, withLanes(frame, inferred = corner), options, workspace))
        val capture = assertNotNull(PetalDecoder.tileEvidence(image, frame, options, workspace))
        workspace.patches.fill(0.0)
        assertEquals(frame.p, merge(listOf(capture)).p, "later scratch reuse cannot change held evidence")
        assertNull(merge(emptyList()).p)
        assertNull(merge(emptyList()).k)
    }

    @Test
    fun sessionNeverOffersAnotherShownFramesTileLanes() {
        val encoder = encoder()
        val image = render(encoder, 11)
        val pose = assertNotNull(PetalDecoder.decode(image).frame)
        val torn = withLanes(pose, d = PetalLaneResult(encoder.laneData(10).d(), 0, 0))
        val session = PetalScanSession()
        repeat(3) { assertEquals("", session.merge(image, torn)) }
        assertEquals(2L, session.stats().merges)
        assertEquals(0L, session.stats().mergedP)
        assertEquals(0L, session.stats().mergedK)
        assertEquals(0L, session.progress().atomsReceived)
        val lanes = merge(session.held.first.evidence)
        assertContentEquals(encoder.laneData(11).p(), assertNotNull(lanes.p).data)
        assertContentEquals(encoder.laneData(11).k(), assertNotNull(lanes.k).data)
        assertEquals(10, session.held.first.shown.frame)
    }

    @Test
    fun tornUnkeyedAndUnrelatedTagCapturesNeverShareEvidence() {
        val encoder = encoder()
        val image = render(encoder, 11)
        val pose = assertNotNull(PetalDecoder.decode(image).frame)
        val session = PetalScanSession()
        val rings = PetalLaneResult(encoder.laneData(10).d(), 0, 0)
        assertEquals("", session.merge(image, withLanes(pose, p = pose.p, d = rings)))
        assertEquals("", session.merge(image, withLanes(pose)))
        assertTrue(session.held.isEmpty(), "torn and unkeyed captures are never held")
        session.merge(image, withLanes(pose, d = rings))
        val other = rings.data
        other[0] = (other[0].toInt() xor 1).toByte()
        session.merge(image, withLanes(pose, d = PetalLaneResult(other, 0, 0)))
        assertEquals(2, session.held.size, "different stream tags cannot share patches")
        assertEquals(0L, session.stats().merges)
    }

    @Test
    fun sessionHoldsOnlyFourCapturesOfSixShownFramesAndResetReleasesThem() {
        val encoder = encoder()
        val image = render(encoder, 11)
        val pose = assertNotNull(PetalDecoder.decode(image).frame)
        val session = PetalScanSession()
        fun rings(frame: Int) = withLanes(pose, d = PetalLaneResult(encoder.laneData(frame).d(), 0, 0))
        repeat(PetalScanSession.MERGE_CAPTURES + 2) { session.merge(image, rings(10)) }
        assertEquals(1, session.held.size)
        assertEquals(PetalScanSession.MERGE_CAPTURES, session.held.first.evidence.size)
        assertEquals((PetalScanSession.MERGE_CAPTURES + 1).toLong(), session.stats().merges)
        for (frame in 12 until 12 + PetalScanSession.MERGE_WINDOW) session.merge(image, rings(frame))
        assertEquals(PetalScanSession.MERGE_WINDOW, session.held.size)
        assertTrue(session.held.all { it.shown.frame >= 12 })
        session.reset()
        assertTrue(session.held.isEmpty())
    }

    @Test
    fun aShownFrameOnlyGainsMissingLanesAndReleasesEvidenceWhenComplete() {
        val encoder = encoder()
        val image = render(encoder, 5)
        val pose = assertNotNull(PetalDecoder.decode(image).frame)
        val session = PetalScanSession()
        val partial = withLanes(pose, p = pose.p, d = pose.d)
        assertEquals("", session.merge(image, partial))
        assertEquals("K", session.merge(image, partial))
        assertEquals(0L, session.stats().mergedP)
        assertEquals(1L, session.stats().mergedK)
        assertTrue(session.held.first.evidence.isEmpty())
        repeat(3) { assertEquals("", session.merge(image, partial)) }
        assertEquals(1L, session.stats().merges, "complete tile lanes are never merged or offered again")
    }

    /** A real beacon/atom lane with deterministic uncorrectable tile words. */
    private fun dOnly(encoder: PetalStreamEncoder, frame: Int): PetalLuma {
        val rng = PetalXorshift32(97)
        val cells = PetalFrameCells.fromWords(
            ByteArray(PetalLanes.P_WORD) { rng.nextByte().toByte() },
            ByteArray(PetalLanes.K_WORD) { rng.nextByte().toByte() },
            encoder.words(frame).d(),
        )
        return PetalRenderer.render(cells, PetalRenderOptions(768, 2)).toLuma().also {
            assertEquals("D", assertNotNull(PetalDecoder.decode(it).frame).lanes)
        }
    }

    @Test
    fun acceptedMetadataReplacementDropsSameTagSameFrameEvidenceAndDoneFlags() {
        // Independent review's two distinct 100-byte payloads whose CRC low byte is 61.
        val oldPayload = ByteArray(100).also { it[3] = 49 }
        val newPayload = ByteArray(100).also { it[3] = 128.toByte() }
        val old = PetalStreamEncoder(oldPayload, 2)
        val next = PetalStreamEncoder(newPayload, 2)
        assertEquals(61, old.meta.tag)
        assertEquals(old.meta.tag, next.meta.tag)
        assertTrue(old.meta != next.meta)
        val session = PetalScanSession()
        session.push(render(old, 0), 0)
        assertTrue(session.held.first.pDone && session.held.first.kDone)
        val image = dOnly(next, 0)
        session.push(image, 33)
        assertEquals(old.meta, session.progress().meta, "one conflicting beacon does not replace the stream")
        session.push(image, 66)
        assertEquals(next.meta, session.progress().meta)
        assertEquals(1, session.held.size)
        val fresh = session.held.first
        assertTrue(!fresh.pDone && !fresh.kDone, "the previous payload's done flags cannot suppress recovery")
        assertEquals(1, fresh.evidence.size, "no prior payload's patches survive replacement")
        val partial = assertNotNull(PetalDecoder.decode(image).frame)
        val recovered = StringBuilder()
        val clean = render(next, 0)
        repeat(PetalScanSession.MERGE_CAPTURES) { recovered.append(session.merge(clean, partial)) }
        assertEquals("PK", recovered.toString())
        assertContentEquals(newPayload, assertNotNull(session.push(render(next, 1), 99).completed).payload)
    }

    @Test
    fun theFirstBeaconPreservesEarlierUnidentifiedFrameEvidence() {
        val encoder = encoder()
        val session = PetalScanSession()
        session.push(dOnly(encoder, 1), 0)
        assertNull(session.progress().meta)
        val held = session.held.single()
        assertEquals(1, held.shown.frame)
        val earlier = held.evidence.single()
        session.push(dOnly(encoder, 0), 33)
        assertEquals(encoder.meta, session.progress().meta)
        val preserved = session.held.single { it.shown.frame == 1 }
        assertTrue(preserved === held && preserved.evidence.single() === earlier)
    }

    private val fixture by lazy { PetalTestSupport.loadFixture("petal_captures_v1.json") }

    private fun runFixture(set: JsonObject): Pair<String, PetalScanStats> {
        val name = set.text("name")
        val captures = ArrayList<PetalDecoder.TileEvidence>()
        val session = PetalScanSession()
        val merged = StringBuilder()
        for ((index, element) in set.array("captures").withIndex()) {
            val capture = element.jsonObject
            val image = assertNotNull(PetalLuma.fromRaw(
                set.number("width").toInt(), set.number("height").toInt(),
                PetalTestSupport.inflateBase64(capture.text("luma_zlib_base64")),
            ))
            val decoded = assertNotNull(PetalDecoder.decode(image).frame, "$name capture $index")
            assertEquals(capture.text("reference_decoded"), decoded.lanes, "$name capture $index lanes")
            assertTrue(capture.text("must_decode").all { it in decoded.lanes }, name)
            for (lane in PetalLane.values()) decoded.lane(lane)?.let {
                assertContentEquals(set.hexBytes("${lane.letter.lowercaseChar()}_data"), it.data, "$name $lane")
            }
            captures += evidence(image, decoded)
            merged.append(session.push(image, index * 33L).merged)
        }
        val lanes = merge(captures)
        val letters = (if (lanes.p != null) "P" else "") + (if (lanes.k != null) "K" else "")
        assertEquals(set.text("reference_merged"), letters, "$name mean lanes")
        lanes.p?.let { assertContentEquals(set.hexBytes("p_data"), it.data, "$name merged P") }
        lanes.k?.let { assertContentEquals(set.hexBytes("k_data"), it.data, "$name merged K") }
        assertTrue(session.stats().merges > 0, "$name must exercise averaging")
        return merged.toString() to session.stats()
    }

    @Test
    fun sharedNoisyAndBandedCapturesRecoverTheReferenceMissingLanes() {
        assertEquals(2, fixture.array("merges").size)
        for (element in fixture.array("merges")) {
            val set = element.jsonObject
            val (merged, stats) = runFixture(set)
            assertTrue(set.text("must_merge").all { it in merged }, "${set.text("name")}: $merged")
            assertEquals(merged.count { it == 'P' }.toLong(), stats.mergedP)
            assertEquals(merged.count { it == 'K' }.toLong(), stats.mergedK)
        }
    }

    @Test
    fun sharedMixedFrameCapturesNeverOfferTheOtherFramesLanes() {
        assertEquals(1, fixture.array("mixed_merges").size)
        for (element in fixture.array("mixed_merges")) {
            val (merged, stats) = runFixture(element.jsonObject)
            assertEquals("", merged)
            assertEquals(0L, stats.mergedP)
            assertEquals(0L, stats.mergedK)
        }
    }
}
