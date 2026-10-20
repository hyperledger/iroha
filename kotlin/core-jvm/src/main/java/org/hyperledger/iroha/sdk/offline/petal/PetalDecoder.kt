package org.hyperledger.iroha.sdk.offline.petal

import java.util.Arrays

/**
 * Decoder tuning. Immutable and thread-safe.
 *
 * @param tryMirrored also try horizontally mirrored images (front-camera previews).
 * @param templateSigmas the five blur widths (in template cells) tried for glyph matching.
 * @param maxPixels largest image (in pixels) the decoder accepts; larger frames
 *   should be downscaled by the caller. Bounds memory and work on hostile input.
 */
class PetalDecodeOptions @JvmOverloads constructor(
    /** Whether horizontally mirrored images are tried too. */
    val tryMirrored: Boolean = true,
    templateSigmas: DoubleArray = doubleArrayOf(0.0, 0.5, 0.8, 1.1, 1.5),
    /** Largest accepted image area in pixels. */
    val maxPixels: Int = 12_000_000,
) {
    private val sigmas = templateSigmas.copyOf()

    init {
        require(sigmas.size == TEMPLATE_SIGMA_COUNT) { "exactly $TEMPLATE_SIGMA_COUNT template sigmas are required" }
        require(sigmas.all { !it.isNaN() && !it.isInfinite() }) { "template sigmas must be finite" }
        require(maxPixels > 0) { "maxPixels must be positive" }
    }

    /** The blur widths tried for glyph matching (a copy). */
    fun templateSigmas(): DoubleArray = sigmas.copyOf()

    /** Expected tile patches per sigma: `32 × 64` values each (polarity-major). */
    internal val patterns: Array<DoubleArray> by lazy {
        Array(TEMPLATE_SIGMA_COUNT) { PetalDecoder.buildPatterns(sigmas[it]) }
    }

    /** [patterns] rescaled by their own contrast, as the normalised tile read compares them. */
    internal val normalisedPatterns: Array<DoubleArray> by lazy {
        Array(TEMPLATE_SIGMA_COUNT) { PetalDecoder.rescalePatterns(patterns[it]) }
    }

    override fun equals(other: Any?): Boolean = other is PetalDecodeOptions && tryMirrored == other.tryMirrored &&
        maxPixels == other.maxPixels && sigmas.contentEquals(other.sigmas)

    override fun hashCode(): Int = 31 * (31 * tryMirrored.hashCode() + maxPixels) + sigmas.contentHashCode()

    companion object {
        /** Number of template blur widths. */
        const val TEMPLATE_SIGMA_COUNT = 5

        /** Mirrored previews tried, sigmas `[0, 0.5, 0.8, 1.1, 1.5]`, at most 12,000,000 pixels. */
        @JvmField
        val DEFAULT = PetalDecodeOptions()
    }
}

/** Why a frame could not be decoded at all. */
enum class PetalDecodeError(
    /** Human-readable description. */
    val description: String,
) {
    /** The image is empty, smaller than 48 pixels on a side, or larger than [PetalDecodeOptions.maxPixels]. */
    UNSUPPORTED_IMAGE("petal image has an unsupported size"),

    /** The four corner finders were not found. */
    NO_FINDERS("petal finders not found"),

    /** Finders were found but no orientation produced a readable lane. */
    NO_ORIENTATION("no petal orientation produced a readable lane"),
}

/** A lane that passed its Reed–Solomon check. */
class PetalLaneResult internal constructor(
    private val bytes: ByteArray,
    /**
     * Byte positions the Reed–Solomon decoder rewrote: the erased bytes plus any
     * errors it found among the others (a measure of how close the lane was to failing).
     */
    val corrected: Int,
    /** Bytes that were passed to the decoder as erasures. */
    val erasures: Int,
) {
    /** Lane data bytes: header and atoms, or the beacon (a copy). */
    val data: ByteArray get() = bytes.copyOf()

    internal val dataView: ByteArray get() = bytes

    override fun equals(other: Any?): Boolean = other is PetalLaneResult && bytes.contentEquals(other.bytes) &&
        corrected == other.corrected && erasures == other.erasures

    override fun hashCode(): Int = 31 * bytes.contentHashCode() + erasures
}

/** Everything read from one camera frame. */
class PetalDecodedFrame internal constructor(
    /** Canvas-to-pixel homography that was used. */
    val homography: PetalHomography,
    /** Orientation: how many quarter turns the code is rotated (`0..3`). */
    val rotation: Int,
    /** Whether the image was mirrored. */
    val mirrored: Boolean,
    /** Lane `P` result. */
    val p: PetalLaneResult?,
    /** Lane `K` result. */
    val k: PetalLaneResult?,
    /** Lane `D` result. */
    val d: PetalLaneResult?,
    /**
     * The corner finder that was hidden (by a finger, a glare or the edge of the
     * frame) and inferred from the other three, as its canonical index: 0 top-left,
     * 1 top-right, 2 bottom-right, 3 bottom-left of the upright code; `null` when
     * all four were seen.
     */
    val inferredCorner: Int?,
) {
    /** Number of lanes that decoded. */
    val lanesOk: Int get() = (if (p != null) 1 else 0) + (if (k != null) 1 else 0) + (if (d != null) 1 else 0)

    /** Decoded lanes as letters from `"PKD"`, in that order. */
    val lanes: String
        get() = buildString(3) {
            if (p != null) append('P')
            if (k != null) append('K')
            if (d != null) append('D')
        }

    /** The result of [lane], when it decoded. */
    fun lane(lane: PetalLane): PetalLaneResult? = when (lane) {
        PetalLane.P -> p
        PetalLane.K -> k
        PetalLane.D -> d
    }

    /** What lane `D` carried, when it decoded. */
    fun dLane(): PetalDLane? = d?.let { PetalStream.parseDLane(it.dataView) }

    /** The beacon, when lane `D` decoded on a beacon frame. */
    fun beacon(): PetalBeacon? = dLane()?.beacon

    /** Atom packets from every lane that decoded (`P`, `K`, then a non-beacon `D`). */
    fun atomPackets(): List<PetalAtomPacket> {
        val packets = ArrayList<PetalAtomPacket>(3)
        p?.let { PetalStream.parseAtomLane(PetalLane.P, it.dataView) }?.let { packets += it }
        k?.let { PetalStream.parseAtomLane(PetalLane.K, it.dataView) }?.let { packets += it }
        dLane()?.atoms?.let { packets += it }
        return packets
    }

    /** Offers everything this frame carries to [assembler] (lane `D` first). */
    fun feed(assembler: PetalStreamAssembler) {
        dLane()?.let(assembler::pushDLane)
        p?.let { PetalStream.parseAtomLane(PetalLane.P, it.dataView) }?.let(assembler::pushAtoms)
        k?.let { PetalStream.parseAtomLane(PetalLane.K, it.dataView) }?.let(assembler::pushAtoms)
    }
}

/** The outcome of [PetalDecoder.decode]: exactly one of [frame] and [error] is non-null. */
class PetalDecodeResult internal constructor(
    /** The decoded frame on success. */
    val frame: PetalDecodedFrame?,
    /** Why nothing was decoded, on failure. */
    val error: PetalDecodeError?,
) {
    /** Whether a frame was decoded. */
    val isSuccess: Boolean get() = frame != null
}

/**
 * From a camera luma plane to lane data.
 *
 * The decoder tries the finder candidates of [PetalLocator.candidates] in turn
 * (four seen corners, or three with the fourth inferred and moved to where the
 * dotted rings line up), derives a homography for each orientation hypothesis
 * (four rotations, optionally mirrored), ranks the hypotheses by their ring
 * gates plus the `天` silhouette, then reads the dots and tiles. Every tile is
 * classified *jointly*: the 8×8 sample patch is compared against the 32
 * hypotheses (polarity × glyph) and the best match wins, so the katakana and
 * the light/dark bit help each other. Cells the decoder is unsure about become
 * Reed–Solomon erasures.
 *
 * After a frame decodes, [track] reads the next ones from its pose without the
 * finder search (what [PetalScanSession] does within 500 ms). The session also averages
 * captures of the same shown frame to recover tile lanes lost to noise or display banding.
 *
 * The tile *level read* judges every patch against the light and dark levels
 * measured at the finders. When it leaves lane `P` or `K` unreadable, the
 * *normalised read* is tried: it rescales each patch (and each template) by
 * its own contrast, so over-exposure, veiling light, glare, shadows and
 * gradients cancel out. Only a lane that the level read could not decode is
 * taken from the normalised read, so a frame the level read handles costs
 * nothing extra.
 *
 * All functions are thread-safe. [PetalScanSession] reuses scratch buffers
 * between frames; direct calls allocate their own.
 */
object PetalDecoder {
    private const val PATCH = PetalGlyphs.TEMPLATE_N
    private const val CELLS = PATCH * PATCH
    private const val HYPOTHESES = 2 * PetalGlyphs.GLYPH_COUNT
    private const val MIN_SIDE = 48

    /** Relative level of the glyph ink on a light tile (ink / light fill). */
    private const val INK_ON_LIGHT = 0.04

    /** Relative level of a pink glyph on a dark tile (pink / light fill). */
    private const val PINK_ON_DARK = 0.83

    /** Cells cut from each end of a sorted patch to find its robust darkest and brightest level. */
    private const val PATCH_CUT = CELLS / 10

    /**
     * Tiles whose contrast is below this fraction of the median tile contrast
     * become erasures in the normalised read.
     */
    private const val WEAK_TILE = 0.25

    /** Smallest span (in luma levels) of a camera patch that counts as contrast in the normalised read. */
    private const val PATCH_SPAN_FLOOR = 1.0

    /** Smallest span (relative to the light fill) of a template that counts as contrast in the normalised read. */
    private const val TEMPLATE_SPAN_FLOOR = 0.001

    /** Rescaled cells are clamped to this range, a quarter beyond the robust darkest and brightest levels. */
    private const val RESCALED_MIN = -0.25
    private const val RESCALED_MAX = 1.25

    private const val HALF_GLYPH_BOX = PetalLayout.GLYPH_BOX / 2.0
    private const val PATCH_CELL = PetalLayout.GLYPH_BOX / PATCH

    /** Sub-cell sample offsets, in cells. */
    private val CELL_OFFSET_X = doubleArrayOf(-0.25, 0.25, -0.25, 0.25)
    private val CELL_OFFSET_Y = doubleArrayOf(-0.25, -0.25, 0.25, 0.25)

    /** Directions of the eight finder-body samples (`τ·k/8`). */
    private val BODY_COS = DoubleArray(8)
    private val BODY_SIN = DoubleArray(8)

    /** Canonical finder centres `x0, y0, …` (clockwise from the top-left). */
    private val CANONICAL = DoubleArray(8)

    /** Lattice cells outside the `天` mask (no tile is ever drawn there). */
    private const val EMPTY_CELLS = PetalLayout.TILE_GRID * PetalLayout.TILE_GRID - PetalLayout.TILE_COUNT

    /** Centres of the [EMPTY_CELLS] lattice cells outside the mask, row-major. */
    private val EMPTY_X = DoubleArray(EMPTY_CELLS)
    private val EMPTY_Y = DoubleArray(EMPTY_CELLS)

    init {
        for (k in 0 until 8) {
            val angle = PetalLayout.TAU * k.toDouble() / 8.0
            BODY_COS[k] = StrictMath.cos(angle)
            BODY_SIN[k] = StrictMath.sin(angle)
        }
        for (finder in 0 until 4) {
            CANONICAL[2 * finder] = PetalLayout.finderCenterX(finder)
            CANONICAL[2 * finder + 1] = PetalLayout.finderCenterY(finder)
        }
        var empty = 0
        for (row in 0 until PetalLayout.TILE_GRID) {
            val line = PetalLayout.MASK[row]
            for (column in 0 until PetalLayout.TILE_GRID) {
                if (line[column] == '#') continue
                EMPTY_X[empty] = PetalLayout.TILE_ORIGIN + PetalLayout.TILE_PITCH * (column + 0.5)
                EMPTY_Y[empty] = PetalLayout.TILE_ORIGIN + PetalLayout.TILE_PITCH * (row + 0.5)
                empty += 1
            }
        }
    }

    /**
     * Decodes one camera frame.
     *
     * Tries the finder candidates of [PetalLocator.candidates] in order and returns the first
     * that reads. For each, the orientation hypotheses (four quarter turns, optionally mirrored)
     * are ranked by the ring gates plus the `天`; lane `D` is tried under the best three whose
     * gate score is at least 0.2, then the tile lanes under the best four.
     *
     * Returns [PetalDecodeError.UNSUPPORTED_IMAGE] for unusable sizes,
     * [PetalDecodeError.NO_FINDERS] when no code is visible and
     * [PetalDecodeError.NO_ORIENTATION] when no orientation yields a readable lane.
     */
    @JvmStatic
    @JvmOverloads
    fun decode(image: PetalLuma, options: PetalDecodeOptions = PetalDecodeOptions.DEFAULT): PetalDecodeResult =
        decode(image, options, PetalWorkspace())

    /**
     * Follows a code from the [previous] frame that decoded, without searching the whole image
     * for finders (the most expensive part of [decode]).
     *
     * Each corner finder seen in the previous frame is re-found near where the previous pose puts
     * it (see [PetalLocator.follow]); the mean movement of those predicts the rest. A corner
     * inferred in the previous frame counts as seen again only when its blossom is re-found within
     * a quarter diameter of that prediction (so a thumb beside it does not count). When exactly one
     * corner is missing it is placed at the prediction and refined against the rings like an
     * inferred corner. The orientation is kept from the previous frame. Returns `null` when the
     * image is unusable, the previous pose is broken (non-finite, or finders larger than the
     * image), two corners are lost or no lane decodes; the caller then runs [decode].
     */
    @JvmStatic
    @JvmOverloads
    fun track(
        image: PetalLuma,
        previous: PetalDecodedFrame,
        options: PetalDecodeOptions = PetalDecodeOptions.DEFAULT,
    ): PetalDecodedFrame? = track(image, previous, options, PetalWorkspace())

    /**
     * Reads all lanes with a known canvas-to-pixel [homography] (no finder
     * search), as trackers, refinement passes and qualification tooling do.
     * Returns `null` when the image is unusable or the finder reference levels
     * are too weak.
     */
    @JvmStatic
    @JvmOverloads
    fun decodeAt(
        image: PetalLuma,
        homography: PetalHomography,
        options: PetalDecodeOptions = PetalDecodeOptions.DEFAULT,
    ): PetalDecodedFrame? {
        if (!supported(image, options)) return null
        val reference = referenceLevels(image, homography.m, NO_CORNER) ?: return null
        return finish(image, options, 0, false, homography, reference, null, PetalWorkspace())
    }

    /**
     * Builds the cells the decoder believes it saw in [frame], for diagnostics. Tiles are taken
     * from the level read (the one that judges against the finder levels), even for a frame whose
     * lanes were rescued by the normalised read. Returns `null` when the image is unusable.
     */
    @JvmStatic
    @JvmOverloads
    fun observedCells(
        image: PetalLuma,
        frame: PetalDecodedFrame,
        options: PetalDecodeOptions = PetalDecodeOptions.DEFAULT,
    ): PetalFrameCells? {
        if (!supported(image, options)) return null
        val h = frame.homography.m
        val reference = referenceLevels(image, h, frame.inferredCorner ?: NO_CORNER) ?: return null
        val workspace = PetalWorkspace()
        samplePatches(image, h, workspace)
        val words = tileWords(readTiles(reference, options, workspace))
        return PetalFrameCells.fromWords(words.p, words.k, readDots(image, h, reference).word)
    }

    /**
     * Mean squared tile-match error of the level read of [frame], a quick image-quality indicator.
     * It can be large for a frame whose lanes were rescued by the normalised read, which is the
     * point: the finder levels did not describe that picture. Returns `null` when the image is unusable.
     */
    @JvmStatic
    @JvmOverloads
    fun tileMatchError(
        image: PetalLuma,
        frame: PetalDecodedFrame,
        options: PetalDecodeOptions = PetalDecodeOptions.DEFAULT,
    ): Double? {
        if (!supported(image, options)) return null
        val h = frame.homography.m
        val reference = referenceLevels(image, h, frame.inferredCorner ?: NO_CORNER) ?: return null
        val workspace = PetalWorkspace()
        samplePatches(image, h, workspace)
        val reads = readTiles(reference, options, workspace)
        var total = -0.0
        for (tile in 0 until reads.count) total += reads.error[tile]
        return total / reads.count.toDouble()
    }

    /** One capture's raw tile patches and finder levels, held independently of decoding scratch. */
    internal class TileEvidence(patches: DoubleArray, reference: Reference) {
        val patches = patches.copyOf()
        val reference = Reference(reference.lit.copyOf(), reference.dark.copyOf())
    }

    /** Samples a usable capture under its canonical decoded pose for later averaging. */
    internal fun tileEvidence(
        image: PetalLuma,
        frame: PetalDecodedFrame,
        options: PetalDecodeOptions,
        workspace: PetalWorkspace,
    ): TileEvidence? {
        if (!supported(image, options) || frame.inferredCorner?.let { it !in 0..3 } == true) return null
        val h = frame.homography.m
        val reference = referenceLevels(image, h, frame.inferredCorner ?: NO_CORNER) ?: return null
        samplePatches(image, h, workspace)
        return TileEvidence(workspace.patches, reference)
    }

    /**
     * Tile lanes from captures of one shown frame. The level read averages patches levelled by
     * each capture's own finder levels; missing lanes then use the normalised mean raw patches.
     * Summation follows capture order, exactly as the reference decoder does. The caller must
     * group captures by their decoded lane headers and check the recovered lane's own header.
     */
    internal fun mergeTiles(
        evidence: Collection<TileEvidence>,
        options: PetalDecodeOptions,
        workspace: PetalWorkspace,
    ): TileLanes {
        if (evidence.isEmpty()) return TileLanes(null, null)
        val mean = workspace.scaled
        Arrays.fill(mean, 0.0)
        for (capture in evidence) {
            for (tile in 0 until PetalLayout.TILE_COUNT) {
                val lit = capture.reference.litAt(PetalLayout.TILE_CENTER_X[tile], PetalLayout.TILE_CENTER_Y[tile])
                val dark = capture.reference.darkAt(PetalLayout.TILE_CENTER_X[tile], PetalLayout.TILE_CENTER_Y[tile])
                val base = tile * CELLS
                for (cell in base until base + CELLS) mean[cell] += (capture.patches[cell] - dark) / (lit - dark)
            }
        }
        val count = evidence.size.toDouble()
        for (cell in mean.indices) mean[cell] /= count
        Arrays.fill(workspace.erased, false)
        var words = tileWords(classify(mean, options, false, workspace.erased, workspace))
        var p = decodeWithErasures(PetalLane.P, words.p, words.pConfidence)
        var k = decodeWithErasures(PetalLane.K, words.k, words.kConfidence)
        if (p == null || k == null) {
            val raw = workspace.patches
            Arrays.fill(raw, 0.0)
            for (capture in evidence) {
                for (cell in raw.indices) raw[cell] += capture.patches[cell]
            }
            for (cell in raw.indices) raw[cell] /= count
            words = tileWords(readTilesNormalised(options, workspace))
            if (p == null) p = decodeWithErasures(PetalLane.P, words.p, words.pConfidence)
            if (k == null) k = decodeWithErasures(PetalLane.K, words.k, words.kConfidence)
        }
        return TileLanes(p, k)
    }

    internal fun decode(image: PetalLuma, options: PetalDecodeOptions, workspace: PetalWorkspace): PetalDecodeResult {
        if (!supported(image, options)) return PetalDecodeResult(null, PetalDecodeError.UNSUPPORTED_IMAGE)
        var located = false
        val candidates = PetalLocator.Candidates(image, workspace)
        while (candidates.hasNext()) {
            val set = candidates.next()
            located = true
            decodeCandidate(image, options, set, workspace)?.let { return PetalDecodeResult(it, null) }
        }
        return PetalDecodeResult(null, if (located) PetalDecodeError.NO_ORIENTATION else PetalDecodeError.NO_FINDERS)
    }

    /** Marks "no inferred corner" where a corner index is expected. */
    internal const val NO_CORNER = -1

    /**
     * Reads one finder candidate: refines an inferred corner against the rings, ranks the
     * orientation hypotheses by gate score + `天` score, tries lane `D` under the best three whose
     * gate score is at least 0.2, then the tile lanes under the best four. `null` when none reads.
     */
    internal fun decodeCandidate(
        image: PetalLuma,
        options: PetalDecodeOptions,
        set: PetalFinderSet,
        workspace: PetalWorkspace,
    ): PetalDecodedFrame? {
        val missing = set.inferred ?: NO_CORNER
        val corners = if (missing == NO_CORNER) set.quad else refineInferredCorner(image, set.quad, missing)
        val scored = ArrayList<Hypothesis>(8)
        for (hypothesis in hypotheses(corners, options.tryMirrored)) {
            val h = hypothesis.homography.m
            val inferred = if (missing == NO_CORNER) NO_CORNER else canonicalCorner(missing, hypothesis.rotation, hypothesis.mirrored)
            val reference = referenceLevels(image, h, inferred) ?: continue
            hypothesis.inferred = inferred
            hypothesis.reference = reference
            hypothesis.gate = gateScore(image, h, reference)
            hypothesis.mask = maskScore(image, h, reference)
            hypothesis.rank = hypothesis.gate + hypothesis.mask
            // Stable descending insertion by rank (`sort_by` with `(b.0 + b.1).total_cmp(&(a.0 + a.1))`).
            var at = scored.size
            while (at > 0 && PetalNumerics.totalCompare(hypothesis.rank, scored[at - 1].rank) > 0) at -= 1
            scored.add(at, hypothesis)
        }
        // 1. the ring beacon is the cheapest and strongest orientation check; the ranking is not by
        //    gate score alone, so a weak gate skips that hypothesis but not the ones after it
        for (index in 0 until minOf(3, scored.size)) {
            val candidate = scored[index]
            if (candidate.gate < 0.2) continue
            val reference = candidate.reference!!
            val d = readLaneD(image, candidate.homography.m, reference) ?: continue
            return finish(
                image, options, candidate.rotation, candidate.mirrored, candidate.homography, reference, d, workspace,
                candidate.inferredCorner(),
            )
        }
        // 2. fall back to the tile lanes under the most promising orientations
        for (index in 0 until minOf(4, scored.size)) {
            val candidate = scored[index]
            val h = candidate.homography.m
            val reference = candidate.reference!!
            samplePatches(image, h, workspace)
            val lanes = readTileLanes(reference, options, workspace)
            if (lanes.p != null || lanes.k != null) {
                return PetalDecodedFrame(
                    candidate.homography,
                    candidate.rotation,
                    candidate.mirrored,
                    lanes.p,
                    lanes.k,
                    readLaneD(image, h, reference),
                    candidate.inferredCorner(),
                )
            }
        }
        return null
    }

    internal fun track(
        image: PetalLuma,
        previous: PetalDecodedFrame,
        options: PetalDecodeOptions,
        workspace: PetalWorkspace,
    ): PetalDecodedFrame? {
        if (!supported(image, options)) return null
        val h0 = previous.homography.m
        val expected = Array(4) { corner ->
            val cx = CANONICAL[2 * corner]
            val cy = CANONICAL[2 * corner + 1]
            // the finder's diameter is 120 units: its widest projection along either axis
            val across = span(h0, cx - 60.0, cy, cx + 60.0, cy)
            val down = span(h0, cx, cy - 60.0, cx, cy + 60.0)
            PetalFinder(applyX(h0, cx, cy), applyY(h0, cx, cy), PetalNumerics.max(across, down))
        }
        // a broken pose, or one whose finders are larger than the picture, cannot be followed
        val short = minOf(image.width, image.height).toDouble()
        for (finder in expected) {
            val finite = !finder.x.isNaN() && !finder.x.isInfinite() && !finder.y.isNaN() && !finder.y.isInfinite() &&
                !finder.size.isNaN() && !finder.size.isInfinite()
            if (!finite || finder.size > short) return null
        }
        val previouslyInferred = previous.inferredCorner ?: NO_CORNER
        val found = arrayOfNulls<PetalFinder>(4)
        for (corner in 0 until 4) {
            if (corner != previouslyInferred) found[corner] = PetalLocator.follow(image, expected[corner])
        }
        // the mean movement of the corners that were followed predicts the others
        var followed = 0
        var sumX = -0.0
        var sumY = -0.0
        for (corner in 0 until 4) {
            val seen = found[corner] ?: continue
            sumX += seen.x - expected[corner].x
            sumY += seen.y - expected[corner].y
            followed += 1
        }
        if (followed < 3) return null
        val shiftX = sumX / followed.toDouble()
        val shiftY = sumY / followed.toDouble()
        fun predicted(corner: Int): PetalFinder =
            PetalFinder(expected[corner].x + shiftX, expected[corner].y + shiftY, expected[corner].size)
        // a corner that was hidden is seen again only when its blossom is found right where the
        // others say it is (a bright thumb beside it must not count)
        if (previouslyInferred != NO_CORNER) {
            val at = predicted(previouslyInferred)
            val again = PetalLocator.follow(image, at)
            found[previouslyInferred] = again?.takeIf {
                val dx = it.x - at.x
                val dy = it.y - at.y
                Math.sqrt(dx * dx + dy * dy) <= 0.25 * at.size
            }
        }
        var lost = 0
        var missing = NO_CORNER
        for (corner in 0 until 4) {
            if (found[corner] == null) {
                lost += 1
                missing = corner
            }
        }
        if (lost > 1) return null
        if (missing != NO_CORNER) found[missing] = predicted(missing)
        var corners = Array(4) { found[it]!! }
        if (missing != NO_CORNER) corners = refineInferredCorner(image, corners, missing)
        val points = DoubleArray(8)
        for (corner in 0 until 4) {
            points[2 * corner] = corners[corner].x
            points[2 * corner + 1] = corners[corner].y
        }
        val homography = PetalHomography.fromPoints(CANONICAL, points) ?: return null
        val h = homography.m
        val reference = referenceLevels(image, h, missing) ?: return null
        val d = readLaneD(image, h, reference)
        samplePatches(image, h, workspace)
        val lanes = readTileLanes(reference, options, workspace)
        if (lanes.p == null && lanes.k == null && d == null) return null
        return PetalDecodedFrame(
            homography,
            previous.rotation,
            previous.mirrored,
            lanes.p,
            lanes.k,
            d,
            if (missing == NO_CORNER) null else missing,
        )
    }

    private fun applyX(h: DoubleArray, x: Double, y: Double): Double =
        (h[0] * x + h[1] * y + h[2]) / (h[6] * x + h[7] * y + h[8])

    private fun applyY(h: DoubleArray, x: Double, y: Double): Double =
        (h[3] * x + h[4] * y + h[5]) / (h[6] * x + h[7] * y + h[8])

    /** Pixel distance between the images of canvas points `(ax, ay)` and `(bx, by)` under [h]. */
    private fun span(h: DoubleArray, ax: Double, ay: Double, bx: Double, by: Double): Double {
        val dx = applyX(h, ax, ay) - applyX(h, bx, by)
        val dy = applyY(h, ax, ay) - applyY(h, bx, by)
        return Math.sqrt(dx * dx + dy * dy)
    }

    private fun supported(image: PetalLuma, options: PetalDecodeOptions): Boolean =
        image.width >= MIN_SIDE && image.height >= MIN_SIDE &&
            image.width.toLong() * image.height.toLong() <= options.maxPixels.toLong()

    /**
     * Reads every lane under one orientation; [d] may carry the lane `D` result already computed.
     * The frame reports [inferredCorner] (canonical index, or `null`).
     */
    private fun finish(
        image: PetalLuma,
        options: PetalDecodeOptions,
        rotation: Int,
        mirrored: Boolean,
        homography: PetalHomography,
        reference: Reference,
        d: PetalLaneResult?,
        workspace: PetalWorkspace,
        inferredCorner: Int? = null,
    ): PetalDecodedFrame {
        val h = homography.m
        val dLane = d ?: readLaneD(image, h, reference)
        samplePatches(image, h, workspace)
        val lanes = readTileLanes(reference, options, workspace)
        return PetalDecodedFrame(homography, rotation, mirrored, lanes.p, lanes.k, dLane, inferredCorner)
    }

    /** One orientation hypothesis and, once measured, its reference levels and scores. */
    internal class Hypothesis(val rotation: Int, val mirrored: Boolean, val homography: PetalHomography) {
        /** Canonical index of the inferred corner under this hypothesis, or [NO_CORNER]. */
        var inferred = NO_CORNER
        var reference: Reference? = null
        var gate = 0.0
        var mask = 0.0

        /** Gate score + `天` score, the ranking key. */
        var rank = 0.0

        fun inferredCorner(): Int? = if (inferred == NO_CORNER) null else inferred
    }

    /**
     * Canonical index of the corner at [index] of a finder quad under the orientation hypothesis
     * ([rotation], [mirrored]).
     */
    internal fun canonicalCorner(index: Int, rotation: Int, mirrored: Boolean): Int =
        if (mirrored) (rotation + 4 - index) % 4 else (index + 4 - rotation) % 4

    /**
     * The brightness summed over all ring slots under the pose that maps the canonical corners
     * onto [corners] (`x0, y0, …` in quad order), or NaN when they admit no homography. The slots
     * form the same set of points under every quarter turn and mirror of the canvas (80, 92 and
     * 104 are multiples of four), so the value does not depend on the orientation.
     */
    private fun ringBrightness(image: PetalLuma, corners: DoubleArray): Double {
        val h = PetalHomography.fromPoints(CANONICAL, corners)?.m ?: return Double.NaN
        var sum = -0.0
        for (flat in 0 until PetalLayout.TOTAL_SLOTS) {
            sum += dotSamples(image, h, PetalLayout.SLOT_CENTER_X[flat], PetalLayout.SLOT_CENTER_Y[flat], 3.5)
        }
        return sum
    }

    /**
     * Moves the [inferred] corner of [corners] to where the three dotted rings line up best: a
     * 13 × 13 search in steps of 2 % of the mean leg around the parallelogram estimate, then a
     * 9 × 9 search in steps of 0.5 % around the best point. The rings fix the geometry only; the
     * orientation is decided afterwards by the gates and the `天`.
     */
    internal fun refineInferredCorner(image: PetalLuma, corners: Array<PetalFinder>, inferred: Int): Array<PetalFinder> {
        val points = DoubleArray(8)
        for (corner in 0 until 4) {
            points[2 * corner] = corners[corner].x
            points[2 * corner + 1] = corners[corner].y
        }
        val startX = points[2 * inferred]
        val startY = points[2 * inferred + 1]
        fun distance(other: Int): Double {
            val dx = points[2 * other] - startX
            val dy = points[2 * other + 1] - startY
            return Math.sqrt(dx * dx + dy * dy)
        }
        val leg = 0.5 * (distance((inferred + 1) % 4) + distance((inferred + 3) % 4))
        // best[0] brightness, best[1..2] the point (the search runs twice, so it lives in an array)
        val best = doubleArrayOf(-Double.MAX_VALUE, startX, startY)
        fun search(centreX: Double, centreY: Double, step: Double, reach: Int) {
            for (dy in -reach..reach) {
                for (dx in -reach..reach) {
                    val x = centreX + dx.toDouble() * step
                    val y = centreY + dy.toDouble() * step
                    points[2 * inferred] = x
                    points[2 * inferred + 1] = y
                    val brightness = ringBrightness(image, points)
                    if (brightness > best[0]) {
                        best[0] = brightness
                        best[1] = x
                        best[2] = y
                    }
                }
            }
        }
        search(startX, startY, 0.02 * leg, 6)
        search(best[1], best[2], 0.005 * leg, 4)
        val refined = corners.copyOf()
        refined[inferred] = PetalFinder(best[1], best[2], corners[inferred].size)
        return refined
    }

    internal fun hypotheses(finders: Array<PetalFinder>, tryMirrored: Boolean): List<Hypothesis> {
        val out = ArrayList<Hypothesis>(8)
        val dst = DoubleArray(8)
        for (mirrored in booleanArrayOf(false, true)) {
            if (mirrored && !tryMirrored) continue
            for (rotation in 0 until 4) {
                for (i in 0 until 4) {
                    val q = if (mirrored) finders[(rotation + 4 - i) % 4] else finders[(i + rotation) % 4]
                    dst[2 * i] = q.x
                    dst[2 * i + 1] = q.y
                }
                PetalHomography.fromPoints(CANONICAL, dst)?.let { out += Hypothesis(rotation, mirrored, it) }
            }
        }
        return out
    }

    /** Lit (finder body) and dark (background) estimates at the four corners. */
    internal class Reference(val lit: DoubleArray, val dark: DoubleArray) {
        fun litAt(x: Double, y: Double): Double = mix(lit, x, y)

        fun darkAt(x: Double, y: Double): Double = mix(dark, x, y)

        /** Bilinear interpolation over the canvas of the four corner estimates. */
        private fun mix(corners: DoubleArray, x: Double, y: Double): Double {
            val u = (x / 1024.0).coerceIn(0.0, 1.0)
            val v = (y / 1024.0).coerceIn(0.0, 1.0)
            val top = corners[0] * (1.0 - u) + corners[1] * u
            val bottom = corners[3] * (1.0 - u) + corners[2] * u
            return top * (1.0 - v) + bottom * v
        }
    }

    /** Samples [image] at the pixel that canvas point `(x, y)` maps to under [h]. */
    private fun sampleThrough(image: PetalLuma, h: DoubleArray, x: Double, y: Double): Double {
        val w = h[6] * x + h[7] * y + h[8]
        return image.sample((h[0] * x + h[1] * y + h[2]) / w, (h[3] * x + h[4] * y + h[5]) / w)
    }

    private fun dotSamples(image: PetalLuma, h: DoubleArray, x: Double, y: Double, spread: Double): Double {
        var sum = 0.0
        sum += sampleThrough(image, h, x + 0.0, y + 0.0)
        sum += sampleThrough(image, h, x + spread, y + 0.0)
        sum += sampleThrough(image, h, x + -spread, y + 0.0)
        sum += sampleThrough(image, h, x + 0.0, y + spread)
        sum += sampleThrough(image, h, x + 0.0, y + -spread)
        return sum / 5.0
    }

    /**
     * Light and dark levels at the four corners: the solid blossom core, and the black canvas 100
     * units inward of it; `null` when a seen corner has less than 12 levels of contrast (or a
     * non-finite one, under a broken pose). An
     * [inferred] corner (canonical index, or [NO_CORNER]) was not seen, so its levels are
     * extrapolated from the other three by the parallelogram rule and kept within their range.
     */
    internal fun referenceLevels(image: PetalLuma, h: DoubleArray, inferred: Int): Reference? {
        val lit = DoubleArray(4)
        val dark = DoubleArray(4)
        for (i in 0 until 4) {
            if (i == inferred) continue
            val cx = CANONICAL[2 * i]
            val cy = CANONICAL[2 * i + 1]
            // the blossom is solid out to radius 24 around its centre
            var sum = sampleThrough(image, h, cx, cy)
            for (k in 0 until 8) sum += sampleThrough(image, h, cx + 20.0 * BODY_COS[k], cy + 20.0 * BODY_SIN[k])
            lit[i] = sum / 9.0
            val sx = if (cx < 512.0) 1.0 else -1.0
            val sy = if (cy < 512.0) 1.0 else -1.0
            val a = dotSamples(image, h, cx + sx * 100.0, cy, 5.0)
            val b = dotSamples(image, h, cx, cy + sy * 100.0, 5.0)
            dark[i] = 0.5 * (a + b)
            // a NaN contrast (from a broken pose) refuses as well
            val contrast = lit[i] - dark[i]
            if (contrast.isNaN() || contrast.isInfinite() || contrast < 12.0) return null
        }
        if (inferred != NO_CORNER) {
            lit[inferred] = extrapolate(lit, inferred)
            dark[inferred] = extrapolate(dark, inferred)
            // uneven light can push the estimates past each other; an inferred corner
            // needs the same contrast as a seen one
            if (lit[inferred] - dark[inferred] < 12.0) return null
        }
        return Reference(lit, dark)
    }

    /** The parallelogram estimate `v[n1] + v[n2] − v[opposite]` for corner [m], clamped to the range of the other three. */
    private fun extrapolate(v: DoubleArray, m: Int): Double {
        val n1 = (m + 1) % 4
        val opposite = (m + 2) % 4
        val n2 = (m + 3) % 4
        val low = PetalNumerics.min(PetalNumerics.min(v[n1], v[opposite]), v[n2])
        val high = PetalNumerics.max(PetalNumerics.max(v[n1], v[opposite]), v[n2])
        val estimate = v[n1] + v[n2] - v[opposite]
        return if (estimate < low) low else if (estimate > high) high else estimate
    }

    /**
     * How well the `天` lines up: the mean normalised level over the tiles (each sampled at five
     * points across the tile, so a glyph stroke at the centre does not decide it) minus the mean
     * over the empty lattice cells. The mask is symmetric left to right but not top to bottom, so
     * this tells the four quarter turns apart even when the ring gates are damaged.
     */
    internal fun maskScore(image: PetalLuma, h: DoubleArray, reference: Reference): Double {
        var tiles = -0.0
        for (tile in 0 until PetalLayout.TILE_COUNT) {
            tiles += maskLevel(image, h, reference, PetalLayout.TILE_CENTER_X[tile], PetalLayout.TILE_CENTER_Y[tile])
        }
        var empty = -0.0
        for (cell in 0 until EMPTY_CELLS) empty += maskLevel(image, h, reference, EMPTY_X[cell], EMPTY_Y[cell])
        return tiles / PetalLayout.TILE_COUNT.toDouble() - empty / EMPTY_CELLS.toDouble()
    }

    private fun maskLevel(image: PetalLuma, h: DoubleArray, reference: Reference, x: Double, y: Double): Double {
        val lit = reference.litAt(x, y)
        val dark = reference.darkAt(x, y)
        return (dotSamples(image, h, x, y, 8.0) - dark) / (lit - dark)
    }

    private fun normalisedDot(image: PetalLuma, h: DoubleArray, reference: Reference, flat: Int): Double {
        val x = PetalLayout.SLOT_CENTER_X[flat]
        val y = PetalLayout.SLOT_CENTER_Y[flat]
        val lit = reference.litAt(x, y)
        val dark = reference.darkAt(x, y)
        return (dotSamples(image, h, x, y, 3.5) - dark) / (lit - dark)
    }

    internal fun gateScore(image: PetalLuma, h: DoubleArray, reference: Reference): Double {
        var gates = -0.0
        for (slot in PetalLayout.GATE_SLOTS) gates += normalisedDot(image, h, reference, slot)
        var guards = -0.0
        for (slot in PetalLayout.GUARD_SLOTS) guards += normalisedDot(image, h, reference, slot)
        return gates / PetalLayout.GATE_SLOTS.size.toDouble() - guards / PetalLayout.GUARD_SLOTS.size.toDouble()
    }

    /** A transmitted lane `D` word with per-byte confidence. */
    private class DotWord(val word: ByteArray, val confidence: DoubleArray)

    /** Reads lane `D` with per-ring thresholds from the gates (lit) and guards (dark). */
    private fun readDots(image: PetalLuma, h: DoubleArray, reference: Reference): DotWord {
        val thresholds = doubleArrayOf(0.5, 0.5, 0.5)
        for (ring in 0 until PetalLayout.RING_COUNT) {
            var litSum = -0.0
            var litCount = 0
            for (slot in PetalLayout.GATE_SLOTS) {
                if (PetalLayout.SLOT_RING[slot] != ring) continue
                litSum += normalisedDot(image, h, reference, slot)
                litCount += 1
            }
            var darkSum = -0.0
            var darkCount = 0
            for (slot in PetalLayout.GUARD_SLOTS) {
                if (PetalLayout.SLOT_RING[slot] != ring) continue
                darkSum += normalisedDot(image, h, reference, slot)
                darkCount += 1
            }
            if (litCount > 0 && darkCount > 0) {
                val l = litSum / litCount.toDouble()
                val d = darkSum / darkCount.toDouble()
                if (l - d > 0.2) thresholds[ring] = 0.5 * (l + d)
            }
        }
        val word = ByteArray(PetalLanes.D_WORD)
        val confidence = DoubleArray(PetalLanes.D_WORD) { Double.MAX_VALUE }
        for (bit in 0 until PetalLayout.D_BITS) {
            val slot = PetalLayout.DATA_SLOTS[bit]
            val value = normalisedDot(image, h, reference, slot)
            val threshold = thresholds[PetalLayout.SLOT_RING[slot]]
            if (value > threshold) word[bit / 8] = (word[bit / 8].toInt() or (1 shl (7 - bit % 8))).toByte()
            confidence[bit / 8] = PetalNumerics.min(confidence[bit / 8], Math.abs(value - threshold))
        }
        return DotWord(word, confidence)
    }

    /** Lane `D` under one pose. */
    private fun readLaneD(image: PetalLuma, h: DoubleArray, reference: Reference): PetalLaneResult? {
        val dots = readDots(image, h, reference)
        return decodeWithErasures(PetalLane.D, dots.word, dots.confidence)
    }

    /**
     * Tries Reed–Solomon with growing numbers of erasures, least confident first.
     *
     * The schedule erases 0, ⅛, ¼, ⅓ and ½ of the parity bytes (integer division), and for lane `K`
     * also ⅔. Lanes `D` and `P` stop at ½: their words have only 11 and 13 parity bytes, and a
     * further erasure step leaves so few spare ones that it accepts wrong codewords (lane `D` at 7
     * erasures: about 0.4 % of random words; lane `P` at 8: wrong lanes in banded 480p frames).
     */
    internal fun decodeWithErasures(lane: PetalLane, word: ByteArray, confidence: DoubleArray): PetalLaneResult? {
        val n = word.size
        // Stable sort of byte positions by confidence (`sort_by` with `total_cmp`).
        val order = IntArray(n) { it }
        for (i in 1 until n) {
            val position = order[i]
            val key = confidence[position]
            var j = i - 1
            while (j >= 0 && PetalNumerics.totalCompare(confidence[order[j]], key) > 0) {
                order[j + 1] = order[j]
                j -= 1
            }
            order[j + 1] = position
        }
        val nsym = lane.parityLength
        val schedule = if (lane == PetalLane.K) {
            intArrayOf(0, nsym / 8, nsym / 4, nsym / 3, nsym / 2, nsym * 2 / 3)
        } else {
            intArrayOf(0, nsym / 8, nsym / 4, nsym / 3, nsym / 2)
        }
        val trial = ByteArray(n)
        var previous = -1
        for (erasures in schedule) {
            if (erasures == previous) continue // `dedup` of consecutive repeats
            previous = erasures
            word.copyInto(trial)
            // zero the erased bytes so stale values cannot leak through
            for (index in 0 until erasures) trial[order[index]] = 0
            return PetalLanes.decodeLaneCountedOrNull(lane, trial, order, erasures) ?: continue
        }
        return null
    }

    /** Expected normalised patches for one blur width: `pred[(polarity * 16 + glyph) * 64 + cell]`. */
    internal fun buildPatterns(sigma: Double): DoubleArray {
        val kernel = DoubleArray(5) { index ->
            val i = index - 2
            if (sigma < 0.05) {
                if (i == 0) 1.0 else 0.0
            } else {
                StrictMath.exp(-(i * i).toDouble() / (2.0 * sigma * sigma))
            }
        }
        var sum = -0.0
        for (value in kernel) sum += value
        for (index in kernel.indices) kernel[index] = kernel[index] / sum
        val pred = DoubleArray(HYPOTHESES * CELLS)
        val coverage = DoubleArray(CELLS)
        val blurred = DoubleArray(CELLS)
        for (polarity in 0 until 2) {
            for (glyph in 0 until PetalGlyphs.GLYPH_COUNT) {
                for (cell in 0 until CELLS) {
                    coverage[cell] = PetalGlyphs.TEMPLATES[glyph * CELLS + cell].toDouble() / 255.0
                }
                for (v in 0 until PATCH) {
                    for (u in 0 until PATCH) {
                        var acc = 0.0
                        for (ky in 0 until 5) {
                            for (kx in 0 until 5) {
                                val sx = u + kx - 2
                                val sy = v + ky - 2
                                if (sx in 0 until PATCH && sy in 0 until PATCH) {
                                    acc += kernel[kx] * kernel[ky] * coverage[sy * PATCH + sx]
                                }
                            }
                        }
                        blurred[v * PATCH + u] = acc
                    }
                }
                val base = (polarity * PetalGlyphs.GLYPH_COUNT + glyph) * CELLS
                for (cell in 0 until CELLS) {
                    val ink = blurred[cell]
                    pred[base + cell] = if (polarity == 1) 1.0 - (1.0 - INK_ON_LIGHT) * ink else PINK_ON_DARK * ink
                }
            }
        }
        return pred
    }

    /**
     * Rescales every `64`-cell template of [pred] (polarity × glyph) by its own contrast, the way
     * the normalised read rescales the patches it compares them with.
     */
    internal fun rescalePatterns(pred: DoubleArray): DoubleArray {
        val out = DoubleArray(pred.size)
        val sorted = DoubleArray(CELLS)
        val levels = DoubleArray(2)
        for (hypothesis in 0 until HYPOTHESES) {
            val base = hypothesis * CELLS
            patchLevels(pred, base, sorted, levels)
            rescaleInto(pred, base, levels[0], levels[1], TEMPLATE_SPAN_FLOOR, out)
        }
        return out
    }

    /**
     * The robust darkest and brightest level of the [CELLS] values of [values] from [base]: the
     * values [PATCH_CUT] cells in from either end of the sorted cells. Writes `[low, high]` to
     * [levels]; [sorted] is scratch space of [CELLS] values.
     */
    private fun patchLevels(values: DoubleArray, base: Int, sorted: DoubleArray, levels: DoubleArray) {
        System.arraycopy(values, base, sorted, 0, CELLS)
        Arrays.sort(sorted)
        levels[0] = sorted[PATCH_CUT]
        levels[1] = sorted[CELLS - 1 - PATCH_CUT]
    }

    /** The robust darkest and brightest level `[low, high]` of one patch of [CELLS] values. */
    internal fun patchLevels(values: DoubleArray): DoubleArray {
        require(values.size == CELLS) { "a patch has $CELLS cells" }
        val levels = DoubleArray(2)
        patchLevels(values, 0, DoubleArray(CELLS), levels)
        return levels
    }

    /**
     * Maps the patch of [values] at [base] so that [low] becomes 0 and [high] becomes 1, with
     * [floor] as the smallest span that counts as contrast, clamped to `[-0.25, 1.25]`; the result
     * goes to the same cells of [out].
     */
    private fun rescaleInto(values: DoubleArray, base: Int, low: Double, high: Double, floor: Double, out: DoubleArray) {
        val range = PetalNumerics.max(high - low, floor)
        for (cell in base until base + CELLS) {
            out[cell] = ((values[cell] - low) / range).coerceIn(RESCALED_MIN, RESCALED_MAX)
        }
    }

    /** One patch of [CELLS] values mapped by its own darkest level to 0 and brightest to 1. */
    internal fun rescale(values: DoubleArray, floor: Double): DoubleArray {
        val levels = patchLevels(values)
        val out = DoubleArray(CELLS)
        rescaleInto(values, 0, levels[0], levels[1], floor, out)
        return out
    }

    /**
     * Samples the raw 8×8 luma patch of every tile as captured into `workspace.patches`: each cell
     * is the mean of four bilinear samples at ±¼ cell, in camera luma levels (no reference
     * levels applied).
     */
    internal fun samplePatches(image: PetalLuma, h: DoubleArray, workspace: PetalWorkspace) {
        val patches = workspace.patches
        for (tile in 0 until PetalLayout.TILE_COUNT) {
            val cx = PetalLayout.TILE_CENTER_X[tile]
            val cy = PetalLayout.TILE_CENTER_Y[tile]
            val base = tile * CELLS
            for (v in 0 until PATCH) {
                val gy = cy - HALF_GLYPH_BOX + (v + 0.5) * PATCH_CELL
                for (u in 0 until PATCH) {
                    val gx = cx - HALF_GLYPH_BOX + (u + 0.5) * PATCH_CELL
                    var sum = 0.0
                    for (offset in 0 until 4) {
                        sum += sampleThrough(
                            image,
                            h,
                            gx + CELL_OFFSET_X[offset] * PATCH_CELL,
                            gy + CELL_OFFSET_Y[offset] * PATCH_CELL,
                        )
                    }
                    patches[base + v * PATCH + u] = sum / 4.0
                }
            }
        }
    }

    /** The joint polarity + glyph reading of every tile under the best blur width. */
    internal class TileReads(val count: Int) {
        val light = BooleanArray(count)
        val glyph = IntArray(count)
        val polarityMargin = DoubleArray(count)
        val glyphMargin = DoubleArray(count)
        val error = DoubleArray(count)
    }

    /**
     * Picks for every patch of [patches] (`TILE_COUNT × 64` values) the polarity and glyph whose
     * template matches best.
     *
     * The template blur is chosen per frame, by the lowest total error. With [rescaleTemplates] the
     * templates are rescaled like the patches; tiles flagged in [erased] get zero margins, so they are
     * the first the Reed–Solomon decoder treats as erasures.
     */
    private fun classify(
        patches: DoubleArray,
        options: PetalDecodeOptions,
        rescaleTemplates: Boolean,
        erased: BooleanArray,
        workspace: PetalWorkspace,
    ): TileReads {
        val errors = workspace.errors
        var bestTotal = Double.MAX_VALUE
        var bestReads = TileReads(0)
        for (pred in if (rescaleTemplates) options.normalisedPatterns else options.patterns) {
            var total = 0.0
            val reads = TileReads(PetalLayout.TILE_COUNT)
            for (tile in 0 until PetalLayout.TILE_COUNT) {
                val base = tile * CELLS
                for (hypothesis in 0 until HYPOTHESES) {
                    val predBase = hypothesis * CELLS
                    var error = -0.0
                    for (cell in 0 until CELLS) {
                        val difference = patches[base + cell] - pred[predBase + cell]
                        error += difference * difference
                    }
                    errors[hypothesis] = error
                }
                var best = 0
                for (hypothesis in 1 until HYPOTHESES) {
                    if (PetalNumerics.totalCompare(errors[hypothesis], errors[best]) < 0) best = hypothesis
                }
                val polarity = best / PetalGlyphs.GLYPH_COUNT
                val glyph = best % PetalGlyphs.GLYPH_COUNT
                var otherPolarity = Double.MAX_VALUE
                val otherBase = (1 - polarity) * PetalGlyphs.GLYPH_COUNT
                for (g in 0 until PetalGlyphs.GLYPH_COUNT) otherPolarity = PetalNumerics.min(otherPolarity, errors[otherBase + g])
                var otherGlyph = Double.MAX_VALUE
                val sameBase = polarity * PetalGlyphs.GLYPH_COUNT
                for (g in 0 until PetalGlyphs.GLYPH_COUNT) {
                    if (g != glyph) otherGlyph = PetalNumerics.min(otherGlyph, errors[sameBase + g])
                }
                val bestError = errors[best]
                total += bestError
                reads.light[tile] = polarity == 1
                reads.glyph[tile] = glyph
                reads.polarityMargin[tile] = if (erased[tile]) 0.0 else otherPolarity - bestError
                reads.glyphMargin[tile] = if (erased[tile]) 0.0 else otherGlyph - bestError
                reads.error[tile] = bestError
            }
            if (total < bestTotal) {
                bestTotal = total
                bestReads = reads
            }
        }
        return bestReads
    }

    /**
     * The level read of the patches in `workspace.patches`: every cell becomes
     * `(v − dark) / (lit − dark)` with the lit and dark levels measured at the finders and
     * interpolated to the tile, and is compared with the templates as drawn.
     */
    internal fun readTiles(reference: Reference, options: PetalDecodeOptions, workspace: PetalWorkspace): TileReads {
        val patches = workspace.patches
        val levelled = workspace.scaled
        for (tile in 0 until PetalLayout.TILE_COUNT) {
            val lit = reference.litAt(PetalLayout.TILE_CENTER_X[tile], PetalLayout.TILE_CENTER_Y[tile])
            val dark = reference.darkAt(PetalLayout.TILE_CENTER_X[tile], PetalLayout.TILE_CENTER_Y[tile])
            val base = tile * CELLS
            for (cell in base until base + CELLS) levelled[cell] = (patches[cell] - dark) / (lit - dark)
        }
        Arrays.fill(workspace.erased, false)
        return classify(levelled, options, false, workspace.erased, workspace)
    }

    /**
     * The normalised read of the patches in `workspace.patches`: every patch and every template is
     * rescaled by its own contrast before they are compared, so the judgement does not depend on
     * absolute levels. Tiles whose contrast is below [WEAK_TILE] times the median contrast are erased.
     */
    internal fun readTilesNormalised(options: PetalDecodeOptions, workspace: PetalWorkspace): TileReads {
        val patches = workspace.patches
        val scaled = workspace.scaled
        val spans = workspace.spans
        val levels = workspace.levels
        for (tile in 0 until PetalLayout.TILE_COUNT) {
            val base = tile * CELLS
            patchLevels(patches, base, workspace.sortedCells, levels)
            spans[tile] = levels[1] - levels[0]
            rescaleInto(patches, base, levels[0], levels[1], PATCH_SPAN_FLOOR, scaled)
        }
        System.arraycopy(spans, 0, workspace.sortedSpans, 0, PetalLayout.TILE_COUNT)
        Arrays.sort(workspace.sortedSpans)
        val median = workspace.sortedSpans[PetalLayout.TILE_COUNT / 2]
        for (tile in 0 until PetalLayout.TILE_COUNT) workspace.erased[tile] = spans[tile] < WEAK_TILE * median
        return classify(scaled, options, true, workspace.erased, workspace)
    }

    /** Lanes `P` and `K` read from one set of patches. */
    internal class TileLanes(val p: PetalLaneResult?, val k: PetalLaneResult?)

    /**
     * Lanes `P` and `K` from the patches in `workspace.patches`: the level read first, then, for any
     * lane still unreadable, the normalised read.
     */
    internal fun readTileLanes(reference: Reference, options: PetalDecodeOptions, workspace: PetalWorkspace): TileLanes {
        var words = tileWords(readTiles(reference, options, workspace))
        var p = decodeWithErasures(PetalLane.P, words.p, words.pConfidence)
        var k = decodeWithErasures(PetalLane.K, words.k, words.kConfidence)
        if (p == null || k == null) {
            words = tileWords(readTilesNormalised(options, workspace))
            if (p == null) p = decodeWithErasures(PetalLane.P, words.p, words.pConfidence)
            if (k == null) k = decodeWithErasures(PetalLane.K, words.k, words.kConfidence)
        }
        return TileLanes(p, k)
    }

    /** Lane `P` and `K` words with per-byte confidence. */
    internal class TileWords(val p: ByteArray, val pConfidence: DoubleArray, val k: ByteArray, val kConfidence: DoubleArray)

    internal fun tileWords(reads: TileReads): TileWords {
        val p = ByteArray(PetalLanes.P_WORD)
        val pConfidence = DoubleArray(PetalLanes.P_WORD) { Double.MAX_VALUE }
        val k = ByteArray(PetalLanes.K_WORD)
        val kConfidence = DoubleArray(PetalLanes.K_WORD) { Double.MAX_VALUE }
        for (tile in 0 until reads.count) {
            if (reads.light[tile]) p[tile / 8] = (p[tile / 8].toInt() or (1 shl (7 - tile % 8))).toByte()
            pConfidence[tile / 8] = PetalNumerics.min(pConfidence[tile / 8], reads.polarityMargin[tile])
            val glyph = reads.glyph[tile]
            k[tile / 2] = (k[tile / 2].toInt() or (if (tile % 2 == 0) glyph shl 4 else glyph)).toByte()
            kConfidence[tile / 2] = PetalNumerics.min(
                kConfidence[tile / 2],
                PetalNumerics.min(reads.glyphMargin[tile], reads.polarityMargin[tile]),
            )
        }
        return TileWords(p, pConfidence, k, kConfidence)
    }
}
