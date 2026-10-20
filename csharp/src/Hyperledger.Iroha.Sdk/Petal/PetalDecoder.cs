using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;

namespace Hyperledger.Iroha.Petal;

/// <summary>Decoder tuning.</summary>
public sealed record PetalDecodeOptions
{
    private readonly IReadOnlyList<double> templateSigmas = Array.AsReadOnly(new[] { 0.0, 0.5, 0.8, 1.1, 1.5 });
    private readonly long maxPixels = 12_000_000;

    /// <summary>The reference defaults.</summary>
    public static PetalDecodeOptions Default { get; } = new();

    /// <summary>Also try horizontally mirrored images (front-camera previews). Default <see langword="true"/>.</summary>
    public bool TryMirrored { get; init; } = true;

    /// <summary>
    /// Blur widths (in template cells) tried for glyph matching; the reading with
    /// the lowest total match error wins. Default <c>[0, 0.5, 0.8, 1.1, 1.5]</c>.
    /// </summary>
    /// <exception cref="ArgumentException">The list is empty or holds a non-finite or negative value.</exception>
    public IReadOnlyList<double> TemplateSigmas
    {
        get => templateSigmas;
        init
        {
            ArgumentNullException.ThrowIfNull(value);
            var copy = value.ToArray();
            if (copy.Length == 0 || copy.Any(sigma => !double.IsFinite(sigma) || sigma < 0.0))
                throw new ArgumentException("Template sigmas must be a non-empty list of finite, non-negative values.", nameof(value));
            templateSigmas = Array.AsReadOnly(copy);
        }
    }

    /// <summary>
    /// Largest image (in pixels) the decoder accepts; larger frames should be
    /// downscaled by the caller. Bounds memory and work on hostile input.
    /// Default 12,000,000.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is negative.</exception>
    public long MaxPixels
    {
        get => maxPixels;
        init
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            maxPixels = value;
        }
    }
}

/// <summary>Why a camera frame could not be decoded at all.</summary>
public enum PetalDecodeError
{
    /// <summary>The image is smaller than 48 pixels on a side or larger than <see cref="PetalDecodeOptions.MaxPixels"/>.</summary>
    UnsupportedImage,

    /// <summary>The four corner finders were not found.</summary>
    NoFinders,

    /// <summary>Finders were found but no orientation produced a readable lane.</summary>
    NoOrientation,
}

/// <summary>A lane that passed its Reed–Solomon check.</summary>
public sealed class PetalLaneResult : IEquatable<PetalLaneResult>
{
    internal PetalLaneResult(byte[] data, int corrected, int erasures)
    {
        Data = data;
        Corrected = corrected;
        Erasures = erasures;
    }

    /// <summary>Lane data bytes (header and atoms, or the beacon).</summary>
    public byte[] Data { get; }

    /// <summary>
    /// Byte positions the Reed–Solomon decoder rewrote: the erased bytes plus any
    /// errors it found among the others (a measure of how close the lane was to
    /// failing).
    /// </summary>
    public int Corrected { get; }

    /// <summary>Bytes that were passed to the Reed–Solomon decoder as erasures.</summary>
    public int Erasures { get; }

    /// <inheritdoc />
    public bool Equals(PetalLaneResult? other) => other is not null
        && Corrected == other.Corrected
        && Erasures == other.Erasures
        && Data.AsSpan().SequenceEqual(other.Data);

    /// <inheritdoc />
    public override bool Equals(object? obj) => Equals(obj as PetalLaneResult);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(Data);
        hash.Add(Corrected);
        hash.Add(Erasures);
        return hash.ToHashCode();
    }
}

/// <summary>Everything read from one camera frame.</summary>
public sealed class PetalDecodedFrame
{
    internal PetalDecodedFrame(
        PetalHomography homography,
        int rotation,
        bool mirrored,
        PetalLaneResult? p,
        PetalLaneResult? k,
        PetalLaneResult? d,
        int? inferredCorner)
    {
        Homography = homography;
        Rotation = rotation;
        Mirrored = mirrored;
        P = p;
        K = k;
        D = d;
        InferredCorner = inferredCorner;
    }

    /// <summary>Canvas-to-pixel homography that was used.</summary>
    public PetalHomography Homography { get; }

    /// <summary>Orientation hypothesis: how many quarter turns the finder order was rotated.</summary>
    public int Rotation { get; }

    /// <summary>Whether the image was mirrored.</summary>
    public bool Mirrored { get; }

    /// <summary>Lane <c>P</c> result.</summary>
    public PetalLaneResult? P { get; }

    /// <summary>Lane <c>K</c> result.</summary>
    public PetalLaneResult? K { get; }

    /// <summary>Lane <c>D</c> result.</summary>
    public PetalLaneResult? D { get; }

    /// <summary>
    /// The corner finder that was hidden (by a finger, a glare or the edge of the frame) and
    /// inferred from the other three, as its canonical index: 0 top-left, 1 top-right,
    /// 2 bottom-right, 3 bottom-left of the upright code; <see langword="null"/> when all four
    /// blossoms were seen.
    /// </summary>
    public int? InferredCorner { get; }

    /// <summary>Number of lanes that decoded.</summary>
    public int LanesOk => (P is null ? 0 : 1) + (K is null ? 0 : 1) + (D is null ? 0 : 1);

    /// <summary>Lanes that decoded, as letters from <c>"PKD"</c> in that order.</summary>
    public string Lanes => (P is null ? string.Empty : "P") + (K is null ? string.Empty : "K") + (D is null ? string.Empty : "D");

    /// <summary>What lane <c>D</c> carried, when it decoded.</summary>
    /// <returns>The parsed lane, or <see langword="null"/>.</returns>
    public PetalDLane? DLane() => D is null ? null : PetalStream.ParseDLane(D.Data);

    /// <summary>The beacon, when lane <c>D</c> decoded on a beacon frame.</summary>
    /// <returns>The beacon, or <see langword="null"/>.</returns>
    public PetalBeacon? Beacon() => DLane()?.Beacon;

    /// <summary>Atom packets from every lane that decoded (<c>P</c>, <c>K</c>, then <c>D</c>).</summary>
    /// <returns>The packets.</returns>
    public IReadOnlyList<PetalAtomPacket> AtomPackets()
    {
        var packets = new List<PetalAtomPacket>(3);
        if (P is not null && PetalStream.ParseAtomLane(PetalLane.P, P.Data) is { } p)
            packets.Add(p);
        if (K is not null && PetalStream.ParseAtomLane(PetalLane.K, K.Data) is { } k)
            packets.Add(k);
        if (DLane()?.Atoms is { } d)
            packets.Add(d);
        return packets;
    }

    /// <summary>Offers everything this frame carries to <paramref name="assembler"/> (lane <c>D</c> first).</summary>
    /// <param name="assembler">The stream assembler.</param>
    public void Feed(PetalStreamAssembler assembler)
    {
        ArgumentNullException.ThrowIfNull(assembler);
        if (DLane() is { } lane)
            assembler.PushDLane(lane);
        if (P is not null && PetalStream.ParseAtomLane(PetalLane.P, P.Data) is { } p)
            assembler.PushAtoms(p);
        if (K is not null && PetalStream.ParseAtomLane(PetalLane.K, K.Data) is { } k)
            assembler.PushAtoms(k);
    }
}

/// <summary>The outcome of <see cref="PetalDecoder.Decode"/>: a frame or the reason there is none.</summary>
public readonly struct PetalDecodeResult
{
    private PetalDecodeResult(PetalDecodedFrame? frame, PetalDecodeError? error)
    {
        Frame = frame;
        Error = error;
    }

    /// <summary>The decoded frame on success.</summary>
    public PetalDecodedFrame? Frame { get; }

    /// <summary>Why decoding failed, or <see langword="null"/> on success.</summary>
    public PetalDecodeError? Error { get; }

    /// <summary>Whether a frame was decoded (at least one lane passed its code).</summary>
    [MemberNotNullWhen(true, nameof(Frame))]
    [MemberNotNullWhen(false, nameof(Error))]
    public bool Success => Frame is not null;

    internal static PetalDecodeResult Ok(PetalDecodedFrame frame) => new(frame, null);

    internal static PetalDecodeResult Fail(PetalDecodeError error) => new(null, error);
}

/// <summary>Owned tile patches and finder levels from one decoded capture (about 128 KB).</summary>
public sealed class PetalTileEvidence
{
    internal PetalTileEvidence(double[] patches, PetalDecoder.Reference reference)
    {
        Patches = patches;
        Reference = reference;
    }

    internal double[] Patches { get; }
    internal PetalDecoder.Reference Reference { get; }
}

/// <summary>
/// From a camera luma plane to lane data.
/// </summary>
/// <remarks>
/// <para>
/// The decoder locates the corner finders, derives a homography for each
/// orientation hypothesis (four rotations, optionally mirrored), ranks the
/// hypotheses by how well the ring gates and the <c>天</c> silhouette line up,
/// takes the first whose lane <c>D</c> (or else a tile lane) codeword checks
/// out, then reads the tiles and dots. When one blossom is hidden, its corner is
/// inferred from the other three and moved to where the dotted rings line up
/// best; <see cref="PetalDecodedFrame.InferredCorner"/> reports it. Every tile is
/// classified jointly: its 8×8 sample patch is compared against the 32
/// hypotheses (polarity × glyph) and the best match wins, so the katakana and the
/// light/dark bit help each other. Cells the decoder is unsure about become
/// Reed–Solomon erasures.
/// </para>
/// <para>
/// <see cref="Track"/> reads the next camera frame by following the pose of the
/// previous one, which skips the finder search.
/// </para>
/// <para>
/// The tile <em>level read</em> judges every patch against the light and dark
/// levels measured at the finders. When it leaves lane <c>P</c> or <c>K</c>
/// unreadable, the <em>normalised read</em> is tried for the missing lane: it
/// rescales each patch (and each template) by its own contrast, so
/// over-exposure, veiling light, glare, shadows and gradients cancel out.
/// </para>
/// <para>
/// Untrusted images never raise exceptions: every failure is reported through
/// <see cref="PetalDecodeResult"/>. A lane that decodes is protected by its
/// Reed–Solomon code and, end to end, by the payload CRC-32C.
/// </para>
/// </remarks>
public static class PetalDecoder
{
    /// <summary>Smallest accepted image side in pixels.</summary>
    public const int MinimumImageSide = 48;

    private const int Patch = PetalGlyphs.TemplateSize;
    private const int Cells = Patch * Patch;
    private const int Hypotheses = 2 * PetalGlyphs.GlyphCount;

    /// <summary>Number of values in the raw patches of all tiles.</summary>
    private const int PatchValues = PetalLayout.TileCount * Cells;

    /// <summary>Relative level of the glyph ink on a light tile (ink / light fill).</summary>
    private const double InkOnLight = 0.04;

    /// <summary>Relative level of a pink glyph on a dark tile (pink / light fill).</summary>
    private const double PinkOnDark = 0.83;

    /// <summary>
    /// Cells cut from each end of a sorted patch to find its robust darkest and brightest level.
    /// </summary>
    private const int PatchCut = Cells / 10;

    /// <summary>
    /// Tiles whose contrast is below this fraction of the median tile contrast become erasures
    /// in the normalised read.
    /// </summary>
    private const double WeakTile = 0.25;

    /// <summary>Smallest span (in luma levels) of a camera patch that counts as contrast.</summary>
    private const double PatchSpanFloor = 1.0;

    /// <summary>Smallest span (in relative levels) of a template that counts as contrast.</summary>
    private const double TemplateSpanFloor = 0.001;

    private static readonly ConcurrentDictionary<long, double[]> PatternCache = new();
    private static readonly ConcurrentDictionary<long, double[]> NormalisedPatternCache = new();
    private static readonly bool[] NoErasures = new bool[PetalLayout.TileCount];
    private static readonly double[] ReferenceCos = new double[8];
    private static readonly double[] ReferenceSin = new double[8];
    private static readonly double[] TileOffsets = [-0.25, -0.25, 0.25, -0.25, -0.25, 0.25, 0.25, 0.25];
    private static readonly bool[] Mirrorings = [false, true];
    private static readonly PetalPoint[] EmptyCells = BuildEmptyCells();

    static PetalDecoder()
    {
        for (var k = 0; k < 8; k++)
        {
            var angle = Math.Tau * k / 8.0;
            ReferenceCos[k] = Math.Cos(angle);
            ReferenceSin[k] = Math.Sin(angle);
        }
    }

    /// <summary>Decodes one camera frame.</summary>
    /// <remarks>
    /// Tries the finder candidates of <see cref="PetalLocator.Candidates"/> in order and returns
    /// the first that reads. For each, the orientation hypotheses (four quarter turns,
    /// optionally mirrored) are ranked by the ring gates plus the <c>天</c>; lane <c>D</c> is
    /// tried under the best three whose gate score is at least 0.2, then the tile lanes under
    /// the best four.
    /// </remarks>
    /// <param name="image">The luma plane.</param>
    /// <param name="options">Decoder options; <see cref="PetalDecodeOptions.Default"/> when omitted.</param>
    /// <returns>
    /// The frame, or <see cref="PetalDecodeError.UnsupportedImage"/>,
    /// <see cref="PetalDecodeError.NoFinders"/> when no code is visible, or
    /// <see cref="PetalDecodeError.NoOrientation"/> when no orientation yields a readable lane.
    /// </returns>
    public static PetalDecodeResult Decode(PetalLuma image, PetalDecodeOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(image);
        options ??= PetalDecodeOptions.Default;
        if (!Supported(image, options))
            return PetalDecodeResult.Fail(PetalDecodeError.UnsupportedImage);
        var located = false;
        foreach (var set in PetalLocator.Candidates(image))
        {
            located = true;
            if (DecodeCandidate(image, options, set) is { } frame)
                return PetalDecodeResult.Ok(frame);
        }

        return PetalDecodeResult.Fail(located ? PetalDecodeError.NoOrientation : PetalDecodeError.NoFinders);
    }

    /// <summary>
    /// Follows a code from the previous frame that decoded, without searching the whole image
    /// for finders (the most expensive part of <see cref="Decode"/>).
    /// </summary>
    /// <remarks>
    /// Each corner finder seen in the previous frame is re-found near where the previous pose
    /// puts it (see <see cref="PetalLocator.Follow"/>); the mean movement of those predicts the
    /// rest. A corner inferred in the previous frame counts as seen again only when its blossom
    /// is re-found within a quarter diameter of that prediction (so a thumb beside it does not
    /// count). When exactly one corner is missing it is placed at the prediction and refined
    /// against the rings like an inferred corner. The orientation is kept from the previous
    /// frame.
    /// </remarks>
    /// <param name="image">The luma plane of the next camera frame.</param>
    /// <param name="previous">The last frame that decoded.</param>
    /// <param name="options">Decoder options; <see cref="PetalDecodeOptions.Default"/> when omitted.</param>
    /// <returns>
    /// The frame, or <see langword="null"/> when the image is unusable, the previous pose is
    /// broken, two corners are lost or no lane decodes; the caller then runs <see cref="Decode"/>.
    /// </returns>
    public static PetalDecodedFrame? Track(PetalLuma image, PetalDecodedFrame previous, PetalDecodeOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(image);
        ArgumentNullException.ThrowIfNull(previous);
        options ??= PetalDecodeOptions.Default;
        // a frame naming a corner that does not exist is refused like a broken pose
        if (!Supported(image, options) || previous.InferredCorner is { } named && (uint)named > 3)
            return null;
        var h0 = previous.Homography;
        Span<PetalFinder> expected = stackalloc PetalFinder[4];
        double shortSide = Math.Min(image.Width, image.Height);
        for (var i = 0; i < 4; i++)
        {
            var center = PetalLayout.FinderCenterTable[i];
            var (cx, cy) = (center.X, center.Y);
            h0.Apply(cx, cy, out var x, out var y);
            var size = PetalMath.Max(
                ProjectedLength(h0, cx - 60.0, cy, cx + 60.0, cy),
                ProjectedLength(h0, cx, cy - 60.0, cx, cy + 60.0));
            expected[i] = new PetalFinder(x, y, size);
        }

        foreach (var f in expected)
        {
            if (!(double.IsFinite(f.X) && double.IsFinite(f.Y) && double.IsFinite(f.Size)) || f.Size > shortSide)
                return null;
        }

        var previouslyInferred = previous.InferredCorner ?? -1;
        Span<PetalFinder> found = stackalloc PetalFinder[4];
        Span<bool> seen = stackalloc bool[4];
        for (var i = 0; i < 4; i++)
        {
            if (i != previouslyInferred && PetalLocator.Follow(image, expected[i]) is { } f)
            {
                found[i] = f;
                seen[i] = true;
            }
        }

        // the mean movement of the corners that were followed predicts the others
        var (sumX, sumY, followed) = (PetalMath.SumIdentity, PetalMath.SumIdentity, 0);
        for (var i = 0; i < 4; i++)
        {
            if (!seen[i])
                continue;
            sumX += found[i].X - expected[i].X;
            sumY += found[i].Y - expected[i].Y;
            followed++;
        }

        if (followed < 3)
            return null;
        var (shiftX, shiftY) = (sumX / followed, sumY / followed);
        // a corner that was hidden is seen again only when its blossom is found right where
        // the others say it is (a bright thumb beside it must not count)
        if (previouslyInferred >= 0)
        {
            var at = Predicted(expected[previouslyInferred], shiftX, shiftY);
            if (PetalLocator.Follow(image, at) is { } f
                && Math.Sqrt((f.X - at.X) * (f.X - at.X) + (f.Y - at.Y) * (f.Y - at.Y)) <= 0.25 * at.Size)
            {
                found[previouslyInferred] = f;
                seen[previouslyInferred] = true;
            }
        }

        int? inferred = null;
        for (var i = 0; i < 4; i++)
        {
            if (seen[i])
                continue;
            if (inferred is not null)
                return null;
            inferred = i;
        }

        var corners = found.ToArray();
        if (inferred is { } m)
        {
            corners[m] = Predicted(expected[m], shiftX, shiftY);
            corners = RefineInferredCorner(image, corners, m);
        }

        Span<PetalPoint> points = stackalloc PetalPoint[4];
        for (var i = 0; i < 4; i++)
            points[i] = new PetalPoint(corners[i].X, corners[i].Y);
        if (PetalHomography.FromPoints(PetalLayout.FinderCenterTable, points) is not { } h)
            return null;
        if (ReferenceLevels(image, h, inferred) is not { } reference)
            return null;
        var d = ReadLaneD(image, h, reference);
        using var patches = PooledValues.Rent(PatchValues);
        SamplePatches(image, h, patches.Span);
        var (p, k) = ReadTileLanes(patches.Span, reference, options.TemplateSigmas);
        if (p is null && k is null && d is null)
            return null;
        return new PetalDecodedFrame(h, previous.Rotation, previous.Mirrored, p, k, d, inferred);
    }

    /// <summary>Reads all lanes with a known canvas-to-pixel homography (no finder search).</summary>
    /// <remarks>
    /// Used by trackers that already know the pose, by refinement passes and by
    /// qualification tooling with a ground-truth pose.
    /// </remarks>
    /// <param name="image">The luma plane.</param>
    /// <param name="homography">Canvas-to-pixel transform.</param>
    /// <param name="options">Decoder options; <see cref="PetalDecodeOptions.Default"/> when omitted.</param>
    /// <returns>
    /// The frame, or <see langword="null"/> when the image is unusable (see
    /// <see cref="PetalDecodeError.UnsupportedImage"/>) or the finder reference levels are too weak.
    /// </returns>
    public static PetalDecodedFrame? DecodeAt(PetalLuma image, PetalHomography homography, PetalDecodeOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(image);
        options ??= PetalDecodeOptions.Default;
        if (!Supported(image, options))
            return null;
        var reference = ReferenceLevels(image, homography, null);
        if (reference is null)
            return null;
        return Finish(image, options, 0, false, homography, reference.Value, null, null);
    }

    /// <summary>Samples owned tile evidence under a decoded pose; unusable images or poses return null.</summary>
    public static PetalTileEvidence? TileEvidence(PetalLuma image, PetalDecodedFrame frame, PetalDecodeOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(image);
        ArgumentNullException.ThrowIfNull(frame);
        options ??= PetalDecodeOptions.Default;
        if (!Supported(image, options) || frame.InferredCorner is { } corner && (uint)corner > 3)
            return null;
        if (ReferenceLevels(image, frame.Homography, frame.InferredCorner) is not { } reference)
            return null;
        var patches = new double[PatchValues];
        SamplePatches(image, frame.Homography, patches);
        return new PetalTileEvidence(patches, reference);
    }

    /// <summary>
    /// Reads tile lanes from the ordered mean of captures of one shown frame. The caller
    /// must group captures by independently decoded headers and check recovered headers.
    /// </summary>
    public static (PetalLaneResult? P, PetalLaneResult? K) MergeTiles(
        IReadOnlyList<PetalTileEvidence> evidence, PetalDecodeOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        if (evidence.Count == 0)
            return (null, null);
        options ??= PetalDecodeOptions.Default;
        using var mean = PooledValues.Rent(PatchValues);
        using var levelled = PooledValues.Rent(PatchValues);
        mean.Span.Clear();
        foreach (var item in evidence)
        {
            LevelPatches(item.Patches, item.Reference, levelled.Span);
            for (var i = 0; i < PatchValues; i++)
                mean.Span[i] += levelled.Span[i];
        }
        for (var i = 0; i < PatchValues; i++)
            mean.Span[i] /= evidence.Count;
        var (pWord, pConfidence, kWord, kConfidence) = TileWords(Classify(mean.Span, options.TemplateSigmas, false, NoErasures));
        var p = DecodeWithErasures(PetalLane.P, pWord, pConfidence);
        var k = DecodeWithErasures(PetalLane.K, kWord, kConfidence);
        if (p is null || k is null)
        {
            mean.Span.Clear();
            foreach (var item in evidence)
                for (var i = 0; i < PatchValues; i++)
                    mean.Span[i] += item.Patches[i];
            for (var i = 0; i < PatchValues; i++)
                mean.Span[i] /= evidence.Count;
            (pWord, pConfidence, kWord, kConfidence) = TileWords(ReadTilesNormalised(mean.Span, options.TemplateSigmas));
            p ??= DecodeWithErasures(PetalLane.P, pWord, pConfidence);
            k ??= DecodeWithErasures(PetalLane.K, kWord, kConfidence);
        }
        return (p, k);
    }

    /// <summary>Builds the cells a decoder believes it saw, for diagnostics.</summary>
    /// <remarks>
    /// Tiles are taken from the level read (the one that judges against the finder levels),
    /// even for a frame whose lanes were rescued by the normalised read. The levels of a corner
    /// the frame inferred are extrapolated as in the decoder.
    /// </remarks>
    /// <param name="image">The luma plane the frame was decoded from.</param>
    /// <param name="frame">The decoded frame.</param>
    /// <param name="options">Decoder options; <see cref="PetalDecodeOptions.Default"/> when omitted.</param>
    /// <returns>
    /// The observed cells, or <see langword="null"/> when the image is unusable or the reference
    /// levels are too weak.
    /// </returns>
    public static PetalFrameCells? ObservedCells(PetalLuma image, PetalDecodedFrame frame, PetalDecodeOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(image);
        ArgumentNullException.ThrowIfNull(frame);
        options ??= PetalDecodeOptions.Default;
        if (!Supported(image, options))
            return null;
        var reference = ReferenceLevels(image, frame.Homography, frame.InferredCorner);
        if (reference is null)
            return null;
        using var patches = PooledValues.Rent(PatchValues);
        SamplePatches(image, frame.Homography, patches.Span);
        var reads = ReadTiles(patches.Span, reference.Value, options.TemplateSigmas);
        var (p, _, k, _) = TileWords(reads);
        var (d, _) = ReadDots(image, frame.Homography, reference.Value);
        return PetalFrameCells.FromWords(p, k, d);
    }

    /// <summary>Mean squared tile-match error of the level read, a quick image-quality indicator.</summary>
    /// <remarks>
    /// It can be large for a frame whose lanes were rescued by the normalised read, which is the
    /// point: the finder levels did not describe that picture.
    /// </remarks>
    /// <param name="image">The luma plane the frame was decoded from.</param>
    /// <param name="frame">The decoded frame.</param>
    /// <param name="options">Decoder options; <see cref="PetalDecodeOptions.Default"/> when omitted.</param>
    /// <returns>
    /// The mean error, or <see langword="null"/> when the image is unusable or the reference
    /// levels are too weak.
    /// </returns>
    public static double? TileMatchError(PetalLuma image, PetalDecodedFrame frame, PetalDecodeOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(image);
        ArgumentNullException.ThrowIfNull(frame);
        options ??= PetalDecodeOptions.Default;
        if (!Supported(image, options))
            return null;
        var reference = ReferenceLevels(image, frame.Homography, frame.InferredCorner);
        if (reference is null)
            return null;
        using var patches = PooledValues.Rent(PatchValues);
        SamplePatches(image, frame.Homography, patches.Span);
        var reads = ReadTiles(patches.Span, reference.Value, options.TemplateSigmas);
        var total = PetalMath.SumIdentity;
        foreach (var read in reads)
            total += read.Error;
        return total / reads.Length;
    }

    private static bool Supported(PetalLuma image, PetalDecodeOptions options) =>
        image.Width >= MinimumImageSide
        && image.Height >= MinimumImageSide
        && (long)image.Width * image.Height <= options.MaxPixels
        // the locator's integral image must fit in one array, whatever MaxPixels says
        && (long)(image.Width + 1) * (image.Height + 1) <= Array.MaxLength;

    /// <summary>Completes a frame under one pose: lane <c>D</c> unless already read, then the tile lanes.</summary>
    private static PetalDecodedFrame Finish(
        PetalLuma image,
        PetalDecodeOptions options,
        int rotation,
        bool mirrored,
        in PetalHomography h,
        in Reference reference,
        PetalLaneResult? d,
        int? inferredCorner)
    {
        d ??= ReadLaneD(image, h, reference);
        using var patches = PooledValues.Rent(PatchValues);
        SamplePatches(image, h, patches.Span);
        var (p, k) = ReadTileLanes(patches.Span, reference, options.TemplateSigmas);
        return new PetalDecodedFrame(h, rotation, mirrored, p, k, d, inferredCorner);
    }

    /// <summary>
    /// One finder candidate: refines an inferred corner against the rings, ranks the
    /// orientation hypotheses by gate score plus <c>天</c> score, then tries lane <c>D</c> under
    /// the best three whose gate score is at least 0.2 and the tile lanes under the best four.
    /// </summary>
    private static PetalDecodedFrame? DecodeCandidate(PetalLuma image, PetalDecodeOptions options, PetalFinderSet set)
    {
        var corners = set.Inferred is { } index
            ? RefineInferredCorner(image, set.CornerArray, index)
            : set.CornerArray;
        var scored = new List<Scored>(8);
        foreach (var (rotation, mirrored, h) in HypothesesFor(corners, options.TryMirrored))
        {
            int? inferred = set.Inferred is { } corner ? CanonicalCorner(corner, rotation, mirrored) : null;
            if (ReferenceLevels(image, h, inferred) is not { } reference)
                continue;
            var gate = GateScore(image, h, reference);
            var mask = MaskScore(image, h, reference);
            var candidate = new Scored(gate, mask, rotation, mirrored, h, reference, inferred);
            // Stable descending insertion by gate + mask (Rust `sort_by` with `b.total_cmp(a)`).
            var key = gate + mask;
            var at = scored.Count;
            while (at > 0 && PetalMath.TotalCompare(key, scored[at - 1].Gate + scored[at - 1].Mask) > 0)
                at--;
            scored.Insert(at, candidate);
        }

        // 1. the ring beacon is the cheapest and strongest orientation check
        for (var i = 0; i < Math.Min(3, scored.Count); i++)
        {
            var s = scored[i];
            // the order is no longer by gate score, so a weak gate skips only this hypothesis
            if (s.Gate < 0.2)
                continue;
            if (ReadLaneD(image, s.Homography, s.Reference) is { } d)
                return Finish(image, options, s.Rotation, s.Mirrored, s.Homography, s.Reference, d, s.InferredCorner);
        }

        // 2. fall back to the tile lanes under the most promising orientations
        using var patches = PooledValues.Rent(PatchValues);
        for (var i = 0; i < Math.Min(4, scored.Count); i++)
        {
            var s = scored[i];
            SamplePatches(image, s.Homography, patches.Span);
            var (p, k) = ReadTileLanes(patches.Span, s.Reference, options.TemplateSigmas);
            if (p is null && k is null)
                continue;
            var d = ReadLaneD(image, s.Homography, s.Reference);
            return new PetalDecodedFrame(s.Homography, s.Rotation, s.Mirrored, p, k, d, s.InferredCorner);
        }

        return null;
    }

    /// <summary>Canonical index of the corner at <paramref name="index"/> of a finder quad under one orientation hypothesis.</summary>
    internal static int CanonicalCorner(int index, int rotation, bool mirrored) =>
        mirrored ? (rotation + 4 - index) % 4 : (index + 4 - rotation) % 4;

    /// <summary>The length of the image of the canvas segment from <c>(x0, y0)</c> to <c>(x1, y1)</c>.</summary>
    private static double ProjectedLength(in PetalHomography h, double x0, double y0, double x1, double y1)
    {
        h.Apply(x0, y0, out var ax, out var ay);
        h.Apply(x1, y1, out var bx, out var by);
        return Math.Sqrt((ax - bx) * (ax - bx) + (ay - by) * (ay - by));
    }

    private static PetalFinder Predicted(PetalFinder expected, double shiftX, double shiftY) =>
        new(expected.X + shiftX, expected.Y + shiftY, expected.Size);

    /// <summary>
    /// The brightness summed over all ring slots under the pose that maps the canonical corners
    /// onto <paramref name="corners"/> (in quad order).
    /// </summary>
    /// <remarks>
    /// The slots form the same set of points under every quarter turn and mirror of the canvas
    /// (80, 92 and 104 are multiples of four), so the value does not depend on the orientation.
    /// </remarks>
    internal static double? RingBrightness(PetalLuma image, ReadOnlySpan<PetalPoint> corners)
    {
        if (PetalHomography.FromPoints(PetalLayout.FinderCenterTable, corners) is not { } h)
            return null;
        var sum = PetalMath.SumIdentity;
        for (var flat = 0; flat < PetalLayout.TotalSlots; flat++)
        {
            var center = PetalLayout.SlotCenterFlat(flat);
            sum += DotSamples(image, h, center.X, center.Y, 3.5);
        }

        return sum;
    }

    /// <summary>
    /// Moves an inferred corner to where the three dotted rings line up best: a 13 × 13 search
    /// in steps of 2 % of the mean leg around the parallelogram estimate, then a 9 × 9 search
    /// in steps of 0.5 % around the best point.
    /// </summary>
    /// <remarks>
    /// The rings fix the geometry only; the orientation is decided afterwards by the gates and
    /// the <c>天</c>. A candidate replaces the best point only when it is strictly brighter.
    /// </remarks>
    internal static PetalFinder[] RefineInferredCorner(PetalLuma image, PetalFinder[] corners, int inferred)
    {
        Span<PetalPoint> points = stackalloc PetalPoint[4];
        for (var i = 0; i < 4; i++)
            points[i] = new PetalPoint(corners[i].X, corners[i].Y);
        var start = points[inferred];
        var leg = 0.5 * (Distance(points[(inferred + 1) % 4], start) + Distance(points[(inferred + 3) % 4], start));
        var bestBrightness = double.MinValue;
        var best = start;
        SearchRings(image, points, inferred, start, 0.02 * leg, 6, ref bestBrightness, ref best);
        SearchRings(image, points, inferred, best, 0.005 * leg, 4, ref bestBrightness, ref best);
        var refined = (PetalFinder[])corners.Clone();
        refined[inferred] = new PetalFinder(best.X, best.Y, corners[inferred].Size);
        return refined;
    }

    private static double Distance(PetalPoint point, PetalPoint start) =>
        Math.Sqrt((point.X - start.X) * (point.X - start.X) + (point.Y - start.Y) * (point.Y - start.Y));

    /// <summary>One grid of <see cref="RefineInferredCorner"/>: <c>dy</c> outer, <c>dx</c> inner.</summary>
    private static void SearchRings(
        PetalLuma image,
        Span<PetalPoint> points,
        int inferred,
        PetalPoint centre,
        double step,
        int reach,
        ref double bestBrightness,
        ref PetalPoint best)
    {
        for (var dy = -reach; dy <= reach; dy++)
        {
            for (var dx = -reach; dx <= reach; dx++)
            {
                var candidate = new PetalPoint(centre.X + dx * step, centre.Y + dy * step);
                points[inferred] = candidate;
                if (RingBrightness(image, points) is { } brightness && brightness > bestBrightness)
                {
                    bestBrightness = brightness;
                    best = candidate;
                }
            }
        }
    }

    /// <summary>
    /// How well the <c>天</c> lines up: the mean normalised level over the tiles (each sampled at
    /// five points across the tile, so a glyph stroke at the centre does not decide it) minus
    /// the mean over the empty lattice cells.
    /// </summary>
    /// <remarks>
    /// The mask is symmetric left to right but not top to bottom, so this tells the four quarter
    /// turns apart even when the ring gates are damaged.
    /// </remarks>
    internal static double MaskScore(PetalLuma image, in PetalHomography h, in Reference reference)
    {
        var tiles = PetalMath.SumIdentity;
        for (var tile = 0; tile < PetalLayout.TileCount; tile++)
        {
            var center = PetalLayout.TileCenterUnchecked(tile);
            tiles += MaskLevel(image, h, reference, center.X, center.Y);
        }

        var empty = PetalMath.SumIdentity;
        foreach (var cell in EmptyCells)
            empty += MaskLevel(image, h, reference, cell.X, cell.Y);
        return tiles / PetalLayout.TileCount - empty / EmptyCells.Length;
    }

    private static double MaskLevel(PetalLuma image, in PetalHomography h, in Reference reference, double x, double y)
    {
        reference.At(x, y, out var lit, out var dark);
        return (DotSamples(image, h, x, y, 8.0) - dark) / (lit - dark);
    }

    /// <summary>Centres of the lattice cells outside the <c>天</c> mask (no tile is ever drawn there), row-major.</summary>
    private static PetalPoint[] BuildEmptyCells()
    {
        var cells = new List<PetalPoint>();
        for (var row = 0; row < PetalLayout.TileGrid; row++)
        {
            var line = PetalLayout.Mask[row];
            for (var column = 0; column < line.Length; column++)
            {
                if (line[column] != '#')
                {
                    cells.Add(new PetalPoint(
                        PetalLayout.TileOrigin + PetalLayout.TilePitch * (column + 0.5),
                        PetalLayout.TileOrigin + PetalLayout.TilePitch * (row + 0.5)));
                }
            }
        }

        return cells.ToArray();
    }

    /// <summary>The orientation hypotheses of a finder quad: four quarter turns, then (optionally) four mirrored ones.</summary>
    internal static List<(int Rotation, bool Mirrored, PetalHomography Homography)> HypothesesFor(
        PetalFinder[] finders,
        bool tryMirrored)
    {
        var canonical = PetalLayout.FinderCenterTable;
        var output = new List<(int, bool, PetalHomography)>(8);
        Span<PetalPoint> destination = stackalloc PetalPoint[4];
        foreach (var mirrored in Mirrorings)
        {
            if (mirrored && !tryMirrored)
                continue;
            for (var rotation = 0; rotation < 4; rotation++)
            {
                for (var i = 0; i < 4; i++)
                {
                    var q = mirrored ? finders[(rotation + 4 - i) % 4] : finders[(i + rotation) % 4];
                    destination[i] = new PetalPoint(q.X, q.Y);
                }

                if (PetalHomography.FromPoints(canonical, destination) is { } h)
                    output.Add((rotation, mirrored, h));
            }
        }

        return output;
    }

    private static double DotSamples(PetalLuma image, in PetalHomography h, double x, double y, double spread)
    {
        var sum = 0.0;
        h.Apply(x + 0.0, y + 0.0, out var px, out var py);
        sum += image.Sample(px, py);
        h.Apply(x + spread, y + 0.0, out px, out py);
        sum += image.Sample(px, py);
        h.Apply(x + -spread, y + 0.0, out px, out py);
        sum += image.Sample(px, py);
        h.Apply(x + 0.0, y + spread, out px, out py);
        sum += image.Sample(px, py);
        h.Apply(x + 0.0, y + -spread, out px, out py);
        sum += image.Sample(px, py);
        return sum / 5.0;
    }

    /// <summary>
    /// Light and dark levels at the four corners: the solid blossom core, and the black canvas
    /// 100 units inward of it.
    /// </summary>
    /// <remarks>
    /// An <paramref name="inferred"/> corner (canonical index) was not seen, so its levels are
    /// extrapolated from the other three by the parallelogram rule and kept within their range.
    /// </remarks>
    /// <returns>
    /// The levels, or <see langword="null"/> when a seen corner has less than 12 levels of
    /// contrast or a non-finite one (only a broken pose produces that).
    /// </returns>
    internal static Reference? ReferenceLevels(PetalLuma image, in PetalHomography h, int? inferred)
    {
        var missing = inferred is { } m && (uint)m < 4 ? m : -1;
        var reference = new Reference();
        for (var i = 0; i < 4; i++)
        {
            if (i == missing)
                continue;
            var center = PetalLayout.FinderCenterTable[i];
            var (cx, cy) = (center.X, center.Y);
            // the blossom is solid out to radius 24 around its centre
            h.Apply(cx, cy, out var px, out var py);
            var sum = image.Sample(px, py);
            for (var k = 0; k < 8; k++)
            {
                h.Apply(cx + 20.0 * ReferenceCos[k], cy + 20.0 * ReferenceSin[k], out px, out py);
                sum += image.Sample(px, py);
            }

            var lit = sum / 9.0;
            var (sx, sy) = (cx < 512.0 ? 1.0 : -1.0, cy < 512.0 ? 1.0 : -1.0);
            var a = DotSamples(image, h, cx + sx * 100.0, cy, 5.0);
            var b = DotSamples(image, h, cx, cy + sy * 100.0, 5.0);
            var dark = 0.5 * (a + b);
            // also refuses NaN levels, which only a non-finite pose can produce
            if (!double.IsFinite(lit - dark) || lit - dark < 12.0)
                return null;
            reference.Set(i, lit, dark);
        }

        if (missing >= 0)
        {
            reference.Extrapolate(missing);
            // uneven light can push the estimates past each other; an inferred corner
            // needs the same contrast as a seen one
            if (reference.Lit(missing) - reference.Dark(missing) < 12.0)
                return null;
        }

        return reference;
    }

    private static double NormalisedDot(PetalLuma image, in PetalHomography h, in Reference reference, int flat)
    {
        var center = PetalLayout.SlotCenterFlat(flat);
        var (x, y) = (center.X, center.Y);
        reference.At(x, y, out var lit, out var dark);
        return (DotSamples(image, h, x, y, 3.5) - dark) / (lit - dark);
    }

    private static double GateScore(PetalLuma image, in PetalHomography h, in Reference reference)
    {
        var gates = PetalLayout.GateSlotTable;
        var guards = PetalLayout.GuardSlotTable;
        var gateSum = PetalMath.SumIdentity;
        foreach (var slot in gates)
            gateSum += NormalisedDot(image, h, reference, slot);
        var guardSum = PetalMath.SumIdentity;
        foreach (var slot in guards)
            guardSum += NormalisedDot(image, h, reference, slot);
        return gateSum / gates.Length - guardSum / guards.Length;
    }

    /// <summary>Reads lane <c>D</c>: the transmitted bytes and per-byte confidence.</summary>
    private static (byte[] Word, double[] Confidence) ReadDots(PetalLuma image, in PetalHomography h, in Reference reference)
    {
        var gates = PetalLayout.GateSlotTable;
        var guards = PetalLayout.GuardSlotTable;
        // per-ring thresholds from the gates (lit) and guards (dark)
        Span<double> thresholds = [0.5, 0.5, 0.5];
        for (var ring = 0; ring < PetalLayout.RingCount; ring++)
        {
            var litSum = PetalMath.SumIdentity;
            var litCount = 0;
            foreach (var slot in gates)
            {
                if (PetalLayout.SplitSlot(slot).Ring != ring)
                    continue;
                litSum += NormalisedDot(image, h, reference, slot);
                litCount++;
            }

            var darkSum = PetalMath.SumIdentity;
            var darkCount = 0;
            foreach (var slot in guards)
            {
                if (PetalLayout.SplitSlot(slot).Ring != ring)
                    continue;
                darkSum += NormalisedDot(image, h, reference, slot);
                darkCount++;
            }

            if (litCount > 0 && darkCount > 0)
            {
                var (l, d) = (litSum / litCount, darkSum / darkCount);
                if (l - d > 0.2)
                    thresholds[ring] = 0.5 * (l + d);
            }
        }

        var bytes = new byte[PetalLanes.DWordLength];
        var confidence = new double[PetalLanes.DWordLength];
        Array.Fill(confidence, double.MaxValue);
        var dataSlots = PetalLayout.DataSlotTable;
        for (var bit = 0; bit < dataSlots.Length; bit++)
        {
            var slot = dataSlots[bit];
            var value = NormalisedDot(image, h, reference, slot);
            var threshold = thresholds[PetalLayout.SplitSlot(slot).Ring];
            if (value > threshold)
                bytes[bit / 8] |= (byte)(1 << (7 - bit % 8));
            confidence[bit / 8] = PetalMath.Min(confidence[bit / 8], Math.Abs(value - threshold));
        }

        return (bytes, confidence);
    }

    /// <summary>Lane <c>D</c> under one pose.</summary>
    private static PetalLaneResult? ReadLaneD(PetalLuma image, in PetalHomography h, in Reference reference)
    {
        var (word, confidence) = ReadDots(image, h, reference);
        return DecodeWithErasures(PetalLane.D, word, confidence);
    }

    /// <summary>Tries Reed–Solomon with growing numbers of erasures, least confident first.</summary>
    /// <remarks>
    /// The schedule erases 0, ⅛, ¼, ⅓ and ½ of the parity bytes, and for lane <c>K</c> also ⅔.
    /// Lanes <c>D</c> and <c>P</c> stop at ½: their words have only 11 and 13 parity bytes, and a
    /// further erasure step leaves so few spare ones that it accepts wrong codewords (lane
    /// <c>D</c> at 7 erasures: about 0.4 % of random words, and 5 wrong lanes in 2 900 simulated
    /// harsh frames; lane <c>P</c> at 8: 2 wrong lanes in 600 banded 480p frames). Capping them
    /// costs 0.65 % of the lane <c>D</c> reads and 0.15 % of the lane <c>P</c> reads in those
    /// frames. Bytes of equal confidence keep their order (the sort is stable, like Rust's
    /// <c>sort_by</c>), which decides which of them are erased.
    /// </remarks>
    internal static PetalLaneResult? DecodeWithErasures(PetalLane lane, byte[] word, double[] confidence)
    {
        var nsym = PetalLanes.ParityLength(lane);
        Span<int> order = stackalloc int[word.Length];
        for (var i = 0; i < order.Length; i++)
            order[i] = i;
        PetalMath.StableSortByKey(order, confidence);
        Span<int> schedule = [0, nsym / 8, nsym / 4, nsym / 3, nsym / 2, nsym * 2 / 3];
        if (lane != PetalLane.K)
            schedule = schedule[..5];
        Span<byte> trial = stackalloc byte[word.Length];
        var previous = -1;
        foreach (var erasures in schedule)
        {
            // Rust `dedup` drops consecutive repeats.
            if (erasures == previous)
                continue;
            previous = erasures;
            var positions = order[..erasures];
            word.CopyTo(trial);
            // zero the erased bytes so stale values cannot leak through
            foreach (var position in positions)
                trial[position] = 0;
            if (PetalLanes.TryDecodeLane(lane, trial, positions, out var data, out var corrected))
                return new PetalLaneResult(data, corrected, positions.Length);
        }

        return null;
    }

    /// <summary>
    /// Expected patches for the level read, relative to the light fill (ink 0.04, pink 0.83):
    /// <c>pattern[(b * 16 + g) * 64 + cell]</c> for polarity <c>b</c> (1 = light tile) and
    /// glyph <c>g</c>.
    /// </summary>
    private static double[] Patterns(double sigma) =>
        PatternCache.GetOrAdd(BitConverter.DoubleToInt64Bits(sigma), static (_, s) => BuildPatterns(s), sigma);

    private static double[] BuildPatterns(double sigma)
    {
        Span<double> kernel = stackalloc double[5];
        for (var i = -2; i <= 2; i++)
        {
            double fi = i;
            kernel[i + 2] = sigma < 0.05
                ? (i == 0 ? 1.0 : 0.0)
                : Math.Exp(-(fi * fi) / (2.0 * sigma * sigma));
        }

        var sum = PetalMath.SumIdentity;
        foreach (var value in kernel)
            sum += value;
        for (var i = 0; i < kernel.Length; i++)
            kernel[i] /= sum;
        var patterns = new double[Hypotheses * Cells];
        Span<double> coverage = stackalloc double[Cells];
        Span<double> blurred = stackalloc double[Cells];
        for (var polarity = 0; polarity < 2; polarity++)
        {
            for (var glyph = 0; glyph < PetalGlyphs.GlyphCount; glyph++)
            {
                var template = PetalGlyphs.Template(glyph);
                for (var c = 0; c < Cells; c++)
                    coverage[c] = template[c] / 255.0;
                for (var v = 0; v < Patch; v++)
                {
                    for (var u = 0; u < Patch; u++)
                    {
                        var acc = 0.0;
                        for (var ky = 0; ky < kernel.Length; ky++)
                        {
                            for (var kx = 0; kx < kernel.Length; kx++)
                            {
                                var (sx, sy) = (u + kx - 2, v + ky - 2);
                                if (sx >= 0 && sx < Patch && sy >= 0 && sy < Patch)
                                    acc += kernel[kx] * kernel[ky] * coverage[sy * Patch + sx];
                            }
                        }

                        blurred[v * Patch + u] = acc;
                    }
                }

                var offset = (polarity * PetalGlyphs.GlyphCount + glyph) * Cells;
                for (var c = 0; c < Cells; c++)
                {
                    var ink = blurred[c];
                    patterns[offset + c] = polarity == 1 ? 1.0 - (1.0 - InkOnLight) * ink : PinkOnDark * ink;
                }
            }
        }

        return patterns;
    }

    /// <summary>
    /// Expected patches rescaled like the observed ones, for the normalised read: the
    /// <see cref="Patterns"/> with every template mapped to its own <c>[0, 1]</c> range.
    /// </summary>
    private static double[] NormalisedPatterns(double sigma) =>
        NormalisedPatternCache.GetOrAdd(BitConverter.DoubleToInt64Bits(sigma), static (_, s) => BuildNormalisedPatterns(s), sigma);

    private static double[] BuildNormalisedPatterns(double sigma)
    {
        var patterns = (double[])Patterns(sigma).Clone();
        for (var hypothesis = 0; hypothesis < Hypotheses; hypothesis++)
        {
            var pattern = patterns.AsSpan(hypothesis * Cells, Cells);
            Rescale(pattern, TemplateSpanFloor, pattern);
        }

        return patterns;
    }

    /// <summary>
    /// The raw 8×8 luma patch of every tile, as captured (no reference levels applied): each cell
    /// is the mean of four bilinear samples at ±¼ cell, in raw luma levels.
    /// </summary>
    /// <param name="image">The luma plane.</param>
    /// <param name="h">Canvas-to-pixel transform.</param>
    /// <param name="patches">Receives <c>patches[tile * 64 + v * 8 + u]</c> for all 256 tiles.</param>
    internal static void SamplePatches(PetalLuma image, in PetalHomography h, Span<double> patches)
    {
        const double half = PetalLayout.GlyphBox / 2.0;
        const double cell = PetalLayout.GlyphBox / Patch;
        for (var tile = 0; tile < PetalLayout.TileCount; tile++)
        {
            var center = PetalLayout.TileCenterUnchecked(tile);
            var (cx, cy) = (center.X, center.Y);
            var patch = patches.Slice(tile * Cells, Cells);
            for (var v = 0; v < Patch; v++)
            {
                for (var u = 0; u < Patch; u++)
                {
                    var gx = cx - half + (u + 0.5) * cell;
                    var gy = cy - half + (v + 0.5) * cell;
                    var sum = 0.0;
                    for (var o = 0; o < TileOffsets.Length; o += 2)
                    {
                        h.Apply(gx + TileOffsets[o] * cell, gy + TileOffsets[o + 1] * cell, out var px, out var py);
                        sum += image.Sample(px, py);
                    }

                    patch[v * Patch + u] = sum / 4.0;
                }
            }
        }
    }

    /// <summary>
    /// The robust darkest and brightest level of a patch: the values <see cref="PatchCut"/> cells
    /// in from either end of the sorted cells.
    /// </summary>
    /// <param name="values">The 64 cells of one patch.</param>
    /// <returns>The darkest and brightest level.</returns>
    internal static (double Low, double High) PatchLevels(ReadOnlySpan<double> values)
    {
        if (values.Length != Cells)
            throw new ArgumentException("A patch has exactly 64 cells.", nameof(values));
        Span<double> sorted = stackalloc double[Cells];
        values.CopyTo(sorted);
        PetalMath.SortTotal(sorted);
        return (sorted[PatchCut], sorted[Cells - 1 - PatchCut]);
    }

    /// <summary>
    /// Maps a patch's own darkest level to 0 and brightest to 1, with <paramref name="floor"/> as
    /// the smallest span that counts as contrast, clamped to <c>[-0.25, 1.25]</c>.
    /// </summary>
    /// <param name="values">The 64 cells of one patch.</param>
    /// <param name="floor">Smallest span treated as contrast.</param>
    /// <param name="destination">Receives the rescaled cells; may be the same memory as <paramref name="values"/>.</param>
    internal static void Rescale(ReadOnlySpan<double> values, double floor, Span<double> destination)
    {
        var (low, high) = PatchLevels(values);
        Rescale(values, low, high, floor, destination);
    }

    private static void Rescale(ReadOnlySpan<double> values, double low, double high, double floor, Span<double> destination)
    {
        var range = PetalMath.Max(high - low, floor);
        for (var c = 0; c < Cells; c++)
            destination[c] = Math.Clamp((values[c] - low) / range, -0.25, 1.25);
    }

    /// <summary>
    /// Picks for every patch the polarity and glyph whose template matches best.
    /// </summary>
    /// <remarks>
    /// The template blur is chosen per frame, by the lowest total error. With
    /// <paramref name="rescaleTemplates"/> the templates are rescaled like the patches; tiles
    /// flagged in <paramref name="erased"/> get zero margins, so they are the first the
    /// Reed–Solomon decoder treats as erasures.
    /// </remarks>
    private static TileRead[] Classify(
        ReadOnlySpan<double> patches,
        IReadOnlyList<double> sigmas,
        bool rescaleTemplates,
        ReadOnlySpan<bool> erased)
    {
        var bestTotal = double.MaxValue;
        var bestReads = Array.Empty<TileRead>();
        TileRead[]? spare = null;
        Span<double> errors = stackalloc double[Hypotheses];
        for (var s = 0; s < sigmas.Count; s++)
        {
            var patterns = rescaleTemplates ? NormalisedPatterns(sigmas[s]) : Patterns(sigmas[s]);
            var total = 0.0;
            var reads = spare ?? new TileRead[PetalLayout.TileCount];
            for (var tile = 0; tile < PetalLayout.TileCount; tile++)
            {
                var patch = patches.Slice(tile * Cells, Cells);
                for (var hypothesis = 0; hypothesis < Hypotheses; hypothesis++)
                {
                    var pattern = patterns.AsSpan(hypothesis * Cells, Cells);
                    var error = PetalMath.SumIdentity;
                    for (var c = 0; c < Cells; c++)
                    {
                        var difference = patch[c] - pattern[c];
                        error += difference * difference;
                    }

                    errors[hypothesis] = error;
                }

                // Rust `min_by` keeps the first of equal minima.
                var best = 0;
                for (var hypothesis = 1; hypothesis < Hypotheses; hypothesis++)
                {
                    if (PetalMath.TotalCompare(errors[hypothesis], errors[best]) < 0)
                        best = hypothesis;
                }

                var polarity = best / PetalGlyphs.GlyphCount;
                var glyph = best % PetalGlyphs.GlyphCount;
                var otherPolarity = double.MaxValue;
                for (var g = 0; g < PetalGlyphs.GlyphCount; g++)
                    otherPolarity = PetalMath.Min(otherPolarity, errors[(1 - polarity) * PetalGlyphs.GlyphCount + g]);
                var otherGlyph = double.MaxValue;
                for (var g = 0; g < PetalGlyphs.GlyphCount; g++)
                {
                    if (g != glyph)
                        otherGlyph = PetalMath.Min(otherGlyph, errors[polarity * PetalGlyphs.GlyphCount + g]);
                }

                total += errors[best];
                var (polarityMargin, glyphMargin) = erased[tile]
                    ? (0.0, 0.0)
                    : (otherPolarity - errors[best], otherGlyph - errors[best]);
                reads[tile] = new TileRead(polarity == 1, (byte)glyph, polarityMargin, glyphMargin, errors[best]);
            }

            if (total < bestTotal)
            {
                bestTotal = total;
                spare = bestReads.Length == 0 ? null : bestReads;
                bestReads = reads;
            }
            else
            {
                spare = reads;
            }
        }

        return bestReads;
    }

    /// <summary>
    /// The level read: every patch is judged against the light and dark levels measured at the
    /// finders, interpolated to the tile.
    /// </summary>
    /// <param name="patches">The raw patches from <see cref="SamplePatches"/>.</param>
    /// <param name="reference">Finder levels.</param>
    /// <param name="sigmas">Template blur widths to try.</param>
    /// <returns>One read per tile.</returns>
    internal static TileRead[] ReadTiles(ReadOnlySpan<double> patches, in Reference reference, IReadOnlyList<double> sigmas)
    {
        using var levelled = PooledValues.Rent(PatchValues);
        LevelPatches(patches, reference, levelled.Span);
        return Classify(levelled.Span, sigmas, false, NoErasures);
    }

    private static void LevelPatches(ReadOnlySpan<double> patches, in Reference reference, Span<double> output)
    {
        for (var tile = 0; tile < PetalLayout.TileCount; tile++)
        {
            var center = PetalLayout.TileCenterUnchecked(tile);
            reference.At(center.X, center.Y, out var lit, out var dark);
            var raw = patches.Slice(tile * Cells, Cells);
            var patch = output.Slice(tile * Cells, Cells);
            for (var c = 0; c < Cells; c++)
                patch[c] = (raw[c] - dark) / (lit - dark);
        }

    }

    /// <summary>
    /// The normalised read: every patch and every template is rescaled by its own contrast
    /// before they are compared, so the judgement does not depend on absolute levels. A tile
    /// whose contrast is below <see cref="WeakTile"/> times the median contrast is unreadable
    /// and becomes the first erasure.
    /// </summary>
    /// <param name="patches">The raw patches from <see cref="SamplePatches"/>.</param>
    /// <param name="sigmas">Template blur widths to try.</param>
    /// <returns>One read per tile.</returns>
    internal static TileRead[] ReadTilesNormalised(ReadOnlySpan<double> patches, IReadOnlyList<double> sigmas)
    {
        using var rescaled = PooledValues.Rent(PatchValues);
        var scaled = rescaled.Span;
        Span<double> spans = stackalloc double[PetalLayout.TileCount];
        for (var tile = 0; tile < PetalLayout.TileCount; tile++)
        {
            var raw = patches.Slice(tile * Cells, Cells);
            var (low, high) = PatchLevels(raw);
            spans[tile] = high - low;
            Rescale(raw, low, high, PatchSpanFloor, scaled.Slice(tile * Cells, Cells));
        }

        Span<double> sorted = stackalloc double[PetalLayout.TileCount];
        spans.CopyTo(sorted);
        PetalMath.SortTotal(sorted);
        var median = sorted[PetalLayout.TileCount / 2];
        Span<bool> erased = stackalloc bool[PetalLayout.TileCount];
        for (var tile = 0; tile < PetalLayout.TileCount; tile++)
            erased[tile] = spans[tile] < WeakTile * median;
        return Classify(scaled, sigmas, true, erased);
    }

    /// <summary>
    /// Lanes <c>P</c> and <c>K</c> from one set of patches: the level read first, then, for any
    /// lane still unreadable, the normalised read. A lane the level read decoded is never
    /// replaced.
    /// </summary>
    /// <param name="patches">The raw patches from <see cref="SamplePatches"/>.</param>
    /// <param name="reference">Finder levels.</param>
    /// <param name="sigmas">Template blur widths to try.</param>
    /// <returns>The lanes that decoded, <see langword="null"/> for the others.</returns>
    internal static (PetalLaneResult? P, PetalLaneResult? K) ReadTileLanes(
        ReadOnlySpan<double> patches,
        in Reference reference,
        IReadOnlyList<double> sigmas)
    {
        var (pWord, pConfidence, kWord, kConfidence) = TileWords(ReadTiles(patches, reference, sigmas));
        var p = DecodeWithErasures(PetalLane.P, pWord, pConfidence);
        var k = DecodeWithErasures(PetalLane.K, kWord, kConfidence);
        if (p is null || k is null)
        {
            (pWord, pConfidence, kWord, kConfidence) = TileWords(ReadTilesNormalised(patches, sigmas));
            p ??= DecodeWithErasures(PetalLane.P, pWord, pConfidence);
            k ??= DecodeWithErasures(PetalLane.K, kWord, kConfidence);
        }

        return (p, k);
    }

    internal static (byte[] P, double[] PConfidence, byte[] K, double[] KConfidence) TileWords(TileRead[] reads)
    {
        var p = new byte[PetalLanes.PWordLength];
        var pConfidence = new double[PetalLanes.PWordLength];
        var k = new byte[PetalLanes.KWordLength];
        var kConfidence = new double[PetalLanes.KWordLength];
        Array.Fill(pConfidence, double.MaxValue);
        Array.Fill(kConfidence, double.MaxValue);
        for (var tile = 0; tile < reads.Length; tile++)
        {
            var read = reads[tile];
            if (read.Light)
                p[tile / 8] |= (byte)(1 << (7 - tile % 8));
            pConfidence[tile / 8] = PetalMath.Min(pConfidence[tile / 8], read.PolarityMargin);
            k[tile / 2] |= tile % 2 == 0 ? (byte)(read.Glyph << 4) : read.Glyph;
            kConfidence[tile / 2] = PetalMath.Min(
                kConfidence[tile / 2],
                PetalMath.Min(read.GlyphMargin, read.PolarityMargin));
        }

        return (p, pConfidence, k, kConfidence);
    }

    /// <summary>The verdict on one tile: polarity, glyph, the margins that rank its confidence, and its match error.</summary>
    internal readonly record struct TileRead(
        bool Light,
        byte Glyph,
        double PolarityMargin,
        double GlyphMargin,
        double Error);

    /// <summary>One orientation hypothesis: gate score, <c>天</c> score, orientation, pose, levels and inferred corner.</summary>
    private readonly record struct Scored(
        double Gate,
        double Mask,
        int Rotation,
        bool Mirrored,
        PetalHomography Homography,
        Reference Reference,
        int? InferredCorner);

    /// <summary>A pooled scratch array of doubles that goes back to the pool when disposed.</summary>
    private readonly struct PooledValues : IDisposable
    {
        private readonly double[] array;
        private readonly int length;

        private PooledValues(double[] array, int length)
        {
            this.array = array;
            this.length = length;
        }

        /// <summary>The usable part of the array: <c>length</c> values with unspecified content.</summary>
        public Span<double> Span => array.AsSpan(0, length);

        public static PooledValues Rent(int length) => new(ArrayPool<double>.Shared.Rent(length), length);

        public void Dispose() => ArrayPool<double>.Shared.Return(array);
    }

    /// <summary>Lit and dark levels at the four finders, interpolated over the canvas.</summary>
    internal struct Reference
    {
        private double lit0;
        private double lit1;
        private double lit2;
        private double lit3;
        private double dark0;
        private double dark1;
        private double dark2;
        private double dark3;

        public void Set(int corner, double lit, double dark)
        {
            switch (corner)
            {
                case 0:
                    (lit0, dark0) = (lit, dark);
                    break;
                case 1:
                    (lit1, dark1) = (lit, dark);
                    break;
                case 2:
                    (lit2, dark2) = (lit, dark);
                    break;
                default:
                    (lit3, dark3) = (lit, dark);
                    break;
            }
        }

        /// <summary>
        /// Fills in the levels of corner <paramref name="missing"/> from the other three by the
        /// parallelogram rule (neighbours minus the opposite corner), kept within their range.
        /// </summary>
        public void Extrapolate(int missing)
        {
            var (n1, opposite, n2) = ((missing + 1) % 4, (missing + 2) % 4, (missing + 3) % 4);
            var lit = Extrapolated(Lit(n1), Lit(opposite), Lit(n2));
            var dark = Extrapolated(Dark(n1), Dark(opposite), Dark(n2));
            Set(missing, lit, dark);
        }

        /// <summary>The light level measured (or extrapolated) at corner <paramref name="corner"/>.</summary>
        public readonly double Lit(int corner) => corner switch
        {
            0 => lit0,
            1 => lit1,
            2 => lit2,
            _ => lit3,
        };

        /// <summary>The dark level measured (or extrapolated) at corner <paramref name="corner"/>.</summary>
        public readonly double Dark(int corner) => corner switch
        {
            0 => dark0,
            1 => dark1,
            2 => dark2,
            _ => dark3,
        };

        /// <summary>Bilinear interpolation over the canvas of the four corner estimates.</summary>
        public readonly void At(double x, double y, out double lit, out double dark)
        {
            var u = Math.Clamp(x / 1024.0, 0.0, 1.0);
            var v = Math.Clamp(y / 1024.0, 0.0, 1.0);
            lit = Mix(lit0, lit1, lit2, lit3, u, v);
            dark = Mix(dark0, dark1, dark2, dark3, u, v);
        }

        private static double Mix(double c0, double c1, double c2, double c3, double u, double v)
        {
            var top = c0 * (1.0 - u) + c1 * u;
            var bottom = c3 * (1.0 - u) + c2 * u;
            return top * (1.0 - v) + bottom * v;
        }

        /// <summary><c>(a + b − opposite)</c> clamped to the range of the three (Rust <c>f64::clamp</c>).</summary>
        private static double Extrapolated(double a, double opposite, double b)
        {
            var low = PetalMath.Min(PetalMath.Min(a, opposite), b);
            var high = PetalMath.Max(PetalMath.Max(a, opposite), b);
            var value = a + b - opposite;
            if (value < low)
                return low;
            return value > high ? high : value;
        }
    }
}
