namespace Hyperledger.Iroha.Petal;

/// <summary>Limits of a scan session.</summary>
public sealed record PetalScanLimits
{
    private readonly TimeSpan idleTimeout = TimeSpan.FromSeconds(30);
    private readonly TimeSpan absoluteTimeout = TimeSpan.FromSeconds(180);
    private readonly PetalAssemblerLimits assembler = PetalAssemblerLimits.Default;
    private readonly PetalDecodeOptions decode = PetalDecodeOptions.Default;

    /// <summary>The reference defaults: 30 s idle, 180 s absolute, default assembler and decoder.</summary>
    public static PetalScanLimits Default { get; } = new();

    /// <summary>Forget a half-received stream after this long without progress (whole milliseconds).</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is negative.</exception>
    public TimeSpan IdleTimeout
    {
        get => idleTimeout;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, TimeSpan.Zero);
            idleTimeout = value;
        }
    }

    /// <summary>Forget a stream that has not finished this long after it started (whole milliseconds).</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is negative.</exception>
    public TimeSpan AbsoluteTimeout
    {
        get => absoluteTimeout;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, TimeSpan.Zero);
            absoluteTimeout = value;
        }
    }

    /// <summary>Assembler memory and size limits.</summary>
    public PetalAssemblerLimits Assembler
    {
        get => assembler;
        init
        {
            ArgumentNullException.ThrowIfNull(value);
            assembler = value;
        }
    }

    /// <summary>Image decoder options.</summary>
    public PetalDecodeOptions Decode
    {
        get => decode;
        init
        {
            ArgumentNullException.ThrowIfNull(value);
            decode = value;
        }
    }
}

/// <summary>Counters for diagnostics and UI hints.</summary>
/// <param name="Frames">Camera frames offered.</param>
/// <param name="Located">Frames in which a code was located, whether or not a lane could be read.</param>
/// <param name="Readable">Frames in which at least one lane decoded.</param>
/// <param name="LaneP">Lane <c>P</c> successes.</param>
/// <param name="LaneK">Lane <c>K</c> successes.</param>
/// <param name="LaneD">Lane <c>D</c> successes.</param>
/// <param name="Tracked">Frames read by tracking the previous pose instead of a full search.</param>
/// <param name="Merges">Attempts to average two or more captures.</param>
/// <param name="MergedP">Missing P lanes recovered by averaging.</param>
/// <param name="MergedK">Missing K lanes recovered by averaging.</param>
/// <param name="Inferred">Frames read with one corner finder hidden and inferred (a hint to move a thumb or the phone).</param>
public readonly record struct PetalScanStats(
    uint Frames,
    uint Located,
    uint Readable,
    uint LaneP,
    uint LaneK,
    uint LaneD,
    uint Tracked,
    uint Inferred,
    uint Merges,
    uint MergedP,
    uint MergedK);

/// <summary>The result of offering one camera frame.</summary>
public sealed class PetalScanOutcome
{
    internal PetalScanOutcome(PetalDecodeError? error, string lanes, string merged, PetalProgress progress, PetalCompletedPayload? completed)
    {
        Error = error;
        Lanes = lanes;
        Merged = merged;
        Progress = progress;
        Completed = completed;
    }

    /// <summary>
    /// Why the frame produced nothing, when it did not.
    /// <see cref="PetalDecodeError.NoOrientation"/> means a code was located but no
    /// lane could be read (too far, too blurry).
    /// </summary>
    public PetalDecodeError? Error { get; }

    /// <summary>Lanes that decoded, as letters from <c>"PKD"</c>.</summary>
    public string Lanes { get; }

    /// <summary>Lanes recovered by averaging captures, as letters from <c>"PK"</c>.</summary>
    public string Merged { get; }

    /// <summary>Receive progress after this frame.</summary>
    public PetalProgress Progress { get; }

    /// <summary>The finished payload, delivered exactly once.</summary>
    public PetalCompletedPayload? Completed { get; }
}

/// <summary>
/// The receive-side object an app holds while its camera is open: decodes
/// camera frames and reassembles the stream they carry.
/// </summary>
/// <remarks>
/// <para>
/// After a frame decodes, the next frames are first read by tracking the code from
/// its last pose (<see cref="PetalDecoder.Track"/>), which skips the finder search;
/// a full <see cref="PetalDecoder.Decode"/> runs when tracking fails or the last
/// pose is older than <see cref="TrackWindowMilliseconds"/>.
/// </para>
/// <para>
/// A half-received stream is forgotten after <see cref="PetalScanLimits.IdleTimeout"/>
/// without new independent atoms, or <see cref="PetalScanLimits.AbsoluteTimeout"/>
/// after it started. Partial tile reads are averaged across at most four captures of
/// each of six shown frames; independently decoded lane headers must agree, and a
/// recovered lane must name the same frame. Instances are not thread-safe; see
/// <see cref="PetalCameraAnalyzer"/> for a camera-callback wrapper.
/// </para>
/// </remarks>
public sealed class PetalScanSession
{
    /// <summary>How long (in milliseconds) a decoded pose stays usable for tracking the next frames.</summary>
    public const long TrackWindowMilliseconds = 500;

    /// <summary>Maximum number of shown-frame sets retained.</summary>
    public const int MergeWindow = 6;
    /// <summary>Maximum captures retained per shown frame; further captures replace the oldest.</summary>
    public const int MergeCaptures = 4;

    private sealed class Held(PetalLaneHeader shown)
    {
        public PetalLaneHeader Shown { get; } = shown;
        public List<PetalTileEvidence> Evidence { get; } = new();
        public bool PDone { get; set; }
        public bool KDone { get; set; }
    }

    private readonly List<Held> held = new();
    private uint merges;
    private uint mergedP;
    private uint mergedK;
    private readonly PetalStreamAssembler assembler;
    private long? startedMs;
    private long progressMs;
    private int lastRank;
    private uint frames;
    private uint located;
    private uint readable;
    private uint laneP;
    private uint laneK;
    private uint laneD;
    private uint tracked;
    private uint inferred;
    private PetalDecodedFrame? lastPose;
    private long lastPoseMs;

    /// <summary>Creates a session.</summary>
    /// <param name="limits">Limits; <see cref="PetalScanLimits.Default"/> when omitted.</param>
    public PetalScanSession(PetalScanLimits? limits = null)
    {
        Limits = limits ?? PetalScanLimits.Default;
        assembler = new PetalStreamAssembler(Limits.Assembler);
    }

    /// <summary>The limits in force.</summary>
    public PetalScanLimits Limits { get; }

    /// <summary>Diagnostic counters.</summary>
    public PetalScanStats Stats => new(frames, located, readable, laneP, laneK, laneD, tracked, inferred, merges, mergedP, mergedK);

    /// <summary>Current progress.</summary>
    public PetalProgress Progress => assembler.Progress;

    /// <summary>Drops all partial state and the pose used for tracking (counters are kept).</summary>
    public void Reset()
    {
        assembler.Reset();
        startedMs = null;
        lastRank = 0;
        lastPose = null;
        held.Clear();
    }

    /// <summary>Offers one camera luma plane captured at monotonic time <paramref name="nowMilliseconds"/>.</summary>
    /// <param name="image">The luma plane.</param>
    /// <param name="nowMilliseconds">Monotonic capture time in milliseconds (for example <see cref="Environment.TickCount64"/>).</param>
    /// <returns>What this frame contributed.</returns>
    public PetalScanOutcome Push(PetalLuma image, long nowMilliseconds)
    {
        ArgumentNullException.ThrowIfNull(image);
        if (startedMs is { } start
            && (Elapsed(nowMilliseconds, progressMs) > WholeMilliseconds(Limits.IdleTimeout)
                || Elapsed(nowMilliseconds, start) > WholeMilliseconds(Limits.AbsoluteTimeout)))
        {
            Reset();
        }

        frames++;
        var followed = lastPose is not null && Elapsed(nowMilliseconds, lastPoseMs) <= TrackWindowMilliseconds
            ? PetalDecoder.Track(image, lastPose, Limits.Decode)
            : null;
        if (followed is not null)
            tracked++;
        var result = followed is not null ? PetalDecodeResult.Ok(followed) : PetalDecoder.Decode(image, Limits.Decode);
        var lanes = string.Empty;
        var merged = string.Empty;
        if (result.Success)
        {
            if (result.Frame.InferredCorner is not null)
                inferred++;
            lastPose = result.Frame;
            lastPoseMs = nowMilliseconds;
            lanes = Absorb(result.Frame);
            merged = Merge(image, result.Frame);
        }

        if (result.Error is not (PetalDecodeError.NoFinders or PetalDecodeError.UnsupportedImage))
            located++;
        var progress = assembler.Progress;
        if (progress.Rank > lastRank || (progress.Meta is not null && startedMs is null))
        {
            progressMs = nowMilliseconds;
            startedMs ??= nowMilliseconds;
        }

        lastRank = progress.Rank;
        return new PetalScanOutcome(result.Error, lanes, merged, progress, assembler.TakeCompleted());
    }

    private string Absorb(PetalDecodedFrame frame)
    {
        if (frame.P is not null)
            laneP++;
        if (frame.K is not null)
            laneK++;
        if (frame.D is not null)
            laneD++;
        var lanes = frame.Lanes;
        if (lanes.Length > 0)
            readable++;
        var previousMeta = assembler.Progress.Meta;
        frame.Feed(assembler);
        if (previousMeta is not null && assembler.Progress.Meta != previousMeta)
            held.Clear();
        return lanes;
    }

    private static PetalLaneHeader? ShownFrame(PetalDecodedFrame frame)
    {
        PetalLaneHeader? shown = null;
        foreach (var lane in new[] { frame.D, frame.P, frame.K })
        {
            if (lane is null)
                continue;
            if (lane.Data.Length < 3)
                return null;
            var header = new PetalLaneHeader(lane.Data[0], (ushort)((lane.Data[1] << 8) | lane.Data[2]));
            if (shown is { } previous && previous != header)
                return null;
            shown = header;
        }
        return shown;
    }

    internal string Merge(PetalLuma image, PetalDecodedFrame frame)
    {
        if (ShownFrame(frame) is not { } shown)
            return string.Empty;
        var item = held.FirstOrDefault(h => h.Shown == shown);
        if (item is null)
        {
            if (held.Count == MergeWindow)
                held.RemoveAt(0);
            item = new Held(shown);
            held.Add(item);
        }
        item.PDone |= frame.P is not null;
        item.KDone |= frame.K is not null;
        if (item.PDone && item.KDone)
        {
            item.Evidence.Clear();
            return string.Empty;
        }
        if (PetalDecoder.TileEvidence(image, frame, Limits.Decode) is not { } evidence)
            return string.Empty;
        if (item.Evidence.Count == MergeCaptures)
            item.Evidence.RemoveAt(0);
        item.Evidence.Add(evidence);
        if (item.Evidence.Count < 2)
            return string.Empty;
        merges++;
        var (p, k) = PetalDecoder.MergeTiles(item.Evidence, Limits.Decode);
        var merged = string.Empty;
        foreach (var (letter, lane, result) in new[] { ("P", PetalLane.P, p), ("K", PetalLane.K, k) })
        {
            var done = lane == PetalLane.P ? item.PDone : item.KDone;
            if (done || result is null || PetalStream.ParseAtomLane(lane, result.Data) is not { } packet || packet.Header != shown)
                continue;
            if (lane == PetalLane.P)
            {
                item.PDone = true;
                mergedP++;
            }
            else
            {
                item.KDone = true;
                mergedK++;
            }
            assembler.PushAtoms(packet);
            merged += letter;
        }
        if (item.PDone && item.KDone)
            item.Evidence.Clear();
        return merged;
    }

    /// <summary>Saturating <c>now - since</c> (Rust <c>u64::saturating_sub</c>).</summary>
    private static ulong Elapsed(long now, long since) => now <= since ? 0 : unchecked((ulong)now - (ulong)since);

    private static ulong WholeMilliseconds(TimeSpan timeout) => (ulong)(timeout.Ticks / TimeSpan.TicksPerMillisecond);
}
