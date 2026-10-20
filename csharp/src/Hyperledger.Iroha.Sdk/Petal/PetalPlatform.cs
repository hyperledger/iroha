namespace Hyperledger.Iroha.Petal;

/// <summary>
/// Sender-side animation driver: maps elapsed time to the frame to show and
/// hands it to a native canvas through <see cref="IPetalCanvas"/>.
/// </summary>
/// <remarks>
/// <para>
/// The player is UI-framework neutral. Call <see cref="Draw"/> from the
/// platform's render callback (for example a .NET MAUI <c>IDrawable.Draw</c>,
/// an <c>SKCanvasView.PaintSurface</c> handler or a WPF
/// <c>OnRender</c>) with the time since playback started and an
/// <see cref="IPetalCanvas"/> adapter over the native canvas, then invalidate
/// the view on a timer. Frames advance at <see cref="FramesPerSecond"/> and
/// the 16-bit frame counter wraps on a beacon frame, so playback can run
/// forever.
/// </para>
/// <para>The draw list of the current frame is cached; instances are thread-safe.</para>
/// </remarks>
public sealed class PetalFramePlayer
{
    /// <summary>Default display rate, the rate used by the reference stream simulation.</summary>
    public const double DefaultFramesPerSecond = 8.0;

    private readonly object gate = new();
    private int cachedFrame = -1;
    private PetalDrawList? cachedDrawList;

    /// <summary>Creates a player.</summary>
    /// <param name="encoder">The stream to show.</param>
    /// <param name="framesPerSecond">Display rate; must be positive and finite.</param>
    /// <param name="firstFrame">Frame counter shown at time zero.</param>
    /// <param name="palette">Colours; <see cref="PetalPalette.Default"/> when omitted.</param>
    /// <exception cref="ArgumentOutOfRangeException">The frame rate is not positive and finite.</exception>
    public PetalFramePlayer(
        PetalStreamEncoder encoder,
        double framesPerSecond = DefaultFramesPerSecond,
        ushort firstFrame = 0,
        PetalPalette? palette = null)
    {
        ArgumentNullException.ThrowIfNull(encoder);
        if (!double.IsFinite(framesPerSecond) || framesPerSecond <= 0.0)
            throw new ArgumentOutOfRangeException(nameof(framesPerSecond));
        Encoder = encoder;
        FramesPerSecond = framesPerSecond;
        FirstFrame = firstFrame;
        Palette = palette ?? PetalPalette.Default;
    }

    /// <summary>The stream being shown.</summary>
    public PetalStreamEncoder Encoder { get; }

    /// <summary>Display rate in frames per second.</summary>
    public double FramesPerSecond { get; }

    /// <summary>Frame counter shown at time zero.</summary>
    public ushort FirstFrame { get; }

    /// <summary>Colours.</summary>
    public PetalPalette Palette { get; }

    /// <summary>Time one frame stays on screen.</summary>
    public TimeSpan FrameDuration => TimeSpan.FromSeconds(1.0 / FramesPerSecond);

    /// <summary>The frame counter to show <paramref name="elapsed"/> after playback started.</summary>
    /// <param name="elapsed">Time since playback started; negative values count as zero.</param>
    /// <returns>The frame counter (wrapping at 65536).</returns>
    public ushort FrameAt(TimeSpan elapsed)
    {
        var seconds = Math.Max(elapsed.TotalSeconds, 0.0);
        var steps = Math.Floor(seconds * FramesPerSecond) % 65_536.0;
        return unchecked((ushort)(FirstFrame + (int)steps));
    }

    /// <summary>The draw list of the frame shown at <paramref name="elapsed"/>.</summary>
    /// <param name="elapsed">Time since playback started.</param>
    /// <returns>The (cached) draw list.</returns>
    public PetalDrawList DrawListAt(TimeSpan elapsed)
    {
        var frame = FrameAt(elapsed);
        lock (gate)
        {
            if (cachedFrame != frame || cachedDrawList is null)
            {
                cachedDrawList = PetalDrawList.Create(Encoder.Cells(frame), Palette);
                cachedFrame = frame;
            }

            return cachedDrawList;
        }
    }

    /// <summary>Draws the frame shown at <paramref name="elapsed"/> into a square of side <paramref name="side"/>.</summary>
    /// <param name="canvas">Adapter over the native canvas.</param>
    /// <param name="elapsed">Time since playback started.</param>
    /// <param name="side">Side of the target square in the canvas's units.</param>
    /// <param name="offsetX">Left edge of the target square.</param>
    /// <param name="offsetY">Top edge of the target square.</param>
    public void Draw(IPetalCanvas canvas, TimeSpan elapsed, double side, double offsetX = 0.0, double offsetY = 0.0)
    {
        ArgumentNullException.ThrowIfNull(canvas);
        DrawListAt(elapsed).Draw(canvas, side / PetalLayout.Canvas, offsetX, offsetY);
    }

    /// <summary>Software-renders the frame shown at <paramref name="elapsed"/> (for bitmap-only surfaces).</summary>
    /// <param name="elapsed">Time since playback started.</param>
    /// <param name="options">Render options; the player's palette is applied.</param>
    /// <returns>The RGB image.</returns>
    public PetalRgbImage RenderAt(TimeSpan elapsed, PetalRenderOptions? options = null)
    {
        options = (options ?? PetalRenderOptions.Default) with { Palette = Palette };
        return PetalRenderer.Render(Encoder.Cells(FrameAt(elapsed)), options);
    }
}

/// <summary>
/// Receiver-side camera glue: turns camera luma (Y) planes into
/// <see cref="PetalLuma"/> images and feeds a <see cref="PetalScanSession"/>.
/// </summary>
/// <remarks>
/// <para>
/// Call <see cref="AnalyzeYPlane"/> from the camera callback with the Y plane
/// of each preview frame: on Android the plane 0 buffer, row stride and pixel
/// stride of a CameraX <c>ImageProxy</c> (<c>YUV_420_888</c>); on iOS the
/// luma plane of a bi-planar <c>CVPixelBuffer</c> with its bytes-per-row. The
/// analyzer reuses one luma buffer per resolution, never throws on camera
/// content, and drops frames that arrive while a previous frame is still being
/// decoded (keep-only-latest back-pressure). <see cref="PayloadCompleted"/>
/// fires once per reassembled, CRC-verified payload, outside the internal lock.
/// </para>
/// <para>
/// The session follows the code from frame to frame instead of searching for it
/// again (<see cref="PetalScanStats.Tracked"/>), and still reads a frame whose
/// corner blossom is covered by a thumb or cut off by the frame edge
/// (<see cref="PetalScanStats.Inferred"/>: a growing count is a cue to show a
/// "one corner blossom is hidden" hint).
/// </para>
/// <para>Instances are thread-safe.</para>
/// </remarks>
public sealed class PetalCameraAnalyzer
{
    private readonly object gate = new();
    private PetalLuma? buffer;

    /// <summary>Creates an analyzer with a fresh session.</summary>
    /// <param name="limits">Session limits; <see cref="PetalScanLimits.Default"/> when omitted.</param>
    public PetalCameraAnalyzer(PetalScanLimits? limits = null)
    {
        Session = new PetalScanSession(limits);
    }

    /// <summary>Raised once per completed payload.</summary>
    public event EventHandler<PetalCompletedPayload>? PayloadCompleted;

    /// <summary>The underlying session (synchronise with the analyzer when touching it directly).</summary>
    public PetalScanSession Session { get; }

    /// <summary>Analyzes one camera luma plane.</summary>
    /// <param name="plane">Plane bytes starting at pixel <c>(0, 0)</c>.</param>
    /// <param name="width">Frame width in pixels.</param>
    /// <param name="height">Frame height in pixels.</param>
    /// <param name="rowStride">Bytes between the starts of consecutive rows.</param>
    /// <param name="pixelStride">Bytes between horizontally adjacent luma samples.</param>
    /// <param name="timestampMilliseconds">Monotonic capture time in milliseconds.</param>
    /// <returns>
    /// The outcome; an outcome with <see cref="PetalDecodeError.UnsupportedImage"/>
    /// for inconsistent plane geometry; or <see langword="null"/> when the frame
    /// was dropped because another frame is being analyzed.
    /// </returns>
    public PetalScanOutcome? AnalyzeYPlane(
        ReadOnlySpan<byte> plane,
        int width,
        int height,
        int rowStride,
        int pixelStride,
        long timestampMilliseconds)
    {
        if (!Monitor.TryEnter(gate))
            return null;
        PetalScanOutcome outcome;
        try
        {
            if (!ValidGeometry(plane.Length, width, height, rowStride, pixelStride, Session.Limits.Decode.MaxPixels))
            {
                outcome = new PetalScanOutcome(PetalDecodeError.UnsupportedImage, string.Empty, string.Empty, Session.Progress, null);
            }
            else
            {
                if (buffer is null || buffer.Width != width || buffer.Height != height)
                    buffer = new PetalLuma(width, height);
                buffer.LoadYPlane(plane, rowStride, pixelStride);
                outcome = Session.Push(buffer, timestampMilliseconds);
            }
        }
        finally
        {
            Monitor.Exit(gate);
        }

        if (outcome.Completed is { } completed)
            PayloadCompleted?.Invoke(this, completed);
        return outcome;
    }

    /// <summary>Analyzes an already converted luma image.</summary>
    /// <param name="image">The luma plane.</param>
    /// <param name="timestampMilliseconds">Monotonic capture time in milliseconds.</param>
    /// <returns>The outcome, or <see langword="null"/> when the frame was dropped.</returns>
    public PetalScanOutcome? Analyze(PetalLuma image, long timestampMilliseconds)
    {
        ArgumentNullException.ThrowIfNull(image);
        if (!Monitor.TryEnter(gate))
            return null;
        PetalScanOutcome outcome;
        try
        {
            outcome = Session.Push(image, timestampMilliseconds);
        }
        finally
        {
            Monitor.Exit(gate);
        }

        if (outcome.Completed is { } completed)
            PayloadCompleted?.Invoke(this, completed);
        return outcome;
    }

    /// <summary>Drops the partial stream (for example when the camera screen reopens).</summary>
    public void Reset()
    {
        lock (gate)
            Session.Reset();
    }

    private static bool ValidGeometry(int length, int width, int height, int rowStride, int pixelStride, long maxPixels)
    {
        var area = (long)width * height;
        if (width < 1 || height < 1 || pixelStride < 1 || area > maxPixels || area > Array.MaxLength)
            return false;
        var rowSpan = (long)(width - 1) * pixelStride + 1;
        return rowStride >= rowSpan && length >= (long)rowStride * (height - 1) + rowSpan;
    }
}
