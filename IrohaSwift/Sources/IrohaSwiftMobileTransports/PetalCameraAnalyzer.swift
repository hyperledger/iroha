#if canImport(AVFoundation) && canImport(CoreVideo)
import AVFoundation
import CoreMedia
import CoreVideo
import Foundation
import IrohaSwift

/// Failures turning a camera pixel buffer into a Petal luma plane.
public enum PetalCameraFrameError: Error, Equatable, LocalizedError, Sendable {
    /// The pixel format is not one of ``PetalCameraFrame/supportedPixelFormats``.
    case unsupportedPixelFormat(OSType)
    /// `CVPixelBufferLockBaseAddress` failed with this status.
    case lockFailed(Int32)
    /// The buffer has no readable luma plane or inconsistent dimensions.
    case invalidBuffer

    public var errorDescription: String? {
        switch self {
        case .unsupportedPixelFormat(let format):
            return "Petal camera frames must be bi-planar YUV, BGRA or 8-bit gray, not \(format)."
        case .lockFailed(let status):
            return "Petal camera frame could not be locked (status \(status))."
        case .invalidBuffer:
            return "Petal camera frame has no readable luma plane."
        }
    }
}

/// Conversion of camera pixel buffers into ``PetalLuma`` planes.
public enum PetalCameraFrame {
    /// Pixel formats ``luma(from:)`` accepts, most preferred first.
    ///
    /// Bi-planar YUV formats are read without conversion: the Y plane is the
    /// luma the decoder wants (video-range Y is used as is; the decoder only
    /// relies on relative levels). BGRA is converted with the Rec. 601
    /// weights of the reference (`(299 r + 587 g + 114 b + 500) / 1000`).
    public static let supportedPixelFormats: [OSType] = [
        kCVPixelFormatType_420YpCbCr8BiPlanarFullRange,
        kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
        kCVPixelFormatType_32BGRA,
        kCVPixelFormatType_OneComponent8,
    ]

    /// Copies the luma of `pixelBuffer` into a ``PetalLuma``.
    ///
    /// - Throws: ``PetalCameraFrameError`` for unsupported formats or
    ///   unreadable buffers.
    public static func luma(from pixelBuffer: CVPixelBuffer) throws -> PetalLuma {
        let format = CVPixelBufferGetPixelFormatType(pixelBuffer)
        guard supportedPixelFormats.contains(format) else {
            throw PetalCameraFrameError.unsupportedPixelFormat(format)
        }
        let status = CVPixelBufferLockBaseAddress(pixelBuffer, .readOnly)
        guard status == kCVReturnSuccess else { throw PetalCameraFrameError.lockFailed(status) }
        defer { CVPixelBufferUnlockBaseAddress(pixelBuffer, .readOnly) }

        switch format {
        case kCVPixelFormatType_420YpCbCr8BiPlanarFullRange,
             kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange:
            guard CVPixelBufferIsPlanar(pixelBuffer),
                  CVPixelBufferGetPlaneCount(pixelBuffer) >= 1,
                  let base = CVPixelBufferGetBaseAddressOfPlane(pixelBuffer, 0) else {
                throw PetalCameraFrameError.invalidBuffer
            }
            return try plane(
                base,
                width: CVPixelBufferGetWidthOfPlane(pixelBuffer, 0),
                height: CVPixelBufferGetHeightOfPlane(pixelBuffer, 0),
                bytesPerRow: CVPixelBufferGetBytesPerRowOfPlane(pixelBuffer, 0)
            )
        case kCVPixelFormatType_OneComponent8:
            guard let base = CVPixelBufferGetBaseAddress(pixelBuffer) else {
                throw PetalCameraFrameError.invalidBuffer
            }
            return try plane(
                base,
                width: CVPixelBufferGetWidth(pixelBuffer),
                height: CVPixelBufferGetHeight(pixelBuffer),
                bytesPerRow: CVPixelBufferGetBytesPerRow(pixelBuffer)
            )
        default:
            guard let base = CVPixelBufferGetBaseAddress(pixelBuffer) else {
                throw PetalCameraFrameError.invalidBuffer
            }
            return try bgra(
                base,
                width: CVPixelBufferGetWidth(pixelBuffer),
                height: CVPixelBufferGetHeight(pixelBuffer),
                bytesPerRow: CVPixelBufferGetBytesPerRow(pixelBuffer)
            )
        }
    }

    private static func plane(
        _ base: UnsafeMutableRawPointer,
        width: Int,
        height: Int,
        bytesPerRow: Int
    ) throws -> PetalLuma {
        guard width > 0, height > 0, bytesPerRow >= width else { throw PetalCameraFrameError.invalidBuffer }
        let readable = bytesPerRow * (height - 1) + width
        do {
            return try PetalLuma(
                width: width,
                height: height,
                bytesPerRow: bytesPerRow,
                plane: UnsafeRawBufferPointer(start: base, count: readable)
            )
        } catch {
            throw PetalCameraFrameError.invalidBuffer
        }
    }

    private static func bgra(
        _ base: UnsafeMutableRawPointer,
        width: Int,
        height: Int,
        bytesPerRow: Int
    ) throws -> PetalLuma {
        guard width > 0, height > 0, bytesPerRow >= width * 4 else { throw PetalCameraFrameError.invalidBuffer }
        let source = UnsafeRawPointer(base).assumingMemoryBound(to: UInt8.self)
        var pixels = [UInt8](repeating: 0, count: width * height)
        pixels.withUnsafeMutableBufferPointer { luma in
            for y in 0..<height {
                let row = source + y * bytesPerRow
                let target = y * width
                for x in 0..<width {
                    let b = UInt32(row[x * 4])
                    let g = UInt32(row[x * 4 + 1])
                    let r = UInt32(row[x * 4 + 2])
                    luma[target + x] = UInt8(truncatingIfNeeded: (299 * r + 587 * g + 114 * b + 500) / 1_000)
                }
            }
        }
        do {
            return try PetalLuma(width: width, height: height, pixels: pixels)
        } catch {
            throw PetalCameraFrameError.invalidBuffer
        }
    }
}

/// Camera analyzer of the Petal Stream receive side.
///
/// Attach it to an `AVCaptureVideoDataOutput` (``attach(to:)``); every
/// camera frame is converted to luma, decoded and fed to one
/// ``PetalScanSession``, which follows the code from frame to frame without a
/// full finder search while the hand stays steady and merges repeated captures
/// of each shown frame to recover tile lanes lost to noise or display banding.
/// Each result is reported through `onOutcome` (called
/// on the thread that analysed the frame, normally ``queue``) and through
/// ``outcomes``. Once a payload completes, the analyzer ignores further frames
/// until ``reset()``, so the completed outcome is always the last one
/// delivered. While a frame is decoded the capture output drops late frames,
/// which keeps old phones responsive.
///
/// Scanner setup (evidence: `specs/petal_stream.md` section 8, "Scanner
/// guidance"). The analyzer only attaches to the output; the capture session
/// and device stay with the app:
/// - Use a 1280×720 session preset (`AVCaptureSession.Preset.hd1280x720`)
///   where the device sustains about five decoded frames per second, and fall
///   back to 640×480 only when it cannot. Lane `K` is harder to read at 480p;
///   repeated captures of one shown frame can recover it by averaging.
/// - Automatic exposure over-exposes a mostly black screen. Set the exposure
///   target bias to about −1 EV (`AVCaptureDevice.setExposureTargetBias`) or
///   lock the exposure once the code has been seen.
public final class PetalCameraAnalyzer: NSObject, AVCaptureVideoDataOutputSampleBufferDelegate,
    @unchecked Sendable {
    /// Serial queue on which sample buffers are analysed.
    public let queue: DispatchQueue
    /// Every outcome in analysis order, completed payload last; buffers the
    /// 32 newest values.
    public let outcomes: AsyncStream<PetalScanOutcome>

    /// Serialises analysis; always taken before `stateLock`.
    private let analysisLock = NSLock()
    /// Guards the published snapshot read by UI code.
    private let stateLock = NSLock()
    private var session: PetalScanSession
    private var completed = false
    private var latestProgress = PetalProgress()
    private var latestStats = PetalScanStats()
    private let continuation: AsyncStream<PetalScanOutcome>.Continuation?
    private let onOutcome: (@Sendable (PetalScanOutcome) -> Void)?

    /// Creates an analyzer.
    ///
    /// - Parameters:
    ///   - limits: Session timeouts, assembler limits and decoder options.
    ///   - queue: Serial queue for sample buffer delivery.
    ///   - onOutcome: Called after every analysed frame.
    public init(
        limits: PetalScanLimits = PetalScanLimits(),
        queue: DispatchQueue = DispatchQueue(label: "org.hyperledger.iroha.petal.camera", qos: .userInitiated),
        onOutcome: (@Sendable (PetalScanOutcome) -> Void)? = nil
    ) {
        self.queue = queue
        self.onOutcome = onOutcome
        session = PetalScanSession(limits: limits)
        var captured: AsyncStream<PetalScanOutcome>.Continuation?
        outcomes = AsyncStream(bufferingPolicy: .bufferingNewest(32)) { captured = $0 }
        continuation = captured
        super.init()
    }

    deinit {
        continuation?.finish()
    }

    /// Progress after the latest analysed frame.
    public var progress: PetalProgress {
        stateLock.lock()
        defer { stateLock.unlock() }
        return latestProgress
    }

    /// Session counters after the latest analysed frame, including the frames
    /// read by tracking the previous pose (``PetalScanStats/tracked``) and those
    /// read with one corner blossom hidden and inferred
    /// (``PetalScanStats/inferred``), for diagnostics and UI hints.
    public var stats: PetalScanStats {
        stateLock.lock()
        defer { stateLock.unlock() }
        return latestStats
    }

    /// Whether a payload completed; frames are ignored until ``reset()``.
    public var isCompleted: Bool { progress.complete }

    /// Configures `output` for Petal scanning and installs the analyzer as
    /// its sample buffer delegate on ``queue``.
    ///
    /// Picks the first of ``PetalCameraFrame/supportedPixelFormats`` the
    /// output offers and drops late frames.
    public func attach(to output: AVCaptureVideoDataOutput) {
        let available = output.availableVideoPixelFormatTypes
        if let format = PetalCameraFrame.supportedPixelFormats.first(where: { available.contains($0) }) {
            output.videoSettings = [kCVPixelBufferPixelFormatTypeKey as String: format]
        }
        output.alwaysDiscardsLateVideoFrames = true
        output.setSampleBufferDelegate(self, queue: queue)
    }

    /// Drops partial state and resumes analysis after a completed payload.
    public func reset() {
        analysisLock.lock()
        defer { analysisLock.unlock() }
        session.reset()
        completed = false
        publishState(progress: session.progress, stats: session.stats)
    }

    /// Ends ``outcomes``; later outcomes are still passed to `onOutcome`.
    public func finish() {
        continuation?.finish()
    }

    /// Analyses one camera frame captured at monotonic time `nowMilliseconds`.
    ///
    /// - Returns: The outcome, or `nil` when a payload already completed.
    /// - Throws: ``PetalCameraFrameError`` when the buffer cannot be read.
    @discardableResult
    public func analyze(_ pixelBuffer: CVPixelBuffer, nowMilliseconds: UInt64) throws -> PetalScanOutcome? {
        if isCompleted { return nil }
        return analyze(try PetalCameraFrame.luma(from: pixelBuffer), nowMilliseconds: nowMilliseconds)
    }

    /// Analyses one luma plane captured at monotonic time `nowMilliseconds`.
    ///
    /// - Returns: The outcome, or `nil` when a payload already completed.
    @discardableResult
    public func analyze(_ luma: PetalLuma, nowMilliseconds: UInt64) -> PetalScanOutcome? {
        analysisLock.lock()
        guard !completed else {
            analysisLock.unlock()
            return nil
        }
        let outcome = session.push(luma, nowMilliseconds: nowMilliseconds)
        if outcome.completed != nil { completed = true }
        publishState(progress: outcome.progress, stats: session.stats)
        continuation?.yield(outcome)
        analysisLock.unlock()
        onOutcome?(outcome)
        return outcome
    }

    public func captureOutput(
        _ output: AVCaptureOutput,
        didOutput sampleBuffer: CMSampleBuffer,
        from connection: AVCaptureConnection
    ) {
        guard let pixelBuffer = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
        // Unsupported or unreadable buffers carry nothing to decode.
        _ = try? analyze(pixelBuffer, nowMilliseconds: DispatchTime.now().uptimeNanoseconds / 1_000_000)
    }

    private func publishState(progress: PetalProgress, stats: PetalScanStats) {
        stateLock.lock()
        latestProgress = progress
        latestStats = stats
        stateLock.unlock()
    }
}
#endif
