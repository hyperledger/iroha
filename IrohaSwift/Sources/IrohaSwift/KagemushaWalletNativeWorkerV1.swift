import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Local worker creation failed before the native operation started.
/// The original POSIX error is retained; this is never a payment or proof verdict.
public struct KagemushaWalletNativeWorkerErrorV1: Error, Equatable, Sendable {
  public let code: Int32
}

enum KagemushaWalletNativeWorkClassV1 {
  // Folding also covers collection and snapshots, which wait without preempting a fold.
  case foreground, folding
}

/// Bounded process-local worker diagnostics. These records contain no operation inputs,
/// results or wallet identifiers, and never establish monetary acceptance.
public enum KagemushaWalletNativeWorkerMetricsV1 {
  public enum Lane: String, Sendable { case foreground, fold, snapshot }
  public enum Path: String, Sendable { case worker, inline }
  public enum Outcome: String, Sendable { case returned, threw, startFailed }
  public struct Record: Sendable {
    public let ordinal: UInt64
    public let lane: Lane
    public let path: Path
    public let outcome: Outcome
    public let startedWorkerMicros, endedWorkerMicros: UInt64
    /// Unentered phases are nil, not measured zero-duration phases.
    public let queueMicros, startMicros, executeMicros, joinMicros: UInt64?
    public init(ordinal: UInt64, lane: Lane, path: Path, outcome: Outcome,
      startedWorkerMicros: UInt64, endedWorkerMicros: UInt64,
      queueMicros: UInt64?, startMicros: UInt64?, executeMicros: UInt64?, joinMicros: UInt64?) {
      self.ordinal = ordinal; self.lane = lane; self.path = path; self.outcome = outcome
      self.startedWorkerMicros = startedWorkerMicros; self.endedWorkerMicros = endedWorkerMicros
      self.queueMicros = queueMicros; self.startMicros = startMicros
      self.executeMicros = executeMicros; self.joinMicros = joinMicros
    }
  }
  public struct Snapshot: Sendable {
    public let schema = "iroha.kagemusha.worker-metrics.v1"
    public let sampledWorkerMicros, totalRecords, evictedRecords: UInt64
    public let records: [Record]
    public init(sampledWorkerMicros: UInt64, totalRecords: UInt64,
      evictedRecords: UInt64, records: [Record]) {
      self.sampledWorkerMicros = sampledWorkerMicros; self.totalRecords = totalRecords
      self.evictedRecords = evictedRecords; self.records = records
    }
  }
  /// Copies at most 32 completed records without invoking Native or any caller callback.
  /// Inline records overlap their enclosing worker and must not be summed with it.
  public static func snapshot() -> Snapshot { store.snapshot() }

  private static let store = Store()
  fileprivate static func now() -> UInt64 { store.now() }
  fileprivate static func append(_ trace: Trace) { store.append(trace) }
  private final class Store: @unchecked Sendable {
    let origin = ProcessInfo.processInfo.systemUptime
    let lock = NSLock()
    var total: UInt64 = 0
    // Store is initialized by Trace.started before the operation can dispatch. This
    // fixed array is never returned or copied, so its backing storage stays unique.
    // A committed operation's append only overwrites one scalar/enum value slot;
    // it neither grows an Array nor allocates a snapshot, string or callback.
    private var slots = [Record?](repeating: nil, count: 32)
    func now() -> UInt64 {
      let value = max(0, ProcessInfo.processInfo.systemUptime - origin) * 1_000_000
      return value < Double(UInt64.max) ? UInt64(value) : .max
    }
    func append(_ trace: Trace) {
      lock.lock(); defer { lock.unlock() }
      // Exhaustion makes later samples visibly incomplete; it never wraps an identity.
      guard total < .max else { return }
      total += 1
      slots[Int((total - 1) % 32)] = trace.record(ordinal: total)
    }
    func snapshot() -> Snapshot {
      lock.lock(); defer { lock.unlock() }
      let retained = Int(min(32, total))
      // Snapshot allocation belongs only to this separate diagnostic read. Never
      // share slots with the returned value, which would introduce post-call COW.
      var records: [Record] = []
      records.reserveCapacity(retained)
      for offset in 0..<retained {
        if let row = slots[Int((total - UInt64(retained) + UInt64(offset)) % 32)] {
          records.append(row)
        }
      }
      return Snapshot(sampledWorkerMicros: now(), totalRecords: total,
        evictedRecords: total - UInt64(records.count), records: records)
    }
  }
  /// Worker writes are observed only after pthread_join. No trace outlives its call.
  fileprivate final class Trace: @unchecked Sendable {
    let lane: Lane
    let started = KagemushaWalletNativeWorkerMetricsV1.now()
    var ended: UInt64 = 0
    var path: Path = .worker
    var outcome: Outcome = .startFailed
    var queued: UInt64?, acquired: UInt64?, entered: UInt64?, actionStarted: UInt64?
    var actionEnded: UInt64?, joined: UInt64?
    init(lane: Lane) { self.lane = lane }
    func execute<T>(_ operation: () throws -> T) rethrows -> T {
      actionStarted = KagemushaWalletNativeWorkerMetricsV1.now()
      defer { actionEnded = KagemushaWalletNativeWorkerMetricsV1.now() }
      do { let value = try operation(); outcome = .returned; return value }
      catch { outcome = .threw; throw error }
    }
    func record(ordinal: UInt64) -> Record {
      func interval(_ start: UInt64?, _ end: UInt64?) -> UInt64? {
        guard let start, let end, end >= start else { return nil }
        return end - start
      }
      return Record(ordinal: ordinal, lane: lane, path: path, outcome: outcome,
        startedWorkerMicros: started, endedWorkerMicros: ended,
        queueMicros: interval(queued, acquired),
        startMicros: interval(acquired, entered ?? (outcome == .startFailed ? ended : nil)),
        executeMicros: interval(actionStarted, actionEnded),
        joinMicros: interval(actionEnded, joined))
    }
  }
}

/// Synchronous native work owns its stack instead of inheriting a dispatch/JNI-sized caller.
/// Eight MiB matches the native catalogue worker and provides headroom above the measured
/// 534,208-byte visible finality frames. At most two foreground and one folding stacks exist;
/// non-preempting calls never consume the foreground capacity needed to preempt them. Activity and
/// close remain independent control calls. No thread or borrowed closure survives `perform`.
final class KagemushaWalletNativeWorkerV1: @unchecked Sendable {
  static let stackBytes = 8 * 1024 * 1024
  private static let foreground = KagemushaWalletNativeWorkerV1(maximumConcurrentCalls: 2)
  private static let folding = KagemushaWalletNativeWorkerV1(maximumConcurrentCalls: 1, lane: .fold)
  private static let workerKey: Result<pthread_key_t, KagemushaWalletNativeWorkerErrorV1> = {
    var key = pthread_key_t()
    let status = pthread_key_create(&key, nil)
    return status == 0 ? .success(key) : .failure(.init(code: status))
  }()
  private let permits: DispatchSemaphore
  private let requestedStackBytes: Int
  private let lane: KagemushaWalletNativeWorkerMetricsV1.Lane

  // Internal construction also permits focused failure/concurrency tests without changing
  // the fixed production worker policy or replacing any native operation.
  init(maximumConcurrentCalls: Int, stackBytes: Int = KagemushaWalletNativeWorkerV1.stackBytes,
    lane: KagemushaWalletNativeWorkerMetricsV1.Lane = .foreground) {
    precondition(maximumConcurrentCalls > 0)
    permits = DispatchSemaphore(value: maximumConcurrentCalls)
    requestedStackBytes = stackBytes
    self.lane = lane
  }

  static func perform<T>(workClass: KagemushaWalletNativeWorkClassV1 = .foreground,
    _ operation: () throws -> T) throws -> T {
    switch workClass {
    case .foreground: return try foreground.run(operation)
    case .folding: return try folding.run(operation)
    }
  }

  func run<T>(_ operation: () throws -> T) throws -> T {
    let trace = KagemushaWalletNativeWorkerMetricsV1.Trace(lane: lane)
    defer {
      trace.ended = KagemushaWalletNativeWorkerMetricsV1.now()
      KagemushaWalletNativeWorkerMetricsV1.append(trace)
    }
    let key = try Self.workerKey.get()
    // A nested SDK helper already owns the required stack. Requeueing would deadlock
    // when all permits are occupied. Platform callbacks still must not re-enter a wallet.
    if pthread_getspecific(key) != nil {
      trace.path = .inline
      return try trace.execute(operation)
    }
    trace.queued = KagemushaWalletNativeWorkerMetricsV1.now()
    permits.wait()
    trace.acquired = KagemushaWalletNativeWorkerMetricsV1.now()
    defer { permits.signal() }
    var attributes = pthread_attr_t()
    var status = pthread_attr_init(&attributes)
    guard status == 0 else { throw KagemushaWalletNativeWorkerErrorV1(code: status) }
    defer { pthread_attr_destroy(&attributes) }
    status = pthread_attr_setstacksize(&attributes, requestedStackBytes)
    guard status == 0 else { throw KagemushaWalletNativeWorkerErrorV1(code: status) }
    return try withoutActuallyEscaping(operation) { borrowed in
      let result = ResultSlot<T>()
      let job = Job {
        trace.entered = KagemushaWalletNativeWorkerMetricsV1.now()
        let status = pthread_setspecific(key, UnsafeMutableRawPointer(bitPattern: 1))
        guard status == 0 else {
          result.value = .failure(KagemushaWalletNativeWorkerErrorV1(code: status))
          return
        }
        defer { pthread_setspecific(key, nil) }
        result.value = Result { try trace.execute(borrowed) }
      }
      let context = Unmanaged.passRetained(job).toOpaque()
      #if canImport(Darwin)
      var thread: pthread_t?
      #else
      var thread = pthread_t()
      #endif
      status = pthread_create(&thread, &attributes, { pointer in
        #if !canImport(Darwin)
        guard let pointer else { return nil }
        #endif
        let job = Unmanaged<Job>.fromOpaque(pointer).takeRetainedValue()
        #if canImport(ObjectiveC)
        autoreleasepool { job.execute() }
        #else
        job.execute()
        #endif
        return nil
      }, context)
      guard status == 0 else {
        Unmanaged<Job>.fromOpaque(context).release()
        throw KagemushaWalletNativeWorkerErrorV1(code: status)
      }
      #if canImport(Darwin)
      let joined = pthread_join(thread!, nil)
      #else
      let joined = pthread_join(thread, nil)
      #endif
      trace.joined = KagemushaWalletNativeWorkerMetricsV1.now()
      // Only this caller owns this joinable thread. Returning without a successful join
      // would invalidate its borrowed operation; an impossible ownership error is fatal.
      precondition(joined == 0, "native worker join ownership failure")
      guard let value = result.value else { preconditionFailure("native worker produced no result") }
      return try value.get()
    }
  }

  /// Access is sequential: worker writes, pthread_join completes, caller reads.
  private final class ResultSlot<T>: @unchecked Sendable {
    var value: Result<T, Error>?
  }
  private final class Job: @unchecked Sendable {
    private let action: () -> Void
    init(_ action: @escaping () -> Void) { self.action = action }
    func execute() { action() }
  }
}
