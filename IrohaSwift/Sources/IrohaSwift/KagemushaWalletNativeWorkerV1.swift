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

/// Synchronous native work owns its stack instead of inheriting a dispatch/JNI-sized caller.
/// Eight MiB matches the native catalogue worker and provides headroom above the measured
/// 534,208-byte visible finality frames. At most two foreground and one folding stacks exist;
/// non-preempting calls never consume the foreground capacity needed to preempt them. Activity and
/// close remain independent control calls. No thread or borrowed closure survives `perform`.
final class KagemushaWalletNativeWorkerV1: @unchecked Sendable {
  static let stackBytes = 8 * 1024 * 1024
  private static let foreground = KagemushaWalletNativeWorkerV1(maximumConcurrentCalls: 2)
  private static let folding = KagemushaWalletNativeWorkerV1(maximumConcurrentCalls: 1)
  private static let workerKey: Result<pthread_key_t, KagemushaWalletNativeWorkerErrorV1> = {
    var key = pthread_key_t()
    let status = pthread_key_create(&key, nil)
    return status == 0 ? .success(key) : .failure(.init(code: status))
  }()
  private let permits: DispatchSemaphore
  private let requestedStackBytes: Int

  // Internal construction also permits focused failure/concurrency tests without changing
  // the fixed production worker policy or replacing any native operation.
  init(maximumConcurrentCalls: Int, stackBytes: Int = KagemushaWalletNativeWorkerV1.stackBytes) {
    precondition(maximumConcurrentCalls > 0)
    permits = DispatchSemaphore(value: maximumConcurrentCalls)
    requestedStackBytes = stackBytes
  }

  static func perform<T>(workClass: KagemushaWalletNativeWorkClassV1 = .foreground,
    _ operation: () throws -> T) throws -> T {
    switch workClass {
    case .foreground: return try foreground.run(operation)
    case .folding: return try folding.run(operation)
    }
  }

  func run<T>(_ operation: () throws -> T) throws -> T {
    let key = try Self.workerKey.get()
    // A nested SDK helper already owns the required stack. Requeueing would deadlock
    // when all permits are occupied. Platform callbacks still must not re-enter a wallet.
    if pthread_getspecific(key) != nil { return try operation() }
    permits.wait()
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
        let status = pthread_setspecific(key, UnsafeMutableRawPointer(bitPattern: 1))
        guard status == 0 else {
          result.value = .failure(KagemushaWalletNativeWorkerErrorV1(code: status))
          return
        }
        defer { pthread_setspecific(key, nil) }
        result.value = Result(catching: borrowed)
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
