// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
import Darwin
import Foundation
import XCTest

@testable import IrohaSwift

/// Genuine native enrollment and staged monetary commands through the real Apple adapter.
/// External account signatures, issuer results, ledger finality and carriers remain independent.
final class KagemushaEnrollmentPhysicalDeviceTests: XCTestCase {
  func testDisposableNativeEnrollmentActor() async throws {
    #if !os(iOS) || targetEnvironment(simulator) || targetEnvironment(macCatalyst)
      throw EnrollmentProbeFailure.lifecycle
    #else
      let env = ProcessInfo.processInfo.environment
      func required(_ key: String) throws -> String {
        guard let value = env[key], !value.isEmpty else { throw EnrollmentProbeFailure.input }
        return value
      }
      func uuid(_ key: String) throws -> String {
        let text = try required(key)
        guard let value = UUID(uuidString: text), value.uuidString == text else {
          throw EnrollmentProbeFailure.input
        }
        return text
      }
      let run = try uuid("KAGEMUSHA_ENROLLMENT_RUN_ID")
      let invocation = try uuid("KAGEMUSHA_ENROLLMENT_INVOCATION_ID")
      let role = try required("KAGEMUSHA_ENROLLMENT_ACTOR")
      let bundle = try XCTUnwrap(Bundle.main.bundleIdentifier)
      guard bundle.hasPrefix("org.hyperledger.iroha.kagemusha.enrollment-probe.") else {
        throw EnrollmentProbeFailure.lifecycle
      }
      // The operator pins the actual selected machine; no simulator or other model fallback.
      var hardware = utsname()
      guard uname(&hardware) == 0 else { throw EnrollmentProbeFailure.lifecycle }
      let machineCapacity = MemoryLayout.size(ofValue: hardware.machine)
      let machine = withUnsafePointer(to: &hardware.machine) {
        $0.withMemoryRebound(to: CChar.self, capacity: machineCapacity) { String(cString: $0) }
      }
      guard machine == (try required("KAGEMUSHA_ENROLLMENT_EXPECTED_MACHINE")) else {
        throw EnrollmentProbeFailure.lifecycle
      }
      let support = try KagemushaWalletAppleSystemV1.live.applicationSupportDirectory().get()
      let probeRoot = support.appendingPathComponent(
        "kagemusha-enrollment-probes", isDirectory: true)
      try EnrollmentProbeFiles.requireDirectory(probeRoot)
      let files = try EnrollmentProbeFiles(
        root: probeRoot.appendingPathComponent(run, isDirectory: true))
      let configBytes = try files.read(
        "inbox/" + invocation + "/configuration.plist", maximum: 8_388_608)
      let configHash = try required("KAGEMUSHA_ENROLLMENT_CONFIG_SHA256")
      guard EnrollmentProbeFiles.isDigest(configHash),
        EnrollmentProbeFiles.digest(configBytes) == configHash,
        let row = try PropertyListSerialization.propertyList(from: configBytes, format: nil)
          as? [String: Any]
      else { throw EnrollmentProbeFailure.input }
      let config = try KagemushaEnrollmentDeviceActor.Configuration(
        files: files, row: row, role: role,
        invocation: invocation, independentGenesis: required("KAGEMUSHA_ENROLLMENT_GENESIS_SHA256"),
        appIDPrefix: required("KAGEMUSHA_ENROLLMENT_APP_ID_PREFIX"), bundleID: bundle)
      try files.mkdir(config.actorPath)
      let lockFD = try files.lock(config.actorPath + "/driver.lock")
      defer { close(lockFD) }
      try files.publish(config.actorPath + "/identity.txt", bytes: config.identity)
      // Every invocation has a new output namespace. Never replay a dead process's live permit.
      let publicPath = config.actorPath + "/public/" + invocation
      try files.mkdir(config.actorPath + "/public")
      try files.mkdirExclusive(publicPath)
      try files.mkdir(config.actorPath + "/private/" + invocation)
      try files.mkdir(config.actorPath + "/custody")
      try files.publish(
        config.actorPath + "/private/" + invocation + "/configuration.plist", bytes: configBytes)
      let driver = try KagemushaEnrollmentDeviceActor(configuration: config)
      var timebase = mach_timebase_info_data_t()
      guard mach_timebase_info(&timebase) == KERN_SUCCESS else {
        throw EnrollmentProbeFailure.lifecycle
      }
      let clock = EnrollmentProbeClock(
        numerator: UInt64(timebase.numer), denominator: UInt64(timebase.denom))
      let started = mach_continuous_time()
      let timeoutSeconds = try required("KAGEMUSHA_ENROLLMENT_TIMEOUT_SECONDS")
      guard let timeout = UInt64(timeoutSeconds), (1...1800).contains(timeout) else {
        throw EnrollmentProbeFailure.input
      }
      let deadline = EnrollmentProbeDeadline(
        clock: clock, started: started, duration: timeout * 1_000_000_000,
        now: mach_continuous_time)
      let header: [String: Any] = [
        "scope": "native-enrollment-and-staged-monetary", "keychainAccessGroup": config.group,
        "run": run, "actor": role,
        "invocation": invocation, "pid": getpid(), "machine": machine,
        "configurationSHA256": configHash, "ticksNumerator": clock.numerator,
        "ticksDenominator": clock.denominator,
      ]
      try files.publish(
        publicPath + "/invocation.plist", bytes: EnrollmentProbeFiles.encode(header))
      var failedCommands = 0
      var achievedStages = Set<String>()
      do {
        for sequence in 0..<10_000 {
          let name = String(format: "%04d", sequence)
          let base = "inbox/" + invocation + "/" + name
          var ready: String? = nil
          while ready == nil {
            ready = try deadline.select { try files.readyDigest(base + ".ready") }
            if ready == nil { try await Task.sleep(nanoseconds: 200_000_000) }
          }
          let commandBytes = try files.read(base + ".plist", maximum: 131_072)
          guard ready == EnrollmentProbeFiles.digest(commandBytes),
            let row = try PropertyListSerialization.propertyList(from: commandBytes, format: nil)
              as? [String: Any]
          else { throw EnrollmentProbeFailure.input }
          let command = try KagemushaEnrollmentDeviceActor.Command(row)
          try files.publish(
            config.actorPath + "/private/" + invocation + "/" + name + ".plist", bytes: commandBytes
          )
          let before = mach_continuous_time()
          try files.publish(
            publicPath + "/" + name + "-started.plist",
            bytes: EnrollmentProbeFiles.encode([
              "sequence": sequence, "action": command.action, "ticks": before,
              "commandSHA256": EnrollmentProbeFiles.digest(commandBytes),
            ]))
          // A filesystem operation or suspension cannot authorize dispatch after expiry.
          try deadline.check()
          let outcome: String
          do { outcome = try await driver.execute(command, sequence: sequence) } catch {
            failedCommands += 1
            let after = mach_continuous_time()
            // Preserve failure without serializing an error description or any sensitive input.
            var failure: [String: Any] = [
              "sequence": sequence, "action": command.action,
              "status": "failed", "errorType": String(reflecting: type(of: error)), "ticks": after,
              "durationNanoseconds": clock.nanoseconds(from: before, to: after),
            ]
            if let native = error as? KagemushaWalletErrorV1,
              case .native(let status, let reason, let platformCode) = native
            {
              failure["nativeStatus"] = status
              failure["nativeReason"] = reason
              failure["platformCode"] = platformCode
            }
            failure.merge(EnrollmentProbeFailureMetadata.fields(error)) { _, safe in safe }
            try files.publish(
              publicPath + "/" + name + "-finished.plist",
              bytes: EnrollmentProbeFiles.encode(failure))
            // The same owner survives ordinary refusal. Any retry is a new explicit command.
            continue
          }
          let after = mach_continuous_time()
          let stages: [String: Set<String>] = [
            "native-installation-registered": ["installed"],
            "installed-owner-retained": ["installed"],
            "live-dispatch-exported": ["dispatch"], "native-durable-e5-exported": ["e5"],
            "retained-e5-exported": ["e5"], "native-durable-e6-exported-not-activated": ["e6"],
            "retained-e6-exported": ["e6"], "native-wallet-opened": ["opened"],
            "native-activation-confirmed": ["activated"], "native-complete-load": ["loaded"],
            "native-complete-send": ["sent"], "native-complete-receive": ["received"],
            "native-exact-send-delivery-admitted-over-nearby": ["sent"],
            "native-durable-receive-acknowledged-over-nearby": ["received"],
            "native-unload-confirmed": ["unloaded"],
          ]
          achievedStages.formUnion(stages[outcome] ?? [])
          try files.publish(
            publicPath + "/" + name + "-finished.plist",
            bytes: EnrollmentProbeFiles.encode([
              "sequence": sequence, "action": command.action, "status": outcome, "ticks": after,
              "durationNanoseconds": clock.nanoseconds(from: before, to: after),
            ]))
          if command.action == "stop" {
            try files.publish(
              publicPath + "/closed.plist",
              bytes: EnrollmentProbeFiles.encode([
                "failedCommands": failedCommands, "commands": sequence + 1, "ticks": after,
                "requiredStage": config.requiredStage, "achievedStages": achievedStages.sorted(),
              ]))
            guard failedCommands == 0 else { throw EnrollmentProbeFailure.commandFailures }
            guard achievedStages.contains(config.requiredStage) else {
              throw EnrollmentProbeFailure.lifecycle
            }
            let summary = XCTAttachment(
              string:
                "Native staged wallet mailbox closed. Review retained stage outcomes; this is not an enrollment/monetary qualification verdict. run=\(run) actor=\(role) invocation=\(invocation)"
            )
            summary.lifetime = .keepAlways
            add(summary)
            return
          }
        }
        throw EnrollmentProbeFailure.timeout
      } catch {
        // No abandon/delete on errors. Release the exact owner and leave custody resumable.
        do { try await driver.close() } catch { throw EnrollmentProbeFailure.custody }
        throw error
      }
    #endif
  }
}

/// Monotonic continuous-clock durations include system sleep; values from different processes
/// or phones are never subtracted. Enrollment deadlines remain exclusively Native decisions.
struct EnrollmentProbeClock {
  let numerator: UInt64
  let denominator: UInt64
  func nanoseconds(from start: UInt64, to end: UInt64) -> UInt64 {
    let delta = end - start
    return (delta / denominator) * numerator + (delta % denominator) * numerator / denominator
  }
}

/// Test mailbox deadlines bound intake; Native owns the lifecycle of any dispatched operation.
struct EnrollmentProbeDeadline {
  let clock: EnrollmentProbeClock
  let started: UInt64
  let duration: UInt64
  let now: () -> UInt64
  var checkCancellation: () throws -> Void = { try Task.checkCancellation() }

  func check() throws {
    try checkCancellation()
    guard clock.numerator > 0, clock.denominator > 0, duration > 0 else {
      throw EnrollmentProbeFailure.input
    }
    let observed = now()
    guard observed >= started else { throw EnrollmentProbeFailure.timeout }
    // Compare exact products so a regressed or very large test clock cannot wrap or trap.
    let elapsed = (observed - started).multipliedFullWidth(by: clock.numerator)
    let limit = duration.multipliedFullWidth(by: clock.denominator)
    guard elapsed.high < limit.high || (elapsed.high == limit.high && elapsed.low < limit.low) else {
      throw EnrollmentProbeFailure.timeout
    }
  }

  func select<T>(_ read: () throws -> T) throws -> T {
    try check()
    let selected = try read()
    try check()
    return selected
  }
}
