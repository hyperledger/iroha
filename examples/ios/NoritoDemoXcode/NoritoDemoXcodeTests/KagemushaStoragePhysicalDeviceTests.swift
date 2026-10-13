// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
import CryptoKit
import Darwin
import Foundation
import Security
import UIKit
import XCTest

@testable import IrohaSwift

/// Disposable physical-device observations of the actual Swift platform adapter.
/// This is not a Rust Advance, a Payment, enrollment attestation, a power cut, or a restore
/// qualification. Anchor payloads are labelled probe bytes, not protocol-encoded markers.
final class KagemushaStoragePhysicalDeviceTests: XCTestCase {
  private static let bundlePrefix = "org.hyperledger.iroha.kagemusha.storage-probe."

  /// `cycle` is self-contained. Other phases use an explicit shared run UUID in separate
  /// test-host invocations; only `verify-release` or `cleanup` removes that run's state.
  func testDisposableAnchorAndSignatureStorage() async throws {
    #if !os(iOS) || targetEnvironment(simulator) || targetEnvironment(macCatalyst)
      throw failure("A physical iPhone is required; no simulator fallback is permitted")
    #else
      let environment = ProcessInfo.processInfo.environment
      let phase = environment["KAGEMUSHA_STORAGE_PROBE_PHASE"] ?? "cycle"
      try require(
        [
          "cycle", "prepare-selected", "complete-release", "verify-release",
          "observe-lock", "cleanup",
        ].contains(phase), "Unknown probe phase")
      let runID: UUID
      if let value = environment["KAGEMUSHA_STORAGE_PROBE_RUN_ID"],
        let parsed = UUID(uuidString: value)
      {
        runID = parsed
      } else {
        try require(phase == "cycle", "Staged runs require KAGEMUSHA_STORAGE_PROBE_RUN_ID")
        runID = UUID()
      }
      let bundleID = try XCTUnwrap(Bundle.main.bundleIdentifier)
      try require(bundleID.hasPrefix(Self.bundlePrefix), "Refusing a non-disposable app bundle")
      let prefix = try XCTUnwrap(
        environment["KAGEMUSHA_STORAGE_PROBE_APP_ID_PREFIX"],
        "Supply the signed probe app's actual App ID prefix")
      let group = try KagemushaWalletApplePlatformV1.keychainAccessGroup(
        applicationIdentifierPrefix: prefix, bundleIdentifier: bundleID)
      let support = try KagemushaWalletAppleSystemV1.live.applicationSupportDirectory().get()
        .appendingPathComponent("kagemusha-storage-probes", isDirectory: true)
        .appendingPathComponent(runID.uuidString, isDirectory: true)
      let slot = try XCTUnwrap(
        KagemushaWalletAppleSlotV1(
          Data(
            SHA256.hash(
              data:
                Data("kagemusha-disposable-storage-probe:\(runID.uuidString)".utf8)))))
      let selected = Data("storage-probe:selected:\(runID.uuidString)".utf8)
      let message = Data(SHA256.hash(data: selected))
      let request = try XCTUnwrap(
        KagemushaWalletAppleKeyGenerationRequestV1(
          challengeDigest: message, profile: .secureElement))
      let platform = adapter(group: group, support: support)
      var cleanAtEnd = false
      defer { if cleanAtEnd { cleanup(platform, slot: slot, support: support) } }
      let device = await MainActor.run { (UIDevice.current.model, UIDevice.current.systemVersion) }
      evidence(
        "probe-identity",
        "run=\(runID.uuidString)\nphase=\(phase)\nbundle=\(bundleID)\n"
          + "pid=\(getpid())\nmodel=\(device.0)\niOS=\(device.1)\n"
          + "scope=Swift adapter and disposable OS storage only\n")

      if phase == "cycle" || phase == "prepare-selected" {
        try require(
          !FileManager.default.fileExists(atPath: support.path),
          "Run directory already exists; use its recovery phase or a fresh UUID")
        try FileManager.default.createDirectory(
          at: support, withIntermediateDirectories: true,
          attributes: [.posixPermissions: 0o700])
        _ = try platform.custodyRootPath().get()
        try require(
          platform.anchorRead(slot) == .absent && platform.keyProbe(slot) == .absent,
          "Probe slot already exists; it will not be replaced or deleted")
        do {
          try require(
            platform.anchorCreate(slot, value: Data("storage-probe:none".utf8)) == .published,
            "Initial Keychain mutation was not acknowledged")
          guard case .generated(let publicKey) = platform.keyGenerate(slot, request) else {
            throw failure("Real Secure Enclave generation was not acknowledged")
          }
          try persist(publicKey, at: support.appendingPathComponent("public-key.x963"))
          try persist(
            Data(String(getpid()).utf8), at: support.appendingPathComponent("selected-pid.txt"))
          try require(
            platform.anchorUpdate(slot, value: selected) == .published,
            "Pre-sign anchor mutation was not acknowledged")
          try require(platform.anchorRead(slot) == .present(selected), "Selected anchor differs")
          evidence(
            "selected-acknowledged", "anchorSha256=\(digest(selected))\nsignatureProduced=false\n")
        } catch {
          cleanup(platform, slot: slot, support: support)
          throw error
        }
        if phase == "prepare-selected" { return }
        cleanAtEnd = true
      } else {
        try require(FileManager.default.fileExists(atPath: support.path), "Unknown probe run")
        _ = try platform.custodyRootPath().get()
      }

      if phase == "cleanup" {
        cleanup(platform, slot: slot, support: support)
        return
      }
      if phase == "observe-lock" {
        try await observeLock(platform, slot: slot, selected: selected, message: message)
        return
      }
      if phase == "cycle" || phase == "complete-release" {
        if phase == "complete-release" {
          try requireDifferentProcess(support.appendingPathComponent("selected-pid.txt"))
        }
        let signatureURL = support.appendingPathComponent("signature.der")
        let retained =
          FileManager.default.fileExists(atPath: signatureURL.path)
          ? try Data(contentsOf: signatureURL) : nil
        let current = platform.anchorRead(slot)
        if current == .present(selected) {
          // Exactly the real adapter call used before signing, including an equal-value update.
          try require(
            platform.anchorUpdate(slot, value: selected) == .published,
            "Selected retry was not acknowledged")
        } else {
          let original = try XCTUnwrap(
            retained, "An advanced anchor without its artifact is refused")
          try require(
            current == .present(releasedAnchor(selected: selected, signature: original)),
            "Unexpected anchor; it will not be lowered")
        }
        let signature: Data
        if let retained {
          signature = retained  // Never re-sign a retained artifact.
        } else {
          signature = try platform.keySign(slot, message: message).get()
          try persist(signature, at: signatureURL)
        }
        try verifySignature(signature, message: message, support: support)
        let final = releasedAnchor(selected: selected, signature: signature)
        try require(
          platform.anchorUpdate(slot, value: final) == .published,
          "Final anchor mutation was not acknowledged")
        try require(platform.anchorRead(slot) == .present(final), "Released anchor differs")
        let releasedPID = support.appendingPathComponent("released-pid.txt")
        if !FileManager.default.fileExists(atPath: releasedPID.path) {
          try persist(Data(String(getpid()).utf8), at: releasedPID)
        }
        evidence(
          "released-acknowledged",
          "anchorSha256=\(digest(final))\n"
            + "signatureSha256=\(digest(signature))\nsignatureBytes=\(signature.count)\n")
        if phase == "complete-release" { return }
      }

      // `cycle` only recreates the adapter. The staged phase requires another real process.
      if phase == "verify-release" {
        try requireDifferentProcess(support.appendingPathComponent("released-pid.txt"))
      }
      cleanAtEnd = true
      let signature = try Data(contentsOf: support.appendingPathComponent("signature.der"))
      try verifySignature(signature, message: message, support: support)
      let reopened = adapter(group: group, support: support)
      _ = try reopened.custodyRootPath().get()
      let publicKey = try Data(contentsOf: support.appendingPathComponent("public-key.x963"))
      try require(reopened.keyProbe(slot) == .present(publicKey), "Payment-key identity changed")
      try require(
        reopened.anchorRead(slot)
          == .present(releasedAnchor(selected: selected, signature: signature)),
        "Reopened anchor differs")
      try require(
        try Data(contentsOf: support.appendingPathComponent("signature.der")) == signature,
        "Retained signature bytes changed")
      evidence(
        "exact-retained-bytes",
        "signatureSha256=\(digest(signature))\n"
          + "recovery=\(phase == "cycle" ? "adapter recreation in same process" : "different test-host process")\n"
          + "signerCalledDuringVerification=false\npowerLossTested=false\nbackupRestoreTested=false\n"
      )
    #endif
  }

  #if os(iOS) && !targetEnvironment(macCatalyst)
    private func adapter(group: String, support: URL) -> KagemushaWalletApplePlatformV1 {
      var system = KagemushaWalletAppleSystemV1.live
      // Only the disposable path changes; Security, Secure Enclave, protection, clock and
      // passcode operations all remain the production system implementations.
      system.applicationSupportDirectory = { .success(support) }
      return KagemushaWalletApplePlatformV1(
        appAttest: KagemushaWalletAppleAppAttestServiceV1(),
        accessGroup: group, system: system)
    }

    private func observeLock(
      _ platform: KagemushaWalletApplePlatformV1,
      slot: KagemushaWalletAppleSlotV1, selected: Data, message: Data
    ) async throws {
      try require(
        platform.anchorRead(slot) == .present(selected), "Lock probe needs Selected state")
      evidence(
        "operator-lock-window",
        "Lock and then unlock the selected test phone; no automated lock is performed.\n")
      let start = ProcessInfo.processInfo.systemUptime
      var observed = false
      while ProcessInfo.processInfo.systemUptime - start < 60 {
        if case .failure(.locked) = platform.storageState() {
          observed = true
          break
        }
        try await Task.sleep(nanoseconds: 250_000_000)
      }
      try require(observed, "No actual locked interval observed; this is not lock qualification")
      try require(
        platform.anchorRead(slot) == .unavailable(.locked), "Locked anchor became usable/absent")
      try require(
        platform.keyProbe(slot) == .unavailable(.locked), "Locked key became usable/absent")
      try require(
        platform.anchorUpdate(slot, value: selected) == .notPublished(.failed(.locked)),
        "Locked anchor update was not refused")
      guard case .failure(.locked) = platform.keySign(slot, message: message) else {
        throw failure("A real locked signature was not refused as locked")
      }
      evidence(
        "locked-observation",
        "protectedStorage=locked\nanchorRead=unavailable\nkeyProbe=unavailable\nsign=locked\n")
      let unlockStart = ProcessInfo.processInfo.systemUptime
      while ProcessInfo.processInfo.systemUptime - unlockStart < 60 {
        if case .success = platform.storageState() {
          try require(platform.anchorRead(slot) == .present(selected), "Lock/unlock changed anchor")
          return
        }
        try await Task.sleep(nanoseconds: 250_000_000)
      }
      throw failure("Unlock was not observed; probe state remains for explicit recovery/cleanup")
    }

    private func cleanup(
      _ platform: KagemushaWalletApplePlatformV1,
      slot: KagemushaWalletAppleSlotV1, support: URL
    ) {
      // Exact random test-slot queries only; no class-wide deletes and no production roots.
      let key = platform.keyDelete(slot)
      let anchor = platform.system.keychain.delete(platform.anchorQuery(slot))
      guard key == .removed, anchor == errSecSuccess || anchor == errSecItemNotFound else {
        XCTFail(
          "Disposable cleanup incomplete: key=\(key), anchor=\(anchor); rerun cleanup unlocked")
        return
      }
      do { try FileManager.default.removeItem(at: support) } catch {
        XCTFail("Disposable directory cleanup failed: \(error)")
      }
      evidence("probe-cleanup", "exactTestSlotRemoved=true\n")
    }
  #endif

  private func releasedAnchor(selected: Data, signature: Data) -> Data {
    Data((String(decoding: selected, as: UTF8.self) + ":released:" + digest(signature)).utf8)
  }

  private func verifySignature(_ bytes: Data, message: Data, support: URL) throws {
    let publicKey = try P256.Signing.PublicKey(
      x963Representation:
        Data(contentsOf: support.appendingPathComponent("public-key.x963")))
    let signature = try P256.Signing.ECDSASignature(derRepresentation: bytes)
    try require(
      publicKey.isValidSignature(signature, for: message), "Retained signature is invalid")
  }

  /// Raw diagnostic artifact persistence only; this does not emulate the native paired store.
  private func persist(_ bytes: Data, at url: URL) throws {
    try bytes.write(to: url, options: [.withoutOverwriting, .completeFileProtection])
    let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW)
    try require(descriptor >= 0, "Cannot open probe artifact for synchronization")
    defer { close(descriptor) }
    try require(
      fsync(descriptor) == 0 && fcntl(descriptor, F_FULLFSYNC) == 0,
      "Probe artifact synchronization failed")
    let directory = open(url.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    try require(directory >= 0, "Cannot open probe directory")
    defer { close(directory) }
    try require(fsync(directory) == 0, "Probe directory synchronization failed")
  }

  private func requireDifferentProcess(_ url: URL) throws {
    let previous = try String(contentsOf: url, encoding: .utf8)
    try require(Int32(previous).map { $0 > 0 } == true, "Invalid recorded process identity")
    try require(previous != String(getpid()), "This phase requires a different test-host process")
    evidence(
      "process-boundary",
      "previousPid=\(previous)\ncurrentPid=\(getpid())\n"
        + "This observes process replacement, not power loss.\n")
  }

  private func digest(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
  }

  private func require(_ condition: Bool, _ message: String) throws {
    if !condition { throw failure(message) }
  }

  private func failure(_ message: String) -> NSError {
    NSError(
      domain: "KagemushaStoragePhysicalDeviceTests", code: 1,
      userInfo: [NSLocalizedDescriptionKey: message])
  }

  private func evidence(_ name: String, _ text: String) {
    let attachment = XCTAttachment(string: text)
    attachment.name = name
    attachment.lifetime = .keepAlways
    add(attachment)
  }
}
