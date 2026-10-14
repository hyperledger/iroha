// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
import Darwin
import Foundation
import XCTest

/// Pure harness guard tests; they confer no Native or physical-device qualification.
final class KagemushaEnrollmentProbeFilesTests: XCTestCase {
  /// Host runs exercise filesystem publication with a protection adapter only. Physical iOS
  /// runs use the actual attribute setter; host success is no Data Protection evidence.
  private func mailbox(
    root: URL,
    publicationBoundary: @escaping (EnrollmentProbeFiles.PublicationBoundary) throws -> Void = {
      _ in
    },
    directoryBoundary: @escaping (EnrollmentProbeFiles.DirectoryBoundary) throws -> Void = { _ in }
  ) throws -> EnrollmentProbeFiles {
    #if os(iOS)
      return try EnrollmentProbeFiles(
        root: root, publicationBoundary: publicationBoundary, directoryBoundary: directoryBoundary)
    #else
      return try EnrollmentProbeFiles(
        root: root, setProtection: { _ in }, publicationBoundary: publicationBoundary,
        directoryBoundary: directoryBoundary)
    #endif
  }

  func testProtectionFailurePreventsPublication() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(
      at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let files = try EnrollmentProbeFiles(
      root: root,
      setProtection: { _ in
        throw EnrollmentProbeFailure.custody
      })
    XCTAssertThrowsError(try files.publish("original", bytes: Data([1])))
    XCTAssertFalse(try files.exists("original"))
  }

  func testPinsRejectPathEscapesUnknownFieldsAndMalformedHashes() throws {
    for path in ["", "/root", "../account", "a/../b", "a//b", "a/./b", "a/"] {
      XCTAssertThrowsError(
        try EnrollmentProbePin([
          "path": path, "size": 1, "sha256": String(repeating: "a", count: 64),
        ]))
    }
    XCTAssertThrowsError(
      try EnrollmentProbePin(["path": "x", "size": -1, "sha256": String(repeating: "a", count: 64)])
    )
    XCTAssertThrowsError(
      try EnrollmentProbePin(["path": "x", "size": 1, "sha256": String(repeating: "A", count: 64)]))
    XCTAssertThrowsError(
      try EnrollmentProbePin([
        "path": "x", "size": 1, "sha256": String(repeating: "a", count: 64), "fallback": true,
      ]))
    let valid = try EnrollmentProbePin([
      "path": "catalog/originals/proof.bin", "size": 0,
      "sha256": EnrollmentProbeFiles.digest(Data()),
    ])
    XCTAssertEqual(valid.path, "catalog/originals/proof.bin")
  }

  func testPrivateReadsRejectSymlinksChangedBytesAndOversizedFiles() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(
      at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let bytes = Data([1, 2, 3])
    let source = root.appendingPathComponent("source")
    try bytes.write(to: source)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: source.path)
    try FileManager.default.createSymbolicLink(
      atPath: root.appendingPathComponent("alias").path, withDestinationPath: source.path)
    let files = try mailbox(root: root)
    XCTAssertThrowsError(try files.read("alias", maximum: 3))
    XCTAssertThrowsError(try files.read("source", maximum: 2))
    let pin = try EnrollmentProbePin([
      "path": "source", "size": 3, "sha256": EnrollmentProbeFiles.digest(bytes),
    ])
    XCTAssertEqual(try files.pinned(pin, maximum: 3), bytes)
    try Data([3, 2, 1]).write(to: source)
    XCTAssertThrowsError(try files.pinned(pin, maximum: 3))
  }

  func testReadyDigestWaitsForEveryIncompleteFrame() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(
      at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let files = try mailbox(root: root)
    let name = "command.ready"
    XCTAssertNil(try files.readyDigest(name))
    let fd = open(root.appendingPathComponent(name).path, O_WRONLY | O_CREAT | O_EXCL, 0o600)
    XCTAssertGreaterThanOrEqual(fd, 0)
    guard fd >= 0 else { return }
    defer { close(fd) }
    let digest = EnrollmentProbeFiles.digest(Data("exact command".utf8))
    for var byte in digest.utf8 {
      XCTAssertNil(try files.readyDigest(name))
      XCTAssertEqual(Darwin.write(fd, &byte, 1), 1)
    }
    XCTAssertEqual(try files.readyDigest(name), digest)
    var extra: UInt8 = 10
    XCTAssertEqual(Darwin.write(fd, &extra, 1), 1)
    XCTAssertThrowsError(try files.readyDigest(name))
  }

  func testReadyDigestRejectsCompleteMalformedAndUnsafeFrames() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(
      at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let files = try mailbox(root: root)
    try files.publish("uppercase.ready", bytes: Data(repeating: 65, count: 64))
    try files.publish("binary.ready", bytes: Data(repeating: 0, count: 64))
    XCTAssertThrowsError(try files.readyDigest("uppercase.ready"))
    XCTAssertThrowsError(try files.readyDigest("binary.ready"))
    try files.mkdir("directory.ready")
    XCTAssertThrowsError(try files.readyDigest("directory.ready"))
    try FileManager.default.createSymbolicLink(
      atPath: root.appendingPathComponent("alias.ready").path,
      withDestinationPath: root.appendingPathComponent("uppercase.ready").path)
    XCTAssertThrowsError(try files.readyDigest("alias.ready"))
    let digest = EnrollmentProbeFiles.digest(Data([1]))
    try files.publish("valid.ready", bytes: Data(digest.utf8))
    let original = root.appendingPathComponent("valid.ready")
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: original.path)
    XCTAssertThrowsError(try files.readyDigest("valid.ready"))
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: original.path)
    try FileManager.default.linkItem(at: original, to: root.appendingPathComponent("linked.ready"))
    XCTAssertThrowsError(try files.readyDigest("valid.ready"))
    XCTAssertThrowsError(try files.readyDigest("linked.ready"))
    XCTAssertThrowsError(try files.readyDigest("../valid.ready"))
  }

  func testExclusivePublicationRetainsOriginalAndRefusesReplacement() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(
      at: root, withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let files = try mailbox(root: root)
    let original = Data([1, 2, 3])
    try files.publish("original", bytes: original)
    try files.publish("original", bytes: original)
    XCTAssertThrowsError(try files.publish("original", bytes: Data([4, 5, 6])))
    XCTAssertEqual(try files.read("original", maximum: 3), original)
    try FileManager.default.createSymbolicLink(
      atPath: root.appendingPathComponent("alias").path,
      withDestinationPath: root.appendingPathComponent("original").path)
    XCTAssertThrowsError(try files.publish("alias", bytes: original))
    XCTAssertEqual(try files.read("original", maximum: 3), original)
  }

  func testInterruptedStagingNeverOccupiesTheFinalName() throws {
    for boundary in [EnrollmentProbeFiles.PublicationBoundary.staged, .written, .fileSynchronized] {
      let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
      try FileManager.default.createDirectory(
        at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
      defer { try? FileManager.default.removeItem(at: root) }
      let files = try mailbox(root: root, publicationBoundary: {
        if $0 == boundary { throw EnrollmentProbeFailure.custody }
      })
      XCTAssertThrowsError(try files.publish("original", bytes: Data([1, 2, 3])))
      XCTAssertFalse(try files.exists("original"))
      // A process death can retain staging; only the final immutable name participates in retry.
      let orphan = root.appendingPathComponent(".publication-" + UUID().uuidString)
      try Data([1]).write(to: orphan)
      try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: orphan.path)
      let resumed = try mailbox(root: root)
      try resumed.publish("original", bytes: Data([1, 2, 3]))
      XCTAssertEqual(try resumed.read("original", maximum: 3), Data([1, 2, 3]))
      XCTAssertEqual(try Data(contentsOf: orphan), Data([1]))
    }
  }

  func testUncertainPublicationRequiresExactByteRetryThroughSynchronization() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(
      at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let original = Data([1, 2, 3])
    let files = try mailbox(root: root, publicationBoundary: {
      if $0 == .published { throw EnrollmentProbeFailure.custody }
    })
    XCTAssertThrowsError(try files.publish("original", bytes: original))
    XCTAssertEqual(try files.read("original", maximum: 3), original)
    var boundaries = [EnrollmentProbeFiles.PublicationBoundary]()
    let resumed = try mailbox(root: root, publicationBoundary: { boundaries.append($0) })
    XCTAssertThrowsError(try resumed.publish("original", bytes: Data([4, 5, 6])))
    boundaries.removeAll()
    try resumed.publish("original", bytes: original)
    XCTAssertEqual(
      boundaries, [.staged, .written, .fileSynchronized, .published, .directorySynchronized])
    XCTAssertEqual(try resumed.read("original", maximum: 3), original)
  }

  func testUncertainDispatchFenceNeverPermitsIdenticalRetryAfterPublication() throws {
    for boundary in [EnrollmentProbeFiles.PublicationBoundary.published, .directorySynchronized] {
      let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
      try FileManager.default.createDirectory(
        at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
      defer { try? FileManager.default.removeItem(at: root) }
      let original = Data([1, 2, 3])
      let interrupted = try mailbox(root: root, publicationBoundary: {
        if $0 == boundary { throw EnrollmentProbeFailure.custody }
      })
      XCTAssertThrowsError(try interrupted.publishDispatchFence("executed", bytes: original))
      let resumed = try mailbox(root: root)
      XCTAssertThrowsError(try resumed.publishDispatchFence("executed", bytes: original))
      XCTAssertThrowsError(try resumed.publishDispatchFence("executed", bytes: Data([4, 5, 6])))
      XCTAssertEqual(try resumed.read("executed", maximum: 3), original)
    }
  }

  func testDispatchFenceRefusesLosingTheNoReplaceRaceEvenToIdenticalBytes() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(
      at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let original = Data([1, 2, 3])
    let winner = try mailbox(root: root)
    let loser = try mailbox(root: root, publicationBoundary: {
      if $0 == .fileSynchronized { try winner.publishDispatchFence("executed", bytes: original) }
    })
    XCTAssertThrowsError(try loser.publishDispatchFence("executed", bytes: original))
    XCTAssertEqual(try winner.read("executed", maximum: 3), original)
  }

  func testUnpublishedDispatchFenceMayBeSelectedOnceBeforeAnyNativeDispatch() throws {
    for boundary in [EnrollmentProbeFiles.PublicationBoundary.staged, .written, .fileSynchronized] {
      let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
      try FileManager.default.createDirectory(
        at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
      defer { try? FileManager.default.removeItem(at: root) }
      let original = Data([1, 2, 3])
      let interrupted = try mailbox(root: root, publicationBoundary: {
        if $0 == boundary { throw EnrollmentProbeFailure.custody }
      })
      XCTAssertThrowsError(try interrupted.publishDispatchFence("executed", bytes: original))
      XCTAssertFalse(try interrupted.exists("executed"))
      let resumed = try mailbox(root: root)
      try resumed.publishDispatchFence("executed", bytes: original)
      XCTAssertThrowsError(try resumed.publishDispatchFence("executed", bytes: original))
    }
  }

  func testPrivateFilesRejectHardLinksAndSpecialPermissionBits() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(
      at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let files = try mailbox(root: root)
    try files.publish("original", bytes: Data([1]))
    let original = root.appendingPathComponent("original")
    let alias = root.appendingPathComponent("alias")
    XCTAssertEqual(link(original.path, alias.path), 0)
    XCTAssertThrowsError(try files.read("original", maximum: 1))
    XCTAssertThrowsError(try files.publish("original", bytes: Data([1])))
    XCTAssertEqual(unlink(alias.path), 0)
    XCTAssertEqual(chmod(original.path, 0o4600), 0)
    XCTAssertThrowsError(try files.read("original", maximum: 1))
    XCTAssertThrowsError(try files.publish("original", bytes: Data([1])))
    XCTAssertEqual(chmod(root.path, 0o1700), 0)
    XCTAssertThrowsError(try mailbox(root: root))
  }

  func testFreshInvocationRequiresAnExclusiveDirectory() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(
      at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let files = try mailbox(root: root)
    try files.mkdir("actor/public")
    try files.mkdirExclusive("actor/public/invocation")
    XCTAssertThrowsError(try files.mkdirExclusive("actor/public/invocation"))
  }

  func testEveryDirectoryComponentSynchronizesItsMetadataAndParentOnCreationAndRetry() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(
      at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    var observed = [EnrollmentProbeFiles.DirectoryBoundary]()
    let files = try mailbox(root: root, directoryBoundary: { observed.append($0) })
    let component: [EnrollmentProbeFiles.DirectoryBoundary] = [
      .beforeDirectorySynchronization, .directorySynchronized,
      .beforeParentSynchronization, .parentSynchronized,
    ]
    try files.mkdir("actor/private/intents")
    XCTAssertEqual(observed, component + component + component)
    observed.removeAll()
    try files.mkdir("actor/private/intents")
    XCTAssertEqual(observed, component + component + component)
    try files.publish("actor/private/intents/identity", bytes: Data([1, 2, 3]))
    XCTAssertEqual(try files.read("actor/private/intents/identity", maximum: 3), Data([1, 2, 3]))
  }

  func testInterruptedDirectorySynchronizationMustRetryBothBarriersForEveryComponent() throws {
    // Two components, four boundaries each. Both pre-sync failures and uncertain returns
    // after a successful sync must fail the attempt and re-enter the barriers on retry.
    for failureIndex in 1...8 {
      let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
      try FileManager.default.createDirectory(
        at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
      defer { try? FileManager.default.removeItem(at: root) }
      var visits = 0
      let interrupted = try mailbox(root: root, directoryBoundary: { _ in
        visits += 1
        if visits == failureIndex { throw EnrollmentProbeFailure.custody }
      })
      XCTAssertThrowsError(try interrupted.mkdir("actor/private"))
      XCTAssertEqual(visits, failureIndex)
      var resumed = [EnrollmentProbeFiles.DirectoryBoundary]()
      let files = try mailbox(root: root, directoryBoundary: { resumed.append($0) })
      try files.mkdir("actor/private")
      XCTAssertEqual(resumed, [
        .beforeDirectorySynchronization, .directorySynchronized,
        .beforeParentSynchronization, .parentSynchronized,
        .beforeDirectorySynchronization, .directorySynchronized,
        .beforeParentSynchronization, .parentSynchronized,
      ])
      try files.publish("actor/private/identity", bytes: Data([1]))
      XCTAssertEqual(try files.read("actor/private/identity", maximum: 1), Data([1]))
    }
  }

  func testContinuousClockConvertsOnlyOneProcessDuration() {
    let clock = EnrollmentProbeClock(numerator: 125, denominator: 3)
    XCTAssertEqual(clock.nanoseconds(from: 10, to: 13), 125)
    XCTAssertEqual(clock.nanoseconds(from: 10, to: 14), 166)
  }

  func testReadyMarkerCannotBypassDeadlineBeforeOrDuringSelection() throws {
    var ticks: UInt64 = 9
    var reads = 0
    let deadline = EnrollmentProbeDeadline(
      clock: .init(numerator: 1, denominator: 1), started: 0, duration: 10, now: { ticks })
    XCTAssertThrowsError(try deadline.select { ticks = 10; reads += 1; return "ready" })
    XCTAssertEqual(reads, 1)
    XCTAssertThrowsError(try deadline.select { reads += 1; return "ready" })
    XCTAssertEqual(reads, 1)
  }

  func testCancellationDuringSelectionAndRetentionPreventsCompletion() throws {
    var cancelled = false
    var ticks: UInt64 = 9
    let deadline = EnrollmentProbeDeadline(
      clock: .init(numerator: 1, denominator: 1), started: 0, duration: 10, now: { ticks },
      checkCancellation: { if cancelled { throw CancellationError() } })
    XCTAssertThrowsError(try deadline.select { cancelled = true; return "ready" }) { error in
      XCTAssertTrue(error is CancellationError)
    }
    cancelled = false
    XCTAssertEqual(try deadline.select { "ready" }, "ready")
    ticks = 10
    XCTAssertThrowsError(try deadline.check())
  }

  func testDeadlineUsesExactTimebaseAndRejectsRegressionAndOverflow() throws {
    var ticks: UInt64 = 102
    let deadline = EnrollmentProbeDeadline(
      clock: .init(numerator: 125, denominator: 3), started: 100, duration: 125, now: { ticks })
    XCTAssertNoThrow(try deadline.check())
    ticks = 103
    XCTAssertThrowsError(try deadline.check())
    ticks = 99
    XCTAssertThrowsError(try deadline.check())
    let large = EnrollmentProbeDeadline(
      clock: .init(numerator: .max, denominator: 1), started: 0, duration: .max,
      now: { .max })
    XCTAssertThrowsError(try large.check())
    let fractional = EnrollmentProbeDeadline(
      clock: .init(numerator: 1, denominator: .max), started: 0, duration: 1,
      now: { .max - 1 })
    XCTAssertNoThrow(try fractional.check())
  }

  func testDeadlineRefusesInvalidBoundsAndKeepsOneDeadlineAcrossPolls() throws {
    for (numerator, denominator, duration) in [(0, 1, 1), (1, 0, 1), (1, 1, 0)] {
      let deadline = EnrollmentProbeDeadline(
        clock: .init(numerator: UInt64(numerator), denominator: UInt64(denominator)),
        started: 0, duration: UInt64(duration), now: { 0 })
      XCTAssertThrowsError(try deadline.check())
    }
    var ticks: UInt64 = 1
    let deadline = EnrollmentProbeDeadline(
      clock: .init(numerator: 1, denominator: 1), started: 0, duration: 10, now: { ticks })
    XCTAssertNil(try deadline.select { nil as String? })
    ticks = 10
    XCTAssertThrowsError(try deadline.select { "ready" })
  }
}
