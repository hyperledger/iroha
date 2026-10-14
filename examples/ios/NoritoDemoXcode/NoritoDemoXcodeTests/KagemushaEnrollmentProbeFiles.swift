// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
import CryptoKit
import Darwin
import Foundation

/// Test mailbox metadata is a plist; every protocol original remains unchanged Norito DATA.
/// Never describe values in errors: inputs include runtime-only FI authorization material.
enum EnrollmentProbeFailure: Error {
  case input, custody, collision, timeout, lifecycle, commandFailures
}

struct EnrollmentProbePin {
  let path: String
  let size: Int
  let sha256: String
  init(_ value: Any) throws {
    guard let row = value as? [String: Any], Set(row.keys) == ["path", "size", "sha256"],
      let path = row["path"] as? String, let size = row["size"] as? Int, size >= 0,
      let digest = row["sha256"] as? String, EnrollmentProbeFiles.isDigest(digest)
    else { throw EnrollmentProbeFailure.input }
    try EnrollmentProbeFiles.requireRelative(path)
    self.path = path
    self.size = size
    self.sha256 = digest
  }
}

/// Owner-only app-container I/O. Immutable outputs are staged and synchronized before
/// atomic publication. Interrupted staging never occupies a final mailbox name.
final class EnrollmentProbeFiles: @unchecked Sendable {
  enum PublicationBoundary: Equatable {
    case staged, written, fileSynchronized, published, directorySynchronized
  }
  enum DirectoryBoundary: Equatable {
    case beforeDirectorySynchronization, directorySynchronized
    case beforeParentSynchronization, parentSynchronized
  }
  let root: URL
  private let setProtection: (URL) throws -> Void
  private let publicationBoundary: (PublicationBoundary) throws -> Void
  private let directoryBoundary: (DirectoryBoundary) throws -> Void
  init(
    root: URL,
    setProtection: @escaping (URL) throws -> Void = {
      try FileManager.default.setAttributes(
        [.protectionKey: FileProtectionType.complete], ofItemAtPath: $0.path)
    },
    publicationBoundary: @escaping (PublicationBoundary) throws -> Void = { _ in },
    directoryBoundary: @escaping (DirectoryBoundary) throws -> Void = { _ in }
  ) throws {
    self.root = root
    self.setProtection = setProtection
    self.publicationBoundary = publicationBoundary
    self.directoryBoundary = directoryBoundary
    try Self.requireDirectory(root)
  }
  static func digest(_ bytes: Data) -> String {
    SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
  }
  static func isDigest(_ text: String) -> Bool {
    text.count == 64 && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
  }
  static func requireRelative(_ path: String) throws {
    guard !path.isEmpty, !path.hasPrefix("/"), !path.utf8.contains(0),
      path.split(separator: "/", omittingEmptySubsequences: false).allSatisfy({
        !$0.isEmpty && $0 != "." && $0 != ".."
      })
    else { throw EnrollmentProbeFailure.input }
  }
  static func requireDirectory(_ url: URL) throws {
    var value = stat()
    guard lstat(url.path, &value) == 0,
      value.st_mode & S_IFMT == S_IFDIR, value.st_uid == geteuid(),
      value.st_mode & 0o7777 == 0o700
    else { throw EnrollmentProbeFailure.custody }
  }
  func url(_ path: String) throws -> URL {
    try Self.requireRelative(path)
    var current = root
    let parts = path.split(separator: "/")
    for part in parts.dropLast() {
      current.appendPathComponent(String(part), isDirectory: true)
      try Self.requireDirectory(current)
    }
    return current.appendingPathComponent(String(parts.last!))
  }
  /// Only this process may create an invocation namespace; never merge with old outputs.
  func mkdirExclusive(_ path: String) throws {
    let target = try url(path)
    guard Darwin.mkdir(target.path, 0o700) == 0 else {
      throw errno == EEXIST ? EnrollmentProbeFailure.collision : EnrollmentProbeFailure.custody
    }
    try mkdir(path)
  }
  func mkdir(_ path: String) throws {
    try Self.requireRelative(path)
    var current = root
    for part in path.split(separator: "/") {
      let parent = current
      try Self.requireDirectory(parent)
      current.appendPathComponent(String(part), isDirectory: true)
      if Darwin.mkdir(current.path, 0o700) != 0 && errno != EEXIST {
        throw EnrollmentProbeFailure.custody
      }
      try Self.requireDirectory(current)
      var values = URLResourceValues()
      values.isExcludedFromBackup = true
      try current.setResourceValues(values)
      try setProtection(current)
      // Persist protection/backup metadata and this component's name before a child may
      // depend on it. Existing directories retry both barriers after uncertain failures.
      try directoryBoundary(.beforeDirectorySynchronization)
      try synchronizeDirectory(current)
      try directoryBoundary(.directorySynchronized)
      try directoryBoundary(.beforeParentSynchronization)
      try synchronizeDirectory(parent)
      try directoryBoundary(.parentSynchronized)
    }
  }
  private func synchronizeDirectory(_ url: URL) throws {
    let fd = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { throw EnrollmentProbeFailure.custody }
    defer { close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
      info.st_uid == geteuid(), info.st_mode & 0o7777 == 0o700,
      fsync(fd) == 0
    else { throw EnrollmentProbeFailure.custody }
  }
  func read(_ path: String, maximum: Int) throws -> Data {
    let source = try url(path)
    let fd = open(source.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { throw EnrollmentProbeFailure.custody }
    defer { close(fd) }
    var value = stat()
    guard fstat(fd, &value) == 0, value.st_mode & S_IFMT == S_IFREG,
      value.st_uid == geteuid(), value.st_mode & 0o7777 == 0o600, value.st_nlink == 1,
      value.st_size >= 0, value.st_size <= maximum
    else { throw EnrollmentProbeFailure.custody }
    var bytes = Data(count: Int(value.st_size))
    try bytes.withUnsafeMutableBytes { target in
      var offset = 0
      while offset < target.count {
        let count = Darwin.read(fd, target.baseAddress!.advanced(by: offset), target.count - offset)
        if count < 0 && errno == EINTR { continue }
        guard count > 0 else { throw EnrollmentProbeFailure.custody }
        offset += count
      }
    }
    var extra: UInt8 = 0
    guard Darwin.read(fd, &extra, 1) == 0 else { throw EnrollmentProbeFailure.custody }
    return bytes
  }
  func pinned(_ pin: EnrollmentProbePin, maximum: Int) throws -> Data {
    guard pin.size <= maximum else { throw EnrollmentProbeFailure.input }
    let bytes = try read(pin.path, maximum: maximum)
    guard bytes.count == pin.size, Self.digest(bytes) == pin.sha256 else {
      throw EnrollmentProbeFailure.input
    }
    return bytes
  }
  /// Stream potentially large proof sources; Native still authenticates its own source contract.
  func verifyLarge(_ pin: EnrollmentProbePin) throws {
    let source = try url(pin.path)
    let fd = open(source.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { throw EnrollmentProbeFailure.custody }
    defer { close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
      info.st_uid == geteuid(), info.st_mode & 0o7777 == 0o600, info.st_nlink == 1,
      info.st_size == pin.size
    else { throw EnrollmentProbeFailure.custody }
    var hash = SHA256()
    var buffer = [UInt8](repeating: 0, count: 1 << 20)
    var total = 0
    while true {
      let count = Darwin.read(fd, &buffer, buffer.count)
      if count < 0 && errno == EINTR { continue }
      guard count >= 0 else { throw EnrollmentProbeFailure.custody }
      if count == 0 { break }
      total += count
      guard total <= pin.size else { throw EnrollmentProbeFailure.input }
      hash.update(data: Data(buffer.prefix(count)))
    }
    guard total == pin.size,
      hash.finalize().map({ String(format: "%02x", $0) }).joined() == pin.sha256
    else { throw EnrollmentProbeFailure.input }
  }
  func plist(_ path: String, maximum: Int = 131_072) throws -> [String: Any] {
    guard
      let value = try PropertyListSerialization.propertyList(
        from: read(path, maximum: maximum), format: nil) as? [String: Any]
    else { throw EnrollmentProbeFailure.input }
    return value
  }
  static func encode(_ row: [String: Any]) throws -> Data {
    try PropertyListSerialization.data(fromPropertyList: row, format: .xml, options: 0)
  }
  /// Fence one reviewed dispatch under the actor lock. Even identical existing bytes refuse
  /// another attempt; ordinary immutable output retry must never authorize a second dispatch.
  /// If publication becomes uncertain, retain the marker and use Native request recovery.
  func publishDispatchFence(_ path: String, bytes: Data) throws {
    try publish(path, bytes: bytes, allowOriginalRecovery: false)
  }
  /// Publish complete bytes without replacement. Retry an uncertain sync on identical output.
  func publish(_ path: String, bytes: Data) throws {
    try publish(path, bytes: bytes, allowOriginalRecovery: true)
  }
  private func publish(_ path: String, bytes: Data, allowOriginalRecovery: Bool) throws {
    let destination = try url(path)
    let parentURL = destination.deletingLastPathComponent()
    let staging = parentURL.appendingPathComponent(".publication-" + UUID().uuidString)
    // An interrupted process may leave its private staging file. It never owns the final
    // name and is not used by a retry. Native custody is never inspected or deleted here.
    let fd = open(staging.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
    guard fd >= 0 else { throw EnrollmentProbeFailure.custody }
    defer {
      close(fd)
      _ = unlink(staging.path)
    }
    try setProtection(staging)
    try publicationBoundary(.staged)
    try bytes.withUnsafeBytes { source in
      var offset = 0
      while offset < source.count {
        let count = Darwin.write(
          fd, source.baseAddress!.advanced(by: offset), source.count - offset)
        if count < 0 && errno == EINTR { continue }
        guard count > 0 else { throw EnrollmentProbeFailure.custody }
        offset += count
      }
    }
    try publicationBoundary(.written)
    guard fsync(fd) == 0, fcntl(fd, F_FULLFSYNC) == 0 else {
      throw EnrollmentProbeFailure.custody
    }
    try publicationBoundary(.fileSynchronized)
    if renamex_np(staging.path, destination.path, UInt32(RENAME_EXCL)) != 0 {
      guard errno == EEXIST else { throw EnrollmentProbeFailure.custody }
      guard allowOriginalRecovery else { throw EnrollmentProbeFailure.lifecycle }
      // All callers hold the actor lock; external staging must preserve immutable files.
      guard try read(path, maximum: bytes.count) == bytes else {
        throw EnrollmentProbeFailure.collision
      }
      let retained = open(destination.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
      guard retained >= 0 else { throw EnrollmentProbeFailure.custody }
      defer { close(retained) }
      var info = stat()
      guard fstat(retained, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
        info.st_uid == geteuid(), info.st_mode & 0o7777 == 0o600, info.st_nlink == 1,
        info.st_size == bytes.count,
        fsync(retained) == 0, fcntl(retained, F_FULLFSYNC) == 0
      else { throw EnrollmentProbeFailure.custody }
    }
    try publicationBoundary(.published)
    let parent = open(parentURL.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard parent >= 0 else { throw EnrollmentProbeFailure.custody }
    defer { close(parent) }
    guard fsync(parent) == 0 else { throw EnrollmentProbeFailure.custody }
    try publicationBoundary(.directorySynchronized)
  }
  func exists(_ path: String) throws -> Bool {
    var info = stat()
    if lstat(try url(path).path, &info) == 0 { return true }
    guard errno == ENOENT else { throw EnrollmentProbeFailure.custody }
    return false
  }
  /// Wait for the sole 64-byte incoming digest frame, including a transfer still writing it.
  /// The controller writes this fresh file last and never rewrites it. A complete frame must
  /// still match the separately read command; visibility is not a persistence guarantee.
  func readyDigest(_ path: String) throws -> String? {
    let fd = open(try url(path).path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
    guard fd >= 0 else {
      if errno == ENOENT { return nil }
      throw EnrollmentProbeFailure.custody
    }
    defer { close(fd) }
    var value = stat()
    guard fstat(fd, &value) == 0, value.st_mode & S_IFMT == S_IFREG,
      value.st_uid == geteuid(), value.st_mode & 0o7777 == 0o600, value.st_nlink == 1,
      value.st_size >= 0, value.st_size <= 64
    else { throw EnrollmentProbeFailure.custody }
    // Read up to the fixed bound plus one, rather than allocating the initial stat size:
    // the writer may complete between fstat and read. Short frames authorize no work.
    var bytes = [UInt8](repeating: 0, count: 65)
    let count = try bytes.withUnsafeMutableBytes { buffer in
      var offset = 0
      while offset < buffer.count {
        let amount = Darwin.read(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
        if amount < 0 && errno == EINTR { continue }
        guard amount >= 0 else { throw EnrollmentProbeFailure.custody }
        if amount == 0 { break }
        offset += amount
      }
      return offset
    }
    guard count <= 64 else { throw EnrollmentProbeFailure.input }
    guard count == 64 else { return nil }
    guard let digest = String(bytes: bytes.prefix(count), encoding: .utf8), Self.isDigest(digest)
    else { throw EnrollmentProbeFailure.input }
    return digest
  }
  func lock(_ path: String) throws -> Int32 {
    let fd = open(try url(path).path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
    guard fd >= 0 else { throw EnrollmentProbeFailure.custody }
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
      info.st_uid == geteuid(), info.st_mode & 0o7777 == 0o600, info.st_nlink == 1,
      flock(fd, LOCK_EX | LOCK_NB) == 0
    else {
      close(fd)
      throw EnrollmentProbeFailure.custody
    }
    return fd
  }
}
