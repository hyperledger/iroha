import Foundation
import CryptoKit
import IrohaSwift

struct PosProvisionManifest: Codable {
  let schema: String
  let manifestId: String
  let sequence: Int
  let publishedAtMs: UInt64
  let validFromMs: UInt64
  let validUntilMs: UInt64
  let rotationHintMs: UInt64?
  let operatorId: String
  let backendRoots: [PosBackendRoot]
  let metadata: [String: String]?

  enum CodingKeys: String, CodingKey {
    case schema
    case manifestId = "manifest_id"
    case sequence
    case publishedAtMs = "published_at_ms"
    case validFromMs = "valid_from_ms"
    case validUntilMs = "valid_until_ms"
    case rotationHintMs = "rotation_hint_ms"
    case operatorId = "operator"
    case backendRoots = "backend_roots"
    case metadata
  }
}

struct PosBackendRoot: Codable {
  let label: String
  let role: String
  let publicKey: String
  let validFromMs: UInt64
  let validUntilMs: UInt64
  let metadata: [String: String]?

  enum CodingKeys: String, CodingKey {
    case label
    case role
    case publicKey = "public_key"
    case validFromMs = "valid_from_ms"
    case validUntilMs = "valid_until_ms"
    case metadata
  }
}

struct PosManifestStatus: Identifiable {
  struct BackendRootStatus: Identifiable {
    var id: String { label }
    let label: String
    let role: String
    let statusLabel: String
    let active: Bool
  }

  var id: String { manifestId }
  let manifestId: String
  let sequence: Int
  let operatorId: String
  let validWindowLabel: String
  let rotationLabel: String
  let dualStatusLabel: String
  let dualStatusHealthy: Bool
  let warnings: [String]
  let backendRoots: [BackendRootStatus]

  static func from(manifest: PosProvisionManifest, now: Date = Date()) -> PosManifestStatus {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let validWindow = "\(formatter.string(from: manifest.validFromMs.date)) – \(formatter.string(from: manifest.validUntilMs.date))"
    let rotationLabel = manifest.rotationHintMs.map { formatter.string(from: $0.date) } ?? "n/a"
    let backendStatuses = manifest.backendRoots.map { root -> BackendRootStatus in
      let active = now >= root.validFromMs.date && now <= root.validUntilMs.date
      let statusText = backendStatusLabel(root: root, active: active, formatter: formatter, now: now)
      return BackendRootStatus(label: root.label, role: root.role, statusLabel: statusText, active: active)
    }
    let dualStatus = computeDualStatus(roots: backendStatuses, manifest: manifest, now: now)
    let warnings = computeWarnings(manifest: manifest, roots: backendStatuses, dualStatus: dualStatus, now: now, formatter: formatter)
    return PosManifestStatus(
      manifestId: manifest.manifestId,
      sequence: manifest.sequence,
      operatorId: manifest.operatorId,
      validWindowLabel: validWindow,
      rotationLabel: rotationLabel,
      dualStatusLabel: dualStatus.label,
      dualStatusHealthy: dualStatus.healthy,
      warnings: warnings,
      backendRoots: backendStatuses
    )
  }

  static func unavailable(message: String) -> PosManifestStatus {
    return PosManifestStatus(
      manifestId: "unavailable",
      sequence: -1,
      operatorId: "n/a",
      validWindowLabel: "n/a",
      rotationLabel: "n/a",
      dualStatusLabel: message,
      dualStatusHealthy: false,
      warnings: [message],
      backendRoots: []
    )
  }

  private struct DualStatus {
    let healthy: Bool
    let label: String
  }

  private static func backendStatusLabel(root: PosBackendRoot, active: Bool, formatter: ISO8601DateFormatter, now: Date) -> String {
    let expiresIn = root.validUntilMs.date.timeIntervalSince(now)
    let expiresLabel: String
    if expiresIn > 0 {
      expiresLabel = "expires \(formatDuration(milliseconds: expiresIn * 1000))"
    } else {
      expiresLabel = "expired \(formatter.string(from: root.validUntilMs.date))"
    }
    let window = "\(formatter.string(from: root.validFromMs.date)) – \(formatter.string(from: root.validUntilMs.date))"
    return "\(active ? "active" : "inactive") · \(window) (\(expiresLabel))"
  }

  private static func computeDualStatus(roots: [BackendRootStatus], manifest: PosProvisionManifest, now: Date) -> DualStatus {
    let activeRoles = Set(roots.filter(\.active).map { $0.role })
    // These roles match the shared signed fixture and the Android retail-wallet sample.
    let required: Set<String> = ["release_signer", "device_attestation_ca"]
    let missing = required.subtracting(activeRoles)
    if missing.isEmpty {
      let remaining = manifest.validUntilMs.date.timeIntervalSince(now)
      return DualStatus(healthy: true, label: "required trust roots active for \(formatDuration(milliseconds: remaining * 1000))")
    }
    return DualStatus(healthy: false, label: "missing \(missing.joined(separator: ", "))")
  }

  private static func computeWarnings(
    manifest: PosProvisionManifest,
    roots: [BackendRootStatus],
    dualStatus: DualStatus,
    now: Date,
    formatter: ISO8601DateFormatter
  ) -> [String] {
    var warnings: [String] = []
    if now < manifest.validFromMs.date {
      warnings.append("manifest not active until \(formatter.string(from: manifest.validFromMs.date))")
    }
    let manifestExpires = manifest.validUntilMs.date.timeIntervalSince(now)
    if manifestExpires <= PosManifestLoader.manifestWarningWindow {
      warnings.append("manifest expires in \(formatDuration(milliseconds: manifestExpires * 1000))")
    }
    if let hint = manifest.rotationHintMs {
      let delta = hint.date.timeIntervalSince(now)
      if delta <= 0 {
        warnings.append("rotation hint passed \(formatDuration(milliseconds: -delta * 1000)) ago")
      } else if delta <= PosManifestLoader.rotationWarningWindow {
        warnings.append("rotation hint in \(formatDuration(milliseconds: delta * 1000))")
      }
    }
    roots.filter { !$0.active }.forEach { root in
      warnings.append("\(root.label) inactive")
    }
    if !dualStatus.healthy {
      warnings.append(dualStatus.label)
    }
    return warnings
  }

  private static func formatDuration(milliseconds: Double) -> String {
    if milliseconds <= 0 {
      return "0s"
    }
    var seconds = Int(milliseconds / 1000)
    let days = seconds / (24 * 3600)
    seconds %= 24 * 3600
    let hours = seconds / 3600
    seconds %= 3600
    let minutes = seconds / 60
    let parts = [
      days > 0 ? "\(days)d" : nil,
      hours > 0 ? "\(hours)h" : nil,
      minutes > 0 ? "\(minutes)m" : nil
    ].compactMap { $0 }
    if parts.isEmpty {
      return "\(Int(milliseconds / 1000))s"
    }
    return parts.joined(separator: " ")
  }
}

enum PosManifestLoader {
  static let manifestWarningWindow: TimeInterval = 7 * 24 * 3600
  static let rotationWarningWindow: TimeInterval = 3 * 24 * 3600

  private struct Envelope: Decodable {
    let payload_base64: String
    let operator_signature: String
  }

  static func loadManifest(bundle: Bundle = .main) throws -> PosProvisionManifest {
    guard let url = bundle.url(forResource: "manifest_v1", withExtension: "json") else {
      throw invalid("manifest_v1.json missing from bundle")
    }
    return try parse(data: Data(contentsOf: url))
  }

  static func parse(data: Data) throws -> PosProvisionManifest {
    guard data.count <= 65_536 else { throw invalid("manifest exceeds its byte bound") }
    let decoder = JSONDecoder()
    let envelope = try decoder.decode(Envelope.self, from: data)
    guard envelope.operator_signature.count == 128,
          envelope.operator_signature.utf8.allSatisfy({
            (48...57).contains($0) || (97...102).contains($0)
          }),
          let signature = Data(hexString: envelope.operator_signature),
          let payload = Data(base64Encoded: envelope.payload_base64),
          payload.base64EncodedString() == envelope.payload_base64 else {
      throw invalid("manifest signature or payload encoding is not canonical")
    }
    // The two-field envelope has one exact ASCII encoding. This also rejects
    // duplicate keys and unsigned copies of any signed manifest field.
    let canonicalEnvelope = "{\"operator_signature\":\"\(envelope.operator_signature)\",\"payload_base64\":\"\(envelope.payload_base64)\"}\n"
    guard data == Data(canonicalEnvelope.utf8) else {
      throw invalid("manifest envelope is not canonical")
    }
    let manifest = try decoder.decode(PosProvisionManifest.self, from: payload)
    let encoder = NoritoJSON.makeEncoder()
    encoder.outputFormatting.insert(.withoutEscapingSlashes)
    // Only the typed, canonically encoded signed payload supplies display state.
    // A roundtrip rejects unknown/duplicate fields and non-integral number tokens.
    guard try encoder.encode(manifest) == payload,
          manifest.schema == "iroha.example.pos-manifest.v1",
          manifest.sequence >= 0,
          [manifest.publishedAtMs, manifest.validFromMs, manifest.validUntilMs]
            .allSatisfy({ $0 <= UInt64(Int64.max) }),
          manifest.rotationHintMs.map({ $0 <= UInt64(Int64.max) }) ?? true,
          manifest.backendRoots.allSatisfy({
            $0.validFromMs <= UInt64(Int64.max) && $0.validUntilMs <= UInt64(Int64.max)
          }) else {
      throw invalid("manifest signed payload is not canonical")
    }
    let account = try AccountAddress.fromI105(manifest.operatorId, expectedPrefix: nil)
    let canonical = try account.canonicalBytes()
    // Native account admission owns the address layout. This example requires
    // its fixed V1 single Ed25519 controller, never a raw-key or multisig alias.
    guard canonical.count == 36,
          canonical.prefix(4) == Data([0x02, 0x00, 0x01, 0x20]) else {
      throw invalid("manifest operator requires a canonical single Ed25519 account")
    }
    let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: canonical.dropFirst(4))
    guard publicKey.isValidSignature(signature, for: payload) else {
      throw invalid("manifest signature verification failed")
    }
    return manifest
  }

  private static func invalid(_ message: String) -> NSError {
    NSError(domain: "PosManifestLoader", code: 1,
            userInfo: [NSLocalizedDescriptionKey: message])
  }
}

private extension UInt64 {
  var date: Date { Date(timeIntervalSince1970: TimeInterval(self) / 1000.0) }
}
