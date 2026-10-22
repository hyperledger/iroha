// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
import Foundation

@testable import IrohaSwift

/// Closed test mailbox inputs. These are not protocol encoders or monetary authority.
enum KagemushaMonetaryProbeManifest {
  // Optional bundles are represented as separate complete input sets; partial bundles fail.
  static let schemas: [String: [Set<String>]] = [
    "nearby-identity": [[]],
    "nearby-prepare": [["setup-id", "offer"], ["setup-id", "offer", "fee-schedule", "fee-certificate"]],
    "nearby-send": [["request-id", "session-id", "request-hash", "peer-certificate"]], "nearby-recover-send": [["request-id", "session-id", "request-hash", "peer-certificate"]],
    "nearby-receive": [["request-id", "session-id", "request-hash", "peer-certificate", "setup-id"]], "nearby-recover-receive": [["request-id", "session-id", "request-hash", "peer-certificate", "setup-id"]],
    "open": [["result"]], "release-wallet": [[]], "bootstrap": [[]], "activation": [[]],
    "retain-activation": [["signed-wire"]], "activation-status": [["signed-wire"]],
    "activation-finality": [["signed-wire", "finality"]],
    "prepare-load": [["request-id", "amount"]], "prepared-load": [["request-id"]],
    "load": [["request-id", "receipt", "finality"]], "ledger-finality": [["finality"]],
    "ledger-status": [[]], "epoch-boundary": [["epoch", "boundary"]], "epoch-status": [[]],
    "offer": [["setup-id", "amount"]],
    "request": [["setup-id", "offer"], ["setup-id", "offer", "fee-schedule", "fee-certificate"]],
    "review-send": [["request-id", "request", "destination"]],
    "review-unload": [
      ["request-id", "amount"], ["request-id", "amount", "quote", "certificates", "beneficiary"],
    ],
    "decide-review": [["decision"]], "receive": [["request-id", "payment", "offer"]],
    "credit": [["request-id"]], "accept-credited": [["request-id", "credited"]],
    "credited-status": [["request-id", "credited"]], "fold-once": [[]], "fold-status": [[]],
    "snapshot": [[]], "request-status": [["request-id"]], "retry": [["operation-id"]],
    "resume": [[]], "released-request": [["request-id"]], "released-operation": [["operation-id"]],
    "unload-claim": [["request-id"], ["request-id", "beneficiary"]],
    "unload-status": [["claim", "signed-wire"]],
    "unload-finality": [["claim", "signed-wire", "finality"]],
    "decode-offer": [["envelope"]], "decode-request": [["envelope"]],
    "decode-payment": [["envelope"]], "decode-credited": [["envelope"]],
    "refresh-time": [["request-id", "anchor", "certificates"]],
    "begin-time": [[]], "finish-time": [["anchor", "certificate"]], "cancel-time": [[]],
  ].merging(KagemushaQRProbeManifest.schemas) { _, _ in preconditionFailure("duplicate probe command") }
  static var actions: Set<String> { Set(schemas.keys) }
  static func validate(_ action: String, names: Set<String>) throws {
    if action.hasPrefix("qr-") {
      guard KagemushaQRProbeManifest.accepts(action, names: names) else { throw EnrollmentProbeFailure.input }
      return
    }
    guard schemas[action]?.contains(names) == true else { throw EnrollmentProbeFailure.input }
  }
  static func maximum(_ name: String) throws -> Int {
    switch name {
    case "request-id", "setup-id", "operation-id", "request-hash", "peer-certificate": return 32
    case "session-id": return 16
    case "amount": return 16
    case "epoch": return 8
    case "result": return KagemushaWalletEnrollmentV1.RESULT_MAX_BYTES
    case "finality": return 36 * 1024 * 1024
    case "boundary": return 256 * 1024
    case "signed-wire", "claim": return 65_536
    case "receipt", "fee-certificate", "anchor", "certificate": return 512
    case "fee-schedule", "quote": return 1024
    case "destination", "beneficiary": return 4096
    case "offer", "request", "payment", "credited", "certificates", "envelope": return 10_000
    case "decision": return 4096
    default: throw EnrollmentProbeFailure.input
    }
  }
  static func word(_ data: Data) throws -> Data {
    guard data.count == 32, data.contains(where: { $0 != 0 }) else {
      throw EnrollmentProbeFailure.input
    }
    return data
  }
  static func limb(_ data: Data) throws -> UInt64 {
    guard data.count == 8 else { throw EnrollmentProbeFailure.input }
    return data.enumerated().reduce(UInt64(0)) { $0 | (UInt64($1.element) << (8 * $1.offset)) }
  }
  static func amount(_ data: Data) throws -> KagemushaWalletUInt128V1 {
    guard data.count == 16 else { throw EnrollmentProbeFailure.input }
    let value = try KagemushaWalletUInt128V1(
      low: limb(Data(data.prefix(8))), high: limb(Data(data.suffix(8))))
    guard value.low != 0 || value.high != 0 else { throw EnrollmentProbeFailure.input }
    return value
  }
  /// Immutable intent identity is content-based, never based on a mutable path or plist key order.
  static func binding(_ kind: String, inputs: [String: Data]) -> Data {
    Data(
      ([kind] + inputs.keys.sorted().map { $0 + ":" + EnrollmentProbeFiles.digest(inputs[$0]!) })
        .joined(separator: "\n").utf8)
  }
  struct Decision {
    let confirmed: Bool
    init(_ bytes: Data, invocation: String, sequence: Int, projection: Data) throws {
      guard
        let row = try PropertyListSerialization.propertyList(from: bytes, format: nil)
          as? [String: Any],
        Set(row.keys) == ["decision", "invocation", "reviewSequence", "reviewSHA256"],
        let choice = row["decision"] as? String, ["confirm", "cancel"].contains(choice),
        row["invocation"] as? String == invocation,
        row["reviewSequence"] as? Int == sequence,
        row["reviewSHA256"] as? String == EnrollmentProbeFiles.digest(projection)
      else { throw EnrollmentProbeFailure.input }
      confirmed = choice == "confirm"
    }
  }
}

/// Portable test-controller observation. This is DATA, never a protocol attestation or finality.
enum KagemushaActivationRetentionProbe {
  static func receipt(
    signedWire: Data, outcome: KagemushaWalletLedgerOutcomeV1, returned: UInt64,
    invocation: String, sequence: Int
  ) throws -> Data? {
    guard !signedWire.isEmpty, signedWire.count <= 65_536, returned > 0,
      (0..<10_000).contains(sequence),
      UUID(uuidString: invocation)?.uuidString == invocation
    else { throw EnrollmentProbeFailure.input }
    // Only the initial Awaiting result, with Native's derived entrypoint, authorizes submission.
    guard case .awaiting(let entrypoint) = outcome else { return nil }
    return try NoritoJSON([
      "schema": "iroha.kagemusha.wallet-activation-retained.v1",
      "action": "retain-activation", "signedWireSHA256": EnrollmentProbeFiles.digest(signedWire),
      "signedWireBytes": String(signedWire.count), "nativeResult": "awaiting",
      "entrypointHex": entrypoint.map { String(format: "%02x", $0) }.joined(),
      "nativeReturnedTicks": String(returned), "invocation": invocation,
      "sequence": String(sequence),
    ]).data
  }
}

/// Closed diagnostics only; never export arbitrary error descriptions or underlying userInfo.
enum EnrollmentProbeFailureMetadata {
  static func fields(_ error: Error) -> [String: Any] {
    if let error = error as? EnrollmentProbeFailure {
      let name: String
      switch error {
      case .input: name = "input"
      case .custody: name = "custody"
      case .collision: name = "collision"
      case .timeout: name = "timeout"
      case .lifecycle: name = "lifecycle"
      case .commandFailures: name = "commandFailures"
      }
      return ["harnessFailure": name]
    }
    if let error = error as? KagemushaWalletAppleEnrollmentAttestationErrorV1 {
      switch error {
      case .invalidDigest: return ["attestationFailure": "invalidDigest"]
      case .appAttestUnsupported: return ["attestationFailure": "appAttestUnsupported"]
      case .paymentKeyAbsent: return ["attestationFailure": "paymentKeyAbsent"]
      case .bindingMismatch: return ["attestationFailure": "bindingMismatch"]
      case .malformedAppAttestKeyID: return ["attestationFailure": "malformedAppAttestKeyID"]
      case .appAttestFailed(let stage, let domain, let code):
        let safe =
          domain.count <= 128
          && domain.utf8.allSatisfy {
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0)
              || [45, 46, 95].contains($0)
          }
        return [
          "attestationFailure": "appAttestFailed", "attestationStage": stage.rawValue,
          "attestationDomain": safe ? domain : "unrecognized-domain", "attestationCode": code,
        ]
      case .paymentKeyUnavailable(let cause):
        switch cause {
        case .locked:
          return ["attestationFailure": "paymentKeyUnavailable", "keyFailure": "locked"]
        case .beforeFirstUnlock:
          return ["attestationFailure": "paymentKeyUnavailable", "keyFailure": "beforeFirstUnlock"]
        case .keyUnusable:
          return ["attestationFailure": "paymentKeyUnavailable", "keyFailure": "keyUnusable"]
        case .io(let code):
          return [
            "attestationFailure": "paymentKeyUnavailable", "keyFailure": "io", "keyCode": code,
          ]
        case .platform(let code):
          return [
            "attestationFailure": "paymentKeyUnavailable", "keyFailure": "platform",
            "keyCode": code,
          ]
        }
      }
    }
    let ns = error as NSError
    if ns.domain == "com.apple.LocalAuthentication" || ns.domain == "LAErrorDomain" {
      return ["confirmationFailure": "localAuthentication", "confirmationCode": ns.code]
    }
    return [:]
  }
}
