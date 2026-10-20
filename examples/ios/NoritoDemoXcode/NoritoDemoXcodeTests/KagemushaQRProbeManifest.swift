// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
import Foundation

/// Canonical closed QR controller selection. Optical peer data has no mailbox input.
enum KagemushaQRProbeManifest {
  static let schemas: [String: [Set<String>]] = [
    "qr-send": [["setup-id", "request-id"]],
    "qr-receive": [["setup-id", "request-id", "amount"],
      ["setup-id", "request-id", "amount", "fee-schedule", "fee-certificate"]],
    "qr-recover-send": [["setup-id", "request-id"]],
    "qr-recover-receive": [["setup-id", "request-id"]],
  ]
  static func accepts(_ action: String, names: Set<String>) -> Bool {
    schemas[action]?.contains(names) == true
  }
}
