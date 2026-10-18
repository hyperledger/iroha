// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
import CryptoKit
import Foundation
import IrohaSwift
import LocalAuthentication
import UIKit

/// Explicit diagnostic display plus fresh system authentication; no trusted-display claim.
@MainActor final class KagemushaNearbyPrompt {
  weak var presenter: UIViewController?
  private weak var alert: UIAlertController?
  private var authentication: LAContext?
  private var authenticationGate = KagemushaNearbyAuthenticationGate()
  init(presenter: UIViewController) { self.presenter = presenter }

  private func choice(title: String, message: String, accept: String,
                      completion: @escaping (Bool) -> Void) {
    guard let presenter, presenter.viewIfLoaded?.window != nil,
      presenter.presentedViewController == nil else { completion(false); return }
    let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
    alert.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in completion(false) })
    alert.addAction(UIAlertAction(title: accept, style: .default) { _ in completion(true) })
    self.alert = alert
    presenter.present(alert, animated: true)
  }
  func cancel() {
    authenticationGate.cancel()
    alert?.dismiss(animated: false)
    authentication?.invalidate()
    authentication = nil
  }
  func pairing(code: String, peer: String, certificate: String, session: String, decision: @escaping (Bool) -> Void) {
    choice(title: "Compare Nearby pairing code", message: "Peer: \(peer)\nCode: \(code)\nPinned identity: \(certificate)\nSession: \(session)\nConfirm only if the selected other phone shows the same code.",
      accept: "Codes match", completion: decision)
  }
  func review(_ projection: KagemushaWalletReviewProjectionV1,
              completion: @escaping (Result<UInt64, Error>) -> Void) {
    let hex = { (data: Data) in data.map { String(format: "%02x", $0) }.joined() }
    let scalar = { (v: KagemushaWalletUInt128V1) in "high=\(v.high), low=\(v.low)" }
    // Keep the whole exact Native projection visible; no locally reconstructed review token.
    let text = "Amount: \(scalar(projection.amount))\nFee: \(scalar(projection.fee))\nGross: \(scalar(projection.grossDebit))\nNet: \(scalar(projection.netDestinationAmount))\nDestination original: \(hex(projection.destinationAccountOriginal ?? Data()))\nRequest: \(hex(projection.requestDigest))\nNative review bytes: \(hex(projection.bytes))"
    choice(title: "Disposable KAGEMUSHA Send", message: text, accept: "Confirm this Send") { [self] accepted in
      guard accepted else { completion(.failure(KagemushaNearbyAttemptGate.Failure.order)); return }
      let authenticationID = UUID()
      guard self.authenticationGate.begin(authenticationID) else {
        completion(.failure(KagemushaNearbyAttemptGate.Failure.order)); return
      }
      let context = LAContext()
      self.authentication = context
      context.touchIDAuthenticationAllowableReuseDuration = 0
      context.evaluatePolicy(.deviceOwnerAuthentication,
        localizedReason: "Confirm the displayed disposable KAGEMUSHA Send") { [weak self] authenticated, error in
        // Capture the actual OS callback clock before scheduling main-actor cleanup.
        let confirmedAt = KagemushaNearbyClock.nowNanoseconds()
        let outcome: Result<UInt64, Error> = authenticated
          ? .success(confirmedAt)
          : .failure(error ?? KagemushaNearbyAttemptGate.Failure.order)
        Task { @MainActor [weak self] in
          guard let self, self.authenticationGate.finish(authenticationID) else {
            completion(.failure(KagemushaNearbyAttemptGate.Failure.order)); return
          }
          // LAContext never crosses the callback's Sendable boundary. This token still
          // owns the stored context, so an older callback cannot invalidate a new one.
          self.authentication?.invalidate()
          self.authentication = nil
          completion(outcome)
        }
      }
    }
  }
}
