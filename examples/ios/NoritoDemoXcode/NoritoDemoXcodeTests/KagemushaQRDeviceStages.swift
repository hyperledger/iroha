// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
#if os(iOS) && !targetEnvironment(macCatalyst)
import Foundation
import IrohaSwift
import UIKit

extension KagemushaEnrollmentDeviceActor {
  func executeQR(_ command: Command, inputs: [String: Data], sequence: Int) async throws -> String {
    guard !carrierBusy, nearbyRun == nil, qrRun == nil, pendingReview == nil, timeExchange == nil,
      let setup = inputs["setup-id"], let request = inputs["request-id"] else {
      throw EnrollmentProbeFailure.lifecycle
    }
    let setupID = try KagemushaMonetaryProbeManifest.word(setup)
    let requestID = try KagemushaMonetaryProbeManifest.word(request)
    let wallet = try walletOwner()
    // Reserve before suspending; every actor entry/release path sees the same carrier owner.
    carrierBusy = true
    defer { qrRun = nil; carrierBusy = false }
    let pair = try await MainActor.run { () throws -> (KagemushaQRPlatform, KagemushaNearbyPrompt) in
      let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        .filter { $0.activationState == .foregroundActive }
      guard scenes.count == 1,
        let root = scenes[0].windows.first(where: { $0.isKeyWindow })?.rootViewController,
        root.presentedViewController == nil else { throw EnrollmentProbeFailure.lifecycle }
      let ui = KagemushaQRPlatform()
      try ui.arm(in: scenes[0])
      ui.modalPresentationStyle = .fullScreen
      root.present(ui, animated: false)
      return (ui, KagemushaNearbyPrompt(presenter: ui))
    }
    let sender = command.action.hasSuffix("send")
    let runner = KagemushaQRDiagnostic(selection: .init(sender: sender,
      recovery: command.action.contains("recover"), setupID: setupID, requestID: requestID, inputs: inputs),
      wallet: wallet, files: config.files, actorPath: config.actorPath,
      attemptPath: config.actorPath + "/public/" + config.invocation + String(format: "/%04d-qr", sequence),
      ui: pair.0, prompt: pair.1)
    qrRun = runner
    await MainActor.run { pair.0.cancelled = { runner.cancel() } }
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
        runner.run { continuation.resume(with: $0) }
      }
    } onCancel: { runner.cancel() }
    return sender ? "native-exact-send-delivery-admitted-over-qr"
      : "native-durable-receive-credited-display-closed-over-qr"
  }
}
#endif
