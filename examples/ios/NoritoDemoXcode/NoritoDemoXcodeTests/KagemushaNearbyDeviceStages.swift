// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
import Foundation
import IrohaSwift
import UIKit

#if os(iOS) && !targetEnvironment(macCatalyst)
extension KagemushaEnrollmentDeviceActor {
  func executeNearby(_ command: Command, inputs: [String: Data], sequence: Int) async throws -> String {
    guard !carrierBusy, nearbyRun == nil, qrRun == nil, pendingReview == nil, timeExchange == nil else { throw EnrollmentProbeFailure.lifecycle }
    // Reserve before the first suspension; actor reentrancy must not share this Native owner.
    carrierBusy = true
    defer { nearbyRun = nil; carrierBusy = false }
    func input(_ name: String) throws -> Data {
      guard let value = inputs[name] else { throw EnrollmentProbeFailure.input }; return value
    }
    func word(_ name: String, size: Int = 32) throws -> Data {
      let value = try input(name)
      guard value.count == size, value.contains(where: { $0 != 0 }) else { throw EnrollmentProbeFailure.input }
      return value
    }
    if command.action == "nearby-identity" {
      try output("nearby-certificate.bin", nearbyIdentity.publicBytes, sequence: sequence)
      return "engineering-transport-identity-exported"
    }
    let wallet = try walletOwner()
    let directory = config.actorPath + "/private/nearby"
    try config.files.mkdir(directory)
    if command.action == "nearby-prepare" {
      let id = try word("setup-id"), offer = try input("offer")
      try bind("setup", id: id, inputs: inputs.merging(["family": Data("request".utf8)]) { first, _ in first })
      let path = directory + "/setup-" + EnrollmentProbeFiles.digest(id)
      try config.files.publish(path + "-binding", bytes: KagemushaMonetaryProbeManifest.binding("nearby-prepare", inputs: inputs))
      let raw = try KagemushaNearbyDiagnostic.prepare(wallet: wallet, setupID: id, offer: offer,
        feeSchedule: inputs["fee-schedule"], feeCertificate: inputs["fee-certificate"])
      let message = try IrohaPeerWireMessageV1.decode(raw, expectedProfile: .kagemushaWalletV1, expectedKind: .request)
      try config.files.publish(path + "-request", bytes: raw)
      try config.files.publish(path + "-offer", bytes: offer)
      try output("nearby-request-ipm1.bin", raw, sequence: sequence)
      try output("nearby-request-hash.bin", message.canonicalHash, sequence: sequence)
      return "native-request-ready-for-nearby"
    }
    let sender = command.action.hasSuffix("send")
    let recovery = command.action.contains("recover")
    let requestID = try word("request-id"), sessionID = try word("session-id", size: 16)
    let requestHash = try word("request-hash"), peer = try word("peer-certificate")
    var request: Data?, offer: Data?
    if !sender {
      let path = directory + "/setup-" + EnrollmentProbeFiles.digest(try word("setup-id"))
      request = try config.files.read(path + "-request", maximum: 32_768)
      offer = try config.files.read(path + "-offer", maximum: 10_000)
    }
    let prompt = try await MainActor.run { () throws -> KagemushaNearbyPrompt in
      let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        .filter { $0.activationState == .foregroundActive }
      guard scenes.count == 1, let presenter = scenes[0].windows.first(where: { $0.isKeyWindow })?.rootViewController
      else { throw EnrollmentProbeFailure.lifecycle }
      return KagemushaNearbyPrompt(presenter: presenter)
    }
    let attemptPath = config.actorPath + "/public/" + config.invocation
      + String(format: "/%04d-nearby", sequence)
    let runner = try KagemushaNearbyDiagnostic(selection: .init(role: sender ? .sender : .receiver,
      recovery: recovery, requestID: requestID, sessionID: sessionID, requestHash: requestHash,
      peerIdentity: peer, requestMessage: request, offer: offer), wallet: wallet,
      identity: nearbyIdentity, files: config.files, actorPath: config.actorPath,
      attemptPath: attemptPath, prompt: prompt)
    nearbyRun = runner
    // Cancellation only requests worker teardown. Await its completion before releasing ownership.
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
        runner.run { result in continuation.resume(with: result) }
      }
    } onCancel: {
      runner.cancel()
    }
    return sender ? "native-exact-send-delivery-admitted-over-nearby"
      : "native-durable-receive-acknowledged-over-nearby"
  }
}
#endif
