// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
import Darwin
import Foundation
import LocalAuthentication

@testable import IrohaSwift

#if os(iOS) && !targetEnvironment(macCatalyst)
  struct KagemushaProbePendingReview {
    let review: KagemushaWalletReviewV1
    let requestID: Data
    let sequence: Int
  }

  extension KagemushaEnrollmentDeviceActor {
    func walletOwner() throws -> KagemushaWalletV1 {
      guard !closed, let wallet else { throw EnrollmentProbeFailure.lifecycle }
      return wallet
    }
    func releaseWallet() throws {
      guard !nearbyBusy else { throw EnrollmentProbeFailure.lifecycle }
      if let wallet {
        // close owns the entire Native review/exchange lifetime. On failure retain the owner.
        try wallet.close()
        self.wallet = nil
        pendingReview = nil
        timeExchange = nil
      }
    }
    func monetaryInputs(_ command: Command, sequence: Int) throws -> [String: Data] {
      try KagemushaMonetaryProbeManifest.validate(command.action, names: Set(command.inputs.keys))
      var originals: [String: Data] = [:]
      for name in command.inputs.keys.sorted() {
        let pin = command.inputs[name]!
        guard pin.path.hasPrefix("inbox/" + config.invocation + "/") else {
          throw EnrollmentProbeFailure.input
        }
        let bytes = try config.files.pinned(
          pin, maximum: KagemushaMonetaryProbeManifest.maximum(name))
        guard !bytes.isEmpty else { throw EnrollmentProbeFailure.input }
        try config.files.publish(
          config.actorPath + "/private/" + config.invocation + "/"
            + String(format: "%04d", sequence) + "-" + name, bytes: bytes)
        originals[name] = bytes
      }
      return originals
    }
    /// Host intent retention is only an audit guard. Native remains the sole recovery authority.
    func bind(_ kind: String, id: Data, inputs: [String: Data]) throws {
      let directory = config.actorPath + "/private/intents"
      try config.files.mkdir(directory)
      try config.files.publish(
        directory + "/" + kind + "-" + EnrollmentProbeFiles.digest(id),
        bytes: KagemushaMonetaryProbeManifest.binding(kind, inputs: inputs))
    }
    func event(_ name: String, values: [String: Any], sequence: Int) throws {
      try output(name + ".plist", EnrollmentProbeFiles.encode(values), sequence: sequence)
    }
    func scalar(_ value: KagemushaWalletUInt128V1) -> [String: String] {
      ["low": String(value.low), "high": String(value.high)]
    }
    func call(_ value: KagemushaWalletCallV1, returned: UInt64, sequence: Int) throws -> String {
      try output("native-call.bin", value.bytes, sequence: sequence)
      try event(
        "native-call",
        values: [
          "status": value.status, "sequenceLow": String(value.sequenceLow),
          "sequenceHigh": String(value.sequenceHigh), "detail": value.detail,
          "nativeReturnedTicks": returned,
          "originalSHA256": EnrollmentProbeFiles.digest(value.bytes),
        ], sequence: sequence)
      // Preserve every native status, including pending/preparing/unknown/delivery-loss.
      return "native-call-status-" + String(value.status)
    }
    func released(_ value: KagemushaWalletReleasedOutputV1, observed: UInt64, sequence: Int) throws
      -> String
    {
      try output("released-original.norito", value.original, sequence: sequence)
      try output("operation-id.bin", value.operationID, sequence: sequence)
      if let kind = value.peerKind, let original = value.peerOriginal {
        try output("peer-original.norito", original, sequence: sequence)
        try output(
          "peer-envelope.norito", walletOwner().envelope(kind, original: original),
          sequence: sequence)
      }
      try event(
        "released",
        values: [
          "kind": value.kind.rawValue, "operationID": value.operationID,
          "sequence": scalar(value.sequence), "durableCompletionObservedTicks": observed,
          "originalSHA256": EnrollmentProbeFiles.digest(value.original),
          "carrierDeliveryClaimed": false,
        ], sequence: sequence)
      switch value.kind {
      case .load: return "native-complete-load"
      case .send: return "native-complete-send"
      case .receive: return "native-complete-receive"
      default: return "native-released-kind-" + String(value.kind.rawValue)
      }
    }
    func completion(
      _ value: KagemushaWalletCallV1, returned: UInt64, requestID: Data, sequence: Int
    ) throws -> String {
      let status = try call(value, returned: returned, sequence: sequence)
      guard value.status == 1 else { return status }
      let original = try walletOwner().releasedOutput(requestId: requestID)
      // `returned` marks this call returning a native durable completion; recovered observations
      // are explicitly labelled as observations, not the historical commit's unknown time.
      try event(
        "durable-call-return",
        values: [
          "nativeReturnedTicks": returned, "requestID": requestID,
          "operationID": original.operationID,
        ], sequence: sequence)
      return try released(original, observed: mach_continuous_time(), sequence: sequence)
    }
    func activationState(
      _ value: KagemushaWalletActivationFinalityV1, returned: UInt64, sequence: Int
    ) throws -> String {
      var row: [String: Any] = [
        "nativeReturnedTicks": returned, "confirmed": value.confirmation != nil,
        "rejected": value.rejected,
      ]
      if let height = value.verifiedHeight { row["height"] = String(height) }
      if let hash = value.blockHash { row["blockHash"] = hash }
      try event("activation-state", values: row, sequence: sequence)
      return value.confirmation != nil
        ? "native-activation-confirmed"
        : (value.rejected ? "native-activation-rejected" : "native-activation-unconfirmed")
    }
    func ledgerState(_ value: KagemushaWalletLedgerProgressV1?, returned: UInt64, sequence: Int)
      throws
    {
      var row: [String: Any] = ["nativeReturnedTicks": returned, "present": value != nil]
      if let value {
        row["height"] = String(value.height)
        row["blockHash"] = value.blockHash
      }
      try event("ledger-progress", values: row, sequence: sequence)
    }
    func recordSnapshot(sequence: Int) throws -> String {
      let snapshot = try walletOwner().snapshot()
      let observed = mach_continuous_time()
      var row: [String: Any] = [
        "observedTicks": observed, "head": snapshot.head, "sequence": scalar(snapshot.sequence),
        "credentialDigest": snapshot.credentialDigest,
        "ownedBalance": scalar(snapshot.ownedBalance),
        "knownBurnedTotal": scalar(snapshot.knownBurnedTotal),
        "backlog": scalar(snapshot.foldBacklog), "headIsFolded": snapshot.headIsFolded,
        "lifecycle": snapshot.lifecycle.rawValue, "operationPermissionClaimed": false,
      ]
      if let amount = snapshot.foldedBalance {
        row["foldedBalance"] = scalar(amount)
        row["currentHeadFoldReadyObservedTicks"] = observed
      }
      try event("snapshot", values: row, sequence: sequence)
      return snapshot.headIsFolded
        ? "native-current-head-fold-ready-observed" : "native-fold-backlog-observed"
    }
    /// The account signer supplies an exact signature only after seeing this Native challenge.
    /// No private account key enters this process, its configuration or XCTest attachments.
    func awaitOpenSignature(_ challenge: Data, sequence: Int) async throws -> Data {
      let challenge = try KagemushaMonetaryProbeManifest.word(challenge)
      try output("open-account-challenge.bin", challenge, sequence: sequence)
      try event(
        "open-challenge",
        values: [
          "nativeChallengeObservedTicks": mach_continuous_time(),
          "challengeSHA256": EnrollmentProbeFiles.digest(challenge),
        ], sequence: sequence)
      let base =
        "inbox/" + config.invocation + "/" + String(format: "%04d", sequence) + "-open-signature"
      var timebase = mach_timebase_info_data_t()
      guard mach_timebase_info(&timebase) == KERN_SUCCESS, timebase.denom > 0 else {
        throw EnrollmentProbeFailure.lifecycle
      }
      let clock = EnrollmentProbeClock(
        numerator: UInt64(timebase.numer), denominator: UInt64(timebase.denom))
      let started = mach_continuous_time()
      let deadline = EnrollmentProbeDeadline(
        clock: clock, started: started, duration: 120_000_000_000, now: mach_continuous_time)
      var ready: String? = nil
      while ready == nil {
        ready = try deadline.select { try config.files.readyDigest(base + ".ready") }
        if ready == nil { try await Task.sleep(nanoseconds: 200_000_000) }
      }
      let bytes = try config.files.read(base + ".plist", maximum: 4096)
      guard
        ready == EnrollmentProbeFiles.digest(bytes),
        let row = try PropertyListSerialization.propertyList(from: bytes, format: nil)
          as? [String: Any],
        Set(row.keys) == ["challengeSHA256", "signature"],
        row["challengeSHA256"] as? String == EnrollmentProbeFiles.digest(challenge)
      else { throw EnrollmentProbeFailure.input }
      let pin = try EnrollmentProbePin(row["signature"]!)
      guard pin.path.hasPrefix("inbox/" + config.invocation + "/") else {
        throw EnrollmentProbeFailure.input
      }
      let signature = try config.files.pinned(pin, maximum: 64)
      guard signature.count == 64 else { throw EnrollmentProbeFailure.input }
      let retained =
        config.actorPath + "/private/" + config.invocation + "/" + String(format: "%04d", sequence)
      try config.files.publish(retained + "-open-signature.plist", bytes: bytes)
      try config.files.publish(retained + "-open-signature.bin", bytes: signature)
      try deadline.check()
      return signature
    }

    func executeMonetary(_ command: Command, sequence: Int) async throws -> String {
      let inputs = try monetaryInputs(command, sequence: sequence)
      if command.action.hasPrefix("nearby-") {
        return try await executeNearby(command, inputs: inputs, sequence: sequence)
      }
      func input(_ name: String) throws -> Data {
        guard let value = inputs[name] else { throw EnrollmentProbeFailure.input }
        return value
      }
      func id(_ name: String = "request-id") throws -> Data {
        try KagemushaMonetaryProbeManifest.word(input(name))
      }
      if command.action == "release-wallet" {
        guard wallet != nil else { throw EnrollmentProbeFailure.lifecycle }
        try releaseWallet()
        return "wallet-released-custody-retained"
      }
      if command.action == "open" {
        guard wallet == nil, pendingReview == nil else { throw EnrollmentProbeFailure.lifecycle }
        let result = try input("result")
        try bind("open", id: config.account, inputs: ["result": result, "account": config.account])
        if let enrollment {
          guard try enrollment.retainedResult() == result else {
            throw EnrollmentProbeFailure.collision
          }
          installed = try enrollment.loadInstalledRuntime()
          self.enrollment = nil
        }
        guard let installed else { throw EnrollmentProbeFailure.lifecycle }
        wallet = try await installed.openEnrolledResult(
          resultOriginal: result, accountOriginal: config.account,
          signExistingAccount: { challenge in
            try await self.awaitOpenSignature(challenge, sequence: sequence)
          },
          requireCurrent: { try Task.checkCancellation() })
        let opened = mach_continuous_time()
        self.installed = nil
        let metadata = try walletOwner().metadata()
        guard metadata.accountOriginal == config.account else {
          throw EnrollmentProbeFailure.collision
        }
        try event(
          "opened",
          values: [
            "nativeReturnedTicks": opened, "schemeID": metadata.schemeID,
            "walletID": metadata.walletID, "accountDigest": metadata.accountDigest,
            "assetDigest": metadata.assetDigest, "assetScale": metadata.assetScale,
          ], sequence: sequence)
        try output("native-account.norito", metadata.accountOriginal, sequence: sequence)
        try output("native-asset.norito", metadata.assetOriginal, sequence: sequence)
        return "native-wallet-opened"
      }
      let wallet = try walletOwner()
      switch command.action {
      case "bootstrap":
        let result = try wallet.bootstrap()
        let returned = mach_continuous_time()
        return try call(result, returned: returned, sequence: sequence)
      case "activation":
        let original = try wallet.activation()
        let returned = mach_continuous_time()
        try output("activation.norito", original, sequence: sequence)
        try output(
          "ledger-instruction.norito",
          wallet.ledgerInstruction(kind: .activate, original: original), sequence: sequence)
        try event(
          "activation-export", values: ["nativeReturnedTicks": returned, "confirmed": false],
          sequence: sequence)
        return "native-activation-exported-not-submitted"
      case "retain-activation", "activation-status", "activation-finality", "confirm-activation":
        let wire = try input("signed-wire")
        if command.action == "confirm-activation" {
          let value = try wallet.confirmLedgerActivation(signedWire: wire)
          let returned = mach_continuous_time()
          try event(
            "activation-confirmation",
            values: [
              "nativeReturnedTicks": returned, "height": String(value.height),
              "blockHash": value.blockHash,
            ], sequence: sequence)
          return "native-activation-confirmed"
        }
        let value: KagemushaWalletActivationFinalityV1
        switch command.action {
        case "retain-activation": value = try wallet.retainActivationAttempt(signedWire: wire)
        case "activation-finality":
          value = try wallet.ingestActivationFinality(signedWire: wire, original: input("finality"))
        default: value = try wallet.activationFinalityProgress(signedWire: wire)
        }
        let returned = mach_continuous_time()
        if command.action == "retain-activation",
          let receipt = try KagemushaActivationRetentionProbe.receipt(
            signedWire: wire, hasConfirmation: value.confirmation != nil, rejected: value.rejected,
            verifiedHeight: value.verifiedHeight, blockHash: value.blockHash, returned: returned,
            invocation: config.invocation, sequence: sequence)
        {
          // Only the actual Native return may produce this original, before any controller POST.
          try output("activation-retained.json", receipt, sequence: sequence)
        }
        return try activationState(value, returned: returned, sequence: sequence)
      case "prepare-load":
        let identity = try id()
        let amount = try KagemushaMonetaryProbeManifest.amount(input("amount"))
        try bind("load-plan", id: identity, inputs: inputs)
        let original = try wallet.prepareLedgerLoad(requestId: identity, amount: amount)
        let returned = mach_continuous_time()
        try output("ledger-load-instruction.norito", original, sequence: sequence)
        try event(
          "prepared-load",
          values: [
            "nativeReturnedTicks": returned, "requestID": identity, "settlementClaimed": false,
          ], sequence: sequence)
        return "native-load-plan-retained"
      case "prepared-load":
        let plan = try wallet.preparedLedgerLoad(requestId: id())
        let returned = mach_continuous_time()
        if let plan {
          try output("ledger-load-instruction.norito", plan.instructionOriginal, sequence: sequence)
          try event(
            "prepared-load",
            values: [
              "nativeReturnedTicks": returned, "requestID": plan.requestID,
              "ordinal": scalar(plan.ordinal), "amount": scalar(plan.amount),
            ], sequence: sequence)
        }
        return plan == nil ? "native-load-plan-absent" : "native-load-plan-retained"
      case "load":
        let identity = try id()
        try bind(
          "operation", id: identity,
          inputs: [
            "family": Data("load".utf8), "receipt": input("receipt"), "finality": input("finality"),
          ])
        let result = try wallet.load(
          requestId: identity, receipt: input("receipt"), finality: input("finality"))
        let returned = mach_continuous_time()
        return try completion(result, returned: returned, requestID: identity, sequence: sequence)
      case "ledger-finality", "ledger-status":
        let value =
          try command.action == "ledger-finality"
          ? wallet.ingestLedgerFinality(input("finality")) : wallet.ledgerProgress()
        try ledgerState(value, returned: mach_continuous_time(), sequence: sequence)
        return "native-ledger-prefix-observed"
      case "epoch-boundary", "epoch-status":
        let value =
          try command.action == "epoch-boundary"
          ? wallet.ingestEpochBoundary(
            expectedEpoch: KagemushaMonetaryProbeManifest.limb(input("epoch")),
            original: input("boundary")) : wallet.epochProgress()
        try event(
          "epoch",
          values: [
            "nativeReturnedTicks": mach_continuous_time(), "epoch": String(value.epoch),
            "firstHeight": String(value.firstHeight),
            "boundaryHeight": String(value.boundaryHeight),
          ], sequence: sequence)
        return "native-epoch-prefix-observed"
      case "offer", "request":
        let identity = try id("setup-id")
        try bind(
          "setup", id: identity,
          inputs: inputs.merging(["family": Data(command.action.utf8)]) { first, _ in first })
        let result =
          try command.action == "offer"
          ? wallet.offer(
            setupId: identity, amount: KagemushaMonetaryProbeManifest.amount(input("amount")))
          : wallet.request(
            setupId: identity, offer: input("offer"), feeSchedule: inputs["fee-schedule"],
            feeCertificate: inputs["fee-certificate"])
        let returned = mach_continuous_time()
        let kind: KagemushaWalletTransportKindV1 = command.action == "offer" ? .offer : .request
        _ = try call(result, returned: returned, sequence: sequence)
        try output("peer-original.norito", result.bytes, sequence: sequence)
        try output(
          "peer-envelope.norito", wallet.envelope(kind, original: result.bytes), sequence: sequence)
        return "native-" + command.action + "-exported-carrier-unobserved"
      case "review-send", "review-unload":
        guard pendingReview == nil else { throw EnrollmentProbeFailure.lifecycle }
        let identity = try id()
        try bind(
          "operation", id: identity,
          inputs: inputs.merging(["family": Data(command.action.utf8)]) { first, _ in first })
        // If an earlier confirmed attempt may have selected, only native recovery commands are allowed.
        let attempted =
          config.actorPath + "/private/intents/executed-" + EnrollmentProbeFiles.digest(identity)
        guard try !config.files.exists(attempted) else { throw EnrollmentProbeFailure.lifecycle }
        let review =
          try command.action == "review-send"
          ? wallet.reviewSend(
            request: input("request"), destinationAccountOriginal: input("destination"))
          : wallet.reviewUnload(
            amount: KagemushaMonetaryProbeManifest.amount(input("amount")), quote: inputs["quote"],
            certificates: inputs["certificates"], chargeBeneficiary: inputs["beneficiary"])
        let returned = mach_continuous_time()
        pendingReview = .init(review: review, requestID: identity, sequence: sequence)
        let p = review.projection
        try output("native-review.bin", p.bytes, sequence: sequence)
        try event(
          "native-review",
          values: [
            "nativeReturnedTicks": returned, "reviewSHA256": EnrollmentProbeFiles.digest(p.bytes),
            "kind": p.kind == .send ? "send" : "unload", "requestID": identity,
            "amount": scalar(p.amount), "fee": scalar(p.fee), "grossDebit": scalar(p.grossDebit),
            "netDestinationAmount": scalar(p.netDestinationAmount), "head": p.currentHead,
            "sourceStateCommitment": p.sourceStateCommitment,
            "destinationAccountDigest": p.destinationAccountDigest,
            "onwardSendReviewReadyObserved": p.kind == .send,
          ], sequence: sequence)
        return "native-review-awaiting-explicit-decision"
      case "decide-review":
        return try await decideReview(input("decision"), sequence: sequence)
      case "receive":
        let identity = try id()
        try bind(
          "operation", id: identity,
          inputs: inputs.merging(["family": Data("receive".utf8)]) { first, _ in first })
        let result = try wallet.receiveFromOffer(
          requestId: identity, payment: input("payment"), offer: input("offer"))
        let returned = mach_continuous_time()
        return try completion(result, returned: returned, requestID: identity, sequence: sequence)
      case "credit":
        let value = try wallet.creditProjection(receiveRequestId: id())
        let returned = mach_continuous_time()
        try event(
          "credit",
          values: [
            "nativeReturnedTicks": returned, "evidence": value.evidence.rawValue,
            "archive": value.archive.rawValue, "corePending": value.corePending,
            "creditID": value.creditId, "paymentDigest": value.paymentDigest,
            "amount": scalar(value.amount),
          ], sequence: sequence)
        if let original = value.creditedOriginal {
          try output("peer-original.norito", original, sequence: sequence)
          try output(
            "peer-envelope.norito", wallet.envelope(.credited, original: original),
            sequence: sequence)
        }
        return "native-credit-evidence-" + String(value.evidence.rawValue)
      case "accept-credited", "credited-status":
        let value =
          try command.action == "accept-credited"
          ? wallet.acceptCreditedForSend(sendRequestId: id(), original: input("credited"))
          : wallet.creditedForSendStatus(sendRequestId: id(), original: input("credited"))
        return try call(value, returned: mach_continuous_time(), sequence: sequence)
      case "fold-once":
        let value = try wallet.foldOnce()
        let returned = mach_continuous_time()
        _ = try call(value, returned: returned, sequence: sequence)
        return try recordSnapshot(sequence: sequence)
      case "snapshot": return try recordSnapshot(sequence: sequence)
      case "fold-status":
        let value = try wallet.foldStatus()
        let returned = mach_continuous_time()
        var row: [String: Any] = [
          "nativeReturnedTicks": returned, "phase": value.phase.rawValue,
          "eligible": value.eligible,
        ]
        if let backlog = value.observedBacklog { row["observedBacklog"] = scalar(backlog) }
        try event("fold-status", values: row, sequence: sequence)
        return "native-fold-worker-observed"
      case "request-status":
        let identity = try id()
        let value = try wallet.requestStatus(requestId: identity)
        let returned = mach_continuous_time()
        return try completion(value, returned: returned, requestID: identity, sequence: sequence)
      case "retry":
        let operationID = try id("operation-id")
        let value = try wallet.retry(operationId: operationID)
        let returned = mach_continuous_time()
        let status = try call(value, returned: returned, sequence: sequence)
        if value.status == 1 {
          return try released(
            wallet.releasedOutput(operationId: operationID), observed: mach_continuous_time(),
            sequence: sequence)
        }
        return status
      case "resume":
        let value = try wallet.resume()
        let returned = mach_continuous_time()
        return try call(value, returned: returned, sequence: sequence)
      case "released-request":
        return try released(
          wallet.releasedOutput(requestId: id()), observed: mach_continuous_time(),
          sequence: sequence)
      case "released-operation":
        return try released(
          wallet.releasedOutput(operationId: id("operation-id")), observed: mach_continuous_time(),
          sequence: sequence)
      case "unload-claim":
        let claim = try wallet.unloadClaimTransport(
          requestId: id(), chargeBeneficiary: inputs["beneficiary"])
        let returned = mach_continuous_time()
        try output("unload-claim.norito", claim, sequence: sequence)
        try output(
          "ledger-instruction.norito", wallet.ledgerInstruction(kind: .unload, original: claim),
          sequence: sequence)
        try event(
          "unload-claim", values: ["nativeReturnedTicks": returned, "settled": false],
          sequence: sequence)
        return "native-unload-claim-exported-not-settled"
      case "unload-status":
        let value = try wallet.unloadFinalityProgress(
          transactionHash: id("transaction-hash"), original: input("claim"))
        let returned = mach_continuous_time()
        var row: [String: Any] = [
          "nativeReturnedTicks": returned, "confirmed": value.confirmation != nil,
        ]
        if let height = value.verifiedHeight { row["height"] = String(height) }
        if let hash = value.blockHash { row["blockHash"] = hash }
        try event("unload-status", values: row, sequence: sequence)
        return value.confirmation == nil ? "native-unload-unconfirmed" : "native-unload-confirmed"
      case "unload-finality":
        let value = try wallet.ingestUnloadFinality(
          transactionHash: id("transaction-hash"), original: input("claim"),
          finality: input("finality"))
        let returned = mach_continuous_time()
        try ledgerState(value, returned: returned, sequence: sequence)
        return "native-unload-prefix-retained-not-confirmed"
      case "confirm-unload":
        let value = try wallet.confirmLedgerUnload(
          transactionHash: id("transaction-hash"), original: input("claim"))
        let returned = mach_continuous_time()
        try event(
          "unload-confirmation",
          values: [
            "nativeReturnedTicks": returned, "height": String(value.height),
            "blockHash": value.blockHash,
          ], sequence: sequence)
        return "native-unload-confirmed"
      case "decode-offer", "decode-request", "decode-payment", "decode-credited":
        let kinds: [String: KagemushaWalletTransportKindV1] = [
          "decode-offer": .offer, "decode-request": .request, "decode-payment": .payment,
          "decode-credited": .credited,
        ]
        let original = try wallet.original(kinds[command.action]!, envelope: input("envelope"))
        let returned = mach_continuous_time()
        try output("peer-original.norito", original, sequence: sequence)
        try event(
          "peer-decoded",
          values: [
            "nativeReturnedTicks": returned, "kind": kinds[command.action]!.rawValue,
            "carrierDeliveryClaimed": false, "monetaryAdmissionClaimed": false,
          ], sequence: sequence)
        return "native-peer-envelope-decoded-not-admitted"
      case "refresh-time":
        let identity = try id()
        try bind(
          "operation", id: identity,
          inputs: inputs.merging(["family": Data("refresh-time".utf8)]) { first, _ in first })
        let result = try wallet.refresh(
          requestId: identity, kind: .timeAnchor, update: input("anchor"),
          certificates: input("certificates"))
        let returned = mach_continuous_time()
        return try completion(result, returned: returned, requestID: identity, sequence: sequence)
      case "begin-time":
        guard timeExchange == nil else { throw EnrollmentProbeFailure.lifecycle }
        let exchange = try wallet.beginTimeExchange()
        let returned = mach_continuous_time()
        timeExchange = exchange
        try output("time-nonce.bin", exchange.nonce, sequence: sequence)
        try event("time-exchange", values: ["nativeReturnedTicks": returned], sequence: sequence)
        return "native-time-exchange-awaiting-issuer"
      case "finish-time":
        guard let exchange = timeExchange else { throw EnrollmentProbeFailure.lifecycle }
        // Valid bounded inputs reach Native exactly once. A dispatched token cannot be reconstructed.
        let anchor = try input("anchor")
        let certificate = try input("certificate")
        timeExchange = nil
        let result = try wallet.finishTimeExchange(
          exchange, anchor: anchor, certificate: certificate)
        let returned = mach_continuous_time()
        return try call(result, returned: returned, sequence: sequence)
      case "cancel-time":
        guard let exchange = timeExchange else { throw EnrollmentProbeFailure.lifecycle }
        timeExchange = nil
        try wallet.cancelTimeExchange(exchange)
        return "native-time-exchange-cancelled"
      default: throw EnrollmentProbeFailure.input
      }
    }

    func decideReview(_ original: Data, sequence: Int) async throws -> String {
      guard let pending = pendingReview else { throw EnrollmentProbeFailure.lifecycle }
      let wallet = try walletOwner()
      let projection = pending.review.projection
      let decision = try KagemushaMonetaryProbeManifest.Decision(
        original, invocation: config.invocation, sequence: pending.sequence,
        projection: projection.bytes)
      if !decision.confirmed {
        pendingReview = nil
        try wallet.discardReview(pending.review)
        try event(
          "review-cancelled",
          values: [
            "nativeReturnedTicks": mach_continuous_time(), "reviewSequence": pending.sequence,
          ], sequence: sequence)
        return "native-review-cancelled"
      }
      let attempted =
        config.actorPath + "/private/intents/executed-"
          + EnrollmentProbeFiles.digest(pending.requestID)
      // A prior marker publication may have failed after installing its final name. A retained
      // review never authorizes another attempt in that state, even with the same decision.
      guard try !config.files.exists(attempted) else { throw EnrollmentProbeFailure.lifecycle }
      // The host's explicit review decision is followed by actual iOS owner authentication.
      // This is a diagnostic confirmation flow, not a claim of a trusted display or carrier tap.
      let context = LAContext()
      context.touchIDAuthenticationAllowableReuseDuration = 0
      let digest = EnrollmentProbeFiles.digest(projection.bytes)
      let reason =
        "Confirm disposable KAGEMUSHA \(projection.kind == .send ? "Send" : "Unload") review \(digest.prefix(12)). Gross atomic units: high=\(projection.grossDebit.high), low=\(projection.grossDebit.low)."
      let confirmed = try await context.evaluatePolicy(
        .deviceOwnerAuthentication, localizedReason: reason)
      guard confirmed else { throw EnrollmentProbeFailure.lifecycle }
      let confirmedTicks = mach_continuous_time()
      try event(
        "confirmation",
        values: [
          "deviceOwnerAuthenticatedTicks": confirmedTicks, "reviewSequence": pending.sequence,
          "reviewSHA256": digest, "requestID": pending.requestID,
          "confirmationSurface": "external-exact-review-plus-ios-device-owner-authentication",
        ], sequence: sequence)
      // Persist before dispatch. An exception after this point never authorizes another reviewed
      // debit under this ID; use request-status/resume/retry/released on the same Native custody.
      try config.files.publishDispatchFence(attempted, bytes: Data(digest.utf8))
      pendingReview = nil
      let before = mach_continuous_time()
      try event(
        "execute-reviewed-start",
        values: ["ticks": before, "requestID": pending.requestID, "reviewSHA256": digest],
        sequence: sequence)
      let result = try wallet.executeReviewed(pending.review, requestId: pending.requestID)
      let returned = mach_continuous_time()
      return try completion(
        result, returned: returned, requestID: pending.requestID, sequence: sequence)
    }
  }
#endif
