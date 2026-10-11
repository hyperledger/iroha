import Foundation

/// Native wallet failure; uncertain outcomes require reconciliation, never a replacement debit.
public enum KagemushaWalletErrorV1: Error, Equatable, Sendable {
  case bridgeUnavailable, artifactsUnavailable, invalidInput, invalidNativeOutput, closed
  case native(status: Int32, reason: Int32, platformCode: Int32)
}

public extension KagemushaWalletErrorV1 {
  /// Design §5.3: free custody storage does not cover the operation. Refused before commit;
  /// nothing debited or credited. Retry after freeing storage.
  static let notEnoughStorageStatus: Int32 = -12
  /// Design §5.3: available memory does not cover the installed relations' peak proving memory.
  /// Refused before commit; nothing debited or credited. Never a device verdict.
  static let notEnoughMemoryStatus: Int32 = -14
}

/// Explicit custody result with original canonical bytes.
public struct KagemushaWalletCallV1: Sendable {
  /// Unknown0, complete1, pending2, not performed3, archived4, delivery loss5,
  /// idle6, caught up7, checkpoint8, folded9, CreditStatus10, preparing11, setup12,
  /// timeChallenge13, timeRetained14, accountChallenge15, opened16, activation17;
  /// background29, closure30, retainedFee31, noFee32, ledgerTip33, noTip34, payoutRecorded35,
  /// feeClaimTransport36, authenticatedEnrollmentSelection37, appleOriginals38, appleCustodyAcknowledged39,
  /// ledgerInstruction40, confirmedUnload42, confirmedActivation44, activationProgress45,
  /// activationNotStarted46, creditProjection47, unloadClaimTransport48, activationRejected49;
  /// collectionIdle50, collectionProgress51, collected52, deletionReview53, deleted54,
  /// deletionReviewDiscarded55, notDeleted56, epochProgress57. Retired kinds41/43 are rejected.
  /// Enrollment18...28 and localAbandoned58 (the no-marker enrollment abandonment, which has
  /// nothing to submit) are projected by the separate enrollment owner.
  static let statusRange: ClosedRange<Int32> = 0...59
  public let status: Int32
  public let sequenceLow: UInt64
  public let sequenceHigh: UInt64
  /// Checkpoint ordinal; for not-performed: stale0, invalid2. A storage or memory shortfall is the
  /// typed failure `notEnoughStorageStatus` or `notEnoughMemoryStatus`.
  public let detail: UInt32
  /// Exact retained bytes for complete1, CreditStatus10, setup12, timeChallenge13,
  /// accountChallenge15, activation17, closure30 and enrollment originals18/19/23/24/25/27/28.
  public let bytes: Data
  init(status: Int32, sequenceLow: UInt64, sequenceHigh: UInt64, detail: UInt32, bytes: Data) throws
  {
    guard Self.statusRange.contains(status), ![41, 43].contains(status), bytes.count <= kagemushaWalletOutputBoundV1(status),
      [1, 10, 12, 13, 15, 17, 18, 19, 23, 24, 25, 27, 28, 30, 31, 33, 36, 37, 38, 40, 42, 44, 45, 47, 48, 49, 53, 54, 57, 59].contains(status) ? !bytes.isEmpty : bytes.isEmpty,
      ![12, 14, 17, 30, 31, 32, 34, 35, 36, 40, 46, 47, 48, 50, 54, 55, 56].contains(status) || (sequenceLow == 0 && sequenceHigh == 0 && detail == 0),
      !([13, 15, 16, 53, 58, 59].contains(status) || (18...28).contains(status) || (37...39).contains(status))
        || (sequenceLow > 0 && sequenceLow <= UInt64(Int64.max) && sequenceHigh == 0 && detail == 0),
      !(50...52).contains(status) || detail == 0,
      ![13, 15, 18, 23].contains(status) || bytes.count == 32,
      status != 13 || bytes.contains(where: { $0 != 0 }),
      status != 19 || bytes.count == 161,
      status != 53 || bytes.count == 254,
      status != 54 || (bytes.count == 32 && bytes.contains(where: { $0 != 0 })),
      status != 57 || (sequenceHigh == 0 && detail == 0 && bytes.count == 16),
      ![42, 44, 49].contains(status) || sequenceLow > 1,
      ![33, 42, 44, 45, 49].contains(status) || (sequenceLow != 0 && sequenceHigh == 0 && detail == 0 && bytes.count == 32 && bytes.contains(where: { $0 != 0 }))
    else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    self.status = status
    self.sequenceLow = sequenceLow
    self.sequenceHigh = sequenceHigh
    self.detail = detail
    self.bytes = bytes
  }
}

import NoritoBridge

/// Exclusive native owner. Use worker threads for proving. Activity/payment calls can preempt
/// folding because no Swift lock is held across native calls. Closing preserves committed bytes.
/// Created only after original account admission through a native-provisioned runtime.
public final class KagemushaWalletV1: KagemushaWalletCleanupResourceV1, @unchecked Sendable {
  private let lease: KagemushaWalletNativeLeaseV1
  private let driver: KagemushaWalletNativeDriverV1
  private let setupOrigin = KagemushaWalletSetupOriginV1()
  private let deletionGate = KagemushaWalletDeletionGateV1()
  init(lease: KagemushaWalletNativeLeaseV1, driver: KagemushaWalletNativeDriverV1) {
    self.lease = lease; self.driver = driver
  }
  var cleanupLease: (any KagemushaWalletCleanupLeaseV1)? { lease }
  private func handle() throws -> UInt64 { try deletionGate.requireOrdinary(); return try lease.handle() }
  /// Join cooperative work and release custody, without deleting keys, markers or Payments.
  /// Once close starts, operations stay blocked; another close can retry the same Native ID.
  public func close() throws { try lease.close() }
  deinit { try? lease.close() }
  /// Enable folding while foreground or charging; leaving both requests cooperative cancellation.
  public func setActivity(foreground: Bool, charging: Bool) throws {
    try KagemushaWalletNativeDriverV1.check(
      driver.activity(try handle(), foreground ? 1 : 0, charging ? 1 : 0))
  }
  private func execute(_ input: KagemushaWalletOperationInputV1) throws -> KagemushaWalletCallV1 {
    let value = try handle()
    return try driver.result { out in
      input.withRequest { request in driver.execute(value, request, out) }
    }.completion()
  }
  func setup(_ input: KagemushaWalletSetupInputV1) throws -> KagemushaWalletCallV1 {
    let value = try handle()
    return try driver.result { out in input.withRequest { driver.setup(value, $0, out) } }
  }
  /// Obtain native-selected display DATA for explicit destructive confirmation.
  public func reviewCustodyDeletion() throws -> KagemushaWalletDeletionReviewV1 {
    try deletionGate.review { try setup(.init(selector: 48)) }
  }
  /// Permanently destroy payment-key custody. Display the review warning first.
  /// Any failure freezes ordinary calls until resume proves a definitive outcome.
  public func destructivelyDeleteCustody(_ review: KagemushaWalletDeletionReviewV1) throws -> Data {
    try deletionGate.confirm(review) { token in try deletionSetup(.init(selector: 49, token: token)) }
  }
  /// Recover the retained owner’s attempted deletion; restart cleanup belongs to native custody reconciliation.
  public func resumeCustodyDeletion() throws -> KagemushaWalletDeletionStatusV1 {
    try deletionGate.resume { try deletionSetup(.init(selector: 50)) }
  }
  /// Discard an unused review; this cannot undo a deletion attempt.
  public func discardCustodyDeletionReview(_ review: KagemushaWalletDeletionReviewV1) throws {
    try deletionGate.discard(review) { token in try setup(.init(selector: 51, token: token)) }
  }
  private func deletionSetup(_ input: KagemushaWalletSetupInputV1) throws -> KagemushaWalletCallV1 {
    let value = try lease.handle()
    return try driver.result { out in input.withRequest { driver.setup(value, $0, out) } }
  }
  /// Read bounded DATA from the existing Native owner; no observation creates a monetary intent.
  func observeProjection(selector: UInt32, identity: Data = Data()) throws -> Data {
    guard (0...3).contains(selector),
      selector == 0 ? identity.isEmpty : (identity.count == 32 && identity.contains(where: { $0 != 0 }))
    else { throw KagemushaWalletErrorV1.invalidInput }
    let owner = try handle()
    return try driver.observation(selector: selector) { result in
      identity.withUnsafeBytes {
        driver.observe(owner, selector, $0.bindMemory(to: UInt8.self).baseAddress, $0.count, result)
      }
    }
  }
  /// Exact Native-authenticated admission originals and authoritative atomic scale.
  public func metadata() throws -> KagemushaWalletMetadataV1 {
    let result = try observeProjection(selector: 0)
    return try .init(result)
  }
  /// Observe a completed local request through its retained Native operation mapping.
  public func releasedOutput(requestId: Data) throws -> KagemushaWalletReleasedOutputV1 {
    let result = try observeProjection(selector: 1, identity: requestId)
    return try .init(result)
  }
  /// Read an already known Native operation's retained output without executing it again.
  public func releasedOutput(operationId: Data) throws -> KagemushaWalletReleasedOutputV1 {
    let result = try observeProjection(selector: 2, identity: operationId)
    return try .init(result)
  }
  /// Complete restart-safe native enrollment Bootstrap.
  public func bootstrap() throws -> KagemushaWalletCallV1 { try setup(.init(selector: 0)).completion() }
  /// Exact retained Activate frame for ledger submission; this is not activation confirmation.
  public func activation() throws -> Data {
    let result = try setup(.init(selector: 15))
    guard result.status == 17 else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    return result.bytes
  }
  /// Exact native signed CloseLoads frame for ledger submission; this is not closure confirmation.
  /// Reuse requestId for exact retries; use a fresh id after a preissued Load and a new complete consumer.
  public func closeLoads(requestId: Data) throws -> Data {
    let result = try setup(.init(selector: 19, identity: requestId))
    guard result.status == 30 else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    return result.bytes
  }
  /// Canonical claim for a completed Unload, never settlement confirmation. Native selects
  /// the admitted account and exact retained package/quote. Charged Unload requires the
  /// quote's canonical beneficiary; uncharged Unload requires absence.
  public func unloadClaimTransport(requestId: Data, chargeBeneficiary: Data? = nil) throws -> Data {
    guard chargeBeneficiary == nil || !(chargeBeneficiary?.isEmpty ?? true) else {
      throw KagemushaWalletErrorV1.invalidInput
    }
    return try setup(.init(selector: 45, identity: requestId, first: chargeBeneficiary ?? Data())).unloadClaimOriginal()
  }
  /// Perform one bounded collection turn for a historical sequence. Native verifies the
  /// selected covering fold and derives Send nonmembership; keys and fee/activation originals
  /// remain retained. Repeat the same sequence after interruption until collected.
  public func collectRetainedStep(sequence: KagemushaWalletUInt128V1) throws -> KagemushaWalletCollectionStatusV1 {
    try .init(setup(.init(selector: 47, amount: sequence)), expectedSequence: sequence)
  }
  /// Read both exact fee-claim originals atomically from one native-retained frame.
  /// Nil means no pending claim; missing selected bytes are an error, never a paid verdict.
  public func feeClaim(creditId: Data) throws -> KagemushaWalletFeeClaimV1? {
    let result = try setup(.init(selector: 20, identity: creditId))
    if result.status == 32 { return nil }
    guard result.status == 31 else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    let payment = try setup(.init(selector: 21, first: result.bytes)).original()
    let request = try setup(.init(selector: 22, first: result.bytes)).original()
    return .init(payment: payment, request: request)
  }
  /// Canonical fee claim for ledger relay, bound by Native to the retained fee schedule.
  /// Beneficiary is an original canonical AccountId; nil means no pending retained claim.
  public func feeClaimTransport(creditId: Data, beneficiary: Data) throws -> Data? {
    let retained = try setup(.init(selector: 20, identity: creditId))
    if retained.status == 32 { return nil }
    return try setup(retained.feeClaimInput(beneficiary: beneficiary)).feeClaimOriginal()
  }
  /// Verify one bounded next Sumeragi finality original; native persists its selected prefix.
  public func ingestLedgerFinality(_ original: Data) throws -> KagemushaWalletLedgerProgressV1 {
    try .init(setup(.init(selector: 23, first: original)))
  }
  /// Read durably retained native Load epoch authority, never an HTTP cursor.
  public func epochProgress() throws -> KagemushaWalletEpochProgressV1 {
    try .init(setup(.init(selector: 52)))
  }
  /// Verify one exact incumbent boundary and atomically retain its successor committee.
  public func ingestEpochBoundary(expectedEpoch: UInt64, original: Data) throws -> KagemushaWalletEpochProgressV1 {
    try .init(setup(.init(selector: 53, amount: .init(low: expectedEpoch, high: 0), first: original)))
  }
  /// Read the selected native prefix; nil means no progress has been durably selected.
  public func ledgerProgress() throws -> KagemushaWalletLedgerProgressV1? {
    let result = try setup(.init(selector: 24))
    if result.status == 34 { return nil }
    return try .init(result)
  }
  /// Authenticate exact payout-row and full World originals against native's selected tip.
  /// Only successful durable acknowledgement releases the separate retained fee claim.
  public func acknowledgeFeePayout(creditId: Data, world: Data, payout: Data) throws {
    let result = try setup(.init(selector: 25, identity: creditId, first: world, second: payout))
    guard result.status == 35 else { throw KagemushaWalletErrorV1.invalidNativeOutput }
  }
  /// Sign an Offer with a retained native nonce; retries return its exact original bytes.
  public func offer(setupId: Data, amount: KagemushaWalletUInt128V1) throws -> KagemushaWalletCallV1 {
    let result = try setup(.init(selector: 1, identity: setupId, amount: amount))
    _ = try result.original()
    return result
  }
  /// Authenticate the payer Offer and issue a Request from native current policy.
  public func request(setupId: Data, offer: Data, feeSchedule: Data? = nil, feeCertificate: Data? = nil) throws -> KagemushaWalletCallV1 {
    let result = try setup(.request(identity: setupId, offer: offer,
      feeSchedule: feeSchedule, feeCertificate: feeCertificate))
    _ = try result.original()
    return result
  }
  /// Convert a durable Receive or CreditStatus output to canonical peer evidence.
  /// Native validates its representation and scheme; this grants no proof or delivery verdict.
  public func credited(_ received: KagemushaWalletCallV1) throws -> Data {
    try setup(received.creditedInput()).original()
  }
  /// Native verifies delivery evidence and derives the private Archive operation.
  public func acceptCredited(_ original: Data) throws -> KagemushaWalletCallV1 {
    try setup(.init(selector: 3, first: original)).completion()
  }
  /// Begin a direct issuer exchange. Only the fresh nonce leaves native clock custody.
  public func beginTimeExchange() throws -> KagemushaWalletTimeExchangeV1 {
    try setup(.init(selector: 4)).exchange(origin: setupOrigin)
  }
  /// Consume the native exchange token and retain its verified anchor before TimeAnchor refresh.
  /// Invalid local bounds leave the challenge usable; dispatch consumes it even on failure.
  public func finishTimeExchange(_ exchange: KagemushaWalletTimeExchangeV1, anchor: Data, certificate: Data) throws -> KagemushaWalletCallV1 {
    let input = try KagemushaWalletSetupInputV1(selector: 5,
      token: exchange.tokenFor(origin: setupOrigin), first: anchor, second: certificate)
    _ = try handle()
    try exchange.consume(origin: setupOrigin)
    return try setup(input).timeRetained()
  }
  /// Discard an unanswered native time exchange without accepting or refreshing an anchor.
  public func cancelTimeExchange(_ exchange: KagemushaWalletTimeExchangeV1) throws {
    let input = try KagemushaWalletSetupInputV1(selector: 6,
      token: exchange.tokenFor(origin: setupOrigin))
    _ = try handle()
    try exchange.consume(origin: setupOrigin)
    let result = try setup(input)
    guard result.status == 6, result.sequenceLow == 0, result.sequenceHigh == 0,
      result.detail == 0 else { throw KagemushaWalletErrorV1.invalidNativeOutput }
  }
  /// Frame exact original bytes for peer transport; this performs no monetary admission.
  public func envelope(_ kind: KagemushaWalletTransportKindV1, original: Data) throws -> Data {
    try setup(.init(selector: 6 + kind.rawValue, first: original)).original()
  }
  /// Extract one expected original kind under this native wallet's scheme, without accepting value.
  public func original(_ kind: KagemushaWalletTransportKindV1, envelope: Data) throws -> Data {
    try setup(.init(selector: 10 + kind.rawValue, first: envelope)).original()
  }
  /// Load exact ordinary-ledger receipt and native BLS finality originals.
  public func load(requestId: Data, receipt: Data, finality: Data) throws -> KagemushaWalletCallV1 {
    try execute(KagemushaWalletOperationInputV1(requestId: requestId, selector: 0, first: receipt, second: finality))
  }
  /// Authenticate the fully folded Send source before fresh hardware UI confirmation.
  public func reviewSend(request: Data, destinationAccountOriginal: Data) throws -> KagemushaWalletReviewV1 {
    guard !request.isEmpty, request.count <= 10_000,
      !destinationAccountOriginal.isEmpty, destinationAccountOriginal.count <= 4_096
    else { throw KagemushaWalletErrorV1.invalidInput }
    return try review(selector: 1, amount: .init(low: 0, high: 0), first: request,
      second: destinationAccountOriginal, expected: .send)
  }
  /// Native selects the durably issued Request using the Payment's canonical digest.
  public func receive(requestId: Data, payment: Data, payerCredential: Data, certificates: Data) throws -> KagemushaWalletCallV1 {
    try execute(KagemushaWalletOperationInputV1(requestId: requestId, selector: 2, first: payment, second: payerCredential, third: certificates))
  }
  /// Forward the exact signed session Offer. Native extracts its payer originals and performs
  /// ordinary Receive authentication; the Offer supplies no monetary authority.
  public func receiveFromOffer(requestId: Data, payment: Data, offer: Data) throws -> KagemushaWalletCallV1 {
    try execute(KagemushaWalletOperationInputV1(requestId: requestId, selector: 10, first: payment, second: offer))
  }
  /// Apply signed policy originals; Native derives effective values and local map changes.
  public func refresh(requestId: Data, kind: KagemushaWalletRefreshKindV1, update: Data, certificates: Data) throws -> KagemushaWalletCallV1 {
    try execute(KagemushaWalletOperationInputV1(requestId: requestId, selector: kind.rawValue, first: update, second: certificates))
  }
  /// Authenticate exact Unload gross debit and optional signed charge before fresh confirmation.
  public func reviewUnload(amount: KagemushaWalletUInt128V1, quote: Data? = nil, certificates: Data? = nil,
    chargeBeneficiary: Data? = nil) throws -> KagemushaWalletReviewV1 {
    guard amount.low != 0 || amount.high != 0, (quote == nil) == (certificates == nil),
      (quote == nil) == (chargeBeneficiary == nil),
      quote.map({ !$0.isEmpty && $0.count <= 1_024 }) ?? true,
      certificates.map({ !$0.isEmpty && $0.count <= 10_000 }) ?? true,
      chargeBeneficiary.map({ !$0.isEmpty && $0.count <= 4_096 }) ?? true else { throw KagemushaWalletErrorV1.invalidInput }
    let companion: Data
    if let certificates, let chargeBeneficiary {
      companion = try KagemushaWalletUnloadChargeReviewV1.encode(certificates: certificates, beneficiary: chargeBeneficiary)
    } else { companion = Data() }
    return try review(selector: 8, amount: amount, first: quote ?? Data(), second: companion, expected: .unload)
  }
  private func review(selector: UInt32, amount: KagemushaWalletUInt128V1, first: Data, second: Data,
    expected: KagemushaWalletReviewProjectionV1.Kind) throws -> KagemushaWalletReviewV1 {
    let handle = try handle()
    var token: UInt64 = 0
    do {
      let reply = try driver.reviewResult { out in
        first.withUnsafeBytes { a in second.withUnsafeBytes { b in
          var request = connect_norito_kagemusha_wallet_review_request_v1()
          request.selector = selector; request.amount = .init(low: amount.low, high: amount.high)
          request.first = a.bindMemory(to: UInt8.self).baseAddress; request.first_length = a.count
          request.second = b.bindMemory(to: UInt8.self).baseAddress; request.second_length = b.count
          let status = driver.review(handle, &request, out)
          token = out.pointee.sequence_low
          return status
        }}
      }
      return try reply.review(origin: self, expected: expected)
    } catch KagemushaWalletErrorV1.invalidNativeOutput {
      let primary = KagemushaWalletErrorV1.invalidNativeOutput
      do {
        if token == 0 { try close() }
        else { try KagemushaWalletNativeDriverV1.check(driver.discardReview(handle, token)) }
      } catch {
        // A token delivery error cannot orphan the actual Native capability. Close the owner;
        // a failed retirement is sticky and retains its actual callbacks/custody resource.
        do { try close() } catch { throw error }
      }
      throw primary
    }
  }
  /// Consume the exact reviewed Native action after fresh hardware confirmation. Native rechecks its whole source.
  public func executeReviewed(_ review: KagemushaWalletReviewV1, requestId: Data) throws -> KagemushaWalletCallV1 {
    guard requestId.count == 32, requestId.contains(where: { $0 != 0 }) else { throw KagemushaWalletErrorV1.invalidInput }
    let handle = try handle(), token = try review.consume(origin: self)
    do {
      return try driver.result { out in requestId.withUnsafeBytes {
        driver.executeReviewed(handle, token, $0.bindMemory(to: UInt8.self).baseAddress, out)
      }}.completion()
    } catch {
      let primary=error
      // Consumed Native tokens return closed. This acknowledges no unused review,
      // never release of the owner or permission to repeat a debit.
      let status=driver.discardReview(handle,token)
      if status != 0 && status != -2 {
        do { try close() } catch { throw error }
      }
      throw primary
    }
  }
  /// Worker-only discard; it creates no intent, signature, proof or debit.
  public func discardReview(_ review: KagemushaWalletReviewV1) throws {
    let handle = try handle(), token = try review.consume(origin: self)
    try KagemushaWalletNativeDriverV1.check(driver.discardReview(handle, token))
  }
  /// Current integration uses the same exact owner-local discard.
  public func cancelReview(_ review:KagemushaWalletReviewV1)throws{try discardReview(review)}
  public func reviewSend(_ request:Data, destinationAccountOriginal:Data)throws->KagemushaWalletReviewV1{
    try reviewSend(request:request, destinationAccountOriginal:destinationAccountOriginal)
  }
  /// Enter Retiring under native folded-state checks.
  public func retire(requestId: Data) throws -> KagemushaWalletCallV1 {
    try execute(KagemushaWalletOperationInputV1(requestId: requestId, selector: 9))
  }
  /// Distinguish durable preparation from irreversible pending and retained completion.
  public func requestStatus(requestId: Data) throws -> KagemushaWalletCallV1 {
    guard requestId.count == 32, requestId.contains(where: { $0 != 0 }) else { throw KagemushaWalletErrorV1.invalidInput }
    let value = try handle()
    return try driver.result { out in
      requestId.withUnsafeBytes { driver.requestStatus(value, $0.bindMemory(to: UInt8.self).baseAddress, out) }
    }.completion()
  }
  /// Return original retained output without a second signature, proof or debit.
  public func retry(operationId: Data) throws -> KagemushaWalletCallV1 {
    guard operationId.count == 32 else { throw KagemushaWalletErrorV1.invalidInput }
    let value = try handle()
    return try driver.result { out in
      operationId.withUnsafeBytes {
        driver.retry(value, $0.bindMemory(to: UInt8.self).baseAddress, out)
      }
    }.completion()
  }
  /// Reconcile and finish the selected operation.
  public func resume() throws -> KagemushaWalletCallV1 {
    let value = try handle()
    return try driver.result { driver.resume(value, $0) }.completion()
  }
  /// Observe native worker state without waiting for its proof or preempting it.
  /// A stored worker failure is thrown and remains parked until a subsequent activity/payment wake.
  public func foldStatus() throws -> KagemushaWalletBackgroundStatusV1 {
    try KagemushaWalletBackgroundStatusV1(setup(.init(selector: 18)))
  }
  /// Compute/persist at most one checkpoint or final Ω.
  public func foldOnce() throws -> KagemushaWalletCallV1 {
    let value = try handle()
    return try driver.result { driver.fold(value, $0) }.completion()
  }
  /// Source-selected ownership and proof backlog. Call on a worker; this grants no operation readiness.
  public func snapshot() throws -> KagemushaWalletSnapshotV1 {
    var output = connect_norito_kagemusha_wallet_snapshot_v1_t()
    let status = driver.snapshot(try handle(), &output)
    try KagemushaWalletNativeDriverV1.check(status, reason: output.reason, platform: output.platform_code)
    return try KagemushaWalletSnapshotV1(output)
  }
  /// Canonical CreditStatus from the permanent first-credit index.
  public func creditStatus(creditId: Data, paymentDigest: Data) throws -> KagemushaWalletCallV1 {
    guard creditId.count == 32, paymentDigest.count == 32 else {
      throw KagemushaWalletErrorV1.invalidInput
    }
    let value = try handle()
    return try driver.result { out in
      creditId.withUnsafeBytes { credit in
        paymentDigest.withUnsafeBytes { payment in
          driver.credit(
            value, credit.bindMemory(to: UInt8.self).baseAddress,
            payment.bindMemory(to: UInt8.self).baseAddress, out)
        }
      }
    }.completion()
  }
}

/// Existing signed update classes; these values never select proof keys or state roots.
public enum KagemushaWalletRefreshKindV1: UInt32, Sendable {
  case credential = 3, schemePolicy = 4, blacklist = 5, timeAnchor = 6, quotaShare = 7
}

/// Fixed foreign intake only; Native performs canonical decoding and all monetary admission.
struct KagemushaWalletOperationInputV1 {
  let requestId: Data
  let selector: UInt32
  let amount: KagemushaWalletUInt128V1
  let first: Data
  let second: Data
  let third: Data
  init(requestId: Data, selector: UInt32, amount: KagemushaWalletUInt128V1 = .init(low: 0, high: 0),
       first: Data = Data(), second: Data = Data(), third: Data = Data()) throws {
    let limits: [Int]
    switch selector {
    case 0: limits = [512, 256 * 1024, 0]
    case 2: limits = [10_000, 1_024, 10_000]
    case 3, 4: limits = [1_024, 10_000, 0]
    case 5: limits = [65_536 * 34 + 512, 10_000, 0]
    case 6: limits = [512, 10_000, 0]
    case 7: limits = [8_192, 10_000, 0]
    case 9: limits = [0, 0, 0]
    case 10: limits = [10_000, 10_000, 0]
    default: throw KagemushaWalletErrorV1.invalidInput
    }
    let nonzero = amount.low != 0 || amount.high != 0
    guard requestId.count == 32, requestId.contains(where: { $0 != 0 }),
      !nonzero else { throw KagemushaWalletErrorV1.invalidInput }
    for (bytes, limit) in zip([first, second, third], limits) {
      guard bytes.count <= limit, !((selector < 8 || selector == 10) && limit != 0 && bytes.isEmpty)
      else { throw KagemushaWalletErrorV1.invalidInput }
    }
    self.requestId = requestId; self.selector = selector; self.amount = amount
    self.first = first; self.second = second; self.third = third
  }
  func withRequest<T>(_ body: (UnsafePointer<connect_norito_kagemusha_wallet_operation_request_v1>) -> T) -> T {
    requestId.withUnsafeBytes { identity in first.withUnsafeBytes { a in
      second.withUnsafeBytes { b in third.withUnsafeBytes { c in
        var request = connect_norito_kagemusha_wallet_operation_request_v1()
        request.request_id = identity.bindMemory(to: UInt8.self).baseAddress
        request.selector = selector
        request.amount = .init(low: amount.low, high: amount.high)
        request.first = a.bindMemory(to: UInt8.self).baseAddress; request.first_length = a.count
        request.second = b.bindMemory(to: UInt8.self).baseAddress; request.second_length = b.count
        request.third = c.bindMemory(to: UInt8.self).baseAddress; request.third_length = c.count
        return body(&request)
      }}
    }}
  }
}

final class KagemushaWalletNativeDriverV1: @unchecked Sendable {
  typealias Output = connect_norito_kagemusha_wallet_result_v1
  typealias AccountDisplay = @convention(c) (UnsafePointer<UInt8>?, Int, UInt16, UnsafeMutablePointer<Output>?) -> Int32
  typealias AccountOriginal = @convention(c) (UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<Output>?) -> Int32
  typealias Observe = @convention(c) (UInt64, UInt32, UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<Output>?) -> Int32
  typealias OpenBegin = @convention(c) (UInt64, UnsafePointer<connect_norito_kagemusha_wallet_open_request_v1>?, UnsafeMutablePointer<Output>?) -> Int32
  typealias OpenFinish = @convention(c) (UInt64, UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<Output>?) -> Int32
  typealias Close = @convention(c) (UInt64) -> Int32
  typealias Activity = @convention(c) (UInt64, UInt8, UInt8) -> Int32
  typealias Execute =
    @convention(c) (UInt64, UnsafePointer<connect_norito_kagemusha_wallet_operation_request_v1>?, UnsafeMutablePointer<Output>?) -> Int32
  typealias Enrollment = @convention(c) (UInt64, UnsafePointer<connect_norito_kagemusha_wallet_enrollment_request_v1>?, UnsafeMutablePointer<Output>?) -> Int32
  typealias Review = @convention(c) (UInt64, UnsafePointer<connect_norito_kagemusha_wallet_review_request_v1>?, UnsafeMutablePointer<Output>?) -> Int32
  typealias ExecuteReviewed = @convention(c) (UInt64, UInt64, UnsafePointer<UInt8>?, UnsafeMutablePointer<Output>?) -> Int32
  typealias DiscardReview = @convention(c) (UInt64, UInt64) -> Int32
  typealias Setup = @convention(c) (UInt64, UnsafePointer<connect_norito_kagemusha_wallet_setup_request_v1>?, UnsafeMutablePointer<Output>?) -> Int32
  typealias Retry =
    @convention(c) (UInt64, UnsafePointer<UInt8>?, UnsafeMutablePointer<Output>?) -> Int32
  typealias Simple = @convention(c) (UInt64, UnsafeMutablePointer<Output>?) -> Int32
  typealias Credit =
    @convention(c) (
      UInt64, UnsafePointer<UInt8>?, UnsafePointer<UInt8>?, UnsafeMutablePointer<Output>?
    ) -> Int32
  typealias Snapshot = @convention(c) (UInt64, UnsafeMutablePointer<connect_norito_kagemusha_wallet_snapshot_v1_t>?) -> Int32
  typealias Free = @convention(c) (UnsafeMutablePointer<UInt8>?) -> Void
  let openBegin: OpenBegin
  let accountDisplay: AccountDisplay
  let accountOriginal: AccountOriginal
  let observe: Observe
  let openFinish: OpenFinish
  let openCancel: Close
  let close: Close
  let activity: Activity
  let execute: Execute
  let setup: Setup
  let enrollment: Enrollment
  let review: Review
  let executeReviewed: ExecuteReviewed
  let discardReview: DiscardReview
  let requestStatus: Retry
  let retry: Retry
  let resume: Simple
  let fold: Simple
  let credit: Credit
  let snapshot: Snapshot
  let free: Free
  init() throws {
    func symbol<T>(_ name: String, _ type: T.Type) throws -> T {
      guard
        let value = NoritoNativeBridge.shared.resolveNativeSymbol(
          name, as: type)
      else { throw KagemushaWalletErrorV1.bridgeUnavailable }
      return value
    }
    let revision = try symbol(
      "connect_norito_kagemusha_wallet_revision_v1", (@convention(c) () -> UInt32).self)
    guard revision() == 1 else { throw KagemushaWalletErrorV1.bridgeUnavailable }
    accountDisplay = try symbol("connect_norito_kagemusha_wallet_account_display_v1", AccountDisplay.self)
    accountOriginal = try symbol("connect_norito_kagemusha_wallet_account_original_v1", AccountOriginal.self)
    observe = try symbol("connect_norito_kagemusha_wallet_observe_v1", Observe.self)
    openBegin = try symbol("connect_norito_kagemusha_wallet_open_begin_v1", OpenBegin.self)
    openFinish = try symbol("connect_norito_kagemusha_wallet_open_finish_v1", OpenFinish.self)
    openCancel = try symbol("connect_norito_kagemusha_wallet_open_cancel_v1", Close.self)
    close = try symbol("connect_norito_kagemusha_wallet_close_v1", Close.self)
    activity = try symbol("connect_norito_kagemusha_wallet_activity_v1", Activity.self)
    enrollment = try symbol("connect_norito_kagemusha_wallet_enrollment_v1", Enrollment.self)
    execute = try symbol("connect_norito_kagemusha_wallet_execute_v1", Execute.self)
    setup = try symbol("connect_norito_kagemusha_wallet_setup_v1", Setup.self)
    review = try symbol("connect_norito_kagemusha_wallet_review_v1", Review.self)
    executeReviewed = try symbol("connect_norito_kagemusha_wallet_execute_reviewed_v1", ExecuteReviewed.self)
    discardReview = try symbol("connect_norito_kagemusha_wallet_discard_review_v1", DiscardReview.self)
    requestStatus = try symbol("connect_norito_kagemusha_wallet_request_status_v1", Retry.self)
    retry = try symbol("connect_norito_kagemusha_wallet_retry_v1", Retry.self)
    resume = try symbol("connect_norito_kagemusha_wallet_resume_v1", Simple.self)
    fold = try symbol("connect_norito_kagemusha_wallet_fold_v1", Simple.self)
    credit = try symbol("connect_norito_kagemusha_wallet_credit_status_v1", Credit.self)
    snapshot = try symbol("connect_norito_kagemusha_wallet_snapshot_v1", Snapshot.self)
    guard
      let value = NoritoNativeBridge.shared.resolveNativeSymbol(
        "connect_norito_free", as: Free.self)
    else { throw KagemushaWalletErrorV1.bridgeUnavailable }
    free = value
  }
  static func check(_ status: Int32, reason: Int32 = -1, platform: Int32 = 0) throws {
    if status == 0 { return }
    if status == -2 { throw KagemushaWalletErrorV1.closed }
    if status == -4 { throw KagemushaWalletErrorV1.artifactsUnavailable }
    throw KagemushaWalletErrorV1.native(status: status, reason: reason, platformCode: platform)
  }
  func reviewResult(_ action: (UnsafeMutablePointer<Output>) -> Int32) throws -> KagemushaWalletReviewReplyV1 {
    var value = Output()
    let status = action(&value)
    defer { if let bytes = value.bytes { free(bytes) } }
    try Self.check(status, reason: value.reason, platform: value.platform_code)
    guard value.status == 18,
      value.length >= KagemushaWalletReviewProjectionV1.fixedByteCount,
      value.length <= KagemushaWalletReviewProjectionV1.maximumByteCount,
      let bytes = value.bytes else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    return .init(status: value.status, reason: value.reason, platformCode: value.platform_code,
      sequenceLow: value.sequence_low, sequenceHigh: value.sequence_high, detail: value.detail, bytes: Data(bytes: bytes, count: value.length))
  }
  /// Observation has a separate, selector-bound DATA geometry. No financial result kind
  /// or global setup output bound is reinterpreted to carry these larger public originals.
  func observation(selector: UInt32, _ action: (UnsafeMutablePointer<Output>) -> Int32) throws -> Data {
    let caps = [5_268, 20_066, 20_066, 65_756]
    guard Int(selector) < caps.count else { throw KagemushaWalletErrorV1.invalidInput }
    var value = Output()
    let status = action(&value)
    defer { if let bytes = value.bytes { free(bytes) } }
    try Self.check(status, reason: value.reason, platform: value.platform_code)
    guard value.status == 12, value.reason == -1, value.platform_code == 0,
      value.sequence_low == 0, value.sequence_high == 0, value.detail == 0,
      value.length > 0, value.length <= caps[Int(selector)], let bytes = value.bytes
    else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    return Data(bytes: bytes, count: value.length)
  }
  func result(_ action: (UnsafeMutablePointer<Output>) -> Int32) throws -> KagemushaWalletCallV1 {
    var value = Output()
    let status = action(&value)
    defer { if let bytes = value.bytes { free(bytes) } }
    try Self.check(status, reason: value.reason, platform: value.platform_code)
    guard value.reason == -1, value.platform_code == 0,
      KagemushaWalletCallV1.statusRange.contains(value.status), value.length >= 0,
      value.length <= kagemushaWalletOutputBoundV1(value.status), value.length == 0 || value.bytes != nil
    else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    return try KagemushaWalletCallV1(
      status: value.status, sequenceLow: value.sequence_low, sequenceHigh: value.sequence_high,
      detail: value.detail,
      bytes: value.bytes.map { Data(bytes: $0, count: value.length) } ?? Data())
  }
}

func kagemushaWalletCallbacksV1(_ platform: KagemushaWalletApplePlatformV1)
  -> connect_norito_kagemusha_platform_v1
{
  var table = connect_norito_kagemusha_platform_v1()
  table.version = 1
  table.anchor_policy = 1
  table.context = Unmanaged.passUnretained(platform).toOpaque()
  table.retain = { pointer in
    if let pointer { _ = Unmanaged<KagemushaWalletApplePlatformV1>.fromOpaque(pointer).retain() }
  }
  table.release = { pointer in
    if let pointer { Unmanaged<KagemushaWalletApplePlatformV1>.fromOpaque(pointer).release() }
  }
  table.invoke = { context, operation, slot, input, length, auxiliary, output, capacity, reply in
    guard let reply else { return }
    reply.pointee = connect_norito_kagemusha_platform_reply_v1(
      tag: 2, reason: 4, code: 0, length: 0)
    guard let context else { return }
    let platform = Unmanaged<KagemushaWalletApplePlatformV1>.fromOpaque(context)
      .takeUnretainedValue()
    func failure(_ reason: KagemushaWalletAppleUnavailableV1, tag: UInt32 = 2) {
      reply.pointee.tag = tag
      switch reason {
      case .locked: reply.pointee.reason = 0
      case .beforeFirstUnlock: reply.pointee.reason = 1
      case .io(let code):
        reply.pointee.reason = 3
        reply.pointee.code = code
      case .platform(let code):
        reply.pointee.reason = 4
        reply.pointee.code = code
      case .keyUnusable: reply.pointee.reason = 5
      }
    }
    func success(_ bytes: Data = Data()) {
      guard bytes.count <= capacity, bytes.isEmpty || output != nil else {
        reply.pointee.tag = UInt32.max
        return
      }
      if let output, !bytes.isEmpty { bytes.copyBytes(to: output, count: bytes.count) }
      reply.pointee.tag = 0
      reply.pointee.length = bytes.count
    }
    func probe(_ result: KagemushaWalletAppleProbeV1<Data>) {
      switch result {
      case .present(let bytes): success(bytes)
      case .absent: reply.pointee.tag = 1
      case .unavailable(let reason): failure(reason)
      }
    }
    func publish(_ result: KagemushaWalletApplePublishOutcomeV1) {
      switch result {
      case .published: success()
      case .uncertain(let reason): failure(reason, tag: 4)
      case .notPublished(let reason):
        switch reason {
        case .destinationExists: reply.pointee.tag = 3
        case .destinationAbsent: reply.pointee.tag = 5
        case .noSpace: failure(.io(28))
        case .failed(let reason): failure(reason)
        }
      }
    }
    if operation == 10 {
      guard slot == nil, length == 0, auxiliary == 0 else { return }
      switch platform.keyEnumerate() {
      case .success(let slots):
        var bytes = Data()
        for slot in slots { bytes.append(slot.bytes) }
        success(bytes)
      case .failure(let reason): failure(reason)
      }
      return
    }
    if operation == 7 {
      switch platform.storageState() {
      case .success: success()
      case .failure(let reason): failure(reason)
      }
      return
    }
    if operation == 8 || operation == 9 {
      let value = operation == 8 ? platform.bootSessionUUID() : platform.custodyRootPath()
      switch value {
      case .success(let text): success(Data(text.utf8))
      case .failure(let reason): failure(reason)
      }
      return
    }
    guard let slot, let parsed = KagemushaWalletAppleSlotV1(Data(bytes: slot, count: 32)),
      length <= 256, length == 0 || input != nil
    else { return }
    let bytes = input.map { Data(bytes: $0, count: length) } ?? Data()
    switch operation {
    case 0: probe(platform.keyProbe(parsed))
    case 1:
      guard
        let profile = KagemushaWalletAppleKeyProfileV1(rawValue: UInt8(exactly: auxiliary) ?? 0),
        let request = KagemushaWalletAppleKeyGenerationRequestV1(
          challengeDigest: bytes, profile: profile)
      else { return }
      switch platform.keyGenerate(parsed, request) {
      case .generated(let key): success(key)
      case .alreadyPresent: reply.pointee.tag = 3
      case .unavailable(let reason): failure(reason)
      }
    case 13:
      guard
        let profile = KagemushaWalletAppleKeyProfileV1(rawValue: UInt8(exactly: auxiliary) ?? 0),
        let request = KagemushaWalletAppleKeyGenerationRequestV1(
          challengeDigest: bytes, profile: profile)
      else { return }
      switch platform.recoverGenerationReply(parsed, request) {
      case .some(.generated(let key)): success(key)
      case .some(.unavailable(let reason)): failure(reason)
      case .none: reply.pointee.tag = 3 // No held successful return, never key absence.
      case .some(.alreadyPresent): break // Recovery cannot generate or claim a new result.
      }
    case 2:
      switch platform.keySign(parsed, message: bytes) {
      case .success(let signature): success(signature)
      case .failure(let reason): failure(reason)
      }
    case 3:
      switch platform.keyDelete(parsed) {
      case .removed: success()
      case .notRemoved(let reason): failure(reason)
      case .uncertain(let reason): failure(reason, tag: 4)
      }
    case 4: probe(platform.anchorRead(parsed))
    case 5: publish(platform.anchorCreate(parsed, value: bytes))
    case 6: publish(platform.anchorUpdate(parsed, value: bytes))
    default: break
    }
  }
  return table
}

func kagemushaWalletOutputBoundV1(_ status: Int32) -> Int {
  switch status {
  case 17, 27, 30, 36, 48: return 16_384
  case 40, 59: return 65_536
  case 24: return KagemushaWalletEnrollmentV1.REQUEST_MAX_BYTES
  case 25: return 262_144
  case 28: return 1024
  case 37: return 1028
  case 38: return 73_740
  case 31: return 21_024
  case 33, 42, 44, 45, 49: return 32
  case 47: return 10_092
  case 53: return 254
  case 54: return 32
  case 55, 56, 58: return 0
  case 57: return 16
  default: return 10_000
  }
}
