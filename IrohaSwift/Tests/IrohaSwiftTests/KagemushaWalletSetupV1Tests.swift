import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import XCTest
@testable import IrohaSwift

final class KagemushaWalletSetupV1Tests: XCTestCase {
  func testCollectionHasOnlySequenceInputAndExactSeparateResults() throws {
    for sequence in [KagemushaWalletUInt128V1(low: 0, high: 0), .init(low: .max, high: .max)] {
      let input = try KagemushaWalletSetupInputV1(selector: 47, amount: sequence)
      XCTAssertEqual(input.amount, sequence)
      XCTAssertEqual(input.identity, Data(repeating: 0, count: 32))
      for status in Int32(50)...52 {
        let result = try KagemushaWalletCallV1(status: status, sequenceLow: status == 50 ? 0 : sequence.low,
          sequenceHigh: status == 50 ? 0 : sequence.high, detail: 0, bytes: Data())
        let expected: KagemushaWalletCollectionStatusV1 = status == 50 ? .idle : (status == 51 ? .progress(sequence) : .collected(sequence))
        XCTAssertEqual(try KagemushaWalletCollectionStatusV1(result, expectedSequence: sequence), expected)
        XCTAssertThrowsError(try result.completion())
        XCTAssertThrowsError(try result.original())
        XCTAssertThrowsError(try result.unloadClaimOriginal())
        XCTAssertThrowsError(try KagemushaWalletCallV1(status: status, sequenceLow: 0, sequenceHigh: 0, detail: 1, bytes: Data()))
        XCTAssertThrowsError(try KagemushaWalletCallV1(status: status, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data([1])))
      }
    }
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 47, identity: Data(repeating: 1, count: 32)))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 47, token: 1))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 47, first: Data([1])))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 47, second: Data([1])))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 47, third: Data([1])))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 56))
    XCTAssertThrowsError(try KagemushaWalletCallV1(status: 50, sequenceLow: 1, sequenceHigh: 0, detail: 0, bytes: Data()))
    let progress = try KagemushaWalletCallV1(status: 51, sequenceLow: 1, sequenceHigh: 0, detail: 0, bytes: Data())
    XCTAssertThrowsError(try KagemushaWalletCollectionStatusV1(progress, expectedSequence: .init(low: 2, high: 0)))
    let fold = try KagemushaWalletCallV1(status: 9, sequenceLow: 1, sequenceHigh: 0, detail: 0, bytes: Data())
    XCTAssertThrowsError(try KagemushaWalletCollectionStatusV1(fold, expectedSequence: .init(low: 1, high: 0)))
  }

  func testActivationAttemptAcceptsOnlyExactBoundedWireWithoutCallerAuthority() throws {
    var wire = Data(repeating: 9, count: 65_536)
    var proof = Data([7])
    let read = try KagemushaWalletSetupInputV1(selector: 37, first: wire)
    let retain = try KagemushaWalletSetupInputV1(selector: 46, first: wire)
    let ingest = try KagemushaWalletSetupInputV1(selector: 36, first: wire, second: proof)
    wire[0] = 0; proof[0] = 0
    XCTAssertEqual(read.first, Data(repeating: 9, count: 65_536))
    XCTAssertEqual(ingest.second, Data([7]))
    XCTAssertEqual(retain.first, read.first)
    XCTAssertNoThrow(try KagemushaWalletSetupInputV1(selector: 36, first: wire, second: Data(repeating: 1, count: 1_327_104)))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 35, first: wire))
    for selector in [UInt32(36), 37, 46] {
      let second = selector == 36 ? Data([1]) : Data()
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, second: second))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, first: Data(repeating: 1, count: 65_537), second: second))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, identity: Data(repeating: 1, count: 32), first: wire, second: second))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, token: 1, first: wire, second: second))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, amount: .init(low: 1, high: 0), first: wire, second: second))
    }
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 36, first: wire))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 36, first: wire, second: Data(repeating: 1, count: 1_327_105)))
    for selector in [UInt32(37), 46] {
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, first: wire, second: Data([1])))
    }
  }

  func testAwaitingCarriesOnlyNativeEntrypointAndNeverImpliesConfirmation() throws {
    let entrypoint = Data(repeating: 3, count: 32)
    let awaiting = try KagemushaWalletCallV1(status: 46, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: entrypoint)
    XCTAssertEqual(try KagemushaWalletLedgerOutcomeV1(awaiting), .awaiting(entrypoint: entrypoint))
    // An offered original never answers Awaiting: it decides the attempt or names an epoch.
    XCTAssertThrowsError(try KagemushaWalletLedgerIngestV1(awaiting))
    XCTAssertThrowsError(try awaiting.completion())
    for bytes in [Data(), Data(repeating: 3, count: 31), Data(repeating: 3, count: 33), Data(repeating: 0, count: 32)] {
      XCTAssertThrowsError(try KagemushaWalletCallV1(status: 46, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: bytes))
    }
    XCTAssertThrowsError(try KagemushaWalletCallV1(status: 46, sequenceLow: 1, sequenceHigh: 0, detail: 0, bytes: entrypoint))
    // The global ledger tip is not an attempt outcome.
    let ledger = try KagemushaWalletCallV1(status: 33, sequenceLow: 1, sequenceHigh: 0, detail: 0, bytes: entrypoint)
    XCTAssertThrowsError(try KagemushaWalletLedgerOutcomeV1(ledger))
  }

  func testAuthenticatedRejectedAttemptNeverConfirmsActivation() throws {
    let result = try KagemushaWalletCallV1(status: 61, sequenceLow: 2, sequenceHigh: 0,
      detail: 0, bytes: Data(repeating: 5, count: 32))
    let commit = KagemushaWalletLedgerCommitV1(height: 2, commitHash: Data(repeating: 5, count: 32))
    XCTAssertEqual(try KagemushaWalletLedgerOutcomeV1(result), .rejected(commit))
    XCTAssertEqual(try KagemushaWalletLedgerIngestV1(result), .outcome(.rejected(commit)))
    XCTAssertThrowsError(try result.completion())
  }

  func testLedgerCommitRejectsMalformedResultAuthority() throws {
    var hash = Data(repeating: 4, count: 32)
    let result = try KagemushaWalletCallV1(status: 62, sequenceLow: 2, sequenceHigh: 0, detail: 0, bytes: hash)
    hash[0] = 0
    guard case .confirmed(let confirmation) = try KagemushaWalletLedgerOutcomeV1(result) else {
      return XCTFail("kind 62 is the confirmed outcome")
    }
    XCTAssertEqual(confirmation.height, 2); XCTAssertEqual(confirmation.commitHash, Data(repeating: 4, count: 32))
    XCTAssertThrowsError(try result.completion()); XCTAssertThrowsError(try result.unloadClaimOriginal())
    let required = try KagemushaWalletCallV1(status: 60, sequenceLow: 3_601, sequenceHigh: 0, detail: 0, bytes: Data())
    XCTAssertEqual(try KagemushaWalletLedgerIngestV1(required), .epochRequired(targetHeight: 3_601))
    XCTAssertThrowsError(try KagemushaWalletLedgerOutcomeV1(required))
    for (low, high, detail, bytes) in [(UInt64(0), UInt64(0), UInt32(0), Data()), (1, 1, 0, Data()), (1, 0, 1, Data()), (1, 0, 0, Data([1]))] {
      XCTAssertThrowsError(try KagemushaWalletCallV1(status: 60, sequenceLow: low, sequenceHigh: high, detail: detail, bytes: bytes))
    }
    for status in [Int32(61), 62] {
      XCTAssertThrowsError(try KagemushaWalletCallV1(status: status, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data(repeating: 1, count: 32)))
      XCTAssertThrowsError(try KagemushaWalletCallV1(status: status, sequenceLow: 2, sequenceHigh: 0, detail: 0, bytes: Data(repeating: 0, count: 32)))
      XCTAssertThrowsError(try KagemushaWalletCallV1(status: status, sequenceLow: 2, sequenceHigh: 1, detail: 0, bytes: Data(repeating: 1, count: 32)))
      XCTAssertThrowsError(try KagemushaWalletCallV1(status: status, sequenceLow: 2, sequenceHigh: 0, detail: 1, bytes: Data(repeating: 1, count: 32)))
      for count in [0, 31, 33] {
        XCTAssertThrowsError(try KagemushaWalletCallV1(status: status, sequenceLow: 2, sequenceHigh: 0, detail: 0, bytes: Data(repeating: 1, count: count)))
      }
    }
    XCTAssertThrowsError(try KagemushaWalletCallV1(status: 62, sequenceLow: 1, sequenceHigh: 0, detail: 0, bytes: Data(repeating: 1, count: 32)))
    XCTAssertThrowsError(try KagemushaWalletCallV1(status: 61, sequenceLow: 1, sequenceHigh: 0, detail: 0, bytes: Data(repeating: 1, count: 32)))
    // The walk's retired Confirmed44/Rejected49 had this exact shape with the Iroha header hash. A
    // Native from before direct finality therefore cannot hand this SDK a terminal outcome.
    for status in [Int32(44), 49] {
      XCTAssertThrowsError(try KagemushaWalletCallV1(status: status, sequenceLow: 2, sequenceHigh: 0, detail: 0, bytes: Data(repeating: 4, count: 32)))
    }
  }

  func testActualDriverCopiesEveryCurrentSetupStatusAndRejectsUnknownStatus() throws {
    let driver = try KagemushaWalletNativeDriverV1()
    // Test only the shared native reply decoder and malloc/free ownership. These bytes
    // are deliberately opaque DATA, not a qualified wallet, signed claim or proof.
    for status in Array(Int32(29)...56) + [61, 62] where ![41, 42, 43, 44, 45, 49].contains(status) {
      let bytes: Data
      switch status {
      case 33, 46, 54, 61, 62: bytes = Data(repeating: 0xa5, count: 32)
      case 53: bytes = Data(repeating: 0xa5, count: 254)
      case 30, 31, 36, 37, 38, 40, 47, 48: bytes = Data(repeating: 0xa5, count: 7)
      default: bytes = Data()
      }
      let result = try driver.result { output in
        output.pointee.status = status
        // Native WalletResult::default uses -1 for an absent failure reason.
        output.pointee.reason = -1
        // Confirmed or rejected ledger attempts require a post-genesis height.
        output.pointee.sequence_low = [61, 62].contains(status) ? 2 : ([33, 37, 38, 39, 53].contains(status) ? 1 : 0)
        output.pointee.length = bytes.count
        if !bytes.isEmpty {
          let allocation = malloc(bytes.count)!.assumingMemoryBound(to: UInt8.self)
          bytes.copyBytes(to: allocation, count: bytes.count)
          output.pointee.bytes = allocation
        }
        return 0
      }
      XCTAssertEqual(result.status, status)
      XCTAssertEqual(result.bytes, bytes)
      XCTAssertThrowsError(try result.completion())
    }
    for status in [Int32(41), 42, 43, 44, 45, 49, 57, 63] {
      XCTAssertThrowsError(try driver.result { output in
        output.pointee.status = status
        output.pointee.reason = -1
        return 0
      }) { error in
        XCTAssertEqual(error as? KagemushaWalletErrorV1, .invalidNativeOutput)
      }
    }
  }

  func testActualDriverRejectsFailureMetadataOnSuccessfulSetupResult() throws {
    let driver = try KagemushaWalletNativeDriverV1()
    let valid = try driver.result { output in
      output.pointee.status = 32 // A valid no-fee reply has no payload or sequence.
      output.pointee.reason = -1
      return 0
    }
    XCTAssertEqual(valid.status, 32)
    for (reason, platformCode) in [(Int32(0), Int32(0)), (1, 0), (-2, 0), (-1, 1), (-1, -1)] {
      XCTAssertThrowsError(try driver.result { output in
        output.pointee.status = 32
        output.pointee.reason = reason
        output.pointee.platform_code = platformCode
        return 0
      }) { error in
        XCTAssertEqual(error as? KagemushaWalletErrorV1, .invalidNativeOutput)
      }
    }
  }

  func testNativeObservationsRejectCollectionAndDeletionResultKinds() throws {
    let driver = try KagemushaWalletNativeDriverV1()
    let original = Data("KWLNV1\0\0".utf8)
    func observe(status: Int32) throws -> Data {
      try driver.observation(selector: 3) { output in
        output.pointee.status = status
        output.pointee.reason = -1
        output.pointee.length = original.count
        let allocation = malloc(original.count)!.assumingMemoryBound(to: UInt8.self)
        original.copyBytes(to: allocation, count: original.count)
        output.pointee.bytes = allocation
        return 0
      }
    }
    XCTAssertEqual(try observe(status: 12), original)
    for status in Int32(50)...56 {
      XCTAssertThrowsError(try observe(status: status)) { error in
        XCTAssertEqual(error as? KagemushaWalletErrorV1, .invalidNativeOutput)
      }
    }
  }

  func testFoldMetricsTextIsBoundedStrictUTF8WithoutInterpretingDiagnosticFields() throws {
    let original = Data(#"{"schema":"iroha.kagemusha.fold-metrics.v1","futureDiagnostic":17}"#.utf8)
    XCTAssertEqual(try KagemushaWalletV1.decodeFoldMetricsJSON(original), String(data: original, encoding: .utf8))
    let maximum = Data(repeating: 0x20, count: 131_072)
    XCTAssertEqual(try KagemushaWalletV1.decodeFoldMetricsJSON(maximum).utf8.count, maximum.count)
    for malformed in [Data(), Data(repeating: 0x20, count: 131_073),
                      Data([0xff]), Data([0xc0, 0xaf]), Data([0xed, 0xa0, 0x80]), Data([0xe2, 0x82])] {
      XCTAssertThrowsError(try KagemushaWalletV1.decodeFoldMetricsJSON(malformed)) { error in
        XCTAssertEqual(error as? KagemushaWalletErrorV1, .invalidNativeOutput)
      }
    }
  }

  func testFoldMetricsObservationHasOnlyItsOwnLargerDATABound() throws {
    let driver = try KagemushaWalletNativeDriverV1()
    func observe(selector: UInt32, count: Int) throws -> Data {
      try driver.observation(selector: selector) { output in
        output.pointee.status = 12
        output.pointee.reason = -1
        output.pointee.length = count
        let bytes = malloc(count)!.assumingMemoryBound(to: UInt8.self)
        bytes.initialize(repeating: 0x20, count: count)
        output.pointee.bytes = bytes
        return 0
      }
    }
    for (selector, bound) in [5_268, 20_134, 20_134, 65_756, 131_072].enumerated() {
      XCTAssertEqual(try observe(selector: UInt32(selector), count: bound).count, bound)
      XCTAssertThrowsError(try observe(selector: UInt32(selector), count: bound + 1)) { error in
        XCTAssertEqual(error as? KagemushaWalletErrorV1, .invalidNativeOutput)
      }
    }
    XCTAssertThrowsError(try KagemushaWalletCallV1(status: 12, sequenceLow: 0, sequenceHigh: 0,
      detail: 0, bytes: Data(repeating: 0x20, count: 131_072))) { error in
      XCTAssertEqual(error as? KagemushaWalletErrorV1, .invalidNativeOutput)
    }
  }

  func testFoldMetricsObservationRejectsForeignResultMetadataAndMissingBytes() throws {
    let driver = try KagemushaWalletNativeDriverV1()
    for field in ["status", "reason", "platform", "sequenceLow", "sequenceHigh", "detail", "empty", "missing"] {
      XCTAssertThrowsError(try driver.observation(selector: 4) { output in
        output.pointee.status = field == "status" ? 29 : 12
        output.pointee.reason = field == "reason" ? 0 : -1
        output.pointee.platform_code = field == "platform" ? 1 : 0
        output.pointee.sequence_low = field == "sequenceLow" ? 1 : 0
        output.pointee.sequence_high = field == "sequenceHigh" ? 1 : 0
        output.pointee.detail = field == "detail" ? 1 : 0
        output.pointee.length = field == "empty" ? 0 : 1
        if field != "missing" {
          let bytes = malloc(1)!.assumingMemoryBound(to: UInt8.self)
          bytes.pointee = 0x20; output.pointee.bytes = bytes
        }
        return 0
      }) { error in
        XCTAssertEqual(error as? KagemushaWalletErrorV1, .invalidNativeOutput, field)
      }
    }
  }

  func testFoldMetricsObservationRejectsUnknownSelectorBeforeCallingNative() throws {
    let driver = try KagemushaWalletNativeDriverV1()
    for selector in [UInt32(5), .max] {
      var called = false
      XCTAssertThrowsError(try driver.observation(selector: selector) { _ in
        called = true; return 0
      }) { error in
        XCTAssertEqual(error as? KagemushaWalletErrorV1, .invalidInput)
      }
      XCTAssertFalse(called)
    }
  }

  func testActualFoldMetricsObservationRefusesUnknownOwnerAndForeignIdentity() throws {
    let driver = try KagemushaWalletNativeDriverV1()
    XCTAssertThrowsError(try driver.observation(selector: 4) { output in
      driver.observe(0, 4, nil, 0, output)
    }) { error in
      XCTAssertEqual(error as? KagemushaWalletErrorV1, .closed)
    }
    let foreignIdentity = Data(repeating: 1, count: 32)
    XCTAssertThrowsError(try driver.observation(selector: 4) { output in
      foreignIdentity.withUnsafeBytes {
        driver.observe(0, 4, $0.bindMemory(to: UInt8.self).baseAddress, $0.count, output)
      }
    })
  }

  func testActualNativeUnloadSelectorRefusesUnknownOwnerWithoutClaimBytes() throws {
    let driver = try KagemushaWalletNativeDriverV1()
    let input = try KagemushaWalletSetupInputV1(selector: 45, identity: Data(repeating: 9, count: 32))
    XCTAssertThrowsError(try driver.result { output in
      input.withRequest { driver.setup(0, $0, output) }
    }) { error in
      XCTAssertEqual(error as? KagemushaWalletErrorV1, .closed)
    }
  }

  func testActualNativeDeliverySelectorsRefuseUnknownOwnerWithoutReceiptBytes() throws {
    let driver = try KagemushaWalletNativeDriverV1()
    // Opaque DATA only: an admitted request shape reaches the missing-owner check,
    // before any wallet, receipt proof, or monetary operation can run.
    for selector in [UInt32(54), 55] {
      for count in [1, 10_034] {
        let input = try KagemushaWalletSetupInputV1(selector: selector,
          identity: Data(repeating: selector == 54 ? 9 : 0, count: 32),
          first: Data(repeating: 0xa5, count: count))
        XCTAssertThrowsError(try driver.result { output in
          input.withRequest { request in
            let status = driver.setup(0, request, output)
            XCTAssertEqual(status, -2, "selector \(selector), first length \(count)")
            XCTAssertEqual(output.pointee.status, -2)
            XCTAssertEqual(output.pointee.reason, -1)
            XCTAssertEqual(output.pointee.platform_code, 0)
            XCTAssertEqual(output.pointee.sequence_low, 0)
            XCTAssertEqual(output.pointee.sequence_high, 0)
            XCTAssertEqual(output.pointee.detail, 0)
            XCTAssertNil(output.pointee.bytes)
            XCTAssertEqual(output.pointee.length, 0)
            return status
          }
        }) { error in
          XCTAssertEqual(error as? KagemushaWalletErrorV1, .closed)
        }
      }
    }
  }

  func testActualNativeDeliverySelectorsRejectForeignScalarsAndUnknownSelector() throws {
    let driver = try KagemushaWalletNativeDriverV1()
    for selector in [UInt32(54), 55] {
      let input = try KagemushaWalletSetupInputV1(selector: selector,
        identity: Data(repeating: selector == 54 ? 9 : 0, count: 32), first: Data([0xa5]))
      for field in ["token", "amount.low", "amount.high", "selector"] {
        XCTAssertThrowsError(try driver.result { output in
          input.withRequest { request in
            // Copy only the C value; all borrowed buffers stay alive in withRequest.
            // No pointer or length mutation is needed to exercise Native intake.
            var malformed = request.pointee
            switch field {
            case "token": malformed.token = 1
            case "amount.low": malformed.amount.low = 1
            case "amount.high": malformed.amount.high = 1
            default: malformed.selector = 56
            }
            let status = driver.setup(0, &malformed, output)
            XCTAssertEqual(status, -1, "selector \(selector), invalid \(field)")
            XCTAssertEqual(output.pointee.status, -1)
            XCTAssertEqual(output.pointee.reason, -1)
            XCTAssertEqual(output.pointee.platform_code, 0)
            XCTAssertEqual(output.pointee.sequence_low, 0)
            XCTAssertEqual(output.pointee.sequence_high, 0)
            XCTAssertEqual(output.pointee.detail, 0)
            XCTAssertNil(output.pointee.bytes)
            XCTAssertEqual(output.pointee.length, 0)
            return status
          }
        }) { error in
          XCTAssertEqual(error as? KagemushaWalletErrorV1,
            .native(status: -1, reason: -1, platformCode: 0))
        }
      }
    }
  }

  func testUnloadClaimRequiresRetainedIdentityAndPreservesNativeData() throws {
    let id = Data(repeating: 7, count: 32)
    XCTAssertNoThrow(try KagemushaWalletSetupInputV1(selector: 45, identity: id))
    XCTAssertNoThrow(try KagemushaWalletSetupInputV1(selector: 45, identity: id, first: Data(repeating: 1, count: 16_384)))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 45))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 45, identity: id, first: Data(repeating: 1, count: 16_385)))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 45, identity: id, second: Data([1])))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 45, identity: id, token: 1))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 45, identity: id, amount: .init(low: 1, high: 0)))
    let bytes = Data(repeating: 255, count: 16_384)
    let result = try KagemushaWalletCallV1(status: 48, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: bytes)
    XCTAssertEqual(try result.unloadClaimOriginal(), bytes)
    let enrollment = try KagemushaWalletCallV1(status: 37, sequenceLow: 1, sequenceHigh: 0, detail: 0, bytes: Data([1]))
    XCTAssertThrowsError(try enrollment.unloadClaimOriginal())
    let activation = try KagemushaWalletCallV1(status: 62, sequenceLow: 2, sequenceHigh: 0, detail: 0, bytes: Data(repeating: 1, count: 32))
    XCTAssertThrowsError(try activation.unloadClaimOriginal())
    XCTAssertThrowsError(try result.completion()); XCTAssertThrowsError(try result.feeClaimOriginal())
    XCTAssertThrowsError(try KagemushaWalletCallV1(status: 48, sequenceLow: 1, sequenceHigh: 0, detail: 0, bytes: Data([1])))
    XCTAssertThrowsError(try KagemushaWalletCallV1(status: 48, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data(repeating: 1, count: 16_385)))
  }

  func testCreditProjectionCannotBecomeUnloadClaim() throws {
    let projection = try KagemushaWalletCallV1(status: 47, sequenceLow: 0, sequenceHigh: 0,
      detail: 0, bytes: Data(repeating: 1, count: 10_126))
    XCTAssertThrowsError(try projection.unloadClaimOriginal())
    XCTAssertThrowsError(try projection.completion())
    XCTAssertThrowsError(try KagemushaWalletCallV1(status: 47, sequenceLow: 0, sequenceHigh: 0,
      detail: 0, bytes: Data(repeating: 1, count: 10_127)))
    XCTAssertThrowsError(try KagemushaWalletCallV1(status: 47, sequenceLow: 1, sequenceHigh: 0,
      detail: 0, bytes: projection.bytes))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 38,
      identity: Data(repeating: 1, count: 32)))
  }

  func testLedgerProducerRequestsPreserveTermsAndRejectAuthorityInUnusedFields() throws {
    let id = Data(repeating: 7, count: 32)
    let load = try KagemushaWalletSetupInputV1(selector: 27, identity: id, amount: .init(low: .max, high: .max))
    XCTAssertEqual(load.amount.high, .max)
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 27, identity: id))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 27, identity: id, amount: .init(low: 1, high: 0), first: Data([1])))
    for selector in [UInt32(28), 31, 32] {
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, first: Data([1]), second: Data([2])))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, first: Data([1])))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, identity: id, first: Data([1]), second: Data([2])))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, first: Data(repeating: 1, count: 513), second: Data([2])))
    }
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 28, first: Data([1]), second: Data(repeating: 1, count: 8193)))
    for kind in UInt64(1)...3 { XCTAssertNoThrow(try KagemushaWalletSetupInputV1(selector: 29, token: kind, first: Data([1]))) }
    for kind in [UInt64(0), 4] { XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 29, token: kind, first: Data([1]))) }
    for identity in [id, Data(repeating: 0, count: 32)] {
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 30, identity: identity, first: Data([1])))
    }
    XCTAssertNoThrow(try KagemushaWalletSetupInputV1(selector: 33, first: Data([1]), second: Data([2])))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 33, identity: id, first: Data([1]), second: Data([2])))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 33, first: Data([1])))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 33, second: Data([2])))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 33, first: Data([1]), second: Data([2]), third: Data([3])))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 33, first: Data(repeating: 1, count: 16_385), second: Data([2])))
    XCTAssertNoThrow(try KagemushaWalletSetupInputV1(selector: 34, first: Data([1]), second: Data([2]), third: Data([3])))
    XCTAssertNoThrow(try KagemushaWalletSetupInputV1(selector: 34, first: Data([1]), second: Data([2]), third: Data(repeating: 3, count: 1_327_104)))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 34, identity: id, first: Data([1]), second: Data([2]), third: Data([3])))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 34, first: Data([1]), second: Data([2])))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 34, first: Data([1]), second: Data([2]), third: Data(repeating: 3, count: 1_327_105)))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 31, first: Data([1])))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 31))
  }
  func testRetiredServerProvingAndWalkResultsAreRefused() throws {
    for status in [Int32(41), 42, 43, 45] {
      for bytes in [Data(), Data([1]), Data(repeating: 2, count: 8)] {
        XCTAssertThrowsError(try KagemushaWalletCallV1(status: status, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: bytes))
        XCTAssertThrowsError(try KagemushaWalletCallV1(status: status, sequenceLow: 7, sequenceHigh: 0, detail: 0, bytes: bytes))
      }
    }
    XCTAssertThrowsError(try KagemushaWalletCallV1(status: 42, sequenceLow: 7, sequenceHigh: 0, detail: 0, bytes: Data(repeating: 9, count: 32)))
    for (status, maximum) in [(Int32(40), 65_536)] {
      XCTAssertNoThrow(try KagemushaWalletCallV1(status: status, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data(repeating: 1, count: maximum)))
      XCTAssertThrowsError(try KagemushaWalletCallV1(status: status, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data(repeating: 1, count: maximum + 1)))
      XCTAssertThrowsError(try KagemushaWalletCallV1(status: status, sequenceLow: 1, sequenceHigh: 0, detail: 0, bytes: Data([1])))
    }
  }
  func testFeeClaimTransportPreservesNativeBytesAndRejectsUnusedAuthority() throws {
    let retained = try KagemushaWalletCallV1(status: 31, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data([0, 255, 7]))
    let beneficiary = Data([3, 0, 255])
    let input = try retained.feeClaimInput(beneficiary: beneficiary)
    XCTAssertEqual(input.selector, 26); XCTAssertEqual(input.first, retained.bytes)
    XCTAssertEqual(input.second, beneficiary); XCTAssertTrue(input.third.isEmpty)
    XCTAssertThrowsError(try retained.feeClaimInput(beneficiary: Data()))
    XCTAssertThrowsError(try retained.feeClaimInput(beneficiary: Data(repeating: 1, count: 16_385)))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 26, identity: Data(repeating: 1, count: 32), first: retained.bytes, second: beneficiary))
    let bytes = Data(repeating: 255, count: 16_384)
    let result = try KagemushaWalletCallV1(status: 36, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: bytes)
    XCTAssertEqual(try result.feeClaimOriginal(), bytes)
    XCTAssertThrowsError(try result.completion()); XCTAssertThrowsError(try result.original())
    XCTAssertThrowsError(try KagemushaWalletCallV1(status: 36, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data(repeating: 1, count: 16_385)))
    XCTAssertThrowsError(try KagemushaWalletCallV1(status: 36, sequenceLow: 1, sequenceHigh: 0, detail: 0, bytes: Data([1])))
  }

  func testFeeAndLedgerBoundariesKeepOriginalsSeparateFromAcknowledgement() throws {
    let id = Data(repeating: 7, count: 32)
    XCTAssertNoThrow(try KagemushaWalletSetupInputV1(selector: 20, identity: id))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 20))
    for selector in UInt32(21)...23 {
      XCTAssertNoThrow(try KagemushaWalletSetupInputV1(selector: selector, first: Data([1])))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, identity: id, first: Data([1])))
    }
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 21, first: Data(repeating: 1, count: 21_093)))
    XCTAssertNoThrow(try KagemushaWalletSetupInputV1(selector: 24))
    XCTAssertNoThrow(try KagemushaWalletSetupInputV1(selector: 25, identity: id, first: Data([1]), second: Data([2])))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 25, identity: id, first: Data([1])))
    for status in Int32(31)...35 {
      let bytes = status == 31 ? Data(repeating: 1, count: 21_092) : status == 33 ? id : Data()
      let result = try KagemushaWalletCallV1(status: status, sequenceLow: status == 33 ? .max : 0, sequenceHigh: 0, detail: 0, bytes: bytes)
      XCTAssertThrowsError(try result.completion())
      if status == 33 { XCTAssertEqual(try KagemushaWalletLedgerProgressV1(result).height, UInt64.max) }
    }
    XCTAssertThrowsError(try KagemushaWalletCallV1(status: 31, sequenceLow: 1, sequenceHigh: 0, detail: 0, bytes: Data([1])))
    XCTAssertThrowsError(try KagemushaWalletCallV1(status: 33, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: id))
    XCTAssertThrowsError(try KagemushaWalletCallV1(status: 35, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: id))
    let claim = KagemushaWalletFeeClaimV1(payment: id, request: Data([2]))
    XCTAssertEqual(claim.payment, id); XCTAssertEqual(claim.request, Data([2]))
  }

  func testCreditedProjectionSelectsOnlyDurableReceiveOrStatusBytes() throws {
    for (status, selector) in [(Int32(1), UInt32(16)), (10, 17)] {
      let result = try KagemushaWalletCallV1(status: status, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data([0, 255, 1]))
      let input = try result.creditedInput()
      XCTAssertEqual(input.selector, selector)
      XCTAssertEqual(input.first, result.bytes)
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, first: Data(repeating: 1, count: 10_035)))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, token: 1, first: result.bytes))
    }
    for status in [Int32(0), 2, 3, 4, 5, 6, 7, 8, 9, 11, 12] {
      let call = try KagemushaWalletCallV1(status: status, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: status == 12 ? Data([1]) : Data())
      XCTAssertThrowsError(try call.creditedInput())
    }
  }
  func testBackgroundStatusIsSeparateFromCompletionAndPreservesUnsignedBacklog() throws {
    XCTAssertNoThrow(try KagemushaWalletSetupInputV1(selector: 18))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 18, first: Data([1])))
    for phase in UInt32(0)...2 {
      let call = try KagemushaWalletCallV1(status: 29, sequenceLow: .max, sequenceHigh: 2, detail: phase | 12, bytes: Data())
      let status = try KagemushaWalletBackgroundStatusV1(call)
      XCTAssertEqual(status.phase.rawValue, phase)
      XCTAssertTrue(status.eligible)
      XCTAssertEqual(status.observedBacklog, .init(low: .max, high: 2))
      XCTAssertThrowsError(try call.completion())
    }
    let unobserved = try KagemushaWalletCallV1(status: 29, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data())
    XCTAssertNil(try KagemushaWalletBackgroundStatusV1(unobserved).observedBacklog)
    for detail in [UInt32(3), 16] {
      let bad = try KagemushaWalletCallV1(status: 29, sequenceLow: 0, sequenceHigh: 0, detail: detail, bytes: Data())
      XCTAssertThrowsError(try KagemushaWalletBackgroundStatusV1(bad))
    }
    let unknown = try KagemushaWalletCallV1(status: 29, sequenceLow: 1, sequenceHigh: 0, detail: 0, bytes: Data())
    XCTAssertThrowsError(try KagemushaWalletBackgroundStatusV1(unknown))
  }
  func testCloseLoadsTransportHasNoForeignBodyAndSeparateResult() throws {
    XCTAssertNoThrow(try KagemushaWalletSetupInputV1(selector: 19, identity: Data(repeating: 1, count: 32)))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 19, identity: Data(repeating: 1, count: 32), first: Data([1])))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 19))
    let valid = try KagemushaWalletCallV1(status: 30, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data(repeating: 1, count: 16_384))
    XCTAssertThrowsError(try valid.completion())
    for count in [0, 16_385] { XCTAssertThrowsError(try KagemushaWalletCallV1(status: 30, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data(repeating: 1, count: count))) }
    XCTAssertThrowsError(try KagemushaWalletCallV1(status: 30, sequenceLow: 1, sequenceHigh: 0, detail: 0, bytes: Data([1])))
  }
  func testActivationTransportHasItsOwnBoundAndNoForeignInputs() throws {
    XCTAssertNoThrow(try KagemushaWalletSetupInputV1(selector: 15))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 15, first: Data([1])))
    XCTAssertNoThrow(try KagemushaWalletCallV1(status: 17, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data(repeating: 1, count: 16_384)))
    for count in [0, 16_385] { XCTAssertThrowsError(try KagemushaWalletCallV1(status: 17, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data(repeating: 1, count: count))) }
    XCTAssertThrowsError(try KagemushaWalletCallV1(status: 17, sequenceLow: 1, sequenceHigh: 0, detail: 0, bytes: Data([1])))
    XCTAssertThrowsError(try KagemushaWalletCallV1(status: 1, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data(repeating: 1, count: 10_035)))
  }
  func testTypedSetupHasExactUnusedFieldsAndUnsignedAmount() throws {
    let id = Data(repeating: 7, count: 32)
    let request = try KagemushaWalletSetupInputV1(selector: 2, identity: id, amount: .init(low: .max, high: .max))
    request.withRequest {
      XCTAssertEqual($0.pointee.selector, 2)
      XCTAssertEqual($0.pointee.amount.high, .max)
      XCTAssertEqual($0.pointee.amount.low, .max)
      XCTAssertEqual($0.pointee.token, 0)
      XCTAssertEqual($0.pointee.first_length, 0)
    }
    XCTAssertNoThrow(try KagemushaWalletSetupInputV1(selector: 0))
    XCTAssertNoThrow(try KagemushaWalletSetupInputV1(selector: 4))
    XCTAssertNoThrow(try KagemushaWalletSetupInputV1(selector: 6, token: 1))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 6))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 6, token: 1, first: Data([1])))
    XCTAssertNoThrow(try KagemushaWalletSetupInputV1(selector: 2, identity: id, amount: .init(low: 1, high: 0)))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 2, identity: id, first: Data([1]), second: Data([2])))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 2, identity: id, first: Data([1]), second: Data([2]), third: Data(repeating: 1, count: 513)))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 4, identity: id))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 5, token: 0, first: Data([1]), second: Data([1])))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 2, identity: id))
    for selector in [UInt32(8), 9, 10, 12, 13, 14] {
      XCTAssertNoThrow(try KagemushaWalletSetupInputV1(selector: selector, first: Data([1])))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, first: Data(repeating: 1, count: 10_035)))
    }
  }
  func testSetupResultsKeepTimeChallengeSeparateFromCompletion() throws {
    let challenge = try KagemushaWalletCallV1(status: 13, sequenceLow: 7, sequenceHigh: 0, detail: 0, bytes: Data(repeating: 1, count: 32))
    XCTAssertEqual(challenge.status, 13)
    XCTAssertNoThrow(try KagemushaWalletCallV1(status: 12, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data([1])))
    XCTAssertNoThrow(try KagemushaWalletCallV1(status: 14, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data()))
    for count in [0, 31, 33] {
      XCTAssertThrowsError(try KagemushaWalletCallV1(status: 13, sequenceLow: 7, sequenceHigh: 0, detail: 0, bytes: Data(repeating: 1, count: count)))
    }
    XCTAssertThrowsError(try KagemushaWalletCallV1(status: 13, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data(repeating: 1, count: 32)))
  }
  func testValidSetupAndOpenResultsCannotBecomeMonetaryCompletion() throws {
    for status in Int32(12)...17 {
      let sequence: UInt64 = [13, 15, 16].contains(status) ? 1 : 0
      let bytes = [14, 16].contains(status) ? Data()
        : Data(repeating: 1, count: [13, 15].contains(status) ? 32 : 1)
      let result = try KagemushaWalletCallV1(status: status, sequenceLow: sequence,
        sequenceHigh: 0, detail: 0, bytes: bytes)
      XCTAssertThrowsError(try result.completion()) { error in
        XCTAssertEqual(error as? KagemushaWalletErrorV1, .invalidNativeOutput)
      }
    }
  }
  func testFeePolicyOriginalsArePairedAndRetainedWithoutReinterpretation() throws {
    let id = Data(repeating: 7, count: 32), amount = KagemushaWalletUInt128V1(low: 7, high: 8)
    var schedule = Data(repeating: 2, count: 10_034), certificates = Data(repeating: 3, count: 10_034)
    let input = try KagemushaWalletSetupInputV1.requestWithFeePolicy(identity: id, amount: amount,
      schedule: schedule, certificates: certificates)
    schedule[0] = 9; certificates[0] = 9
    input.withRequest { request in
      XCTAssertEqual(request.pointee.selector, 39)
      XCTAssertEqual(Data(bytes: request.pointee.setup_id!, count: 32), id)
      XCTAssertEqual(request.pointee.amount.low, 7)
      XCTAssertEqual(request.pointee.amount.high, 8)
      XCTAssertEqual(Data(bytes: request.pointee.first!, count: 10_034), Data(repeating: 2, count: 10_034))
      XCTAssertEqual(Data(bytes: request.pointee.second!, count: 10_034), Data(repeating: 3, count: 10_034))
      XCTAssertEqual(request.pointee.third_length, 0)
    }
    XCTAssertNoThrow(try KagemushaWalletSetupInputV1.requestWithFeePolicy(identity: id, amount: amount,
      schedule: nil, certificates: nil))
    for (schedule, certificates) in [(Data([1]) as Data?, nil as Data?), (nil, Data([1])),
      (Data(), Data()), (Data(), Data([1])), (Data([1]), Data()),
      (Data(repeating: 1, count: 10_035), Data([1])), (Data([1]), Data(repeating: 1, count: 10_035))] {
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1.requestWithFeePolicy(identity: id, amount: amount,
        schedule: schedule, certificates: certificates))
    }
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1.requestWithFeePolicy(identity: id,
      amount: .init(low: 0, high: 0), schedule: nil, certificates: nil))
    XCTAssertNoThrow(try KagemushaWalletSetupInputV1(selector: 38))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 38, identity: id))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 38, first: schedule))
    XCTAssertNoThrow(try KagemushaWalletSetupInputV1(selector: 40, first: schedule, second: certificates))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 40, identity: id, first: schedule, second: certificates))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 40, first: schedule))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 40, first: schedule, second: certificates, third: Data([1])))
    for selector in [UInt32(38), 40] {
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector,
        amount: amount, first: selector == 38 ? Data() : schedule, second: selector == 38 ? Data() : certificates))
    }
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 39, identity: id, amount: amount,
      token: 1, first: schedule, second: certificates))
  }

  func testPaymentCompanionSelectorIsBoundedAndCannotCarryForeignAuthority() throws {
    let payment = Data(repeating: 5, count: 10_034)
    let input = try KagemushaWalletSetupInputV1(selector: 55, first: payment)
    input.withRequest { request in
      XCTAssertEqual(request.pointee.selector, 55)
      XCTAssertEqual(request.pointee.first_length, payment.count)
      XCTAssertEqual(Data(bytes: request.pointee.first!, count: payment.count), payment)
    }
    for invalid in [Data(), Data(repeating: 1, count: 10_035)] {
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 55, first: invalid))
    }
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 55, identity: Data(repeating: 1, count: 32), first: payment))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 55, amount: .init(low: 1, high: 0), first: payment))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 55, first: payment, second: Data([1])))
  }

  func testNativeFeeSelectionHasExactDigestGeometryAndIsOnlyData() throws {
    let asset = Data(repeating: 7, count: 32), zeroFee = Data(repeating: 0, count: 32)
    let call = try KagemushaWalletCallV1(status: 12, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: asset + zeroFee)
    let selection = try KagemushaWalletRequestFeeSelectionV1(call)
    XCTAssertEqual(selection.assetDigest, asset); XCTAssertEqual(selection.feeDigest, zeroFee)
    XCTAssertThrowsError(try call.completion())
    for count in [1, 63, 65] {
      let malformed = try KagemushaWalletCallV1(status: 12, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data(repeating: 7, count: count))
      XCTAssertThrowsError(try KagemushaWalletRequestFeeSelectionV1(malformed))
    }
    let completion = try KagemushaWalletCallV1(status: 1, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: asset + zeroFee)
    XCTAssertThrowsError(try KagemushaWalletRequestFeeSelectionV1(completion))
  }

  func testCreditedArchiveRequestsBindTheSelectedSendAndKeepExactOriginal() throws {
    let id = Data(repeating: 7, count: 32), original = Data([0, 255, 1])
    for selector in [UInt32(41), 42] {
      let input = try KagemushaWalletSetupInputV1(selector: selector, identity: id, first: original)
      input.withRequest { request in
        XCTAssertEqual(request.pointee.selector, selector)
        XCTAssertEqual(Data(bytes: request.pointee.setup_id!, count: 32), id)
        XCTAssertEqual(Data(bytes: request.pointee.first!, count: request.pointee.first_length), original)
      }
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, first: original))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, identity: id))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, identity: id, first: Data(repeating: 1, count: 10_035)))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, identity: id, first: original, second: original))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, identity: id, first: original, third: original))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, identity: id, amount: .init(low: 1, high: 0), first: original))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, identity: id, token: 1, first: original))
    }
  }

}
