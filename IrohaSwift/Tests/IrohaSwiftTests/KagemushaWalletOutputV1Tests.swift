import XCTest
@testable import IrohaSwift

final class KagemushaWalletOutputV1Tests: XCTestCase {
  // Projection DATA only; no test fixture installs an owner or claims financial validity.
  private func metadata() -> Data {
    var bytes = Array("KWMDV1".utf8) + [0,0]
    bytes += [2,0,0,0]; bytes += Array(repeating: UInt8(7), count: 128)
    bytes += [2,0,0,0,3,0,0,0,11,12,21,22,23]
    return Data(bytes)
  }
  private func output(_ family: UInt8, _ peer: UInt8) -> Data {
    var bytes = Array("KWROV1".utf8) + [0,0,family]
    bytes += Array(repeating: UInt8(7), count: 32)
    bytes += Array(repeating: UInt8(255), count: 16)
    bytes += [2,0,0,0,peer,peer == 0 ? 0 : 2,0,0,0,11,12]
    if peer != 0 { bytes += [11,12] }
    return Data(bytes)
  }
  func testMetadataRetainsExactBoundedOriginalsAndScale() throws {
    let value = try KagemushaWalletMetadataV1(metadata())
    XCTAssertEqual(value.assetScale, 2); XCTAssertEqual(value.accountOriginal, Data([11,12]))
    XCTAssertEqual(value.assetOriginal, Data([21,22,23]))
    for offset in [0,8,140,144] { var bytes = metadata(); bytes[offset] = 255
      XCTAssertThrowsError(try KagemushaWalletMetadataV1(bytes)) }
    for count in [0,8,147,150] { XCTAssertThrowsError(try KagemushaWalletMetadataV1(metadata().prefix(count))) }
    var trailing = metadata(); trailing.append(0); XCTAssertThrowsError(try KagemushaWalletMetadataV1(trailing))
  }
  func testReleasedSendAndReceiveCarryOnlyTheirOwnPeerKind() throws {
    let send = try KagemushaWalletReleasedOutputV1(output(3,3))
    XCTAssertEqual(send.kind, .send); XCTAssertEqual(send.peerKind, .payment)
    XCTAssertEqual(send.original, send.peerOriginal); XCTAssertEqual(send.sequence.high, UInt64.max)
    let receive = try KagemushaWalletReleasedOutputV1(output(4,4))
    XCTAssertEqual(receive.peerKind, .credited)
    for pair: (UInt8, UInt8) in [(3,4),(4,3),(6,3),(3,0),(4,0),(9,0)] {
      XCTAssertThrowsError(try KagemushaWalletReleasedOutputV1(output(pair.0,pair.1))) }
    var changed = output(3,3); changed[changed.count-1] ^= 1
    XCTAssertThrowsError(try KagemushaWalletReleasedOutputV1(changed))
  }
  func testOtherFamiliesNeverManufacturePeerEvidenceOrAcceptWrongLengths() throws {
    for kind: UInt8 in [1,2,5,6,7,8] {
      let value = try KagemushaWalletReleasedOutputV1(output(kind,0))
      XCTAssertNil(value.peerOriginal); XCTAssertNil(value.peerKind)
    }
    var missing = output(4,4); missing.removeLast(); XCTAssertThrowsError(try KagemushaWalletReleasedOutputV1(missing))
    var overlong = output(4,4); overlong.append(1); XCTAssertThrowsError(try KagemushaWalletReleasedOutputV1(overlong))
    var emptyOriginal = output(6,0); emptyOriginal[57] = 0
    XCTAssertThrowsError(try KagemushaWalletReleasedOutputV1(emptyOriginal))
  }
  func testLoadObservationAbsenceIsExplicitAndDoesNotReuseGlobalResultKinds() throws {
    let identity = Data(repeating: 7, count: 32)
    let absent = Data([75,87,76,78,86,49,0,0])
    XCTAssertNil(try KagemushaWalletPreparedLoadV1.observation(absent, requestID: identity))
    for invalid in [Data(), absent + Data([0]), Data(absent.dropLast()), Data("KWLPV1\0\0".utf8)] {
      XCTAssertThrowsError(try KagemushaWalletPreparedLoadV1.observation(invalid, requestID: identity))
    }
    XCTAssertThrowsError(try KagemushaWalletPreparedLoadV1.observation(absent, requestID: Data(repeating: 0, count: 32)))
    for status: Int32 in [50, 51, 52] {
      XCTAssertThrowsError(try KagemushaWalletCallV1(status: status, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: absent))
    }
    XCTAssertThrowsError(try KagemushaWalletMetadataV1(absent))
    XCTAssertThrowsError(try KagemushaWalletReleasedOutputV1(absent))
  }
  func testPreparedLoadObservationRequiresExactRetainedRequest() throws {
    var bytes = Data("KWLPV1\0\0".utf8)
    for value: UInt8 in [1,2,3,4,5] { bytes.append(Data(repeating: value, count: 32)) }
    bytes.append(Data(repeating: 0, count: 16))
    bytes.append(Data([1] + Array(repeating: 0, count: 15)))
    bytes.append(Data(repeating: 0, count: 16))
    bytes.append(Data([1,0,0,0,99]))
    let result = try XCTUnwrap(KagemushaWalletPreparedLoadV1.observation(bytes, requestID: Data(repeating: 1, count: 32)))
    XCTAssertEqual(result.amount.low, 1); XCTAssertEqual(result.instructionOriginal, Data([99]))
    XCTAssertThrowsError(try KagemushaWalletPreparedLoadV1.observation(bytes, requestID: Data(repeating: 2, count: 32)))
    var zeroAmount = bytes; zeroAmount[184] = 0
    XCTAssertThrowsError(try KagemushaWalletPreparedLoadV1.observation(zeroAmount, requestID: Data(repeating: 1, count: 32)))
    for offset in [0, 8, 200, 216] { var mutated = bytes; mutated[offset] ^= 255
      XCTAssertThrowsError(try KagemushaWalletPreparedLoadV1.observation(mutated, requestID: Data(repeating: 1, count: 32))) }
  }

}
