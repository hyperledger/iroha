import Foundation
import NoritoBridge

/// Exact original admission DATA copied from the live Native owner.
public struct KagemushaWalletMetadataV1: Equatable, Sendable {
  public let schemeID: Data
  public let walletID: Data
  public let assetDigest: Data
  public let accountDigest: Data
  public let assetScale: UInt32
  public let accountOriginal: Data
  public let assetOriginal: Data
  init(_ original: Data) throws {
    let bytes = [UInt8](original)
    guard (150...5_268).contains(bytes.count), Array(bytes[0..<8]) == [75,87,77,68,86,49,0,0]
    else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    func u32(_ at: Int) -> UInt32 { var result: UInt32 = 0; for i in 0..<4 { result |= UInt32(bytes[at+i]) << (8*i) }; return result }
    let scale = u32(8), accountLength = Int(u32(140)), assetLength = Int(u32(144))
    guard scale <= 28, (1...4_096).contains(accountLength), (1...1_024).contains(assetLength),
      bytes.count == 148 + accountLength + assetLength,
      [12,44,76,108].allSatisfy({ bytes[$0..<($0+32)].contains(where: { $0 != 0 }) })
    else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    assetScale = scale; schemeID = Data(bytes[12..<44]); walletID = Data(bytes[44..<76])
    assetDigest = Data(bytes[76..<108]); accountDigest = Data(bytes[108..<140])
    accountOriginal = Data(bytes[148..<(148+accountLength)])
    assetOriginal = Data(bytes[(148+accountLength)..<bytes.count])
  }
}

/// The actual released operation and its exact output. This is observation DATA, not a retry capability.
public struct KagemushaWalletReleasedOutputV1: Sendable {
  public enum Kind: UInt8, Sendable {
    case bootstrap = 1, load = 2, send = 3, receive = 4, archiveSent = 5, unload = 6, refreshPolicy = 7, retiring = 8
  }
  public let operationID: Data
  public let kind: Kind
  public let sequence: KagemushaWalletUInt128V1
  /// Exact source-retained Payment for Send, Package for the other families.
  public let original: Data
  /// Payment for Send, Credited for Receive, absent for all other families.
  public let peerKind: KagemushaWalletTransportKindV1?
  public let peerOriginal: Data?
  init(_ original: Data) throws {
    let bytes = [UInt8](original)
    guard (67...20_066).contains(bytes.count), Array(bytes[0..<8]) == [75,87,82,79,86,49,0,0],
      let family = Kind(rawValue: bytes[8]), bytes[9..<41].contains(where: { $0 != 0 })
    else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    func u32(_ at: Int) -> UInt32 { var result: UInt32 = 0; for i in 0..<4 { result |= UInt32(bytes[at+i]) << (8*i) }; return result }
    func u64(_ at: Int) -> UInt64 { var result: UInt64 = 0; for i in 0..<8 { result |= UInt64(bytes[at+i]) << (8*i) }; return result }
    let originalLength = Int(u32(57)), peerLength = Int(u32(62)), peerTag = bytes[61]
    let expectedPeer: UInt8 = family == .send ? 3 : (family == .receive ? 4 : 0)
    guard (1...10_000).contains(originalLength), peerLength <= 10_000,
      bytes.count == 66 + originalLength + peerLength, peerTag == expectedPeer,
      (peerTag == 0) == (peerLength == 0)
    else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    let released = Data(bytes[66..<(66+originalLength)])
    let peer = peerTag == 0 ? nil : Data(bytes[(66+originalLength)..<bytes.count])
    guard family != .send || peer == released else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    kind = family; operationID = Data(bytes[9..<41]); sequence = .init(low: u64(41), high: u64(49))
    self.original = released; peerKind = peerTag == 0 ? nil : KagemushaWalletTransportKindV1(rawValue: UInt32(peerTag))
    peerOriginal = peer
  }
}

extension CanonicalNorito {
  /// Full current Rust canonical AccountId frame for the exact I105 literal.
  /// Native review still authenticates this original against the signed receiver digest.
  public static func encodeAccountOriginal(_ value: String) throws -> Data {
    let literal = Data(value.utf8)
    guard !literal.isEmpty, literal.count <= 4_096 else { throw KagemushaWalletErrorV1.invalidInput }
    let driver = try KagemushaWalletNativeDriverV1()
    let result = try driver.result { result in
      literal.withUnsafeBytes { driver.accountOriginal($0.bindMemory(to: UInt8.self).baseAddress, $0.count, result) }
    }
    let original = try result.original()
    guard original.count <= 4_096 else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    return original
  }
}


extension CanonicalNorito {
  /// Render an exact full AccountId original using the current Rust address codec.
  /// Select networkPrefix independently from the authenticated installed network.
  public static func renderAccountOriginal(_ original: Data, networkPrefix: UInt16) throws -> String {
    guard !original.isEmpty, original.count <= 4_096 else { throw KagemushaWalletErrorV1.invalidInput }
    let driver = try KagemushaWalletNativeDriverV1()
    let result = try driver.result { result in
      original.withUnsafeBytes { driver.accountDisplay($0.bindMemory(to: UInt8.self).baseAddress,
        $0.count, networkPrefix, result) }
    }
    let bytes = try result.original()
    guard bytes.count <= 4_096, let text = String(data: bytes, encoding: .utf8), !text.isEmpty
    else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    return text
  }
}

/// Exact immutable terms copied from the one canonical Native ledger Load plan.
public struct KagemushaWalletPreparedLoadV1: Equatable, Sendable {
  public let requestID: Data
  public let schemeID: Data
  public let walletID: Data
  public let assetDigest: Data
  public let payerAccountDigest: Data
  public let ordinal: KagemushaWalletUInt128V1
  public let amount: KagemushaWalletUInt128V1
  public let onlineCharge: KagemushaWalletUInt128V1
  public let instructionOriginal: Data
  public var wireName: String { "iroha.kagemusha.wallet.ledger.v1" }
  static func observation(_ bytes: Data, requestID: Data) throws -> Self? {
    guard requestID.count == 32, requestID.contains(where: { $0 != 0 }) else { throw KagemushaWalletErrorV1.invalidInput }
    if bytes == Data([75,87,76,78,86,49,0,0]) { return nil }
    let value = try Self(bytes)
    guard value.requestID == requestID else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    return value
  }
  init(_ original: Data) throws {
    let bytes = [UInt8](original)
    guard (221...65_756).contains(bytes.count), Array(bytes[0..<8]) == [75,87,76,80,86,49,0,0]
    else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    func word(_ at: Int) -> Data { Data(bytes[at..<(at+32)]) }
    func u64(_ at: Int) -> UInt64 { var value: UInt64 = 0; for i in 0..<8 { value |= UInt64(bytes[at+i]) << (8*i) }; return value }
    func scalar(_ at: Int) -> KagemushaWalletUInt128V1 { .init(low: u64(at), high: u64(at+8)) }
    var length: UInt32 = 0; for i in 0..<4 { length |= UInt32(bytes[216+i]) << (8*i) }
    let next = scalar(168), net = scalar(184), charge = scalar(200)
    guard [8,40,72,104,136].allSatisfy({ word($0).contains(where: { $0 != 0 }) }),
      net.low != 0 || net.high != 0, charge.low == 0 && charge.high == 0,
      (1...65_536).contains(length), bytes.count == 220 + Int(length)
    else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    requestID = word(8); schemeID = word(40); walletID = word(72); assetDigest = word(104)
    payerAccountDigest = word(136); ordinal = next; amount = net; onlineCharge = charge
    instructionOriginal = Data(bytes[220..<bytes.count])
  }
}

extension KagemushaWalletV1 {
  /// Read only the exact retained request; absence never selects a replacement ordinal.
  public func preparedLedgerLoad(requestId: Data) throws -> KagemushaWalletPreparedLoadV1? {
    let result = try observeProjection(selector: 3, identity: requestId)
    return try KagemushaWalletPreparedLoadV1.observation(result, requestID: requestId)
  }
}
