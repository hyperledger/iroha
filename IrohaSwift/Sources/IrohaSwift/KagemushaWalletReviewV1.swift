import Foundation
import NoritoBridge

/// Native-authenticated review DATA. Copying it creates no capability or monetary operation.
public struct KagemushaWalletReviewProjectionV1: Sendable {
  static let fixedByteCount = 495
  static let maximumByteCount = fixedByteCount + 4_096
  public enum Kind: Sendable { case send, unload }
  public let kind: Kind
  public let amount: KagemushaWalletUInt128V1
  public let fee: KagemushaWalletUInt128V1
  public let grossDebit: KagemushaWalletUInt128V1
  public let netDestinationAmount: KagemushaWalletUInt128V1
  private let retained: Data
  init(original:Data)throws{try self.init(original)}
  init(_ original: Data) throws {
    guard original.count >= Self.fixedByteCount, original.count <= Self.maximumByteCount
    else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    let bytes = [UInt8](original)
    guard Array(bytes[0..<8]) == [75,87,79,82,86,49,0,0], [1,8].contains(bytes[8])
    else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    func word(_ offset: Int) -> Bool { bytes[offset..<(offset+32)].contains(where: { $0 != 0 }) }
    func scalar(_ offset: Int) -> KagemushaWalletUInt128V1 {
      func limb(_ at: Int) -> UInt64 { var value: UInt64 = 0; for i in 0..<8 { value |= UInt64(bytes[at+i]) << (8*i) }; return value }
      return .init(low: limb(offset), high: limb(offset+8))
    }
    kind = bytes[8] == 1 ? .send : .unload
    var accountLength: UInt32 = 0
    for i in 0..<4 { accountLength |= UInt32(bytes[491+i]) << (8*i) }
    guard accountLength <= 4_096, bytes.count == Self.fixedByteCount + Int(accountLength),
      kind == .send ? accountLength > 0 : accountLength == 0
    else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    amount = scalar(9); fee = scalar(25); grossDebit = scalar(41); netDestinationAmount = scalar(57)
    guard amount.low != 0 || amount.high != 0, bytes[426] == 4,
      bytes[427..<491].contains(where: { $0 != 0 }),
      [106,202,234,266,298,330,362,394].allSatisfy(word),
      kind == .send ? (bytes[73] == 1 && word(74) && word(138) && !word(170)) : (bytes[73] == 0 && !word(74) && !word(138))
    else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    retained = Data(original)
  }
  /// Exact whole projection for fresh hardware confirmation. It is never reassembled locally.
  public var bytes: Data { retained }
  public var receiverWalletID: Data? { kind == .send ? retained.subdata(in: 74..<106) : nil }
  private func word(_ index: Int) -> Data { retained.subdata(in: (106+index*32)..<(138+index*32)) }
  public var destinationAccountDigest: Data { word(0) }
  /// Exact Native-authenticated canonical AccountId original for Send; absent for Unload.
  /// Render only under independently authenticated installed network presentation selection.
  public var destinationAccountOriginal: Data? {
    kind == .send ? retained.subdata(in: Self.fixedByteCount..<retained.count) : nil
  }
  public var requestDigest: Data { word(1) }
  public var chargeQuoteDigest: Data { word(2) }
  public var schemeID: Data { word(3) }
  public var walletID: Data { word(4) }
  public var currentHead: Data { word(5) }
  public var sourceStateCommitment: Data { word(6) }
  public var sourceCapsuleDigest: Data { word(7) }
  public var credentialDigest: Data { word(8) }
  public var artifactManifestDigest: Data { word(9) }
  public var paymentPublicKey: Data { retained.subdata(in: 426..<491) }
  public var receiverWalletId:Data?{receiverWalletID}
  public var schemeId:Data{schemeID}
  public var walletId:Data{walletID}
  public var paymentKey:Data{paymentPublicKey}
}

/// Move-only owner-local Native capability; a projection cannot reconstruct one.
public final class KagemushaWalletReviewV1: @unchecked Sendable {
  private let lock = NSLock()
  private let origin: AnyObject
  private var token: UInt64
  public let projection: KagemushaWalletReviewProjectionV1
  private init(origin: AnyObject, token: UInt64, projection: KagemushaWalletReviewProjectionV1) {
    self.origin = origin; self.token = token; self.projection = projection
  }
  static func fromNative(origin: AnyObject, token: UInt64, projection: KagemushaWalletReviewProjectionV1) -> KagemushaWalletReviewV1 {
    .init(origin: origin, token: token, projection: projection)
  }
  func consume(origin: AnyObject) throws -> UInt64 {
    lock.lock(); defer { lock.unlock() }
    guard self.origin === origin else { throw KagemushaWalletErrorV1.invalidInput }
    guard token != 0 else { throw KagemushaWalletErrorV1.closed }
    let value = token; token = 0; return value
  }
}

/// Dedicated review result parser; status18 and bounded original DATA never enter monetary completion.
struct KagemushaWalletReviewReplyV1 {
  let status: Int32, reason: Int32, platformCode: Int32
  let sequenceLow: UInt64, sequenceHigh: UInt64
  let detail: UInt32
  let bytes: Data
  func review(origin: AnyObject, expected: KagemushaWalletReviewProjectionV1.Kind) throws -> KagemushaWalletReviewV1 {
    guard status == 18, reason == -1, platformCode == 0, sequenceLow > 0,
      sequenceLow <= UInt64(Int64.max), sequenceHigh == 0, detail == 0 else {
      throw KagemushaWalletErrorV1.invalidNativeOutput
    }
    let projection = try KagemushaWalletReviewProjectionV1(bytes)
    guard projection.kind == expected else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    return .fromNative(origin: origin, token: sequenceLow, projection: projection)
  }
}

public typealias KagemushaWalletReviewedKindV1 = KagemushaWalletReviewProjectionV1.Kind
final class KagemushaWalletReviewOriginV1: @unchecked Sendable {}
/// Fixed foreign bounds/copies only; Native authenticates all financial inputs.
struct KagemushaWalletReviewInputV1 {
  let selector: UInt32
  let amount: KagemushaWalletUInt128V1
  let first: Data
  let second: Data
  init(selector: UInt32, amount: KagemushaWalletUInt128V1 = .init(low: 0, high: 0),
       first: Data = Data(), second: Data = Data()) throws {
    let nonzero = amount.low != 0 || amount.high != 0
    switch selector {
    case 1:
      guard !nonzero, !first.isEmpty, first.count <= 10_000,
        !second.isEmpty, second.count <= 4_096
      else { throw KagemushaWalletErrorV1.invalidInput }
    case 8:
      guard nonzero, first.count <= 1_024, first.isEmpty == second.isEmpty
      else { throw KagemushaWalletErrorV1.invalidInput }
      if !second.isEmpty { try KagemushaWalletUnloadChargeReviewV1.validate(second) }
    default: throw KagemushaWalletErrorV1.invalidInput
    }
    self.selector = selector; self.amount = amount; self.first = first; self.second = second
  }
  func withRequest<T>(_ body: (UnsafePointer<connect_norito_kagemusha_wallet_review_request_v1>) throws -> T) rethrows -> T {
    try first.withUnsafeBytes { a in try second.withUnsafeBytes { b in
      var request = connect_norito_kagemusha_wallet_review_request_v1()
      request.selector = selector; request.amount = .init(low: amount.low, high: amount.high)
      request.first = a.bindMemory(to: UInt8.self).baseAddress; request.first_length = a.count
      request.second = b.bindMemory(to: UInt8.self).baseAddress; request.second_length = b.count
      return try body(&request)
    }}
  }
}
