import Foundation

/// Exact canonical Load receipt and finality originals bound to the authenticated read.
/// Decoding grants no finality verdict, wallet admission, balance or Load permission.
/// Native Load independently authenticates its certificate, event path, installed genesis/epoch
/// authority, enrolled account, ordinal and durable operation before changing value.
public struct KagemushaWalletLoadOriginalV1: Sendable {
  private let input: KagemushaWalletLoadOriginalInputV1
  /// Network retained from authenticated transport; never inferred from receipt data.
  public let networkID: NetworkId
  /// Exact payer literal retained from the signed original read.
  public let payerAccountID: String
  /// Canonical receipt height DATA, used only to bound native epoch synchronization.
  public let blockHeight: UInt64
  /// Exact authenticated-read selectors; never a native authority capability.
  public let selection: ToriiKagemushaWalletLoadSelectionV1
  /// Exact original request selector bound to the canonical receipt DATA.
  public var requestID: Data { input.requestID }
  /// Whole original canonical receipt; never reconstructed from a managed projection.
  public var receiptOriginal: Data { input.receipt }
  /// Whole native BLS evidence. Authentication remains Native Load's obligation.
  public var finalityOriginal: Data { input.finality }

  /// Decode through the maintained Native canonical types and retain the exact input frames.
  public static func decode(issuance: ToriiKagemushaWalletLoadIssuanceOriginalV1,
    finalityOriginal: Data) throws -> Self {
    try decodeRetained(selection: issuance.selection, payerAccountID: issuance.payerAccountID,
      networkID: issuance.networkID, receiptOriginal: issuance.canonicalResponseOriginal,
      finalityOriginal: finalityOriginal)
  }

  /// Reopen exact retained DATA through the same Native decoder. Selectors and network are
  /// untrusted until the installed wallet verifies finality before its Load Advance.
  public static func decodeRetained(selection: ToriiKagemushaWalletLoadSelectionV1,
    payerAccountID: String, networkID: NetworkId, receiptOriginal: Data,
    finalityOriginal: Data) throws -> Self {
    let input = try KagemushaWalletLoadOriginalInputV1(selection: selection,
      payer: payerAccountID, receipt: receiptOriginal, finality: finalityOriginal)
    typealias Revision = @convention(c) () -> UInt32
    typealias Validate = @convention(c) (
      UnsafePointer<UInt8>?, UnsafePointer<UInt8>?, UnsafePointer<UInt8>?,
      UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, Int,
      UnsafeMutablePointer<UInt64>?
    ) -> Int32
    guard let revision = NoritoNativeBridge.shared.resolveNativeSymbol(
      "connect_norito_kagemusha_wallet_revision_v1", as: Revision.self), revision() == 1,
      let validate = NoritoNativeBridge.shared.resolveNativeSymbol(
        "connect_norito_kagemusha_wallet_load_original_validate_v1", as: Validate.self)
    else { throw KagemushaWalletErrorV1.bridgeUnavailable }
    var height: UInt64 = 0
    let status = input.schemeID.withUnsafeBytes { scheme in
      input.walletID.withUnsafeBytes { wallet in
        input.requestID.withUnsafeBytes { request in
          input.payer.withUnsafeBytes { payer in
            input.receipt.withUnsafeBytes { receipt in
              input.finality.withUnsafeBytes { finality in
                validate(scheme.bindMemory(to: UInt8.self).baseAddress,
                  wallet.bindMemory(to: UInt8.self).baseAddress,
                  request.bindMemory(to: UInt8.self).baseAddress,
                  payer.bindMemory(to: UInt8.self).baseAddress, payer.count,
                  receipt.bindMemory(to: UInt8.self).baseAddress, receipt.count,
                  finality.bindMemory(to: UInt8.self).baseAddress, finality.count, &height)
              }
            }
          }
        }
      }
    }
    if status < 0 { throw KagemushaWalletErrorV1.native(status: status, reason: -1, platformCode: 0) }
    guard status == 0, height > 0 else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    return Self(input: input, networkID: networkID, payerAccountID: payerAccountID,
      blockHeight: height, selection: selection)
  }
}

/// Finite owned input DATA only; construction confers no canonical/proof/authority verdict.
struct KagemushaWalletLoadOriginalInputV1: Sendable {
  let schemeID: Data
  let walletID: Data
  let requestID: Data
  let payer: Data
  let receipt: Data
  let finality: Data
  init(selection: ToriiKagemushaWalletLoadSelectionV1, payer: String, receipt: Data, finality: Data) throws {
    guard !payer.isEmpty, payer.utf8.count <= 1024,
      !receipt.isEmpty, receipt.count <= 512, !finality.isEmpty, finality.count <= 256 * 1024
    else { throw KagemushaWalletErrorV1.invalidInput }
    self.schemeID = Data(selection.schemeID)
    self.walletID = Data(selection.walletID)
    self.requestID = Data(selection.requestID)
    // Preserve I105 kana and exact DATA bytes; native code owns canonical account parsing.
    self.payer = Data(payer.utf8)
    self.receipt = Data(receipt)
    self.finality = Data(finality)
  }
}
