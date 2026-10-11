import Foundation

/// Fixed selectors of the committed Load receipt read route. They identify an original;
/// they do not authorize issuance, prove finality or select a different wallet incarnation.
public struct ToriiKagemushaWalletLoadSelectionV1: Equatable, Sendable {
    public let schemeID: Data
    public let walletID: Data
    public let requestID: Data

    public init(schemeID: Data, walletID: Data, requestID: Data) throws {
        for value in [schemeID, walletID, requestID] {
            guard value.count == 32, value.contains(where: { $0 != 0 }) else {
                throw ToriiClientError.invalidPayload("KAGEMUSHA load selectors must be nonzero 32-byte identities")
            }
        }
        self.schemeID = Data(schemeID)
        self.walletID = Data(walletID)
        self.requestID = Data(requestID)
    }

    var path: String {
        func hex(_ value: Data) -> String { value.map { String(format: "%02x", $0) }.joined() }
        return "/v1/kagemusha/\(hex(schemeID))/wallets/\(hex(walletID))/loads/\(hex(requestID))"
    }
}

/// Bounded, unverified HTTP original of an unsigned `KagemushaWalletLoadReceiptV1`.
///
/// The consumer must decode the canonical receipt and bind its request, payer, scheme and
/// wallet to the expected owner. Before a fresh Advance, the native wallet verifies the exact
/// receipt's BLS certificate and event inclusion against genesis-rooted, locally selected
/// epoch authority. Selected and completed retries use the exact authenticated retained custody.
/// This transport implements none of those checks and exposes no balance or admission verdict.
/// The receipt and HTTP success alone never authorize offline value.
public struct ToriiKagemushaWalletLoadIssuanceOriginalV1: Sendable {
    /// Local online response limit for the unsigned receipt and canonical payer frame.
    /// The response bound is independent of the canonical account request-header text limit.
    public static let maximumBytes = 64 * 1024
    public let selection: ToriiKagemushaWalletLoadSelectionV1
    public let payerAccountID: String
    public let networkID: NetworkId
    public let canonicalResponseOriginal: Data

    init(selection: ToriiKagemushaWalletLoadSelectionV1, payerAccountID: String,
        networkID: NetworkId, expectedURL: URL?, response: HTTPURLResponse, bytes: Data) throws {
        guard response.statusCode == 200, let expectedURL,
              response.url?.absoluteString == expectedURL.absoluteString else {
            throw ToriiClientError.invalidResponse
        }
        guard response.value(forHTTPHeaderField: "Content-Type")?
            .trimmingCharacters(in: .whitespacesAndNewlines) == "application/x-norito" else {
            throw ToriiClientError.invalidPayload("KAGEMUSHA issuance requires exact application/x-norito")
        }
        let encoding = response.value(forHTTPHeaderField: "Content-Encoding")?
            .trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard encoding == nil || encoding == "identity" else {
            throw ToriiClientError.invalidPayload("KAGEMUSHA issuance must preserve the identity representation")
        }
        guard !bytes.isEmpty, bytes.count <= Self.maximumBytes else {
            throw ToriiClientError.invalidPayload("KAGEMUSHA issuance original is empty or exceeds its bound")
        }
        if let length = response.value(forHTTPHeaderField: "Content-Length") {
            let digits = length.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !digits.isEmpty, digits.utf8.allSatisfy({ (48...57).contains($0) }),
                  let count = Int(digits), count == bytes.count else {
                throw ToriiClientError.invalidPayload("KAGEMUSHA issuance original length differs")
            }
        }
        self.selection = selection
        self.payerAccountID = payerAccountID
        self.networkID = networkID
        self.canonicalResponseOriginal = Data(bytes)
    }
}
