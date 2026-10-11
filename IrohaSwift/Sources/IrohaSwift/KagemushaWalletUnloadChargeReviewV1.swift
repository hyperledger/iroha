import Foundation

/// Closed review DATA only. Native authenticates the exact quote and beneficiary account.
enum KagemushaWalletUnloadChargeReviewV1 {
    static let maximumBytes = 14_112
    private static let magic = Data([75, 87, 85, 67, 86, 49, 0, 0])

    static func encode(certificates: Data, beneficiary: Data) throws -> Data {
        guard (1...10_000).contains(certificates.count), (1...4_096).contains(beneficiary.count)
        else { throw KagemushaWalletErrorV1.invalidInput }
        var original = magic
        func appendLength(_ count: Int) {
            for shift in stride(from: 0, through: 24, by: 8) { original.append(UInt8((count >> shift) & 255)) }
        }
        appendLength(certificates.count); original.append(certificates)
        appendLength(beneficiary.count); original.append(beneficiary)
        return original
    }

    static func validate(_ original: Data) throws {
        guard (18...maximumBytes).contains(original.count), original.prefix(8) == magic
        else { throw KagemushaWalletErrorV1.invalidInput }
        let bytes = [UInt8](original)
        func length(_ offset: Int) -> UInt32 {
            (0..<4).reduce(UInt32(0)) { $0 | (UInt32(bytes[offset + $1]) << UInt32($1 * 8)) }
        }
        let certificates = length(8)
        guard (1...10_000).contains(certificates), original.count >= 16 + Int(certificates)
        else { throw KagemushaWalletErrorV1.invalidInput }
        let beneficiary = length(12 + Int(certificates))
        guard (1...4_096).contains(beneficiary), original.count == 16 + Int(certificates) + Int(beneficiary)
        else { throw KagemushaWalletErrorV1.invalidInput }
    }
}
