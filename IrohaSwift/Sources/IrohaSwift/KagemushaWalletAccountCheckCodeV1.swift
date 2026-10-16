import Foundation

/// The account check code two people compare aloud before an offline payment: eight decimal digits
/// in two groups of four, such as `0006 6051`. The payer's wallet shows it for the reviewed receiver
/// account digest and the receiver's wallet shows it for its own account, so every wallet renders the
/// same text for one account (`specs/kagemusha_wallet_wire_v1.md` §6,
/// `fixtures/kagemusha/wallet_account_check_code_v1.json`).
///
/// Display DATA only. A code authenticates nothing; Native still binds the payment to the full
/// reviewed account.
public enum KagemushaWalletAccountCheckCodeV1 {
    /// The code for a 32-byte account digest `H(account, original)`: its first four bytes as a
    /// big-endian unsigned integer, modulo 10^8, as eight zero-padded digits split by one space.
    public static func code(accountDigest: Data) throws -> String {
        guard accountDigest.count == KagemushaWalletWireV1.digestBytes else { throw KagemushaWalletErrorV1.invalidInput }
        return render(accountDigest)
    }

    /// The code for a canonical account original (``KagemushaWalletAccountOriginalV1``).
    public static func code(accountOriginal: Data) -> String {
        render(KagemushaWalletWireV1.digest(role: .account, body: accountOriginal))
    }

    /// The code for an I105 account ID, through its canonical account original.
    public static func code(accountID: String) throws -> String {
        code(accountOriginal: try KagemushaWalletAccountOriginalV1.encode(accountID))
    }

    private static func render(_ digest: Data) -> String {
        let value = digest.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        let digits = String(value % 100_000_000)
        let padded = String(repeating: "0", count: 8 - digits.count) + digits
        return String(padded.prefix(4)) + " " + String(padded.suffix(4))
    }
}
