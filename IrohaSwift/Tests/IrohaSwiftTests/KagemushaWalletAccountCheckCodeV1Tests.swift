import Foundation
import XCTest
@testable import IrohaSwift

final class KagemushaWalletAccountCheckCodeV1Tests: XCTestCase {
    private func fixture() throws -> [String: Any] {
        var root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let file = root.appendingPathComponent("fixtures/kagemusha/wallet_account_check_code_v1.json")
            if FileManager.default.fileExists(atPath: file.path) {
                let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
                XCTAssertEqual(object["schema"] as? String, "iroha.kagemusha.wallet-account-check-code.v1")
                return object
            }
            root.deleteLastPathComponent()
        }
        throw CocoaError(.fileNoSuchFile)
    }
    private func vectors(_ key: String) throws -> [[String: Any]] {
        try XCTUnwrap(fixture()[key] as? [[String: Any]])
    }
    private func bytes(_ value: Any?) throws -> Data {
        let hex = try XCTUnwrap(value as? String)
        return Data(try stride(from: 0, to: hex.count, by: 2).map { index in
            let start = hex.index(hex.startIndex, offsetBy: index)
            return try XCTUnwrap(UInt8(hex[start..<hex.index(start, offsetBy: 2)], radix: 16))
        })
    }

    func testSharedAccountsGiveTheSameCodeFromTheirIDOriginalAndDigest() throws {
        let discriminant = try XCTUnwrap(fixture()["chain_discriminant"] as? Int)
        for vector in try vectors("accounts") {
            let name = try XCTUnwrap(vector["name"] as? String)
            let literal = try XCTUnwrap(vector["i105"] as? String)
            let original = try bytes(vector["account_original_hex"])
            let digest = try bytes(vector["account_digest_hex"])
            let code = try XCTUnwrap(vector["check_code"] as? String)
            XCTAssertEqual(try KagemushaWalletAccountOriginalV1.encode(literal), original, name)
            XCTAssertEqual(try KagemushaWalletAccountOriginalV1.decode(original, chainDiscriminant: UInt16(discriminant)), literal, name)
            XCTAssertEqual(KagemushaWalletWireV1.digest(role: .account, body: original), digest, name)
            XCTAssertEqual(try KagemushaWalletAccountCheckCodeV1.code(accountDigest: digest), code, name)
            XCTAssertEqual(KagemushaWalletAccountCheckCodeV1.code(accountOriginal: original), code, name)
            XCTAssertEqual(try KagemushaWalletAccountCheckCodeV1.code(accountID: literal), code, name)
        }
    }

    func testDigestEdgesAreUnsignedReducedAndZeroPadded() throws {
        for vector in try vectors("digests") {
            XCTAssertEqual(try KagemushaWalletAccountCheckCodeV1.code(accountDigest: bytes(vector["account_digest_hex"])),
                           vector["check_code"] as? String, vector["name"] as? String ?? "")
        }
    }

    func testOnlyTheFirstFourDigestBytesChooseTheCode() throws {
        let digest = try bytes(XCTUnwrap(vectors("accounts").first)["account_digest_hex"])
        let code = try KagemushaWalletAccountCheckCodeV1.code(accountDigest: digest)
        var tail = digest; tail[tail.count - 1] ^= 1
        var head = digest; head[3] ^= 1
        XCTAssertEqual(try KagemushaWalletAccountCheckCodeV1.code(accountDigest: tail), code)
        XCTAssertNotEqual(try KagemushaWalletAccountCheckCodeV1.code(accountDigest: head), code)
        // A slice keeps its parent's indices; only its own first four bytes count.
        XCTAssertEqual(try KagemushaWalletAccountCheckCodeV1.code(accountDigest: (Data([0xAA]) + digest).dropFirst()), code)
    }

    func testADigestOfAnyOtherLengthIsRefused() throws {
        for length in try XCTUnwrap(fixture()["invalid_digest_lengths"] as? [Int]) {
            XCTAssertThrowsError(try KagemushaWalletAccountCheckCodeV1.code(accountDigest: Data(count: length))) { error in
                XCTAssertEqual(error as? KagemushaWalletErrorV1, .invalidInput)
            }
        }
    }
}
