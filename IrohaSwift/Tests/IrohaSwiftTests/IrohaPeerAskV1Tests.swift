import Foundation
import XCTest
@testable import IrohaSwift

/// The receiver's `IAK1` ask: the shared record and text vectors, every invalid record and text
/// of `fixtures/kagemusha/peer_ask_v1.json`, and the account-ID digest it shares with the check
/// code. Display DATA only; nothing here authorizes a payment.
final class IrohaPeerAskV1Tests: XCTestCase {
    func testSharedAsksEncodeDecodeAndRenderExactly() throws {
        let fixture = try irohaPeerAskFixtureV1()
        let layout = try XCTUnwrap(fixture["ask_record"] as? [String: Any])
        XCTAssertEqual(layout["bytes"] as? Int, IrohaPeerAskV1.recordBytes)
        XCTAssertEqual(IrohaPeerAskV1.recordBytes, 56)
        XCTAssertEqual(IrohaPeerAskV1.textPrefix, "IAK1:")
        let vectors = try irohaPeerAskVectorsV1("asks", in: fixture)
        XCTAssertEqual(vectors.count, 5)
        for vector in vectors {
            let name = try XCTUnwrap(vector["name"] as? String)
            let amount = try irohaPeerAskAmountV1(decimal: vector["amount_decimal"])
            let littleEndian = try irohaPeerAskBytesV1(vector["amount_le128_hex"])
            XCTAssertEqual(
                withUnsafeBytes(of: amount.low.littleEndian) { Data($0) }
                    + withUnsafeBytes(of: amount.high.littleEndian) { Data($0) },
                littleEndian, name
            )
            let digest = try irohaPeerAskBytesV1(vector["account_digest_hex"])
            let record = try irohaPeerAskBytesV1(vector["record_hex"])
            let text = try XCTUnwrap(vector["text"] as? String)
            let ask = try IrohaPeerAskV1(amount: amount, receiverAccountDigest: digest)
            XCTAssertEqual(ask.amount, amount, name)
            XCTAssertEqual(ask.receiverAccountDigest, digest, name)
            XCTAssertEqual(ask.encode(), record, name)
            XCTAssertEqual(ask.toText(), text, name)
            XCTAssertEqual(text.utf8.count, 90, name)
            XCTAssertEqual(ask.checkCode, vector["check_code"] as? String, name)
            XCTAssertEqual(ask.checkCode, try KagemushaWalletAccountCheckCodeV1.code(accountDigest: digest), name)
            XCTAssertEqual(try IrohaPeerAskV1.decode(record), ask, name)
            XCTAssertEqual(try IrohaPeerAskV1.fromText(text), ask, name)
        }
    }

    func testEveryInvalidRecordIsRefusedWithItsViolation() throws {
        let expected: [String: IrohaPeerAskErrorV1] = [
            "empty": .invalidLength,
            "short-by-one": .invalidLength,
            "long-by-one": .invalidLength,
            "wrong-magic": .invalidMagic,
            "version-0": .unsupportedVersion,
            "version-2": .unsupportedVersion,
            "nonzero-flags": .invalidFlags,
            "unknown-profile-0": .invalidProfile,
            "unknown-profile-2": .invalidProfile,
            "zero-amount": .invalidAmount,
            "zero-digest": .invalidAccountDigest,
        ]
        let vectors = try irohaPeerAskVectorsV1("invalid_records", in: try irohaPeerAskFixtureV1())
        XCTAssertEqual(Set(try vectors.map { try XCTUnwrap($0["name"] as? String) }), Set(expected.keys))
        for vector in vectors {
            let name = try XCTUnwrap(vector["name"] as? String)
            let record = try irohaPeerAskBytesV1(vector["record_hex"])
            XCTAssertThrowsError(try IrohaPeerAskV1.decode(record), name) {
                XCTAssertEqual($0 as? IrohaPeerAskErrorV1, expected[name], name)
            }
            // A Data slice keeps its parent's indices; decoding must not depend on them.
            XCTAssertThrowsError(try IrohaPeerAskV1.decode((Data([0x49]) + record).dropFirst()), name) {
                XCTAssertEqual($0 as? IrohaPeerAskErrorV1, expected[name], name)
            }
            // The same record inside otherwise canonical text fails for the same reason.
            if record.count == IrohaPeerAskV1.recordBytes {
                let text = IrohaPeerAskV1.textPrefix + IrohaBase45V1.encode(record) + ":"
                XCTAssertThrowsError(try IrohaPeerAskV1.fromText(text), name) {
                    XCTAssertEqual($0 as? IrohaPeerAskErrorV1, expected[name], name)
                }
            }
        }
    }

    func testEveryInvalidTextIsRefused() throws {
        let fixture = try irohaPeerAskFixtureV1()
        let vectors = try irohaPeerAskVectorsV1("invalid_texts", in: fixture)
        XCTAssertEqual(vectors.count, 9)
        for vector in vectors {
            let name = try XCTUnwrap(vector["name"] as? String)
            XCTAssertThrowsError(try IrohaPeerAskV1.fromText(try XCTUnwrap(vector["text"] as? String)), name) {
                XCTAssertEqual($0 as? IrohaPeerAskErrorV1, .invalidText, name)
            }
        }
        let good = try XCTUnwrap(irohaPeerAskVectorsV1("asks", in: fixture)[1]["text"] as? String)
        XCTAssertNoThrow(try IrohaPeerAskV1.fromText(good))
        // Byte comparison, not Unicode equivalence: KELVIN SIGN canonically equals "K".
        let kelvin = good.replacingOccurrences(of: "IAK1:", with: "IA\u{212A}1:")
        XCTAssertEqual(kelvin, good, "Swift String equality treats the alias as equal")
        let aliases = [
            kelvin,
            String(good.dropLast()) + "\u{FF1A}",
            String(good.dropFirst(5).dropLast()),
            good + "\n",
            "\u{FEFF}" + good,
        ]
        for alias in aliases {
            XCTAssertThrowsError(try IrohaPeerAskV1.fromText(alias)) {
                XCTAssertEqual($0 as? IrohaPeerAskErrorV1, .invalidText)
            }
        }
        // A 90-character text whose body is not canonical Base45: "GGW" is 65,536 > 0xFFFF.
        var body = Array(good.utf8)
        body.replaceSubrange(5..<8, with: Array("GGW".utf8))
        XCTAssertThrowsError(try IrohaPeerAskV1.fromText(String(decoding: body, as: UTF8.self))) {
            XCTAssertEqual($0 as? IrohaPeerAskErrorV1, .invalidText)
        }
    }

    func testInitializerRefusesZeroAmountAndMalformedDigest() throws {
        let digest = Data((1...32).map(UInt8.init))
        XCTAssertThrowsError(try IrohaPeerAskV1(amount: .init(low: 0, high: 0), receiverAccountDigest: digest)) {
            XCTAssertEqual($0 as? IrohaPeerAskErrorV1, .invalidAmount)
        }
        for bad in [Data(), Data(repeating: 1, count: 31), Data(repeating: 1, count: 33), Data(count: 32)] {
            XCTAssertThrowsError(try IrohaPeerAskV1(amount: .init(low: 1, high: 0), receiverAccountDigest: bad)) {
                XCTAssertEqual($0 as? IrohaPeerAskErrorV1, .invalidAccountDigest)
            }
        }
        // Only the high limb set is still a positive amount.
        let high = try IrohaPeerAskV1(amount: .init(low: 0, high: 1), receiverAccountDigest: digest)
        XCTAssertEqual(try IrohaPeerAskV1.decode(high.encode()).amount, .init(low: 0, high: 1))
        // The digest is a defensive copy rebased to index zero.
        let sliced = try IrohaPeerAskV1(
            amount: .init(low: 7, high: 0), receiverAccountDigest: (Data([0xAA]) + digest).dropFirst())
        XCTAssertEqual(sliced.receiverAccountDigest, digest)
        XCTAssertEqual(sliced.receiverAccountDigest.startIndex, 0)
        XCTAssertEqual(sliced.encode().suffix(32), digest)
    }

    func testDescriptionKeepsTheAmountAndDigestOutOfLogs() throws {
        let ask = try IrohaPeerAskV1(
            amount: .init(low: 987_654_321, high: 0), receiverAccountDigest: Data(repeating: 0xAB, count: 32))
        for text in [String(describing: ask), "\(ask)", String(reflecting: ask)] {
            XCTAssertEqual(text, "IrohaPeerAskV1(kagemushaWalletV1)")
            XCTAssertFalse(text.contains("987654321"))
            XCTAssertFalse(text.lowercased().contains("abab"))
        }
    }

    func testAccountIDAskUsesTheCheckCodeDigestForEverySharedAccount() throws {
        var root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        var accounts: [[String: Any]]?
        for _ in 0..<8 where accounts == nil {
            let file = root.appendingPathComponent("fixtures/kagemusha/wallet_account_check_code_v1.json")
            if FileManager.default.fileExists(atPath: file.path) {
                let object = try XCTUnwrap(
                    JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
                accounts = try XCTUnwrap(object["accounts"] as? [[String: Any]])
            }
            root.deleteLastPathComponent()
        }
        let vectors = try XCTUnwrap(accounts)
        XCTAssertFalse(vectors.isEmpty)
        let amount = KagemushaWalletUInt128V1(low: 1_200, high: 0)
        let shared = try irohaPeerAskVectorsV1("asks", in: irohaPeerAskFixtureV1())
        var sharedMatches = 0
        for vector in vectors {
            let name = try XCTUnwrap(vector["name"] as? String)
            let accountID = try XCTUnwrap(vector["i105"] as? String)
            let digest = try irohaPeerAskBytesV1(vector["account_digest_hex"])
            let ask = try IrohaPeerAskV1(amount: amount, accountID: accountID)
            XCTAssertEqual(ask.receiverAccountDigest, digest, name)
            XCTAssertEqual(ask.checkCode, vector["check_code"] as? String, name)
            XCTAssertEqual(ask.checkCode, try KagemushaWalletAccountCheckCodeV1.code(accountID: accountID), name)
            XCTAssertEqual(ask.amount, amount, name)
            XCTAssertEqual(try IrohaPeerAskV1.fromText(ask.toText()), ask, name)
            // The shared asks addressed to these accounts are the same bytes built from the ID.
            for sharedAsk in shared {
                guard try irohaPeerAskBytesV1(sharedAsk["account_digest_hex"]) == digest else { continue }
                let built = try IrohaPeerAskV1(
                    amount: irohaPeerAskAmountV1(decimal: sharedAsk["amount_decimal"]), accountID: accountID)
                XCTAssertEqual(built.toText(), sharedAsk["text"] as? String, name)
                XCTAssertEqual(built.encode(), try irohaPeerAskBytesV1(sharedAsk["record_hex"]), name)
                sharedMatches += 1
            }
        }
        XCTAssertEqual(sharedMatches, 3)
        let first = try XCTUnwrap(vectors.first?["i105"] as? String)
        XCTAssertThrowsError(try IrohaPeerAskV1(amount: .init(low: 0, high: 0), accountID: first)) {
            XCTAssertEqual($0 as? IrohaPeerAskErrorV1, .invalidAmount)
        }
        XCTAssertThrowsError(try IrohaPeerAskV1(amount: amount, accountID: first + "x"))
        XCTAssertThrowsError(try IrohaPeerAskV1(amount: amount, accountID: ""))
    }
}
