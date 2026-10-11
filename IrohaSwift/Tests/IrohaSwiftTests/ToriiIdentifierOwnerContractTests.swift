import Foundation
import XCTest
@testable import IrohaSwift

final class ToriiIdentifierOwnerContractTests: XCTestCase {
    private struct Signature: Decodable {
        let value: String
        enum CodingKeys: String, CodingKey { case value }

        init(from decoder: Decoder) throws {
            try ToriiIdentifierOwnerContract.fields(decoder, required: ["value"])
            let container = try decoder.container(keyedBy: CodingKeys.self)
            value = try ToriiIdentifierOwnerContract.decodeString(from: container, forKey: .value) {
                try ToriiIdentifierOwnerContract.signature($0, field: "owner.value")
            }
        }
    }

    private struct Envelope: Decodable { let owner: Signature }

    func testInvalidOwnerSignatureRetainsItsFieldPathAndUnderlyingError() throws {
        let valid = try JSONDecoder().decode(Envelope.self, from: Data(#"{"owner":{"value":"ab"}}"#.utf8))
        XCTAssertEqual(valid.owner.value, "ab")
        for value in [" ab", "GG", "abc", ""] {
            let data = try JSONSerialization.data(withJSONObject: ["owner": ["value": value]])
            XCTAssertThrowsError(try JSONDecoder().decode(Envelope.self, from: data)) { error in
                guard case let DecodingError.dataCorrupted(context) = error else {
                    return XCTFail("Expected a field decoding error, got \(error)")
                }
                XCTAssertEqual(context.codingPath.map(\.stringValue), ["owner", "value"])
                XCTAssertNotNil(context.underlyingError as? ToriiClientError)
            }
        }
    }

    func testOwnerSchemaRefusesMissingAndUnknownFieldsAtTheirObject() {
        for json in [#"{"owner":{}}"#, #"{"owner":{"value":"ab","extra":true}}"#] {
            XCTAssertThrowsError(try JSONDecoder().decode(Envelope.self, from: Data(json.utf8))) { error in
                guard case let DecodingError.dataCorrupted(context) = error else {
                    return XCTFail("Expected an object decoding error, got \(error)")
                }
                XCTAssertEqual(context.codingPath.map(\.stringValue), ["owner"])
                XCTAssertTrue(context.debugDescription.contains("exact current fields"))
            }
        }
    }

    func testFieldTypeErrorsRetainTheOriginalDecoderContext() {
        XCTAssertThrowsError(try JSONDecoder().decode(Envelope.self, from: Data(#"{"owner":{"value":12}}"#.utf8))) { error in
            guard case let DecodingError.typeMismatch(_, context) = error else {
                return XCTFail("Expected the original type mismatch, got \(error)")
            }
            XCTAssertEqual(context.codingPath.map(\.stringValue), ["owner", "value"])
        }
    }

    func testSignatureBoundAndModelCaseStayStrict() throws {
        let maximum = String(repeating: "ab", count: 3_309)
        XCTAssertEqual(try ToriiIdentifierOwnerContract.signature(maximum, field: "signature"), maximum)
        XCTAssertThrowsError(try ToriiIdentifierOwnerContract.signature(maximum + "ab", field: "signature"))
        XCTAssertEqual(try ToriiIdentifierOwnerContract.modelSignature("AB", field: "signature"), "ab")
        for value in ["ab", " AB", "AB ", "0XAB", ""] {
            XCTAssertThrowsError(try ToriiIdentifierOwnerContract.modelSignature(value, field: "signature"))
        }
    }
}
