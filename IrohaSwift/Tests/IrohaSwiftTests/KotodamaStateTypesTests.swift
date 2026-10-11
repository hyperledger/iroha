import Foundation
import XCTest
@testable import IrohaSwift

/// Durable type names preserve nominal empty products without accepting malformed declarations.
final class KotodamaStateTypesTests: XCTestCase {
    private func decode(_ typeName: String) throws -> ToriiContractManifest {
        let payload = #"{"permissions":[],"events":[],"enum_types":[],"states":[{"name":"Stored","type_name":"\#(typeName)"}]}"#
        return try JSONDecoder().decode(ToriiContractManifest.self, from: Data(payload.utf8))
    }

    func testEmptyProductsKeepTheirNominalSpellingInDurableSchemas() throws {
        for typeName in [
            "StateTypes::Empty{}", "StateTypes::Other{}", "StateTypes::Transfer{}", "List<StateTypes::Empty{}, 2>", "List<List<StateTypes::Empty{}, 2>, 2>",
            "StateTypes::Envelope{empty: StateTypes::Empty{}}", "StateMap<int, StateTypes::Empty{}>",
            "std/math@1.0.0::Math::Empty{}",
        ] {
            let manifest = try decode(typeName)
            XCTAssertEqual(manifest.states?.first?.typeName, typeName)
            let encoded = try JSONEncoder().encode(manifest)
            let roundtrip = try JSONDecoder().decode(ToriiContractManifest.self, from: encoded)
            XCTAssertEqual(roundtrip.states?.first?.typeName, typeName)
        }
    }

    func testMalformedEmptyProductsAndReservedShapesAreRejected() {
        for typeName in [
            "{}", "StateTypes::Empty{", "StateTypes::Empty{ }", "StateTypes::Empty{,}", "StateTypes::Empty{: int}",
            "StateTypes::Empty{field: int, }", "StateTypes::Empty{}trailing", "List<StateTypes::Empty{},2>",
            "List<StateTypes::Empty{}, 0>", "StateTypes::Envelope{empty: StateTypes::Empty{}, empty: StateTypes::Empty{}}",
            "StatePage{}", "Option{}", "int{}",
        ] {
            XCTAssertThrowsError(try decode(typeName), typeName)
        }
    }
}
