import Foundation
import XCTest
@testable import IrohaSwift

/// The native public schema consumer shares the compiler's final V1 table bounds.
final class KotodamaCallTableTests: XCTestCase {
    func testAuthorizationRequiresDeclaredCanonicalScopes() throws {
        let decoder = JSONDecoder()
        let permissions = #"[{"name":"Admin","scope":{"kind":"Instance","value":null}},{"name":"Operator","scope":{"kind":"Chain","value":{"permission_name":"SharedOperators"}}}]"#
        func payload(_ table: String, _ authorization: String) -> Data {
            Data("""
            {"events":[],"enum_types":[],"permissions":\(table),"entrypoints":[{"name":"inspect","kind":{"kind":"View","value":null},"params":[],"return_type":"()","return_schema":{"nodes":[{"kind":"Unit","value":null}]},"authorization":\(authorization)}]}
            """.utf8)
        }
        let role = #"{"kind":"Permission","value":"Admin"}"#
        let manifest = try decoder.decode(ToriiContractManifest.self, from: payload(permissions, role))
        XCTAssertEqual(manifest.permissions[1].scope, .chain(permissionName: "SharedOperators"))
        XCTAssertEqual(manifest.entrypoints?.first?.authorization, .permission("Admin"))
        XCTAssertNoThrow(try decoder.decode(ToriiContractManifest.self, from: payload("[]", #"{"kind":"Anyone","value":null}"#)))
        for (table, authorization) in [("null", role), ("[]", role), (permissions, "null"), (permissions, #""Admin""#), (permissions, #"{"kind":"RuntimeLifecycle","value":null}"#)] {
            XCTAssertThrowsError(try decoder.decode(ToriiContractManifest.self, from: payload(table, authorization)))
        }
        XCTAssertThrowsError(try decoder.decode(ToriiContractManifest.self, from: Data(#"{"entrypoints":[]}"#.utf8)))
    }

    func testWideArgumentsAndReturnsUseTableWords() throws {
        let value = descriptor(fields: Array(repeating: boolean, count: 64), returns: tuple(64))
        let decoded = try roundtrip(value)
        XCTAssertEqual(decoded.argumentSchema?.fields.count, 64)
        XCTAssertEqual(decoded.returnSchema?.wordCount, 64)
    }

    func testArgumentFieldCountHasAnInclusive8192Bound() throws {
        var value = descriptor(fields: Array(repeating: boolean, count: 8192))
        XCTAssertEqual(try roundtrip(value).argumentSchema?.fields.count, 8192)
        value.params.append(.init(name: "extra", typeName: "bool"))
        value.argumentSchema?.fields.append(.init(name: "extra", type: boolean))
        XCTAssertThrowsError(try JSONEncoder().encode(value))
        XCTAssertThrowsError(try JSONDecoder().decode(
            ToriiEntrypointArgumentSchemaV1.self,
            from: Data(schemaJSON(fieldCount: 8193).utf8)
        ))
    }

    func testArgumentLimitCountsFlattenedWordsAcrossFields() throws {
        var fields = Array(repeating: tuple(128), count: 64)
        let decoded = try roundtrip(descriptor(fields: fields))
        XCTAssertEqual(decoded.argumentSchema?.fields.reduce(0) { $0 + ($1.type.wordCount ?? 0) }, 8192)
        fields.append(boolean)
        XCTAssertThrowsError(try JSONEncoder().encode(descriptor(fields: fields)))
    }

    func testTableCallingDoesNotRelaxTheTypeSchemaNodeBound() throws {
        XCTAssertEqual(try roundtrip(descriptor(fields: [], returns: tuple(255))).returnSchema?.wordCount, 255)
        XCTAssertThrowsError(try JSONEncoder().encode(descriptor(fields: [], returns: tuple(256))))
    }

    func testEmptyNamedProductsKeepNominalIdentityAndOneWord() throws {
        let empty = ToriiEntrypointValueTypeV1(nodes: [.structType(.init(name: "CallTable::Empty", fields: []))])
        let list = ToriiEntrypointValueTypeV1(nodes: [.list(.init(capacity: 2))] + empty.nodes)
        let value = try roundtrip(descriptor(fields: [empty], returns: list))
        XCTAssertEqual(value.argumentSchema?.fields.first?.type.wordCount, 1)
        XCTAssertEqual(value.argumentSchema?.fields.first?.type.canonicalTypeName, "struct CallTable::Empty")
        XCTAssertEqual(value.returnSchema?.wordCount, 1)
    }

    private let boolean = ToriiEntrypointValueTypeV1(nodes: [.leaf(.bool)])

    private func tuple(_ width: Int) -> ToriiEntrypointValueTypeV1 {
        .init(nodes: [.tuple(UInt16(width))] + Array(repeating: .leaf(.bool), count: width))
    }

    private func descriptor(
        fields: [ToriiEntrypointValueTypeV1],
        returns: ToriiEntrypointValueTypeV1 = .init(nodes: [.unit])
    ) -> ToriiContractEntrypointDescriptor {
        .init(
            name: "inspect", kind: .view,
            params: fields.enumerated().map { index, type in
                .init(name: "arg_\(index)", typeName: type.canonicalTypeName ?? "invalid")
            },
            argumentSchema: fields.isEmpty ? nil : .init(fields: fields.enumerated().map { index, type in
                .init(name: "arg_\(index)", type: type)
            }),
            returnType: returns.canonicalTypeName ?? "invalid", returnSchema: returns, authorization: .anyone
        )
    }

    private func roundtrip(_ value: ToriiContractEntrypointDescriptor) throws -> ToriiContractEntrypointDescriptor {
        let bytes = try JSONEncoder().encode(value)
        return try JSONDecoder().decode(ToriiContractEntrypointDescriptor.self, from: bytes)
    }

    private func schemaJSON(fieldCount: Int) -> String {
        let fields = (0..<fieldCount).map { index in
            "{\"name\":\"arg_\(index)\",\"ty\":{\"nodes\":[{\"kind\":\"Leaf\",\"value\":{\"kind\":\"Bool\",\"value\":null}}]}}"
        }.joined(separator: ",")
        return "{\"fields\":[\(fields)]}"
    }
}
