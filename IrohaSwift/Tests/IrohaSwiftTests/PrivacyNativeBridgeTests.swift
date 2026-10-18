import CryptoKit
import Foundation
import XCTest
@testable import IrohaSwift

final class PrivacyNativeBridgeTests: XCTestCase {
    private static let matrix = loadExact12Matrix()
    private var protocolRows: [[String]] { Self.matrix.filter { $0[0] == "protocol" } }
    private var typedEnvelopeRows: [[String]] {
        Self.matrix.filter { $0[0] == "typed-envelope" }
    }
    private var expected: [String] { protocolRows.map { $0[2] } }

    func testExactClosedRegistryIsStable() throws {
        XCTAssertEqual(PrivacyNativeBridge.requiredBridgeABIVersion, 30)
        XCTAssertEqual(PrivacyNativeBridge.protocolsV1.map(\.rawValue), expected)
        XCTAssertEqual(PrivacyNativeBridge.protocolsV1.count, 12)
        XCTAssertEqual(
            PrivacyNativeBridge.protocolsV1.map(\.noritoDiscriminant),
            (0..<12).map(UInt32.init)
        )
        XCTAssertEqual(
            PrivacyNativeBridge.protocolsV1.map(\.canonicalTypedVariantLabel),
            protocolRows.map { $0[3] }
        )
        for (index, label) in expected.enumerated() {
            XCTAssertEqual(
                try PrivacyProtocolIdV1(canonicalLabel: label),
                PrivacyNativeBridge.protocolsV1[index]
            )
            XCTAssertEqual(
                try PrivacyProtocolIdV1(noritoDiscriminant: UInt32(index)),
                PrivacyNativeBridge.protocolsV1[index]
            )
            XCTAssertEqual(
                try PrivacyProtocolIdV1(canonicalTypedVariantLabel: protocolRows[index][3]),
                PrivacyNativeBridge.protocolsV1[index]
            )
        }
    }

    func testCanonicalProofSystemAndNativeEngineTagsMatchRustRegistry() {
        XCTAssertEqual(
            PrivacyProofSystemIdV1.allCases.map(\.rawValue),
            (0..<9).map(UInt32.init)
        )
        XCTAssertEqual(
            PrivacyEngineIdV1.allCases.map(\.rawValue),
            (0..<9).map(UInt32.init)
        )
        XCTAssertEqual(
            PrivacyNativeBridge.protocolsV1.map { $0.expectedProofSystem.rawValue },
            [0, 2, 3, 1, 4, 0, 5, 8, 6, 7, 0, 0]
        )
        XCTAssertEqual(
            PrivacyNativeBridge.protocolsV1.map { $0.expectedEngine.rawValue },
            [0, 2, 3, 1, 4, 0, 5, 8, 6, 7, 0, 0]
        )
        for rejectedTag in [UInt32(9), UInt32.max] {
            XCTAssertNil(PrivacyProofSystemIdV1(rawValue: rejectedTag))
            XCTAssertNil(PrivacyEngineIdV1(rawValue: rejectedTag))
        }
    }

    func testFirstReleaseIdentifiersMatchCanonicalV1Profiles() {
        XCTAssertEqual(
            PrivacyProtocolIdV1.zkAcePqAuthorizationV1.rawValue,
            "zk-ace-pq-authorization-v1"
        )
        XCTAssertEqual(
            PrivacyProtocolIdV1.vegaExistingCredentialZkV1.rawValue,
            "vega-existing-credential-zk-v1"
        )
        XCTAssertEqual(
            PrivacyProtocolIdV1.irohaZkX509StarkP256V1.rawValue,
            "iroha-zk-x509-stark-p256-v1"
        )
        XCTAssertEqual(
            PrivacyProtocolIdV1.irohaJindoPolynomialCommitmentV1.rawValue,
            "iroha-jindo-polynomial-commitment-v1"
        )
        XCTAssertEqual(
            PrivacyProtocolIdV1.pqMaspStarkV1.rawValue,
            "pq-masp-stark-v1"
        )
        XCTAssertEqual(
            PrivacyProofSystemIdV1(rawValue: 0),
            .starkFriSha3_384Goldilocks
        )
        XCTAssertEqual(
            PrivacyEngineIdV1(rawValue: 0),
            .nativeGoldilocksSha3_384StarkFri
        )
        let starkProtocols: [PrivacyProtocolIdV1] = [
            .zkAcePqAuthorizationV1,
            .irohaZkX509StarkP256V1,
            .irohaIvmPrivateNoteStarkV1,
            .pqMaspStarkV1,
        ]
        for protocolId in starkProtocols {
            XCTAssertEqual(protocolId.expectedProofSystem, .starkFriSha3_384Goldilocks)
            XCTAssertEqual(protocolId.expectedEngine, .nativeGoldilocksSha3_384StarkFri)
        }
    }

    func testSharedExact12MatrixBindsRoutesAndTypedEnvelopeDigests() {
        XCTAssertEqual(
            Set(Self.matrix.map { $0[0] }),
            Set(["matrix-version", "registry-sha256", "protocol", "typed-envelope"])
        )
        XCTAssertEqual(
            Self.matrix.filter { $0[0] == "matrix-version" },
            [["matrix-version", "1"]]
        )
        XCTAssertEqual(protocolRows.map { $0[1] }, (0..<12).map(String.init))
        XCTAssertEqual(Set(expected).count, 12)
        let registryPreimage = expected.map { "\($0)\n" }.joined()
        let registryDigest = SHA256.hash(data: Data(registryPreimage.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
        XCTAssertEqual(
            Self.matrix.filter { $0[0] == "registry-sha256" },
            [["registry-sha256", registryDigest]]
        )
        XCTAssertEqual(
            typedEnvelopeRows.map { Array($0[1..<4]) },
            protocolRows.map { Array($0[2..<5]) }
        )
        XCTAssertEqual(typedEnvelopeRows.count, 12)
        for row in typedEnvelopeRows {
            XCTAssertEqual(row.count, 6)
            for digest in row[4...] {
                XCTAssertNotNil(digest.range(of: "^[0-9a-f]{64}$", options: .regularExpression))
                XCTAssertNotEqual(digest, String(repeating: "0", count: 64))
            }
        }
    }

    func testAliasesAndNonCanonicalSpellingsAreRejected() {
        for rejected in [
            "iroha-zk-ams-v1 ",
            "Iroha-Zk-Ams-V1",
            "",
            "unknown-privacy-protocol-v1",
        ] {
            XCTAssertThrowsError(try PrivacyProtocolIdV1(canonicalLabel: rejected)) {
                XCTAssertEqual(
                    $0 as? PrivacyProtocolIdParseErrorV1,
                    .unknownCanonicalLabel
                )
            }
        }

        for rejectedTag in [UInt32(12), UInt32.max] {
            XCTAssertThrowsError(
                try PrivacyProtocolIdV1(noritoDiscriminant: rejectedTag)
            ) {
                XCTAssertEqual(
                    $0 as? PrivacyProtocolIdParseErrorV1,
                    .unknownNoritoDiscriminant(rejectedTag)
                )
            }
        }

        for rejectedVariant in [
            "SisWithHints",
            "IrohaZkAmsV1 ",
            "irohaZkAmsV1",
            "ZkAmsRecursiveAdmissionV0",
            "",
        ] {
            XCTAssertThrowsError(
                try PrivacyProtocolIdV1(canonicalTypedVariantLabel: rejectedVariant)
            ) {
                XCTAssertEqual(
                    $0 as? PrivacyProtocolIdParseErrorV1,
                    .unknownCanonicalTypedVariantLabel
                )
            }
        }
    }

    private static func loadExact12Matrix() -> [[String]] {
        var directory = URL(
            fileURLWithPath: FileManager.default.currentDirectoryPath,
            isDirectory: true
        )
        while directory.path != "/" {
            let candidate = directory.appendingPathComponent(
                "fixtures/privacy/exact12_v1.tsv"
            )
            if FileManager.default.fileExists(atPath: candidate.path) {
                guard
                    let text = try? String(contentsOf: candidate, encoding: .utf8),
                    text.hasSuffix("\n"),
                    !text.contains("\r"),
                    !text.dropLast().split(separator: "\n", omittingEmptySubsequences: false)
                        .contains(where: { $0.isEmpty })
                else {
                    fatalError("exact12 fixture is not canonical LF text")
                }
                return text
                    .split(separator: "\n")
                    .filter { !$0.isEmpty && !$0.hasPrefix("#") }
                    .map { $0.split(separator: "\t", omittingEmptySubsequences: false).map(String.init) }
            }
            directory.deleteLastPathComponent()
        }
        fatalError("cannot locate fixtures/privacy/exact12_v1.tsv")
    }

    func testSharedTypedValidatorStatusContractIsStable() {
        XCTAssertEqual(
            PrivacyNativeBridge.compiledProfileCatalogArchiveMaximumBytes,
            256 * 1024
        )
        XCTAssertEqual(
            PrivacyNativeBridge.exact12FixtureBundleMaximumBytes,
            2 * 1024 * 1024
        )
        XCTAssertEqual(
            PrivacyCompiledProfileCatalogValidationStatusV1.allCases.map(\.rawValue),
            Array(0...8)
        )
        XCTAssertEqual(
            PrivacyExact12FixtureValidationStatusV1.allCases.map(\.rawValue),
            Array(0...8)
        )
    }

    func testCompiledProfileCatalogPreflightRejectsEmptyAndOversizeWithoutNativeCalls() throws {
        XCTAssertEqual(
            try PrivacyNativeBridge.validateCompiledProfileCatalogV1(Data()),
            .empty
        )
        XCTAssertEqual(
            try PrivacyNativeBridge.validateCompiledProfileCatalogV1(
                Data(
                    repeating: 0,
                    count: PrivacyNativeBridge.compiledProfileCatalogArchiveMaximumBytes + 1
                )
            ),
            .archiveTooLarge
        )
    }

    func testCompiledProfileCatalogRoundTripsAndRejectsAdversarialBytes() throws {
        XCTAssertTrue(
            PrivacyNativeBridge.isNativeAvailable,
            "ABI-30 NoritoBridge with compiled-profile catalog symbols is required."
        )
        let canonical = try PrivacyNativeBridge.compiledProfileCatalogV1()
        XCTAssertFalse(canonical.isEmpty)
        XCTAssertLessThanOrEqual(
            canonical.count,
            PrivacyNativeBridge.compiledProfileCatalogArchiveMaximumBytes
        )
        XCTAssertEqual(
            try PrivacyNativeBridge.validateCompiledProfileCatalogV1(canonical),
            .valid
        )
        XCTAssertEqual(try PrivacyNativeBridge.compiledProfileCatalogV1(), canonical)

        for truncated in [
            Data(canonical.dropLast()),
            Data(canonical.dropFirst()),
            Data(canonical.prefix(canonical.count / 2)),
        ] {
            XCTAssertNotEqual(
                try PrivacyNativeBridge.validateCompiledProfileCatalogV1(truncated),
                .valid
            )
            XCTAssertThrowsError(
                try PrivacyNativeBridge.requireCompiledProfileCatalogV1(truncated)
            )
        }

        var trailing = canonical
        trailing.append(0)
        XCTAssertNotEqual(
            try PrivacyNativeBridge.validateCompiledProfileCatalogV1(trailing),
            .valid
        )
        for index in Set([0, canonical.count / 2, canonical.count - 1]) {
            var mutated = canonical
            mutated[index] ^= 0x80
            XCTAssertNotEqual(
                try PrivacyNativeBridge.validateCompiledProfileCatalogV1(mutated),
                .valid
            )
        }
    }

    func testExact12FixturePreflightRejectsEmptyAndOversizeWithoutNativeCalls() throws {
        XCTAssertEqual(
            try PrivacyNativeBridge.validateExact12FixtureBundleV1(Data()),
            .empty
        )
        XCTAssertEqual(
            try PrivacyNativeBridge.validateExact12FixtureBundleV1(
                Data(
                    repeating: 0,
                    count: PrivacyNativeBridge.exact12FixtureBundleMaximumBytes + 1
                )
            ),
            .archiveTooLarge
        )
    }

    func testExact12FixtureBundleRoundTripsAndRejectsAdversarialBytes() throws {
        XCTAssertTrue(
            PrivacyNativeBridge.isNativeAvailable,
            "ABI-30 NoritoBridge with exact-12 fixture symbols is required."
        )

        let canonical = try PrivacyNativeBridge.exact12FixtureBundleV1()
        XCTAssertFalse(canonical.isEmpty)
        XCTAssertLessThanOrEqual(
            canonical.count,
            PrivacyNativeBridge.exact12FixtureBundleMaximumBytes
        )
        XCTAssertEqual(
            try PrivacyNativeBridge.validateExact12FixtureBundleV1(canonical),
            .valid
        )
        XCTAssertEqual(try PrivacyNativeBridge.exact12FixtureBundleV1(), canonical)

        for truncated in [
            Data(canonical.dropLast()),
            Data(canonical.dropFirst()),
            Data(canonical.prefix(canonical.count / 2)),
        ] {
            XCTAssertNotEqual(
                try PrivacyNativeBridge.validateExact12FixtureBundleV1(truncated),
                .valid
            )
            XCTAssertThrowsError(
                try PrivacyNativeBridge.requireExact12FixtureBundleV1(truncated)
            )
        }

        var trailing = canonical
        trailing.append(0)
        XCTAssertNotEqual(
            try PrivacyNativeBridge.validateExact12FixtureBundleV1(trailing),
            .valid
        )

        for index in Set([0, canonical.count / 2, canonical.count - 1]) {
            var mutated = canonical
            mutated[index] ^= 0x80
            XCTAssertNotEqual(
                try PrivacyNativeBridge.validateExact12FixtureBundleV1(mutated),
                .valid
            )
        }

        let crossSchemaArchive = try PrivacyNativeBridge.compiledProfileCatalogV1()
        XCTAssertNotEqual(
            try PrivacyNativeBridge.validateExact12FixtureBundleV1(crossSchemaArchive),
            .valid
        )
    }
}
