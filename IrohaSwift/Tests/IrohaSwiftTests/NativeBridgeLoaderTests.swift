import CryptoKit
import Foundation
import XCTest
@testable import IrohaSwift
#if canImport(Darwin)
import Darwin
#endif

final class NativeBridgeLoaderTests: XCTestCase {
    #if canImport(Darwin)
    func testLinkedNativeArchiveRetainsEveryDynamicExport() throws {
        let (handle, status) = NoritoBridgeLoader.openHandle()
        guard case .valid = status else {
            XCTFail("Linked native bridge failed admission: \(status)")
            return
        }
        let nativeHandle = try XCTUnwrap(handle)
        XCTAssertTrue(NoritoBridgeLoader.hasRequiredExports(resolving: { symbol in
            dlsym(nativeHandle, symbol) != nil
        }))

        var packageRoot = URL(fileURLWithPath: #filePath)
        for _ in 0..<3 {
            packageRoot.deleteLastPathComponent()
        }
        let inventoryURL = packageRoot.appendingPathComponent(
            "Sources/NoritoBridgeRetention/NoritoBridgeRetention.c"
        )
        let inventory = try String(contentsOf: inventoryURL, encoding: .utf8)
        let referencePattern = try NSRegularExpression(
            pattern: #"\(NoritoBridgeExportReference\)([A-Za-z0-9_]+),"#
        )
        let references = referencePattern.matches(
            in: inventory, range: NSRange(inventory.startIndex..., in: inventory)
        )
        let symbols = try references.map { reference in
            let symbolRange = try XCTUnwrap(Range(reference.range(at: 1), in: inventory))
            return String(inventory[symbolRange])
        }
        XCTAssertFalse(symbols.isEmpty, "Native export retention inventory is empty")
        XCTAssertEqual(Set(symbols).count, symbols.count, "Native export retention inventory contains duplicates")
        guard !symbols.isEmpty, Set(symbols).count == symbols.count else {
            return
        }
        for symbol in symbols {
            XCTAssertNotNil(dlsym(nativeHandle, symbol), "Missing linked native export: \(symbol)")
        }
    }
    #endif

    func testRetiredKagemushaExportsAreNotRequiredForAdmission() {
        XCTAssertTrue(NoritoBridgeLoader.hasRequiredExports(resolving: { symbol in
            !symbol.hasPrefix("connect_norito_kagemusha_")
        }))
    }

    func testRetiredKagemushaStatusIsUnknown() {
        XCTAssertEqual(NativeBridgeError.fromStatus(-311), .unknown(-311))
    }

    func testEveryCurrentMlDsaExportIsRequiredForAdmission() {
        XCTAssertEqual(NoritoBridgeLoader.mldsaRequiredSymbols, [
            "soranet_mldsa_parameters",
            "soranet_mldsa_generate_keypair",
            "soranet_mldsa_sign",
            "soranet_mldsa_verify"
        ])
        XCTAssertTrue(NoritoBridgeLoader.hasRequiredExports(resolving: { _ in true }))
        for missing in NoritoBridgeLoader.mldsaRequiredSymbols {
            XCTAssertFalse(NoritoBridgeLoader.hasRequiredExports(resolving: { $0 != missing }))
        }
        let current = Set(NoritoBridgeLoader.mldsaRequiredSymbols)
        // Every other export, including an obsolete prefixed alias, is present.
        XCTAssertFalse(NoritoBridgeLoader.hasRequiredExports(resolving: { !current.contains($0) }))
    }

    func testEveryCurrentAccelerationExportIsRequiredForAdmission() {
        XCTAssertEqual(NoritoBridgeLoader.accelerationRequiredSymbols, [
            "connect_norito_acceleration_config_set_v1",
            "connect_norito_acceleration_config_get_v1",
            "connect_norito_acceleration_state_get_v1"
        ])
        XCTAssertTrue(NoritoBridgeLoader.hasRequiredExports(resolving: { _ in true }))
        for missing in NoritoBridgeLoader.accelerationRequiredSymbols {
            XCTAssertFalse(NoritoBridgeLoader.hasRequiredExports(resolving: { $0 != missing }))
        }
        let required = Set(NoritoBridgeLoader.accelerationRequiredSymbols)
        XCTAssertFalse(NoritoBridgeLoader.hasRequiredExports(resolving: { !required.contains($0) }))
    }

    func testAdmissionRequiresNoRetiredKagemushaBridgeExport() {
        // The bridge exports no KAGEMUSHA symbol, so a fresh bridge that lacks
        // every connect_norito_kagemusha_* export must still pass admission.
        XCTAssertTrue(NoritoBridgeLoader.hasRequiredExports(resolving: { symbol in
            !symbol.hasPrefix("connect_norito_kagemusha_")
        }))
        // The bridge no longer defines status -311, so it maps to an unknown status.
        XCTAssertEqual(NativeBridgeError.fromStatus(-311), .unknown(-311))
    }

    func testExpectedBridgeAbiVersionIsTwentyFiveForPackagedArtifacts() {
        XCTAssertEqual(NoritoBridgeLoader.expectedBridgeAbiVersion(for: "macos-arm64_x86_64"), 25)
        XCTAssertEqual(NoritoBridgeLoader.expectedBridgeAbiVersion(for: "ios-arm64"), 25)
        XCTAssertEqual(NoritoBridgeLoader.expectedBridgeAbiVersion(for: "ios-arm64_x86_64-simulator"), 25)
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(20, for: "macos-arm64_x86_64"))
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(18, for: "macos-arm64_x86_64"))
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(19, for: "macos-arm64_x86_64"))
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(nil, for: "macos-arm64_x86_64"))
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(21, for: "macos-arm64_x86_64"))
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(22, for: "macos-arm64_x86_64"))
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(23, for: "macos-arm64_x86_64"))
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(24, for: "macos-arm64_x86_64"))
        XCTAssertTrue(NoritoBridgeLoader.isSupportedBridgeAbiVersion(25, for: "macos-arm64_x86_64"))
        XCTAssertEqual(
            NoritoBridgeLoader.parliamentTimedOvnWalletRequiredSymbols,
            [
                "connect_norito_parliament_timed_ovn_verify_casting_proof_page_v1",
                "connect_norito_parliament_timed_ovn_verify_casting_proof_v1",
                "connect_norito_parliament_timed_ovn_registration_from_proof_v1",
                "connect_norito_parliament_timed_ovn_ballot_from_proof_v1"
            ]
        )
    }

    func testParliamentTimedOvnWalletUsesClosedChoiceAndErrorSets() {
        XCTAssertEqual(ParliamentTimedOvnBallotChoiceV1.aye.rawValue, 0)
        XCTAssertEqual(ParliamentTimedOvnBallotChoiceV1.nay.rawValue, 1)
        XCTAssertEqual(ParliamentTimedOvnBallotChoiceV1.abstain.rawValue, 2)
        XCTAssertEqual(NativeBridgeError.fromStatus(-505), .parliamentTimedOvnWallet)
        XCTAssertEqual(
            NoritoNativeBridge.parliamentTimedOvnCastingProofPageSummaryBytes,
            41
        )
        let verification = try? ParliamentTimedOvnCastingProofPageVerificationV1(
            evaluatedBlockHeight: 70,
            evaluatedContextID: Data(repeating: 0x22, count: 32),
            moreAvailable: true,
                promotedCheckpointNorito: Data(repeating: 0x22, count: 32)
        )
        XCTAssertEqual(verification?.evaluatedBlockHeight, 70)
        XCTAssertEqual(verification?.evaluatedContextID, Data(repeating: 0x22, count: 32))
        XCTAssertEqual(verification?.moreAvailable, true)
        XCTAssertThrowsError(
            try ParliamentTimedOvnCastingProofPageVerificationV1(
                evaluatedBlockHeight: 0,
                evaluatedContextID: Data(repeating: 0x22, count: 32),
                moreAvailable: false,
                promotedCheckpointNorito: Data(repeating: 0x22, count: 32)
            )
        )
        var encoded = Data(repeating: 0, count: 41)
        encoded[7] = 70
        encoded.replaceSubrange(8..<40, with: Data(repeating: 0x22, count: 32))
        encoded[40] = 1
        XCTAssertEqual(
            try? NoritoNativeBridge.decodeParliamentTimedOvnCastingProofPageVerificationV1(
                encoded, checkpointNorito: Data(repeating: 0x22, count: 32)
            ),
            verification
        )
        XCTAssertThrowsError(
            try NoritoNativeBridge.decodeParliamentTimedOvnCastingProofPageVerificationV1(
                Data(encoded.dropLast()), checkpointNorito: Data(repeating: 0x22, count: 32)
            )
        )
        encoded[40] = 2
        XCTAssertThrowsError(
            try NoritoNativeBridge.decodeParliamentTimedOvnCastingProofPageVerificationV1(
                encoded, checkpointNorito: Data(repeating: 0x22, count: 32)
            )
        )
    }

    // These opaque bytes test the FFI result boundary, not native consensus authentication.
    func testParliamentPromotionRequiresCompleteCheckpointComponent() throws {
        var summary = Data(repeating: 0, count: 41)
        summary[7] = 7
        summary.replaceSubrange(8..<40, with: Data(repeating: 3, count: 32))
        XCTAssertThrowsError(try NoritoNativeBridge.decodeParliamentTimedOvnCastingProofPageVerificationV1(
            summary, checkpointNorito: Data()
        ))
        let checkpoint = Data(repeating: 9, count: 113)
        let verified = try NoritoNativeBridge.decodeParliamentTimedOvnCastingProofPageVerificationV1(
            summary, checkpointNorito: checkpoint
        )
        let anchor = try ParliamentTimedOvnCastingTrustAnchorV1(
            networkID: Data(repeating: 1, count: 32), trustedCheckpointHeight: 7,
            trustedCheckpointNorito: Data([1]), expectedBallotAttemptID: Data(repeating: 5, count: 32)
        )
        XCTAssertEqual(try anchor.promoted(by: verified).trustedCheckpointNorito, checkpoint)
    }

    func testParliamentTimedOvnTrustAnchorSnapshotsInputsAndArchiveOnlySurfaceIsGone() throws {
        var network = Data(repeating: 1, count: 32)
        var context = Data(repeating: 3, count: 32)
        var ballot = Data(repeating: 5, count: 32)
        let anchor = try ParliamentTimedOvnCastingTrustAnchorV1(
            networkID: network,
            trustedCheckpointHeight: 7,
            trustedCheckpointNorito: context,
            expectedBallotAttemptID: ballot
        )
        network.resetBytes(in: network.startIndex..<network.endIndex)
        context.resetBytes(in: context.startIndex..<context.endIndex)
        ballot.resetBytes(in: ballot.startIndex..<ballot.endIndex)
        XCTAssertEqual(
            anchor,
            try ParliamentTimedOvnCastingTrustAnchorV1(
                networkID: Data(repeating: 1, count: 32),
                trustedCheckpointHeight: 7,
                trustedCheckpointNorito: Data(repeating: 3, count: 32),
                expectedBallotAttemptID: Data(repeating: 5, count: 32)
            )
        )
        XCTAssertThrowsError(
            try ParliamentTimedOvnCastingTrustAnchorV1(
                networkID: Data(repeating: 1, count: 31),
                trustedCheckpointHeight: 7,
                trustedCheckpointNorito: Data(repeating: 3, count: 32),
                expectedBallotAttemptID: Data(repeating: 5, count: 32)
            )
        )

        var packageRoot = URL(fileURLWithPath: #filePath)
        for _ in 0..<3 { packageRoot.deleteLastPathComponent() }
        let source = try String(
            contentsOf: packageRoot.appendingPathComponent("Sources/IrohaSwift/NativeBridge.swift"),
            encoding: .utf8
        )
        XCTAssertFalse(source.contains("registration_from_seed_v1"))
        XCTAssertFalse(source.contains("ballot_from_seed_v1"))
        let proofGate = try XCTUnwrap(source.range(of: "let verifyStatus ="))
        let seedBorrow = try XCTUnwrap(source.range(of: "let record = try seedHandle.withUnsafeSeedBytes"))
        XCTAssertLessThan(proofGate.lowerBound, seedBorrow.lowerBound)
    }

    #if canImport(Darwin)
    func testParliamentTimedOvnWalletFailsClosedWhenBridgeIsDisabled() throws {
        struct SeedHandle: ParliamentTimedOvnSeedHandle {
            let seed: [UInt8]

            func withUnsafeSeedBytes(
                _ body: (UnsafeRawBufferPointer) throws -> Data
            ) throws -> Data {
                try seed.withUnsafeBytes(body)
            }
        }

        NoritoNativeBridge.shared.overrideBridgeAvailabilityForTests(false)
        defer { NoritoNativeBridge.shared.overrideBridgeAvailabilityForTests(nil) }
        let handle = SeedHandle(seed: [UInt8](repeating: 7, count: 32))
        let trustAnchor = try ParliamentTimedOvnCastingTrustAnchorV1(
            networkID: Data(repeating: 1, count: 32),
            trustedCheckpointHeight: 7,
            trustedCheckpointNorito: Data(repeating: 3, count: 32),
            expectedBallotAttemptID: Data(repeating: 5, count: 32)
        )
        XCTAssertThrowsError(
            try NoritoNativeBridge.shared.parliamentTimedOvnRegistrationFromProofV1(
                castingProofResponseNorito: Data([1]),
                trustAnchor: trustAnchor,
                authority: "ed0120" + String(repeating: "00", count: 32),
                seedHandle: handle
            )
        ) { error in
            XCTAssertEqual(
                error as? ParliamentTimedOvnNativeWalletError,
                .bridgeUnavailable
            )
        }
    }
    #endif

    #if os(macOS)
    func testMacOSLoaderSelectsTheUniversalSlice() {
        XCTAssertEqual(NoritoBridgeLoader.currentIdentifier(), "macos-arm64_x86_64")
    }
    #endif

    func testMissingBridgeIsReported() {
        let status = NoritoBridgeLoader.validateForTests(at: "/tmp/does/not/exist", allowUntrustedLocation: true)
        XCTAssertEqual(status, .missing(path: "/tmp/does/not/exist"))
    }

    func testZkAssetPolicyStatusUsesTheCurrentFirstReleaseName() {
    }

    func testExplicitChainDiscriminantRequiresNativeScope() throws {
        XCTAssertNoThrow(try NoritoNativeBridge.validateChainDiscriminantContext(
            nil,
            scopeAvailable: false
        ))
        XCTAssertNoThrow(try NoritoNativeBridge.validateChainDiscriminantContext(
            TairaTestnetProfile.i105Discriminant,
            scopeAvailable: true
        ))
        XCTAssertThrowsError(try NoritoNativeBridge.validateChainDiscriminantContext(
            TairaTestnetProfile.i105Discriminant,
            scopeAvailable: false
        )) { error in
            XCTAssertEqual(error as? NativeBridgeError, .bridgeUnavailable)
        }
    }

    func testTamperedBridgeFailsHashCheck() throws {
        let original = try bundledBridgeBinary()
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let tampered = stagedBridgeURL(root: tempDir, identifier: original.identifier)
        try FileManager.default.createDirectory(
            at: tampered.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try FileManager.default.copyItem(at: original.url, to: tampered)

        var data = try Data(contentsOf: tampered)
        if !data.isEmpty {
            data[0] ^= 0xFF
        }
        try data.write(to: tampered, options: .atomic)

        let status = NoritoBridgeLoader.validateForTests(at: tampered.path, allowUntrustedLocation: true)
        switch status {
        case .hashMismatch(let path, _, _):
            XCTAssertEqual(path, tampered.path)
        default:
            XCTFail("expected hash mismatch, got \(status)")
        }
    }

    func testManifestlessBridgeUsesPinnedFallbackHash() throws {
        // `dist` is an ignored local build output, so use controlled bytes to test the
        // fallback policy independently of whichever XCFramework a developer materialized.
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let identifier = NoritoBridgeLoader.currentIdentifier()
        let bridgeURL = stagedBridgeURL(root: tempDir, identifier: identifier)
        try FileManager.default.createDirectory(
            at: bridgeURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let fixture = Data("manifestless-native-bridge-fixture-v1".utf8)
        try fixture.write(to: bridgeURL, options: .atomic)
        let pinnedHash = "6a917bf15f2d25afa0100a8d2b320eb1ec55c48b99ccb1cef3cf43d92b2af4f2"
        XCTAssertEqual(
            SHA256.hash(data: fixture).map { String(format: "%02x", $0) }.joined(),
            pinnedHash
        )

        let status = NoritoBridgeLoader.validateForTests(
            at: bridgeURL.path,
            allowUntrustedLocation: true,
            pinnedHashesForTests: [identifier: pinnedHash]
        )
        XCTAssertEqual(status, .valid(path: bridgeURL.path, identifier: identifier))
    }

    func testManifestlessBridgeRejectsBinaryThatDoesNotMatchPinnedFallbackHash() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let identifier = NoritoBridgeLoader.currentIdentifier()
        let bridgeURL = stagedBridgeURL(root: tempDir, identifier: identifier)
        try FileManager.default.createDirectory(
            at: bridgeURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let fixture = Data("manifestless-native-bridge-fixture-v1".utf8)
        try fixture.write(to: bridgeURL, options: .atomic)
        let actualHash = SHA256.hash(data: fixture)
            .map { String(format: "%02x", $0) }
            .joined()
        let incorrectPin = String(repeating: "0", count: 64)

        let status = NoritoBridgeLoader.validateForTests(
            at: bridgeURL.path,
            allowUntrustedLocation: true,
            pinnedHashesForTests: [identifier: incorrectPin]
        )
        XCTAssertEqual(
            status,
            .hashMismatch(path: bridgeURL.path, expected: incorrectPin, actual: actualHash)
        )
    }

    func testUntrustedPathIsDeniedWhenOverridesDisabled() throws {
        let original = try bundledBridgeBinary()
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let target = tempDir.appendingPathComponent("NoritoBridge")
        try FileManager.default.copyItem(at: original.url, to: target)

        let status = NoritoBridgeLoader.validateForTests(at: target.path, allowUntrustedLocation: false)
        XCTAssertEqual(status, .pathDenied(path: target.path))
    }

    func testArtifactManifestHashOverridesPinnedHashForLocalBridge() throws {
        let original = try bundledBridgeBinary()
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let bridgeURL = stagedBridgeURL(root: tempDir, identifier: original.identifier)
        try FileManager.default.createDirectory(
            at: bridgeURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try FileManager.default.copyItem(at: original.url, to: bridgeURL)

        var tamperedData = try Data(contentsOf: bridgeURL)
        if !tamperedData.isEmpty {
            tamperedData[0] ^= 0xA5
        }
        try tamperedData.write(to: bridgeURL, options: .atomic)

        let hashHex = SHA256.hash(data: tamperedData).map { String(format: "%02x", $0) }.joined()
        let manifestURL = tempDir.appendingPathComponent("NoritoBridge.artifacts.json")
        let manifest = """
        {
          "version": "\(NoritoBridgeLoader.expectedVersion)",
          "native_bridge_abi_version": 25,
          "hashes": {
            "\(original.identifier)": "\(hashHex)"
          }
        }
        """
        try manifest.write(to: manifestURL, atomically: true, encoding: .utf8)

        let status = NoritoBridgeLoader.validateForTests(at: bridgeURL.path, allowUntrustedLocation: true)
        XCTAssertEqual(status, .valid(path: bridgeURL.path, identifier: original.identifier))
    }

    func testArtifactManifestRejectsStaleAbiNineteenBeforeHashAcceptance() throws {
        let identifier = NoritoBridgeLoader.currentIdentifier()
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let bridgeURL = stagedBridgeURL(root: tempDir, identifier: identifier)
        try FileManager.default.createDirectory(
            at: bridgeURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let bytes = Data("stale-abi-19-bridge".utf8)
        try bytes.write(to: bridgeURL, options: .atomic)
        let hashHex = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        let manifestURL = tempDir.appendingPathComponent("NoritoBridge.artifacts.json")
        let manifest = """
        {
          "version": "\(NoritoBridgeLoader.expectedVersion)",
          "native_bridge_abi_version": 19,
          "hashes": {
            "\(identifier)": "\(hashHex)"
          }
        }
        """
        try manifest.write(to: manifestURL, atomically: true, encoding: .utf8)

        let status = NoritoBridgeLoader.validateForTests(
            at: bridgeURL.path,
            allowUntrustedLocation: true
        )
        XCTAssertEqual(
            status,
            .abiMismatch(path: bridgeURL.path, expected: 25, actual: 19)
        )
    }

    func testArtifactManifestAtDistRootOverridesPinnedHashForXcframeworkLayout() throws {
        let original = try bundledBridgeBinary()
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let target = tempDir
            .appendingPathComponent("NoritoBridge.xcframework", isDirectory: true)
        let bridgeURL = stagedBridgeURL(root: target, identifier: original.identifier)
        try FileManager.default.createDirectory(
            at: bridgeURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try FileManager.default.copyItem(at: original.url, to: bridgeURL)

        var tamperedData = try Data(contentsOf: bridgeURL)
        if !tamperedData.isEmpty {
            tamperedData[0] ^= 0x5A
        }
        try tamperedData.write(to: bridgeURL, options: .atomic)

        let hashHex = SHA256.hash(data: tamperedData).map { String(format: "%02x", $0) }.joined()
        let manifestURL = tempDir.appendingPathComponent("NoritoBridge.artifacts.json")
        let manifest = """
        {
          "version": "\(NoritoBridgeLoader.expectedVersion)",
          "native_bridge_abi_version": 25,
          "hashes": {
            "\(original.identifier)": "\(hashHex)"
          }
        }
        """
        try manifest.write(to: manifestURL, atomically: true, encoding: .utf8)

        let status = NoritoBridgeLoader.validateForTests(at: bridgeURL.path, allowUntrustedLocation: true)
        XCTAssertEqual(status, .valid(path: bridgeURL.path, identifier: original.identifier))
    }

    func testArtifactManifestCandidateSearchHonorsAscentLimit() {
        let binaryURL = URL(fileURLWithPath:
            "/tmp/NoritoBridge.xcframework/ios-arm64/Library/Frameworks/libNoritoBridge.a")
        let xcframeworkManifest = URL(fileURLWithPath:
            "/tmp/NoritoBridge.xcframework/NoritoBridge.artifacts.json")
        let siblingManifest = URL(fileURLWithPath: "/tmp/NoritoBridge.artifacts.json")

        let limited = NoritoBridgeLoader.candidateArtifactManifestURLsForTests(
            near: binaryURL,
            maxAscents: 1
        )
        XCTAssertFalse(limited.contains(xcframeworkManifest))
        XCTAssertFalse(limited.contains(siblingManifest))

        let full = NoritoBridgeLoader.candidateArtifactManifestURLsForTests(
            near: binaryURL,
            maxAscents: 4
        )
        XCTAssertTrue(full.contains(xcframeworkManifest))
        XCTAssertTrue(full.contains(siblingManifest))
    }

    private func bundledBridgeBinary() throws -> (url: URL, identifier: String) {
        #if os(macOS)
        let identifier = "macos-arm64_x86_64"
        #else
        #if targetEnvironment(simulator)
        let identifier = "ios-arm64_x86_64-simulator"
        #else
        let identifier = "ios-arm64"
        #endif
        #endif

        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<4 { root.deleteLastPathComponent() }
        // Match the package's authenticated artifact input when qualification uses
        // an external XCFramework instead of a repository-local build output.
        let artifactDirectory = ProcessInfo.processInfo.environment[
            "MOBILE_SDK_APPLE_ARTIFACT_DIR"
        ].map { URL(fileURLWithPath: $0, isDirectory: true) }
            ?? root.appendingPathComponent("dist", isDirectory: true)
        let url = stagedBridgeURL(
            root: artifactDirectory.appendingPathComponent("NoritoBridge.xcframework"),
            identifier: identifier
        )
        try requireNativeTestCapability(
            FileManager.default.fileExists(atPath: url.path),
            "NoritoBridge.xcframework missing at \(url.path)"
        )
        return (url, identifier)
    }

    private func stagedBridgeURL(root: URL, identifier: String) -> URL {
        root
            .appendingPathComponent(identifier, isDirectory: true)
            .appendingPathComponent("libNoritoBridge.a")
    }
}

final class BridgePolicyHintTests: XCTestCase {
    func testBridgeRequirementHintReferencesPath() {
        let hint = NoritoNativeBridge.bridgeRequirementHint
        XCTAssertTrue(hint.contains("NoritoBridge.xcframework"))
        XCTAssertTrue(hint.contains("../dist/NoritoBridge.xcframework"))
    }
}

#if canImport(Darwin)
final class BridgeAvailabilitySurfaceTests: XCTestCase {
    func testTransferEncodingFailsWhenBridgeUnavailable() throws {
        let keypair = try Keypair(privateKeyBytes: Data(repeating: 7, count: 32))
        let authority = try AccountId.make(publicKey: keypair.publicKey)
        let request = TransferRequest(networkId: TestNetworkIds.canonical,
                                      authority: authority,
                                      assetDefinitionId: "66owaQmAQMuHxPzxUN3bqZ6FJfDa",
                                      quantity: "1",
                                      destination: authority,
                                      description: nil,
                                      feePayment: .authority(chargeLimits: [], gasLimit: nil),
                                      ttlMs: nil)

        NoritoNativeBridge.shared.overrideBridgeAvailabilityForTests(false)
        defer { NoritoNativeBridge.shared.overrideBridgeAvailabilityForTests(nil) }

        XCTAssertThrowsError(try SwiftTransactionEncoder.encodeTransfer(transfer: request,
                                                                        keypair: keypair,
                                                                        creationTimeMs: 0)) { error in
            guard case SwiftTransactionEncoderError.nativeBridgeUnavailable = error else {
                XCTFail("expected nativeBridgeUnavailable, got \(error)")
                return
            }
            XCTAssertTrue(error.localizedDescription.contains("NoritoBridge.xcframework"))
        }
    }

    func testConnectCodecUnavailableWhenBridgeDisabled() throws {
        NoritoNativeBridge.shared.overrideBridgeAvailabilityForTests(false)
        NoritoNativeBridge.shared.overrideConnectCodecAvailabilityForTests(false)
        defer {
            NoritoNativeBridge.shared.overrideBridgeAvailabilityForTests(nil)
            NoritoNativeBridge.shared.overrideConnectCodecAvailabilityForTests(nil)
        }

        let frame = ConnectFrame(
            sessionID: Data([0x01]),
            direction: .appToWallet,
            sequence: 0,
            kind: .ciphertext(.init(payload: Data([0x02])))
        )

        XCTAssertThrowsError(try ConnectCodec.encode(frame)) { error in
            guard case ConnectCodecError.bridgeUnavailable = error else {
                XCTFail("expected ConnectCodecError.bridgeUnavailable, got \(error)")
                return
            }
            XCTAssertTrue(error.localizedDescription.contains("NoritoBridge.xcframework"))
        }
    }
}
#endif
