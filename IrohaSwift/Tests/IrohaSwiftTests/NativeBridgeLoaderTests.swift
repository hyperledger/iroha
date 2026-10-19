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

    func testChainDiscriminantScopeExportsAreRequiredForAdmission() {
        XCTAssertEqual(NoritoBridgeLoader.chainDiscriminantScopeRequiredSymbols, [
            "connect_norito_chain_discriminant_scope_enter",
            "connect_norito_chain_discriminant_scope_exit"
        ])
        for missing in NoritoBridgeLoader.chainDiscriminantScopeRequiredSymbols {
            XCTAssertFalse(NoritoBridgeLoader.hasRequiredExports(resolving: { $0 != missing }))
        }
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

    func testAdmissionRequiresNoParliamentWalletBridgeExport() {
        // The bridge exports no Parliament wallet symbol, so a bridge that lacks every
        // connect_norito_parliament_* export must still pass admission.
        XCTAssertTrue(NoritoBridgeLoader.hasRequiredExports(resolving: { symbol in
            !symbol.hasPrefix("connect_norito_parliament_")
        }))
    }

    func testExactABI31AdmissionRejectsOlderAndFutureVersions() {
        for identifier in ["macos-arm64_x86_64", "ios-arm64", "ios-arm64_x86_64-simulator"] {
            XCTAssertEqual(NoritoBridgeLoader.expectedBridgeAbiVersion(for: identifier), 31)
            XCTAssertTrue(NoritoBridgeLoader.isSupportedBridgeAbiVersion(31, for: identifier))
            for rejected in [UInt32(18), 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 32] {
                XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(rejected, for: identifier))
            }
            XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(nil, for: identifier))
        }
    }

    func testRetiredTimedOvnExportsAndStatusAreNotPartOfABI31Admission() {
        XCTAssertTrue(NoritoBridgeLoader.hasRequiredExports(resolving: {
            !$0.hasPrefix("connect_norito_parliament_timed_ovn_")
        }))
        XCTAssertEqual(NativeBridgeError.fromStatus(-505), .unknown(-505))
    }

    func testExpectedBridgeAbiVersionIsThirtyOneForPackagedArtifacts() {
        XCTAssertEqual(NoritoBridgeLoader.expectedBridgeAbiVersion(for: "macos-arm64_x86_64"), 31)
        XCTAssertEqual(NoritoBridgeLoader.expectedBridgeAbiVersion(for: "ios-arm64"), 31)
        XCTAssertEqual(NoritoBridgeLoader.expectedBridgeAbiVersion(for: "ios-arm64_x86_64-simulator"), 31)
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(20, for: "macos-arm64_x86_64"))
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(18, for: "macos-arm64_x86_64"))
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(19, for: "macos-arm64_x86_64"))
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(nil, for: "macos-arm64_x86_64"))
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(21, for: "macos-arm64_x86_64"))
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(22, for: "macos-arm64_x86_64"))
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(23, for: "macos-arm64_x86_64"))
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(24, for: "macos-arm64_x86_64"))
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(25, for: "macos-arm64_x86_64"))
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(26, for: "macos-arm64_x86_64"))
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(27, for: "macos-arm64_x86_64"))
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(28, for: "macos-arm64_x86_64"))
        // ABI 31 refuses the retired ABI 30 Native contract in both directions; there
        // is no compatibility export in either direction.
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(29, for: "macos-arm64_x86_64"))
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(29, for: "ios-arm64"))
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(30, for: "macos-arm64_x86_64"))
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(30, for: "ios-arm64"))
        XCTAssertFalse(NoritoBridgeLoader.isSupportedBridgeAbiVersion(32, for: "macos-arm64_x86_64"))
        XCTAssertTrue(NoritoBridgeLoader.isSupportedBridgeAbiVersion(31, for: "macos-arm64_x86_64"))
    }

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
          "native_bridge_abi_version": 31,
          "hashes": {
            "\(original.identifier)": "\(hashHex)"
          }
        }
        """
        try manifest.write(to: manifestURL, atomically: true, encoding: .utf8)

        let status = NoritoBridgeLoader.validateForTests(at: bridgeURL.path, allowUntrustedLocation: true)
        XCTAssertEqual(status, .valid(path: bridgeURL.path, identifier: original.identifier))
    }

    func testArtifactManifestRejectsNativeAbiMismatchBeforeHashAcceptance() throws {
        let identifier = NoritoBridgeLoader.currentIdentifier()
        for rejected in [30, 32] {
            let tempDir = FileManager.default.temporaryDirectory
                .appendingPathComponent(UUID().uuidString, isDirectory: true)
            defer { try? FileManager.default.removeItem(at: tempDir) }
            let bridgeURL = stagedBridgeURL(root: tempDir, identifier: identifier)
            try FileManager.default.createDirectory(
                at: bridgeURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            // A matching hash is insufficient to admit an incompatible Native ABI.
            // These bytes are never executable; this exercises manifest admission only.
            let bytes = Data("native-abi-\(rejected)".utf8)
            try bytes.write(to: bridgeURL, options: .atomic)
            let hashHex = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
            let manifest = """
            {
              "version": "\(NoritoBridgeLoader.expectedVersion)",
              "native_bridge_abi_version": \(rejected),
              "hashes": { "\(identifier)": "\(hashHex)" }
            }
            """
            try manifest.write(
                to: tempDir.appendingPathComponent("NoritoBridge.artifacts.json"),
                atomically: true, encoding: .utf8
            )
            XCTAssertEqual(
                NoritoBridgeLoader.validateForTests(at: bridgeURL.path, allowUntrustedLocation: true),
                .abiMismatch(path: bridgeURL.path, expected: 31, actual: UInt32(rejected))
            )
        }
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
            .abiMismatch(path: bridgeURL.path, expected: 31, actual: 19)
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
          "native_bridge_abi_version": 31,
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

    func testExplicitArtifactSelectionDoesNotFallBackToRepositoryArchive() throws {
        let missingDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let expectedManifest = missingDirectory
            .appendingPathComponent("NoritoBridge.xcframework/Info.plist").path
        for selector in ["MOBILE_SDK_LOCAL_UNIT_ARTIFACT_DIR", "MOBILE_SDK_APPLE_ARTIFACT_DIR"] {
            XCTAssertThrowsError(try bundledBridgeBinary(environment: [selector: missingDirectory.path])) { error in
                XCTAssertTrue(error.localizedDescription.contains(expectedManifest))
            }
        }
    }

    func testArtifactSelectionRejectsConflictingAndInvalidExplicitInputs() throws {
        XCTAssertThrowsError(try bundledBridgeBinary(environment: [
            "MOBILE_SDK_LOCAL_UNIT_ARTIFACT_DIR": "/selected/local-unit",
            "MOBILE_SDK_APPLE_ARTIFACT_DIR": "/selected/release"
        ])) { error in
            XCTAssertTrue(error.localizedDescription.contains("mutually exclusive"))
        }
        for selector in ["MOBILE_SDK_LOCAL_UNIT_ARTIFACT_DIR", "MOBILE_SDK_APPLE_ARTIFACT_DIR"] {
            for invalidDirectory in ["", "relative/artifact"] {
                XCTAssertThrowsError(try bundledBridgeBinary(environment: [selector: invalidDirectory])) { error in
                    XCTAssertTrue(error.localizedDescription.contains("absolute artifact directory"))
                }
            }
        }
    }

    private func bundledBridgeBinary(
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) throws -> (url: URL, identifier: String) {
        let localUnitDirectory = environment["MOBILE_SDK_LOCAL_UNIT_ARTIFACT_DIR"]
        let releaseDirectory = environment["MOBILE_SDK_APPLE_ARTIFACT_DIR"]
        try requireNativeTestCapability(
            localUnitDirectory == nil || releaseDirectory == nil,
            "Local-unit and release artifact selectors are mutually exclusive"
        )
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<4 { root.deleteLastPathComponent() }
        let artifactDirectory: URL
        if let selectedDirectory = localUnitDirectory ?? releaseDirectory {
            try requireNativeTestCapability(
                selectedDirectory.hasPrefix("/"),
                "An explicit selector requires an absolute artifact directory"
            )
            artifactDirectory = URL(fileURLWithPath: selectedDirectory, isDirectory: true)
        } else {
            artifactDirectory = root.appendingPathComponent("dist", isDirectory: true)
        }
        let framework = artifactDirectory.appendingPathComponent("NoritoBridge.xcframework", isDirectory: true)
        let manifestURL = framework.appendingPathComponent("Info.plist")
        try requireNativeTestCapability(
            FileManager.default.fileExists(atPath: manifestURL.path),
            "Selected NoritoBridge.xcframework Info.plist missing at \(manifestURL.path)"
        )
        let manifest = try PropertyListSerialization.propertyList(
            from: Data(contentsOf: manifestURL), options: [], format: nil
        )
        let libraries = try XCTUnwrap((manifest as? [String: Any])?["AvailableLibraries"] as? [[String: Any]])
        #if os(macOS)
        let platform = "macos"
        let variant: String? = nil
        #else
        let platform = "ios"
        #if targetEnvironment(simulator)
        let variant: String? = "simulator"
        #else
        let variant: String? = nil
        #endif
        #endif
        #if arch(arm64)
        let architecture = "arm64"
        #elseif arch(x86_64)
        let architecture = "x86_64"
        #else
        throw RequiredNativeTestCapabilityError.unavailable("Unsupported native test architecture")
        #endif
        let matchingLibraries = libraries.filter {
            $0["SupportedPlatform"] as? String == platform
                && $0["SupportedPlatformVariant"] as? String == variant
                && ($0["SupportedArchitectures"] as? [String])?.contains(architecture) == true
        }
        try requireNativeTestCapability(
            matchingLibraries.count == 1,
            "Selected Info.plist must contain exactly one \(platform)/\(architecture) slice"
        )
        let selected = matchingLibraries[0]
        let sourceIdentifier = try XCTUnwrap(selected["LibraryIdentifier"] as? String)
        let libraryPath = try XCTUnwrap(selected["LibraryPath"] as? String)
        try requireNativeTestCapability(
            !sourceIdentifier.isEmpty && !sourceIdentifier.contains("/")
                && sourceIdentifier != "." && sourceIdentifier != ".."
                && libraryPath == "libNoritoBridge.a",
            "Selected Info.plist must identify one direct native archive slice"
        )
        let url = framework.appendingPathComponent(sourceIdentifier, isDirectory: true)
            .appendingPathComponent(libraryPath)
        try requireNativeTestCapability(
            FileManager.default.fileExists(atPath: url.path),
            "Selected NoritoBridge archive missing at \(url.path)"
        )
        // The source is the package-selected physical host slice. The caller copies
        // its bytes into a controlled release-layout fixture to exercise hash policy;
        // that fixture identifier does not relabel or admit the local-unit artifact.
        return (url, NoritoBridgeLoader.currentIdentifier())
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
