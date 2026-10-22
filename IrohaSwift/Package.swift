// swift-tools-version:5.9
import Foundation
import PackageDescription
#if os(macOS)
import CryptoKit
#endif
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// Foundation standardization can rewrite /private/tmp to its /tmp symlink alias.
// Use the same physical filesystem identity as the artifact and custody guards.
guard let packageManifestPath = canonicalExistingFilesystemPath(#filePath) else {
    fatalError("error: the Swift package manifest must have an existing canonical filesystem path.")
}
let packageDirectory = URL(fileURLWithPath: packageManifestPath).deletingLastPathComponent()
let bridgeRelativePath = "../dist/NoritoBridge.xcframework"
let requiredBridgeAbiVersion = 31
let repositoryDirectory = packageDirectory.deletingLastPathComponent()
let localIntegrationArtifactDirectory = repositoryDirectory
    .appendingPathComponent("target/norito-bridge-local/artifacts", isDirectory: true).path
let localUnitArtifactParent = repositoryDirectory
    .appendingPathComponent("target/qualification", isDirectory: true).path
let configuredArtifactDirectory = ProcessInfo.processInfo.environment[
    "MOBILE_SDK_APPLE_ARTIFACT_DIR"
]
// Explicit developer-only host unit input. The release selector remains separate.
let configuredLocalUnitArtifactDirectory = ProcessInfo.processInfo.environment[
    "MOBILE_SDK_LOCAL_UNIT_ARTIFACT_DIR"
]
// Explicit physical iOS Debug input; never a reviewed Release artifact.
let configuredDeviceDemoArtifactDirectory = ProcessInfo.processInfo.environment[
    "MOBILE_SDK_APPLE_DEVICE_DEMO_ARTIFACT_DIR"
]
// A consumer-only diagnostic choice. The native producer's original commit and
// artifact evidence stay authoritative; this never selects a Release artifact.
let deviceDemoSourceHeadDriftInput = ProcessInfo.processInfo.environment[
    "MOBILE_SDK_APPLE_DEVICE_DEMO_ALLOW_SOURCE_HEAD_DRIFT"
]
guard deviceDemoSourceHeadDriftInput == nil
    || deviceDemoSourceHeadDriftInput == "0"
    || deviceDemoSourceHeadDriftInput == "1"
else {
    fatalError("error: MOBILE_SDK_APPLE_DEVICE_DEMO_ALLOW_SOURCE_HEAD_DRIFT must be exactly 0 or 1.")
}
let allowDeviceDemoSourceHeadDrift = deviceDemoSourceHeadDriftInput == "1"
let deviceDemoConsumptionReceipt = ProcessInfo.processInfo.environment[
    "MOBILE_SDK_APPLE_DEVICE_DEMO_CONSUMPTION_RECEIPT"
]
if allowDeviceDemoSourceHeadDrift || deviceDemoConsumptionReceipt != nil {
    guard configuredDeviceDemoArtifactDirectory != nil else {
        fatalError("error: source-head drift and its receipt require the physical-device demo selector.")
    }
}
if allowDeviceDemoSourceHeadDrift && deviceDemoConsumptionReceipt == nil {
    fatalError("error: source-head drift requires a separate physical-device demo consumption receipt.")
}
let selectedArtifactDirectory = configuredDeviceDemoArtifactDirectory ?? configuredLocalUnitArtifactDirectory ?? configuredArtifactDirectory
let requireExternalArtifactInput = ProcessInfo.processInfo.environment[
    "MOBILE_SDK_REQUIRE_EXTERNAL_APPLE_ARTIFACT"
]
guard requireExternalArtifactInput == nil
    || requireExternalArtifactInput == "0"
    || requireExternalArtifactInput == "1"
else {
    fatalError(
        "error: MOBILE_SDK_REQUIRE_EXTERNAL_APPLE_ARTIFACT must be exactly 0 or 1."
    )
}
let requireExternalArtifact = requireExternalArtifactInput == "1"
if configuredDeviceDemoArtifactDirectory != nil,
    requireExternalArtifact || configuredArtifactDirectory != nil || configuredLocalUnitArtifactDirectory != nil {
    fatalError("error: physical-device demo artifacts cannot enter an external/release or local-unit corridor.")
}
if configuredLocalUnitArtifactDirectory != nil,
    requireExternalArtifact || configuredArtifactDirectory != nil {
    fatalError("error: local-unit artifacts cannot enter an external/release artifact corridor.")
}
#if !os(macOS)
if configuredLocalUnitArtifactDirectory != nil {
    fatalError("error: local-unit artifacts require a macOS host.")
}
#endif
if requireExternalArtifact, configuredArtifactDirectory == nil {
    fatalError(
        """
        error: reviewed Release builds require MOBILE_SDK_APPLE_ARTIFACT_DIR \
        to identify an authenticated artifact directory outside the Iroha source tree.
        """
    )
}

func relativePath(from base: URL, to destination: URL) -> String {
    let baseComponents = base.pathComponents
    let destinationComponents = destination.pathComponents
    var commonComponentCount = 0
    while
        commonComponentCount < baseComponents.count,
        commonComponentCount < destinationComponents.count,
        baseComponents[commonComponentCount] == destinationComponents[commonComponentCount]
    {
        commonComponentCount += 1
    }
    let parentComponents = Array(
        repeating: "..",
        count: baseComponents.count - commonComponentCount
    )
    let childComponents = destinationComponents.dropFirst(commonComponentCount)
    return (parentComponents + childComponents).joined(separator: "/")
}

func canonicalExistingFilesystemPath(_ path: String) -> String? {
    path.withCString { encodedPath in
        guard let resolvedPath = realpath(encodedPath, nil) else {
            return nil
        }
        defer { free(resolvedPath) }
        return String(cString: resolvedPath)
    }
}

let bridgeAbsolutePath: URL
let bridgeTargetPath: String
if let configuredArtifactDirectory = selectedArtifactDirectory {
    guard configuredArtifactDirectory.hasPrefix("/") else {
        fatalError("error: MOBILE_SDK_APPLE_ARTIFACT_DIR must be an absolute path.")
    }
    guard
        let canonicalArtifactDirectory =
            canonicalExistingFilesystemPath(configuredArtifactDirectory),
        canonicalArtifactDirectory == configuredArtifactDirectory
    else {
        fatalError(
            """
            error: MOBILE_SDK_APPLE_ARTIFACT_DIR must be an existing canonical \
            path that does not traverse a symbolic link.
            """
        )
    }
    let resolvedURL = URL(
        fileURLWithPath: canonicalArtifactDirectory,
        isDirectory: true
    )
    if configuredLocalUnitArtifactDirectory != nil {
        guard resolvedURL.path.hasPrefix(localUnitArtifactParent + "/"),
            let attributes = try? FileManager.default.attributesOfItem(atPath: resolvedURL.path),
            attributes[.type] as? FileAttributeType == .typeDirectory,
            (attributes[.ownerAccountID] as? NSNumber)?.intValue == Int(geteuid()),
            (attributes[.posixPermissions] as? NSNumber)?.intValue == 0o700
        else {
            fatalError("error: local-unit artifact directory must be below target/qualification, owned, canonical and mode 0700.")
        }
    } else {
        guard
            resolvedURL.path != repositoryDirectory.path,
            !resolvedURL.path.hasPrefix(repositoryDirectory.path + "/")
                || (!requireExternalArtifact && resolvedURL.path == localIntegrationArtifactDirectory)
        else {
            fatalError(
                "error: MOBILE_SDK_APPLE_ARTIFACT_DIR must be outside the reviewed Iroha source tree."
            )
        }
    }
    bridgeAbsolutePath = resolvedURL
        .appendingPathComponent("NoritoBridge.xcframework", isDirectory: true)
    bridgeTargetPath = relativePath(
        from: packageDirectory,
        to: bridgeAbsolutePath
    )
} else {
    bridgeAbsolutePath = repositoryDirectory
        .appendingPathComponent("dist/NoritoBridge.xcframework", isDirectory: true)
    bridgeTargetPath = bridgeRelativePath
}

#if os(macOS)
func localUnitSHA256(_ url: URL) -> String? {
    guard canonicalExistingFilesystemPath(url.path) == url.path,
        let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
        attributes[.type] as? FileAttributeType == .typeRegular,
        let handle = try? FileHandle(forReadingFrom: url)
    else { return nil }
    defer { try? handle.close() }
    var digest = SHA256()
    do {
        while let bytes = try handle.read(upToCount: 1024 * 1024), !bytes.isEmpty {
            digest.update(data: bytes)
        }
    } catch { return nil }
    return digest.finalize().map { String(format: "%02x", $0) }.joined()
}

func deviceDemoSourceCommit() -> String? {
    let git = Process(); let output = Pipe()
    git.executableURL = URL(fileURLWithPath: "/usr/bin/git")
    git.arguments = ["-C", repositoryDirectory.path, "rev-parse", "HEAD"]
    git.standardOutput = output
    do { try git.run(); git.waitUntilExit() } catch { return nil }
    guard git.terminationStatus == 0,
        let commit = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines),
        commit.count == 40,
        commit.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
    else { return nil }
    return commit
}

func validateDeviceDemoConsumption(_ record: [String: Any], outside artifactRoot: URL) -> String? {
    guard let selectedPath = deviceDemoConsumptionReceipt else { return nil }
    let destination = URL(fileURLWithPath: selectedPath)
    let parent = destination.deletingLastPathComponent()
    guard selectedPath.hasPrefix("/"), destination.path == selectedPath,
        canonicalExistingFilesystemPath(parent.path) == parent.path,
        !selectedPath.hasPrefix(artifactRoot.deletingLastPathComponent().path + "/"),
        selectedPath != artifactRoot.deletingLastPathComponent().path,
        let bytes = try? JSONSerialization.data(withJSONObject: record, options: [.sortedKeys])
    else { return "error: device-demo consumption receipt requires a canonical path outside the artifact directory." }
    // SwiftPM evaluates manifests in a read-only sandbox. The explicit consumer
    // wrapper retains this separate record first; this owner checks every field
    // against its own successful artifact validation and never rewrites evidence.
    guard FileManager.default.fileExists(atPath: selectedPath) else {
        return "error: device-demo consumption requires a prepared receipt from the consumer wrapper."
    }
    guard canonicalExistingFilesystemPath(selectedPath) == selectedPath,
        let attributes = try? FileManager.default.attributesOfItem(atPath: selectedPath),
        attributes[.type] as? FileAttributeType == .typeRegular,
        let existing = try? Data(contentsOf: destination),
        let object = try? JSONSerialization.jsonObject(with: existing),
        let canonical = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]),
        canonical == bytes
    else { return "error: existing device-demo consumption receipt differs; select a fresh receipt path." }
    return nil
}

func validateDeviceDemoArtifact(
    at artifactRoot: URL,
    libraries: [[String: Any]],
    manifest: [String: Any]
) -> String? {
    let identifier = "ios-arm64"
    guard manifest["schema"] as? String == "iroha.norito-bridge-device-demo-artifact.v1",
        manifest["artifact_scope"] as? String == "physical-device-demo",
        manifest["purpose"] as? String == "physical-ios-debug",
        manifest["native_bridge_abi_version"] as? Int == requiredBridgeAbiVersion,
        manifest["target_triple"] as? String == "aarch64-apple-ios",
        manifest["source_root"] as? String == repositoryDirectory.path,
        let commit = manifest["source_commit"] as? String, commit.count == 40,
        commit.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
        libraries.count == 1, let library = libraries.first,
        library["LibraryIdentifier"] as? String == identifier,
        library["LibraryPath"] as? String == "libNoritoBridge.a",
        library["BinaryPath"] == nil || library["BinaryPath"] as? String == "libNoritoBridge.a",
        library["HeadersPath"] as? String == "Headers",
        library["SupportedArchitectures"] as? [String] == ["arm64"],
        library["SupportedPlatform"] as? String == "ios",
        library["SupportedPlatformVariant"] == nil,
        let hashes = manifest["hashes"] as? [String: String], Set(hashes.keys) == Set([identifier]),
        localUnitSHA256(artifactRoot.appendingPathComponent(identifier + "/libNoritoBridge.a")) == hashes[identifier],
        let evidence = manifest["evidence"] as? [String: String],
        Set(evidence.keys) == Set(["producer-launch.json", "producer-record.json", "cargo-messages.jsonl",
                                  "pqcrypto-normalization.json", "consumer", "source-observation.json"])
    else { return "error: physical-device demo metadata or archive is not exact." }
    guard let currentCommit = deviceDemoSourceCommit()
    else { return "error: unable to observe the selected source commit." }
    guard currentCommit == commit || allowDeviceDemoSourceHeadDrift
    else { return "error: physical-device demo source commit differs from the selected checkout." }
    guard let manifestHash = localUnitSHA256(artifactRoot.appendingPathComponent("NoritoBridge.artifacts.json"))
    else { return "error: physical-device demo manifest has no canonical file identity." }
    for (name, hash) in evidence {
        guard localUnitSHA256(artifactRoot.appendingPathComponent("evidence/" + name)) == hash
        else { return "error: physical-device demo evidence changed: \(name)." }
    }
    guard let receiptData = try? Data(contentsOf: artifactRoot.appendingPathComponent("evidence/producer-record.json")),
        let receipt = (try? JSONSerialization.jsonObject(with: receiptData)) as? [String: Any],
        receipt["status"] as? String == "ios-device-staged-full-producer-continues",
        receipt["sourceCommit"] as? String == commit,
        receipt["sourceRoot"] as? String == repositoryDirectory.path,
        receipt["archiveSha256"] as? String == hashes[identifier],
        let launchData = try? Data(contentsOf: artifactRoot.appendingPathComponent("evidence/producer-launch.json")),
        let launch = (try? JSONSerialization.jsonObject(with: launchData)) as? [String: Any],
        launch["sourceCommit"] as? String == commit,
        launch["sourceRoot"] as? String == repositoryDirectory.path
    else { return "error: physical-device demo producer origin differs." }
    let headers = [
        "NoritoBridge.h": "crates/connect_norito_bridge/include/NoritoBridge.h",
        "connect_norito_bridge.h": "crates/connect_norito_bridge/include/connect_norito_bridge.h",
        "module.modulemap": "crates/connect_norito_bridge/module.modulemap.template"
    ]
    for (name, source) in headers {
        guard let sourceHash = localUnitSHA256(repositoryDirectory.appendingPathComponent(source)),
            localUnitSHA256(artifactRoot.appendingPathComponent(identifier + "/Headers/" + name)) == sourceHash
        else { return "error: physical-device demo header differs from current source: \(name)." }
    }
    guard deviceDemoSourceCommit() == currentCommit,
        localUnitSHA256(artifactRoot.appendingPathComponent("NoritoBridge.artifacts.json")) == manifestHash,
        localUnitSHA256(artifactRoot.appendingPathComponent(identifier + "/libNoritoBridge.a")) == hashes[identifier],
        evidence.allSatisfy({ localUnitSHA256(artifactRoot.appendingPathComponent("evidence/" + $0.key)) == $0.value })
    else { return "error: physical-device demo source or artifact changed during validation." }
    return validateDeviceDemoConsumption([
        "schema": "iroha.norito-bridge-device-demo-consumption.v1",
        "purpose": "physical-ios-debug",
        "artifact_root": artifactRoot.path,
        "artifact_source_commit": commit,
        "current_source_commit": currentCommit,
        "allow_source_head_drift": allowDeviceDemoSourceHeadDrift,
        "source_head_drifted": currentCommit != commit,
        "native_bridge_abi_version": requiredBridgeAbiVersion,
        "target_triple": "aarch64-apple-ios",
        "archive_sha256": hashes[identifier]!,
        "artifact_manifest_sha256": manifestHash,
        "evidence": evidence
    ], outside: artifactRoot)
}

func validateLocalUnitArtifact(
    at artifactRoot: URL,
    libraries: [[String: Any]],
    manifest: [String: Any]
) -> String? {
    #if arch(arm64)
    let architecture = "arm64"
    let targetTriple = "aarch64-apple-darwin"
    #elseif arch(x86_64)
    let architecture = "x86_64"
    let targetTriple = "x86_64-apple-darwin"
    #else
    return "error: local-unit artifact host architecture is unsupported."
    #endif
    let identifier = "macos-" + architecture
    let fields: Set<String> = [
        "schema", "artifact_scope", "purpose", "version", "native_bridge_abi_version",
        "target_triple", "hashes", "source_inputs", "tool_inputs", "receipt_inputs",
        "producer_record", "producer_record_sha256"
    ]
    guard Set(manifest.keys) == fields,
        manifest["schema"] as? String == "iroha.norito-bridge-local-unit-artifact.v1",
        manifest["artifact_scope"] as? String == "local-unit",
        manifest["purpose"] as? String == "macos-swift-debug-unit-tests",
        manifest["version"] as? String == "0.1.0",
        manifest["native_bridge_abi_version"] as? Int == requiredBridgeAbiVersion,
        manifest["target_triple"] as? String == targetTriple,
        libraries.count == 1,
        let library = libraries.first,
        Set(library.keys).subtracting(["BinaryPath"]) == Set([
            "LibraryIdentifier", "LibraryPath", "HeadersPath",
            "SupportedArchitectures", "SupportedPlatform"
        ]),
        library["BinaryPath"] == nil || library["BinaryPath"] as? String == "libNoritoBridge.a",
        library["LibraryIdentifier"] as? String == identifier,
        library["LibraryPath"] as? String == "libNoritoBridge.a",
        library["HeadersPath"] as? String == "Headers",
        library["SupportedArchitectures"] as? [String] == [architecture],
        library["SupportedPlatform"] as? String == "macos",
        let hashes = manifest["hashes"] as? [String: String],
        Set(hashes.keys) == Set([identifier]),
        localUnitSHA256(artifactRoot.appendingPathComponent(identifier)
            .appendingPathComponent("libNoritoBridge.a")) == hashes[identifier]
    else { return "error: local-unit archive/host metadata is not exact." }

    let headers = [
        "NoritoBridge.h": "crates/connect_norito_bridge/include/NoritoBridge.h",
        "connect_norito_bridge.h": "crates/connect_norito_bridge/include/connect_norito_bridge.h",
        "module.modulemap": "crates/connect_norito_bridge/module.modulemap.template"
    ]
    for (name, source) in headers {
        let expected = localUnitSHA256(repositoryDirectory.appendingPathComponent(source))
        guard expected != nil,
            localUnitSHA256(artifactRoot.appendingPathComponent(identifier)
                .appendingPathComponent("Headers").appendingPathComponent(name)) == expected
        else { return "error: local-unit headers differ from current source." }
    }
    // The repository-owned verifier rederives the full source/dep-info membership,
    // immutable emitter/static/ABI relationships, exact five native children,
    // original normalization and crypto consumer, and actual framework contents.
    for key in ["source_inputs", "tool_inputs", "receipt_inputs"] {
        guard let inputs = manifest[key] as? [String: String], !inputs.isEmpty else {
            return "error: local-unit custody input inventory is missing."
        }
    }
    let outputDirectory = artifactRoot.deletingLastPathComponent()
    guard manifest["producer_record"] as? String
            == outputDirectory.appendingPathComponent("producer-record.json").path,
        let producerHash = manifest["producer_record_sha256"] as? String,
        producerHash.count == 64,
        producerHash.allSatisfy({ "0123456789abcdef".contains($0) }),
        localUnitSHA256(outputDirectory.appendingPathComponent("producer-record.json")) == producerHash
    else { return "error: local-unit producer record is missing or changed." }

    let pythonCandidates: [String]
    if let configuredPython = ProcessInfo.processInfo.environment["MOBILE_SDK_PYTHON_BINARY"] {
        guard configuredPython.hasPrefix("/") else {
            return "error: MOBILE_SDK_PYTHON_BINARY must be an absolute Python 3.12 path."
        }
        pythonCandidates = [configuredPython]
    } else {
        pythonCandidates = ["/opt/homebrew/opt/python@3.12/bin/python3.12",
                            "/usr/local/opt/python@3.12/bin/python3.12"]
    }
    guard let python = pythonCandidates.compactMap(canonicalExistingFilesystemPath).first,
        let producer = try? Data(contentsOf: outputDirectory.appendingPathComponent("producer-record.json")),
        let record = try? JSONSerialization.jsonObject(with: producer) as? [String: Any],
        let configuration = record["config"] as? [String: String],
        let producerPython = configuration["python"],
        canonicalExistingFilesystemPath(producerPython) == python
    else { return "error: local-unit verifier requires the producer's guarded Python 3.12." }
    let verifier = repositoryDirectory.appendingPathComponent("scripts/norito_bridge_local_unit.py")
    guard canonicalExistingFilesystemPath(verifier.path) == verifier.path else {
        return "error: local-unit repository verifier is missing or aliased."
    }
    let process = Process()
    let diagnostic = Pipe()
    process.executableURL = URL(fileURLWithPath: python)
    process.arguments = ["-I", "-S", "-B", verifier.path, "verify", "--root", repositoryDirectory.path,
                         "--output", outputDirectory.path, "--producer-sha256", producerHash]
    process.currentDirectoryURL = repositoryDirectory
    process.environment = ["PATH": "/usr/bin:/bin", "HOME": NSHomeDirectory(), "LANG": "C.UTF-8",
                           "LC_ALL": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"]
    process.standardOutput = diagnostic
    process.standardError = diagnostic
    do {
        try process.run()
        let output = diagnostic.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationReason == .exit, process.terminationStatus == 0 else {
            let detail = String(decoding: output.prefix(4096), as: UTF8.self)
            return "error: local-unit current-input verification refused: \(detail)"
        }
    } catch { return "error: unable to execute the repository local-unit verifier: \(error)" }
    return nil
}
#endif

func validateBridgeArtifact(at artifactRoot: URL) -> String? {
    guard FileManager.default.fileExists(atPath: artifactRoot.path) else {
        return """
        error: NoritoBridge.xcframework is required at \(artifactRoot.path). \
        Set MOBILE_SDK_APPLE_ARTIFACT_DIR to the external directory containing \
        NoritoBridge.xcframework before building a reviewed source closure.
        """
    }

    let infoURL = artifactRoot.appendingPathComponent("Info.plist")
    guard
        let data = try? Data(contentsOf: infoURL),
        let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
        let dictionary = plist as? [String: Any],
        let libraries = dictionary["AvailableLibraries"] as? [[String: Any]],
        !libraries.isEmpty
    else {
        return "error: NoritoBridge.xcframework at \(artifactRoot.path) has unreadable metadata."
    }

    for library in libraries {
        let identifier = library["LibraryIdentifier"] as? String ?? "<unknown>"
        let relativePaths = ["BinaryPath", "LibraryPath"].compactMap { library[$0] as? String }
        guard !relativePaths.isEmpty else {
            return "error: NoritoBridge.xcframework slice \(identifier) is missing BinaryPath/LibraryPath metadata."
        }

        for relativePath in relativePaths {
            let referencedURL = artifactRoot
                .appendingPathComponent(identifier, isDirectory: true)
                .appendingPathComponent(relativePath)
            guard FileManager.default.fileExists(atPath: referencedURL.path) else {
                return "error: NoritoBridge.xcframework slice \(identifier) is missing \(relativePath)."
            }
        }
    }

    let artifactManifestURL = artifactRoot.appendingPathComponent(
        "NoritoBridge.artifacts.json"
    )
    guard
        let manifestData = try? Data(contentsOf: artifactManifestURL),
        let manifest = try? JSONSerialization.jsonObject(with: manifestData)
            as? [String: Any],
        let bridgeAbiVersion = manifest["native_bridge_abi_version"] as? Int
    else {
        return "error: NoritoBridge.xcframework is missing readable ABI-bound artifact metadata."
    }
    if configuredDeviceDemoArtifactDirectory != nil {
        #if os(macOS)
        guard !requireExternalArtifact,
            dictionary["CFBundlePackageType"] as? String == "XFWK",
            dictionary["XCFrameworkFormatVersion"] as? String == "1.0",
            canonicalExistingFilesystemPath(artifactRoot.path) == artifactRoot.path
        else { return "error: physical-device demo artifact path is not canonical." }
        return validateDeviceDemoArtifact(at: artifactRoot, libraries: libraries, manifest: manifest)
        #else
        return "error: physical-device demo artifacts require a macOS build host."
        #endif
    }
    if configuredLocalUnitArtifactDirectory != nil {
        #if os(macOS)
        guard !requireExternalArtifact,
            dictionary["CFBundlePackageType"] as? String == "XFWK",
            dictionary["XCFrameworkFormatVersion"] as? String == "1.0",
            canonicalExistingFilesystemPath(artifactRoot.path) == artifactRoot.path
        else { return "error: local-unit artifact path is not canonical." }
        return validateLocalUnitArtifact(at: artifactRoot, libraries: libraries, manifest: manifest)
        #else
        return "error: local-unit artifacts require a macOS host."
        #endif
    }
    let isLocalIntegration = artifactRoot.deletingLastPathComponent().path
        == localIntegrationArtifactDirectory
    if isLocalIntegration {
        guard !requireExternalArtifact,
            manifest["artifact_scope"] as? String == "local-integration",
            canonicalExistingFilesystemPath(artifactRoot.path) == artifactRoot.path
        else {
            return "error: checkout-local NoritoBridge requires its local-integration scope; release use is forbidden."
        }
    } else if manifest["artifact_scope"] != nil {
        return "error: a local-integration NoritoBridge cannot be consumed as a release artifact."
    }
    guard bridgeAbiVersion == requiredBridgeAbiVersion else {
        return "error: NoritoBridge.xcframework requires exact native bridge ABI \(requiredBridgeAbiVersion); found \(bridgeAbiVersion)."
    }

    return nil
}

if let bridgeArtifactError = validateBridgeArtifact(at: bridgeAbsolutePath) {
    fatalError(bridgeArtifactError)
}
var targets: [Target] = []
var irohaSwiftDependencies: [Target.Dependency] = []
var testDependencies: [Target.Dependency] = ["IrohaSwift"]
var irohaSwiftLinkerSettings: [LinkerSetting] = []

targets.append(
    .binaryTarget(
        name: "NoritoBridge",
        path: bridgeTargetPath
    )
)
let bridgeDependency: Target.Dependency = .target(name: "NoritoBridge", condition: .when(platforms: [.iOS, .macOS]))
irohaSwiftDependencies.append(bridgeDependency)
testDependencies.append(bridgeDependency)
// Ordinary C references retain the dlsym exports while keeping this product
// eligible for use as a versioned dependency in another Swift package.
targets.append(
    .target(
        name: "NoritoBridgeRetention",
        dependencies: [bridgeDependency],
        path: "Sources/NoritoBridgeRetention",
        publicHeadersPath: "include"
    )
)
irohaSwiftDependencies.append(
    .target(name: "NoritoBridgeRetention", condition: .when(platforms: [.iOS, .macOS]))
)
// The retained Rust archive uses these Apple frameworks directly. Declare them
// on the library so executable and test consumers inherit the native link inputs.
irohaSwiftLinkerSettings.append(.linkedFramework("Foundation", .when(platforms: [.iOS, .macOS])))
irohaSwiftLinkerSettings.append(.linkedFramework("Security", .when(platforms: [.iOS, .macOS])))
irohaSwiftLinkerSettings.append(.linkedFramework("Metal", .when(platforms: [.iOS, .macOS])))
irohaSwiftLinkerSettings.append(.linkedFramework("CoreGraphics", .when(platforms: [.iOS, .macOS])))
irohaSwiftLinkerSettings.append(.linkedFramework("Accelerate", .when(platforms: [.iOS, .macOS])))

var swiftSettings: [SwiftSetting] = [
    .define("IROHA_SWIFT"),
    .define("IROHASWIFT_ENABLE_SECP256K1"),
    .define("IROHASWIFT_ENABLE_MLDSA"),
    .define("IROHASWIFT_ENABLE_BLS"),
    .define("IROHASWIFT_ENABLE_GOST"),
    .define("IROHASWIFT_ENABLE_SM"),
    .define("IROHASWIFT_BRIDGE_REQUIRED"),
    .define("IROHASWIFT_BRIDGE_PRESENT")
]
if configuredDeviceDemoArtifactDirectory != nil {
    swiftSettings.append(.define("IROHASWIFT_DEVICE_DEMO_ARTIFACT"))
    swiftSettings.append(.define("IROHASWIFT_DEVICE_DEMO_DEBUG", .when(configuration: .debug)))
}
if configuredLocalUnitArtifactDirectory != nil {
    swiftSettings.append(.define("IROHASWIFT_LOCAL_UNIT_ARTIFACT"))
    swiftSettings.append(.define("IROHASWIFT_LOCAL_UNIT_DEBUG", .when(configuration: .debug)))
}
// Keep Google's Apple Nearby implementation deterministic for fresh Xcode
// checkouts. Nearby's transitive Abseil branch is additionally locked by the
// checked-in Package.resolved file.
let packageDependencies: [Package.Dependency] = [
    .package(
        url: "https://github.com/google/nearby.git",
        revision: "53568fe88281d4408e48e3ebec7d8560bed7077d"
    ),
    .package(
        url: "https://github.com/firebase/boringssl-SwiftPM.git",
        exact: "0.7.2"
    )
]
let mobileTransportDependencies: [Target.Dependency] = [
    "IrohaSwift",
    .product(
        name: "NearbyConnections",
        package: "nearby",
        condition: .when(platforms: [.iOS, .macOS])
    )
]
let mobileTransportTestDependencies: [Target.Dependency] =
    testDependencies + ["IrohaSwiftMobileTransports"]

let package = Package(
    name: "IrohaSwift",
    platforms: [
        .iOS(.v15),
        .macOS(.v12)
    ],
    products: [
        .executable(name: "confidential-redemption-example", targets: ["ConfidentialRedemptionExample"]),
        .library(
            name: "IrohaSwift",
            targets: ["IrohaSwift"]),
        .library(
            name: "IrohaSwiftMobileTransports",
            targets: ["IrohaSwiftMobileTransports"]),
        .library(
            name: "IrohaSwiftTransferUI",
            targets: ["IrohaSwiftTransferUI"])
    ],
    dependencies: packageDependencies,
    targets: targets + [
        .executableTarget(
            name: "ConfidentialRedemptionExample",
            dependencies: ["IrohaSwift"],
            path: "Examples/ConfidentialRedemption"
        ),
        .target(
            name: "IrohaSwift",
            dependencies: irohaSwiftDependencies,
            path: "Sources/IrohaSwift",
            exclude: [],
            resources: [],
            swiftSettings: swiftSettings,
            linkerSettings: irohaSwiftLinkerSettings
        ),
        .target(
            name: "IrohaSwiftMobileTransports",
            dependencies: mobileTransportDependencies,
            path: "Sources/IrohaSwiftMobileTransports",
            swiftSettings: swiftSettings
        ),
        .target(
            name: "IrohaSwiftTransferUI",
            dependencies: ["IrohaSwift"],
            path: "Sources/IrohaSwiftTransferUI",
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "IrohaSwiftTests",
            dependencies: testDependencies,
            path: "Tests/IrohaSwiftTests",
            resources: [
                .process("Fixtures")
            ],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "IrohaSwiftMobileTransportsTests",
            dependencies: mobileTransportTestDependencies,
            path: "Tests/IrohaSwiftMobileTransportsTests",
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "IrohaSwiftTransferUITests",
            dependencies: testDependencies + ["IrohaSwiftTransferUI"],
            path: "Tests/IrohaSwiftTransferUITests",
            swiftSettings: swiftSettings
        )
    ]
)
