// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
import CryptoKit
import Darwin
import Foundation
import IrohaSwift
import UIKit
import XCTest

/// Local native execution on a physical iPhone/iPad, with disposable proof witnesses.
/// These controls create no ledger transaction, installed financial owner, hardware
/// attestation or release qualification. No native capability may be skipped or mocked.
final class NativePrivacyPhysicalDeviceTests: XCTestCase {
  override func setUpWithError() throws {
    try super.setUpWithError()
    #if !os(iOS) || targetEnvironment(simulator)
    throw NSError(domain: "NativePrivacyPhysicalDeviceTests", code: 1,
      userInfo: [NSLocalizedDescriptionKey: "Select an actual iOS device; simulators are not physical evidence."])
    #else
    XCTAssertTrue(NoritoNativeBridge.shared.isAvailable, "The packaged native bridge must load")
    XCTAssertEqual(try nativeRevision("connect_norito_bridge_abi_version"), 30)
    XCTAssertEqual(try nativeRevision("connect_norito_confidential_prover_revision_v1"), 1)
    #endif
  }

  func testLoadedAbi30AndConfidentialRevision() async throws {
    let abi = try nativeRevision("connect_norito_bridge_abi_version")
    let revision = try nativeRevision("connect_norito_confidential_prover_revision_v1")
    XCTAssertEqual(abi, 30)
    XCTAssertEqual(revision, 1)
    let device = await MainActor.run {
      (UIDevice.current.model, UIDevice.current.systemName, UIDevice.current.systemVersion)
    }
    retain("native-device", ["nativeBridgeAbi": abi, "confidentialProverRevision": revision,
      "model": device.0, "system": device.1, "systemVersion": device.2])
  }

  func testNativeX25519AgreementAndMlDsaTamperRejection() throws {
    let alice = try ConnectCrypto.generateKeyPair()
    let bob = try ConnectCrypto.generateKeyPair()
    XCTAssertEqual(alice.publicKey.count, 32)
    XCTAssertEqual(bob.publicKey.count, 32)
    XCTAssertEqual(try ConnectCrypto.publicKey(fromPrivateKey: alice.privateKey), alice.publicKey)
    XCTAssertEqual(try ConnectCrypto.publicKey(fromPrivateKey: bob.privateKey), bob.publicKey)
    let session = Data((1...32).map(UInt8.init))
    let first = try ConnectCrypto.deriveDirectionKeys(localPrivateKey: alice.privateKey,
      peerPublicKey: bob.publicKey, sessionID: session)
    let second = try ConnectCrypto.deriveDirectionKeys(localPrivateKey: bob.privateKey,
      peerPublicKey: alice.publicKey, sessionID: session)
    XCTAssertEqual(first.appToWallet.count, 32)
    XCTAssertEqual(first.walletToApp.count, 32)
    XCTAssertTrue(first.appToWallet == second.appToWallet)
    XCTAssertTrue(first.walletToApp == second.walletToApp)
    XCTAssertTrue(first.appToWallet != first.walletToApp)
    XCTAssertThrowsError(try ConnectCrypto.deriveDirectionKeys(localPrivateKey: alice.privateKey,
      peerPublicKey: Data(repeating: 0, count: 32), sessionID: session))

    let keypair = try MlDsaKeypair.generate(suite: .mlDsa65)
    let message = Data("physical-native-privacy-control".utf8)
    let signature = try keypair.sign(message: message)
    XCTAssertEqual(keypair.publicKey.count, 1_952)
    XCTAssertEqual(signature.count, 3_309)
    let verified = try keypair.verify(message: message, signature: signature)
    let changedMessageVerified = try keypair.verify(message: Data("changed".utf8), signature: signature)
    XCTAssertTrue(verified)
    XCTAssertFalse(changedMessageVerified)
    var changedSignature = signature
    changedSignature[0] ^= 1
    let changedSignatureVerified = try keypair.verify(message: message, signature: changedSignature)
    XCTAssertFalse(changedSignatureVerified)
    retain("native-crypto", ["x25519AppKeyAgrees": first.appToWallet == second.appToWallet,
      "x25519WalletKeyAgrees": first.walletToApp == second.walletToApp, "mlDsaSuite": "ML-DSA-65",
      "signatureBytes": signature.count, "signatureVerified": verified,
      "tamperedMessageVerified": changedMessageVerified, "tamperedSignatureVerified": changedSignatureVerified])
  }

  func testRealRedemptionProofAndNativeRejections() async throws {
    // This is the public disposable-input domain used by the SDK native suite.
    // A local proof is not a claim that this note/root is admitted by a ledger.
    let network = try NetworkId(
      literal: "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0")
    let asset = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
    var key = Data(repeating: 2, count: 32)
    var rho = Data(repeating: 4, count: 32)
    var otherRho = Data(repeating: 5, count: 32)
    var diversifier = try ConfidentialOwnerTag.defaultDiversifier()
    defer {
      key.resetBytes(in: 0..<key.count)
      rho.resetBytes(in: 0..<rho.count)
      otherRho.resetBytes(in: 0..<otherRho.count)
      diversifier.resetBytes(in: 0..<diversifier.count)
    }
    let owner = try ConfidentialOwnerTag.deriveFromSpendKeyWithDiversifier(key, diversifier: diversifier)
    let commitment = try ConfidentialNoteCommitment.derive(asset: asset, amount: 7, rho: rho, ownerTag: owner)
    let other = try ConfidentialNoteCommitment.derive(asset: asset, amount: 7, rho: otherRho, ownerTag: owner)
    let provider = try LocalZkAssetMerklePathProvider(rootHistory: [], commitmentHistory: [commitment])
    let otherProvider = try LocalZkAssetMerklePathProvider(rootHistory: [], commitmentHistory: [other])
    let path = try await provider.getMerklePathForCommitment(asset: asset, commitment: commitment)
    let wrongPath = try await otherProvider.getMerklePathForCommitment(asset: asset, commitment: other)
    XCTAssertNotEqual(path.rootAtHeight, wrongPath.rootAtHeight)
    let prover = try ConfidentialProver(networkId: network, assetDefinitionId: asset, spendKey: key)
    key.resetBytes(in: 0..<key.count)
    defer { try? prover.close() }
    let input = try ConfidentialInput(amount: 7, rho: rho, diversifier: diversifier, leafIndex: 0)
    do {
      _ = try await prover.proveUnshield(
        tree: .commitments(root: wrongPath.rootAtHeight, leaves: [commitment]), inputs: [input], publicAmount: 7)
      XCTFail("Native proof accepted a root from another genuine tree")
    } catch { XCTAssertEqual(error as? ConfidentialProverError, .native(code: -24)) }
    let tree = ConfidentialTree.paths(root: path.rootAtHeight, paths: [path])
    do {
      _ = try await prover.proveUnshield(tree: tree, inputs: [input], publicAmount: 8)
      XCTFail("Native preflight accepted an unconserved redemption")
    } catch { XCTAssertEqual(error as? ConfidentialProverError, .native(code: -21)) }
    let start = ProcessInfo.processInfo.systemUptime
    let proof = try await prover.proveUnshield(tree: tree, inputs: [input], publicAmount: 7)
    let elapsed = ProcessInfo.processInfo.systemUptime - start
    XCTAssertEqual(proof.relation, .fullRedemption)
    XCTAssertEqual(proof.backend, "halo2/ipa")
    XCTAssertFalse(proof.proof.isEmpty)
    XCTAssertEqual(proof.root, path.rootAtHeight)
    XCTAssertEqual(proof.nullifiers.count, 1)
    XCTAssertTrue(proof.nullifiers.allSatisfy { $0.count == 32 && $0.contains(where: { $0 != 0 }) })
    XCTAssertTrue(proof.outputCommitments.isEmpty)
    retain("native-redemption", ["backend": proof.backend, "relation": proof.relation.rawValue,
      "proofBytes": proof.proof.count, "proofSha256": SHA256.hash(data: proof.proof).map { String(format: "%02x", $0) }.joined(),
      "proofElapsedSeconds": elapsed, "root": proof.root.map { String(format: "%02x", $0) }.joined(),
      "nullifierCount": proof.nullifiers.count, "outputCommitmentCount": proof.outputCommitments.count])
    let original = XCTAttachment(data: proof.proof, uniformTypeIdentifier: "public.data")
    original.name = "native-redemption-proof"
    original.lifetime = .keepAlways
    add(original)
    try prover.close()
    do {
      _ = try await prover.proveUnshield(tree: tree, inputs: [input], publicAmount: 7)
      XCTFail("Closed native owner accepted new work")
    } catch { XCTAssertEqual(error as? ConfidentialProverError, .closed) }
  }

  private func nativeRevision(_ name: String) throws -> UInt32 {
    let image = try XCTUnwrap(dlopen(nil, RTLD_NOW), "The running test host must be available")
    defer { dlclose(image) }
    let address = try XCTUnwrap(dlsym(image, name), "Missing native symbol: \(name)")
    typealias Revision = @convention(c) () -> UInt32
    return unsafeBitCast(address, to: Revision.self)()
  }

  private func retain(_ name: String, _ fields: [String: Any]) {
    // Public diagnostic metadata only. Never attach spend keys, openings or platform credentials.
    do {
      let data = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys])
      let attachment = XCTAttachment(data: data, uniformTypeIdentifier: "public.json")
      attachment.name = name
      attachment.lifetime = .keepAlways
      add(attachment)
    } catch { XCTFail("Could not retain device evidence: \(error)") }
  }
}
