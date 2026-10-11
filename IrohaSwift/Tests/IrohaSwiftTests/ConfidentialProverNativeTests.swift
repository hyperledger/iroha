import Foundation
import XCTest
import IrohaSwift

/// Requires the current authenticated native artifact; never substitutes a mock or skips it.
final class ConfidentialProverNativeTests: XCTestCase {
    func testRetainedChangeCanBeRedeemedWithItsDefaultOwner() async throws {
        let asset = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
        var key = Data(repeating: 9, count: 32)
        var rho = Data(repeating: 10, count: 32)
        var diversifier = Data(repeating: 7, count: 32)
        var changeRho = Data(repeating: 11, count: 32)
        defer {
            key.resetBytes(in: 0..<key.count)
            rho.resetBytes(in: 0..<rho.count)
            diversifier.resetBytes(in: 0..<diversifier.count)
            changeRho.resetBytes(in: 0..<changeRho.count)
        }
        let owner = try ConfidentialOwnerTag.deriveFromSpendKeyWithDiversifier(key, diversifier: diversifier)
        let commitment = try ConfidentialNoteCommitment.derive(asset: asset, amount: 7, rho: rho, ownerTag: owner)
        let provider = try LocalZkAssetMerklePathProvider(rootHistory: [], commitmentHistory: [commitment])
        let path = try await provider.getMerklePathForCommitment(asset: asset, commitment: commitment)
        let prover = try ConfidentialProver(networkId: TestNetworkIds.canonical,
                                           assetDefinitionId: asset, spendKey: key)
        defer { try? prover.close() }
        let input = try ConfidentialInput(amount: 7, rho: rho, diversifier: diversifier, leafIndex: 0)
        // Retain the opening before proving. This test's next tree is local;
        // a wallet must authenticate its real change index and root separately.
        let change = try ConfidentialChange(amount: 3, rho: changeRho)
        let partial = try await prover.proveUnshield(tree: .paths(root: path.rootAtHeight, paths: [path]),
                                                     inputs: [input], publicAmount: 4, change: change)
        XCTAssertEqual(partial.relation, .redemptionWithChange)
        XCTAssertEqual(partial.backend, "pipa-r/pasta")
        XCTAssertFalse(partial.proof.isEmpty)
        XCTAssertEqual(partial.root, path.rootAtHeight)
        XCTAssertEqual(partial.nullifiers.count, 1)
        XCTAssertTrue(partial.nullifiers.allSatisfy { $0.count == 32 && $0.contains(where: { $0 != 0 }) })
        let nextInput = try change.asInput(leafIndex: 1)
        XCTAssertEqual(nextInput.leafIndex, 1)
        XCTAssertEqual(nextInput.diversifier, try ConfidentialOwnerTag.defaultDiversifier())
        XCTAssertNotEqual(nextInput.diversifier, diversifier)
        let changeOwner = try ConfidentialOwnerTag.deriveFromSpendKeyWithDiversifier(
            key, diversifier: nextInput.diversifier)
        let expected = try ConfidentialNoteCommitment.derive(asset: asset, amount: 3,
                                                            rho: change.rho, ownerTag: changeOwner)
        XCTAssertEqual(partial.outputCommitments, [expected])
        let nextProvider = try LocalZkAssetMerklePathProvider(rootHistory: [], commitmentHistory: [commitment, expected])
        let nextPath = try await nextProvider.getMerklePathForCommitment(asset: asset, commitment: expected)
        XCTAssertEqual(nextPath.leafIndex, 1)
        XCTAssertEqual(nextPath.heightOrIndex, 2)
        let redeemed = try await prover.proveUnshield(
            tree: .paths(root: nextPath.rootAtHeight, paths: [nextPath]), inputs: [nextInput], publicAmount: 3)
        XCTAssertEqual(redeemed.relation, .fullRedemption)
        XCTAssertEqual(redeemed.root, nextPath.rootAtHeight)
        XCTAssertTrue(redeemed.outputCommitments.isEmpty)
        assertFullProof(redeemed, root: nextPath.rootAtHeight)
        XCTAssertNotEqual(partial.nullifiers, redeemed.nullifiers)
    }

    func testOneInputAtFinalIndexOfFullTreeProvesThroughPublicNativeBridge() async throws {
        let asset = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
        let capacity = 65_536
        var key = Data(repeating: 94, count: 32)
        var rho = Data(repeating: 0, count: 32)
        var diversifier = Data()
        defer {
            key.resetBytes(in: 0..<key.count)
            rho.resetBytes(in: 0..<rho.count)
            diversifier.resetBytes(in: 0..<diversifier.count)
        }
        diversifier = try ConfidentialOwnerTag.defaultDiversifier()
        let owner = try ConfidentialOwnerTag.deriveFromSpendKeyWithDiversifier(key, diversifier: diversifier)
        var commitments: [Data] = []
        commitments.reserveCapacity(capacity)
        // Every leaf is a genuine commitment to a distinct disposable opening.
        for index in 0..<capacity {
            let nonce = UInt32(index + 1)
            for byte in 0..<4 { rho[byte] = UInt8(truncatingIfNeeded: nonce >> (8 * byte)) }
            commitments.append(try ConfidentialNoteCommitment.derive(
                asset: asset, amount: 7, rho: rho, ownerTag: owner))
        }
        XCTAssertEqual(commitments.count, capacity)
        XCTAssertEqual(Set(commitments).count, capacity)
        let provider = try LocalZkAssetMerklePathProvider(rootHistory: [], commitmentHistory: commitments)
        let path = try await provider.getMerklePathForCommitment(asset: asset, commitment: commitments[capacity - 1])
        XCTAssertEqual(path.leafIndex, 65_535)
        XCTAssertEqual(path.heightOrIndex, 65_536)
        XCTAssertEqual(path.siblings.count, 16)
        XCTAssertEqual(path.directions, Data(repeating: 1, count: 16))
        let prover = try ConfidentialProver(networkId: TestNetworkIds.canonical,
                                           assetDefinitionId: asset, spendKey: key)
        key.resetBytes(in: 0..<key.count)
        defer { try? prover.close() }
        let input = try ConfidentialInput(amount: 7, rho: rho, diversifier: diversifier, leafIndex: 65_535)
        let proof = try await prover.proveUnshield(
            tree: .commitments(root: path.rootAtHeight, leaves: commitments),
            inputs: [input], publicAmount: 7)
        assertFullProof(proof, root: path.rootAtHeight)
    }

    func testWrongRootFailsNativeProvingAndTheOwnerRecovers() async throws {
        let asset = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
        var key = Data(repeating: 95, count: 32)
        var rho = Data(repeating: 96, count: 32)
        var otherRho = Data(repeating: 97, count: 32)
        var diversifier = Data()
        defer {
            key.resetBytes(in: 0..<key.count)
            rho.resetBytes(in: 0..<rho.count)
            otherRho.resetBytes(in: 0..<otherRho.count)
            diversifier.resetBytes(in: 0..<diversifier.count)
        }
        diversifier = try ConfidentialOwnerTag.defaultDiversifier()
        let owner = try ConfidentialOwnerTag.deriveFromSpendKeyWithDiversifier(key, diversifier: diversifier)
        let commitment = try ConfidentialNoteCommitment.derive(asset: asset, amount: 7, rho: rho, ownerTag: owner)
        let other = try ConfidentialNoteCommitment.derive(asset: asset, amount: 7, rho: otherRho, ownerTag: owner)
        let provider = try LocalZkAssetMerklePathProvider(rootHistory: [], commitmentHistory: [commitment])
        let otherProvider = try LocalZkAssetMerklePathProvider(rootHistory: [], commitmentHistory: [other])
        let path = try await provider.getMerklePathForCommitment(asset: asset, commitment: commitment)
        let wrongPath = try await otherProvider.getMerklePathForCommitment(asset: asset, commitment: other)
        XCTAssertNotEqual(path.rootAtHeight, wrongPath.rootAtHeight)
        let prover = try ConfidentialProver(networkId: TestNetworkIds.canonical,
                                           assetDefinitionId: asset, spendKey: key)
        key.resetBytes(in: 0..<key.count)
        defer { try? prover.close() }
        let input = try ConfidentialInput(amount: 7, rho: rho, diversifier: diversifier, leafIndex: 0)
        do {
            _ = try await prover.proveUnshield(
                tree: .commitments(root: wrongPath.rootAtHeight, leaves: [commitment]),
                inputs: [input], publicAmount: 7)
            XCTFail("native proving accepted a root from another genuine tree")
        } catch { XCTAssertEqual(error as? ConfidentialProverError, .native(code: -24)) }
        let proof = try await prover.proveUnshield(
            tree: .commitments(root: path.rootAtHeight, leaves: [commitment]),
            inputs: [input], publicAmount: 7)
        assertFullProof(proof, root: path.rootAtHeight)
    }

    func testDuplicateInputsFailNativePreflightAndTheOwnerRecovers() async throws {
        let asset = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
        var key = Data(repeating: 98, count: 32)
        var rho = Data(repeating: 99, count: 32)
        var diversifier = Data()
        defer {
            key.resetBytes(in: 0..<key.count)
            rho.resetBytes(in: 0..<rho.count)
            diversifier.resetBytes(in: 0..<diversifier.count)
        }
        diversifier = try ConfidentialOwnerTag.defaultDiversifier()
        let owner = try ConfidentialOwnerTag.deriveFromSpendKeyWithDiversifier(key, diversifier: diversifier)
        let commitment = try ConfidentialNoteCommitment.derive(asset: asset, amount: 7, rho: rho, ownerTag: owner)
        let provider = try LocalZkAssetMerklePathProvider(rootHistory: [], commitmentHistory: [commitment])
        let path = try await provider.getMerklePathForCommitment(asset: asset, commitment: commitment)
        let prover = try ConfidentialProver(networkId: TestNetworkIds.canonical,
                                           assetDefinitionId: asset, spendKey: key)
        key.resetBytes(in: 0..<key.count)
        defer { try? prover.close() }
        let input = try ConfidentialInput(amount: 7, rho: rho, diversifier: diversifier, leafIndex: 0)
        let tree = ConfidentialTree.commitments(root: path.rootAtHeight, leaves: [commitment])
        do {
            _ = try await prover.proveUnshield(tree: tree, inputs: [input, input], publicAmount: 14)
            XCTFail("native preflight accepted the same owned input twice")
        } catch { XCTAssertEqual(error as? ConfidentialProverError, .native(code: -17)) }
        let proof = try await prover.proveUnshield(tree: tree, inputs: [input], publicAmount: 7)
        assertFullProof(proof, root: path.rootAtHeight)
    }

    private func assertFullProof(_ proof: ConfidentialProof, root: Data,
                                 file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(proof.relation, .fullRedemption, file: file, line: line)
        XCTAssertEqual(proof.backend, "pipa-r/pasta", file: file, line: line)
        XCTAssertFalse(proof.proof.isEmpty, file: file, line: line)
        XCTAssertEqual(proof.root, root, file: file, line: line)
        XCTAssertEqual(proof.nullifiers.count, 1, file: file, line: line)
        XCTAssertTrue(proof.nullifiers.allSatisfy { $0.count == 32 && $0.contains(where: { $0 != 0 }) }, file: file, line: line)
        XCTAssertTrue(proof.outputCommitments.isEmpty, file: file, line: line)
    }

    func testRealRedemptionThroughPublicNativeBridge() async throws {
        let asset = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
        var key = Data(repeating: 2, count: 32)
        var rho = Data(repeating: 4, count: 32)
        var diversifier = Data()
        defer {
            key.resetBytes(in: 0..<key.count)
            rho.resetBytes(in: 0..<rho.count)
            diversifier.resetBytes(in: 0..<diversifier.count)
        }
        diversifier = try ConfidentialOwnerTag.defaultDiversifier()
        let owner = try ConfidentialOwnerTag.deriveFromSpendKeyWithDiversifier(key, diversifier: diversifier)
        let commitment = try ConfidentialNoteCommitment.derive(asset: asset, amount: 7, rho: rho, ownerTag: owner)
        let provider = try LocalZkAssetMerklePathProvider(rootHistory: [], commitmentHistory: [commitment])
        let path = try await provider.getMerklePathForCommitment(asset: asset, commitment: commitment)
        let prover = try ConfidentialProver(networkId: TestNetworkIds.canonical,
                                           assetDefinitionId: asset, spendKey: key)
        key.resetBytes(in: 0..<key.count)
        defer { try? prover.close() }
        let input = try ConfidentialInput(amount: 7, rho: rho, diversifier: diversifier, leafIndex: 0)
        let tree = ConfidentialTree.paths(root: path.rootAtHeight, paths: [path])
        let proof = try await prover.proveUnshield(tree: tree, inputs: [input], publicAmount: 7)
        XCTAssertEqual(proof.relation, .fullRedemption)
        XCTAssertEqual(proof.backend, "pipa-r/pasta")
        XCTAssertFalse(proof.proof.isEmpty)
        XCTAssertEqual(proof.root, path.rootAtHeight)
        XCTAssertEqual(proof.nullifiers.count, 1)
        XCTAssertTrue(proof.outputCommitments.isEmpty)
        do {
            _ = try await prover.proveUnshield(tree: tree, inputs: [input], publicAmount: 8)
            XCTFail("native preflight accepted an unconserved redemption")
        } catch { XCTAssertEqual(error as? ConfidentialProverError, .native(code: -21)) }
        try prover.close()
        do {
            _ = try await prover.proveUnshield(tree: tree, inputs: [input], publicAmount: 7)
            XCTFail("closed native owner accepted new work")
        } catch { XCTAssertEqual(error as? ConfidentialProverError, .closed) }
    }
}
