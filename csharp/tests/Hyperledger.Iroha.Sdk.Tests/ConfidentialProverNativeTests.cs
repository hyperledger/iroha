using System.Security.Cryptography;
using Hyperledger.Iroha.Privacy;

namespace Hyperledger.Iroha.Sdk.Tests;

public sealed class ConfidentialProverNativeTests
{
    private static byte[] Word(byte value) => Enumerable.Repeat(value, 32).ToArray();
    private static ConfidentialAssetId Asset => new("62Fk4FPcMuLvW5QjDGNF2a4jAmjM");
    [Fact]
    public void NativeContractUsesCanonicalFirstReleaseRevisions()
    {
        Assert.Equal(27U, ConfidentialWalletNative.Abi());
        Assert.Equal(1U, ConfidentialWalletNative.Revision());
        Assert.Equal(1U, ConfidentialWalletNative.DerivationRevision());
        ConfidentialWalletNative.RequireAvailable();
    }

    [Fact]
    public void NativeDefaultDerivationAndDisposedOpeningsAreExact()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            Assert.Equal(27u, ConfidentialWalletNative.Abi());
            Assert.Equal(1u, ConfidentialWalletNative.Revision());
            Assert.Equal(1u, ConfidentialWalletNative.DerivationRevision());
            var diversifier = ConfidentialNotes.DefaultDiversifier();
            var first = ConfidentialNotes.OwnerTag(key, diversifier);
            using var change = new ConfidentialChangeNote(2, Word(9));
            using var input = change.ToInput(65535);
            Assert.Equal(65535, input.LeafIndex); Assert.Equal((UInt128)2, input.Amount);
            diversifier[0] ^= 1; Assert.NotEqual(diversifier, ConfidentialNotes.DefaultDiversifier());
            Assert.Equal(first, ConfidentialNotes.OwnerTag(key, ConfidentialNotes.DefaultDiversifier()));
            change.Dispose(); Assert.Throws<ConfidentialProverException>(() => change.ToInput(0));
            Assert.Throws<ConfidentialProverException>(() => new ConfidentialProver(NetworkId.FromBytes(Word(1)), Asset, new byte[32]));
            Assert.Throws<ConfidentialProverException>(() => ConfidentialNotes.MerklePath([], 1));
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    [Fact]
    public async Task NonDefaultInputChangeThenDefaultOwnerRedemptionSurvivesDispose()
    {
        var key = RandomNumberGenerator.GetBytes(32); var rho = RandomNumberGenerator.GetBytes(32); var changeRho = RandomNumberGenerator.GetBytes(32);
        var seed = RandomNumberGenerator.GetBytes(32); var networkBytes = RandomNumberGenerator.GetBytes(32); networkBytes[31] |= 1;
        try
        {
            var diversifier = ConfidentialNotes.Diversifier(seed); var defaultDiversifier = ConfidentialNotes.DefaultDiversifier();
            Assert.NotEqual(defaultDiversifier, diversifier);
            var original = ConfidentialNotes.Commitment(Asset, 7, rho, ConfidentialNotes.OwnerTag(key, diversifier));
            var expectedChange = ConfidentialNotes.Commitment(Asset, 2, changeRho, ConfidentialNotes.OwnerTag(key, defaultDiversifier));
            using var prover = new ConfidentialProver(NetworkId.FromBytes(networkBytes), Asset, key);
            CryptographicOperations.ZeroMemory(key);
            using var path = ConfidentialNotes.MerklePath([original], 0);
            using var input = new ConfidentialInputNote(7, rho, diversifier, 0);
            // The caller retains changeRho securely before the proving call consumes its owned copy.
            using var change = new ConfidentialChangeNote(2, changeRho);
            var firstTask = prover.ProveRedemptionAsync(ConfidentialTreeEvidence.Paths(path.Root, [path]), [input], 5, change);
            Assert.True(input.ClearedForTest); Assert.True(change.ClearedForTest);
            var first = await firstTask; Assert.Equal(ConfidentialProofRelation.RedemptionWithChange, first.Relation); Assert.Equal(expectedChange, Assert.Single(first.OutputCommitments));
            using var restored = new ConfidentialChangeNote(2, changeRho); using var changeInput = restored.ToInput(1);
            var history = new[] { original, first.OutputCommitments[0] }; var finalRoot = ConfidentialNotes.Root(history);
            var secondTask = prover.ProveRedemptionAsync(ConfidentialTreeEvidence.Commitments(finalRoot, history), [changeInput], 2);
            prover.Dispose();
            using var closedInput = new ConfidentialInputNote(2, changeRho, defaultDiversifier, 1);
            Assert.Equal(-2, Assert.Throws<ConfidentialProverException>(() => { _ = prover.ProveRedemptionAsync(ConfidentialTreeEvidence.Commitments(finalRoot, history), [closedInput], 2); }).Code);
            var second = await secondTask;
            Assert.Equal(ConfidentialProofRelation.FullRedemption, second.Relation); Assert.Empty(second.OutputCommitments);
            Assert.Single(second.Nullifiers); Assert.Equal(finalRoot, second.Root); Assert.NotEmpty(first.Proof); Assert.NotEmpty(second.Proof);
        }
        finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(rho); CryptographicOperations.ZeroMemory(changeRho); CryptographicOperations.ZeroMemory(seed); }
    }

    [Fact]
    public async Task NativeMembershipFailureConsumesJobWithoutClosingProver()
    {
        var key = RandomNumberGenerator.GetBytes(32); var rho = RandomNumberGenerator.GetBytes(32);
        try
        {
            var d = ConfidentialNotes.DefaultDiversifier(); var note = ConfidentialNotes.Commitment(Asset, 7, rho, ConfidentialNotes.OwnerTag(key,d));
            using var prover = new ConfidentialProver(NetworkId.FromBytes(Word(1)), Asset, key);
            for (var attempt = 0; attempt < 2; attempt++)
            {
                using var input = new ConfidentialInputNote(7,rho,d,0);
                var pending = prover.ProveRedemptionAsync(ConfidentialTreeEvidence.Commitments(Word(3),[note]),[input],7);
                Assert.Equal(-24,(await Assert.ThrowsAsync<ConfidentialProverException>(()=>pending)).Code);
                Assert.True(input.ClearedForTest);
            }
        }
        finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(rho); }
    }

    [Fact]
    public async Task OneInputAtFullTreeBoundaryProvesWithBothEvidenceFormats()
    {
        const int capacity = 65_536;
        const int lastIndex = capacity - 1;
        // Fixed disposable material makes this local proof control reproducible.
        var key = Word(91); byte[] diversifier = [];
        var leaves = new byte[capacity][];
        var rho = new byte[32];
        try
        {
            diversifier = ConfidentialNotes.DefaultDiversifier();
            var owner = ConfidentialNotes.OwnerTag(key, diversifier);
            for (var index = 0; index < capacity; index++)
            {
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(rho, (uint)index + 1);
                leaves[index] = ConfidentialNotes.Commitment(Asset, 7, rho, owner);
            }
            using var path = ConfidentialNotes.MerklePath(leaves, lastIndex);
            var root = path.Root;
            Assert.Equal(capacity, leaves.Length);
            Assert.Equal(lastIndex, path.LeafIndex);
            Assert.Equal(ConfidentialNotes.Root(leaves), root);
            using var prover = new ConfidentialProver(NetworkId.FromBytes(Word(1)), Asset, key);
            using var completeInput = new ConfidentialInputNote(7, rho, diversifier, lastIndex);
            var complete = await prover.ProveRedemptionAsync(
                ConfidentialTreeEvidence.Commitments(root, leaves), [completeInput], 7);
            using var pathInput = new ConfidentialInputNote(7, rho, diversifier, lastIndex);
            var compact = await prover.ProveRedemptionAsync(
                ConfidentialTreeEvidence.Paths(root, [path]), [pathInput], 7);
            foreach (var proof in new[] { complete, compact })
            {
                Assert.Equal(ConfidentialProofRelation.FullRedemption, proof.Relation);
                Assert.Equal("pipa-r/pasta", proof.Backend);
                Assert.Equal(root, proof.Root);
                Assert.NotEmpty(proof.Proof);
                Assert.Single(proof.Nullifiers);
                Assert.Empty(proof.OutputCommitments);
            }
            Assert.Equal(Assert.Single(complete.Nullifiers), Assert.Single(compact.Nullifiers));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(rho);
            CryptographicOperations.ZeroMemory(diversifier);
            foreach (var leaf in leaves) if (leaf is not null) CryptographicOperations.ZeroMemory(leaf);
        }
    }

    [Fact]
    public async Task DuplicateAndUnconservedRequestsDoNotCloseTheNativeOwner()
    {
        var key = Word(92); var rho = Word(93); var changeRho = Word(94);
        byte[] diversifier = [];
        try
        {
            diversifier = ConfidentialNotes.DefaultDiversifier();
            var note = ConfidentialNotes.Commitment(Asset, 7, rho, ConfidentialNotes.OwnerTag(key, diversifier));
            var leaves = new[] { note }; var root = ConfidentialNotes.Root(leaves);
            using var prover = new ConfidentialProver(NetworkId.FromBytes(Word(1)), Asset, key);
            using var first = new ConfidentialInputNote(7, rho, diversifier, 0);
            using var duplicate = new ConfidentialInputNote(7, rho, diversifier, 0);
            Assert.Equal(-17, Assert.Throws<ConfidentialProverException>(() =>
            {
                _ = prover.ProveRedemptionAsync(ConfidentialTreeEvidence.Commitments(root, leaves), [first, duplicate], 14);
            }).Code);
            using var overspent = new ConfidentialInputNote(7, rho, diversifier, 0);
            Assert.Equal(-21, Assert.Throws<ConfidentialProverException>(() =>
            {
                _ = prover.ProveRedemptionAsync(ConfidentialTreeEvidence.Commitments(root, leaves), [overspent], 8);
            }).Code);
            using var wrongChangeInput = new ConfidentialInputNote(7, rho, diversifier, 0);
            using var wrongChange = new ConfidentialChangeNote(3, changeRho);
            Assert.Equal(-22, Assert.Throws<ConfidentialProverException>(() =>
            {
                _ = prover.ProveRedemptionAsync(ConfidentialTreeEvidence.Commitments(root, leaves), [wrongChangeInput], 5, wrongChange);
            }).Code);
            // Rejected requests consume their owners through the public API.
            Assert.Equal(-2, Assert.Throws<ConfidentialProverException>(() =>
            {
                _ = prover.ProveRedemptionAsync(ConfidentialTreeEvidence.Commitments(root, leaves), [first], 7);
            }).Code);
            using var recovered = new ConfidentialInputNote(7, rho, diversifier, 0);
            var proof = await prover.ProveRedemptionAsync(ConfidentialTreeEvidence.Commitments(root, leaves), [recovered], 7);
            Assert.Equal(ConfidentialProofRelation.FullRedemption, proof.Relation);
            Assert.Equal("pipa-r/pasta", proof.Backend);
            Assert.Equal(root, proof.Root);
            Assert.NotEmpty(proof.Proof);
            Assert.Single(proof.Nullifiers);
            Assert.Empty(proof.OutputCommitments);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(rho);
            CryptographicOperations.ZeroMemory(changeRho);
            CryptographicOperations.ZeroMemory(diversifier);
        }
    }
}
