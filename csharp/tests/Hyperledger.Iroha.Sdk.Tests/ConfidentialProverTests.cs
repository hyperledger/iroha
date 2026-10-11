using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Hyperledger.Iroha.Privacy;

namespace Hyperledger.Iroha.Sdk.Tests;

public sealed class ConfidentialProverTests
{
    private static byte[] Word(byte value) => Enumerable.Repeat(value, 32).ToArray();
    private static NetworkId Network => NetworkId.FromBytes(Word(1));
    private static ConfidentialAssetId Asset => new("62Fk4FPcMuLvW5QjDGNF2a4jAmjM");

    private sealed class Driver : IConfidentialWalletDriver
    {
        internal readonly ManualResetEventSlim Entered = new(false), Continue = new(false);
        internal byte[]? Key, Rho, Diversifier, Tree;
        internal int Jobs, Closed, JobClosed, Proved;
        internal bool FailInput, FailProof, FailDispatch;
        internal UInt128 InputAmount;
        internal ulong Handle;
        internal byte Operation;
        public ulong Create(byte[] network, byte[] asset, byte[] key) { Key = key; Assert.Equal(32, network.Length); return 9; }
        public void Close(ulong handle) { Assert.Equal(9UL, handle); Closed++; }
        public ulong Job(ulong handle, byte operation, byte[] root, UInt128 amount) { Jobs++; Handle = handle; Operation = operation; return 10; }
        public void Input(ulong job, UInt128 amount, byte[] rho, byte[] diversifier, int index) { Rho = rho; Diversifier = diversifier; InputAmount = amount; if (FailInput) throw new ConfidentialProverException(-16); }
        public void Output(ulong job, UInt128 amount, byte[] rho, byte[] owner) { }
        public void Commitments(ulong job, byte[] leaves) => Tree = leaves;
        public void Paths(ulong job, byte[] siblings, byte[] directions) => Tree = siblings;
        public byte[] Prove(ulong job)
        {
            Entered.Set(); Continue.Wait();
            if (FailDispatch) throw new EntryPointNotFoundException("Injected dispatch failure before native consumption.");
            Proved++;
            if (FailProof) throw new ConfidentialProverException(-24);
            var json = "{\"relation\":\"confidential_full_unshield\",\"backend\":\"pipa-r/pasta\",\"proof_hex\":\"01\",\"root_hex\":\"" + new string('1', 64) + "\",\"nullifiers_hex\":[\"" + new string('2', 64) + "\"],\"output_commitments_hex\":[]}";
            if (Operation == 0) json = json.Replace("confidential_full_unshield", "confidential_transfer").Replace("\"output_commitments_hex\":[]", "\"output_commitments_hex\":[\"" + new string('3', 64) + "\"]");
            return Encoding.UTF8.GetBytes(json);
        }
        public void CloseJob(ulong job) => JobClosed++;
    }

    [Fact]
    public async Task AcceptedJobSurvivesDisposeAndClearsAllManagedCopies()
    {
        var driver = new Driver(); var key = Word(9); var callerRho = Word(8);
        using var prover = new ConfidentialProver(Network, Asset, key, driver);
        Assert.All(driver.Key!, value => Assert.Equal((byte)0, value)); Assert.All(key, value => Assert.Equal((byte)9, value));
        var amount = ((UInt128)1 << 100) + 7;
        var note = new ConfidentialInputNote(amount, callerRho, Word(3), 0);
        var tree = ConfidentialTreeEvidence.Commitments(Word(0x11), [Word(2)]);
        var pending = prover.ProveRedemptionAsync(tree, [note], amount);
        try
        {
            Assert.True(driver.Entered.Wait(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken)); Assert.False(pending.IsCompleted);
            Assert.True(note.ClearedForTest); Assert.True(tree.ClearedForTest); Assert.Equal(amount, driver.InputAmount);
            Assert.All(driver.Rho!, value => Assert.Equal((byte)0, value)); Assert.All(driver.Diversifier!, value => Assert.Equal((byte)0, value)); Assert.All(driver.Tree!, value => Assert.Equal((byte)0, value));
            prover.Dispose(); prover.Dispose(); Assert.Equal(1, driver.Closed);
            using var next = new ConfidentialInputNote(7, Word(3), Word(4), 0);
            using var nextTree = ConfidentialTreeEvidence.Commitments(Word(0x11), [Word(2)]);
            Assert.Equal(-2, Assert.Throws<ConfidentialProverException>(() => { _ = prover.ProveRedemptionAsync(nextTree, [next], 7); }).Code);
        }
        finally { driver.Continue.Set(); }
        var proof = await pending; Assert.Equal(ConfidentialProofRelation.FullRedemption, proof.Relation); Assert.Equal(1, driver.Proved);
        Assert.Equal(1, driver.JobClosed); Assert.All(callerRho, value => Assert.Equal((byte)8, value));
        var root = proof.Root; root[0] ^= 1; Assert.Equal((byte)0x11, proof.Root[0]);
    }

    [Fact]
    public async Task RejectedPreparationAndWorkerFailureCloseOnceAndEraseInputs()
    {
        var driver = new Driver { FailInput = true }; using var prover = new ConfidentialProver(Network, Asset, Word(9), driver);
        var note = new ConfidentialInputNote(7, Word(8), Word(3), 0); var tree = ConfidentialTreeEvidence.Commitments(Word(0x11), [Word(2)]);
        Assert.Equal(-16, Assert.Throws<ConfidentialProverException>(() => { _ = prover.ProveRedemptionAsync(tree, [note], 7); }).Code);
        Assert.Equal(1, driver.JobClosed); Assert.True(note.ClearedForTest); Assert.True(tree.ClearedForTest); Assert.All(driver.Rho!, value => Assert.Equal((byte)0, value));
        driver.FailInput = false; driver.FailProof = true; driver.Continue.Set();
        var next = new ConfidentialInputNote(7, Word(8), Word(3), 0);
        var pending = prover.ProveRedemptionAsync(ConfidentialTreeEvidence.Commitments(Word(0x11), [Word(2)]), [next], 7);
        Assert.Equal(-24, (await Assert.ThrowsAsync<ConfidentialProverException>(() => pending)).Code); Assert.True(next.ClearedForTest); Assert.Equal(2, driver.JobClosed);
    }

    [Fact]
    public async Task DispatchFailureBeforeNativeConsumptionStillClosesAcceptedJob()
    {
        var driver = new Driver { FailDispatch = true };
        driver.Continue.Set();
        using var prover = new ConfidentialProver(Network, Asset, Word(9), driver);
        using var input = new ConfidentialInputNote(7, Word(8), Word(3), 0);
        var pending = prover.ProveRedemptionAsync(ConfidentialTreeEvidence.Commitments(Word(0x11), [Word(2)]), [input], 7);
        await Assert.ThrowsAsync<EntryPointNotFoundException>(() => pending);
        Assert.Equal(0, driver.Proved);
        Assert.Equal(1, driver.JobClosed);
        Assert.True(input.ClearedForTest);
    }

    [Fact]
    public void PublicPreflightRejectsShapeAmountsAndPathIndexBeforeJobCreation()
    {
        var driver = new Driver(); using var prover = new ConfidentialProver(Network, Asset, Word(9), driver);
        Assert.Throws<ArgumentException>(() => new ConfidentialInputNote(0, Word(1), Word(2), 0));
        Assert.Throws<ArgumentException>(() => new ConfidentialOutputNote(1, new byte[31], Word(2)));
        Assert.Throws<ConfidentialProverException>(() => new ConfidentialInputNote(1, Word(1), Word(2), 65536));
        using var path = new ConfidentialMerklePath(Word(0x11), 1, Enumerable.Range(0,16).Select(_ => Word(2)).ToArray(), [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
        using var note = new ConfidentialInputNote(7, Word(8), Word(3), 0);
        using var tree = ConfidentialTreeEvidence.Paths(Word(0x11), [path]);
        Assert.Equal(-16, Assert.Throws<ConfidentialProverException>(() => { _ = prover.ProveRedemptionAsync(tree, [note], 7); }).Code);
        Assert.Equal(0, driver.Jobs);
        using var extra = new ConfidentialInputNote(7, Word(8), Word(3), 0);
        Assert.Equal(-21, Assert.Throws<ConfidentialProverException>(() => { _ = prover.ProveRedemptionAsync(ConfidentialTreeEvidence.Commitments(Word(1), [Word(2)]), [extra], 8); }).Code);
        using var overflow1 = new ConfidentialInputNote(UInt128.MaxValue, Word(8), Word(3), 0);
        using var overflow2 = new ConfidentialInputNote(1, Word(9), Word(3), 1);
        Assert.Equal(-20, Assert.Throws<ConfidentialProverException>(() => { _ = prover.ProveRedemptionAsync(ConfidentialTreeEvidence.Commitments(Word(1), [Word(2), Word(3)]), [overflow1,overflow2], 1); }).Code);
        Assert.Equal(0, driver.Jobs);
    }

    private sealed class ChangingCountList<T>(params T[] values) : IReadOnlyList<T>
    {
        internal int CountReads;
        public int Count => ++CountReads == 1 ? values.Length : int.MaxValue;
        public T this[int index] => values[index];
        public IEnumerator<T> GetEnumerator() => ((IEnumerable<T>)values).GetEnumerator();
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    [Fact]
    public async Task MutableCollectionCountsCannotExpandAdmittedAllocationBounds()
    {
        var driver = new Driver(); driver.Continue.Set();
        using var prover = new ConfidentialProver(Network, Asset, Word(9), driver);
        var leaves = new ChangingCountList<byte[]>(Word(2));
        using var tree = ConfidentialTreeEvidence.Commitments(Word(0x11), leaves);
        Assert.Equal(1, leaves.CountReads);
        using var note = new ConfidentialInputNote(7, Word(8), Word(3), 0);
        var inputs = new ChangingCountList<ConfidentialInputNote>(note);
        await prover.ProveRedemptionAsync(tree, inputs, 7);
        Assert.Equal(1, inputs.CountReads);

        using var path = new ConfidentialMerklePath(Word(0x11), 0,
            Enumerable.Range(0, 16).Select(_ => Word(2)).ToArray(), new byte[16]);
        var paths = new ChangingCountList<ConfidentialMerklePath>(path);
        using var pathTree = ConfidentialTreeEvidence.Paths(Word(0x11), paths);
        Assert.Equal(1, paths.CountReads);
        using var transferInput = new ConfidentialInputNote(7, Word(8), Word(3), 0);
        using var transferOutput = new ConfidentialOutputNote(7, Word(9), Word(4));
        var outputs = new ChangingCountList<ConfidentialOutputNote>(transferOutput);
        var proof = await prover.ProveTransferAsync(pathTree, [transferInput], outputs);
        Assert.Equal(1, outputs.CountReads);
        Assert.Equal(ConfidentialProofRelation.Transfer, proof.Relation);
        Assert.Single(proof.OutputCommitments);
        Assert.True(transferInput.ClearedForTest); Assert.True(transferOutput.ClearedForTest);
    }

    [Fact]
    public void PublicResultRejectsWrongRelationRootCardinalityBackendAndDuplicateFields()
    {
        var correct = "{\"relation\":\"confidential_full_unshield\",\"backend\":\"pipa-r/pasta\",\"proof_hex\":\"01\",\"root_hex\":\"" + new string('1',64) + "\",\"nullifiers_hex\":[\"" + new string('2',64) + "\"],\"output_commitments_hex\":[]}";
        foreach (var changed in new[] { correct.Replace("confidential_full_unshield", "confidential_transfer"), correct.Replace(new string('1',64), new string('3',64)), correct.Replace("\"01\"", "\"\""), correct.Replace("pipa-r/pasta", "halo2"), correct.Replace("pipa-r/pasta", "pipa-r/pasta/confidential-unshield-full-v1"), correct.Replace("\"proof_hex\":\"01\"", "\"proof_hex\":\"01\",\"proof_hex\":\"02\"") })
            Assert.Throws<ConfidentialProverException>(() => ConfidentialProof.Decode(Encoding.UTF8.GetBytes(changed), ConfidentialProofRelation.FullRedemption, Word(0x11), 1, 0));
        Assert.Throws<ConfidentialProverException>(() => ConfidentialProof.Decode(Encoding.UTF8.GetBytes(correct), ConfidentialProofRelation.FullRedemption, Word(0x11), 2, 0));
    }

    [Fact]
    public void PrivateOwnersRedactAndDisposeAndAbiUsesPlatformCLong()
    {
        using var note = new ConfidentialInputNote(123, Word(0xab), Word(0xcd), 0);
        using var change = new ConfidentialChangeNote(1, Word(0xab));
        using var output = new ConfidentialOutputNote(1, Word(0xab), Word(0xcd));
        Assert.DoesNotContain("123", note.ToString()); Assert.Contains("REDACTED", change.ToString()); Assert.Contains("REDACTED", output.ToString());
        note.Dispose(); change.Dispose(); output.Dispose();
        Assert.True(note.ClearedForTest); Assert.True(change.ClearedForTest); Assert.True(output.ClearedForTest);
        Assert.Throws<ConfidentialProverException>(() => _ = note.Amount);
        Assert.Equal(OperatingSystem.IsWindows() ? 4 : IntPtr.Size, Marshal.SizeOf<CULong>());
    }
}
