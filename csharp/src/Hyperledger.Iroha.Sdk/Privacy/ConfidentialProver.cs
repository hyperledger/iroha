using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Hyperledger.Iroha.Privacy;

/// <summary>Canonical local relation; a proof is not ledger spending authorization.</summary>
public enum ConfidentialProofRelation { Transfer, FullRedemption, RedemptionWithChange }

/// <summary>Public self-verified native proof. Arrays are defensive copies.</summary>
public sealed class ConfidentialProof
{
    public ConfidentialProofRelation Relation { get; }
    public string Backend { get; }
    private readonly byte[] proof, root;
    private readonly byte[][] nullifiers, outputs;
    public byte[] Proof => (byte[])proof.Clone();
    public byte[] Root => (byte[])root.Clone();
    public IReadOnlyList<byte[]> Nullifiers => Array.AsReadOnly(nullifiers.Select(value => (byte[])value.Clone()).ToArray());
    public IReadOnlyList<byte[]> OutputCommitments => Array.AsReadOnly(outputs.Select(value => (byte[])value.Clone()).ToArray());
    private ConfidentialProof(ConfidentialProofRelation relation, string backend, byte[] proof, byte[] root, byte[][] nullifiers, byte[][] outputs)
    { Relation = relation; Backend = backend; this.proof = proof; this.root = root; this.nullifiers = nullifiers; this.outputs = outputs; }
    internal static ConfidentialProof Decode(byte[] bytes, ConfidentialProofRelation expected, byte[] expectedRoot, int inputCount, int outputCount)
    {
        if (bytes.Length is < 1 or > 16 * 1024 * 1024) throw new ConfidentialProverException(-100);
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 }); var value = document.RootElement;
            var fields = new HashSet<string>(StringComparer.Ordinal) { "relation", "backend", "proof_hex", "root_hex", "nullifiers_hex", "output_commitments_hex" };
            if (value.ValueKind != JsonValueKind.Object || value.EnumerateObject().Any(field => !fields.Remove(field.Name)) || fields.Count != 0) throw new ConfidentialProverException(-100);
            var relation = value.GetProperty("relation").GetString() switch
            {
                "confidential_transfer" => ConfidentialProofRelation.Transfer,
                "confidential_full_unshield" => ConfidentialProofRelation.FullRedemption,
                "confidential_change_unshield" => ConfidentialProofRelation.RedemptionWithChange,
                _ => throw new ConfidentialProverException(-100),
            };
            var backend = value.GetProperty("backend").GetString();
            // ProofBox.backend identifies the proof system. The native producer
            // chooses and self-verifies the exact circuit carried in its envelope.
            const string expectedBackend = "pipa-r/pasta";
            byte[] Hex(JsonElement item, int? length = null)
            {
                var text = item.GetString() ?? throw new ConfidentialProverException(-100);
                if ((text.Length & 1) != 0 || (length.HasValue && text.Length != length * 2) || text.Any(c => !(c is >= '0' and <= '9' or >= 'a' and <= 'f'))) throw new ConfidentialProverException(-100);
                return Convert.FromHexString(text);
            }
            byte[][] Words(string name, int count)
            {
                var items = value.GetProperty(name);
                if (items.ValueKind != JsonValueKind.Array || items.GetArrayLength() != count) throw new ConfidentialProverException(-100);
                return items.EnumerateArray().Select(item => Hex(item, 32)).ToArray();
            }
            var root = Hex(value.GetProperty("root_hex"), 32); var proof = Hex(value.GetProperty("proof_hex"));
            if (relation != expected || backend != expectedBackend || proof.Length == 0 || !root.AsSpan().SequenceEqual(expectedRoot)) throw new ConfidentialProverException(-100);
            return new(relation, backend, proof, root, Words("nullifiers_hex", inputCount), Words("output_commitments_hex", outputCount));
        }
        catch (Exception error) when (error is not ConfidentialProverException && error is JsonException or InvalidOperationException or FormatException)
        { throw new ConfidentialProverException(-100, error); }
    }
}

internal interface IConfidentialWalletDriver
{
    ulong Create(byte[] network, byte[] asset, byte[] key);
    void Close(ulong handle);
    ulong Job(ulong handle, byte operation, byte[] root, UInt128 amount);
    void Input(ulong job, UInt128 amount, byte[] rho, byte[] diversifier, int index);
    void Output(ulong job, UInt128 amount, byte[] rho, byte[] owner);
    void Commitments(ulong job, byte[] leaves);
    void Paths(ulong job, byte[] siblings, byte[] directions);
    byte[] Prove(ulong job);
    void CloseJob(ulong job);
}

internal sealed class ConfidentialNativeJob : IDisposable
{
    private readonly IConfidentialWalletDriver driver;
    private readonly object gate = new();
    private ulong handle;
    internal ConfidentialNativeJob(IConfidentialWalletDriver driver) => this.driver = driver;
    internal void Attach(ulong value) { lock (gate) { if (handle != 0 || value == 0) throw new ConfidentialProverException(-100); handle = value; } }
    internal byte[] Prove() { ulong previous; lock (gate) { previous = handle; handle = 0; } if (previous == 0) throw new ConfidentialProverException(-2); try { return driver.Prove(previous); } finally { driver.CloseJob(previous); } }
    public void Dispose() { ulong previous; lock (gate) { previous = handle; handle = 0; } try { if (previous != 0) driver.CloseJob(previous); } finally { GC.SuppressFinalize(this); } }
    ~ConfidentialNativeJob() { try { if (handle != 0) driver.CloseJob(handle); } catch { /* Native cleanup cannot throw from finalization. */ } }
}

/// <summary>
/// Native-owned local prover with automatic relation/key selection. Use using/Dispose.
/// Accepted requests consume note/tree owners before returning a task and prove on the
/// ordinary thread pool. Dispose prevents new requests and leaves accepted jobs alive.
/// Original caller arrays and UInt128 values remain caller-owned; no stack/register erasure is promised.
/// </summary>
public sealed class ConfidentialProver : IDisposable
{
    private readonly object gate = new();
    private readonly IConfidentialWalletDriver driver;
    private ulong handle;
    public ConfidentialProver(NetworkId network, ConfidentialAssetId asset, ReadOnlySpan<byte> spendKey)
        : this(network, asset, spendKey, ConfidentialWalletNative.Driver) { }
    internal ConfidentialProver(NetworkId network, ConfidentialAssetId asset, ReadOnlySpan<byte> spendKey, IConfidentialWalletDriver driver)
    {
        ArgumentNullException.ThrowIfNull(network); ArgumentNullException.ThrowIfNull(asset); ConfidentialChecks.Word(spendKey);
        if (spendKey.IndexOfAnyExcept((byte)0) < 0) throw new ConfidentialProverException(-10);
        this.driver = driver; var key = spendKey.ToArray();
        try { handle = driver.Create(network.ToBytes(), Encoding.UTF8.GetBytes(asset.Value), key); if (handle == 0) throw new ConfidentialProverException(-100); }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
    /// <summary>Background transfer proving; consumes the supplied owned notes and tree evidence.</summary>
    public Task<ConfidentialProof> ProveTransferAsync(ConfidentialTreeEvidence tree, IReadOnlyList<ConfidentialInputNote> inputs, IReadOnlyList<ConfidentialOutputNote> outputs)
    {
        ArgumentNullException.ThrowIfNull(outputs);
        return Prepare(tree, inputs, outputs, 0, null);
    }
    /// <summary>Redeem a positive amount; omit change for full redemption. Persist change before proving consumes it.</summary>
    public Task<ConfidentialProof> ProveRedemptionAsync(ConfidentialTreeEvidence tree, IReadOnlyList<ConfidentialInputNote> inputs, UInt128 publicAmount, ConfidentialChangeNote? change = null)
        => Prepare(tree, inputs, null, publicAmount, change);
    private Task<ConfidentialProof> Prepare(ConfidentialTreeEvidence tree, IReadOnlyList<ConfidentialInputNote> inputValues, IReadOnlyList<ConfidentialOutputNote>? outputValues, UInt128 publicAmount, ConfidentialChangeNote? change)
    {
        ArgumentNullException.ThrowIfNull(tree); ArgumentNullException.ThrowIfNull(inputValues);
        var inputCount = inputValues.Count;
        var transferOutputCount = outputValues?.Count;
        if (inputCount is < 1 or > 2) throw new ConfidentialProverException(-11);
        if (transferOutputCount is < 1 or > 2) throw new ConfidentialProverException(-18);
        var inputs = new ConfidentialInputNote[inputCount];
        for (var i = 0; i < inputs.Length; i++) inputs[i] = inputValues[i];
        var outputs = outputValues is null ? null : new ConfidentialOutputNote[transferOutputCount!.Value];
        if (outputs is not null) for (var i = 0; i < outputs.Length; i++) outputs[i] = outputValues![i];
        ConfidentialNativeJob? job = null; byte[]? root = null;
        try
        {
            if (inputs.Any(value => value is null) || outputs?.Any(value => value is null) == true) throw new ArgumentException("Note owners must not be null.");
            UInt128 total = 0;
            try { foreach (var input in inputs) total = checked(total + input.Amount); }
            catch (OverflowException) { throw new ConfidentialProverException(-20); }
            if (inputs.Length == 2 && inputs[0].LeafIndex == inputs[1].LeafIndex) throw new ConfidentialProverException(-17);
            tree.Validate(inputs);
            ConfidentialProofRelation relation; int outputCount;
            if (outputs is not null)
            {
                UInt128 outputTotal = 0;
                try { foreach (var output in outputs) outputTotal = checked(outputTotal + output.Amount); }
                catch (OverflowException) { throw new ConfidentialProverException(-19); }
                if (total != outputTotal) throw new ConfidentialProverException(-19);
                relation = ConfidentialProofRelation.Transfer; outputCount = outputs.Length;
            }
            else
            {
                if (publicAmount == 0 || publicAmount > total) throw new ConfidentialProverException(-21);
                var remainder = total - publicAmount;
                if ((remainder == 0) != (change is null) || (change is not null && change.Amount != remainder)) throw new ConfidentialProverException(-22);
                relation = change is null ? ConfidentialProofRelation.FullRedemption : ConfidentialProofRelation.RedemptionWithChange; outputCount = change is null ? 0 : 1;
            }
            root = tree.Root; ulong id;
            job = new ConfidentialNativeJob(driver);
            lock (gate) { if (handle == 0) throw new ConfidentialProverException(-2); id = driver.Job(handle, outputs is null ? (byte)1 : (byte)0, root, publicAmount); }
            if (id == 0) throw new ConfidentialProverException(-100);
            job.Attach(id);
            foreach (var input in inputs) input.Append(driver, id);
            if (outputs is not null) foreach (var output in outputs) output.Append(driver, id);
            change?.Append(driver, id); tree.Append(driver, id);
            var accepted = job; var expectedRoot = root; var count = inputs.Length;
            var task = Task.Run(() => { try { using (accepted) { return ConfidentialProof.Decode(accepted.Prove(), relation, expectedRoot, count, outputCount); } } finally { CryptographicOperations.ZeroMemory(expectedRoot); } });
            job = null; root = null; return task;
        }
        finally
        {
            try { job?.Dispose(); }
            finally { if (root is not null) CryptographicOperations.ZeroMemory(root); foreach (var input in inputs) input?.Dispose(); if (outputs is not null) foreach (var output in outputs) output?.Dispose(); change?.Dispose(); tree.Dispose(); }
        }
    }
    public void Dispose() { lock (gate) { var previous = handle; handle = 0; try { if (previous != 0) driver.Close(previous); } finally { GC.SuppressFinalize(this); } } }
    ~ConfidentialProver() { try { if (handle != 0) driver.Close(handle); } catch { /* Never throw from finalization. */ } }
    public override string ToString() => "ConfidentialProver([REDACTED])";
}
