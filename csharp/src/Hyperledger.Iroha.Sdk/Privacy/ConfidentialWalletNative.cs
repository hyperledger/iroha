using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Hyperledger.Iroha.Privacy;

/// <summary>Core-backed derivation; never implements scalar encodings or cryptography in managed code.</summary>
public static class ConfidentialNotes
{
    public static byte[] DefaultDiversifier() { ConfidentialWalletNative.RequireAvailable(); var output = new byte[32]; ConfidentialWalletNative.DerivationCheck(ConfidentialWalletNative.Default(output, new(32))); return output; }
    public static byte[] Diversifier(ReadOnlySpan<byte> seed)
    {
        if (seed.Length is < 1 or > 4096) throw new ArgumentException("Diversifier seed must contain 1 to 4096 bytes.");
        ConfidentialWalletNative.RequireAvailable(); var copy = new byte[seed.Length]; var output = new byte[32];
        try { seed.CopyTo(copy); ConfidentialWalletNative.DerivationCheck(ConfidentialWalletNative.Diversifier(copy, new((uint)copy.Length), output, new(32))); return output; }
        finally { CryptographicOperations.ZeroMemory(copy); }
    }
    public static byte[] OwnerTag(ReadOnlySpan<byte> spendKey, ReadOnlySpan<byte> diversifier)
    {
        ConfidentialChecks.Word(spendKey); ConfidentialChecks.Word(diversifier); ConfidentialWalletNative.RequireAvailable();
        var key = new byte[32]; var d = new byte[32]; var output = new byte[32];
        try { spendKey.CopyTo(key); diversifier.CopyTo(d); ConfidentialWalletNative.DerivationCheck(ConfidentialWalletNative.Owner(key, new(32), d, new(32), output, new(32))); return output; }
        finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(d); }
    }
    /// <summary>Derive a commitment without retaining the spend key. The caller owns all original openings.</summary>
    public static byte[] Commitment(ConfidentialAssetId asset, UInt128 amount, ReadOnlySpan<byte> rho, ReadOnlySpan<byte> ownerTag)
    {
        ArgumentNullException.ThrowIfNull(asset); ConfidentialChecks.Amount(amount); ConfidentialChecks.Word(rho); ConfidentialChecks.Word(ownerTag); ConfidentialWalletNative.RequireAvailable();
        var a = Encoding.UTF8.GetBytes(asset.Value); var digits = new byte[39]; var r = new byte[32]; var owner = new byte[32]; var output = new byte[32];
        try
        {
            if (!amount.TryFormat(digits, out var count, default, CultureInfo.InvariantCulture)) throw new ConfidentialProverException(-100);
            rho.CopyTo(r); ownerTag.CopyTo(owner);
            ConfidentialWalletNative.DerivationCheck(ConfidentialWalletNative.Commitment(a, new((uint)a.Length), digits, new((uint)count), r, new(32), owner, new(32), output, new(32))); return output;
        }
        finally { CryptographicOperations.ZeroMemory(digits); CryptographicOperations.ZeroMemory(r); CryptographicOperations.ZeroMemory(owner); }
    }
    /// <summary>Derive a local history path. It does not authenticate that history or authorize a spend.</summary>
    public static ConfidentialMerklePath MerklePath(IReadOnlyList<byte[]> commitments, int leafIndex)
    {
        ArgumentNullException.ThrowIfNull(commitments); ConfidentialChecks.Index(leafIndex);
        var count = commitments.Count;
        if (count > ConfidentialChecks.Capacity) throw new ConfidentialProverException(-12);
        if (leafIndex > count) throw new ConfidentialProverException(-15);
        for (var i = 0; i < count; i++) { ArgumentNullException.ThrowIfNull(commitments[i]); ConfidentialChecks.Word(commitments[i]); }
        ConfidentialWalletNative.RequireAvailable(); var packed = new byte[count * 32]; var output = new byte[560];
        try { for (var i = 0; i < count; i++) commitments[i].CopyTo(packed, i * 32); ConfidentialWalletNative.DerivationCheck(ConfidentialWalletNative.Path(packed, new((uint)packed.Length), (ulong)leafIndex, output, new(560))); return new ConfidentialMerklePath(output, leafIndex); }
        finally { CryptographicOperations.ZeroMemory(packed); CryptographicOperations.ZeroMemory(output); }
    }
    /// <summary>Compute a local commitment-history root; the application must authenticate ledger roots independently.</summary>
    public static byte[] Root(IReadOnlyList<byte[]> commitments) { using var path = MerklePath(commitments, 0); return path.Root; }
}

internal sealed class ConfidentialWalletNative : IConfidentialWalletDriver
{
    internal static readonly IConfidentialWalletDriver Driver = new ConfidentialWalletNative();
    private const string Library = "connect_norito_bridge";
    private static readonly Lazy<bool> Available = new(DetectAvailable);
    private static readonly string[] RequiredExports =
    [
        "connect_norito_bridge_abi_version", "connect_norito_free",
        "connect_norito_confidential_prover_revision_v1",
        "connect_norito_confidential_prover_create_v1", "connect_norito_confidential_prover_close_v1",
        "connect_norito_confidential_prover_job_create_v1", "connect_norito_confidential_prover_job_input_v1",
        "connect_norito_confidential_prover_job_output_v1", "connect_norito_confidential_prover_job_commitments_v1",
        "connect_norito_confidential_prover_job_paths_v1", "connect_norito_confidential_prover_job_prove_v1",
        "connect_norito_confidential_prover_job_close_v1",
        "connect_norito_confidential_note_derivation_revision_v3", "connect_norito_confidential_default_diversifier_v3",
        "connect_norito_confidential_diversifier_derive_v3", "connect_norito_confidential_owner_tag_derive_v3",
        "connect_norito_confidential_note_commitment_derive_v3", "connect_norito_confidential_merkle_path_derive_v3",
    ];
    // The V3 note relation has first-release native contract revision 1.
    private static bool DetectAvailable()
    {
        IntPtr handle = IntPtr.Zero;
        try { return NativeLibrary.TryLoad(Library, typeof(ConfidentialWalletNative).Assembly, null, out handle) && RequiredExports.All(symbol => NativeLibrary.TryGetExport(handle, symbol, out _)) && Abi() == 29 && Revision() == 1 && DerivationRevision() == 1; }
        catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException) { return false; }
        finally { if (handle != IntPtr.Zero) NativeLibrary.Free(handle); }
    }
    internal static void RequireAvailable() { if (!Available.Value) throw new ConfidentialProverException(-101); }
    internal static void DerivationCheck(int code) { if (code != 0) throw new ArgumentException("Native confidential derivation rejected its bounded input."); }
    public ulong Create(byte[] network, byte[] asset, byte[] key) { RequireAvailable(); ConfidentialProverException.Check(CreateNative(network, new((uint)network.Length), asset, new((uint)asset.Length), key, new((uint)key.Length), out var handle)); return handle; }
    public void Close(ulong handle) => ConfidentialProverException.Check(CloseNative(handle));
    public ulong Job(ulong handle, byte operation, byte[] root, UInt128 amount) { ConfidentialProverException.Check(JobNative(handle, operation, root, new((uint)root.Length), (ulong)amount, (ulong)(amount >> 64), out var job)); return job; }
    public void Input(ulong job, UInt128 amount, byte[] rho, byte[] diversifier, int index) => ConfidentialProverException.Check(InputNative(job, (ulong)amount, (ulong)(amount >> 64), rho, new((uint)rho.Length), diversifier, new((uint)diversifier.Length), (ulong)index));
    public void Output(ulong job, UInt128 amount, byte[] rho, byte[] owner) => ConfidentialProverException.Check(OutputNative(job, (ulong)amount, (ulong)(amount >> 64), rho, new((uint)rho.Length), owner, new((uint)owner.Length)));
    public void Commitments(ulong job, byte[] leaves) => ConfidentialProverException.Check(CommitmentsNative(job, leaves, new((uint)leaves.Length)));
    public void Paths(ulong job, byte[] siblings, byte[] directions) => ConfidentialProverException.Check(PathsNative(job, siblings, new((uint)siblings.Length), directions, new((uint)directions.Length)));
    public void CloseJob(ulong job) { var status = CloseJobNative(job); if (status != -2) ConfidentialProverException.Check(status); }
    public byte[] Prove(ulong job)
    {
        IntPtr pointer = IntPtr.Zero;
        try { ConfidentialProverException.Check(ProveNative(job, out pointer, out var length)); var count = length.Value.ToUInt64(); if (pointer == IntPtr.Zero || count is 0 or > 16 * 1024 * 1024) throw new ConfidentialProverException(-100); var bytes = new byte[(int)count]; Marshal.Copy(pointer, bytes, 0, bytes.Length); return bytes; }
        finally { if (pointer != IntPtr.Zero) Free(pointer); }
    }

    // CULong preserves C unsigned long's 32-bit Windows and 64-bit Unix widths.
    [DllImport(Library, EntryPoint = "connect_norito_bridge_abi_version", CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint Abi();
    [DllImport(Library, EntryPoint = "connect_norito_confidential_prover_revision_v1", CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint Revision();
    [DllImport(Library, EntryPoint = "connect_norito_confidential_note_derivation_revision_v3", CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint DerivationRevision();
    [DllImport(Library, EntryPoint = "connect_norito_free", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void Free(IntPtr pointer);
    [DllImport(Library, EntryPoint = "connect_norito_confidential_prover_create_v1", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int CreateNative(byte[] network, CULong networkLength, byte[] asset, CULong assetLength, byte[] key, CULong keyLength, out ulong handle);
    [DllImport(Library, EntryPoint = "connect_norito_confidential_prover_close_v1", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int CloseNative(ulong handle);
    [DllImport(Library, EntryPoint = "connect_norito_confidential_prover_job_create_v1", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int JobNative(ulong handle, byte operation, byte[] root, CULong rootLength, ulong low, ulong high, out ulong job);
    [DllImport(Library, EntryPoint = "connect_norito_confidential_prover_job_input_v1", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int InputNative(ulong job, ulong low, ulong high, byte[] rho, CULong rhoLength, byte[] diversifier, CULong diversifierLength, ulong index);
    [DllImport(Library, EntryPoint = "connect_norito_confidential_prover_job_output_v1", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int OutputNative(ulong job, ulong low, ulong high, byte[] rho, CULong rhoLength, byte[] owner, CULong ownerLength);
    [DllImport(Library, EntryPoint = "connect_norito_confidential_prover_job_commitments_v1", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int CommitmentsNative(ulong job, byte[] leaves, CULong length);
    [DllImport(Library, EntryPoint = "connect_norito_confidential_prover_job_paths_v1", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int PathsNative(ulong job, byte[] siblings, CULong siblingsLength, byte[] directions, CULong directionsLength);
    [DllImport(Library, EntryPoint = "connect_norito_confidential_prover_job_prove_v1", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int ProveNative(ulong job, out IntPtr output, out CULong length);
    [DllImport(Library, EntryPoint = "connect_norito_confidential_prover_job_close_v1", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int CloseJobNative(ulong job);
    [DllImport(Library, EntryPoint = "connect_norito_confidential_default_diversifier_v3", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int Default([Out] byte[] output, CULong length);
    [DllImport(Library, EntryPoint = "connect_norito_confidential_diversifier_derive_v3", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int Diversifier(byte[] seed, CULong seedLength, [Out] byte[] output, CULong length);
    [DllImport(Library, EntryPoint = "connect_norito_confidential_owner_tag_derive_v3", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int Owner(byte[] key, CULong keyLength, byte[] diversifier, CULong diversifierLength, [Out] byte[] output, CULong length);
    [DllImport(Library, EntryPoint = "connect_norito_confidential_note_commitment_derive_v3", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int Commitment(byte[] asset, CULong assetLength, byte[] amount, CULong amountLength, byte[] rho, CULong rhoLength, byte[] owner, CULong ownerLength, [Out] byte[] output, CULong length);
    [DllImport(Library, EntryPoint = "connect_norito_confidential_merkle_path_derive_v3", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int Path(byte[] commitments, CULong commitmentsLength, ulong index, [Out] byte[] output, CULong length);
}
