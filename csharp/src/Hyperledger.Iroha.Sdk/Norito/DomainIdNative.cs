using System.Runtime.InteropServices;
using System.Text;

namespace Hyperledger.Iroha.Norito;

/// <summary>Native pinned UTS-46 admission for already canonical domain identities.</summary>
internal static class DomainIdNative
{
    private const string Library = "connect_norito_bridge";
    private static readonly Lazy<bool> Available = new(DetectAvailability);
    private static bool Uses32BitUnsignedLong => OperatingSystem.IsWindows() || IntPtr.Size == 4;

    private static bool DetectAvailability()
    {
        IntPtr handle = IntPtr.Zero;
        try
        {
            return NativeLibrary.TryLoad(Library, typeof(DomainIdNative).Assembly, null, out handle)
                && NativeLibrary.TryGetExport(handle, "connect_norito_bridge_abi_version", out _)
                && NativeLibrary.TryGetExport(handle, "connect_norito_domain_id_validate_v1", out _)
                && BridgeAbiVersion() == 29;
        }
        catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            return false;
        }
        finally
        {
            if (handle != IntPtr.Zero) NativeLibrary.Free(handle);
        }
    }

    internal static void ValidateCanonical(string value, string paramName)
    {
        ArgumentNullException.ThrowIfNull(value, paramName);
        // Canonical DomainId wire labels are ASCII and each is at most 63 bytes.
        // This only bounds allocation; Rust owns complete label/IDNA admission.
        if (value.Length is < 1 or > 127 || value.Any(static character => character > 0x7f))
            throw Invalid(paramName);
        if (!Available.Value) throw Unavailable();
        var bytes = Encoding.ASCII.GetBytes(value);
        try
        {
            var status = Uses32BitUnsignedLong
                ? Validate32(bytes, checked((uint)bytes.Length))
                : Validate64(bytes, checked((ulong)bytes.Length));
            if (status == 1 || status == -2) throw Invalid(paramName);
            if (status != 0) throw Unavailable();
        }
        catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            throw Unavailable(error);
        }
    }

    private static ArgumentException Invalid(string paramName) => new(
        "Domain ID must use exact native-canonical ASCII domain.dataspace labels.", paramName);

    private static InvalidOperationException Unavailable(Exception? inner = null) => new(
        "Domain identities require the ABI-29 Rust domain validator from connect_norito_bridge.", inner);

    [DllImport(Library, EntryPoint = "connect_norito_bridge_abi_version", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint BridgeAbiVersion();
    [DllImport(Library, EntryPoint = "connect_norito_domain_id_validate_v1", CallingConvention = CallingConvention.Cdecl)]
    private static extern int Validate32(byte[] input, uint length);
    [DllImport(Library, EntryPoint = "connect_norito_domain_id_validate_v1", CallingConvention = CallingConvention.Cdecl)]
    private static extern int Validate64(byte[] input, ulong length);
}
