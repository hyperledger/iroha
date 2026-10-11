using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace Hyperledger.Iroha.Address;

/// <summary>The mandatory Rust owner for complete V1 account-controller admission.</summary>
internal static class AccountAddressNative
{
    private const string Library = "connect_norito_bridge";
    private static readonly Lazy<bool> Available = new(DetectAvailability);
    internal static bool IsAvailable => Available.Value;
    private static bool Uses32BitUnsignedLong => OperatingSystem.IsWindows() || IntPtr.Size == 4;

    private static bool DetectAvailability()
    {
        IntPtr handle = IntPtr.Zero;
        try
        {
            return NativeLibrary.TryLoad(Library, typeof(AccountAddressNative).Assembly, null, out handle)
                && NativeLibrary.TryGetExport(handle, "connect_norito_bridge_abi_version", out _)
                && NativeLibrary.TryGetExport(handle, "connect_norito_account_address_render", out _)
                && NativeLibrary.TryGetExport(handle, "connect_norito_free", out _)
                && BridgeAbiVersion() == 29;
        }
        catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            return false;
        }
        finally { if (handle != IntPtr.Zero) NativeLibrary.Free(handle); }
    }

    internal static void ValidateCanonical(byte[] canonical)
    {
        if (!IsAvailable) throw Unavailable();
        IntPtr hex = IntPtr.Zero, literal = IntPtr.Zero, error = IntPtr.Zero;
        try
        {
            int status;
            ulong hexLength, literalLength, errorLength;
            // C unsigned long is 32 bits on Windows (including x64) and on
            // 32-bit Unix; it is 64 bits on 64-bit Darwin/Linux.
            if (Uses32BitUnsignedLong)
            {
                status = Render32(canonical, checked((uint)canonical.Length), AccountAddress.DefaultChainDiscriminant,
                    out hex, out var h, out literal, out var l, out error, out var e);
                hexLength = h; literalLength = l; errorLength = e;
            }
            else
            {
                status = Render64(canonical, checked((ulong)canonical.Length), AccountAddress.DefaultChainDiscriminant,
                    out hex, out hexLength, out literal, out literalLength, out error, out errorLength);
            }
            if (status != 0)
            {
                if (error == IntPtr.Zero || errorLength == 0 || errorLength > 65_536) throw Unavailable();
                using var decoded = JsonDocument.Parse(Copy(error, checked((int)errorLength)));
                var code = decoded.RootElement.GetProperty("code").GetString();
                var message = decoded.RootElement.GetProperty("message").GetString() ?? "Invalid account controller.";
                throw new AccountAddressException(MapCode(code), message);
            }
            if (hex == IntPtr.Zero || literal == IntPtr.Zero || literalLength == 0
                || error != IntPtr.Zero || errorLength != 0
                || hexLength != checked(2UL + 2UL * (ulong)canonical.Length)) throw Unavailable();
            var canonicalHex = new UTF8Encoding(false, true).GetString(Copy(hex, checked((int)hexLength)));
            if (!string.Equals(canonicalHex, "0x" + Convert.ToHexString(canonical).ToLowerInvariant(), StringComparison.Ordinal))
                throw Unavailable();
        }
        catch (Exception failure) when (failure is DllNotFoundException or EntryPointNotFoundException
            or BadImageFormatException or JsonException or DecoderFallbackException or OverflowException)
        {
            throw Unavailable(failure);
        }
        finally
        {
            if (hex != IntPtr.Zero) Free(hex);
            if (literal != IntPtr.Zero) Free(literal);
            if (error != IntPtr.Zero) Free(error);
        }
    }

    private static byte[] Copy(IntPtr pointer, int length)
    {
        var bytes = new byte[length]; Marshal.Copy(pointer, bytes, 0, length); return bytes;
    }

    private static AccountAddressException Unavailable(Exception? inner = null) => new(
        AccountAddressErrorCode.NativeBridgeUnavailable,
        "Account addresses require the complete ABI-29 Rust address validator from connect_norito_bridge.", inner);

    private static AccountAddressErrorCode MapCode(string? code) => code switch
    {
        "ERR_INVALID_PUBLIC_KEY" => AccountAddressErrorCode.InvalidPublicKey,
        "ERR_INVALID_LENGTH" => AccountAddressErrorCode.InvalidLength,
        "ERR_INVALID_HEADER_VERSION" => AccountAddressErrorCode.InvalidHeaderVersion,
        "ERR_INVALID_NORM_VERSION" => AccountAddressErrorCode.InvalidNormVersion,
        "ERR_UNKNOWN_ADDRESS_CLASS" => AccountAddressErrorCode.UnknownAddressClass,
        "ERR_UNKNOWN_CONTROLLER_TAG" => AccountAddressErrorCode.UnknownControllerTag,
        "ERR_UNKNOWN_CURVE" => AccountAddressErrorCode.UnknownCurve,
        "ERR_UNEXPECTED_TRAILING_BYTES" => AccountAddressErrorCode.UnexpectedTrailingBytes,
        "ERR_INVALID_MULTISIG_POLICY" => AccountAddressErrorCode.InvalidMultisigPolicy,
        "ERR_DECODE_RESOURCE_LIMIT" => AccountAddressErrorCode.DecodeResourceLimit,
        "ERR_MULTISIG_MEMBER_OVERFLOW" => AccountAddressErrorCode.InvalidMultisigPolicy,
        "ERR_UNSUPPORTED_ALGORITHM" => AccountAddressErrorCode.UnknownCurve,
        "ERR_UNSUPPORTED_ADDRESS_FORMAT" => AccountAddressErrorCode.UnsupportedAddressFormat,
        _ => throw Unavailable(),
    };

    [DllImport(Library, EntryPoint = "connect_norito_bridge_abi_version", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint BridgeAbiVersion();
    [DllImport(Library, EntryPoint = "connect_norito_free", CallingConvention = CallingConvention.Cdecl)]
    private static extern void Free(IntPtr pointer);
    [DllImport(Library, EntryPoint = "connect_norito_account_address_render", CallingConvention = CallingConvention.Cdecl)]
    private static extern int Render32(byte[] input, uint length, ushort prefix, out IntPtr hex, out uint hexLength,
        out IntPtr literal, out uint literalLength, out IntPtr error, out uint errorLength);
    [DllImport(Library, EntryPoint = "connect_norito_account_address_render", CallingConvention = CallingConvention.Cdecl)]
    private static extern int Render64(byte[] input, ulong length, ushort prefix, out IntPtr hex, out ulong hexLength,
        out IntPtr literal, out ulong literalLength, out IntPtr error, out ulong errorLength);
}
