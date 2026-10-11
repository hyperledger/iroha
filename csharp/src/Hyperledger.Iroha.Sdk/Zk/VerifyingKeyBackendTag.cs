using System;
using System.Collections.Generic;
using System.Text;

namespace Hyperledger.Iroha.Zk;

/// <summary>
/// Low-level proof engines accepted by the canonical Norito
/// <c>iroha_data_model::zk::BackendTag</c> wire contract.
/// </summary>
/// <remarks>
/// Privacy protocols and verifier profiles remain separate catalog labels and
/// never become wire-enum variants.
/// </remarks>
public enum VerifyingKeyBackendTag : uint
{
    NativePipaRPasta = 0,
    Stark = 1,
}

/// <summary>
/// Human-facing catalog classification separate from the Norito wire enum.
/// </summary>
public enum VerifyingKeyBackendCatalogTag
{
    Production,
    Unsupported,
}

public static class VerifyingKeyBackendTags
{
    private static readonly HashSet<string> StarkFriProductionBackends =
        new(StringComparer.Ordinal)
        {
            "stark/fri/poseidon-x7-goldilocks-6x64-v1",
        };

    private static readonly HashSet<string> ProductionNativePipaRPastaBackends =
        new(StringComparer.Ordinal)
        {
            "pipa-r/pasta",
            "pipa-r/pasta/kaigi-authorization-v1",
            "pipa-r/pasta/kaigi-usage-v1",
            "pipa-r/pasta/confidential-transfer-v1",
            "pipa-r/pasta/confidential-unshield-full-v1",
            "pipa-r/pasta/confidential-unshield-change-v1",
        };

    private static readonly HashSet<string> TrustedSetupBackendSegments =
        new(StringComparer.Ordinal)
        {
            "groth16", "kzg", "bn254", "bn256", "bls12", "srs", "crs",
            "ptau", "ceremony", "powersoftau",
        };

    private static readonly string[] TrustedSetupCompactTokens =
    {
        "groth16", "kzg", "bn254", "bn256", "bls12381", "bls12",
        "srs", "crs", "ptau", "ceremony", "trustedsetup",
        "structuredreferencestring", "universalsrs", "powersoftau",
    };

    private static readonly string[] ProductionClaimBackendFragments =
    {
        "productionready", "productionhardened", "productionenabled",
        "productionapproved", "productioncertified", "productionclaim",
        "claimedproduction", "mainnetready", "mainnetcomplete", "mainnetclaim",
        "claimedmainnet", "mainnetcertified", "mainnetapproved", "mainnetrelease",
        "auditedproduction", "externallyaudited", "thirdpartyaudited",
        "boiaudited", "auditedmainnet", "externalaudit", "auditpassed",
        "auditapproved", "auditsignoff", "auditclaim", "claimedaudit",
        "securityreviewpassed", "securityauditpassed", "securityaudited",
        "externalsecurityreview", "certifiedproduction", "certifiedmainnet",
        "releaseready", "releaseapproved", "releasecertified",
    };

    /// <summary>Resolve one exact registry profile to its canonical wire engine.</summary>
    public static VerifyingKeyBackendTag? RegistryTag(string? label)
    {
        if (label is null) return null;
        if (StarkFriProductionBackends.Contains(label)) return VerifyingKeyBackendTag.Stark;
        if (ProductionNativePipaRPastaBackends.Contains(label)) return VerifyingKeyBackendTag.NativePipaRPasta;
        return null;
    }

    public static uint NoritoDiscriminant(this VerifyingKeyBackendTag tag)
    {
        EnsureDefined(tag);
        return (uint)tag;
    }

    public static string CanonicalLabel(this VerifyingKeyBackendTag tag) => tag switch
    {
        VerifyingKeyBackendTag.Stark => "stark",
        VerifyingKeyBackendTag.NativePipaRPasta => "native-pipa-r-pasta",
        _ => throw new ArgumentOutOfRangeException(
            nameof(tag),
            tag,
            "Unknown Norito verifying-key backend tag."),
    };

    public static bool TryFromCanonicalLabel(
        string? label,
        out VerifyingKeyBackendTag tag)
    {
        switch (label)
        {
            case "stark":
                tag = VerifyingKeyBackendTag.Stark;
                return true;
            case "native-pipa-r-pasta":
                tag = VerifyingKeyBackendTag.NativePipaRPasta;
                return true;
            default:
                tag = default;
                return false;
        }
    }

    public static VerifyingKeyBackendTag FromCanonicalLabel(
        string? label,
        string context = "backend")
    {
        if (!TryFromCanonicalLabel(label, out var tag))
        {
            throw new ArgumentException(
                $"{context} must be one of the exact canonical backend labels: "
                    + "\"stark\" or \"native-pipa-r-pasta\".",
                context);
        }

        return tag;
    }

    public static string RequireCanonicalLabel(
        string? label,
        string context = "backend")
    {
        _ = FromCanonicalLabel(label, context);
        return label!;
    }

    public static VerifyingKeyBackendCatalogTag FromCatalogLabel(string? raw)
    {
        var label = raw ?? string.Empty;
        if (label.Length == 0 || HasNonAscii(label))
        {
            return VerifyingKeyBackendCatalogTag.Unsupported;
        }

        if (VerifierBackendRegistryLabels.IsSupportedLabel(label)
            || TryFromCanonicalLabel(label, out _))
        {
            return VerifyingKeyBackendCatalogTag.Production;
        }
        return VerifyingKeyBackendCatalogTag.Unsupported;
    }

    public static bool IsProductionVerifyBackendLabel(string? raw)
    {
        if (raw is null)
        {
            return false;
        }
        var backend = raw;
        if (string.IsNullOrWhiteSpace(backend)
            || backend.Trim() != backend
            || !IsPortableVerifierBackendLabel(backend)
            || IsProductionClaimBackendLabel(backend)
            || IsTrustedSetupBackendLabel(backend)
            || IsDeveloperOnlyBackendLabel(backend))
        {
            return false;
        }
        return StarkFriProductionBackends.Contains(backend)
            || ProductionNativePipaRPastaBackends.Contains(backend);
    }

    public static string RequireProductionVerifyBackendLabel(
        string? raw,
        string context = "backend")
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            throw new ArgumentException($"{context} must not be blank.", context);
        }
        var backend = raw;
        if (backend.Trim() != backend)
        {
            throw new ArgumentException(
                $"{context} must not contain surrounding whitespace.",
                context);
        }
        if (!IsProductionVerifyBackendLabel(backend))
        {
            throw new ArgumentException(
                $"{context} uses unsupported production verifier backend {backend}.",
                context);
        }
        return backend;
    }

    private static bool IsProductionClaimBackendLabel(string raw)
    {
        var compact = CompactAscii(raw.ToLowerInvariant());
        foreach (var fragment in ProductionClaimBackendFragments)
        {
            if (compact.Contains(fragment, StringComparison.Ordinal))
            {
                return true;
            }
        }
        return false;
    }

    private static bool IsTrustedSetupBackendLabel(string raw)
    {
        var label = raw.ToLowerInvariant();
        var compact = CompactAscii(label);
        foreach (var segment in LowercaseAsciiSegments(label))
        {
            if (TrustedSetupBackendSegments.Contains(segment))
            {
                return true;
            }
        }
        foreach (var token in TrustedSetupCompactTokens)
        {
            if (compact.Contains(token, StringComparison.Ordinal))
            {
                return true;
            }
        }
        return false;
    }

    private static bool IsDeveloperOnlyBackendLabel(string raw)
    {
        var label = raw.ToLowerInvariant();
        var compact = CompactAscii(label);
        foreach (var fragment in new[]
        {
            "notforproduction", "notproduction", "notproductionready", "notready",
            "replacebeforeproduction", "replacebeforemainnet", "draftonly",
        })
        {
            if (compact.Contains(fragment, StringComparison.Ordinal))
            {
                return true;
            }
        }

        var letterRun = new StringBuilder();
        foreach (var token in LowercaseAsciiSegments(label))
        {
            if (IsDeveloperOnlyBackendRun(token))
            {
                return true;
            }
            if (token.Length == 1)
            {
                letterRun.Append(token);
            }
            else
            {
                if (IsDeveloperOnlyBackendRun(letterRun.ToString()))
                {
                    return true;
                }
                letterRun.Clear();
            }
        }
        return IsDeveloperOnlyBackendRun(letterRun.ToString());
    }

    private static bool IsDeveloperOnlyBackendRun(string value) =>
        value.Contains("debug", StringComparison.Ordinal)
        || value.Contains("mock", StringComparison.Ordinal)
        || value.Contains("fixture", StringComparison.Ordinal)
        || value.Contains("dev", StringComparison.Ordinal)
        || value.Contains("todo", StringComparison.Ordinal)
        || value.Contains("draft", StringComparison.Ordinal)
        || value.Contains("pending", StringComparison.Ordinal)
        || value.Contains("replace", StringComparison.Ordinal)
        || value is "test" or "dummy" or "fake" or "stub" or "sample" or "placeholder";

    private static bool IsPortableVerifierBackendLabel(string value)
    {
        if (value.Length == 0
            || !IsLowerAsciiAlphanumeric(value[0])
            || !IsLowerAsciiAlphanumeric(value[^1]))
        {
            return false;
        }
        foreach (var character in value)
        {
            if (!IsLowerAsciiAlphanumeric(character)
                && character is not ('/' or ':' or '.' or '_' or '-'))
            {
                return false;
            }
        }
        foreach (var separator in new[]
        {
            "//", "::", "..", "/:", ":/", "/.", "./", ":.", ".:",
        })
        {
            if (value.Contains(separator, StringComparison.Ordinal))
            {
                return false;
            }
        }
        return true;
    }

    private static IEnumerable<string> LowercaseAsciiSegments(string value)
    {
        var segment = new StringBuilder();
        foreach (var character in value)
        {
            if (IsLowerAsciiAlphanumeric(character))
            {
                segment.Append(character);
            }
            else if (segment.Length != 0)
            {
                yield return segment.ToString();
                segment.Clear();
            }
        }
        if (segment.Length != 0)
        {
            yield return segment.ToString();
        }
    }

    private static string CompactAscii(string value)
    {
        var compact = new StringBuilder(value.Length);
        foreach (var character in value)
        {
            if (IsLowerAsciiAlphanumeric(character))
            {
                compact.Append(character);
            }
        }
        return compact.ToString();
    }

    private static bool IsLowerAsciiAlphanumeric(char value) =>
        value is >= '0' and <= '9' or >= 'a' and <= 'z';

    private static bool HasNonAscii(string value)
    {
        foreach (var character in value)
        {
            if (character > 0x7F)
            {
                return true;
            }
        }
        return false;
    }

    private static void EnsureDefined(VerifyingKeyBackendTag tag)
    {
        if (tag is not VerifyingKeyBackendTag.Stark
            and not VerifyingKeyBackendTag.NativePipaRPasta)
        {
            throw new ArgumentOutOfRangeException(
                nameof(tag),
                tag,
                "Unknown Norito verifying-key backend tag.");
        }
    }
}
