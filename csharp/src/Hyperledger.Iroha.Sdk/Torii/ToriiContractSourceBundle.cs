using System.Text;

namespace Hyperledger.Iroha.Torii;

/// <summary>Shared bounded, owner-relative source validation for submission and retrieval.</summary>
internal static class ToriiContractSourceBundle
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal static ToriiContractVerifiedSourceSubmission Normalize(
        ToriiContractVerifiedSourceSubmission request,
        bool requireRootName = true)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Artifacts);
        ArgumentNullException.ThrowIfNull(request.Sources);
        ArgumentNullException.ThrowIfNull(request.Imports);
        ArgumentNullException.ThrowIfNull(request.Packages);
        var hasBundle = request.Artifacts.Count != 0 || request.Sources.Count != 0 || request.Imports.Count != 0 || request.Packages.Count != 0;
        if (requireRootName && hasBundle && request.SourceName is null)
            throw new ArgumentException("SourceName is required with a source bundle.", nameof(request));
        if (request.Packages.Count > 512)
            throw new ArgumentException("Source set exceeds 512 packages.", nameof(request));

        var rootName = request.SourceName is null ? null : NormalizePath(request.SourceName);
        var rootNames = new HashSet<string>(StringComparer.Ordinal);
        if (rootName is not null) rootNames.Add(rootName);
        long bytes = SourceByteCount(request.SourceText);
        var count = 1;
        IReadOnlyList<ToriiContractSourceFile> Files(IReadOnlyList<ToriiContractSourceFile> files, HashSet<string> names)
        {
            ArgumentNullException.ThrowIfNull(files);
            if (files.Count > 512 - count)
                throw new ArgumentException("Source set exceeds 512 files.", nameof(request));
            var normalized = new List<ToriiContractSourceFile>(files.Count);
            foreach (var file in files)
            {
                ArgumentNullException.ThrowIfNull(file);
                var name = NormalizePath(file.SourceName);
                if (!names.Add(name)) throw new ArgumentException("Duplicate logical source path in an owner.", nameof(request));
                bytes += SourceByteCount(file.SourceText);
                if (bytes > 16 * 1024 * 1024)
                    throw new ArgumentException("Source set exceeds 16 MiB.", nameof(request));
                count++;
                normalized.Add(file with { SourceName = name });
            }
            return normalized;
        }

        IReadOnlyList<ToriiContractSourceArtifact> Artifacts(IReadOnlyList<ToriiContractSourceArtifact> artifacts, HashSet<string> names)
        {
            ArgumentNullException.ThrowIfNull(artifacts);
            if (artifacts.Count > 512 - count) throw new ArgumentException("Source set exceeds 512 files.", nameof(request));
            var normalized = new List<ToriiContractSourceArtifact>(artifacts.Count);
            foreach (var artifact in artifacts)
            {
                ArgumentNullException.ThrowIfNull(artifact);
                var name = NormalizePath(artifact.SourceName);
                if (!name.EndsWith(".to", StringComparison.Ordinal)) throw new ArgumentException("Compiled interface requires a .to path.", nameof(request));
                if (!names.Add(name)) throw new ArgumentException("Duplicate source or artifact path in an owner.", nameof(request));
                var payload = artifact.Artifact;
                if (payload.Count == 0) throw new ArgumentException("Compiled interface bytes must not be empty.", nameof(request));
                bytes += payload.Count;
                if (bytes > 16 * 1024 * 1024) throw new ArgumentException("Source set exceeds 16 MiB.", nameof(request));
                count++;
                normalized.Add(artifact with { SourceName = name });
            }
            return normalized;
        }

        var identities = new HashSet<string>(StringComparer.Ordinal);
        foreach (var package in request.Packages)
        {
            ArgumentNullException.ThrowIfNull(package);
            RequireExactToken(package.Identity, "package identity");
            if (!identities.Add(package.Identity))
                throw new ArgumentException("Duplicate locked package identity.", nameof(request));
        }
        IReadOnlyList<ToriiContractSourceImport> Imports(IReadOnlyList<ToriiContractSourceImport> imports)
        {
            ArgumentNullException.ThrowIfNull(imports);
            var aliases = new HashSet<string>(StringComparer.Ordinal);
            foreach (var import in imports)
            {
                ArgumentNullException.ThrowIfNull(import);
                RequireExactToken(import.Alias, "import alias");
                RequireExactToken(import.Package, "import package identity");
                if (!aliases.Add(import.Alias)) throw new ArgumentException("Duplicate import alias in an owner.", nameof(request));
                if (!identities.Contains(import.Package)) throw new ArgumentException("Import references an absent locked package.", nameof(request));
            }
            return imports.ToArray();
        }

        var sources = Files(request.Sources, rootNames);
        var artifacts = Artifacts(request.Artifacts, rootNames);
        var imports = Imports(request.Imports);
        var packages = new List<ToriiContractSourcePackage>(request.Packages.Count);
        foreach (var package in request.Packages)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            var modules = Files(package.Modules, names);
            var companions = Files(package.Sources, names);
            var interfaces = Artifacts(package.Artifacts, names);
            ArgumentNullException.ThrowIfNull(package.Exports);
            var exports = new HashSet<string>(StringComparer.Ordinal);
            foreach (var export in package.Exports)
            {
                RequireExactToken(export, "package export");
                if (!exports.Add(export)) throw new ArgumentException("Duplicate package export.", nameof(request));
            }
            packages.Add(package with { Modules = modules, Sources = companions, Artifacts = interfaces, Imports = Imports(package.Imports) });
        }
        return request with { SourceName = rootName, Sources = sources, Artifacts = artifacts, Imports = imports, Packages = packages };
    }

    private static int SourceByteCount(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var length = Utf8Length(value);
        if (length > 1024 * 1024) throw new ArgumentException("Source file exceeds 1 MiB.", nameof(value));
        return length;
    }

    private static int Utf8Length(string value)
    {
        try { return StrictUtf8.GetByteCount(value); }
        catch (EncoderFallbackException error)
        {
            throw new ArgumentException("Source bundle text must contain valid Unicode scalar values.", nameof(value), error);
        }
    }

    private static void RequireExactToken(string value, string label)
    {
        if (string.IsNullOrEmpty(value) || value.Any(character => char.IsWhiteSpace(character) || char.IsControl(character)))
            throw new ArgumentException($"{label} must be nonempty exact text.", nameof(value));
        _ = Utf8Length(value);
    }

    private static string NormalizePath(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Any(char.IsControl) || Utf8Length(value) > 4096
            || value.StartsWith('/') || value.StartsWith('\\') || value.Contains(':'))
            throw new ArgumentException("Source path must be a bounded relative logical path.", nameof(value));
        var parts = new List<string>();
        foreach (var part in value.Replace('\\', '/').Split('/'))
        {
            if (part is "" or ".") continue;
            if (part == "..")
            {
                if (parts.Count == 0) throw new ArgumentException("Source path escapes its root.", nameof(value));
                parts.RemoveAt(parts.Count - 1);
            }
            else
            {
                if (part.All(character => character == '.')) throw new ArgumentException("Source path contains an invalid component.", nameof(value));
                parts.Add(part);
            }
        }
        if (parts.Count == 0) throw new ArgumentException("Source path must name a file.", nameof(value));
        return string.Join('/', parts);
    }
}
