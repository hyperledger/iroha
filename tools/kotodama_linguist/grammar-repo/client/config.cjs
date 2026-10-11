"use strict";
const path = require("node:path");

/** Find the nearest Musubi manifest from the workspace folder, including its ancestors. */
function nearestManifest(folder, fileExists) {
  if (!folder) return undefined;
  for (let directory = path.resolve(folder);;) {
    const manifest = path.join(directory, "Musubi.toml");
    if (fileExists(manifest)) return manifest;
    const parent = path.dirname(directory);
    if (parent === directory) return undefined;
    directory = parent;
  }
}
/** Resolve one authoritative Musubi project, or an explicit standalone compiler root. */
function serverConfiguration(folder, settings, fileExists) {
  const configured = settings.manifestPath;
  if (configured && !folder && !path.isAbsolute(configured)) {
    throw new Error("Kotodama: a relative manifest path requires a workspace folder");
  }
  const manifest = configured
    ? path.resolve(folder || path.parse(configured).root, configured.replaceAll("${workspaceFolder}", folder || ""))
    : nearestManifest(folder, fileExists);
  if (configured && !fileExists(manifest)) {
    throw new Error(`Kotodama: configured Musubi manifest does not exist: ${manifest}`);
  }
  const command = manifest ? (settings.musubiPath || "musubi") : (settings.kotoPath || "koto");
  const args = ["lsp"];
  if (manifest) args.push("--manifest-path", manifest);
  else if (folder) args.push("--source-root", path.resolve(folder));
  if (!manifest && settings.chainDiscriminant !== undefined) {
    if (!Number.isInteger(settings.chainDiscriminant) || settings.chainDiscriminant < 1 || settings.chainDiscriminant > 65535) {
      throw new Error("Kotodama: chain discriminant must be an integer from 1 to 65535");
    }
    args.push("--chain-discriminant", String(settings.chainDiscriminant));
  }
  if (settings.contract) {
    if (!manifest) throw new Error("Kotodama: selecting a contract requires Musubi.toml");
    args.push("--contract", settings.contract);
  }
  if (settings.zk) args.push("--zk");
  return { command, args, manifest };
}
/**
 * Forward Musubi metadata buffers only to a project server. The resolver authenticates which
 * snapshots belong to its graph; workspace package manifests may be outside the root directory.
 * TOML documents retain their own completion, hover, and formatting providers.
 */
function isProjectManifest(manifest, document) {
  return Boolean(manifest && document.uri.scheme === "file" && (path.resolve(document.uri.fsPath) === path.resolve(manifest) || path.basename(document.uri.fsPath) === "Musubi.toml"));
}
/** Validate a typed Run test lens and construct an exact invocation without a shell. */
function testRunConfiguration(settings, lens) {
  const invalid = () => { throw new Error("Kotodama: the language server sent a malformed test lens"); };
  const text = value => typeof value === "string" && value.length > 0;
  if (!lens || !text(lens.name) || lens.name.startsWith("-") || !Array.isArray(lens.args) || !lens.args.every(text)) invalid();
  if (!Number.isInteger(lens.chainDiscriminant) || lens.chainDiscriminant < 1
      || lens.chainDiscriminant > 65535 || typeof lens.zk !== "boolean") invalid();
  let args;
  let command;
  if (lens.tool === "koto") {
    const source = lens.args[5];
    if (!text(source) || !path.isAbsolute(source)) invalid();
    args = ["test", "run", "--filter", lens.name, "--exact", source];
    command = settings.kotoPath || "koto";
  } else if (lens.tool === "musubi") {
    if (!text(lens.manifestPath) || !path.isAbsolute(lens.manifestPath)
        || !text(lens.package) || !text(lens.contract)
        || lens.package.startsWith("-") || lens.contract.startsWith("-")) invalid();
    args = ["test", "--manifest-path", lens.manifestPath, "--package", lens.package,
      "--contract", lens.contract, "--filter", lens.name, "--exact"];
    command = settings.musubiPath || "musubi";
  } else invalid();
  args.push("--chain-discriminant", String(lens.chainDiscriminant));
  if (lens.zk) args.push("--zk");
  if (lens.tool === "musubi") {
    if (lens.network !== null && (!text(lens.network) || lens.network.startsWith("-"))) invalid();
    if (lens.configPath !== null && (!text(lens.configPath) || !path.isAbsolute(lens.configPath))) invalid();
    args.push("--locked", "--offline");
    if (lens.network !== null) args.push("--network", lens.network);
    if (lens.configPath !== null) args.push("--config", lens.configPath);
  }
  if (lens.args.length !== args.length || lens.args.some((argument, index) => argument !== args[index])) invalid();
  return { command, args };
}
module.exports = { nearestManifest, serverConfiguration, isProjectManifest, testRunConfiguration };
