"use strict";
const assert = require("node:assert/strict");
const test = require("node:test");
const path = require("node:path");
const { nearestManifest, serverConfiguration, isProjectManifest, testRunConfiguration } = require("./config.cjs");

test("uses a selected Musubi manifest and target as separate arguments", () => {
  const folder = path.resolve("space 日本");
  const manifest = path.join(folder, "Musubi.toml");
  const result = serverConfiguration(folder, { musubiPath: "musubi path", manifestPath: "${workspaceFolder}/Musubi.toml", contract: "demo/treasury::pool", zk: true }, value => value === manifest);
  assert.deepEqual(result, { command: "musubi path", args: ["lsp", "--manifest-path", manifest, "--contract", "demo/treasury::pool", "--zk"], manifest });
});
test("discovers the closest ancestor manifest without inferring imports", () => {
  const folder = path.resolve("workspace/packages/pool/contracts");
  const manifest = path.resolve("workspace/packages/pool/Musubi.toml");
  const outer = path.resolve("workspace/Musubi.toml");
  assert.equal(nearestManifest(folder, value => [manifest, outer].includes(value)), manifest);
  assert.deepEqual(serverConfiguration(folder, {}, value => value === manifest), { command: "musubi", args: ["lsp", "--manifest-path", manifest], manifest });
});
test("standalone roots and untitled documents do not invent package authority", () => {
  const folder = path.resolve("workspace");
  assert.deepEqual(serverConfiguration(folder, { kotoPath: "/opt/koto" }, () => false), { command: "/opt/koto", args: ["lsp", "--source-root", folder], manifest: undefined });
  assert.deepEqual(serverConfiguration(undefined, {}, () => { throw Error("unexpected filesystem lookup"); }), { command: "koto", args: ["lsp"], manifest: undefined });
  assert.throws(() => serverConfiguration(folder, { manifestPath: "missing/Musubi.toml" }, () => false), /does not exist/);
  assert.throws(() => serverConfiguration(folder, { contract: "pool" }, () => false), /requires Musubi.toml/);
  assert.throws(() => serverConfiguration(undefined, { manifestPath: "relative/Musubi.toml" }, () => false), /requires a workspace/);
});
test("project servers synchronize only Musubi TOML metadata", () => {
  const manifest = path.resolve("金庫😀/Musubi.toml");
  const document = fsPath => ({ uri: { scheme: "file", fsPath } });
  assert.equal(isProjectManifest(manifest, document(manifest)), true);
  assert.equal(isProjectManifest(manifest, document(path.resolve("sibling/math/Musubi.toml"))), true);
  assert.equal(isProjectManifest(undefined, document(manifest)), false);
  assert.equal(isProjectManifest(manifest, { uri: { scheme: "untitled", fsPath: manifest } }), false);
  assert.equal(isProjectManifest(manifest, document(path.resolve("other/config.toml"))), false);
  assert.equal(isProjectManifest(manifest, document(path.resolve("kotodama.project.json"))), false);
});
test("standalone test lenses run one exact koto process", () => {
  const source = path.resolve("w/t.test.ko");
  const lens = { tool: "koto", uri: "file:///w/t.test.ko", name: "quotes_points", chainDiscriminant: 42, zk: true,
    args: ["test", "run", "--filter", "quotes_points", "--exact", source, "--chain-discriminant", "42", "--zk"] };
  assert.deepEqual(testRunConfiguration({ kotoPath: "/opt/koto" }, lens), { command: "/opt/koto", args: lens.args });
  assert.equal(testRunConfiguration({}, lens).command, "koto");
  assert.throws(() => testRunConfiguration({}, { ...lens, tool: undefined }));
  assert.throws(() => testRunConfiguration({}, { ...lens, args: ["test", "run", "--filter", "other", "--exact", source] }));
  assert.throws(() => testRunConfiguration({}, { ...lens, args: ["build", "--out", "/tmp/x"] }));
  assert.throws(() => testRunConfiguration({}, { ...lens, args: [...lens.args.slice(0, 5), "--zk"] }));
});
test("Musubi test lenses preserve the selected package, target, and exact test", () => {
  const manifestPath = path.resolve("workspace 日本/Musubi.toml");
  const lens = { tool: "musubi", name: "quotes_points", manifestPath, package: "demo/pool", contract: "pool", chainDiscriminant: 369, zk: false, network: null, configPath: null };
  lens.args = ["test", "--manifest-path", manifestPath, "--package", lens.package, "--contract", lens.contract, "--filter", lens.name, "--exact", "--chain-discriminant", "369", "--locked", "--offline"];
  assert.deepEqual(testRunConfiguration({ musubiPath: "/opt/musubi" }, lens), { command: "/opt/musubi", args: lens.args });
  assert.equal(testRunConfiguration({}, lens).command, "musubi");
  const networkLens = { ...lens, network: "test", configPath: path.resolve("runtime/client.toml") };
  networkLens.args = [...lens.args, "--network", networkLens.network, "--config", networkLens.configPath];
  assert.deepEqual(testRunConfiguration({}, networkLens).args, networkLens.args);
  assert.throws(() => testRunConfiguration({}, { ...lens, network: undefined }));
  assert.throws(() => testRunConfiguration({}, { ...networkLens, configPath: "relative.toml" }));
  assert.throws(() => testRunConfiguration({}, { ...lens, args: lens.args.slice(0, -2) }));
  assert.throws(() => testRunConfiguration({}, { ...lens, contract: "other" }));
  assert.throws(() => testRunConfiguration({}, { ...lens, manifestPath: "relative/Musubi.toml" }));
  assert.throws(() => testRunConfiguration({}, { ...lens, args: [...lens.args, "--network"] }));
});

test("standalone server and test lenses preserve compiler capabilities", () => {
  const folder = path.resolve("workspace");
  const config = serverConfiguration(folder, { chainDiscriminant: 42, zk: true }, () => false);
  assert.deepEqual(config.args, ["lsp", "--source-root", folder, "--chain-discriminant", "42", "--zk"]);
  for (const chainDiscriminant of [0, 65536, 1.5, "42"]) {
    assert.throws(() => serverConfiguration(folder, { chainDiscriminant }, () => false), /chain discriminant/);
  }
  const source = path.resolve("tests/z.test.ko");
  const lens = { tool: "koto", name: "zero", chainDiscriminant: 42, zk: false,
    args: ["test", "run", "--filter", "zero", "--exact", source, "--chain-discriminant", "42"] };
  assert.equal(testRunConfiguration({}, lens).command, "koto");
  for (const changed of [{ chainDiscriminant: 753 }, { chainDiscriminant: undefined }, { zk: undefined }, { zk: true }]) {
    assert.throws(() => testRunConfiguration({}, { ...lens, ...changed }));
  }
});
