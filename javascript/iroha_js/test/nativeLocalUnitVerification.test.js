import assert from "node:assert/strict";
import childProcess from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const sdk = fileURLToPath(new URL("../", import.meta.url));
const source = path.join(sdk, "src/native.js");
const artifactHash = path.join(sdk, "src/nativeArtifactHash.js");
const schema = "iroha.js-native-local-unit.v1";
const sha256 = (data) => createHash("sha256").update(data).digest("hex");

async function fixture(t, mutate, diagnostic, relativeOutput = "target/qualification/inert-local-records") {
  const dir = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "iroha-local-native-refusal-")));
  const root = path.join(dir, "inert-source-layout");
  const moduleDir = path.join(root, "javascript/iroha_js/src");
  const output = path.join(root, relativeOutput);
  await fs.mkdir(moduleDir, { recursive: true });
  await fs.mkdir(output, { recursive: true, mode: 0o700 });
  // An inert loader fixture, never a Cargo build or native artifact. It permits
  // direct refusal checks before any verifier child or native dlopen can occur.
  await fs.writeFile(path.join(root, "Cargo.toml"), "# inert source-layout marker\n");
  await fs.writeFile(path.join(root, "package.json"), '{"type":"module"}\n');
  await fs.copyFile(source, path.join(moduleDir, "native.js"));
  await fs.copyFile(artifactHash, path.join(moduleDir, "nativeArtifactHash.js"));
  const producer = Buffer.from('{"config":{"python":"/caller-selected/python"},"tools":{}}\n');
  const manifest = { schema, artifact_scope: "local-unit", build_provenance_version: 4,
    cargo_profile: "debug", platform: `${process.platform}-${process.arch}`, source_root: root,
    producer_record_sha256: sha256(producer), artifact_sha256: "b".repeat(64) };
  await fs.writeFile(path.join(output, "producer-record.json"), producer);
  await mutate({ dir, root, output, manifest });
  if (!Object.hasOwn(manifest, "noWrite")) {
    await fs.writeFile(path.join(output, "iroha_js_host.local-unit.json"), JSON.stringify(manifest));
  }
  const previous = process.env.IROHA_JS_NATIVE_DIR;
  const children = t.mock.method(childProcess, "execFileSync", () => {
    throw new Error("refusal fixture attempted a verifier child");
  });
  const dlopen = t.mock.method(process, "dlopen", () => {
    throw new Error("refusal fixture attempted native dlopen");
  });
  syncBuiltinESMExports();
  try {
    process.env.IROHA_JS_NATIVE_DIR = output;
    const implementation = await import(pathToFileURL(path.join(moduleDir, "native.js")));
    assert.throws(() => implementation.getNativeBinding(), (error) => {
      assert.equal(error.code, "ERR_IROHA_NATIVE_BINDING");
      assert.equal(error.nativeStatus, "local_unit_provenance_error");
      assert.match(error.message, diagnostic);
      return true;
    });
    assert.equal(children.mock.callCount(), 0);
    assert.equal(dlopen.mock.callCount(), 0);
    await assert.rejects(fs.stat(path.join(output, "iroha_js_host.node")), { code: "ENOENT" });
  } finally {
    children.mock.restore(); dlopen.mock.restore(); syncBuiltinESMExports();
    if (previous === undefined) delete process.env.IROHA_JS_NATIVE_DIR;
    else process.env.IROHA_JS_NATIVE_DIR = previous;
    await fs.rm(dir, { recursive: true, force: true });
  }
}

for (const [name, mutate, diagnostic] of [
  ["Release scope", ({ manifest }) => { manifest.artifact_scope = "release"; }, /scope\/profile\/platform\/source/],
  ["Release profile", ({ manifest }) => { manifest.cargo_profile = "release"; }, /scope\/profile\/platform\/source/],
  ["deploy profile", ({ manifest }) => { manifest.cargo_profile = "deploy"; }, /scope\/profile\/platform\/source/],
  ["iOS platform", ({ manifest }) => { manifest.platform = "ios-arm64"; }, /scope\/profile\/platform\/source/],
  ["old V3 record", ({ manifest }) => { manifest.build_provenance_version = 3; }, /scope\/profile\/platform\/source/],
  ["old source root", ({ manifest }) => { manifest.source_root = "/old/source-root"; }, /scope\/profile\/platform\/source/],
  ["wrong producer digest", ({ manifest }) => { manifest.producer_record_sha256 = "c".repeat(64); }, /producer record differs from its pin/],
  ["missing producer digest", ({ manifest }) => { delete manifest.producer_record_sha256; }, /scope\/profile\/platform\/source/],
  ["extra release admission field", ({ manifest }) => { manifest.release_qualified = true; }, /scope\/profile\/platform\/source/],
  ["caller-selected Python", () => {}, /Python\/repository verifier differs from current fixed owners/],
  ["manifest alias", async ({ output, manifest }) => {
    const owner = path.join(output, "real-manifest.json");
    await fs.writeFile(owner, JSON.stringify(manifest));
    await fs.symlink(owner, path.join(output, "iroha_js_host.local-unit.json"));
    manifest.noWrite = true;
  }, /bounded original regular file/],
  ["producer alias", async ({ output }) => {
    const owner = path.join(output, "real-producer.json");
    await fs.rename(path.join(output, "producer-record.json"), owner);
    await fs.symlink(owner, path.join(output, "producer-record.json"));
  }, /bounded original regular file/],
]) {
  test(`local native ${name} refuses before verifier or native use`, async (t) => fixture(t, mutate, diagnostic));
}

for (const relative of ["../external", "target/qualification", "target/qualification-other/artifact"]) {
  test(`local native artifact path rejects ${relative} before verifier or native use`, async (t) =>
    fixture(t, () => {}, /canonical target\/qualification child/, relative));
}

test("local native symbolic artifact directory refuses before verifier or native use", async (t) =>
  fixture(t, async ({ output }) => {
    const actual = output + "-original";
    await fs.rename(output, actual);
    await fs.symlink(actual, output);
  }, /canonical target\/qualification child/));
