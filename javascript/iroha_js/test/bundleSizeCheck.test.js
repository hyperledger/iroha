// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { relative, resolve } from "node:path";
import test, { after, before } from "node:test";
import { fileURLToPath } from "node:url";

import {
  BUNDLE_TARGETS,
  analyzeSplitBundle,
  findForbiddenBrowserInputs,
  hasForbiddenGlobalBufferMutation,
  listExplicitBrowserExports,
  runBundleSizeCheck,
} from "../scripts/bundle-size-check.mjs";
import {
  acquireDistLock,
  releaseDistLock,
} from "../scripts/build-dist.mjs";

const PACKAGE_ROOT = fileURLToPath(new URL("..", import.meta.url));
let bundleDistLock;

function splitBuildOptions(target) {
  return {
    absWorkingDir: PACKAGE_ROOT,
    entryPoints: [target.entryPoint],
    bundle: true,
    splitting: true,
    write: false,
    outdir: resolve(PACKAGE_ROOT, ".bundle-audit-test"),
    entryNames: "entry",
    chunkNames: "[hash]",
    platform: target.platform,
    target: target.target,
    format: "esm",
    treeShaking: true,
    sourcemap: false,
    minify: true,
    metafile: true,
    charset: "utf8",
  };
}

function fakeSplitBundle(options, entryText = "") {
  const entryPoint = options.entryPoints[0];
  const entryInput = relative(PACKAGE_ROOT, entryPoint).replaceAll("\\", "/");
  const outputRoot = relative(PACKAGE_ROOT, options.outdir).replaceAll("\\", "/");
  const outputName = (name) => `${outputRoot}/${name}.js`;
  const isTorii = entryInput === "src/toriiClient.js";
  const lazyChunks = isTorii
    ? [
        {
          name: "torii-optional",
          input: "src/toriiOptional.js",
          specifier: "./toriiOptional.js",
          edges: 1,
        },
        {
          name: "sumeragi",
          input: "src/sumeragiTyped.js",
          specifier: "./sumeragiTyped.js",
          edges: 2,
        },
      ]
    : [
        {
          name: "sumeragi",
          input: "dist/sumeragiTyped.js",
          specifier: "./sumeragiTyped.js",
          edges: 2,
        },
        {
          name: "deployment",
          input: "dist/smartContractDeploymentSubmit.js",
          specifier: "./smartContractDeploymentSubmit.js",
          edges: 1,
        },
      ];
  const inputImports = [];
  const outputImports = [];
  const inputs = {};
  const outputs = {};
  const outputFiles = [];
  for (const lazy of lazyChunks) {
    for (let edge = 0; edge < lazy.edges; edge += 1) {
      inputImports.push({
        path: lazy.input,
        original: lazy.specifier,
        kind: "dynamic-import",
      });
      outputImports.push({
        path: outputName(lazy.name),
        kind: "dynamic-import",
      });
    }
    inputs[lazy.input] = { imports: [] };
    outputs[outputName(lazy.name)] = {
      entryPoint: lazy.input,
      imports: [],
      bytes: 0,
    };
    outputFiles.push({
      path: resolve(PACKAGE_ROOT, outputName(lazy.name)),
      contents: new Uint8Array(),
      text: "",
    });
  }
  const entryBytes = new TextEncoder().encode(entryText);
  inputs[entryInput] = { imports: inputImports };
  outputs[outputName("entry")] = {
    entryPoint: entryInput,
    imports: outputImports,
    bytes: entryBytes.byteLength,
  };
  outputFiles.unshift({
    path: resolve(PACKAGE_ROOT, outputName("entry")),
    contents: entryBytes,
    text: entryText,
  });
  return { outputFiles, metafile: { inputs, outputs } };
}

function assertSplitByteInventory(result, metrics) {
  const actualBytes = (names) => names.reduce((total, name) => {
    const output = result.outputFiles.find(({ path }) =>
      resolve(path) === resolve(PACKAGE_ROOT, name));
    assert.ok(output, `missing emitted output ${name}`);
    return total + output.contents.byteLength;
  }, 0);
  assert.equal(metrics.eagerBytes, actualBytes(metrics.eagerOutputs));
  for (const lazy of metrics.lazyChunks) {
    assert.equal(lazy.bytes, actualBytes(lazy.outputs));
  }
  assert.equal(metrics.combinedBytes, actualBytes(metrics.outputs));
  assert.equal(metrics.combinedBytes,
    metrics.eagerBytes + metrics.lazyChunks.reduce((total, lazy) => total + lazy.bytes, 0));
}

before(async () => {
  bundleDistLock = await acquireDistLock({ root: PACKAGE_ROOT });
});

after(() => {
  if (bundleDistLock) releaseDistLock(bundleDistLock);
});

test("bundle-size check fails closed when esbuild cannot be resolved", async () => {
  await assert.rejects(
    runBundleSizeCheck({
      loadEsbuild: async () => {
        throw new Error("simulated missing esbuild");
      },
      log() {},
    }),
    /requires the pinned esbuild devDependency/u,
  );
});

for (const scope of ["eager", "lazy", "single"]) {
  test(`bundle audit accepts code growth in the ${scope} output`, async () => {
    const padding = `/* ${"x".repeat(2 * 1024 * 1024)} */ export {};`;
    const logs = [];
    await runBundleSizeCheck({
      loadEsbuild: async () => ({
        async build(options) {
          if (options.splitting === true) {
            const result = fakeSplitBundle(options, scope === "eager" ? padding : "");
            if (scope === "lazy") {
              const output = result.outputFiles[1];
              output.text = padding;
              output.contents = new TextEncoder().encode(padding);
              const name = relative(PACKAGE_ROOT, output.path).replaceAll("\\", "/");
              result.metafile.outputs[name].bytes = output.contents.byteLength;
            }
            return result;
          }
          const entryPoint = options.entryPoints[0];
          const text = scope === "single" && entryPoint.endsWith("/dist/transactionCodec.js")
            ? padding : "export {};";
          return {
            outputFiles: [{ contents: new TextEncoder().encode(text), text }],
            metafile: { inputs: { [entryPoint]: {} } },
          };
        },
      }),
      log(line) { logs.push(line); },
    });
    assert.ok(logs.some((line) => line.includes(`${Buffer.byteLength(padding)} bytes`)));
    assert.ok(logs.every((line) => !/limit|ceiling|reviewed/u.test(line)));
  });
}

test("bundle-size targets retain declared module boundaries and browser graph guards", () => {
  assert.deepEqual(
    BUNDLE_TARGETS.map(({ label, lazyChunks, forbidNodeInputs, forbidGlobalBuffer }) => ({
      label,
      lazyChunks: (lazyChunks ?? []).map(
        ({ specifier, edgeCount }) => ({
          specifier,
          edgeCount,
        }),
      ),
      forbidNodeInputs: forbidNodeInputs === true,
      forbidGlobalBuffer: forbidGlobalBuffer === true,
    })),
    [
      {
        label: "toriiClient.js",
        lazyChunks: [
          {
            specifier: "./toriiOptional.js",
            edgeCount: 1,
          },
          {
            specifier: "./sumeragiTyped.js",
            edgeCount: 2,
          },
        ],
        forbidNodeInputs: false,
        forbidGlobalBuffer: false,
      },
      {
        label: "transactionCodec.js (browser)",
        lazyChunks: [],
        forbidNodeInputs: true,
        forbidGlobalBuffer: true,
      },
      {
        label: "nexusApp.js (browser)",
        lazyChunks: [],
        forbidNodeInputs: true,
        forbidGlobalBuffer: true,
      },
      {
        label: "canonicalRequest.js (browser)",
        lazyChunks: [],
        forbidNodeInputs: true,
        forbidGlobalBuffer: true,
      },
      {
        label: "ivmArtifact.js (browser)",
        lazyChunks: [],
        forbidNodeInputs: true,
        forbidGlobalBuffer: true,
      },
      {
        label: "kotodamaCompiler/browser.js (browser)",
        lazyChunks: [],
        forbidNodeInputs: true,
        forbidGlobalBuffer: true,
      },
      {
        label: "browser.js (public aggregate)",
        lazyChunks: [
          {
            specifier: "./sumeragiTyped.js",
            edgeCount: 2,
          },
          {
            specifier: "./smartContractDeploymentSubmit.js",
            edgeCount: 1,
          },
        ],
        forbidNodeInputs: true,
        forbidGlobalBuffer: true,
      },
    ],
  );
  for (const target of BUNDLE_TARGETS) {
    assert.equal(Object.hasOwn(target, "limitKb"), false);
    assert.equal(Object.hasOwn(target, "reviewedEagerBytes"), false);
    assert.equal(Object.hasOwn(target, "reviewedCombinedBytes"), false);
    for (const lazy of target.lazyChunks ?? []) {
      assert.equal(Object.hasOwn(lazy, "limitKb"), false);
      assert.equal(Object.hasOwn(lazy, "reviewedBytes"), false);
    }
  }
});

test("bundle-size check covers the browser transaction codec", () => {
  const target = BUNDLE_TARGETS.find(({ label }) => label.includes("transactionCodec"));
  assert.ok(target, "browser transaction-codec bundle target is required");
  assert.equal(target.platform, "browser");
  assert.match(target.entryPoint, /dist[/\\]transactionCodec\.js$/u);
});

test("bundle-size check proves the Nexus app export has a browser-only graph", () => {
  const target = BUNDLE_TARGETS.find(({ label }) => label.includes("nexusApp"));
  assert.ok(target, "browser Nexus app bundle target is required");
  assert.equal(target.platform, "browser");
  assert.match(target.entryPoint, /dist[/\\]nexusApp\.js$/u);
});

test("bundle-size check gates the complete public browser aggregate", () => {
  const target = BUNDLE_TARGETS.find(({ label }) => label.includes("public aggregate"));
  assert.ok(target, "public browser aggregate bundle target is required");
  assert.equal(target.platform, "browser");
  assert.match(target.entryPoint, /dist[/\\]browser\.js$/u);
  assert.equal(target.forbidNodeInputs, true);
  assert.match(target.lazyChunks[0].entryPoint, /dist[/\\]sumeragiTyped\.js$/u);
  assert.match(
    target.lazyChunks[1].entryPoint,
    /dist[/\\]smartContractDeploymentSubmit\.js$/u,
  );
});

test("bundle-size check gates canonical requests as a browser subpath", () => {
  const target = BUNDLE_TARGETS.find(({ label }) => label.includes("canonicalRequest"));
  assert.ok(target, "browser canonical-request bundle target is required");
  assert.equal(target.platform, "browser");
  assert.match(target.entryPoint, /dist[/\\]canonicalRequest\.js$/u);
  assert.equal(target.forbidNodeInputs, true);
});

test("bundle-size check gates the IVM artifact helper as a browser leaf", () => {
  const target = BUNDLE_TARGETS.find(({ label }) => label.includes("ivmArtifact"));
  assert.ok(target, "browser IVM artifact bundle target is required");
  assert.equal(target.platform, "browser");
  assert.match(target.entryPoint, /dist[/\\]ivmArtifact\.js$/u);
  assert.equal(target.forbidNodeInputs, true);
  assert.equal(target.forbidGlobalBuffer, true);
});

test("bundle-size check gates the remote Kotodama compiler browser export", () => {
  const target = BUNDLE_TARGETS.find(({ label }) =>
    label.includes("kotodamaCompiler/browser"),
  );
  assert.ok(target, "browser Kotodama compiler bundle target is required");
  assert.equal(target.platform, "browser");
  assert.match(target.entryPoint, /dist[/\\]kotodamaCompiler[/\\]browser\.js$/u);
  assert.equal(target.forbidNodeInputs, true);
  assert.equal(target.forbidGlobalBuffer, true);
});

test("browser graph guard detects every forbidden Node-only edge", () => {
  const candidates = [
    "node:crypto",
    "src/crypto.js",
    "dist/cryptoHash.js",
    "src/native.js",
    "dist/toriiClient.js",
    "/package/dist/crypto.js",
    "/package/dist/cryptoHash.js",
    "/package/dist/native.js",
    "/package/dist/toriiClient.js",
    "/package/dist/crypto.browser.js",
    "/package/dist/native.browser.js",
    "/package/dist/toriiBrowserClient.js",
  ];
  assert.deepEqual(findForbiddenBrowserInputs(candidates), candidates.slice(0, 9));
});

test("global Buffer guard rejects assignment and property-definition bypasses", () => {
  for (const source of [
    "globalThis.Buffer = value",
    "window.Buffer ||= value",
    "global['Buffer'] ??= value",
    "self[\"Buffer\"] &&= value",
    "globalThis.Buffer++",
    "--window['Buffer']",
    'Object.defineProperty(globalThis, "Buffer", { value })',
    "Reflect.defineProperty(window, 'Buffer', { value })",
    "Object.defineProperties(global, { Buffer: { value } })",
    "Object.assign(self, { Buffer: value })",
  ]) {
    assert.equal(hasForbiddenGlobalBufferMutation(source), true, source);
  }
  assert.equal(hasForbiddenGlobalBufferMutation("const Buffer = LocalBuffer"), false);
  assert.equal(hasForbiddenGlobalBufferMutation("delete globalThis.Buffer"), false);
});

test("browser graph audit derives every explicit browser-conditioned package export", async () => {
  const pkg = JSON.parse(
    await readFile(new URL("../package.json", import.meta.url), "utf8"),
  );
  assert.deepEqual(listExplicitBrowserExports(pkg), [
    { target: "./dist/nft.js", subpaths: ["./nft"] },
    { target: "./dist/public/address.js", subpaths: ["./address"] },
    { target: "./dist/browser.js", subpaths: ["./browser"] },
    {
      target: "./dist/privacyCapabilities.js",
      subpaths: ["./privacy-capabilities"],
    },
    {
      target: "./dist/bootleLanternIssuance.js",
      subpaths: ["./bootle-lantern-issuance"],
    },
    {
      target: "./dist/atomicPrivateSettlement.js",
      subpaths: ["./atomic-private-settlement"],
    },
    { target: "./dist/public/transactionCodec.js", subpaths: ["./transaction-codec"] },
    { target: "./dist/contractPayload.js", subpaths: ["./contract-payload"] },
    {
      target: "./dist/smartContractDeployment.js",
      subpaths: ["./smart-contract-deployment"],
    },
    { target: "./dist/public/normalizers.js", subpaths: ["./normalizers"] },
    { target: "./dist/blake2b.js", subpaths: ["./blake2b"] },
    { target: "./dist/ivmArtifact.js", subpaths: ["./ivm-artifact"] },
    {
      target: "./dist/toriiBrowserClient.js",
      subpaths: ["./torii-browser"],
    },
    { target: "./dist/sumeragiTyped.js", subpaths: ["./sumeragi-typed"] },
    { target: "./dist/canonicalRequest.js", subpaths: ["./canonical-request"] },
    { target: "./dist/public/crypto.browser.js", subpaths: ["./crypto"] },
    { target: "./dist/nexusApp.js", subpaths: ["./nexus-app"] },
    {
      target: "./dist/kotodamaCompiler/browser.js",
      subpaths: ["./kotodama-compiler"],
    },
    { target: "./dist/race.js", subpaths: ["./race"] },
    { target: "./dist/classedRace.js", subpaths: ["./classed-race"] },
    { target: "./dist/game.js", subpaths: ["./game"] },
    { target: "./dist/petal.js", subpaths: ["./petal"] },
  ]);
});

test("privacy policy stays out of base entry graphs and optional API stays client-agnostic", async () => {
  const { build } = await import("esbuild");
  const baseTargets = [
    BUNDLE_TARGETS.find(({ label }) => label === "toriiClient.js"),
    BUNDLE_TARGETS.find(({ label }) => label.includes("public aggregate")),
  ];
  for (const target of baseTargets) {
    assert.ok(target);
    const result = await build({
      entryPoints: [target.entryPoint],
      bundle: true,
      write: false,
      platform: target.platform,
      target: target.target,
      format: "esm",
      treeShaking: true,
      metafile: true,
    });
    const inputs = Object.keys(result.metafile?.inputs ?? {});
    assert.equal(
      inputs.some((input) => /[/\\]privacyCapabilities\.js$/u.test(input)),
      false,
      `${target.label} must not include the optional privacy policy parser`,
    );
  }

  const result = await build({
    entryPoints: [`${PACKAGE_ROOT}/dist/privacyCapabilities.js`],
    bundle: true,
    write: false,
    platform: "browser",
    target: "es2020",
    format: "esm",
    treeShaking: true,
    metafile: true,
  });
  const inputs = Object.keys(result.metafile?.inputs ?? {});
  assert.equal(
    inputs.some((input) => /[/\\]privacyCapabilities\.js$/u.test(input)),
    true,
  );
  assert.equal(
    inputs.some((input) => /[/\\]torii(?:Browser)?Client\.js$/u.test(input)),
    false,
    "optional privacy API must use the private transport capability without importing clients",
  );
});

test("browser graph audit catches Node edges in an export omitted from size budgets", async () => {
  await assert.rejects(
    runBundleSizeCheck({
      loadEsbuild: async () => ({
        async build(options) {
          const entryPoint = options.entryPoints[0];
          if (options.splitting === true) return fakeSplitBundle(options);
          return {
            outputFiles: [{ contents: new Uint8Array(), text: "" }],
            metafile: {
              inputs: entryPoint.endsWith("/dist/public/normalizers.js")
                ? { "node:fs": {} }
                : { [entryPoint]: {} },
            },
          };
        },
      }),
      log() {},
    }),
    /\.\/normalizers explicit browser export includes forbidden Node-only inputs: node:fs/u,
  );
});

test("browser runtime probe catches aliased global Buffer installation", async () => {
  await assert.rejects(
    runBundleSizeCheck({
      loadEsbuild: async () => ({
        async build(options) {
          const entryPoint = options.entryPoints[0];
          const installsBuffer = entryPoint.endsWith("/dist/browser.js");
          const text = installsBuffer
            ? "const root = globalThis; root.Buffer = class BufferShim {};"
            : "export {};";
          if (options.splitting === true) return fakeSplitBundle(options, text);
          return {
            outputFiles: [{ contents: new TextEncoder().encode(text), text }],
            metafile: { inputs: { [entryPoint]: {} } },
          };
        },
      }),
      log() {},
    }),
    /\.\/browser explicit browser export installs a forbidden global Buffer shim at runtime/u,
  );
});

test("split graph audit permits only the reviewed literal lazy edges", () => {
  const target = BUNDLE_TARGETS.find(({ label }) => label.includes("public aggregate"));
  assert.ok(target);
  const options = splitBuildOptions(target);
  const accepted = fakeSplitBundle(options);
  assert.deepEqual(
    analyzeSplitBundle(accepted, target).lazyChunks.map(
      ({ specifier, bytes }) => ({ specifier, bytes }),
    ),
    [
      { specifier: "./sumeragiTyped.js", bytes: 0 },
      { specifier: "./smartContractDeploymentSubmit.js", bytes: 0 },
    ],
  );

  const unexpected = fakeSplitBundle(options);
  unexpected.metafile.inputs["dist/browser.js"].imports.push({
    path: "dist/unreviewed.js",
    original: "./unreviewed.js",
    kind: "dynamic-import",
  });
  assert.throws(
    () => analyzeSplitBundle(unexpected, target),
    /unapproved local dynamic import \.\/unreviewed\.js/u,
  );

  const nonLiteral = fakeSplitBundle(options);
  delete nonLiteral.metafile.inputs["dist/browser.js"].imports[0].original;
  assert.throws(
    () => analyzeSplitBundle(nonLiteral, target),
    /unapproved local dynamic import dist\/sumeragiTyped\.js/u,
  );

  const reclassified = fakeSplitBundle(options);
  reclassified.metafile.inputs["dist/browser.js"].imports[0].kind =
    "import-statement";
  assert.throws(
    () => analyzeSplitBundle(reclassified, target),
    /reclassified \.\/sumeragiTyped\.js as import-statement/u,
  );
});

test("public browser aggregate audits eager, lazy, and unique combined closures", async () => {
  const target = BUNDLE_TARGETS.find(({ label }) => label.includes("public aggregate"));
  assert.ok(target);
  const { build } = await import("esbuild");
  const result = await build(splitBuildOptions(target));
  const metrics = analyzeSplitBundle(result, target);
  assert.deepEqual(
    findForbiddenBrowserInputs(Object.keys(result.metafile.inputs)),
    [],
  );
  // Exact observed closure includes event declarations, typed faults, durable
  // schemas, product identities, and the two shared Norito metadata/value owners.
  assert.equal(Object.keys(result.metafile.inputs).length, 120);
  assertSplitByteInventory(result, metrics);
  assert.deepEqual(metrics.lazyChunks.map(({ specifier }) => specifier), [
    "./sumeragiTyped.js",
    "./smartContractDeploymentSubmit.js",
  ]);
  for (const output of result.outputFiles) {
    assert.doesNotMatch(
      output.text,
      /(?:globalThis|window|global)\.Buffer\s*=/u,
    );
  }
});

test("IVM artifact browser leaf excludes Node and Buffer shims", async () => {
  const target = BUNDLE_TARGETS.find(({ label }) => label.includes("ivmArtifact"));
  assert.ok(target);
  const { build } = await import("esbuild");
  const result = await build({
    entryPoints: [target.entryPoint],
    bundle: true,
    write: false,
    platform: "browser",
    target: target.target,
    format: "esm",
    treeShaking: true,
    sourcemap: false,
    minify: true,
    metafile: true,
  });
  assert.deepEqual(
    findForbiddenBrowserInputs(Object.keys(result.metafile.inputs)),
    [],
  );
  assert.equal(Object.keys(result.metafile.inputs).length, 7);
  assert.doesNotMatch(
    result.outputFiles[0].text,
    /(?:globalThis|window|global)\.Buffer\s*=/u,
  );
});

test("bundle targets retain canonical module ownership and accurate byte inventories", async () => {
  const expected = new Map([
    ["toriiClient.js", { modules: 140 }],
    ["transactionCodec.js (browser)", { modules: 70 }],
    ["nexusApp.js (browser)", { modules: 79 }],
    ["canonicalRequest.js (browser)", { modules: 47 }],
  ]);
  const { build } = await import("esbuild");
  for (const target of BUNDLE_TARGETS.filter(({ label }) => expected.has(label))) {
    const split = (target.lazyChunks?.length ?? 0) > 0;
    const result = await build(
      split
        ? splitBuildOptions(target)
        : {
            entryPoints: [target.entryPoint],
            bundle: true,
            write: false,
            platform: target.platform,
            target: target.target,
            format: "esm",
            treeShaking: true,
            sourcemap: false,
            minify: true,
            metafile: true,
          },
    );
    const splitMetrics = split ? analyzeSplitBundle(result, target) : undefined;
    const actual = {
      modules: Object.keys(result.metafile.inputs).length,
    };
    if ([
      "toriiClient.js",
      "transactionCodec.js (browser)",
      "nexusApp.js (browser)",
    ].includes(target.label)) {
      assert.equal(
        Object.keys(result.metafile.inputs).filter((input) =>
          /(?:^|[/\\])proofAttachment\.js$/u.test(input),
        ).length,
        1,
        `${target.label} must retain exactly one canonical ProofAttachment module`,
      );
      assert.equal(
        Object.keys(result.metafile.inputs).filter((input) =>
          /(?:^|[/\\])retailFeeAssessment\.js$/u.test(input),
        ).length,
        1,
        `${target.label} must retain exactly one retail fee assessment validator`,
      );
    }
    if (target.label === "toriiClient.js") {
      const replicationInput = Object.keys(result.metafile.inputs).filter((input) =>
        /(?:^|[/\\])sorafsReplicationResponses\.js$/u.test(input),
      );
      assert.equal(replicationInput.length, 1, "replication responses retain one owner");
      const includesReplication = (outputs) => outputs.some((output) =>
        Object.hasOwn(result.metafile.outputs[output].inputs, replicationInput[0]),
      );
      assert.equal(includesReplication(splitMetrics.eagerOutputs), false,
        "replication response validation must remain outside the eager Torii graph");
      const optional = splitMetrics.lazyChunks.find(({ specifier }) =>
        specifier === "./toriiOptional.js");
      assert.ok(optional, "the existing optional closure must remain audited");
      assert.equal(includesReplication(optional.outputs), true,
        "replication responses belong to the existing audited optional closure");
      assert.equal(
        Object.keys(result.metafile.inputs).some(
          (input) =>
            input.includes("@noble/curves") && input.includes("bls12-381"),
        ),
        false,
        "Torii must use the local synchronous BLS validator, not bundle noble's full curve implementation",
      );
      assertSplitByteInventory(result, splitMetrics);
      assert.deepEqual(
        splitMetrics.lazyChunks.map(({ specifier }) => specifier),
        ["./toriiOptional.js", "./sumeragiTyped.js"],
      );
    }
    assert.deepEqual(actual, expected.get(target.label), target.label);

  }
});

test("Kotodama compiler browser export excludes Node and Buffer shims", async () => {
  const target = BUNDLE_TARGETS.find(({ label }) =>
    label.includes("kotodamaCompiler/browser"),
  );
  assert.ok(target);
  const { build } = await import("esbuild");
  const result = await build({
    entryPoints: [target.entryPoint],
    bundle: true,
    write: false,
    platform: "browser",
    target: target.target,
    format: "esm",
    treeShaking: true,
    sourcemap: false,
    minify: true,
    metafile: true,
  });
  assert.deepEqual(
    findForbiddenBrowserInputs(Object.keys(result.metafile.inputs)),
    [],
  );
  const inputs = Object.keys(result.metafile.inputs);
  // Exact CNTR comparison includes trigger AccountIds, JSON metadata, and frame
  // validation. Those canonical value codecs are shared with manifest encoding.
  assert.equal(inputs.length, 55);
  for (const owner of [
    "noritoContractMetadata.js", "noritoValueCodecs.js", "noritoContractCodecs.js",
    "entrypointSchema.js", "contractDeclarations.js", "embeddedStateSchema.js",
  ]) {
    assert.equal(inputs.filter((input) => input.endsWith(`/${owner}`)).length, 1,
      `compiler must retain exactly one ${owner} owner`);
  }
  for (const unrelated of [
    "norito.js", "blockProofVerification.js", "noritoGameCodecs.js",
    "noritoGameEngine.js", "noritoGameInstructionCodecs.js", "noritoGameRegistry.js",
    "noritoGameResourceEngine.js", "noritoNftMarketCodecs.js",
    "noritoReplicationOrderValidator.js", "noritoStakingCodecs.js",
    "privacyExact12Network.js", "proofAttachment.js", "retailFeeAssessment.js",
    "sorafsReplicationProfiles.js",
  ]) {
    assert.equal(inputs.some((input) => input.endsWith(`/${unrelated}`)), false,
      `compiler metadata must not pull the unrelated ${unrelated} codec`);
  }
  assert.doesNotMatch(
    result.outputFiles[0].text,
    /(?:globalThis|window|global)\.Buffer\s*=/u,
  );
});
