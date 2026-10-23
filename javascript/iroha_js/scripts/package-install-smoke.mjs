#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  acquireDistLock,
  buildDistribution,
  directoryDigest,
  releaseDistLock,
  validateDistOutputs,
} from "./build-dist.mjs";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const SCRIPT_DIR = resolve(SCRIPT_PATH, "..");
const ROOT = resolve(SCRIPT_DIR, "..");
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const ALLOWED_RECIPE_PATHS = new Set([
  "recipes/iso_bridge_builder.mjs",
  "recipes/iso_bridge_context.mjs",
  "recipes/nexus_app_transfer.mjs",
  "recipes/README.md",
]);

function run(command, args, options = {}) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env ?? process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.once("error", rejectRun);
    child.once("close", (code, signal) => {
      const output = Buffer.concat(stdout).toString("utf8");
      const errors = Buffer.concat(stderr).toString("utf8");
      if (code !== 0 || signal !== null) {
        rejectRun(
          new Error(
            `${command} ${args.join(" ")} failed with code=${code} signal=${signal}:\n${output}\n${errors}`,
          ),
        );
        return;
      }
      resolveRun({ stdout: output, stderr: errors });
    });
  });
}

function parsePackMetadata(stdout) {
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch (error) {
    throw new Error(`package smoke could not parse npm pack metadata: ${error.message}`);
  }
  const metadata = Array.isArray(parsed) ? parsed.at(-1) : parsed;
  if (!metadata?.filename || !Array.isArray(metadata.files)) {
    throw new Error("package smoke received incomplete npm pack metadata");
  }
  return metadata;
}

export function validatePackPaths(metadata) {
  const paths = new Set();
  for (const entry of metadata.files) {
    const path = entry?.path;
    if (
      typeof path !== "string" ||
      path.length === 0 ||
      isAbsolute(path) ||
      path.split(/[\\/]/u).includes("..") ||
      path.includes("\0")
    ) {
      throw new Error(`package smoke rejected unsafe tar entry: ${String(path)}`);
    }
    paths.add(path.replaceAll("\\", "/"));
  }
  for (const required of [
    "package.json",
    "atomic-private-settlement.d.ts",
    "index.d.ts",
    "ivm-artifact.d.ts",
    "kotodama-compiler.d.ts",
    "privacy-capabilities.d.ts",
    "repo-agreement.d.ts",
    "sumeragi-typed.d.ts",
    "dist/index.js",
    "dist/atomicPrivateSettlement.js",
    "dist/ivmArtifact.js",
    "dist/kotodamaCompiler/browser.js",
    "dist/kotodamaCompiler/index.js",
    "dist/nexusApp.js",
    "dist/privacyCapabilities.js",
    "dist/boundedByteSnapshot.js",
    "dist/validationFeeTrust.js",
    "dist/sorafsOrderbookPreflight.js",
    "dist/sorafsOrderbookSubmission.js",
    "dist/sorafsOrderbookSubmission.d.ts",
    "dist/smartContractDeploymentSubmit.js",
    "dist/sumeragiTyped.js",
    "dist/tairaTestnetProfile.js",
    "nexus-app.d.ts",
    "recipes/iso_bridge_builder.mjs",
    "recipes/iso_bridge_context.mjs",
    "recipes/nexus_app_transfer.mjs",
  ]) {
    if (!paths.has(required)) {
      throw new Error(`package smoke missing required tar entry: ${required}`);
    }
  }
  for (const path of paths) {
    if (/(?:^|\/)wasm(?:\/|$)|\.wasm$/iu.test(path)
      || /(?:^|\/)(?:browserCodec(?:Runtime)?\.js|browser-codec\.d\.ts)$/u.test(path)) {
      throw new Error(`package smoke found forbidden browser codec artifact: ${path}`);
    }
    if (path.startsWith("src/") || path.startsWith("scripts/")) {
      throw new Error(`package smoke found unpublished development path: ${path}`);
    }
    if (path.startsWith("recipes/") && !ALLOWED_RECIPE_PATHS.has(path)) {
      throw new Error(`package smoke found forbidden non-portable recipe: ${path}`);
    }
  }
}

async function main() {
  const tempRoot = mkdtempSync(join(tmpdir(), "iroha-js-package-install-"));
  try {
    await buildDistribution({ root: ROOT });

    let packMetadata;
    let tarball;
    const readerLock = await acquireDistLock({ root: ROOT });
    try {
      const src = join(ROOT, "src");
      const dist = join(ROOT, "dist");
      validateDistOutputs(dist);
      const sourceDigest = directoryDigest(src);
      const distDigest = directoryDigest(dist);
      if (sourceDigest !== distDigest) {
        throw new Error(
          `package smoke requires exact src/dist parity (${sourceDigest} != ${distDigest})`,
        );
      }

      const packed = await run(
        npmCommand,
        ["pack", "--ignore-scripts", "--json", "--pack-destination", tempRoot],
        { cwd: ROOT },
      );
      packMetadata = parsePackMetadata(packed.stdout);
      validatePackPaths(packMetadata);
      tarball = join(tempRoot, packMetadata.filename);
    } finally {
      releaseDistLock(readerLock);
    }

    const consumerRoot = join(tempRoot, "consumer");
    mkdirSync(consumerRoot, { recursive: true });
    writeFileSync(
      join(consumerRoot, "package.json"),
      `${JSON.stringify({ private: true, type: "module" })}\n`,
      "utf8",
    );
    await run(
      npmCommand,
      [
        "install",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--no-package-lock",
        "--omit=dev",
        tarball,
      ],
      {
        cwd: consumerRoot,
        env: { ...process.env, npm_config_ignore_scripts: "true" },
      },
    );

    const smokeProgram = [
      'import * as sdk from "@iroha/iroha-js";',
      'import * as canonical from "@iroha/iroha-js/canonical-request";',
      'import * as artifact from "@iroha/iroha-js/ivm-artifact";',
      'import * as codec from "@iroha/iroha-js/transaction-codec";',
      'import * as nexus from "@iroha/iroha-js/nexus-app";',
      'import * as compiler from "@iroha/iroha-js/kotodama-compiler";',
      'import * as privacy from "@iroha/iroha-js/privacy-capabilities";',
      'import * as sumeragi from "@iroha/iroha-js/sumeragi-typed";',
      "const checks = [",
      '  ["AccountAddress", sdk.AccountAddress],',
      '  ["ToriiClient", sdk.ToriiClient],',
      '  ["createTairaLocalSigningContext", sdk.createTairaLocalSigningContext],',
      '  ["computeIvmArtifactHashes", artifact.computeIvmArtifactHashes],',
      '  ["buildCanonicalRequestHeaders", canonical.buildCanonicalRequestHeaders],',
      '  ["buildBrowserTransferPayload", codec.buildBrowserTransferPayload],',
      '  ["NexusAppClient", nexus.NexusAppClient],',
      '  ["KotodamaCompilerClient", compiler.KotodamaCompilerClient],',
      '  ["decodePrivacyExact12CapabilityManifestV1", privacy.decodePrivacyExact12CapabilityManifestV1],',
      '  ["getPrivacyExact12CapabilityManifestV1", privacy.getPrivacyExact12CapabilityManifestV1],',
      '  ["parseSumeragiStatusPayload", sumeragi.parseSumeragiStatusPayload],',
      "];",
      "for (const [name, value] of checks) {",
      '  if (typeof value !== "function") throw new Error(`missing packed export: ${name}`);',
      "}",
      'if (JSON.stringify(sdk.supportedCryptoAlgorithms()) !== JSON.stringify(["ed25519"])) {',
      '  throw new Error("clean packed install must advertise only portable Ed25519");',
      "}",
      "try {",
      '  sdk.generateKeyPair({ algorithm: "sm2" });',
      '  throw new Error("native-only crypto unexpectedly succeeded");',
      "} catch (error) {",
      '  if (error?.code !== "ERR_IROHA_NATIVE_BINDING" || !String(error.message).includes("IROHA_JS_NATIVE_DIR")) {',
      '    throw new Error(`packed native setup error is not actionable: ${error?.message ?? error}`);',
      "  }",
      "}",
      'if (!Object.isFrozen(sdk.TAIRA_TESTNET_PROFILE) ||',
      '    sdk.TAIRA_TESTNET_PROFILE.toriiBaseUrl !== "https://taira.sora.org" ||',
      '    sdk.TAIRA_TESTNET_PROFILE.dsAssetDefinitionId !== "7ZepsJTHCVLKsrFFNZGSRGZgvBhv" ||',
      '    sdk.TAIRA_TESTNET_PROFILE.dsAssetAlias !== "ds#boi.is" ||',
      '    sdk.TAIRA_TESTNET_PROFILE.dsAssetScale !== 2) {',
      '  throw new Error("packed Taira profile is missing or invalid");',
      "}",
      'const tairaNetworkId = sdk.NetworkId.parse("hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0");',
      "const tairaSigningContext = sdk.createTairaLocalSigningContext(tairaNetworkId);",
      "if (tairaSigningContext.networkId !== tairaNetworkId || tairaSigningContext.chainDiscriminant !== 369) {",
      '  throw new Error("packed Taira signing context does not preserve the deployed NetworkId");',
      "}",
      "if (sdk.computeIvmArtifactHashes !== artifact.computeIvmArtifactHashes) {",
      '  throw new Error("root and ivm-artifact subpath exports differ");',
      "}",
      'for (const name of ["getPrivacyCapabilitiesV1", "parsePrivacyCapabilitySnapshotV1", "decodePrivacyExact12CapabilityManifestV1", "getPrivacyExact12CapabilityManifestV1"]) {',
      '  if (Object.hasOwn(sdk, name)) throw new Error(`root leaks optional privacy export: ${name}`);',
      "}",
      'if (Object.hasOwn(sdk.ToriiClient.prototype, "getPrivacyCapabilitiesV1") ||',
      '    Object.hasOwn(sdk.ToriiBrowserClient.prototype, "getPrivacyCapabilitiesV1")) {',
      '  throw new Error("base clients leak optional privacy policy methods");',
      "}",
    ].join("\n");
    await run(process.execPath, ["--input-type=module", "--eval", smokeProgram], {
      cwd: consumerRoot,
      env: {
        ...process.env,
        IROHA_JS_NATIVE_DIR: join(tempRoot, "missing-native"),
      },
    });
    await run(
      process.execPath,
      [
        "--conditions=browser",
        "--input-type=module",
        "--eval",
        [
          'import { compileKotodamaProgram, KotodamaCompilerClient } from "@iroha/iroha-js/kotodama-compiler";',
          'if (typeof compileKotodamaProgram !== "function" || typeof KotodamaCompilerClient !== "function") {',
          '  throw new Error("missing browser-conditioned Kotodama compiler exports");',
          "}",
        ].join("\n"),
      ],
      { cwd: consumerRoot },
    );

    const installedRecipe = join(
      consumerRoot,
      "node_modules",
      "@iroha",
      "iroha-js",
      "recipes",
      "nexus_app_transfer.mjs",
    );
    // This portable installation has no platform binding. The source native
    // suite checks the complete recipe and exact payload/transaction goldens.
    // Here approval must fail before requesting a signature or submitting.
    const recipe = await run(process.execPath, [
      "--input-type=module",
      "--eval",
      [
        'import assert from "node:assert/strict";',
        'import { pathToFileURL } from "node:url";',
        'await assert.rejects(() => import(pathToFileURL(process.argv[1]).href), (error) => {',
        '  assert.equal(error.phase, "validation");',
        '  assert.equal(error.submissionState, "not_submitted");',
        '  assert.equal(error.cause?.code, "ERR_IROHA_NATIVE_BINDING");',
        '  assert.equal(error.cause?.nativeStatus, "missing_file");',
        '  return true;',
        '});',
      ].join("\n"),
      installedRecipe,
    ], {
      cwd: consumerRoot,
      env: {
        ...process.env,
        IROHA_JS_NATIVE_DIR: join(tempRoot, "missing-native"),
      },
    });
    if (/payload hash:|signed transaction hash:|final status:/u.test(recipe.stdout)) {
      throw new Error("packed Nexus recipe progressed without its required native binding");
    }

    const installedIsoBuilderRecipe = join(
      consumerRoot,
      "node_modules",
      "@iroha",
      "iroha-js",
      "recipes",
      "iso_bridge_builder.mjs",
    );
    const isoBuilder = await run(process.execPath, [installedIsoBuilderRecipe], {
      cwd: consumerRoot,
      env: {
        ...process.env,
        ISO_MESSAGE_ID: "package-smoke-message",
        ISO_CREATION_TIME: "2026-01-01T00:00:00.000Z",
        ISO_INSTRUCTION_ID: "package-smoke-instruction",
        ISO_BUILDER_CONFIG: "",
        ISO_SUBMIT: "0",
        ISO_DRY_RUN: "1",
        ISO_UETR: "123e4567-e89b-42d3-a456-426614174000",
        ISO_NETWORK_ID: "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0",
        ISO_EXPIRES_AT_HEIGHT: "100",
        ISO_SOURCE_ACCOUNT_ID: "sorauﾛ1P5ﾁXEｴﾕGjgﾕﾚﾎﾕｸﾁEtﾀ3ﾂｺ2gALｺﾒefﾍ8DLgｾoCVGUYHS5",
        ISO_TARGET_ACCOUNT_ID: "sorauﾛ1PﾜdﾎｼﾋﾉNｸdﾁﾑkiﾇ3ｵﾓaPBQDTｲKqｼqｵrﾗｶwSQ1ﾌﾅQU61Y7",
        ISO_ASSET_DEFINITION_ID: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
      },
    });
    for (const expected of [
      "<MsgId>package-smoke-message</MsgId>",
      "<InstrId>package-smoke-instruction</InstrId>",
      '<IntrBkSttlmAmt Ccy="EUR">100.00</IntrBkSttlmAmt>',
      "<UETR>123e4567-e89b-42d3-a456-426614174000</UETR>",
      "sorauﾛ1P5ﾁXEｴﾕGjgﾕﾚﾎﾕｸﾁEtﾀ3ﾂｺ2gALｺﾒefﾍ8DLgｾoCVGUYHS5",
      "sorauﾛ1PﾜdﾎｼﾋﾉNｸdﾁﾑkiﾇ3ｵﾓaPBQDTｲKqｼqｵrﾗｶwSQ1ﾌﾅQU61Y7",
      "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
    ]) {
      if (!isoBuilder.stdout.includes(expected)) {
        throw new Error(`packed ISO builder recipe output is missing: ${expected}`);
      }
    }

    if (process.argv.includes("--native-wallet")) {
      // Portable smoke above is unchanged. This additional installed-native lane
      // uses the supported external binding directory and retains clean-source
      // provenance; a dirty local-debug addon cannot be relabelled for packaging.
      if (process.env.NODE_OPTIONS || process.env.IROHA_JS_NATIVE_DIR) {
        throw new Error("installed wallet qualification requires an unoverridden native loader");
      }
      const originalNative = join(ROOT, "native", "iroha_js_host.node");
      const originalManifest = join(ROOT, "native", "iroha_js_host.checksums.json");
      const digest = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
      const nativeHash = digest(originalNative);
      const manifestHash = digest(originalManifest);
      const manifest = JSON.parse(readFileSync(originalManifest, "utf8"));
      const entry = manifest.entries?.[`${process.platform}-${process.arch}`];
      if (entry?.source_tree_clean !== true || entry?.sha256 !== nativeHash) {
        throw new Error("installed native wallet requires the normally rebuilt clean-source addon and exact checksum manifest");
      }
      const nativeDirectory = join(tempRoot, "authenticated-native");
      mkdirSync(nativeDirectory, { mode: 0o700 });
      copyFileSync(originalNative, join(nativeDirectory, "iroha_js_host.node"));
      copyFileSync(originalManifest, join(nativeDirectory, "iroha_js_host.checksums.json"));
      const consumer = join(consumerRoot, "wallet-consumer.mjs");
      copyFileSync(join(ROOT, "test/fixtures/installedConfidentialWallet.mjs"), consumer);
      copyFileSync(join(ROOT, "test/helpers/confidentialWalletNativeCases.js"), join(consumerRoot, "wallet-cases.mjs"));
      const wallet = await run(process.execPath, [consumer, nativeHash, manifestHash], {
        cwd: consumerRoot,
        env: { ...process.env, IROHA_JS_NATIVE_DIR: nativeDirectory },
      });
      const receipt = JSON.parse(wallet.stdout.trim());
      if (receipt.kind !== "installed-confidential-wallet" || receipt.passed !== 2 ||
          receipt.failed !== 0 || receipt.skipped !== 0 ||
          receipt.nativeSha256 !== nativeHash || receipt.loadedImageSha256 !== nativeHash ||
          receipt.nativeManifestSha256 !== manifestHash ||
          digest(originalNative) !== nativeHash || digest(originalManifest) !== manifestHash ||
          digest(join(nativeDirectory, "iroha_js_host.node")) !== nativeHash ||
          digest(join(nativeDirectory, "iroha_js_host.checksums.json")) !== manifestHash) {
        throw new Error("installed native wallet qualification lost its exact artifact binding");
      }
      console.log(JSON.stringify({ ...receipt, tarballSha256: digest(tarball),
        sourceGitRevision: entry.source_git_revision, sourceTreeSha256: entry.source_tree_sha256 }));
    }

    const packageJson = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
    if (packMetadata.name !== packageJson.name || packMetadata.version !== packageJson.version) {
      throw new Error("package smoke metadata does not match package.json identity");
    }
    console.log(
      `[package-smoke] ${packMetadata.name}@${packMetadata.version}: ${packMetadata.entryCount} files, clean install/import passed`,
    );
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === SCRIPT_PATH) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
