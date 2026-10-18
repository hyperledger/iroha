// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { spawnSync } from "node:child_process";
import { webcrypto } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";

import {
  findForbiddenBrowserInputs,
} from "../scripts/bundle-size-check.mjs";
import {
  publicKeyFromPrivate,
  verifyEd25519,
} from "../src/crypto.browser.js";

function withGlobalCrypto(value, action) {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    enumerable: descriptor?.enumerable ?? true,
    value,
    writable: true,
  });
  return Promise.resolve()
    .then(action)
    .finally(() => {
      if (descriptor) {
        Object.defineProperty(globalThis, "crypto", descriptor);
      } else {
        delete globalThis.crypto;
      }
    });
}

test("packed canonical-request subpath executes securely and has strict DOM types", async () => {
  const packageRoot = fileURLToPath(new URL("..", import.meta.url));
  const tempRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "iroha-js-canonical-request-browser-"),
  );
  try {
    const packed = spawnSync(
      "npm",
      ["pack", "--ignore-scripts", "--json", "--pack-destination", tempRoot],
      { cwd: packageRoot, encoding: "utf8" },
    );
    assert.equal(
      packed.status,
      0,
      `npm pack failed:\n${packed.stdout}\n${packed.stderr}`,
    );
    const packResult = JSON.parse(packed.stdout);
    const extracted = spawnSync(
      "tar",
      ["-xzf", path.join(tempRoot, packResult[0].filename), "-C", tempRoot],
      { encoding: "utf8" },
    );
    assert.equal(
      extracted.status,
      0,
      `tar extraction failed:\n${extracted.stdout}\n${extracted.stderr}`,
    );
    const packagePath = path.join(
      tempRoot,
      "node_modules",
      "@iroha",
      "iroha-js",
    );
    fs.mkdirSync(path.dirname(packagePath), { recursive: true });
    fs.renameSync(path.join(tempRoot, "package"), packagePath);
    const entryPoint = path.join(tempRoot, "consumer.mjs");
    fs.writeFileSync(
      entryPoint,
      [
        'export * from "@iroha/iroha-js/canonical-request";',
      ].join("\n"),
      "utf8",
    );

    const result = await build({
      entryPoints: [entryPoint],
      absWorkingDir: tempRoot,
      nodePaths: [path.join(packageRoot, "node_modules")],
      bundle: true,
      write: false,
      platform: "browser",
      target: "es2020",
      format: "esm",
      treeShaking: true,
      sourcemap: false,
      minify: true,
      metafile: true,
    });
    const inputs = Object.keys(result.metafile.inputs);
    assert.deepEqual(findForbiddenBrowserInputs(inputs), []);
    assert.ok(inputs.some((input) => /dist[/\\]canonicalRequest\.js$/u.test(input)));
    assert.ok(inputs.some((input) => /dist[/\\]cryptoHash\.browser\.js$/u.test(input)));
    assert.ok(inputs.some((input) => /dist[/\\]crypto\.browser\.js$/u.test(input)));
    assert.equal(
      inputs.some((input) => /dist[/\\]cryptoHash\.js$/u.test(input)),
      false,
    );
    assert.doesNotMatch(
      result.outputFiles[0].text,
      /(?:globalThis|window|global)\.Buffer\s*=/u,
    );

    const entropyCalls = [];
    const bundleUrl = `data:text/javascript;base64,${Buffer.from(
      result.outputFiles[0].contents,
    ).toString("base64")}`;
    const canonicalRequest = await withGlobalCrypto(
      {
        getRandomValues(view) {
          entropyCalls.push(view.byteLength);
          return webcrypto.getRandomValues(view);
        },
      },
      () => import(bundleUrl),
    );
    const privateKey = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
    const timestampMs = 1_700_000_000_123;
    const method = "POST";
    const requestPath = "/v1/aliases/resolve";
    const body = '{"alias":"tidal-river-4160@mibank.paynet"}';
    const networkId = canonicalRequest.NetworkId.fromBytes(
      Uint8Array.from({ length: 32 }, () => 0xa5),
    );
    const headers = await withGlobalCrypto(
      {
        getRandomValues(view) {
          entropyCalls.push(view.byteLength);
          return webcrypto.getRandomValues(view);
        },
      },
      () =>
        canonicalRequest.buildCanonicalRequestHeaders({
          accountId: "operator@wonderland",
          networkId,
          method,
          path: requestPath,
          body,
          privateKey,
          timestampMs,
        }),
    );
    assert.deepEqual(entropyCalls, [16]);
    assert.match(headers["X-Iroha-Nonce"], /^[0-9a-f]{32}$/u);
    assert.equal(headers["X-Iroha-Timestamp-Ms"], String(timestampMs));
    const message = canonicalRequest.canonicalRequestSignatureMessage({
      networkId,
      method,
      path: requestPath,
      body,
      timestampMs,
      nonce: headers["X-Iroha-Nonce"],
    });
    assert.equal(
      verifyEd25519(
        message,
        Buffer.from(headers["X-Iroha-Signature"], "base64"),
        publicKeyFromPrivate(privateKey),
      ),
      true,
      "packed browser Ed25519 signature must verify over the exact canonical message",
    );

    const packageJson = JSON.parse(
      fs.readFileSync(path.join(packagePath, "package.json"), "utf8"),
    );
    assert.equal(
      packageJson.exports["./canonical-request"].types,
      "./canonical-request.d.ts",
    );
    assert.deepEqual(packageJson.typesVersions["*"]["canonical-request"], [
      "./canonical-request.d.ts",
    ]);
    assert.ok(packageJson.files.includes("canonical-request.d.ts"));
    const declarations = fs.readFileSync(
      path.join(packagePath, "canonical-request.d.ts"),
      "utf8",
    );
    assert.match(declarations, /import type \{ Buffer \} from "buffer";/u);
    assert.doesNotMatch(declarations, /reference types=["']node|from ["']node:/u);

    const nodeModules = path.join(tempRoot, "node_modules");
    fs.symlinkSync(
      path.join(packageRoot, "node_modules", "buffer"),
      path.join(nodeModules, "buffer"),
      "dir",
    );
    assert.equal(
      fs.existsSync(path.join(nodeModules, "@types", "node")),
      false,
      "the packed strict-DOM proof must not resolve ambient Node declarations",
    );
    fs.writeFileSync(
      path.join(tempRoot, "consumer.ts"),
      [
        "import {",
        "  buildCanonicalJsonRequest,",
        "  buildCanonicalRequestHeaders,",
        "  canonicalQueryString,",
        "  canonicalRequestMessage,",
        "  canonicalRequestSignatureMessage,",
        "  withCanonicalReadRetry,",
        "  NetworkId,",
        '  type CanonicalJsonRequest,',
        '  type CanonicalJsonRequestSignerInput,',
        '  type CanonicalRequestHeaders,',
        '} from "@iroha/iroha-js/canonical-request";',
        "const query: string = canonicalQueryString(new URLSearchParams([[\"b\", \"2\"], [\"a\", \"1\"]]));",
        "const base: Uint8Array = canonicalRequestMessage({ method: \"POST\", path: \"/v1\", query, body: new Uint8Array() });",
        "const networkId = NetworkId.fromBytes(Uint8Array.from({ length: 32 }, () => 0xa5));",
        "const signed: Uint8Array = canonicalRequestSignatureMessage({ networkId, method: \"POST\", path: \"/v1\", timestampMs: 1, nonce: \"nonce\" });",
        "const headers: CanonicalRequestHeaders = buildCanonicalRequestHeaders({ accountId: \"a@b\", networkId, method: \"POST\", path: \"/v1\", privateKey: new Uint8Array(32) });",
        "const request: Promise<CanonicalJsonRequest> = buildCanonicalJsonRequest({",
        "  accountId: \"a@b\", networkId, path: \"/v1\", headers: new Headers(),",
        "  sign(input: CanonicalJsonRequestSignerInput): Uint8Array {",
        "    const message: Uint8Array = input.message;",
        "    void message;",
        "    return new Uint8Array(64);",
        "  },",
        "});",
        "const retried: Promise<string> = withCanonicalReadRetry({ method: \"POST\", path: \"/v1/multisig/spec\", signal: new AbortController().signal, operation: (attempt: number) => String(attempt) });",
        "void query; void base; void signed; void headers; void request; void retried;",
      ].join("\n"),
      "utf8",
    );
    fs.writeFileSync(
      path.join(tempRoot, "tsconfig.json"),
      JSON.stringify(
        {
          compilerOptions: {
            strict: true,
            exactOptionalPropertyTypes: true,
            noUncheckedIndexedAccess: true,
            target: "ES2022",
            module: "NodeNext",
            moduleResolution: "NodeNext",
            lib: ["ES2022", "DOM"],
            types: [],
            noEmit: true,
          },
          files: ["consumer.ts"],
        },
        null,
        2,
      ),
      "utf8",
    );
    const tsc = fileURLToPath(
      new URL("../node_modules/typescript/bin/tsc", import.meta.url),
    );
    const compiled = spawnSync(process.execPath, [tsc, "-p", "tsconfig.json"], {
      cwd: tempRoot,
      encoding: "utf8",
    });
    assert.equal(
      compiled.status,
      0,
      `packed canonical-request strict-DOM compile failed:\n${compiled.stdout}\n${compiled.stderr}`,
    );
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});
