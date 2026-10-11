import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import ts from "typescript";

import { validatePackPaths } from "../scripts/package-install-smoke.mjs";

const PACKAGE_ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const TSC = fileURLToPath(
  new URL("../node_modules/typescript/bin/tsc", import.meta.url),
);
const PACKAGE_NAME = "@iroha/iroha-js";
const PORTABLE_RECIPES = [
  "recipes/iso_bridge_builder.mjs",
  "recipes/nexus_app_transfer.mjs",
];

function readPackageJson() {
  return JSON.parse(
    fs.readFileSync(path.join(PACKAGE_ROOT, "package.json"), "utf8"),
  );
}

function assertSafePackageTarget(target, context) {
  assert.equal(typeof target, "string", `${context} must be a string`);
  assert.match(target, /^\.\/[A-Za-z0-9._/-]+$/u, `${context} is unsafe`);
  assert.equal(target.includes(".."), false, `${context} traverses the package`);
  const absolute = path.resolve(PACKAGE_ROOT, target);
  assert.equal(
    absolute.startsWith(`${PACKAGE_ROOT}${path.sep}`),
    true,
    `${context} escapes the package`,
  );
  assert.equal(fs.statSync(absolute).isFile(), true, `${context} is not a file`);
}

function createPackedLayout({ includeNodeTypes }) {
  const tempRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "iroha-js-packed-types-"),
  );
  const nodeModules = path.join(tempRoot, "node_modules");
  const packagePath = path.join(nodeModules, "@iroha", "iroha-js");
  fs.mkdirSync(packagePath, { recursive: true });
  fs.copyFileSync(
    path.join(PACKAGE_ROOT, "package.json"),
    path.join(packagePath, "package.json"),
  );
  for (const entry of fs.readdirSync(PACKAGE_ROOT, { withFileTypes: true })) {
    if (entry.isFile() && entry.name.endsWith(".d.ts")) {
      fs.copyFileSync(
        path.join(PACKAGE_ROOT, entry.name),
        path.join(packagePath, entry.name),
      );
    }
  }
  fs.cpSync(path.join(PACKAGE_ROOT, "dist"), path.join(packagePath, "dist"), {
    recursive: true,
  });
  fs.symlinkSync(
    path.join(PACKAGE_ROOT, "node_modules", "buffer"),
    path.join(nodeModules, "buffer"),
    "dir",
  );
  if (includeNodeTypes) {
    const atTypes = path.join(nodeModules, "@types");
    fs.mkdirSync(atTypes, { recursive: true });
    fs.symlinkSync(
      path.join(PACKAGE_ROOT, "node_modules", "@types", "node"),
      path.join(atTypes, "node"),
      "dir",
    );
    fs.symlinkSync(
      path.join(PACKAGE_ROOT, "node_modules", "undici-types"),
      path.join(nodeModules, "undici-types"),
      "dir",
    );
  }
  fs.writeFileSync(
    path.join(tempRoot, "package.json"),
    `${JSON.stringify({ private: true, type: "module" })}\n`,
    "utf8",
  );
  return { tempRoot, packagePath };
}

function compileFixture(tempRoot, tsconfig) {
  fs.writeFileSync(
    path.join(tempRoot, "tsconfig.json"),
    `${JSON.stringify(tsconfig, null, 2)}\n`,
    "utf8",
  );
  return spawnSync(process.execPath, [TSC, "-p", "tsconfig.json", "--pretty", "false"], {
    cwd: tempRoot,
    encoding: "utf8",
  });
}

test("retired generic confidential declarations are absent from the published surface", () => {
  const declarations = fs.readFileSync(path.join(PACKAGE_ROOT, "index.d.ts"), "utf8");
  const retiredDeclarations = [
    ["ConfidentialEncryptedPayload", "Input"],
    ...[["Shi", "eld"], ["Zk", "Transfer"], ["Un", "shield"]].flatMap(
      (variantParts) => {
        const variant = variantParts.join("");
        return [
          [variant, "InstructionInput"],
          [variant, "TransactionInput"],
          ["build", variant, "Instruction"],
          ["build", variant, "Transaction"],
        ];
      },
    ),
  ].map((parts) => parts.join(""));
  for (const retired of retiredDeclarations) {
    assert.doesNotMatch(declarations, new RegExp(`\\b${retired}\\b`, "u"), retired);
  }
});

test("algorithm options use omission rather than a nullable compatibility sentinel", () => {
  const declarations = fs.readFileSync(path.join(PACKAGE_ROOT, "index.d.ts"), "utf8");
  assert.doesNotMatch(
    declarations,
    /(?:privateKeyAlgorithm|algorithm)\?: string \| null/u,
  );
});

test("first-release HTTP client declarations omit compatibility escape hatches", () => {
  const declarationPath = path.join(PACKAGE_ROOT, "index.d.ts");
  const declarationText = fs.readFileSync(declarationPath, "utf8");
  const source = ts.createSourceFile(
    declarationPath,
    declarationText,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  const declaration = (kind, name) => {
    const node = source.statements.find(
      (statement) => kind(statement) && statement.name?.text === name,
    );
    assert.ok(node, `missing ${name} declaration`);
    return node;
  };
  const memberNames = (node) =>
    node.members.map((member) => member.name?.getText(source)).filter(Boolean);

  assert.equal(
    memberNames(declaration(ts.isClassDeclaration, "NoritoRpcClient")).includes("close"),
    false,
  );
  assert.equal(
    memberNames(
      declaration(ts.isInterfaceDeclaration, "ToriiBrowserClientOptions"),
    ).includes("config"),
    false,
  );
  assert.equal(
    memberNames(
      declaration(ts.isInterfaceDeclaration, "ToriiBrowserRequestOptions"),
    ).includes("successStatuses"),
    false,
  );

  for (const browserDeclaration of ["browser.d.ts", "torii-browser.d.ts"]) {
    const text = fs.readFileSync(path.join(PACKAGE_ROOT, browserDeclaration), "utf8");
    assert.doesNotMatch(text, /ToriiBrowserClient as ToriiClient/u);
    assert.doesNotMatch(text, /ToriiBrowserHttpError as ToriiHttpError/u);
  }
});

test("consensus declarations expose only the current Sumeragi surface", () => {
  const declarations = fs.readFileSync(path.join(PACKAGE_ROOT, "index.d.ts"), "utf8");
  for (const current of [
    "ToriiSumeragiStatus",
    "ToriiSumeragiLaneStatus",
    "ToriiSumeragiLaneRecord",
    "ToriiSumeragiParameters",
  ]) {
    assert.match(
      declarations,
      new RegExp(`export interface ${current}\\b`, "u"),
      `missing current ${current} declaration`,
    );
  }
  assert.doesNotMatch(
    declarations,
    /ToriiSumeragiV2/u,
    "retired consensus declarations must be absent",
  );
});

test("every public export has a safe runtime target and an explicit declaration target", () => {
  const packageJson = readPackageJson();
  const legacyTypes = packageJson.typesVersions["*"];
  const expectedLegacyKeys = [];

  for (const [subpath, descriptor] of Object.entries(packageJson.exports)) {
    assert.equal(
      descriptor !== null && typeof descriptor === "object" && !Array.isArray(descriptor),
      true,
      `${subpath} must use conditional exports with an explicit types target`,
    );
    assertSafePackageTarget(descriptor.import, `${subpath}.import`);
    if (descriptor.browser !== undefined) {
      assertSafePackageTarget(descriptor.browser, `${subpath}.browser`);
    }
    assertSafePackageTarget(descriptor.types, `${subpath}.types`);
    assert.match(descriptor.types, /\.d\.ts$/u, `${subpath}.types must be a declaration`);

    if (subpath !== ".") {
      const legacyKey = subpath.slice(2);
      expectedLegacyKeys.push(legacyKey);
      assert.deepEqual(
        legacyTypes[legacyKey],
        [descriptor.types],
        `${subpath} typesVersions target diverges from exports`,
      );
    }
  }

  assert.deepEqual(
    Object.keys(legacyTypes).sort(),
    expectedLegacyKeys.sort(),
    "typesVersions must cover every public subpath exactly once",
  );
  assert.deepEqual(packageJson.exports["./norito"], {
    import: "./dist/public/norito.js",
    types: "./norito.d.ts",
  });
});

test("the registry package allowlists only clean-install portable recipes", () => {
  const packageJson = readPackageJson();
  const fileRecipes = packageJson.files
    .filter((entry) => entry === "recipes" || entry.startsWith("recipes/"))
    .sort();
  assert.deepEqual(fileRecipes, [...PORTABLE_RECIPES].sort());
  assert.equal(packageJson.files.includes("recipes"), false);

  const sourceRecipes = fs
    .readdirSync(path.join(PACKAGE_ROOT, "recipes"), { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".mjs"))
    .map((entry) => `recipes/${entry.name}`)
    .sort();
  assert.deepEqual(
    sourceRecipes.filter((entry) => PORTABLE_RECIPES.includes(entry)).sort(),
    [...PORTABLE_RECIPES].sort(),
  );
  assert.ok(
    sourceRecipes.some((entry) => !PORTABLE_RECIPES.includes(entry)),
    "fixture must retain a forbidden source-checkout-only recipe",
  );
});

test("published recipe documentation exactly matches the portable allowlist", () => {
  const rootReadme = fs.readFileSync(path.join(PACKAGE_ROOT, "README.md"), "utf8");
  const recipeReadme = fs.readFileSync(
    path.join(PACKAGE_ROOT, "recipes", "README.md"),
    "utf8",
  );
  const rootContract = /The registry artifact includes only(?<body>[\s\S]*?)The wider recipe catalog/u.exec(
    rootReadme,
  );
  const recipeContract = /The portable registry\s+tarball includes only(?<body>[\s\S]*?);\s+examples that require/u.exec(
    recipeReadme,
  );
  assert.ok(rootContract?.groups?.body, "root README lacks the registry recipe contract");
  assert.ok(
    recipeContract?.groups?.body,
    "recipes README lacks the registry recipe contract",
  );

  const rootRecipes = [
    ...rootContract.groups.body.matchAll(/recipes\/[a-z0-9_]+\.mjs/gu),
  ].map((match) => match[0]);
  const recipeRecipes = [
    ...recipeContract.groups.body.matchAll(/[a-z0-9_]+\.mjs/gu),
  ].map((match) => `recipes/${match[0]}`);
  assert.deepEqual(rootRecipes.sort(), [...PORTABLE_RECIPES].sort());
  assert.deepEqual(recipeRecipes.sort(), [...PORTABLE_RECIPES].sort());
});

test("package smoke rejects every non-portable or missing required artifact", () => {
  const requiredHelperPaths = [
    "dist/boundedByteSnapshot.js",
    "dist/validationFeeTrust.js",
    "dist/sorafsOrderbookPreflight.js",
    "dist/smartContractDeploymentSubmit.js",
    "dist/sumeragiTyped.js",
  ];
  const requiredPaths = [
    "package.json",
    "atomic-private-settlement.d.ts",
    "index.d.ts",
    "browser.d.ts",
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
    "dist/sorafsOrderbookSubmission.js",
    "dist/sorafsOrderbookSubmission.d.ts",
    "dist/tairaTestnetProfile.js",
    ...requiredHelperPaths,
    "nexus-app.d.ts",
    ...PORTABLE_RECIPES,
  ];
  const metadata = {
    files: requiredPaths.map((entry) => ({ path: entry })),
  };
  assert.doesNotThrow(() => validatePackPaths(metadata));
  for (const forbiddenPath of [
    "dist/wasm/codec.js", "dist/codec.wasm", "dist/codec.WASM",
    "dist/browserCodec.js", "dist/browserCodecRuntime.js", "dist/public/browserCodec.js",
    "browser-codec.d.ts",
  ]) {
    assert.throws(() => validatePackPaths({
      files: [...metadata.files, { path: forbiddenPath }],
    }), /forbidden browser codec artifact/u, forbiddenPath);
  }
  for (const unpublishedPath of ["src/index.js", "scripts/build-dist.mjs"]) {
    assert.throws(
      () => validatePackPaths({
        files: [...metadata.files, { path: unpublishedPath }],
      }),
      /unpublished development path/u,
      unpublishedPath,
    );
  }

  for (const requiredPath of [
    "index.d.ts",
    "atomic-private-settlement.d.ts",
    "dist/atomicPrivateSettlement.js",
    "dist/tairaTestnetProfile.js",
    ...PORTABLE_RECIPES,
    ...requiredHelperPaths,
  ]) {
    assert.throws(
      () =>
        validatePackPaths({
          files: metadata.files.filter((entry) => entry.path !== requiredPath),
        }),
      new RegExp(
        `missing required tar entry: ${requiredPath.replaceAll(".", "\\.")}`,
        "u",
      ),
    );
  }
  for (const forbidden of [
    "recipes/batching.mjs",
    "recipes/contracts.mjs",
    "recipes/governance.mjs",
    "recipes/walletlessFollowGame.mjs",
  ]) {
    assert.throws(
      () =>
        validatePackPaths({
          files: [...metadata.files, { path: forbidden }],
        }),
      new RegExp(`forbidden non-portable recipe: ${forbidden.replace(".", "\\.")}`, "u"),
    );
  }
});

test("runtime namespace declarations expose exactly their module exports", async () => {
  const declarationPath = path.join(PACKAGE_ROOT, "index.d.ts");
  const program = ts.createProgram([declarationPath], {
    strict: true,
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
    skipLibCheck: false,
  });
  const declarations = program.getSourceFile(declarationPath);
  assert.ok(declarations);
  const checker = program.getTypeChecker();
  const moduleSymbol = checker.getSymbolAtLocation(declarations);
  assert.ok(moduleSymbol);
  const declarationExports = new Map(
    checker.getExportsOfModule(moduleSymbol).map((symbol) => [symbol.name, symbol]),
  );

  const rootTargets = ["../src/index.js", "../dist/index.js"];
  const rootModules = await Promise.all(rootTargets.map((target) => import(target)));
  for (const [namespaceName, moduleName, rootOnlyNames = []] of [
    ["Torii", "toriiClient"],
    ["Norito", "public/norito"],
    ["Crypto", "public/crypto"],
  ]) {
    const namespaceSymbol = declarationExports.get(namespaceName);
    assert.ok(namespaceSymbol, `missing ${namespaceName} declaration`);
    const namespaceType = checker.getTypeOfSymbolAtLocation(
      namespaceSymbol,
      namespaceSymbol.valueDeclaration ?? declarations,
    );
    const declaredNames = checker
      .getPropertiesOfType(namespaceType)
      .map((symbol) => symbol.name)
      .sort();
    const runtimeModule = await import(`../src/${moduleName}.js`);
    const runtimeNames = [...Object.keys(runtimeModule), ...rootOnlyNames].sort();
    assert.deepEqual(
      declaredNames,
      runtimeNames,
      `${namespaceName} declaration diverges from ${moduleName}.js`,
    );
    for (const [index, rootModule] of rootModules.entries()) {
      assert.deepEqual(
        Object.keys(rootModule[namespaceName]).sort(),
        runtimeNames,
        `${rootTargets[index]} ${namespaceName} diverges from ${moduleName}.js`,
      );
    }
  }
});

test("public facades exclude internal codecs while retaining their declared owners", async () => {
  const noritoImplementation = await import("../src/norito.js");
  for (const rootTarget of ["../src/index.js", "../dist/index.js"]) {
    const { Norito } = await import(rootTarget);
    for (const internal of [
      "_canonicalAccountIdNoritoValue", "_createNoritoInstructionApi",
      "noritoEncodeGameValueV1", "noritoDecodeGameValueV1",
      "noritoEncodeNftMarketValueV1", "noritoDecodeNftMarketValueV1",
      "encodeGameResourceValueV1", "decodeGameResourceValueV1",
    ]) {
      assert.equal(typeof noritoImplementation[internal], "function", internal);
      assert.equal(Object.hasOwn(Norito, internal), false, `${rootTarget}: ${internal}`);
    }
    assert.equal(typeof Norito.decodeAccountIdNoritoValue, "function");
  }
  const game = await import("../src/game.js");
  const nft = await import("../src/nft.js");
  assert.equal(game.encodeGameValueV1, noritoImplementation.noritoEncodeGameValueV1);
  assert.equal(nft.encodeNftMarketValueV1, noritoImplementation.noritoEncodeNftMarketValueV1);
});

test("root declarations expose exactly the source and distribution values", async () => {
  const declarationPath = path.join(PACKAGE_ROOT, "index.d.ts");
  const program = ts.createProgram([declarationPath], {
    strict: true,
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
    skipLibCheck: false,
  });
  const declarations = program.getSourceFile(declarationPath);
  assert.ok(declarations);
  const checker = program.getTypeChecker();
  const moduleSymbol = checker.getSymbolAtLocation(declarations);
  assert.ok(moduleSymbol);
  const declaredValues = checker
    .getExportsOfModule(moduleSymbol)
    .filter((symbol) => {
      const target =
        (symbol.flags & ts.SymbolFlags.Alias) !== 0
          ? checker.getAliasedSymbol(symbol)
          : symbol;
      return (target.flags & ts.SymbolFlags.Value) !== 0;
    })
    .map((symbol) => symbol.name)
    .sort();

  for (const runtimeTarget of ["../src/index.js", "../dist/index.js"]) {
    const runtime = await import(runtimeTarget);
    assert.deepEqual(
      Object.keys(runtime).sort(),
      declaredValues,
      `${runtimeTarget} diverges from the root value declarations`,
    );
  }
});

test("Torii client declarations never promise unimplemented methods", async () => {
  const declarationPath = path.join(PACKAGE_ROOT, "index.d.ts");
  const declarationText = fs.readFileSync(declarationPath, "utf8");
  const source = ts.createSourceFile(
    declarationPath,
    declarationText,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );

  for (const [className, runtimeTarget] of [
    ["ToriiClient", "../src/toriiClient.js"],
    ["ToriiBrowserClient", "../src/toriiBrowserClient.js"],
  ]) {
    const declaration = source.statements.find(
      (statement) =>
        ts.isClassDeclaration(statement) && statement.name?.text === className,
    );
    assert.ok(declaration, `missing ${className} declaration`);
    const runtime = await import(runtimeTarget);
    const runtimeClass = runtime[className];
    assert.equal(typeof runtimeClass, "function", `missing runtime ${className}`);

    for (const member of declaration.members.filter(ts.isMethodDeclaration)) {
      const methodName = member.name?.getText(source);
      assert.ok(methodName, `${className} has an unnamed method declaration`);
      const isStatic = member.modifiers?.some(
        (modifier) => modifier.kind === ts.SyntaxKind.StaticKeyword,
      );
      const owner = isStatic ? runtimeClass : runtimeClass.prototype;
      assert.equal(
        typeof owner[methodName],
        "function",
        `${className}.${methodName} is declared but not implemented`,
      );
    }
  }
});

test("narrow subpath declarations exactly match their runtime values", async () => {
  const packageJson = readPackageJson();
  const subpaths = Object.keys(packageJson.exports).filter(
    (subpath) => subpath !== ".",
  );

  for (const subpath of subpaths) {
    const descriptor = packageJson.exports[subpath];
    const declarationPath = path.resolve(PACKAGE_ROOT, descriptor.types);
    const program = ts.createProgram([declarationPath], {
      strict: true,
      target: ts.ScriptTarget.ES2022,
      module: ts.ModuleKind.NodeNext,
      moduleResolution: ts.ModuleResolutionKind.NodeNext,
      skipLibCheck: false,
    });
    const declaration = program.getSourceFile(declarationPath);
    assert.ok(declaration, `${subpath} declaration did not load`);
    const checker = program.getTypeChecker();
    const declaredValueNames = (source, seen = new Set()) => {
      if (seen.has(source.fileName)) return [];
      seen.add(source.fileName);
      return source.statements.flatMap((statement) => {
        if (ts.isExportDeclaration(statement)) {
          if (statement.isTypeOnly) return [];
          if (statement.exportClause && ts.isNamedExports(statement.exportClause)) {
            return statement.exportClause.elements
              .filter((element) => !element.isTypeOnly)
              .map((element) => element.name.text);
          }
          if (!statement.exportClause && statement.moduleSpecifier) {
            const target = checker.getSymbolAtLocation(statement.moduleSpecifier);
            assert.ok(target, `${subpath} wildcard export did not resolve`);
            return (target.declarations ?? []).flatMap((targetDeclaration) =>
              ts.isSourceFile(targetDeclaration)
                ? declaredValueNames(targetDeclaration, seen)
                : []);
          }
          return [];
        }
        if (!statement.modifiers?.some(
          (modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword,
        )) return [];
        if ((ts.isClassDeclaration(statement) || ts.isFunctionDeclaration(statement) ||
             ts.isEnumDeclaration(statement)) && statement.name) return [statement.name.text];
        if (ts.isVariableStatement(statement)) {
          return statement.declarationList.declarations.map((entry) => {
            assert.ok(ts.isIdentifier(entry.name), `${subpath} exports a destructured declaration`);
            return entry.name.text;
          });
        }
        return [];
      });
    };
    const uniqueDeclaredValues = [...new Set(declaredValueNames(declaration))].sort();

    const runtimeTargets = new Set(
      [descriptor.import, descriptor.browser].filter(Boolean),
    );
    for (const runtimeTarget of runtimeTargets) {
      const runtimePath = path.resolve(PACKAGE_ROOT, runtimeTarget);
      const runtime = await import(pathToFileURL(runtimePath).href);
      assert.deepEqual(
        Object.keys(runtime).sort(),
        uniqueDeclaredValues,
        `${subpath} runtime ${runtimeTarget} diverges from its declarations`,
      );
    }
  }

  const addressText = fs.readFileSync(path.join(PACKAGE_ROOT, "address.d.ts"), "utf8");
  const toriiText = fs.readFileSync(path.join(PACKAGE_ROOT, "torii.d.ts"), "utf8");
  assert.doesNotMatch(addressText, /\bToriiClient\b/u);
  assert.doesNotMatch(toriiText, /\bNetworkId\b/u);
});

test("SoraFS gateway denial declarations expose only governed catalog evidence", () => {
  const declarationPath = path.join(PACKAGE_ROOT, "index.d.ts");
  const declarationText = fs.readFileSync(declarationPath, "utf8");
  const source = ts.createSourceFile(
    declarationPath,
    declarationText,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  const findInterface = (name) => {
    const declaration = source.statements.find(
      (statement) =>
        ts.isInterfaceDeclaration(statement) && statement.name.text === name,
    );
    assert.ok(declaration, `missing ${name} declaration`);
    return declaration;
  };
  const propertyName = (member) => member.name?.getText(source);

  const options = findInterface("SorafsGatewayFetchOptions");
  const optionNames = options.members.map(propertyName);
  assert.ok(optionNames.includes("cacheVersion"));
  assert.equal(optionNames.includes("moderationTokenKey"), false);
  const exactOptionTypes = new Map([
    ["rolloutPhase", '"canary" | "ramp" | "default"'],
    [
      "transportPolicy",
      '"soranet-first" | "soranet-strict" | "direct-only"',
    ],
    [
      "anonymityPolicy",
      '"anon-guard-pq" | "anon-majority-pq" | "anon-strict-pq"',
    ],
    ["writeMode", '"read-only" | "upload-pq-only"'],
  ]);
  for (const [name, expectedType] of exactOptionTypes) {
    const property = options.members.find(
      (member) => propertyName(member) === name,
    );
    assert.ok(property && ts.isPropertySignature(property), `missing ${name}`);
    assert.equal(
      property.type?.getText(source),
      expectedType,
      `${name} must expose only exact V1 labels`,
    );
  }

  const failure = findInterface("SorafsGatewayFetchAttemptFailure");
  const policyBlock = failure.members.find(
    (member) => propertyName(member) === "policyBlock",
  );
  assert.ok(policyBlock && ts.isPropertySignature(policyBlock));
  assert.ok(
    policyBlock.type && ts.isTypeLiteralNode(policyBlock.type),
    "policyBlock must be a closed type literal",
  );
  assert.deepEqual(policyBlock.type.members.map(propertyName), [
    "observedStatus",
    "code",
    "source",
    "catalogDigestHex",
  ]);
  assert.equal(
    policyBlock.type.members[0].type?.getText(source),
    "451",
    "the observed denial status must be exact",
  );
  assert.equal(
    policyBlock.type.members[1].type?.getText(source),
    '"gateway_compliance_denied"',
    "the denial code must be exact",
  );
  for (const removed of [
    "canonicalStatus",
    "cacheVersion",
    "denylistVersion",
    "proofTokenPresent",
    "message",
  ]) {
    assert.equal(
      policyBlock.type.members.some((member) => propertyName(member) === removed),
      false,
      `removed denial field ${removed} must stay absent`,
    );
  }
});

test("strict NodeNext resolves the root and every public subpath from a packed layout", () => {
  const packageJson = readPackageJson();
  const rootDeclarations = fs.readFileSync(
    path.join(PACKAGE_ROOT, "index.d.ts"),
    "utf8",
  );
  const blockProofDeclarations = fs.readFileSync(
    path.join(PACKAGE_ROOT, "src", "blockProofTypes.d.ts"),
    "utf8",
  );
  for (const name of [
    "ToriiBlockMerkleCommitment",
    "ToriiBlockMerkleProof",
    "ToriiBlockProofs",
    "ToriiBlockProofTrustedAnchor",
    "ToriiBlockProofVerification",
  ]) {
    assert.doesNotMatch(
      rootDeclarations,
      new RegExp(`export interface ${name}\\b`, "u"),
      `${name} must have one canonical declaration source`,
    );
    assert.match(
      blockProofDeclarations,
      new RegExp(`export interface ${name}\\b`, "u"),
      `missing canonical ${name} declaration`,
    );
  }
  assert.match(
    blockProofDeclarations,
    /readonly networkId: NetworkId;/u,
    "authenticated BlockProofs must bind the nominal exact NetworkId",
  );
  assert.doesNotMatch(
    blockProofDeclarations,
    /readonly chainId:/u,
    "retired ChainId spelling must stay absent",
  );
  const indexOfSubpath = (subpath) => Object.keys(packageJson.exports).indexOf(subpath);
  const noritoIndex = indexOfSubpath("./norito");
  const cryptoIndex = indexOfSubpath("./crypto");
  const browserIndex = indexOfSubpath("./browser");
  assert.notEqual(noritoIndex, -1);
  assert.notEqual(cryptoIndex, -1);
  assert.notEqual(browserIndex, -1);
  const { tempRoot } = createPackedLayout({ includeNodeTypes: true });
  try {
    const imports = Object.keys(packageJson.exports).map((subpath, index) => {
      const specifier = subpath === "." ? PACKAGE_NAME : `${PACKAGE_NAME}/${subpath.slice(2)}`;
      return `import * as export${index} from ${JSON.stringify(specifier)};`;
    });
    const bindings = Object.keys(packageJson.exports).map((_, index) => `export${index}`);
    fs.writeFileSync(
      path.join(tempRoot, "consumer.mts"),
      [
        ...imports,
        `import * as RootSdk from ${JSON.stringify(PACKAGE_NAME)};`,
        `import { Crypto, Norito, NumericV1, SorafsOrderbookSubmissionAmbiguousError, Torii, ToriiClient, CANCEL_ASSET_LOCK_MAX_LOCK_ID_UTF8_BYTES_V1, buildCancelAssetLockInstruction, buildSetAssetTransferAvailabilityInstruction, decodeCancelAssetLockV1, encodeCancelAssetLockV1, validateAppealFinanceCancelAssetLock, type AssetTransferAvailability, type CancelAssetLockInstruction, type CancelAssetLockV1, type CancelAssetLockV1Archive, type CanonicalRequestAuth, type ContractEntrypointValueKindName, type CryptoAlgorithm, type IdentifierClaimLookupResponse, type IdentifierPolicyListResponse, type IdentifierResolutionReceipt, type PrivacyEngineIdV1, type PrivacyProofSystemIdV1, type RamLfeExecuteResponse, type IdentifierOriginalOutputOpening, type IdentifierPrepareResponse, type SetAssetTransferAvailabilityInstruction, type SorafsOrderbookSubmissionReceipt, type SorafsValidationOutcome, type ToriiRepoAgreement, type ToriiVerifierBackendLabelV1 } from ${JSON.stringify(PACKAGE_NAME)};`,
        `import { buildSetAssetTransferBlacklistInstruction, buildSetAssetTransferControlInstruction, type AssetTransferControlWindow, type AssetTransferLimitInput, type SetAssetTransferBlacklistInstruction, type SetAssetTransferControlInstruction } from ${JSON.stringify(PACKAGE_NAME)};`,
        `import { decodePrivacyExact12CapabilityManifestV1, getPrivacyExact12CapabilityManifestV1, type PrivacyExact12CapabilityManifestV1 } from ${JSON.stringify(`${PACKAGE_NAME}/privacy-capabilities`)};`,
        "type Expect<T extends true> = T;",
        'const algorithm: CryptoAlgorithm = "ed25519";',
        "const cancelAssetLockMaxLockIdUtf8BytesV1: 4096 = CANCEL_ASSET_LOCK_MAX_LOCK_ID_UTF8_BYTES_V1;",
        'const cancelAssetLock: CancelAssetLockInstruction = buildCancelAssetLockInstruction({ lockId: "merchant-lock-001", expectedRemainingAmount: "15" });',
        'const bareCancelAssetLock: CancelAssetLockV1 = { escrow_id: "hash:73CCD4E0DD69AD434DB75056B600AA4F74C8FC5556B11BDC799DFDB7EA29851F#434B", expected_remaining_amount: "20" };',
        "const bareCancelAssetLockArchive: CancelAssetLockV1Archive = encodeCancelAssetLockV1(bareCancelAssetLock);",
        "const decodedBareCancelAssetLock: CancelAssetLockV1 = decodeCancelAssetLockV1(bareCancelAssetLockArchive);",
        "const appealFinanceOutcome: SorafsValidationOutcome = validateAppealFinanceCancelAssetLock(bareCancelAssetLockArchive, { label: 'cancel_asset_lock_v1.to', generatedAtUnix: 41n });",
        "// @ts-expect-error bare V1 quantities must be canonical strings.",
        'encodeCancelAssetLockV1({ escrow_id: bareCancelAssetLock.escrow_id, expected_remaining_amount: 20 });',
        "// @ts-expect-error quantity-bearing APIs reject lossy JavaScript numbers.",
        'buildCancelAssetLockInstruction({ lockId: "merchant-lock-001", expectedRemainingAmount: 15 });',
        'const availability: AssetTransferAvailability = "Disabled";',
        'const setAvailability: SetAssetTransferAvailabilityInstruction = buildSetAssetTransferAvailabilityInstruction({ accountId: "i105...", assetDefinitionId: "asset...", expectedRevision: 0, incoming: availability, outgoing: "Enabled" });',
        '// @ts-expect-error availability spellings are exact.',
        'buildSetAssetTransferAvailabilityInstruction({ accountId: "i105...", assetDefinitionId: "asset...", expectedRevision: 0, incoming: "disabled", outgoing: "Enabled" });',
        'const setBlacklist: SetAssetTransferBlacklistInstruction = buildSetAssetTransferBlacklistInstruction({ accountId: "i105...", assetDefinitionId: "asset...", blacklisted: true });',
        'const controlWindow: AssetTransferControlWindow = "DAY";',
        'const controlLimits: readonly AssetTransferLimitInput[] = [{ window: controlWindow, capAmount: "100" }, { window: "WEEK", capAmount: null }];',
        'const setControl: SetAssetTransferControlInstruction = buildSetAssetTransferControlInstruction({ accountId: "i105...", assetDefinitionId: "asset...", limits: controlLimits });',
        '// @ts-expect-error blacklist state is an exact boolean.',
        'buildSetAssetTransferBlacklistInstruction({ accountId: "i105...", assetDefinitionId: "asset...", blacklisted: "true" });',
        '// @ts-expect-error control window spellings are exact.',
        'buildSetAssetTransferControlInstruction({ accountId: "i105...", assetDefinitionId: "asset...", limits: [{ window: "day", capAmount: "1" }] });',
        '// @ts-expect-error transfer cap quantities reject lossy JavaScript numbers.',
        'buildSetAssetTransferControlInstruction({ accountId: "i105...", assetDefinitionId: "asset...", limits: [{ window: "DAY", capAmount: 1 }] });',
        "const toriiConstructor: typeof ToriiClient = Torii.ToriiClient;",
        "declare const signedOrderbookTransaction: Uint8Array;",
        "const orderbookReceipt: Promise<SorafsOrderbookSubmissionReceipt> = new ToriiClient('https://torii.example').submitSorafsOrderbookOrder(signedOrderbookTransaction, { expectedReceiptSigner: 'ed0120...' });",
        "const orderbookAmbiguity: typeof SorafsOrderbookSubmissionAmbiguousError = Torii.SorafsOrderbookSubmissionAmbiguousError;",
        "// @ts-expect-error the receipt trust anchor is mandatory.",
        "new ToriiClient('https://torii.example').submitSorafsOrderbookOrder(signedOrderbookTransaction);",
        "// @ts-expect-error signed orderbook wires reject text inputs.",
        "new ToriiClient('https://torii.example').submitSorafsOrderbookOrder('wire', { expectedReceiptSigner: 'ed0120...' });",
        "// @ts-expect-error signed orderbook wires reject numeric arrays.",
        "new ToriiClient('https://torii.example').submitSorafsOrderbookCancel([1, 2, 3], { expectedReceiptSigner: 'ed0120...' });",
        `const encodeInstruction: typeof export${noritoIndex}.noritoEncodeInstruction = Norito.noritoEncodeInstruction;`,
        `const validateFrame: typeof export${noritoIndex}.validateNoritoFrame = Norito.validateNoritoFrame;`,
        `const exact12Decoder: typeof export${noritoIndex}.noritoDecodePrivacyExact12FixtureBundleBase64V1 = Norito.noritoDecodePrivacyExact12FixtureBundleBase64V1;`,
        "// @ts-expect-error fixture-only Exact12 codecs are not retained by the broad browser facade.",
        `void export${browserIndex}.noritoDecodePrivacyExact12FixtureBundleBase64V1;`,
        `const generateKeyPair: typeof export${cryptoIndex}.generateKeyPair = Crypto.generateKeyPair;`,
        "declare const exact12ManifestArchive: Uint8Array;",
        "const privacyManifest: PrivacyExact12CapabilityManifestV1 = decodePrivacyExact12CapabilityManifestV1(exact12ManifestArchive);",
        "const privacyCommittedHeight: bigint = privacyManifest.committed_height;",
        "declare const privacyExpectedNetwork: RootSdk.NetworkId;",
        "// @ts-expect-error local signing requires the deployment's explicit I105 discriminant.",
        "new RootSdk.LocalSigningContext(privacyExpectedNetwork);",
        "const privacyNode = new ToriiClient('https://torii.example', { localSigningContext: new RootSdk.LocalSigningContext(privacyExpectedNetwork, 753) });",
        "const privacyNodeResult: Promise<PrivacyExact12CapabilityManifestV1> = getPrivacyExact12CapabilityManifestV1(privacyNode, { canonicalAuth: { accountId: 'i105...', privateKey: '11'.repeat(32) } });",
        'const privacyProofSystems: PrivacyProofSystemIdV1[] = ["stark-fri-sha3-384-goldilocks-v1", "anonymous-pgc-p256", "iroha-verange-p256", "zk-ams-masked-relaxed-spartan-t256-ristretto255-sha3-512", "vega-neutron-nova-spartan-hyrax-t256", "jindo-polynomial-commitment", "lantern-lnp22-module-linear-norm", "halo2-ipa-pasta", "fcmp-plus-plus-curve-tree-bulletproofs"];',
        'const privacyEngines: PrivacyEngineIdV1[] = ["native-goldilocks-sha3-384-stark-fri-v1", "native-anonymous-pgc-p256", "native-verange-p256", "native-zk-ams-masked-relaxed-spartan-t256-ristretto255", "native-vega", "native-jindo", "native-lantern-lnp22", "native-halo2-orchard", "native-fcmp-plus-plus"];',
        "// @ts-expect-error retired SIS-with-hints proof systems fail closed.",
        'const retiredPrivacyProofSystem: PrivacyProofSystemIdV1 = "sis-with-hints";',
        "// @ts-expect-error proof-system labels are case-sensitive.",
        'const caseShiftedPrivacyProofSystem: PrivacyProofSystemIdV1 = "HALO2-IPA-PASTA";',
        "// @ts-expect-error proof-system labels reject surrounding whitespace.",
        'const paddedPrivacyProofSystem: PrivacyProofSystemIdV1 = " halo2-ipa-pasta";',
        "// @ts-expect-error retired SIS-with-hints engines fail closed.",
        'const retiredPrivacyEngine: PrivacyEngineIdV1 = "native-sis-with-hints";',
        "// @ts-expect-error engine labels are case-sensitive.",
        'const caseShiftedPrivacyEngine: PrivacyEngineIdV1 = "NATIVE-JINDO";',
        "// @ts-expect-error engine labels reject Unicode confusables.",
        'const confusablePrivacyEngine: PrivacyEngineIdV1 = "native-jindо";',
        "declare const repoAgreement: ToriiRepoAgreement;",
        "const repoLifecycle: [string, string, number | null, 'active' | 'settled'] = [repoAgreement.cashSource, repoAgreement.collateralCustodyAsset, repoAgreement.settlementTimestampMs, repoAgreement.status];",
        'const verifierBackend: ToriiVerifierBackendLabelV1 = "pipa-r/pasta";',
        "// @ts-expect-error retired privacy backend aliases fail closed.",
        'const retiredVerifierBackend: ToriiVerifierBackendLabelV1 = "halo2/ipa-pasta-cycle-v1";',
        "// @ts-expect-error backend labels are case-sensitive.",
        'const caseShiftedVerifierBackend: ToriiVerifierBackendLabelV1 = "HALO2/IPA";',
        "// @ts-expect-error backend labels reject surrounding whitespace.",
        'const paddedVerifierBackend: ToriiVerifierBackendLabelV1 = " halo2/ipa";',
        "// @ts-expect-error backend labels reject Unicode confusables.",
        'const confusableVerifierBackend: ToriiVerifierBackendLabelV1 = "halо2/ipa";',
        "// @ts-expect-error privacy capability fetch is not a base-client method.",
        "void ToriiClient.prototype.getPrivacyCapabilitiesV1;",
        "// @ts-expect-error privacy capability parser is not a root runtime export.",
        "void RootSdk.parsePrivacyCapabilitySnapshotV1;",
        "// @ts-expect-error the Exact12 fetch API rejects unknown request options.",
        "getPrivacyExact12CapabilityManifestV1(new ToriiClient('https://torii.example'), { canonicalAuth: { accountId: 'i105...', privateKey: '11'.repeat(32) }, unknown: true });",
        "const quantityFrame: Uint8Array = NumericV1.encodeQuantityFrame(42n);",
        "const quantityEnvelope: Uint8Array = NumericV1.encodeQuantityEnvelope(42n);",
        "const quantityJson: string = NumericV1.encodeQuantityJson(42n);",
        "// @ts-expect-error exact integer JSON getters accept canonical strings only.",
        "NumericV1.decodeIntJson(1);",
        "// @ts-expect-error exact decimal JSON getters reject legacy number tokens.",
        "NumericV1.decodeDecimalJson(1.25);",
        "// @ts-expect-error exact quantity JSON getters reject legacy number tokens.",
        "NumericV1.decodeQuantityJson(1);",
        'const rootNumericKinds: ContractEntrypointValueKindName[] = ["Int", "Decimal", "Quantity"];',
        '// @ts-expect-error Amount is a permanently retired V1 boundary kind.',
        'const retiredRootAmount: ContractEntrypointValueKindName = "Amount";',
        '// @ts-expect-error U128 is not a canonical V1 boundary kind.',
        'const retiredRootU128: ContractEntrypointValueKindName = "U128";',
        "async function checkIdentifierApiTypes(client: ToriiClient, auth: CanonicalRequestAuth, opening: IdentifierOriginalOutputOpening): Promise<void> {",
        "  const policies: IdentifierPolicyListResponse = await client.listIdentifierPolicies();",
        "  const policy = policies.items[0]!;",
        "  // @ts-expect-error Seed overrides are retired from the public encryption API.",
        "  RootSdk.encryptIdentifierInputForPolicy(policy, 'private input', { seedHex: '00' });",
        "  // @ts-expect-error Request builders require current normalized input, private nonce, original opening and selected network.",
        "  RootSdk.buildIdentifierRequestForPolicy(policy, { input: 'private input', encrypt: true, outputOpening: opening });",
        "  const unavailableCode: 'ram_lfe_encryption_unavailable' = new RootSdk.RamLfeEncryptionUnavailableError().code;",
        "  void unavailableCode;",
        "  const prepare: IdentifierPrepareResponse | null = await client.prepareIdentifierClaimReceipt('account-id', { policyId: policy.policy_id, normalizedInput: 'alice@example.test', inputNonce: 'a1'.repeat(32), canonicalAuth: auth });",
        "  const execution: RamLfeExecuteResponse | null = await client.executeRamLfeProgram(policy.program_id, { normalizedInput: 'alice@example.test', inputNonce: 'a1'.repeat(32), canonicalAuth: auth });",
        "  const claim: IdentifierClaimLookupResponse | null = await client.getIdentifierClaimByReceiptHash('11'.repeat(32));",
        "  if (execution) {",
        "    // @ts-expect-error Execution cannot attest to a plaintext opening.",
        "    void execution.output_opening;",
        "    // @ts-expect-error Retired backend tags are not current wire values.",
        "    execution.backend = 'bfv-programmed-sha3-256-v1';",
        "    // @ts-expect-error Unknown lowercase modes are not current wire values.",
        "    execution.verification_mode = 'unknown';",
        "    const resolved: IdentifierResolutionReceipt | null = await client.resolveIdentifier({ policyId: policy.policy_id, normalizedInput: 'alice@example.test', inputNonce: 'a1'.repeat(32), outputOpening: opening, canonicalAuth: auth });",
        "    const issued: IdentifierResolutionReceipt | null = await client.issueIdentifierClaimReceipt('account-id', { policyId: policy.policy_id, normalizedInput: 'alice@example.test', inputNonce: 'a1'.repeat(32), outputOpening: opening, canonicalAuth: auth });",
        "    void [resolved, issued, opening.payload.opened_output_hash];",
        "  }",
        "  void [claim, prepare];",
        "}",
        "// @ts-expect-error Torii does not expose crypto helpers.",
        "void Torii.generateKeyPair;",
        "// @ts-expect-error Crypto does not expose Torii clients.",
        "void Crypto.ToriiClient;",
        "// @ts-expect-error The source-only crypto runtime factory is not public.",
        "void RootSdk._createCryptoApi;",
        "// @ts-expect-error The Crypto namespace omits source-only runtime factories.",
        "void Crypto._createCryptoApi;",
        "// @ts-expect-error The crypto subpath omits source-only runtime factories.",
        `void export${cryptoIndex}._createCryptoApi;`,
        "// @ts-expect-error Source-only transaction runtime factories are not public.",
        "void RootSdk._createTransactionApi;",
        "// @ts-expect-error The Norito namespace omits source-only runtime factories.",
        "void Norito._createNoritoInstructionApi;",
        "// @ts-expect-error The Norito subpath omits source-only runtime factories.",
        `void export${noritoIndex}._createNoritoInstructionApi;`,
        "// @ts-expect-error game codecs belong to the game package subpath.",
        "void Norito.noritoEncodeGameValueV1;",
        "// @ts-expect-error NFT codecs belong to the NFT package subpath.",
        "void Norito.noritoEncodeNftMarketValueV1;",
        "// @ts-expect-error Norito does not expose crypto helpers.",
        "void Norito.generateKeyPair;",
        `void [${bindings.join(", ")}];`,
        "void algorithm; void cancelAssetLock; void toriiConstructor; void orderbookReceipt; void orderbookAmbiguity; void encodeInstruction; void validateFrame; void exact12Decoder; void generateKeyPair; void privacyManifest; void privacyCommittedHeight; void privacyNodeResult; void privacyProofSystems; void privacyEngines; void retiredPrivacyProofSystem; void caseShiftedPrivacyProofSystem; void paddedPrivacyProofSystem; void retiredPrivacyEngine; void caseShiftedPrivacyEngine; void confusablePrivacyEngine; void repoLifecycle; void verifierBackend; void retiredVerifierBackend; void caseShiftedVerifierBackend; void paddedVerifierBackend; void confusableVerifierBackend; void quantityFrame; void quantityEnvelope; void quantityJson; void rootNumericKinds; void retiredRootAmount; void retiredRootU128; void checkIdentifierApiTypes;",
      ].join("\n"),
      "utf8",
    );
    const compiled = compileFixture(tempRoot, {
      compilerOptions: {
        strict: true,
        exactOptionalPropertyTypes: true,
        noUncheckedIndexedAccess: true,
        skipLibCheck: false,
        target: "ES2022",
        module: "NodeNext",
        moduleResolution: "NodeNext",
        types: ["node"],
        noEmit: true,
      },
      files: ["consumer.mts"],
    });
    assert.equal(
      compiled.status,
      0,
      `strict packed NodeNext compile failed:\n${compiled.stdout}\n${compiled.stderr}`,
    );
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("dedicated browser declarations compile without ambient Node types", () => {
  for (const declaration of ["index.d.ts", "dist/blockProofTypes.d.ts"]) {
    const source = fs.readFileSync(path.join(PACKAGE_ROOT, declaration), "utf8");
    assert.doesNotMatch(source, /reference types=["']node["']/u, declaration);
    assert.doesNotMatch(source, /["']node:/u, declaration);
  }
  const { tempRoot } = createPackedLayout({ includeNodeTypes: false });
  try {
    assert.equal(fs.existsSync(path.join(tempRoot, "node_modules", "@types", "node")), false);
    fs.writeFileSync(
      path.join(tempRoot, "browser-consumer.ts"),
      [
        'import { createConnectAppSession, createConnectCanonicalRequestAuth, TORII_CANONICAL_REQUEST_DOMAIN_TAG, type BrowserConnectApproval, type BrowserConnectCanonicalRequestAuth } from "@iroha/iroha-js/connect-browser";',
        'import { NexusAppClient, type NexusFinalizeOptions } from "@iroha/iroha-js/nexus-app";',
        'import { browserTransactionCodec } from "@iroha/iroha-js/transaction-codec";',
        'import { computeIvmArtifactHashes } from "@iroha/iroha-js/ivm-artifact";',
        'import { canonicalQueryString } from "@iroha/iroha-js/canonical-request";',
        'import { compileKotodamaProgram, KotodamaCompilerClient, type KotodamaCompiledEntrypointValueKindName, type KotodamaCompiledManifestMetadata, type KotodamaCompilerCallOptions, type KotodamaCompilerTransportOptions, type KotodamaCompilerDiagnostic, type KotodamaCompiledSourceMapEntry } from "@iroha/iroha-js/kotodama-compiler";',
        "declare const approval: BrowserConnectApproval;",
        "declare const connectSession: ReturnType<typeof createConnectAppSession>;",
        "const connectAuth: Promise<BrowserConnectCanonicalRequestAuth> = createConnectCanonicalRequestAuth(connectSession);",
        'const options: NexusFinalizeOptions = { wait: true, signal: new AbortController().signal };',
        "const bytes = new Uint8Array(17);",
        "void createConnectAppSession; void approval; void connectAuth; void options;",
        "void connectSession.signRaw(TORII_CANONICAL_REQUEST_DOMAIN_TAG, bytes);",
        "void new NexusAppClient({ chainDiscriminant: 753, transactionCodec: browserTransactionCodec });",
        "void computeIvmArtifactHashes(bytes);",
        'void canonicalQueryString(new URLSearchParams({ browser: "true" }));',
        'void compileKotodamaProgram("CREATE DOMAIN browser");',
        "const compilerTransport: KotodamaCompilerTransportOptions = { signal: new AbortController().signal, timeoutMs: 30_000 };",
        "const compilerCall: KotodamaCompilerCallOptions = { ...compilerTransport, sourceName: 'browser.ko', zk: true };",
        "void new KotodamaCompilerClient('https://compiler.example').compile('seiyaku Demo {}', compilerCall);",
        'const compilerNumericKinds: KotodamaCompiledEntrypointValueKindName[] = ["Int", "Decimal", "Quantity"];',
        "declare const compilerManifest: KotodamaCompiledManifestMetadata;",
        "const compilerManifestName: string = compilerManifest.seiyaku_name;",
        "const compilerFingerprint: string = compilerManifest.compiler_fingerprint;",
        "const compilerFeatureBitmap: number = compilerManifest.features_bitmap;",
        "const compilerEntrypoints = compilerManifest.entrypoints.map(({ name }) => name);",
        "const compilerStates = compilerManifest.states.map(({ name }) => name);",
        "declare const compilerDiagnostic: KotodamaCompilerDiagnostic;",
        "declare const compilerSourceEntry: KotodamaCompiledSourceMapEntry;",
        "const diagnosticPackage: string | null | undefined = compilerDiagnostic.primary_span?.package_identity;",
        "const alternativeReplacements: string[] = compilerDiagnostic.alternative_fixes.map(({ replacement }) => replacement);",
        "const localizedMessage: string | undefined = compilerDiagnostic.localized?.message;",
        "const sourceKind: 'function' | 'statement' = compilerSourceEntry.source_kind;",
        "declare const incompleteDiagnostic: Omit<KotodamaCompilerDiagnostic, 'alternative_fixes' | 'localized'>;",
        "// @ts-expect-error Both diagnostic companion fields are required, even when empty/null.",
        "const retiredDiagnostic: KotodamaCompilerDiagnostic = incompleteDiagnostic;",
        "declare const incompleteSourceEntry: Omit<KotodamaCompiledSourceMapEntry, 'source_kind'>;",
        "// @ts-expect-error Source maps require a statement/function discriminator.",
        "const retiredSourceEntry: KotodamaCompiledSourceMapEntry = incompleteSourceEntry;",
        "void diagnosticPackage; void alternativeReplacements; void localizedMessage; void sourceKind; void retiredDiagnostic; void retiredSourceEntry;",
        '// @ts-expect-error Amount is a permanently retired V1 boundary kind.',
        'const retiredCompilerAmount: KotodamaCompiledEntrypointValueKindName = "Amount";',
        '// @ts-expect-error U128 is not a canonical V1 boundary kind.',
        'const retiredCompilerU128: KotodamaCompiledEntrypointValueKindName = "U128";',
        'void compilerTransport; void compilerCall; void compilerNumericKinds; void compilerManifestName; void compilerFingerprint; void compilerFeatureBitmap; void compilerEntrypoints; void compilerStates; void retiredCompilerAmount; void retiredCompilerU128;',
      ].join("\n"),
      "utf8",
    );
    const compiled = compileFixture(tempRoot, {
      compilerOptions: {
        strict: true,
        exactOptionalPropertyTypes: true,
        noUncheckedIndexedAccess: true,
        skipLibCheck: false,
        target: "ES2022",
        module: "ESNext",
        moduleResolution: "Bundler",
        lib: ["ES2022", "DOM", "DOM.Iterable"],
        types: [],
        noEmit: true,
      },
      files: ["browser-consumer.ts"],
    });
    assert.equal(
      compiled.status,
      0,
      `strict packed browser compile failed:\n${compiled.stdout}\n${compiled.stderr}`,
    );
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});
