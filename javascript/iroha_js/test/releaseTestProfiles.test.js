import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const SDK_DIRECTORY = fileURLToPath(new URL("../", import.meta.url));
const REPOSITORY_ROOT = path.resolve(SDK_DIRECTORY, "../..");

function readRepositoryFile(relativePath) {
  return readFileSync(path.join(REPOSITORY_ROOT, relativePath), "utf8");
}

test("release test profiles separate provisioned lanes and reject skipped results", () => {
  const packageDocument = JSON.parse(
    readFileSync(path.join(SDK_DIRECTORY, "package.json"), "utf8"),
  );
  assert.equal(
    packageDocument.scripts.test,
    "npm run build:native && node ./scripts/run-test-profile.mjs unit",
  );
  assert.equal(
    packageDocument.scripts["test:sorafs-native"],
    "node ./scripts/run-test-profile.mjs sorafs-native",
  );
  const retiredArtifactProfile = "test:release-" + "artifacts";
  assert.equal(Object.hasOwn(packageDocument.scripts, retiredArtifactProfile), false);
  assert.equal(
    packageDocument.scripts["test:heavy"],
    "node ./scripts/run-test-profile.mjs heavy",
  );

  const runner = readFileSync(
    path.join(SDK_DIRECTORY, "scripts", "run-test-profile.mjs"),
    "utf8",
  );
  for (const required of [
    '"integrationTorii.test.js"',
    '"sorafsChunker.oneGib.test.js"',
    '"sorafsAppealFinanceValidation.test.js"',
    '"sorafsFixtureBundleValidation.test.js"',
    '"sorafsOrderbookSubmission.test.js"',
    '"sorafsOrchestrator.parity.test.js"',
    '"sorafsPdpValidation.test.js"',
    'testArguments.push("--test-concurrency=1")',
    '/# (?:SKIP|TODO)(?:\\s|$)/u',
  ]) {
    assert.ok(runner.includes(required), `test profile runner must contain ${required}`);
  }
});

test("release-scoped JavaScript tests contain no capability skip declarations", () => {
  for (const relativePath of [
    "javascript/iroha_js/test/currentRustContractArtifact.test.js",
    "javascript/iroha_js/test/helpers/native.js",
    "javascript/iroha_js/test/helpers/nativeRequirements.js",
    "javascript/iroha_js/test/sorafsNativeSuites/cancelAssetLockV1.js",
    "javascript/iroha_js/test/sorafsNativeSuites/sorafsAppealFinanceValidation.js",
    "javascript/iroha_js/test/sorafsNativeSuites/sorafsFixtureBundleValidation.js",
    "javascript/iroha_js/test/sorafsNativeSuites/sorafsOrderbookSubmission.js",
    "javascript/iroha_js/test/sorafsNativeSuites/sorafsOrchestrator.parity.js",
    "javascript/iroha_js/test/sorafsNativeSuites/sorafsPdpValidation.js",

    "javascript/iroha_js/test/integrationTorii.test.js",
    "javascript/iroha_js/test/nativeBuildProvenance.test.js",
    "javascript/iroha_js/test/retailDailyLimitInstructions.test.js",
    "javascript/iroha_js/test/sorafsChunker.oneGib.test.js",
  ]) {
    const source = readRepositoryFile(relativePath);
    assert.doesNotMatch(source, /\bskip\s*:/u, `${relativePath} must not declare skipped tests`);
    assert.doesNotMatch(source, /\.skip\s*(?:\(|=)/u, `${relativePath} must not expose skip helpers`);
  }
});

test("retired browser verifier surface cannot return", () => {
  const retiredSubpath = "./ivm-" + "artifact-admission-wasm";
  const retiredSelector = "IROHA_IVM_" + "ARTIFACT_ADMISSION_WASM";
  const retiredVerifierOption = "artifactAdmission" + "Verifier";
  const packageDocument = JSON.parse(
    readFileSync(path.join(SDK_DIRECTORY, "package.json"), "utf8"),
  );
  assert.equal(Object.hasOwn(packageDocument.exports, retiredSubpath), false);
  assert.equal(
    Object.hasOwn(packageDocument.typesVersions["*"], retiredSubpath.slice(2)),
    false,
  );
  assert.equal(
    packageDocument.files.some((entry) => entry.includes(retiredSubpath.slice(2))),
    false,
  );
  for (const retiredFile of [
    "javascript/iroha_js/ivm-" + "artifact-admission-wasm.d.ts",
    "javascript/iroha_js/src/ivm" + "ArtifactAdmissionWasm.js",
    "javascript/iroha_js/test/ivm" + "ArtifactAdmissionWasm.test.js",
    "javascript/iroha_js/test/helpers/artifact" + "AdmissionWasm.js",
  ]) {
    assert.equal(
      existsSync(path.join(REPOSITORY_ROOT, retiredFile)),
      false,
      `${retiredFile} must remain removed`,
    );
  }
  const auditedSources = [
    "javascript/iroha_js/README.md",
    "javascript/iroha_js/index.d.ts",
    "javascript/iroha_js/package.json",
    "javascript/iroha_js/smart-contract-deployment.d.ts",
    "javascript/iroha_js/scripts/run-test-profile.mjs",
    "javascript/iroha_js/src/browser.js",
    "javascript/iroha_js/src/index.js",
    "javascript/iroha_js/src/smartContractDeployment.js",
    ".github/workflows/kotodama_perf.yml",
  ];
  for (const relativePath of auditedSources) {
    const source = readRepositoryFile(relativePath);
    assert.equal(source.includes(retiredSubpath), false, `${relativePath} has retired export`);
    assert.equal(source.includes(retiredSelector), false, `${relativePath} has retired selector`);
    assert.equal(
      source.includes(retiredVerifierOption),
      false,
      `${relativePath} has retired verifier option`,
    );
  }
});

test("release workflows require platform provenance, heavy, and SoraFS native lanes", () => {
  const kotodamaWorkflow = readRepositoryFile(".github/workflows/kotodama_perf.yml");
  for (const required of [
    '      - "javascript/iroha_js/**"',
    '      - "scripts/sorafs_javascript_native_cache.mjs"',
    "os: [ubuntu-latest, macos-latest, windows-latest]",
    "npm run test:native-provenance --prefix javascript/iroha_js",
  ]) {
    assert.ok(kotodamaWorkflow.includes(required), `Kotodama workflow must contain ${required}`);
  }

  assert.match(
    readRepositoryFile("ci/check_sorafs_fixtures.sh"),
    /node scripts\/run-test-profile\.mjs heavy/u,
  );
  assert.match(
    readRepositoryFile("ci/sdk_sorafs_orchestrator.sh"),
    /node scripts\/run-test-profile\.mjs sorafs-native/u,
  );
  const privacyWorkflow = readRepositoryFile(".github/workflows/pr_privacy_sdk_guard.yml");
  for (const path of [
    "javascript/iroha_js/src/boundedByteSnapshot.js",
    "javascript/iroha_js/src/validationFeeTrust.js",
    "javascript/iroha_js/src/sorafsOrderbookPreflight.js",
    "javascript/iroha_js/src/sorafsOrderbookSubmission.js",
    "javascript/iroha_js/src/sorafsOrderbookSubmissionBytes.js",
    "javascript/iroha_js/src/sorafsOrderbookSubmission.d.ts",
    "javascript/iroha_js/test/sorafsOrderbookPreflight.test.js",
    "javascript/iroha_js/test/validationFeeTrustCapture.test.js",
    "javascript/iroha_js/test/sorafsOrderbookSubmission.test.js",
    "javascript/iroha_js/test/sorafsOrderbookSubmissionBytes.test.js",
    "javascript/iroha_js/test/sorafsNativeSuites/**",
    "javascript/iroha_js/test/helpers/nativeRequirements.js",
    "javascript/iroha_js/test/helpers/native.js",
    "scripts/sorafs_javascript_native_cache.mjs",
    "javascript/iroha_js/test/sorafsNativeCache.test.js",
    "javascript/iroha_js/test/sorafsNativeSuiteStructure.test.js",
    "javascript/iroha_js/test/helpers/sorafsNativeSuiteContract.js",
    "javascript/iroha_js/test/fixtures/sorafs_native_suite_contract_v1.json",
  ]) {
    assert.ok(privacyWorkflow.includes(`- \"${path}\"`), `${path} must trigger ABI-29 checks`);
  }
});
