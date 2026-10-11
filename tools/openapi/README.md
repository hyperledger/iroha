# Torii OpenAPI release tooling

This directory contains the code-coupled tooling for the canonical Torii
OpenAPI artifact in `artifacts/openapi/`. Public API documentation belongs in
the sibling `iroha-docs` repository.

`artifacts/openapi/torii.json` is the authored release authority. Runtime builds
embed an exact package-local mirror at
`crates/iroha_torii/assets/openapi/torii.json`, while
`artifacts/openapi/versions/current/torii.json` is the release alias. All three
files must remain byte-identical. Runtime parses this authority, installs
catalog security schemes, prunes disabled catalog operations, and serializes
the compiled projection. Retired schemas are absent from the authored authority.
Its response is not a claim that the authored JSON bytes were served unchanged.

The xtask and release wrappers load the static authority through a live Torii
router, validate its OpenAPI shape and route contract, and emit the bytes for
manifest handling. They are verification/replay tooling, not an independent
schema derivation path. Rust tests additionally bind the authority to the route
catalog, component references, operation effects, and production constants.

The checked-in artifact uses manifest contract version 2. The Rust verifier and
these Node tools reject legacy manifests, unknown fields, unsafe paths, and
digest or signature mismatches. `allowed_signers.json` is deliberately empty;
production operators must supply a separately governed Ed25519 allowlist.

## Cargo.lock pin owner

`release/openapi-cargo-lock-v1.txt` is generated metadata, not a second lock
authority. Derive it only from an explicit, stable Cargo.lock into an absolute
path outside the repository:

```bash
REPO_ROOT="$(pwd -P)"
OPENAPI_RUN_ROOT="$(mktemp -d /private/tmp/iroha-openapi-owner.XXXXXX)"
chmod 700 "${OPENAPI_RUN_ROOT}"
PIN_STAGE="${OPENAPI_RUN_ROOT}/openapi-cargo-lock-v1.txt"

node tools/openapi/scripts/provision-openapi-cargo-lock.mjs pin \
  --source="${REPO_ROOT}/Cargo.lock" \
  --output="${PIN_STAGE}"
node tools/openapi/scripts/provision-openapi-cargo-lock.mjs pin \
  --source="${REPO_ROOT}/Cargo.lock" \
  --check="${PIN_STAGE}"
```

The owner rejects relative paths, links, executable inputs, source races, and
repository output paths. It never edits `Cargo.lock` or the tracked pin.
Publish reviewed staged bytes through the repository's per-file preimage guard,
then run the `--check` form against the tracked pin. Rust and Node parse that
tracked file as the sole size and SHA-256 authority; no hash constant is
hand-maintained in either implementation.

`provision` is verification-only. It requires `Cargo.lock` to be one clean,
stage-zero mode-`100644` blob shared by the Git index and `HEAD`, with working
bytes matching that blob and the tracked pin. `--source` adds only a stable,
byte-identical comparison input; it never replaces the tracked root authority.
The provisioner never edits the checkout, starts Cargo, or generates lock
bytes. Release wrappers verify the lock already present in each isolated Git
clone. All Cargo work remains behind the shared `+1.93.1`, `--locked`,
`--offline`, `-j1` policy and its same-snapshot guard.

An unsigned dirty-tree replay may repair a stale pin only while `Cargo.lock`
still matches the mode-`100644` blob shared by `HEAD` and the index. The working
pin must exactly match the bytes compiled into `xtask`, and the dirty-source
digest binds that repair. Signed generation and clean release provenance still
require the committed lock and pin to agree.

## Unsigned authored-spec metadata

Update all three authored spec copies together without changing their bytes,
then commit the reviewed source. Plain `--unsigned-manifest` uses the Node
metadata owner on that exact clean checkout. It runs no Cargo command, creates
no clone or Cargo target, and does not execute the compiled Torii projection. The mandatory
native Torii tests validate the compiled projection separately; their evidence
must not be inferred from a successful metadata refresh.

The V2 manifest binds the actual clean commit, its commit timestamp, the source
inventory digest, and the exact authored artifact hashes. The recursive `tools`
entry in `release/openapi-generator-inputs-v1.txt` includes this generator and
its shared verifier. A separate `unsigned-authored-spec.json` receipt identifies
this owner and explicitly records `runtime_projection: "not_executed"`. No
xtask command identity, router result, or signature is invented.

Use an empty owner-private output directory below `<run>/artifacts`. The owner
preserves historical public versions, checks the existing real V2 release-input
verifier against the complete staged tree, rechecks source and destination,
then publishes by one directory rename. Validation failures leave the output
empty. Existing output contents are rejected. Callers overriding either
`IROHA_RELEASE_ARTIFACT_ROOT` or `IROHA_RELEASE_CANCEL_REQUEST_PATH` must provide both;
cancellation remains cooperative at command boundaries.

```bash
OPENAPI_RUN_ROOT="$(mktemp -d /private/tmp/iroha-openapi-refresh.XXXXXX)"
chmod 700 "${OPENAPI_RUN_ROOT}"
OPENAPI_ARTIFACT_ROOT="${OPENAPI_RUN_ROOT}/artifacts"
OPENAPI_STAGE="${OPENAPI_ARTIFACT_ROOT}/openapi"
mkdir -m 700 "${OPENAPI_ARTIFACT_ROOT}" "${OPENAPI_STAGE}"
export IROHA_RELEASE_ARTIFACT_ROOT="${OPENAPI_ARTIFACT_ROOT}"
export IROHA_RELEASE_CANCEL_REQUEST_PATH="${OPENAPI_RUN_ROOT}/cancel-request.json"

bash ci/run_openapi_generator.sh \
  --output-dir "${OPENAPI_STAGE}" \
  --unsigned-manifest
node tools/openapi/scripts/verify-openapi-versions.mjs \
  --output-dir="${OPENAPI_STAGE}" --allow-unsigned
npm --prefix tools/openapi test
```

Unsigned artifacts are for development only. Review and publish the five JSON
outputs listed in `generated-files.toml`; retain the receipt as run evidence and
leave `allowed_signers.json` and the package mirror unchanged. Commit only those
metadata outputs after the clean generator commit. The existing release-input
verifier admits that later output-only commit through its ancestor/source-tree
contract, without changing the native binary identity or rebuilding Rust.

## Release signing

Release signing is detached-only: private keys remain encrypted and runtime-only in the external software signer
custody. First commit the complete generator input tree. At that clean commit,
create private out-of-tree staging, copy the existing artifact baseline, and
emit the deterministic signing payload:

```bash
OPENAPI_RUN_ROOT="$(mktemp -d /private/tmp/iroha-openapi-sign.XXXXXX)"
chmod 700 "${OPENAPI_RUN_ROOT}"
OPENAPI_ARTIFACT_ROOT="${OPENAPI_RUN_ROOT}/artifacts"
OPENAPI_STAGE="${OPENAPI_ARTIFACT_ROOT}/openapi"
OPERATOR_STAGE="${OPENAPI_ARTIFACT_ROOT}/operator"
mkdir -m 700 \
  "${OPENAPI_ARTIFACT_ROOT}" "${OPENAPI_STAGE}" "${OPERATOR_STAGE}"
cp -R artifacts/openapi/. "${OPENAPI_STAGE}/"
export IROHA_RELEASE_ARTIFACT_ROOT="${OPENAPI_ARTIFACT_ROOT}"
export IROHA_RELEASE_CANCEL_REQUEST_PATH="${OPENAPI_RUN_ROOT}/cancel-request.json"

bash ci/run_openapi_generator.sh \
  --output-dir "${OPENAPI_STAGE}" \
  --unsigned-manifest \
  --signing-payload "${OPERATOR_STAGE}/openapi-manifest-v2.payload"
```

After the external software signer returns an Ed25519 signature envelope,
replay and emit from the same source state, then attach it:

```bash
chmod 600 "${OPERATOR_STAGE}/openapi-manifest-v2.signature.json"
bash ci/run_openapi_generator.sh \
  --output-dir "${OPENAPI_STAGE}" \
  --signature-envelope "${OPERATOR_STAGE}/openapi-manifest-v2.signature.json"

node tools/openapi/scripts/sync-openapi.mjs \
  --version=current --latest \
  --allowed-signers=<absolute-operator-allowlist-path> \
  --output-dir="${OPENAPI_STAGE}"

OPENAPI_REQUIRE_SIGNED=1 \
OPENAPI_ALLOWED_SIGNERS_FILE=<absolute-operator-allowlist-path> \
  bash ci/check_openapi_spec.sh
```

`ci/check_openapi_spec.sh` requires clean release provenance; byte-identical
root, current, package-local, and compiled-projection authority bytes; deterministic
replay from two independent sealed candidate mirrors; private out-of-tree
targets and staging; and exact agreement with
`release/openapi-generator-inputs-v1.txt`. It retains
the replay bundles and a commit/tree identity receipt below the authenticated
artifact root. A valid release therefore uses a reviewed clean source-input
commit followed by an output-bearing candidate commit. Both standalone scripts
publish their final source-identity receipt only between cooperative
before/after completion boundaries below that authenticated root.
