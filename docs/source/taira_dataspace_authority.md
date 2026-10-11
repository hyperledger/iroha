# Retained dataspace authority originals

A successful `iroha dataspace status` invocation can export the exact public
originals needed to authenticate a completed allocation:

```sh
iroha --config /private/original-client.toml dataspace status /private/definition.toml \
  --trust /private/original-trust.json --state /private/dataspace-state \
  --export-authority /private/fresh-authority-bundle
```

Export requires that invocation's completed three-phase allocation verification.
Pending status cannot export. The destination must be a fresh direct directory in
private current-owner custody. It contains `authority.json`, its exact inventoried
public originals, and a zero-byte `lock` owned by the current user with mode 0600.
No account private key, validator configuration, binary, or credentials are exported.

After a preserved-state runtime update, status additionally uses
`--verification-runtime-update /private/runtime/taira-public-reset/update-<id>`.
By default the verifier must be the actual compiled candidate CLI. A separately
admitted newer verifier may instead select the target using the paired
`--verification-source-commit <commit>` and `--verification-source-version <version>`
from the same independently authenticated source. This explicit pair is accepted
only for read-only status with the actual Linux runtime-update operation. Native
still measures and holds the target binaries, original receipts, root ownership,
retained configuration/state, installed units and exact running processes. The
four signed peer attestations must match the target build fingerprint computed
from that source commit and version. Verifier provenance remains the caller's
independent release authority; it does not become target provenance.

The portable verifier consumes the exported originals with separately selected
trust and source:

```sh
iroha dataspace verify-authority --bundle /private/fresh-authority-bundle \
  --trust /private/original-trust.json --source-commit <authenticated-target-commit> \
  --source-version <version-from-that-source> --output /private/fresh-result.json
```

This command is credential-free and performs no network or signing operations.
It rejects unrelated/missing originals, changed hashes, indirect files, partial
runtime receipts, changed trust, source mismatches and noncanonical inventories.
The one native replay checks the signed preparations, exact dispatch claims,
fee bounds, contiguous genesis-anchored finality, four challenge-bound peer
attestations, successful transaction input/output inclusion and exact executed
carrier bytes. Runtime-update public receipts prove their semantic joins only;
portable verification makes no claim about historical or present host custody.

All numeric projection values are canonical decimal strings, including 64-bit
dataspace IDs and block heights. The returned JSON is diagnostic output, never
an admission credential. Saved output must not replace fresh original replay.
It does not prove source signatures, current network readiness, current validator
processes or a subsequent asset deployment.

Installed Rust consumers call the same implementation through
`iroha_cli::verify_dataspace_authority_originals`. Inputs are exact `authority.json`
bytes, a `BTreeMap<String, Vec<u8>>` of exactly its inventoried originals, independent
trust bytes, and the authenticated target source commit/version. The returned
`VerifiedDataspaceAuthority` has private fields and no deserializer or public
constructor. Its typed getters and diagnostic projection are available only after
successful replay. The caller retains original custody and verifies signed source,
source object relationships, release authority and any application-specific joins.
