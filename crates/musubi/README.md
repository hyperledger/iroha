# Musubi

Musubi owns Kotodama package resolution, compilation, publication and contract deployment
adapters. The canonical compiler is `kotodama_lang`; signed deployment, fees and finality
belong to `iroha_contract_deploy`.

`deployment_runtime::DeploymentRuntime::new(config, journal_root, cache_root)` requires an
already resolved SDK configuration and explicit private journal/cache roots; deployment selects
its alias scope separately. It compiles `.ko`, verifies `.to`, or builds an explicit Musubi package
without discovering a client configuration, wallet or operating-system user cache. Source,
bytecode and local-only package builds do not open a cache. Managed Kagami and Mochi retain the
original generation's `PreparedLocalnet::build_cache_root()` path for both authenticated resolver
records and immutable archives, including private roots. Cold registry dependencies additionally
require the exact prepared archive transport.

The native SDK's `get_provider_discovery` verifies current provider authority and its exact
signed advert against an independently selected finality decision and qualified native World
schema. The bounded projection includes the complete current World hash preimages and exact
admission heads/owner, so a historical admission cannot conceal a later revocation.

`with_build_registry_resolver` supplies an explicitly selected registry only after local-only
resolution fails. A private child uses its retained parent registry identity and parent account;
absence never selects the child's registry. An unchanged locked graph whose sources authenticate
in the immutable cache requires no registry or provider HTTP once that explicit binding is resolved.

Account-mode archive fetching uses the existing storage transport and stream-token issuer.
The provider must explicitly admit the `registered_account_read` capability: an exact HTTPS
DNS origin on its admitted nonzero port and finite token limits for registered-account reads of its immutable objects.
The same finalized projection authenticates the current StreamToken custody record and original
signed enrollment, including expiry and revocation. Every token mint and replacement reobserves
the same authority; a retired key cannot refresh an earlier session. Provider requests carry fresh canonical account
signatures; parent listener tokens and unrelated HTTP credentials are never forwarded. Providers
without this policy remain unavailable to account-mode downloads.

TODO: Qualify the composed cold-cache workflow against an admitted provider, including revocation
during issuance, expiry, cancellation, and adversarial DNS rebinding. Component tests do not establish
whole-service readiness. Existing archive commitments, strict token signatures, bounded CAR
verification, pinned public DNS and immutable cache checks remain authoritative.

`ContractInput::from_path` captures the original native regular `.ko`, `.to`, or explicitly
selected package manifest before a frontend provisions a network. Parent paths resolve at
selection; the selected leaf is never followed through a link. The original native file and its
ancestors stay retained through build, and changed/replaced roots are refused. Descriptor reads
use explicit offsets so repeat builds do not depend on a shared cursor. Declared companions and
package members/dependencies still use their existing fresh, bounded selection owners; this
capture does not claim custody of an entire project before it is read. Selecting a member
manifest or member directory deploys that member by default and refuses `--package` for
another member. Selecting the actual workspace-root manifest or directory keeps the declared
workspace defaults and explicit package selection, including roots which also declare a package.

Generated publication profiles initialize their empty client journal directory before the generation
is published. Begin, Resume and Recover require that original custody before namespace or registry
HTTP; losing either directory refuses the action without recreating history. The shared service
crate owns directory placement, while Musubi remains the sole operation-journal and sidecar owner.

Deployment retains exact bytes and signed transactions before dispatch. A repeated identical
request resumes its pending journal; a completed request returns its receipt only after
authenticated current alias and artifact readback. Changed input cannot replace unresolved
work. Slot and journal locks serialize concurrent writers; recovery binds the journal location
to its authenticated target and exact commit. Both fresh deployment and recovery require the
caller's scope and fee review before execution. Each reopened journal must match
that complete original review, including ordered signed hashes and fee quotes;
replacing it with another valid plan is refused before network reads or dispatch. Execution failures show their public cause and
exact recovery journal together, while preserving the native error type for callers. The shared
slot publishes a bounded `Empty` / `Preparing { candidate, previous }` / `Active` record.
`Preparing` is durable before the native service atomically publishes the complete lock and signed
plan; `Active` is durable before dispatch. A retry reconciles this exact cutover before preparing
another plan. A truly absent candidate restores its recorded predecessor; partial or malformed
custody is retained and refused. Historical completed recovery never moves the active slot backward.
Existing slots require their original named lock and publication record; retired pointer layouts
are rejected. Fallible native progress observers recheck the original slot and journal locks
after user callbacks and before submission. Managed and package commands share the same original-plan retry admission. A package
`--prepare` retry returns the retained preflight and journal without dispatch; ordinary retry resumes
the same signed transactions. Package-command recovery holds the original package slot lock.

Focused validation: `cargo test -p musubi --lib deployment_runtime`.

`generated_publication::publish_generated` accepts the source-bound generated publication context,
an explicit package manifest, private publication state/cache roots, and the retained generated
archive transport. Generated Begin uses the shared local selection preflight: a member input
binds that member, while a workspace-root input keeps defaults and explicit selection; exactly
one member is required. Kagami and Mochi preflight before managed startup, and the canonical
publication entry validates selection again before namespace or publication effects. Begin
performs the owner-paid namespace binding through the existing wallet parent before resolving
a fresh publication graph. Exact current binding permits a read-only skip
only after the complete original parent census; missing custody is never recreated. Resume and
sidecar recovery retain the original request and do not authorize a new namespace transaction.
Generated TLS selection and fresh native provider discovery remain in the sole archive transport;
this entry never reconstructs that transport from TOML or selects an operating-system user cache.
The ordinary CLI and generated entry share one publication engine and redacting command output.

TODO: Execute the generated three-provider cold publication, detach/restart recovery and subsequent
cold package fetch against the composed native candidate. Source and component controls alone do
not establish publication or service readiness.

## Local compilation

`Musubi.toml` and `Musubi.lock` are the sole persisted project contract. `koto` compiles
standalone sources with an optional `--source-root`; package resolution, project tests and
project editor sessions use Musubi. Local builds use the `dev` output profile in both tools;
`--profile NAME` selects an output directory. Deployment and invocation builds explicitly
select `production`. Profiles name output/cache locations; compiler policy stays explicit.

A compiled contract import such as `import seiyaku "./interfaces/pool.to" as Pool;`
reads the complete admitted artifact from the importing source's package. Source collection and
packaging follow this declaration, include the exact binary bytes in the package commitment,
and preserve separate inventories for locked dependencies. Builds and editor reloads reject
missing artifacts, paths outside the source owner, and invalid embedded interfaces; a loose JSON
manifest does not substitute for the `.to` artifact.

`musubi lsp --manifest-path Musubi.toml` serves selected contract and library targets through the
same authenticated source graphs used by builds. Library-only projects retain their package
identity, declared exports and locked dependency bindings. Unsaved local source and TOML buffers retain
exact source identities and export token spans. Shared modules require a unique target or
`--contract NAME` for semantic requests; diagnostics include all targets. Reloads validate the
existing lock without silently changing dependencies. Save dependency changes and run
`musubi check` before reloading the editor. Test lenses invoke `musubi test` with the exact
manifest, package, contract, test filter and lock context; `musubi test --contract NAME
--filter TEST --exact` also runs that selection directly.

`musubi check`, `musubi build` and `musubi test` compile for the data-model default
account-address profile (SORA, `0x02F1` = 753) unless a network binding or
`--chain-discriminant` selects another one; `koto` uses the same default, so address
literals compile identically in both tools. `--zk` enables the Kotodama ZK surface for
the selected contracts and tests. `musubi new <dir>` creates a counter seiyaku named
after the package, four tests, a README and `.gitignore`; `--namespace` defaults to
`local`, which `musubi publish` refuses until `[package] namespace` names a registry
namespace you own.

Kotodama lints warn by default. A `[lints]` table in `Musubi.toml` sets a level per lint
name, and `deny-warnings = true` turns every warning into an error; a package without
`[lints]` uses its workspace root's table. `musubi check|build|test --deny-warnings` does
the same for one run. A denied lint fails the command with `MUSUBI_E_COMPILER`:

```toml
[lints]
unused-local = "deny"
exact-division = "allow"
deny-warnings = false
```

Unknown lint names are manifest errors that name the closest lint; `koto explain --list`
lists them all.

Path dependencies stay below one workspace root. For two standalone sibling packages,
`musubi add <alias> --path ../<dir> --create-workspace` writes the shared parent
`Musubi.toml` listing both as members before adding the dependency; it refuses packages
that already hold network bindings, deployment or call journals, or publication state,
because that state is scoped to the old root. A member's earlier `Musubi.lock` is no
longer read once the workspace exists, and the command lists each one to delete.

## SDK bindings

`musubi bindgen contract.to --language typescript|swift|kotlin --out PATH` generates SDK
request models and checked result decoders from the complete admitted artifact. It does not
read a loose manifest or resolve a project. `--name SEED` selects the generated namespace
seed; the default is the artifact filename stem. Output replaces one file atomically in an
existing directory and cannot replace the input artifact.

Generated entrypoint builders return distinct `ViewRequest`, `KotoageRequest`,
`HajimariRequest` or `KaizenRequest` types, each carrying the exact code hash, signed ordinal,
selector and schemas. The application checks that code hash against the target's current
binding and chooses the corresponding view, call, activation or upgrade workflow. The
generator does not sign transactions or choose fees. Its payloads integrate with the SDK's
existing contract request API; its `decodeResult` validates the returned value before
constructing typed products, enums and sums. Lossless `KotodamaInt`, `KotodamaDecimal` and
`KotodamaQuantity` reuse the existing SDK numeric codecs. TypeScript follows the JavaScript
SDK's safe-integer JSON limit for `DataSpaceId`; Swift and Kotlin preserve the full unsigned
64-bit dataspace domain.

Nominal identities remain distinct across package owners. Generated identifier escaping is
injective and signed ordinals keep entrypoint names collision-free. The unmodified wire
names and full nominal identities appear in the generated metadata and comments.

Focused validation: `cargo test -p musubi --lib bindgen`. Setting the developer-only test
variable `MUSUBI_BINDGEN_CAPTURE_DIR` retains the compiler-produced sample bindings for
compilation against the corresponding installed SDKs; it does not change production behavior.

## Command output and exit codes

`--format human` (default) writes success to stdout and failures to stderr. `--format json`
writes one `musubi-cli-output` document to stdout; compiler failures carry the canonical
Kotodama diagnostic records (codes, spans, labels, notes, help and fixes) under
`error.diagnostics`. `--format sarif` (`check`, `build` and `test` only) writes one SARIF
2.1.0 document with the same diagnostics. Sources of local workspace packages are named by
their path from the workspace root (for example `feemath/src/lib.ko`); registry package
sources keep their package identity. Test-source parse and compilation failures use the
same structured records, including machine-applicable fixes. The exit status does not depend
on the format:

| Status | Codes |
| --- | --- |
| 0 | success |
| 2 | `MUSUBI_E_USAGE`, `MUSUBI_E_MANIFEST_INVALID`, `MUSUBI_E_WORKSPACE_INVALID` |
| 3 | `MUSUBI_E_LOCKFILE_INVALID`, `MUSUBI_E_LOCKFILE_LEGACY`, `MUSUBI_E_LOCKED` |
| 4 | `MUSUBI_E_OFFLINE_MISS`, `MUSUBI_E_RESOLUTION_CONFLICT`, `MUSUBI_E_DEPENDENCY_CYCLE` |
| 5 | `MUSUBI_E_REGISTRY`, `MUSUBI_E_NETWORK` |
| 6 | `MUSUBI_E_UNAUTHORIZED`, `MUSUBI_E_GOVERNANCE` |
| 7 | `MUSUBI_E_PACKAGE_INVALID`, `MUSUBI_E_ARCHIVE_INVALID`, `MUSUBI_E_CACHE_CORRUPT` |
| 8 | `MUSUBI_E_COMPILER` (source, link or test compilation rejected) |
| 9 | `MUSUBI_E_PUBLISH` |
| 10 | `MUSUBI_E_IO` |
| 11 | `MUSUBI_E_TEST_FAILED` (tests compiled and ran, and at least one failed) |
| 70 | `MUSUBI_E_INTERNAL` |

## Deployment, activation and calls

`musubi deploy` rebuilds the declared contract from its locked source. With
`--artifact <file.to> --artifact-manifest <file.manifest.json>` it deploys that exact
prebuilt artifact only when the locked build reproduces its code and ABI hashes. A
seiyaku that declares `hajimari`/`始まり` rejects every other call and view until the
hook runs: `musubi deploy --activate [--args JSON]` checks the arguments against the hook's
schema before anything is signed, then runs it as a recoverable call after the deployment
is Applied. Otherwise the deploy output prints the exact activation command; for a hook
that takes arguments, its `--args` lists every parameter with a `<type>` placeholder to
replace. Its JSON `activation.status` is `pending` when this command completed the
deployment and `unverified` when it returns an earlier completed deployment whose hook may
already have run. `call`, `view` and `deploy --activate` all take named arguments with `--args
JSON` or `--args-file PATH`.

Every `kotoage` and `view` states `authorize(anyone)` or a declared permission,
before any `-> ReturnType`. `permission Increment;` declares an instance role;
its native grant is `CanUseContractPermission` with the exact `contract` address
and `permission: "Increment"`. `import permission "SharedOperators" as Operator;`
explicitly imports a chain permission and `authorize(Operator)` requires its exact
null-payload token. A declaration name that is not in the signed table is rejected.

The scaffold's complete flow is to deploy, grant its `Increment` role, activate
`hajimari`, then call `increment`. Use the live instance owner or an exact role holder
to submit the following permission JSON to
`iroha account permission grant --id <CALLER>` (replace `<CONTRACT_ADDRESS>` with
the deployment receipt's address):

```json
{"name":"CanUseContractPermission","payload":{"contract":"<CONTRACT_ADDRESS>","permission":"Increment"}}
```

Run the activation command printed by `musubi deploy`, then
`musubi call --entrypoint increment --args '{"step":"1"}'` with the configured fee
authorization. `musubi deploy --activate` combines deployment and activation; the
role grant may follow activation when the hook does not require that role. Missing
instance or imported permissions stop a call with the exact token to grant. Only
the exact lifecycle token can be granted automatically by the call workflow.

Ingress authorization checks the caller. Ledger effects execute as the contract
subject and need that subject's separate effect permissions. A contract method
using `ledger::seiyaku::grant_permission` must itself already hold the exact role it
delegates; a caller's role does not transfer to the contract subject. The instance
owner can root-grant that role to the subject. Fixtures model these independently
with `grant_seiyaku_permission(actor, "Increment")`,
`grant_seiyaku_lifecycle_permission(actor, "hajimari")`, and
`grant_seiyaku_permission(seiyaku_subject, "Increment")`.

`musubi call` simulates the call on current state before signing. A rejected simulation
stops the call; otherwise the signature-bound gas limit is the simulated gas plus half
again and a fixed margin, unless `--gas-limit` chooses one. A call that first grants its
own lifecycle permission cannot be simulated beforehand and uses 1,500,000 gas unless
`--gas-limit` is given. Every Applied stage in deployment and call receipts records the
gas used and fee settled by its committed fee receipt when the node reports it; that
charge is reporting evidence and never gates finality or recovery.

Mutable calls require finite aggregate fee authorization. Use the selected network's
configured maxima or supply `musubi call --entrypoint SELECTOR --max-fee-asset ASSET
--max-fee AMOUNT`. The shared native owner quotes, signs and retains the optional
exact self-grant and call before either is sent. Both expire within the original
sixty-second authorization; `--resume JOURNAL` reconciles those exact hashes without
rebuilding, quoting or signing replacements. `DeploymentRuntime::current_deployment`
provides the verified current artifact and receipt for native alias-selected view/call
adapters and never creates a missing slot or repairs its records.
