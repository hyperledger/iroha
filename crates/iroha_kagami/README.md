# Kagami

Kagami provides managed developer networks and native contract deployment, plus
operator tooling for genesis, validator keys, and inspection. Managed commands
use the shared `iroha_deploy` engine and Musubi deployment service.

## Build

From anywhere in the repository, run:

```bash
cargo build --bin kagami
```

This places `kagami` in `target/debug/` from the repository root.

The native CLI package builds the matching `iroha` client, Kagami worker and
standard daemon together in one locked Cargo invocation:

```bash
cargo xtask kagami-bundle --profile debug
```

It publishes `target/kagami-bundle/kagami-<os>-<arch>-debug/bin/{iroha,kagami,iroha3d}`
with a sorted hash inventory. Use a fresh `--out` directory for another immutable
package. The default release command requires the exact committed public preset at
`defaults/developer/network-profiles.nrt`, including Taira, through the same release
selector as Mochi. It refuses missing release input or a caller replacement before
building or creating output. The approved artifact remains a release-owner prerequisite;
the packager creates no signing authority. Debug packages may omit presets or use
`--network-profiles <artifact.nrt>` for explicit development input. The manifest retains
the selected image digest and public source provenance. Use the packaged `iroha` for
network and dataspace deployment and recovery so the client matches the worker and daemon.
The CLI package requires no Mochi desktop;
`cargo xtask mochi-bundle` remains the separate desktop application packager.

Kagami always includes the BLS validator tooling required by Sumeragi.
Optional crypto features come from `iroha_crypto`:

- `--features gost` enables the TC26 GOST R 34.10-2012 parameter sets
- `--features sm` enables SM2 tooling

Example:

```bash
cargo build --bin kagami --features "gost,sm"
```

## Help

- Full generated CLI reference: [CommandLineHelp.md](CommandLineHelp.md)
- Regenerate CLI help from the repository root with `scripts/tests/consistency.sh --update cli-help`.
  Its guarded producer stages successful output before replacing each snapshot.

## Quickstart

Start or resume a four-validator localnet without supplying configuration:

```bash
kagami localnet up
kagami contract deploy hello.ko
kagami localnet down
```

Install the native CLI package with `kagami` and `iroha3d` side by side.
State and credentials live outside the project in a private workspace-scoped
store. `down` retains the ledger; `localnet reset local` deliberately retires it.
`contract deploy` also accepts `.to` or a Musubi package directory and starts the
default localnet when no context has been selected. Use `context list`,
`context show`, or `context use NAME` to inspect or select retained environments.

For contracts declaring `hajimari`/`始まり`, the deployment result includes the
canonical hook name and parameter types. Deployment does not invoke that hook;
run it before other calls or views if it has not already succeeded. Repeat and
resume results do not infer its current state from the artifact.

`kagami package publish .` explicitly publishes a Musubi package using the retained generated
developer client and its `dev.universal` namespace intent. Begin may start the default localnet;
`--resume OPERATION_ID` and `--recover OPERATION_ID` require its existing selected context.
An explicit member manifest or directory selects that member; `--package dev.universal/NAME`
must match it. A workspace-root input keeps declared defaults and explicit package selection.
Begin requires exactly one selected member and validates that selection before managed startup.
`--detach` returns at the canonical durable seed-ingress boundary. Manifest namespaces are
never rewritten. Original namespace
custody, generation-bound publication/cache roots and the prepared native archive transport are
shared with `mochi_core::developer::DeveloperWorkspace::publish_package`. Neither frontend accepts
a replacement client TOML, copies a manager key into a daemon, or changes contract deployment.
The canonical publication outcome supplies human/JSON rendering and process status. Complete
three-provider publication and cold-package runtime qualification remain acceptance gates.

Private dataspaces use an independently pinned network profile installed with the
native bundle. `kagami dataspace networks` lists the available names. With a
qualified parent profile installed, the command surface is:

```bash
kagami dataspace up privateapp --network taira
kagami dataspace status
kagami contract deploy counter.ko --alias Counter::privateapp
kagami contract call Counter::privateapp --entrypoint hajimari --max-fee 1000
kagami contract call Counter::privateapp --entrypoint set --args '{"next":"7"}' --max-fee 1000 --readback current
kagami contract view Counter::privateapp --entrypoint current
```

This retains four owner-private local validators, their original owner identity,
and exact parent-operation journals. One paid request leases the dataspace and
its owner's `admin@privateapp` alias without adding a parent execution lane.
`--account-alias LABEL` selects another canonical owner label before first
provisioning; changing it on retry is refused. The original two-lease rent quote
and fee allowance survive interrupted preparation. A timeout leaves that work
available for status and retry. Release installation, recurring Taira checkpoint publication
and combined runtime qualification remain tracked acceptance gates; the CLI invents no release key.

Views and calls use an existing selected context and the verified deployed alias.
A call's positive `--max-fee` caps the combined self-grant and call in that private
root's native fee asset. `--timeout` fixes the original authorization and signed
expiry; `--prepare` retains both signed stages without dispatch. Recover the exact
printed journal with `kagami contract call --resume JOURNAL`; recovery does not
quote or sign replacement transactions. `--readback SELECTOR` observes an explicit
view after local `Applied`; the separate parent observation remains historical.

The [developer acceptance goals](../../specs/kagami_mochi_devex_goals.md) track
remaining native-platform, private-dataspace, and end-to-end qualification.

Existing Sora network / observer peer config, guided:

```bash
kagami wizard
```

Direct disposable localnet, permissioned by default:

```bash
kagami localnet generate --peers 4 --out-dir ./localnet
```

Direct NPoS localnet:

```bash
kagami localnet generate --consensus-mode npos --peers 4 --out-dir ./localnet-npos
```

Docker Compose from one authoritative prepared bundle:

```bash
kagami localnet generate \
  --peers 4 \
  --out-dir ./localnet
kagami docker \
  --peers 4 \
  --config-dir ./localnet \
  --image hyperledger/iroha:dev \
  --out-file docker-compose.yml
docker compose -f docker-compose.yml up
```

`localnet generate` uses operating-system-random keys by default and refuses a non-empty
output directory. Pass `--seed` only for reproducible development fixtures.

Ed25519 or BLS keys:

```bash
kagami keys --algorithm ed25519 --out-dir ./key-custody
kagami keys --algorithm bls_normal --pop --out-dir ./validator-custody
```

`--out-dir` is required and must name a fresh directory. The generator atomically
publishes a complete mode-`0700` directory containing newline-terminated
`public.key` and owner-only `private.key` files. It refuses every existing
destination, including an empty directory, and never prints the private key.

The generator commands print a concise summary with generated paths and the
next handoff. `localnet generate` and `wizard` also emit a generated `README.md`
into the output directory.

## Main Flows

`kagami localnet up|status|logs|down|reset`
- Uses one retained generation and native supervisor per managed environment.
- Generates independent validator and developer identities, loopback ports,
  signed genesis, fixed-name runtime seeds, and private node/client configuration.
- Readiness requires all four validators and a signed committed smoke transaction.
- Native control IPC authenticates the owner; numeric PID files do not establish
  process ownership.
- Logs are bounded; `--json` returns public connection metadata with progress on stderr.
- Failed startup preserves its nonzero result and reports any retained status. JSON recovery
  actions contain exact argument arrays bound to the opened state store; reset reports the
  matching next startup action. Human output lists the action, name and state path separately.

`kagami dataspace up ALIAS --network NETWORK`
- Uses the installed parent profile and retains the original attachment work for recovery.
- Defaults to the exact alias as its local context name, including valid 63-character labels.
  `--name` selects an explicit context; managed names allow 1..63 ASCII letters, digits, `-`
  or `_`, starting with a letter or digit. Kagami and Mochi use the same shared name bound.
- Failed attachment reports any retained child and parent status separately, plus exact
  `dataspace status` and `localnet logs` actions for the requested context and state store.
  Observation or output failures preserve the original startup error and nonzero result.

`kagami contract deploy`
- Compiles `.ko`, verifies `.to`, or resolves a Musubi package through shared services.
- Derives a contract alias inside the selected environment's authorized dataspace.
- Quotes exact fees, retains signed transactions before dispatch, and verifies
  Applied evidence and artifact/alias readback before reporting completion.
- `--resume JOURNAL` recovers the original operation without rebuilding or signing
  replacements. Identical repeated deployments reconcile their retained operation.

`kagami wizard`
- Guided observer-onboarding flow for the existing Sora Nexus network; use
  `localnet up` for a new local network
- Supports interactive and fully flag-driven non-interactive use
- Requires the operator-authenticated full validator peer/PoP roster encoded by
  the network's signed genesis; the generated local peer is not promoted to validator
- Stages `config.toml`, a non-signable `genesis.template.json` source, and a
  generated guide that requires the network-authoritative complete manifest,
  signed genesis block, and exact hash before showing the final `iroha3d`
  launch step

`kagami localnet generate`
- Bare-metal local network generator
- Requires an exact `3f + 1` validator count in `4..=31`, the Sumeragi global
  committee geometry
- Protects validator/client configs and runtime signer/token sidecars with
  owner-only permissions and emits a bundle-wide `.gitignore`
- Emits `genesis.signed.nrt`, `genesis.public_key`, and
  `genesis.expected_hash` as a cross-checked runtime bundle. The latter contains
  one canonical checked `hash:<64 uppercase hex>#<CRC16>` NetworkId literal.
  An owner-only `genesis.private_key` is never mounted by generated Compose files
- Fresh-custody bundles keep directories and lifecycle scripts at `0700`, all
  other files at `0600`, and lifecycle scripts enforce `umask 077` for new
  logs and runtime state. Generic localnets retain pidfiles; Taira emits only
  exact mode-`0600` process records and rejects legacy pidfiles.
- Defaults to `permissioned` unless a Sora profile or perf preset requires
  `npos`
- `--sora-profile nexus` enforces public-dataspace rules and requires `npos`
- `--sora-profile dataspace --private-dataspace bpng --consensus-mode npos`
  generates the isolated BPNG physical dataspace `8648377547929788715` on local
  lane `5`, its four-validator restricted manifest, and paid `bpng` and
  `mibank.bpng` namespaces in genesis before signing. The preset assigns no
  public Taira allocation. BPNG application contracts, fee sponsorship and
  application service provisioning remain separate unfinished work.

`kagami docker`
- Docker Compose generator for an authoritative prepared bundle from
  `kagami localnet generate` (or equivalent peer configs plus signed genesis artifacts)
- Normal mode omits `--seed`: Kagami parses every `peerN.toml` without ambient
  environment overrides, rejects `extends`, and verifies the exact signed
  genesis, manifest, expected hash, verifier key, validator identities, trusted
  roster, and PoPs as one binding. It does not generate replacement validator
  identities.
- Kagami proves that each container-safe projection preserves the Sumeragi,
  execution-policy, and Nexus/AMX fingerprints, mounts the projected TOML as a
  file-backed Compose secret, and passes its BLAKE3 digest to `irohad` for a
  read-hash-parse startup check. Validator keys and private onboarding/faucet
  files are absent from Compose YAML and environment variables; the latter are
  mounted as separate Compose secrets.
- Byte-exact public policy assets are interned by digest as base64 Compose
  configs and decoded into `/config/runtime` before `iroha3d` starts. Prepared
  Compose accepts fresh state only, uses named validator storage volumes, never
  migrates live state, resolves relative source-state paths and omitted
  defaults against the prepared bundle directory for freshness checks, and
  fails closed on unsupported transport, CIDR-filter, or helper-service modes.
- `--seed` is an explicit deterministic development mode for relocatable sample
  manifests. That mode requires `IROHA_GENESIS_SIGNED_FILE`,
  `IROHA_GENESIS_PUBLIC_KEY_FILE`, and `IROHA_GENESIS_EXPECTED_HASH_FILE` when
  Compose is evaluated; those artifacts must match the seeded validator roster.

`kagami genesis`
- Power-user genesis generation, explicit source-template materialization, PoP
  embedding, validation, normalization, and signing helpers

`kagami verify`
- Profile-aware genesis verification for shipped Iroha 3 profiles

`kagami advanced`
- Low-level helpers that are not part of the main onboarding path:
  `client-configs`, `codec`, `kura`, `schema`, and `markdown-help`

## Iroha 3 Profiles

- Run `cargo xtask kagami-profiles --xor-allocations-dir <ALLOCATIONS_DIR>` to emit operator-owned bundles for
  `iroha3-dev` and `iroha3-nexus` under
  `defaults/kagami/<profile>/`
- Each generated bundle includes:
  - `genesis.json`
  - `verify.txt`
  - `config.toml`
  - `docker-compose.yml`
  - `README.md`
- Checked-in `genesis.template.json` files deliberately omit their consensus
  fingerprint and NPoS XOR pin and cannot be validated, signed, or used by a
  node. Materialize one explicitly with `kagami genesis materialize
  <SOURCE.template.json> --xor-asset-definition-id <CANONICAL_XOR_ID>` for NPoS, or generate a
  complete profile bundle with the command above. The XOR identity is committed
  in NPoS parameters; Taira uses `6TEAJqbb8oEPmLncoNiMRbLEK6tw`, while Nexus requires
  its own operator-provisioned identity. Validator allocations must be explicitly
  supplied in genesis; signing and startup do not mint missing stake or faucet funds.
- For a disposable four-validator Taira deployment, use
  `python3 scripts/taira_devnet.py up --inrou-canary-dir <owner-only-workspace>`;
  use its `check` and `down` subcommands
  for inspection and teardown. The low-level `iroha3-taira` Kagami profile
  remains available for manifest generation and verification, targets the live
  Taira chain id, requires NPoS, and requires `--vrf-seed-hex`. Disposable
  Taira lifecycle scripts require Linux pidfd/procfs APIs and deliberately have
  no `ps`, numeric-PID signal, shell-kill, or non-Linux fallback.

See [specs/kagami_profiles.md](../../specs/kagami_profiles.md) for
the profile-specific defaults.

## Validator PoP and Genesis Signing

Generate BLS validator keys and PoPs:

```bash
target/debug/kagami keys --algorithm bls_normal --pop --out-dir ./validator-a
target/debug/kagami keys --algorithm bls_normal --pop --out-dir ./validator-b
target/debug/kagami keys --algorithm bls_normal --pop --out-dir ./validator-c
target/debug/kagami keys --algorithm bls_normal --pop --out-dir ./validator-d
```

Each directory contains `public.key`, `private.key`, and `pop.hex`; the private
key is owner-only and is never printed to the terminal.

Generate a genesis JSON:

```bash
target/debug/kagami genesis generate \
  --profile iroha3-dev \
  --ivm-dir ./ivm_libs \
  --genesis-public-key ed25519:... \
  --consensus-mode permissioned \
  default
```

Sign with topology and PoPs:

Localnet generation partitions mixed asset and scoped namespace drafts before
staging and signing. Global permissions and subsequent account/asset registration
share the generated bootstrap phase. Scoped domain registration has its own input;
alias binding, global balance minting, ownership transfer and subsequent universal
service bootstrap continue in the next global input. Routing authenticates that
input against the original World before installing the asset alias. Normalization preserves authored
boundaries and refuses sources above the 11-input FASTPQ bootstrap limit. Generated
crypto and confidential parameters share one global metadata input. Structured
parameter, topology, and IVM trigger batches cannot be partitioned.

```bash
target/debug/kagami genesis sign \
  genesis.json \
  --topology "$TOPOLOGY_JSON" \
  --peer-pop "$PK_A=$POP_A" \
  --peer-pop "$PK_B=$POP_B" \
  --peer-pop "$PK_C=$POP_C" \
  --peer-pop "$PK_D=$POP_D" \
  --private-key-file "$GENESIS_PRIVATE_KEY_FILE" \
  --expected-public-key "$GENESIS_PUBLIC_KEY" \
  --out-file genesis.signed.nrt \
  --expected-hash-out genesis.expected_hash
```

`TOPOLOGY_JSON` must contain those same four validators at distinct canonical
addresses. First-release NPoS admission requires an exact `3f + 1` committee,
so a two-validator signing example is intentionally unsupported.

For a native AMX participant, the input manifest must already select its private
dataspace and parent network. Supply `--amx-global-chain-id`,
`--amx-global-genesis`, and `--amx-global-successor` together. The two files are
the parent's canonical signed genesis and its genuine committed H2. Core's
certified-prefix verifier authenticates them before one participant instruction
is appended and the private genesis is staged and signed. Existing transactions
remain intact; duplicate participant registration and outputs that alias either
source are rejected. Managed private preparation acquires and retains the selected
parent's original G1/H2 under its authenticated release; reopening uses the same
complete capsule and signed generation. Durable validator relaying remains open. `--config` uses the node configuration
loader, including compiled profiles and the generated `data_dir` layout; its
claimed genesis identity must still pass runtime validation.

AMX registration on the parent is a separate administrative action. After explicit
`kagami localnet down NAME`, run `kagami dataspace register-amx NAME --admin-config
PARENT_ADMIN_CONFIG --fee-asset ASSET_ID --max-fee AMOUNT --deadline-unix-ms
ORIGINAL_UTC_DEADLINE`. The retained inactive generation supplies the child;
`PARENT_ADMIN_CONFIG` supplies a separately selected parent signer whose native
execution must hold `CanSetParameters`. No SNS permission implies this authority.
`--timeout` bounds this turn's I/O to 1–60 seconds. Retry with the same signer,
source, fees and original UTC deadline: the create-only journal preserves one
signed transaction and authenticated successful or rejected carrier. A rejected
original is terminal and never re-signed after a grant. Authorizing a distinct new
attempt needs a separate owner/API that is not implemented here. Only the certified successful result is
registration evidence; status alone is insufficient. Ordinary `kagami localnet up
NAME` restarts the retained generation. Signing material stays runtime-only.
This action does not implement Prepared/Decision relaying or qualify full H2.

The one-line `genesis.expected_hash` output is the deployment trust root. It
carries the exact signed header hash as one canonical checked NetworkId literal.
Production templates select that same byte-exact file through validator
`genesis.expected_hash_file` and client `network_id_file`; do not copy the value
into independently rendered inline settings.

After an intentional genesis change, such as `iroha taira seat-parliament`, use
`genesis sign --replace-expected-hash '<PRIOR_NETWORK_ID>'` together with
`--expected-hash-out`, `--out-file`, `--bound-manifest-out`, and
`--nexus-context-output`. Seating prints
this command with the observed prior identity. Kagami locks and checks the
owner-held, single-link identity before output writes; a missing, stale, unsafe,
or concurrently held identity leaves the requested outputs unchanged. Without
this explicit option, publishing a different identity remains forbidden.

Replacement stages all four outputs, publishes the signed block, bound
manifest and the exact Nexus/AMX context preimage committed by the signed
genesis (`nexus-amx-context.v1.bin`), then publishes the identity last as a
commit marker. This is not a
multi-file atomic transaction. After interruption, consumers must reject any
bundle disagreement; retry the same command with the same prior identity. If
that prior is already stale, verify the exact signed block, manifest, and
published identity before proceeding. Do not rename identity files manually.

For seedless `kagami docker`, place that body and checked network identity beside the canonical
`genesis.public_key` and exact `peerN.toml` validator configs. Generation rejects
any signer, hash, identity, trusted-roster, or PoP disagreement. The generated
validator-only Compose projection rewrites operational paths to container
storage. Configured account-onboarding and faucet private-key files become
file-backed Compose secrets, while public binary policy inputs become
digest-interned Compose configs. The original bare-metal configs are unchanged.

## Streaming Identities

Iroha's streaming control plane always signs messages with an Ed25519 key. If a
validator uses another algorithm for its main identity, configure a dedicated
Ed25519 streaming identity:

```toml
[streaming]
identity_public_key  = "ed0120..."
identity_private_key = "802620..."
```

Use `kagami keys --algorithm ed25519 --out-dir ./client-custody` to generate that pair.

## Advanced Examples

- [Norito codec](docs/codec.md)
- [Kura block inspection](docs/kura.md)
- [Docker Compose generation](docs/swarm.md)
