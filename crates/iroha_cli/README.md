# Iroha CLI Client

The `iroha` command-line client exposes the operator and ledger workflows for
the first Hyperledger Iroha 3 release. It builds on the reusable `iroha` client
crate. See [Operate Iroha 3 via CLI](https://docs.iroha.tech/get-started/operate-iroha-via-cli.html)
for the current tutorial.

Within this workspace, `crates/iroha` is the reusable Rust client library and
`crates/iroha_cli` contains the `iroha_cli_lib` implementation package. Its
`bins` directory contains the `iroha_cli` package that builds the `iroha`
command-line binary and owns the binary integration tests. Run
`cargo test -p iroha_cli_lib --lib` for the implementation suite. The library
always includes its runtime dependencies; its optional flags control bridge
commands, visual offline codecs and test hooks. The executable owns the `cli`
and `dev-tools` target-selection flags.

## Installation

**Requirements:** install
[Rust 1.93.1](https://www.rust-lang.org/learn/get-started), the toolchain pinned
for this workspace in the repository-root `rust-toolchain.toml`.

Build Iroha and its binaries:

```bash
cargo build -p iroha_cli --bin iroha
```

The binary is written to `target/debug/iroha` (`target/debug/iroha.exe` on
Windows).

See [Install Iroha 3](https://docs.iroha.tech/get-started/install-iroha.html) for
the current installation instructions.

## Usage
The CLI will attempt to detect your system language for messages. Use `--language <CODE>` to override this selection.
`-o/--output-format` selects `text`, `json` (one pretty document) or `jsonl`
(compact JSON, one value per line; list results print one element per line and
event streams one event per line). Without the option the CLI prints text when
stdout is a terminal and JSON otherwise, so scripts that capture stdout always
receive JSON. `--machine` always defaults to JSON and loads client configuration
strictly; it is the recommended flag for automation.

Errors go to stderr. Text errors list every distinct cause once under
`Caused by:` and end with an actionable `hint:` when one is known; JSON errors
carry the same data as `{"error": {"kind", "message", "causes", "hints",
"exit_code"}}`. Exit codes: 1 command failure, 3 configuration, 4 invalid input,
7 internal. Invoking a command group without a subcommand prints that group's
help to stderr and exits 2.

Validator summaries retain complete activation heights and tenure bounds.
Space Directory and ZK JSON inputs use Norito's shared JSON nesting limit
(`MAX_JSON_VALUE_NESTING_DEPTH`, currently 33 including the root value).
Local contract durable-state fixtures require exact NFC path spelling and
reject duplicate decoded JSON keys.

Binding-only IVM proof helpers are removed. Core rejects `IvmProved` until the
complete native STARK execution relation and State-owned finalized anchor are
available. Generic proof and verifying-key registry commands remain available.

Use `iroha taira doctor` for read-only public-testnet diagnostics. Both scopes
require `/readyz` to return HTTP 200 with the exact plain-text `Ready` response;
unavailable readiness fails the report with a bounded machine error code. Authorized
public reset writes belong to the durable `iroha taira public-reset apply`
coordinator. Retry the same apply command with the same inventory and authorization;
the durable journal selects recovery inputs for the interrupted phase. Its low-level `write-canary` child accepts exactly one ordered
operation and one prepare, retained-envelope submit, or read-only recovery
action; it is not a one-shot operator command. Keep onboarding tokens and all
signing inputs in owner-only runtime files outside the repository.

`iroha taira public-reset torii-rate-config-amend --config-fd 3
--config-source-path /private/runtime/validator/config.toml --rate-per-second 1000000
--burst 10000000 --output /private/runtime/validator/config.next.toml` creates a fresh
0600 flat configuration beside its source and emits only public budget/provenance metadata.
The native launcher supplies the read-only descriptor; configuration bodies and credentials
never enter argv or stdout. Repeat `--section` to select `torii`, `mcp`, `push`, `content`,
`connect`, `gateway`, `operator-auth`, `privacy-ingest`, or `recipient-lookup`; omission
selects all. The `torii` section covers query, transaction, deploy, pre-auth, proof and
Soracloud requests. Absent optional recipient lookup stays absent. Gateway windows and
all non-rate settings remain unchanged. Validate the result with the exact installed
daemon's `--check-config --json` before installing it and restarting validators; running
Torii buckets do not reload from disk. An output hash does not establish release qualification.
`scripts/taira_validator_unit.py --role taira-validator-1 --amend-unit
/etc/systemd/system/iroha3d-taira-validator-1.service --rate-config-receipt
/private/runtime/native-rate-receipt.json --output
/private/runtime/next/iroha3d-taira-validator-1.service` prepares the matching public
unit by replacing only its old config fingerprint. It verifies the native receipt's
source binding and fresh output metadata without reading config or signer bodies.
The config path and full launcher stay unchanged; installation and restart remain
separate, supervised deployment steps after native daemon validation.

A sealed occupied deployment uses the native
[`prepare-dispatcher-transition` / `dispatcher-transition` owner](DISPATCHER_TRANSITION.md)
to advance the fixed dispatcher and its five guards before preparing the next
reset. The completed transfer carries its preparation proof; the owner preserves
current runtime bindings and durable deployment history.

Reset input validation checks the complete action timeout budget before scanning
artifacts or reading signing custody. The install budget counts every required
artifact upload, including `kagami`, plus each validator's stage and install
actions. All four signed-genesis bootstrap beacon providers activate before
restart qualification. The retired epoch worker service and state must be
absent. Prepared Inrou stage files
use mode0600; retained runtime snapshots use mode0400. Both remain owner-only, direct,
singly linked files, with unchanged content verification.

Journal admission holds one exclusive lock through classification and execution.
The journal owner explicitly unlocks it on drop, so descriptors inherited by
unrelated forked children cannot delay the next admission.

Automation that already retains a private client file uses `--config-fd <FD>`
with `--config-source-path <absolute-original-path>`. The descriptor is read
directly, without environment overrides; the source path provides provenance
and the base for relative paths and is never reopened. Descriptors must be
read-only, owner-private regular files. Onboarding prepare/submit similarly
accepts `--onboarding-token-fd <FD>` instead of `--onboarding-token-file`.
Do not pass descriptor pseudo-paths through the ordinary file options.

Public node onboarding is deliberately a single future surface:
`iroha taira join --data-dir <owner-only-directory>`. It will consume the
published signed bootstrap bundle, generate local keys, and join as a
permissionless observer with no operator-issued admission token. Validator
activation is a separate on-chain transition through the existing staking and
peer lifecycle after the node has synchronized; it does not use a parallel
off-chain token format. The command and bundle are not shipped yet. The
disposable four-validator devnet is qualification tooling, not a way to join
the public testnet.

### Public-lane staking commands

`iroha app staking prepare --request intent.json` accepts a strict Norito JSON
`PublicLanePreparationRequestV1` and prints the complete response: the exact plan,
network and observed tip, pinned XOR definition, and each exact asset's balance,
stake reserve and reward reserve. Inspect and retain that observation before
passing its `plan.value` as the corresponding signing command's plan file.
Preparation is read-only; the reported tip is not independently authenticated.

`iroha app nexus public-lane committee-status --target-epoch 2` prints the
original finality attachments and the selected attempt's preparation, candidate
keys and pending beacon transcript. Authenticate those attachments against signed
genesis and the native chain before provisioning or signing.
`iroha app nexus public-lane committee-submit --file operation.json` accepts one
strict `ValidatorCommitteeOperationV1` and uses the normal transaction signing and
explicit fee-selection flow. Its only operations publish candidate keys, prepare
credentials and admit a target seat. Activation and cancellation remain certified
boundary decisions; the command cannot force them or modify a frozen roster.

`iroha app staking register-candidate` atomically registers a fresh consensus peer
and bonds the validator's initial stake on a stake-elected lane, including global
lane 0. Admission schedules future election eligibility; changing the committee
requires complete preparation and incumbent-certified boundary finality. The command signs the complete registration
against the genesis-derived `--network-id` with the key from
`--peer-private-key-file`. That runtime file must use an absolute path, contain
one canonical BLS-normal private key, and be owned by the caller with exact
mode `0600`; the CLI checks that it matches `--peer-id`. Keep it outside the
repository. The transaction is submitted by the validator account. Admission
schedules future eligibility; it does not change the current committee.

```sh
iroha --config validator.toml --fee-payer authority app staking register-candidate \
  --lane-id "$STAKE_ELECTED_LANE_ID" --validator "$VALIDATOR" --peer-id "$PEER_ID" \
  --initial-stake 25000 --network-id "$NETWORK_ID" --activation-height "$ACTIVATION_HEIGHT" \
  --peer-private-key-file /run/iroha/peer.key --monetary-plan candidate-plan.json
iroha --config staker.toml --fee-payer authority app staking bond \
  --lane-id 0 --validator "$VALIDATOR" --amount 10.000000001 --monetary-plan bond-plan.json
iroha --config staker.toml --fee-payer authority app staking schedule-unbond \
  --lane-id 0 --validator "$VALIDATOR" --amount 5 \
  --request-id "$WITHDRAWAL_HASH" --release-at-ms "$RELEASE_AT_MS"
iroha --config staker.toml --fee-payer authority app staking finalize-unbond \
  --lane-id 0 --validator "$VALIDATOR" --request-id "$WITHDRAWAL_HASH" --monetary-plan withdrawal-plan.json
iroha --config recipient.toml --fee-payer authority app staking claim-rewards --lane-id 0 --claim-plan claim-plan.json
iroha --config treasury.toml --fee-payer authority app staking record-rewards --file epoch-rewards.json
```

`bond` supports self stake and delegation. `--staker` defaults to the configured
transaction authority for bond and both unbond commands; `claim-rewards`
similarly defaults `--account` to that authority. The chain requires the stake
owner or reward recipient to authorize their respective operations. Amounts
are exact decimal quantities. Bond metadata accepts a Norito JSON object via
`--metadata` and replaces the stake share's metadata.

Candidate `--activation-height` binds the signed registration to its scheduled
eligibility boundary. If that boundary passes before inclusion, prepare a new
authorization.

Choose and retain a unique canonical hash for `--request-id`; use that exact
value when finalizing. `--release-at-ms` must respect the network's configured
unbonding delay. Finalization additionally waits for the consensus liability
window. Registration, bonding, and finalization require a
Norito JSON `PublicLaneMonetaryPlanV1`; claims require a
`PublicLaneRewardClaimPlanV1`. These files bind the target network, expiry,
exact assets and amounts, and current tenure or reward cursor/record commitments.
The CLI rejects mismatched runtime networks, recipients, amounts, or noncanonical
plans. Core rechecks
all state preconditions at execution. Plans must use the network's configured
genesis-pinned global XOR definition at scale 9 and exact custody accounts.

Claim plans contain at most 64 ordered reward record commitments and 64 exact
sources. A zero payout may advance record processing while preserving unpaid
dust. Construct canonical plan files from independently authenticated current
state and refresh them when they expire or become stale. Execution checks
permissions, maturity, lifecycle and all monetary preconditions.

`record-rewards` reads a Norito JSON `RecordPublicLaneRewards` object with
`lane_id`, `epoch`, `reward_asset`, `total_reward`, `shares`, and `metadata`.
Each share contains `account`, `role` (`"Validator"` or `"Nominator"`), and an
exact `amount`. The configured fee-sink authority submits the distribution;
the chain verifies its funding and allocation totals. This command does not
mint rewards. The existing `register`, `rebind`, `activate`, and `exit`
commands remain available for their corresponding validator transitions.
`rebind` requires `--network-id` matching the configured genesis network, `--peer-private-key-file`,
`--activation-height`, and `--previous-peer-id` to sign replacement-peer
consent for the exact stored pending tenure and binding. Consent is required
even when the replacement peer matches the existing binding. A distinct
replacement peer must already have a valid registered consensus key.

### Scaling load terminal handoff

`tx load` requires a fresh nonzero 64-character lowercase hexadecimal
`--invocation-id`. Machine execution emits one bounded JSON line only after
resource collection, workload checks, exact global and peer-local Applied
observations, and durable journal/trace publication complete. The receipt binds
that invocation, pair/variant/seed, resource budget, scheduled request count,
and raw SHA-256 plus byte length of both original output files. Retained native
file and parent handles remain checked through the actual reply flush.

### Local SoraFS artifacts

Local SoraFS compilation and packaging run without client configuration:

```sh
iroha app sorafs toolkit compile --source contract.ko \
  --bytecode-out artifacts/contract.to --json-out artifacts/contract.json
iroha app sorafs toolkit pack artifacts/contract.to \
  --car-out artifacts/contract.car --manifest-out artifacts/contract.manifest.to
```

Compilation accepts `--source -` for stdin and publishes the compiler manifest
and authenticated build sidecars with the artifact. Its JSON summary includes
the exact byte length, BLAKE3 digest, ABI version, and source origin. Both toolkit
operations also support machine output without a populated `client.toml`.

### Client configuration

Runtime commands read `client.toml` from the current directory, or the file
passed with `-c/--config`; relative paths are resolved against the current
directory. Offline helpers (`tools address`, `tools crypto`, `tools ivm` and
`tools version`) run without a configuration, also with `--machine`;
`tools version` then reports only the client build.

Select a public network with `[account].profile`. The supported `taira` and
`minamoto` profiles derive the correct I105 chain discriminant; the top-level
`chain` value does not select that profile. `network_id` is required: it is the
genesis-derived identity that every signed request binds. A node advertises it
at `GET <torii_url>/v1/accounts/capabilities`; confirm it through an
independent channel before trusting it.

```toml
chain = "fc56984b-2be7-431d-840e-21514d1883f0"
network_id = "<genesis-derived network id>"
torii_url = "https://taira.sora.org/"

[account]
profile = "taira"
public_key = "..."
private_key = "..."
```

For a local or custom network, set `[account].chain_discriminant` to its I105
chain discriminant instead (the default local genesis uses `753`). One of the
two is required: there is no default network, and a configuration that sets
both must keep them consistent. The corresponding environment overrides are
`ACCOUNT_PROFILE` and `ACCOUNT_CHAIN_DISCRIMINANT`.

The CLI owns two optional filesystem settings that are deliberately absent from
the reusable Rust SDK configuration:

```toml
[connect]
queue_root = "/var/lib/iroha/connect"

[soracloud]
http_witness_file = "/run/iroha/canonical-request-witness.json"
```

`connect.queue_root` defaults to `~/.iroha/connect`. Soracloud mutation commands
load the witness through a bounded, change-detecting reader and validate its
schema, account, exact network request hash, and signer set before sending it.
Configured relative paths resolve from the directory containing the client TOML file.

### Fixed-schedule transaction collection

`iroha tx load` uses persistent SDK clients to prepare and submit a fixed
open-loop workload. Every request must reach state-resolved Applied globally
and on the required local observer at the same block height within the original
drain deadline. The fixed launcher selects the original peer whose stopped Kura
will be inspected. It supplies that peer's client configuration, a funded account
pool, an explicit fee payer and the bounded resource sampler inputs:

```sh
iroha --config client.toml --fee-payer authority tx load \
  --invocation-id "${INVOCATION_ID}" \
  --pair-index 1 --variant one_lane --seed "${PAIR_SEED}" \
  --offered-load-tps "${OFFERED_TPS}" --warmup-seconds "${WARMUP_SECONDS}" \
  --measurement-seconds "${MEASUREMENT_SECONDS}" --drain-seconds "${DRAIN_SECONDS}" \
  --max-submission-lag-ms "${SUBMISSION_LAG_MS}" \
  --account-config "${ACCOUNT_0_CONFIG}" --account-config "${ACCOUNT_1_CONFIG}" \
  --account-config "${ACCOUNT_2_CONFIG}" --account-config "${ACCOUNT_3_CONFIG}" \
  --local-observer-config "${PEER_3_CLIENT_CONFIG}" \
  --resource-program "${ABSOLUTE_PYTHON_PATH}" \
  --resource-worker "${ABSOLUTE_RESOURCE_WORKER_PATH}" \
  --resource-config "${OWNER_ONLY_PROBE_CONFIG}" \
  --resource-budget-sha256 "${PUBLIC_RUN_BUDGET_SHA256}" \
  --resource-capture-dir "${ABSENT_ABSOLUTE_CAPTURE_DIR}" \
  --resource-interval-ms "${SAMPLING_INTERVAL_MS}" \
  --resource-timeout-ms "${SAMPLING_TIMEOUT_MS}" \
  --resource-max-start-lag-ms "${SAMPLING_START_LAG_MS}" \
  --trace-out "${ABSENT_ABSOLUTE_TRACE_PATH}" \
  --diagnostic-out "${ABSENT_ABSOLUTE_JOURNAL_PATH}"
```

Use repeated `--account-config` paths to select an ordered pool of independently
funded signing accounts on the same chain and genesis network as the local
observer. The pool contains 4 through 64 accounts in multiples of four, and each
nonempty cohort contains complete pool rounds. Logical identities select accounts
deterministically and bind self-owned account metadata inserts. The collector
verifies the complete account effects after draining; routing, fee contention and
real workload representativeness still require qualification. Configuration files
and signing credentials remain local.

Preparation, submission, outstanding observations and diagnostic recording have
explicit fixed bounds. A missed schedule, exhausted local capacity, unknown or
failed submission, authoritative terminal failure, or incomplete drain fails
collection; no transaction is automatically replayed. `--help` lists the
lookahead, concurrency and polling controls. Global and local reads share the same
observation capacity and fixed clock. The trace retains global observation latency,
including polling and transport delay; waiting for the local peer does not rewrite
those timestamps or extend the drain deadline.

The new diagnostic JSON-lines file retains the schedule, exact hashes,
observations and final outcomes. The strict V1 trace is published without
replacing an existing file only after every scheduled request is acknowledged
and state-applied globally and locally at the same height within its phase deadline,
and the journal reaches durable storage. Local hash, scope, provenance, height and
observation time are retained separately so the launcher can verify the local
barrier before stopping the peer. Both files have hard byte bounds; oversized experiments fail instead
of truncating records. Endpoint URLs and external error text are omitted; the
journal retains fixed failure stages and bounded status classifications. No
private key or authentication header is written.

### Transaction waits

Use the built-in wait flow instead of shell polling:

```bash
iroha tx status --hash <SIGNED_TX_HASH> --wait
iroha contract call --contract-alias router::dex.universal --entrypoint swap \
  --draft-intent-file trusted-swap-intent.json --wait
iroha contract call --contract-alias router::dex.universal --entrypoint swap --simulate
```

Every non-simulated contract call must provide `--draft-intent-file`. The
secret-free JSON file is the caller-trusted exact contract invocation (resolved
address, code hash, entrypoint, and canonical argument record) plus the exact
final transaction metadata. Build it from the locally verified artifact/schema
and an authenticated deployment binding; never copy either value from the Torii
draft response. The CLI keeps this intent off wire and refuses to sign or return
an unsigned payload unless every signature-bound field matches it.

Run `iroha tools markdown-help` for the complete reference generated from the
installed CLI.

### Atomic private-settlement online auditor

The governed online-auditor flow uses one purpose-specific approval key from
the global `--operator-private-key-file` option and a distinct hybrid capsule
decryption key from an owner-only runtime file. It pins the four ordered Torii
endpoints to a separately governed committee-authority record, verifies each
responder's purpose-separated BLS attestation and proof of possession, requires
one exact three-of-four view, evaluates the decrypted capsule at the middle
ordered node-authoritative height so one outlier cannot choose it, then requires
an exact three-of-four, roster-authenticated approval acknowledgement. Neither
the capsule plaintext nor either secret is
printed. The signing key must be listed in the active local audit policy and
must not be a committee consensus key.

```bash
iroha --operator-private-key-file /run/secrets/aps-auditor-signing.key \
  nexus private-settlement audit-online \
  --committee-endpoint https://validator-1.example/ \
  --committee-endpoint https://validator-2.example/ \
  --committee-endpoint https://validator-3.example/ \
  --committee-endpoint https://validator-4.example/ \
  --committee-authority /etc/iroha/aps-committee-authority.json \
  --payload-digest <LEG_PAYLOAD_DIGEST> \
  --pool-governance /run/secrets/aps-pool-governance.json \
  --auditor-decryption-key-file /run/secrets/aps-auditor-hybrid.json \
  --business-policy /run/secrets/aps-business-policy.json \
  --decision approve
```

The committee-authority file must come from the participant dataspace's
governed configuration; endpoint order must match its ordered validator roster
exactly. Because it is the local trust anchor, it and the three restricted
input files must be absolute, owner-owned, singly linked regular files with
exact mode `0600`; on Linux they must be xattr-free, while macOS permits only
the exact `com.apple.provenance` metadata attribute. Extended ACL entries and
all other xattrs are rejected, and final path components cannot be symlinks. Files are opened
nonblocking and without following the final component, then rechecked through
the retained descriptor before and after the bounded read. The
restricted files must reside on a qualified local filesystem whose
descriptor-bound ACL and xattr APIs expose every effective access grant; NFS
and SMB custody is not qualified by POSIX mode bits alone. The
decryption-key file's strict Norito JSON shape is:

```json
{
  "version": 1,
  "x25519_secret_hex": "<64 lowercase hexadecimal characters>",
  "ml_kem_768_secret_hex": "<canonical lowercase hexadecimal ML-KEM-768 secret>"
}
```

The business-policy file is also strict Norito JSON. It binds one exact
network, route, opaque pool, audit-policy lineage/revision/key epoch, canonical
non-empty allowlists for payer, recipient, sponsor, and asset, inclusive amount
and reimbursement ceilings, a memo-size ceiling, canonical allowed/required
policy-reference lists, and a maximum remaining-height window. Unknown fields,
wildcard identity/asset lists, unordered or duplicate values, a zero window, or
a required reference absent from the allowed list fail closed. There is no
environment-variable fallback. `--decision approve` is necessary but not
sufficient: the decrypted leg must also match every business-policy constraint.
Omitting the decision or using `--decision reject` cannot create or submit an
approval. Decryption-key and pool-governance files are limited to 16 KiB; the
bounded business-policy file is limited to 256 KiB.

Refer to [Iroha Special Instructions](https://docs.iroha.tech/blockchain/instructions.html) for more information about Iroha instructions such as register, mint, grant, and so on.

### Sumeragi consensus helpers

Operator reads require an explicit runtime key whose public key is allowlisted by the node.
Pass either `--operator-private-key-file /absolute/path` or an inherited read-only descriptor with
`--operator-private-key-fd FD` (3–65535). These options are mutually exclusive. The CLI does not
read this credential from the environment or client TOML and never substitutes the account key.
On Unix the key must be in an owner-owned, singly linked regular file with exact mode `0600`.
Descriptor reads use the inherited file directly, preserve the caller's file offset and never
reopen a path. Requests are signed for the exact `network_id` in `client.toml`.

Fetch the Sumeragi core status:

```bash
iroha --operator-private-key-file /run/secrets/iroha/operator.key \
  --output-format text ops sumeragi status
```

> `--output-format text` prints height, view, stage, leader, proxy tail, lock view, committed and applied heights, whether the node awaits application, whether it is signing, and the halt reason.

Fetch non-authoritative pipeline, queue, NPoS election, and Nexus lane diagnostics separately:

```bash
iroha --operator-private-key-file /run/secrets/iroha/operator.key \
  --output-format text ops sumeragi diagnostics
```

Read the committed equivocation evidence:

```bash
iroha --operator-private-key-file /run/secrets/iroha/operator.key \
  --output-format text ops sumeragi evidence count
iroha --operator-private-key-file /run/secrets/iroha/operator.key \
  --output-format text ops sumeragi evidence list --limit 100
```

Tip: You can combine these with `jq` for consistency checks.

### SoraFS gateway helpers

Generate a TOML snippet with default gateway settings (rate limits and ACME hosts):

```bash
iroha app sorafs gateway template-config --host gateway-a.example.com --host gateway-b.example.com
```

Pipe the output into your node configuration to bootstrap `torii.sorafs_gateway`.

Derive canonical and vanity hostnames for a provider (useful for direct-mode tooling):

```bash
iroha app sorafs gateway generate-hosts --provider-id 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --chain-id nexus
```

The command prints JSON with the canonical and vanity hostnames derived from the provider id.

Plan a direct-mode rollout by inspecting manifest metadata and (optionally) admission envelopes:

```bash
iroha app sorafs gateway direct-mode plan \
  --manifest fixtures/sorafs_manifest/example_manifest.to \
  --provider-id 1111111111111111111111111111111111111111111111111111111111111111
```

The command returns a JSON plan capturing host mapping, direct-CAR endpoints, and capability flags
detected from the manifest/admission bundle.

Apply the plan to generate a configuration snippet (the snippet targets `torii.sorafs_gateway` and
the new `torii.sorafs_gateway.direct_mode` table):

```bash
iroha app sorafs gateway direct-mode enable --plan direct-mode-plan.json
```

To restore default gateway settings, emit the rollback snippet:

```bash
iroha app sorafs gateway direct-mode rollback
```

### ZK vote tally (app API convenience)

The CLI provides helpers for app‑facing ZK endpoints. For example, to fetch a vote tally for an election id via Torii:

```bash
iroha app zk vote tally --election-id demo-election-1
```

This posts to `/v1/zk/vote/tally` and prints the snapshot-bound JSON response, e.g. `{ "evaluated_block_height": 42, "evaluated_block_hash": "<64 lowercase hex characters>", "finalized": true, "tally": [42, 58] }`. An unknown election is an HTTP `404`; it is never represented as an empty tally.

### Governance helpers (app API convenience)

Build governance transaction skeletons and query governance state via Torii app endpoints. The server does not sign or submit transactions; clients assemble and POST to `/v1/pipeline/transactions`.

- Propose deployment of IVM bytecode via governance:

```bash
iroha app gov deploy propose \
  --contract-address irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw \
  --code-hash <64-lowercase-hex> --abi-hash <64-lowercase-hex> \
  --abi-version 1
```

Responds with `{ proposal_id, tx_instructions: [{ wire_id, payload_hex }] }`.
The certificate lifecycle and enactment height are Core-derived; this command
accepts no referendum window or voting mode.

- Submit a ballot (auto-detects referendum mode unless overridden):

```bash
iroha app gov vote --referendum-id r1 --backend halo2/ipa \
  --envelope-b64 BASE64_ENVELOPE \
  [--public public.json]
```

For plain (non-ZK) referenda provide the required fields explicitly:

```bash
iroha app gov vote --referendum-id r1 --mode plain --owner <canonical-i105-owner> \
  --amount 1000 --duration-blocks 6000 --direction Aye
```

Proposal-backed Parliament decisions are certificate driven. The node advances
certified attempts at their consensus-scheduled due height; the CLI does not
expose client finalization or proposal-enactment drafts.

- Apply protected namespaces on the server (admin/testing):

  iroha app gov protected apply --namespaces apps,system

- Build governance metadata for protected-namespace admission:

  iroha app gov deploy meta --contract-address irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw

- Audit a governed contract binding by canonical address or alias:

  iroha app gov deploy audit --contract-address irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw

- Combined manifest command (prints or saves when --out is provided):

  iroha contract manifest get --code-hash 0xAA..AA
  iroha contract manifest get --code-hash 0xAA..AA --out manifest.json

```

- Read governance state:

```bash
iroha app gov proposal get --id 0123...ABCD
iroha app gov locks get --referendum-id r1
iroha app gov referendum get --referendum-id r1
iroha app gov tally get --referendum-id r1

Governance events (subscribe via `iroha ledger events`)
- ProposalSubmitted, ProposalRejected, ProposalEnacted
- ParliamentAttemptCreated, ParliamentLifecycleTransitionApplied
- ReferendumOpened, ReferendumClosed, ReferendumDecided
- BallotAccepted { mode, weight }, BallotRejected { reason }
- LockCreated { owner, amount, expiry }, LockExtended { ... }, LockUnlocked { ... },
  LockSlashed { ... }, LockRestituted { ... }
- CitizenRegistered, CitizenRevoked, ThresholdKeyLifecycleApplied
```

- Stream governance events:

```bash
iroha ledger events governance [--proposal-id 0123...ABCD | --referendum-id r1]
```


### ZK Verifying Key registry (register/update)

The CLI builds, quotes, signs, and submits VK registry transactions with the account and key from
the active client configuration. VK JSON files contain public registry data only; signing
authorities and private keys are not accepted in these files.

Register a verifying-key DTO produced by the circuit's canonical tooling:

The optional `namespace` field defaults to `core` when omitted or `null`. Explicit
namespace values must be non-empty and must not contain leading or trailing
whitespace.

```bash
iroha app zk vk register --json vk_register.json
```

The DTO must contain the admitted circuit's exact key, schema, curve and proof
limit. Retain these values from its canonical generator or authenticated release
artifact; do not invent circuit names or transcript parameters.

To update an existing record, use a generated registration DTO with the same
registry name and increase its `version` before submitting it:

```bash
iroha app zk vk update --json vk_update.json
```

Register and update use the standard CLI fee-quote, signing and submission
workflow. JSON mode returns the standard transaction receipt on stdout;
submission does not claim that the transaction has reached `Applied` finality.

Keep generated key metadata together. If you omit embedded `vk_bytes`, retain
both the exact `commitment_hex` and the mandatory nonzero `vk_len`. Arbitrary
circuit IDs and schema hashes are rejected by the production registry.

Read a VK record as JSON:

```bash
iroha app zk vk get --backend halo2/ipa --name <registered-key-name>
```

Use the canonical generator's `public_inputs_schema_hash_hex` unchanged. It
identifies the circuit's fixed schema descriptor; hashing a proof's concrete
public-input values does not produce a registry schema digest.

### ZK attachments (app API convenience)

Upload an attachment (set Content-Type appropriately):

```bash
iroha app zk attachments upload --file ./proof.json --content-type application/json
```

List attachments, download one, and delete it:

```bash
iroha app zk attachments list
iroha app zk attachments get --id 0123ab... --out ./downloaded.bin
iroha app zk attachments delete --id 0123ab...

# Clean up attachments (client-side filtering)
# Preview Norito attachments older than 7 days
iroha app zk attachments cleanup --content-type application/x-norito --older-than-secs 604800 --summary
# Delete all JSON attachments created before a timestamp
iroha app zk attachments cleanup --content-type application/json --before-ms 1725500000000 --yes

```

### Confidential asset ingress

The first-release CLI intentionally has no generic `zk shield` command. The generic
confidential-asset verifier settings do not authorize callers to inject opaque
commitments.

Encrypted memo envelopes remain available as a local wallet utility:

```bash
iroha app zk envelope --envelope-json memo.json --output memo.bin
iroha app zk envelope --envelope-json memo.json --format base64
```

`memo.json` is one typed `ConfidentialMemoEnvelopeV1` produced by the wallet's
encryption API. This command validates and encodes an existing encrypted memo.
Choose `--format base64`, `hex`, or `json` for exactly one stdout value; base64
is the default without `--output`. An output file contains Norito bytes. This
local command does not load `client.toml` or signing credentials; transaction and
credential globals are rejected. Input files and JSON allocations use the CLI's
bounded decoder.

### Register a ZK-capable asset

```bash
iroha app zk register-asset --asset <base58-asset-definition-id> \
  --vk-unshield halo2/ipa:vk_unshield
```

Register and inspect the referenced verifying keys with `iroha app zk vk register`,
`iroha app zk vk update`, and `iroha app zk vk get`. The first-release confidential-asset
model rejects `vk_shield`. No asset-bound private-transfer verifier or generic
transfer/withdrawal ISI exists.

### ZK verify batch

```bash
iroha app zk verify-batch --norito ./batch.norito
# Or pass a JSON array of base64-encoded Norito envelopes:
iroha app zk verify-batch --json ./batch.json
```

Run the full sample sequence:

```bash
cd fuzz/attachments/zk
bash ./run.sh
```

## Examples

:grey_exclamation: All examples below are Unix-oriented. If you're working on Windows, we would highly encourage you to consider using WSL, as most documentation assumes a POSIX-like shell running on your system. Please be advised that the differences in the syntax may go beyond executing `iroha.exe` instead of `iroha`.

### Create a domain and alias lease

Ordinary transactions create domains through the declarative alias planner so the SNS lease, owner capabilities, and domain state are checked and applied atomically. Put the secret-free setup request in a JSON file, plan it against live state, then verify and submit that exact plan locally:

```bash
iroha app alias setup plan --intent-file alias-setup.json --plan-file alias-plan.json
iroha app alias setup apply --plan-file alias-plan.json
```

Raw `ledger domain register` is reserved for genesis/bootstrap and is not exposed as an ordinary CLI mutation.

### Create new Account

To create an account, pass its canonical I105 `AccountId` to `account register`.
Every submitted transaction names its fee source explicitly with
`--fee-payer authority` (or `--fee-payer sponsor --fee-program <id>
--fee-program-revision <revision>`) and waits for `Applied` finality unless
`--no-wait` is given:

```bash
iroha --fee-payer authority account register \
  --id "sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE"
```

### Register and mint an asset

An asset definition is addressed by its checksummed Base58 identifier and may
also carry an alias such as `usd#wonderland.universal`. `--scale` fixes the
number of decimal places; omit it for an unconstrained quantity.

```bash
iroha --fee-payer authority ledger asset definition register \
  --id "66owaQmAQMuHxPzxUN3bqZ6FJfDa" --name USD --scale 2 \
  --alias "usd#wonderland.universal"
iroha --fee-payer authority ledger asset mint \
  --definition "66owaQmAQMuHxPzxUN3bqZ6FJfDa" --account "<I105_ACCOUNT>" --quantity 1010
iroha --fee-payer authority ledger asset transfer \
  --definition-alias "usd#wonderland.universal" --account "<I105_ACCOUNT>" \
  --to "<I105_RECIPIENT>" --quantity 10.50
```

### Read balances and entities

Point reads use exact by-id queries:

```bash
iroha ledger asset get --definition "66owaQmAQMuHxPzxUN3bqZ6FJfDa" --account "<I105_ACCOUNT>"
iroha ledger asset definition get --alias "usd#wonderland.universal"
iroha ledger domain get --id wonderland.universal
iroha account get --id "<I105_ACCOUNT>"
```

### List collections

Every Torii collection has one `list` command with the same flags and the same
output, following [`specs/torii/collection_queries.md`](../../specs/torii/collection_queries.md):

| Command | Collection |
| --- | --- |
| `iroha ledger domain list` | domains |
| `iroha account list` | accounts |
| `iroha ledger asset definition list` | asset definitions |
| `iroha ledger nft list` | NFTs |
| `iroha ledger rwa list` | RWA lots |
| `iroha ledger asset list [--account <ID>]` | balances of one account (default: the configured account) |
| `iroha ledger asset holders --definition <ID>` | holders of one asset definition |
| `iroha tx list [--account <ID>]` | transactions of one account (default: the configured account) |
| `iroha app repo list` | repo agreements |
| `iroha contract activity` | contract activity history |
| `iroha contract events` | contract event history |
| `iroha account permission list --id <ID>` | effective account permissions |
| `iroha app subscriptions plan list` | subscription plans |
| `iroha app subscriptions subscription list` | subscriptions |
| `iroha app space-directory manifest fetch --uaid <UAID>` | UAID capability manifests |

- `--filter <FILTER>` (alias `--where`) keeps matching rows; filters read like a
  SQL `WHERE` clause: `owned_by = "sorau…" and quantity >= 10.5`,
  `status in ["active", "paused"]`, ``not exists(metadata.`ui-order`)``.
- `--sort -quantity,id` orders rows (`-` is descending); `--select id,quantity`
  returns only those fields.
- `--limit N` sets the page size; `--cursor <next_cursor>` continues after a
  page; `--all` follows every cursor; `--include-total` adds the exact `total`.

The default output is one page document, `{"items": [...], "next_cursor": ...,
"total": ...}` (`total` only with `--include-total`). With `--all`, `-o json`
prints every row in one document, while `-o jsonl` prints one row per line as
pages arrive. Text output is a table of the collection's main columns, or of the
`--select` fields. Invalid flags and Torii's `invalid_*` rejections exit with 4
and show Torii's hint.

```bash
# Asset definitions owned by an account in descending id order, one page of 20
iroha ledger asset definition list --filter 'owned_by = "<I105_ACCOUNT>"' --sort -id --limit 20
# Every balance of the configured account, streamed as JSON lines
iroha -o jsonl ledger asset list --all
# Holders of an asset with at least 100 units, with the exact count
iroha ledger asset holders --definition-alias "usd#wonderland.universal" \
  --filter 'quantity >= 100' --sort -quantity --include-total
# Recent failed transactions of one account
iroha tx list --account "<I105_ACCOUNT>" --filter 'result_ok = false' --limit 10
```

### Contract Developer Workflow

Use [Musubi](../musubi/README.md) for Kotodama package projects. `Musubi.toml`
owns library, contract, test, and dependency declarations. `musubi new`,
`musubi check`, `musubi build`, and `musubi test` use the native compiler and
an explicit locked module graph. Named network bindings select the runtime
client config and exact contract alias for `musubi deploy` and `musubi view`.

The low-level `iroha contract` commands inspect artifacts, derive addresses,
manage aliases, perform calls and views, and run local bytecode diagnostics.
They do not own another project manifest or package build workflow.

### Execute IVM transaction

Use `--path` to submit an IVM bytecode file (typically a `.to` file produced by
compiling Kotodama `.ko` source), or omit it to read the bytecode from standard
input. IVM transactions require a signature-bound `--gas-limit`:

```bash
iroha --fee-payer authority tx ivm --path /path/to/contract.to --gas-limit 1000000
cat /path/to/contract.to | iroha --fee-payer authority tx ivm --gas-limit 1000000
```

These subcommands submit the provided IVM bytecode as an `Executable` to be executed outside a trigger context.

### Execute Multi-instruction Transactions

`--emit-instructions` prints a command's instructions as a JSON array instead of
submitting them, and `--stdin-instructions` runs a JSON array read from stdin
before the command's own instructions. Together they compose one transaction from
several commands; `tx stdin` submits a finished array:

```bash
iroha --emit-instructions ledger asset definition register \
  --id "66owaQmAQMuHxPzxUN3bqZ6FJfDa" --name USD --scale 2 > instructions.json
iroha --emit-instructions --stdin-instructions ledger asset mint \
  --definition "66owaQmAQMuHxPzxUN3bqZ6FJfDa" --account "<I105_ACCOUNT>" --quantity 1010 \
  < instructions.json > batch.json
iroha --fee-payer authority tx stdin < batch.json
```

### Request arbitrary query

`ledger query stdin` reads one query envelope: `{"singular": {"type": ...,
"payload": {...}}}` or `{"iterable": {"type": ..., "params": {...},
"predicate": {...}}}`. Torii's signed `/v1/query` admits singular queries and
only the unfiltered `FindPeers`, `FindAccountIds`, `FindTriggers` and
`FindActiveTriggerIds` iterable shapes; it refuses every other iterable with
`signed_query_shape_not_admitted` (see
[`specs/query_json.md`](../../specs/query_json.md)). List collections with the
`list` commands above.

```bash
echo '{"singular": {"type": "FindParameters"}}' | iroha ledger query stdin
echo '{"iterable": {"type": "FindAccountIds", "params": {"limit": 10}}}' | iroha ledger query stdin
```

### Stream events

`--timeout` is a deadline for the whole subscription, not an idle timeout. Use
`-o jsonl` for one compact JSON event per line:

```bash
iroha -o jsonl ledger events transaction --timeout 30s
iroha -o jsonl ledger blocks 1 --timeout 1m
```
## Rendering Markdown Help

Ensure the CLI builds, then run:

```bash
make docs-cli
# or
cargo run -p iroha_cli --bin iroha -- tools markdown-help
```

The full Iroha CLI reference is rendered from the live command tree and is not
checked into the repository. Redirect it to an operator-chosen path when a
standalone copy is needed. Kagami retains its smaller checked-in
`CommandLineHelp.md` snapshot and validates that snapshot in its unit tests.

Parliament timed-OVN `ballot register` and `ballot cast` require a complete,
independently authenticated `SumeragiFinalityCheckpoint` before reading or
creating seed material. Initialize custody once with
`--trusted-checkpoint-file <checkpoint.nrt>`, using the canonical headered Norito
checkpoint exported by `SumeragiFinalityVerifier::export_checkpoint`. The input
must be an owner-only regular file. Its signed genesis, chain label, retained
committee schedule and certified tip remain bound together; a height and digest
alone cannot initialize trust. Fetching a checkpoint from the same untrusted
proof response does not establish an independent trust anchor.

The owner-only state file defaults to `<key-file>.state.nrt`; `--state-file`
selects another path. It stores the same complete canonical checkpoint format
and advances atomically after each authenticated proof page under an exclusive
file lock. Existing state rejects initialization flags. Scalar JSON checkpoint
files and the former height/context-id arguments are rejected. `ballot status`
reads existing custody without changing it; `ballot dropout` authenticates its
context whenever a state file is selected, including through a lost key's path.

`iroha account history [--id ACCOUNT]` reads account movements. Explorer feeds
use `iroha explorer accounts`, `domains`, `asset-definitions`, `assets`, `nfts`,
`rwas`, `blocks`, `transactions`, `transactions-latest`, `instructions` or
`instructions-latest`. All accept shared list flags (`--filter`, `--select`,
`--limit`, `--cursor`, `--all`); history and Explorer feeds reject sorting,
totals and aggregates.
