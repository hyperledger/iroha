---
name: sora-taira-testnet
description: "Work against the SORA Taira testnet through its deployed Torii MCP endpoint, or operate the repository's disposable four-validator Taira devnet. Use for live account, asset, alias, contract, governance, Musubi, transaction, endpoint-health, and local deployment workflows."
---

# SORA Taira Testnet

Use current compiled Iroha surfaces and native Torii MCP. Do not reconstruct
API contracts in shell scripts.

## Select the workflow

- For a disposable local four-validator testnet, use
  `python3 scripts/taira_devnet.py up --inrou-canary-dir <owner-only-workspace>`.
- For live public Taira reads, prefer the curated `iroha.*` MCP tools at
  `https://taira.sora.org/v1/mcp`.
- For public endpoint diagnostics, use the same-revision compiled
  `iroha taira doctor --public-root https://taira.sora.org --json`.
- For explicitly authorized ordinary account onboarding or funding, use the
  same-revision integrated `musubi wallet create`, `musubi wallet fund`, and
  `musubi wallet namespace <full-domain>` workflow. Funding reads the independently
  trusted public faucet policy from the exact pinned network. The advanced native
  `iroha taira account onboard` or `iroha taira account faucet` workflows retain
  their separate `prepare`, `submit`, and read-only `resume` actions; obtain their
  explicit trusted issuer and any onboarding token from the deployment operator.
- For a public write canary, require explicit user authorization and use the
  same-revision `iroha taira public-reset apply` coordinator. Its
  `write-canary` child is a low-level singular prepared-operation surface, not
  a standalone aggregate command.

Stay read-only until the user explicitly asks to mutate live state. Treat
`authority`, `private_key`, bearer tokens, onboarding tokens, and forwarded
authorization headers as runtime-only secrets; never persist them in tracked
files or committed documentation.

## Disposable deployment

Before the first run on each native AArch64 Linux validator, install root-owned,
single-link executable implementations at `/usr/bin/qemu-system-aarch64`,
`/usr/bin/setpriv`, `/usr/bin/ldd`, `/usr/bin/bwrap`, `/usr/bin/nsenter`, and
`/usr/bin/socat`. All listed entries except `socat` must be direct files.
The packager authenticates every component of package-managed `socat`, dynamic
loader, and library symlink chains; its published runtime contains direct files.
Then create the fixed parent and package the immutable runtime from the
`optimizations` checkout:

```bash
sudo install -d -o root -g root -m 0755 /opt/iroha
sudo -- python3 scripts/ci/package_inrou_runtime_v1.py
```

The packager publishes only the previously absent
`/opt/iroha/inrou-runtime-v1/{root,manifest.sha256}` and never replaces it. Its
CLI exposes only canonical absolute `--qemu`, `--setpriv`, and `--ldd` source
overrides; use the defaults for Taira AArch64. The host must also provide
root-custodied `/usr/bin/qemu-img`, a supported standard-path `iptables`, KVM
API 12, and unified cgroup-v2 `cpu`, `io`, `memory`, and `pids` controllers.
The daemon's bounded startup probe verifies the remaining namespace, QEMU
user-network listener/private connector, QMP, firewall, and cgroup posture. It
does not start or verify the workload loopback bridge.

Run from the repository root:

```bash
python3 scripts/taira_devnet.py up \
  --inrou-canary-dir /private/runtime/taira-inrou-canary
python3 scripts/taira_devnet.py check
python3 scripts/taira_devnet.py down
```

`up`, `check`, and `down` serialize on the owner-only managed marker. `down` is
destructive by design: after it proves the exact managed cohort is stopped, it
atomically quarantines the cleanup directory, proves the same inode again, and
removes the complete tree, including configs, logs, state, and runtime
credentials. If either proof fails, it preserves the tree or quarantined racing
replacement for operator recovery.

All three disposable-deployment commands require Linux pidfds and procfs.
Kagami records each peer only as owner-only `peerN.process.json` schema V1,
binding its boot ID, process start time, executable path/device/inode, exact
argv/config, UID/GID, session, and process group. Every observation, restart,
signal, and exit wait reopens and holds a pidfd; signaling uses only
`pidfd_send_signal` and waiting uses the pidfd readiness event. Never add a
`ps`, numeric-PID signal, shell-kill, or non-Linux fallback. Retired
`peerN.pid` files are an error and are not migrated.

`up` builds the current Kagami, daemon, CLI, and SoraFS node and replaces one
marked owner-only directory under `/var/lib/iroha-taira-devnet/` by default. It
generates exactly four fresh-key NPoS validators on the canonical Taira chain,
binds them to loopback, validates all four configs with the current daemon,
stages and preseeds the required Inrou guest, starts the validators, requires
health/readiness, submits a signed ping, waits for its typed `Applied` status,
requires four-peer height convergence, performs a semantic MCP
initialize/tools-list smoke, and proves the exact four-replica workload route.
The preseed helper emits one canonical ready receipt while holding every store
lock, waits for parent stdin EOF, then emits the exact V1 `released`
acknowledgment; the parent requires all three protocol events in that order.

Treat `up` as the startup-boundary and guest-workload qualification command. It requires
Linux/AArch64, uid 0, KVM API version 12, and the four canonical locked Inrou
identities. Each daemon runs an artifact-free probe of the production machine
type and host CPU under KVM, private namespaces, cgroup limits, anonymous QMP,
QEMU user networking, the private loopback connector, and the owner firewall.
It then proves guest boot, a workload, four placements, and the public route
from the required canary workspace. `up` builds the fixed `local-release`
binaries for the exact native target, records the `optimizations` HEAD plus a
pre/post tracked-diff and non-ignored-untracked worktree observation, hashes the
selected executables, and verifies live validator and CLI build identities. The
report calls this `source_observation` and sets
`cargo_source_consumption` to `not_proven`; ignored files, Cargo configuration,
external build-script inputs, toolchains, and caches are outside its scope.
`check` is read-only live verification and requires the owner-only exact V1
guest qualification record emitted by `up`. It rehashes the retained input
snapshot, revalidates the retained stage with the exact recorded CLI binary,
requires that binary, the current `optimizations` HEAD, and every live
validator still match the recorded source/target identities, then invokes
exactly one `iroha taira inrou-check`. That command performs an account-signed
service-status read, compares the live container and service manifest hashes
with the fully revalidated stage, and observes all four exact route identities.
It does not repeat KVM qualification, submit a ping, register an artifact, or
submit an Inrou mutation. The historical deploy receipt is reported only as
`inrou_stored_deploy_receipt`; fresh evidence is `inrou_live_check`.

Keep the required `--inrou-canary-dir` workspace outside the repository and
disjoint from both `--dir` and the qualification Cargo target. Every
ancestor must be direct, root-owned, and non-writable by group/other. The
launcher pins each input identity and digest, revalidates it before cohort
replacement, snapshots it through no-follow descriptors, and reports
`inrou_canary_input_content_sha256`; the compiled stager consumes only that
owner-only snapshot.

Add `--full-doctor` to the mandatory `up --inrou-canary-dir ...` command only
when the broad public-product route surface is part of the test. The doctor is
additive and never replaces guest workload qualification.

This optional local diagnostic does not qualify a public ingress. Run the
same-revision `iroha taira doctor` directly against the public ingress under
test for that purpose.

The generated bundle contains private keys and tokens. Do not print, move,
archive, or commit it. On failure the command prints bounded peer log tails,
attempts bounded teardown, and destroys the bundle after proving shutdown and
directory identity. If either proof fails, it warns and retains the complete
bundle instead of claiming cleanup.

The local `iroha taira public-reset source-manifest --source-root /absolute/iroha`
command prints the exact Norito source manifest consumed by admission. Capture
stdout outside the checkout after its reviewed signed checkpoint. Export requires
one clean `optimizations` HEAD/tree and does not grant release authority; preflight
also requires the revision to match the compiled CLI. Every tracked entry is
bound: regular files retain exact modes and match their indexed Git blob bytes
through one streaming Git process, the unbuilt SDK symlink retains its
Git-authenticated relative target text with an absent in-root referent, and an
empty gitlink directory retains its exact indexed commit. Populated gitlinks or
materialized symlink referents require an explicitly supported closure; never
ignore them or relabel working-tree observations as a committed release.

Build the public-reset evidence binary with the release profile, then admit the
signed local inputs and all five read-only host targets from the Linux controller
before starting mutation:

```bash
cargo build --locked --profile release -p iroha_cli --bin iroha
target/release/iroha taira public-reset preflight \
  --inventory /private/runtime/taira-public-reset/inventory.json \
  --authorization /private/runtime/taira-public-reset/authorization.json \
  --trusted-public-key /private/runtime/taira-public-reset/trusted-public-key.json \
  --ssh-identity /private/runtime/taira-public-reset/id_ed25519 \
  --known-hosts /private/runtime/taira-public-reset/known_hosts
```

`iroha taira public-reset preflight` and `iroha taira public-reset apply` are
the only public-reset admission and execution surfaces. The local
`source-manifest` command only exports source metadata. There is no Python controller, compatibility
alias, or parallel V1 schema. Preflight performs local fail-closed admission and
then checks the four validators and edge through pinned SSH without creating a
journal, host lease, lock, progress or durable receipt. It does not load canary
signing inputs, tokens or runtime stages. Each host uses the signed install
timeout, and any host failure fails preflight. Apply repeats these host checks
and is the live mutating operation. Apply requires explicit owner-private,
runtime-only authorization, SSH, and canary inputs and every admitted host must
already contain the trusted compiled dispatcher and reset guard. Never persist
those inputs in the repository or let the candidate provision its own host
authority.

## Public MCP endpoint

The default public Torii root is `https://taira.sora.org`; its native MCP
endpoint is `https://taira.sora.org/v1/mcp`. If the operator supplies another
Torii root, use that exact deployment instead.

If MCP returns `404`, report that native Torii MCP is not enabled. If the MCP
endpoint or public root returns `502` or `503`, classify it as ingress or
upstream deployment degradation before investigating a signer or payload.

Prefer curated `iroha.*` tools over raw route wrappers. Use each tool's current
`inputSchema`; rediscover tools when the server reports a changed tool set.

The first-release public contract is exact:

- chain id: `fc56984b-2be7-431d-840e-21514d1883f0`
- Digital Shekel asset definition: `7ZepsJTHCVLKsrFFNZGSRGZgvBhv`
- public Digital Shekel alias: `ds#boi.is`
- Digital Shekel numeric scale: `2`
- native/fee XOR asset definition: `6TEAJqbb8oEPmLncoNiMRbLEK6tw`
- public XOR alias: `xor#universal`
- XOR numeric scale: `9`

Reject the retired `iroha3-taira` chain alias and legacy `<name>#<domain>`
asset-definition literals in Taira signing inputs. The KAGEMUSHA V1 top-up and
redemption commands were deleted from the source; do not build Digital Shekel
top-up or redemption inputs for the deployed `/v1/kagemusha/*` routes.

## Public-node triage

Before long or stateful writes, sample:

- `iroha.health`
- `iroha.blocks.list`
- `iroha.transactions.status` or `iroha.transactions.wait`
- `GET https://taira.sora.org/status`

Iroha does not create empty blocks. An unchanged block height is healthy when
there is no pending work; do not require idle height advancement or submit
transactions just to make height increase. Check queue saturation and the
relevant dataspace backlog. For an authorized write, prove that its exact
transaction hash reaches state-resolved `Applied`. If certified lane work is
pending without a canonical application, inspect lane frontiers and merge
selection as well as consensus status.

Interpret common failures narrowly:

- `route_unavailable` with healthy reads usually means public ingress cannot
  reach an authoritative peer for the write lane.
- `Transaction expired` usually indicates slow/stalled finality or queue
  saturation. Report `blocks`, `commit_qc_height`, `highest_qc_height`,
  `queue_size`, `tx_queue_depth`, `tx_queue_saturated`,
  `teu_dataspace_backlog`, and `view_change_causes.last_cause` when available.
- A transaction-status `404` means only that the queried node cannot currently
  see that hash; it does not prove commit, rejection, or network-wide loss.
- `Failed to find asset` during a signed canary usually means the signer is not
  funded for the fee asset.
- `403` after a chain reset is usually a signer existence or permission issue.

Do not infer validator-set size from `/status.peers`; that is the queried
node's current remote-peer count. Do not claim a whole-network outage from one
public node without validator/operator evidence.

## Public CLI diagnostics

Run the read-only public diagnostic without loading client configuration or
signing material:

```bash
target/release/iroha \
  taira doctor --public-root https://taira.sora.org --json
```

The `mcp_discovery` check validates native stateless `server/discover`. The
public-reset verifier consumes that same scoped diagnostic contract.

## Ordinary account onboarding and funding

For the ordinary Musubi developer flow, create or select runtime custody outside
the project, fund native XOR, and acquire the exact domain used by the contract
alias:

```bash
musubi wallet create
musubi wallet fund
musubi wallet balance
musubi wallet namespace developer.universal
musubi network configure taira --wallet default \
  --contract coffee-club --alias coffee::developer.universal
musubi deploy
musubi view --contract coffee-club --entrypoint quote --args '{"coffees":"3"}'
```

Choose an available domain and retain the same suffix in its contract alias.
The wallet pins the genesis-derived `NetworkId`, canonical Taira chain label,
profile 369 and trusted HTTPS root. Native public capability discovery supplies
the admitted signing policy. Funding separately reads
`/v1/accounts/faucet/policy`, verifies its exact network/profile and canonical XOR
asset, and uses the advertised issuer and amount as the independent policy for
native claim verification. The faucet's prepared response cannot choose a
different issuer, asset, amount or fee policy. This trusted public policy replaces
manual issuer delivery for integrated `fund`; the explicit issuer native CLI
path below remains available for operator-admitted contexts.

The deployed node must expose the current faucet-policy route. Its HTTP 404 is a
rollout prerequisite failure. The current basic and full doctor scopes validate
both account capabilities and faucet policy through the SDK and fail readiness
when either is missing or invalid; report that
specific blocker instead of guessing policy, changing assets, or inferring a
public reset request. Account creation, namespace acquisition, transfers and
contract writes use the normal native pipeline with explicit fee payment.
The faucet pays its funding transaction fees. Transfers and paid namespace
setup default to authority payment, with SDK-quoted limits in the retained
signed envelope; an exact sponsor revision can pay transaction fees but does
not automatically cover transferred principal or domain rent.

Registered, funded developers may publish immutable verified contract code with
normal fees; ordinary public artifact creation needs no global management
grant. Paid domain acquisition grants only its exact `CanManageAccountAlias`
scope. Named alias deployment still requires that scope and exact ownership/CAS
checks. `CanManageSmartContractCode` is for privileged unreferenced code removal
and entrypoint delegation; only `CanGrantSmartContractCodeManagement` admits
later grants/revocations of that management permission. Do not conflate those
privileged operations with normal developer code creation.

Wallet `fund`, `send` and `namespace` commands can stop at `--prepare`, submit a
saved envelope with `--submit <journal>`, or reconcile it read-only with
`--resume <journal>`. `--submit` dispatches only wholly unattempted work and
recovers an existing attempt without another dispatch. Preserve the printed
wallet/store selectors and journal path through recovery. Deployment uses its
own retained plan: `musubi deploy --prepare` followed by
`musubi deploy --resume <journal>`. Keys and tokens remain runtime-only; a
completed deployment requires exact Applied and code/address readback.

Use `iroha taira account onboard prepare|submit|resume` for one account and alias,
or `iroha taira account faucet prepare|submit|resume` for one funding claim. These
ordinary workflows do not require a public reset. Use a same-revision native CLI
and a populated client configuration in an owner-only runtime workspace. Pin the
canonical Taira chain, exact genesis network identity, and address profile 369.
For these explicit native CLI commands, obtain the onboarding issuer, onboarding
token, and faucet issuer/asset/amount policy independently from the operator;
never trust a prepared response to supply its own issuer or funding policy.
For public discovery, the read-only
`iroha.accounts.faucet.policy` tool maps to `GET /v1/accounts/faucet/policy`
and reports the enabled faucet's exact network, address profile, public authority,
canonical asset, and amount. In these operator-admitted CLI workflows, compare
this unsigned response with the operator's independent policy; it does not
establish the trusted preparation inputs.

Prepare a new operation in a previously absent journal directory whose parent
already exists. For example:

```bash
iroha --config /private/runtime/taira/client.toml --fee-payer authority \
  taira account onboard prepare --alias "<account-alias>" \
  --issuer "<trusted-onboarding-account>" \
  --token-file /private/runtime/taira/onboarding.token \
  --journal /private/runtime/taira/onboarding
iroha --config /private/runtime/taira/client.toml \
  taira account onboard submit --journal /private/runtime/taira/onboarding \
  --token-file /private/runtime/taira/onboarding.token
iroha --config /private/runtime/taira/client.toml \
  taira account onboard resume --journal /private/runtime/taira/onboarding

iroha --config /private/runtime/taira/client.toml --fee-payer authority \
  taira account faucet prepare --issuer "<trusted-faucet-account>" \
  --asset-definition "<canonical-faucet-asset>" --amount "<authorized-amount>" \
  --journal /private/runtime/taira/funding
iroha --config /private/runtime/taira/client.toml \
  taira account faucet submit --journal /private/runtime/taira/funding
iroha --config /private/runtime/taira/client.toml \
  taira account faucet resume --journal /private/runtime/taira/funding
```

Choose the explicit fee intent during preparation; submission reuses the retained
intent. The CLI generates a fresh public request ID unless `--request-id` supplies
one canonical 64-character lowercase hexadecimal ID. The public
`PreparedOperationBindingV1` binds that request and its execution deadline to the
verified receipt or claim. Preparation verifies the native SDK contract, solves
faucet PoW with bounded native code, and durably saves the exact signed envelope
before any submission. Journals contain public evidence, never private keys or
onboarding tokens. Keep the token in an owner-only runtime file or an explicitly
inherited descriptor; do not put it in command arguments or repository files.

After an ambiguous submission, use read-only `resume` with the same journal.
Never reconstruct, re-sign, or replace the retained transaction. Successful
transaction recovery requires its exact global, state-resolved `Applied` status
and the same committed signed wire envelope. Cached `Applied`, `Pending`, `Absent`,
or a successful submit response is not completion. If onboarding requires a
current-state proof instead of a transaction, the SDK atomically verifies the
account and alias and reports `AlreadyPresent`; this is not an `Applied`
transaction or proof of requested permissions. Follow up separately on any
reported owner auto-renew instruction. Funding does not grant namespace ownership
or privileged code-management authority: acquire and verify the exact alias
scope, and obtain operator admission only for operations that require a
privileged management permission.

## Public reset and canary qualification

For explicitly authorized public reset or write-canary qualification, use the
admitted same-revision `iroha taira public-reset apply` workflow. It owns the ordered onboarding,
faucet, and final-canary prepare/persist/submit/recover sequence. Its low-level
`iroha taira write-canary` child handles exactly one operation and exactly one
action over inherited numeric descriptors; there is no aggregate or one-shot
form. Keep the populated
`configs/soranexus/taira/taira-canary-client.example.toml` copy and onboarding
token in the owner-only runtime workspace. Do not replace the compiled protocol
with a parallel Python implementation.

Public-reset inventory, authorization, journal and report explicitly bind
`qualification_scope`. Use `core_testnet` for basic Taira and BPNG connectivity:
four-validator convergence, onboarding, faucet and an Applied write, restart
persistence, public Torii/MCP checks and application connectivity. Advanced
Inrou workloads are qualified separately. The `inrou` scope additionally runs
the Inrou mutations and fresh same-revision read-only Inrou checks; retained
receipts never substitute for current workload liveness. A core testnet result
does not claim Inrou qualification. The existing host stage/preseed barrier
remains part of installation in both scopes.

The basic scope restarts one validator and proves all four converge before the
postrestart onboarding, faucet and Applied write. Inrou qualification exercises
all four ordered restart waves. `taira doctor --scope basic` is the default
connectivity check; `--scope full` adds advanced product and synchronized-time
requirements. Basic reports valid local-clock fallback as a warning. Malformed
time/MCP responses still fail. Render public validator units with
`scripts/taira_validator_unit.py`; its Type=exec startup waits for the custody
launcher before native daemon attestation and readiness begin.

Host cleanup persists one request-bound plan before mutation, then
removes only marker-admitted upload/release roots and older superseded
marker-bound Inrou stage roots through crash-resumable tombstones within the
signed reclaim-byte cap. It does not scan or prune live state, secrets, the
selected release, its current Inrou stage, rollback state, or durable
`.operator-preseed-v1` qualifications.

Before other live writes, verify the account exists, holds a positive fee
asset balance, and has the exact required permission. After any reset, treat
cached or previously funded signers as suspect until rechecked.

## MCP transaction and package workflows

When the deployed writer profile advertises
`iroha.accounts.faucet.prepare` and `iroha.accounts.faucet.submit`, use them as
one exact two-step workflow: send the typed PoW claim, public
`PreparedOperationBindingV1` request/deadline binding, and explicit fee intent to
`prepare`, verify its response through the native SDK against the independently
trusted faucet policy, persist its returned prepared envelope unchanged, then
send that entire envelope to `submit`. Never reconstruct the
faucet-signed transaction or place keys, bearer tokens, or runtime authorization
material inside tool arguments. New prepared envelopes carry a
signature-bound marker version; consensus consumes the authority-scoped claim
marker atomically with successful execution, so a duplicate claim through a
different binding, peer, generic transaction ingress, or restart must be
treated as a deterministic rejection rather than retried as another payout.
Use writer tools only when the deployed profile advertises the current verified
prepared-operation contract and the operator has admitted their authority and fee
policy. Ordinary account operations use their own public request bindings; the
public-reset coordinator retains its separate durable reset/canary protocol.

For a pre-signed transaction envelope, prefer
`iroha.transactions.submit_and_wait`:

```json
{
  "body_base64": "<base64-encoded versioned SignedTransaction>",
  "hash": "<64-character canonical lowercase Iroha transaction hash>",
  "status_accept": "application/json",
  "timeout_ms": 120000
}
```

Compute the expected hash locally and require the submit receipt hash, returned
hash fields, and exact global, state-resolved `Applied` status to match it. The
wait finality rule is fixed and has no terminal-status override. `Rejected`,
`Expired`, cached `Applied`, a timeout, or a successful submit without
state-resolved `Applied` is not success. Do not pass more than one envelope
encoding.

For Musubi reads, prefer:

- `iroha.musubi.queries.exact_package`
- `iroha.musubi.queries.exact_release`
- `iroha.musubi.queries.resolver_index`
- `iroha.musubi.queries.versions`
- `iroha.musubi.queries.maintainers`
- `iroha.musubi.queries.archive_locations`
- `iroha.musubi.queries.alias`
- `iroha.musubi.queries.alias_history`
- `iroha.musubi.queries.ordered_prefix`

Pass the structural V1 package/release object required by `inputSchema`.
Human-facing `namespace/package` text is not a substitute for typed
`home_dataspace`, `scope`, and `name` fields.

Musubi instruction helpers return unsigned Norito-framed instructions. They do
not accept signing material. Assemble and sign locally, then submit with
`iroha.transactions.submit_and_wait`. Common helpers are:

- `iroha.musubi.instructions.release_publish`
- `iroha.musubi.instructions.release_yank_set`
- `iroha.musubi.instructions.alias_register`
- `iroha.musubi.instructions.release_digest_assert`

## SoraFS and application reads

For SoraFS/app-api diagnosis, sample both:

- `GET /v1/sorafs/capacity/state`
- repeated `GET /v1/app-api/cid/<cid>`

A stable app-api `404` with zero capacity declarations suggests missing provider
publication. Mixed `200`/`404` responses suggest inconsistent upstream manifest
visibility, not a bad CID.

## Response handling and safety

1. Treat a routed read as incomplete when the
   `x-iroha-fanout-routes-*` headers show any failed, denied, unavailable, or
   not-found route, even when HTTP status is 2xx. Do not reconcile or zero
   cached wallet state from an incomplete read.
2. Report transaction hashes and exact global/state `Applied` evidence for successful writes.
3. Surface server errors and classify them as authentication, validation,
   missing-tool exposure, endpoint availability, or chain-health failures.
4. Do not invent operator credentials or direct validator hostnames.
5. Do not assume operator-only routes are exposed publicly.
6. Persist a newly generated signer only when the user explicitly requests it,
   and then only in an ignored owner-only runtime file.
