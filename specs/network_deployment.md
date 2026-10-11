# Iroha network and dataspace deployment

Status: operator deployment design under implementation. This specification covers
definition-driven `iroha network` and `iroha dataspace` workflows. The first-release
[Kagami/Mochi developer contract](kagami_mochi_devex_goals.md) owns unattended
localnet startup, one-call contract deployment and local owner-private dataspace
attachment without user-supplied definitions. Both surfaces share `iroha_deploy`.
Restricted globally merged lanes described here do not satisfy the developer
workflow's independent private-State requirement.

Current implementation on `optimizations`: `iroha dataspace plan|apply|status
<definition> --trust <public-profile.json>` is the canonical existing-network
path. It derives the owner from `owner_key`, selects an authenticated HTTPS
parent, and constructs native manifests from the exact four-member NPoS
validator/account bindings in the independently selected signed genesis.
Before catalog signing it checks that those members have matching live
Committee-role credentials; HTTP responses do not supply new account bindings.
It retains immutable plans and once-only signed transactions beneath
`~/.iroha-dataspaces` (or `--state`). An explicit operator signing credential is
still required for authenticated reads. `max_fee` bounds the total operation.
`plan` writes only local state, `apply` plans if needed, and `status` never
submits. `dataspace export-profile` exports the independently retained public
network/chain/discriminant/genesis/validator trust input once per parent.

The same operation lock covers definition validation, preflight, planning and
execution. A purpose-bound preflight child journal retains verified finality
proofs even before a plan can be published. Batches of at most 128 new proofs
continue automatically within the command timeout; retries reauthenticate the
retained local prefix and fetch its missing successors. This cache cannot admit
signed phases, dispatch claims or completion evidence when their plan is lost.
An unsigned alias phase may refresh only its deadline under unchanged terms,
policy and exact rent; every already signed transaction remains immutable.
Before a plan or deployment evidence exists, explicit `plan` may correct only
the total fee cap. The read-only proof cache survives that correction; spending
continues to bind the exact current definition and subsequently retained plan.

The catalog transition atomically adds the corresponding native fixed-lane
policy. Ordinary finalization creates its record at carrier height `h`, active
from `h + 2`; catalog, bootstrap and namespace acquisition remain global, and
application transactions resolve the exact dataspace and wait for its native
lane. Completion requires authenticated catalog/namespace state and every
expected validator's matching, active native lane instance. A catalog row alone
is insufficient. The retired manual `taira dataspace-deploy` command has no
alias. Owner committees, SSH/edge provisioning and explicit `[monitor]` are not
implemented by this runtime and are rejected. The in-process native test now
passes paid catalog/bootstrap/namespace execution and a real three-of-four BLS
private-lane certificate through production storage and global merge. The focused
CLI dataspace suite passes 111 tests; the four-daemon deployment rehearsal
is an optional engineering diagnostic, never a signing or deployment prerequisite
for Taira or production. Full regression suites and fixed-duration fault runs,
including 24-hour tests, are likewise optional. This source change performs no
live deployment.
The rest of this design includes planned network rendering, owner committees
and teardown work.

Approved decisions (2026-09-26):
- The overall design is approved: `iroha network` and `iroha dataspace` run on one `crates/iroha_deploy` engine, network constants come from compiled profiles, and the old Taira toolchain is deleted.
- One release. Every phase lands before anything is released, and Taira gets exactly one ledger replacement: the P9 restore, done with the new engine, whose genesis already carries the dataspace protocol and Inrou.
- The customer dataspaces that were baked into genesis (is, dpn, paynet, sbp, cbuae, is2, cbsi) are re-registered as runtime dataspaces during that same restore.
- Minamoto is out of scope. `--sora`, `IROHA_SORA_PROFILE` and `apply_sora_profile` stay unchanged.
- Still open, needed before P9: the host provider and architecture for 4 validators plus the edge, custody of the CI release key, and the SSH access mode (root with `restrict`, or sudo).

---

## 0. Summary

**Problem.** Deploying public Taira, or a private dataspace on Taira, currently goes through about 153k lines of Taira-specific tooling:
- 80.6k lines of Rust in `iroha_cli` `taira*`;
- about 30k lines of Python scripts and 28.5k lines of Python tests;
- plus shell and docs;
- plus 16.7k lines of `kagami localnet`.

The operator faces 19 `public-reset` subcommands and a hand-written topology intent of about 238 values, of which about 24 are real choices. Behind it sit four journals, four locks, a root host dispatcher (rotating it is a ceremony of its own), all validators on one SSH host, seven Taira definitions that disagree with each other, and a release gate that runs on every deploy.

One run of 32 release attempts took about 91 hours, and roughly half of those failures came from the tooling itself. Public Taira has been down since 2026-09-15: an update crossed the first mandatory NPoS beacon pulse with no beacon session installed, and nothing checked for that. No private dataspace deployment has ever completed.

**Design.** One compiled engine lives in the new library crate `crates/iroha_deploy`. It is exposed as two small verb families in the existing `iroha` CLI:

```
iroha network   plan | apply | reset | verify | status | up | down
iroha dataspace plan | apply | status | down
```

The hand-written inputs:
- one TOML network definition (about 50 lines for Taira);
- one TOML dataspace definition per dataspace (10–35 lines).

Everything else is derived or observed:
- keys, generated on the hosts;
- genesis and the beacon session;
- per-node configs of about 20 keys;
- systemd units, the nginx edge and per-node mTLS gateways;
- host-key pins, checked against the definition;
- the network card and all evidence.

The same engine runs every scenario:
- **S3, devnet.** A local driver with a native supervisor. It runs unprivileged on macOS and Linux, x86_64 and aarch64. A container render mode serves compose fixtures.
- **S1, public Taira.** Remote Linux hosts plus an edge, reached over SSH. The agent is the release's own content-addressed `iroha` binary.
- **S2, private dataspace on Taira.** A typed on-chain `RegisterDataspaceV1`. The lane committee is either Taira's validators or validators the owner brings, and the owner's validators are provisioned by the same engine.

Consensus-bound constants move into compiled, named network profiles in `iroha_config`. Each profile has three parts:
- static constants;
- a compiled `derive(n)` step for roster-dependent geometry;
- non-consensus deployment policy.

It carries separate consensus and policy digests.

One `iroha3d` binary replaces `iroha3d_taira`, the FD 198/199/200 transport and the inline-Python launcher. It reads owner-only files from `<data_dir>/secrets/`.

Deploys never build and never run regression suites. CI produces a signed release bundle from authenticated source and exact built artifacts. Regression suites and four-peer fault rehearsals are optional diagnostics and never prerequisites for signing or deploying a release. On-chain governance owns deployment policy for testnet and production.

**Guarantees.** Protocol-level guarantees are unchanged: signatures, 2f+1 finality over exact 3f+1 committees, pinned peer and network identity, permissions, revocation, and replay protection. Deploy-time ceremony that had no live-safety value is deleted: the owner-signed authorization envelope and its 15-minute window, the dispatcher, the guards and the dispatcher transition, the source closures, the receipt chains, and transcribed hashes.

**Outcome.**

| Scenario | Operator effort | Time |
|---|---|---|
| Public Taira first deploy | 1 file, `plan` once to pin host keys, then `apply` | ~20–30 min with Inrou off (up to 10 min of that waits for first snapshots); ~35–45 min with Inrou |
| Ledger-preserving upgrade | 1 command | ~10–20 min |
| Reset | 1 command, plus typing the network name | ~20–35 min |
| S2a | 1 command after a one-line grant | minutes |
| S2b | 1 command | ~20–40 min, plus replaying the Taira chain |
| Devnet | `iroha network up`, no decisions | ~60–90 s after `cargo build` |

**Restoration.**
- Everything ships in one release.
- Taira comes back once, at P9: four separate Linux hosts plus an edge, Inrou on. Its genesis already carries the dataspace protocol: the new permission tokens and the registration budget.
- The customer dataspaces are re-registered through `iroha dataspace apply` in the same restore.
- This is the only planned ledger replacement.

**Size.** Deploy tooling goes from about 153k lines to about 27k production lines (about 9k of them moved code) plus about 12k lines of tests. The new node and protocol features add about 8k production lines and about 5k lines of tests.

---

## 1. Principles

1. **One hand-written file per network or dataspace.** It states what should exist. It contains no secrets, no hashes, and no timeouts or paths the code already knows. Secret-bearing values such as a webhook URL are referenced by file path.
2. **Converge, don't choreograph.** Every host action is an idempotent ensure: check, act, verify. Re-running the same command is the recovery procedure.
3. **Destroying a ledger is its own verb.** Only `iroha network reset` creates a new generation. It needs the network name typed, and it restores the old generation automatically if the new one is not proven. `apply` refuses any plan that implies a reset.
4. **On-chain writes happen at most once.** They are journaled as exact signed wire and reconciled by an effect predicate. Nothing is re-signed while an older signature could still land.
5. **Protocol guarantees live in the protocol.** Tooling checks attestations, finality proofs and genesis identity. It never re-implements or re-signs them.
6. **Build once, deploy many.** Deploys consume signed, content-addressed bundles. Cargo and tests run only in CI or in the maintainer's release command.
7. **Compiled Rust only.** No Python or shell orchestration, and no Python on hosts. Records are Norito, and definitions are read with `iroha_config_base` `ReadConfig`. There is no serde.
8. **Every gate traces to a recorded incident or a protocol property.** Every deleted mechanism is shown to have prevented no recorded incident (§7).
9. **Secrets stay where they were born.** Validator keys never leave their host. Network authority keys and beacon shares pass once through controller memory and are zeroized there.
10. **Cutover, not coexistence.** A replacement lands together with the deletion of what it replaces. No release point has two paths.
11. **Inrou is a per-network toggle.** It is on for public Taira validators. It is off for devnets, observers and owner-run lane validators, and in those cases it is never loaded or checked.

---

## 2. Concepts

- **Network definition** (`networks/<name>.toml`). Hosts, profile, toggles, edge, grants. Committed to git.
- **Dataspace definition** (`dataspaces/<name>.toml`). Parent network, name, visibility, owner key path, fee cap, and the committee source: `network`, or `owner` with a list of hosts.
- **Role.**
  - `validator`: member of the global roster.
  - `observer`: explorer, indexer or archive node. It syncs, does not vote, and has no Inrou.
  - `lane_validator`: an owner-committee node. It runs the global protocol as an observer and signs its own lane.
- **Profile.** A named, versioned, compiled bundle. Examples: `sora-nexus-v1` (the Taira shape), `sora-nexus-v1-qual` (differs only in genesis cadence, epoch length and snapshot interval), `iroha-dev-v1`. A profile has four parts:
  - `static`: consensus-bound constants that do not depend on roster size;
  - `derive`: the inputs to a compiled `derive(n)`, which computes queue, byte and connection geometry, the NPoS `max_validators = n`, and lane quorums;
  - `policy`: non-consensus deployment policy such as rate limits, storage budget, Soracloud capacities, systemd limits and snapshot interval;
  - role overlays.

  `consensus_digest = H(static ‖ derive(n) ‖ genesis recipe)`. `policy_digest = H(policy ‖ roles)`. When a node config sets `profile`, only allowlisted per-node keys may appear in it. It requires `validators` and `data_dir`; `role` defaults to `validator`. The profile owns the discriminant and the role owns the Sumeragi role.
- **Release bundle.** A signed tar of content-addressed blobs plus a `ReleaseManifestV1`. It is the only thing that changes code on hosts.
- **Node card.** The public output of on-host key generation: peer id, PoP, account key, transport and streaming public keys, gateway certificate, addresses.
- **Generation.** One ledger lifetime, identified by its NetworkId. It is recorded in `GENERATION` next to each node's state, outside the Kura store root.
- **Plan and decision hash.** The diff between desired state (definition, profile, release) and observed state (agent host facts, attested chain facts). The decision hash covers only facts that change decisions: release digests, config and unit hashes, `GENERATION` contents, node cards, host keys, roster, edge config hash and grant set. `apply` refuses if the decision hash changed since the plan. Volatile facts such as heights, lag and blocks-to-pulse are re-validated as gates at action time.
- **Op journal and host record.** One controller journal per operation. Each touched node gets a host-side `host-record.norito` holding its prior release, config, unit, state location and health class, so rollback works even if the controller is lost.
- **Network card.** A public description of the network: chain id, NetworkId, genesis key, profile `{id, roster_size, consensus_digest}`, roster with PoPs and URLs, release, public root. It is served at `/.well-known/iroha/network-card.norito` over an untrusted transport, and clients verify it against genesis and 2f+1 challenge-bound attestations. At seal the tool also writes a human-readable **card anchor**, `networks/<name>.card.toml`, next to the definition. Committed with a signed commit, it is the out-of-band anchor that owners and SDKs compare against.
- **Gates.** One ordered set of checks, G0–G12 (§9), shared by plan, apply, reset, verify, the watch timers and dataspace apply.

---

## 3. What the operator writes: file formats

### 3.1 Format rules and state layout

- Definitions are TOML, parsed by `iroha_deploy::definition` through the `iroha_config_base` `ReadConfig` derive. Errors carry their origin and unknown keys are errors. There is no serde.
- Relative paths resolve against the file, and `~` is expanded. Files contain only public data, so they are safe to commit.
- `<DEF>` accepts either a path or the name of a network already in the state root.
- **Network state:** `~/.local/state/iroha/networks/<name>/`. Override with `--state DIR`. The tool refuses a state directory inside a git worktree (the rule kept from `kagami localnet.rs:1411-1413`). It contains:
  - `lock`, `known_hosts`
  - `keys/`: generated `admin.key`, `operator.key`, 0600
  - `credentials/<id>.token`, `client.toml`
  - `cards/<network-id>.norito`, `checkpoint.norito`
  - `ops/<op-id>/{journal.norito, log.txt, diagnostics/}`
  - `local/` (local and container drivers only)
- **Dataspace state:** `~/.local/state/iroha/dataspaces/<name>/`. It contains `lock`, `known_hosts`, `keys/operator.key` (the owner's operator key for its own nodes), `cards/` (the pinned parent card), `checkpoint.norito`, `ops/`, and `local/` for rehearsals.
- Validator and owner-node private keys are never stored in either state directory.

### 3.2 Network definition schema

```
[network]                        required
  name               [a-z0-9-]{1,32}. State dir, unit names, host paths.
  profile            "sora-nexus-v1" | "sora-nexus-v1-qual" | "iroha-dev-v1".
  chain_id           string. Absent: fresh UUIDv4 per generation (devnets).
  chain_discriminant u16. Default from profile (sora-nexus-*: 369; iroha-dev-v1: 753).
  public_root        https URL. Required iff [edge].
  admin_key          path to 0600 Ed25519 key. Absent: generated into <state>/keys/admin.key.
  operators          [public key]. Extra Torii operator keys; <state>/keys/operator.key is always included.
[release]                        optional
  source             URL or directory of bundles. Default: official channel compiled into the CLI.
  signers            [Ed25519 public key]. Default: CI + maintainer keys compiled into the CLI.
[ssh]                            required iff any host is remote
  identity           path to the deploy key (.pub or private); selects the key.
  agent              bool, default true: IdentityAgent=$SSH_AUTH_SOCK, IdentitiesOnly selecting `identity`
                     (passphrase-protected or hardware-backed keys work). false uses an unencrypted
                     key file directly and is refused for networks with [edge].
  user               default "root".   become   "none" | "sudo" (required when user != "root").
  port               default 22.
  jump               optional "user@host[:port]".   jump_host_key   required iff jump.
[inrou]      enabled   bool, default false. Validator-role nodes only.
[faucet]     enabled   bool, profile default.   amount   decimal, profile default.
[[onboarding.credential]]        repeatable
  id                 string. Renaming or removing an id rotates or revokes it (exact set).
  scope              "universal" | "dataspace:<name>".
[edge]                           optional
  host, host_key     edge SSH host and its pinned key.
  domain             e.g. taira.sora.org.
  tls_certificate / tls_private_key   paths on the edge host (certbot owns renewal).
  cors_origins       [origin], default [].
  per_node_domains   bool, default false (true requires node.domain).
  explorer_domain / explorer_root     optional explorer vhost; the tool writes runtime-config.json.
  upstream           "mtls" (default: per-node TLS gateway, Torii bound to loopback) |
                     "private" (Torii bound to node.private_address; G0 requires RFC1918/ULA/100.64/10).
[monitor]    webhook_file   path to a 0600 file containing the webhook URL.   interval   default "5m".
[retention]  releases = 3; previous_ledgers = 1; failed_ops = 1; journal_max = "2G".
[local]      local/container drivers only: bind_host = "127.0.0.1", public_host, base_torii_port = 29080,
             base_p2p_port = 29337.
[scaling]    local/container drivers only (perf definitions): lanes, accounts.
[[grant]]    repeatable; exact set, converged on-chain by the admin; removing a line revokes it.
  account            AccountId.   permission   "CanRegisterDataspace" (only value in v1).
[[node]]                         validators must be exactly 3f+1 and >= 4
  name               unique slug.
  role               "validator" (default) | "observer".
  host / host_key    SSH host (absent = local driver) and its pinned "ssh-ed25519 AAAA..." key.
  address            advertised P2P host. Default: host, or [local] public_host.
  private_address    required iff edge.upstream = "private".
  domain             per-node public domain (edge.per_node_domains).
  p2p_port / torii_port   default 1337 / 8080 remote; base + index locally.
  failure_domain     default: the host identity. Use it for VMs sharing a physical host or disk.
```

Parse-time and plan-time validation:
- Exactly 3f+1 validators, at least 4.
- For remote definitions, it is a hard error if more than f validators share one host identity (aliases with the same host key count as one host) or one `failure_domain`.
- Every host of a network with `[edge]` must have `host_key` set, which removes trust on first use. On first contact, `plan` prints the scanned keys as ready-to-paste lines for the operator to compare with the provider console.
- `[inrou] enabled` requires Linux validator hosts and a guest image in the release for every validator ISA.
- `[edge]` requires `public_root`.

### 3.3 Dataspace definition schema

```
[dataspace]                      required
  name               SNS dataspace name; determines DataSpaceId.
  network            parent https root | path to a network definition | path to a card anchor file.
  network_id         optional pin "hash:<64 hex>#<crc>" (non-interactive; else prompt on first use).
  visibility         "restricted" (default) | "public".
  owner_key          path to the owner's 0600 Ed25519 key (the owner account is derived from it).
  account_alias      optional (creates <alias>@<name>).
  lease_years        1..10, default 1. apply renews when < 60 days remain.
  max_fee            decimal in the parent's fee asset; hard cap across all registration writes.
  operators          optional [public key], only for source = "owner" nodes.
[committee]  source   "network" (default; entire section may be omitted) | "owner".
[ssh]                            as above; allowed iff source = "owner" with remote hosts.
[edge]                           optional, source = "owner" only: host, host_key, domain,
                                 tls_certificate, tls_private_key, upstream. When present every member's
                                 manifest torii_url is https://<node>.<domain>; when absent no torii_url is
                                 bound and Taira reaches the committee over P2P only. upstream = "private"
                                 is refused until committee nodes gain a private address (TODO P6).
[monitor]    webhook_file, interval.
[[committee.node]]               iff source = "owner"; exactly 3f+1, >= 4
  name, host, host_key, address, p2p_port, torii_port, failure_domain.
```

Inrou is not accepted in dataspace files in the first release, because Soracloud placement targets global validators only.

### 3.4 `networks/taira.toml`

This is the only hand-written Taira deploy input, and it is committed.

```toml
[network]
name = "taira"
profile = "sora-nexus-v1"
chain_id = "fc56984b-2be7-431d-840e-21514d1883f0"
chain_discriminant = 369
public_root = "https://taira.sora.org"
admin_key = "~/.iroha/keys/taira-admin.key"

[ssh]
identity = "~/.ssh/taira_deploy_ed25519.pub"   # held in ssh-agent (agent = true by default)
user = "root"

[inrou]
enabled = true           # Inrou on for public Taira validators

[faucet]
enabled = true

[[onboarding.credential]]
id = "inori-app"
scope = "universal"

[edge]
host = "taira-edge.sora.org"
host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...edge"
domain = "taira.sora.org"
tls_certificate = "/etc/letsencrypt/live/taira.sora.org/fullchain.pem"
tls_private_key = "/etc/letsencrypt/live/taira.sora.org/privkey.pem"
cors_origins = ["https://taira-explorer.sora.org", "https://explorer.sora.org"]
per_node_domains = true
explorer_domain = "taira-explorer.sora.org"
explorer_root = "/var/www/taira-explorer"

[monitor]
webhook_file = "~/.iroha/secrets/taira-webhook.url"

# Dataspace registration rights (exact set).
# `iroha dataspace plan` prints the exact line for an owner to send here.
# [[grant]]
# account = "<owner account id>"
# permission = "CanRegisterDataspace"

[[node]]
name = "v1"
host = "taira-v1.sora.org"
host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...v1"
domain = "taira-validator-1.sora.org"

[[node]]
name = "v2"
host = "taira-v2.sora.org"
host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...v2"
domain = "taira-validator-2.sora.org"

[[node]]
name = "v3"
host = "taira-v3.sora.org"
host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...v3"
domain = "taira-validator-3.sora.org"

[[node]]
name = "v4"
host = "taira-v4.sora.org"
host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...v4"
domain = "taira-validator-4.sora.org"
```

### 3.5 `networks/dev.toml`

This file is also the built-in default when `iroha network up` is given no file.

```toml
[network]
name = "dev"
profile = "sora-nexus-v1-qual"   # Taira policy; 64-block epochs so verify --full crosses a pulse in ~1 min
# chain_id omitted: fresh per generation

[[node]]
name = "n0"
[[node]]
name = "n1"
[[node]]
name = "n2"
[[node]]
name = "n3"
```

No node has a host, so the local driver runs it:
- 127.0.0.1, Torii on 29080+i, P2P on 29337+i;
- Inrou off, unprivileged;
- keys generated into the state dir.

`networks/ci.toml` is identical apart from its name. `networks/perf-10k.toml` adds `[scaling] lanes = 8`, `accounts = 10000` and sets `profile = "sora-nexus-v1-qual"`.

### 3.6 `dataspaces/dpn.toml` (S2a: committee = Taira validators)

The checked-in [DPN definition](../dataspaces/dpn.toml) has five inputs:

```toml
[dataspace]
name = "dpn"
network = "https://taira.sora.org"
owner_key = "~/.iroha/keys/dpn-owner.key"
account_alias = "admin"
max_fee = "0"
```

Restricted visibility, a one-year lease and the parent network's committee are
inherited defaults. The zero cap authorizes no spending; set an explicit cap
for paid registration. Network services, global governance, validator keys,
consensus tuning and unrelated lanes are not dataspace inputs and are rejected.
`iroha dataspace plan|apply|status` consumes this definition with an independently
selected `--trust` profile and a separate operator read credential. It derives
the native lane and manifests and retains one durable operation. The current
path supports the existing four-validator parent committee; owner provisioning
and the broader P6 lifecycle remain open. See the
[implementation contract](../docs/source/taira_dataspace_deploy.md).

### 3.7 `dataspaces/acme.toml` (S2b: owner-brought validators)

```toml
[dataspace]
name = "acme"
network = "https://taira.sora.org"
network_id = "hash:<64 hex from networks/taira.card.toml>#<crc>"   # optional non-interactive pin
visibility = "restricted"
owner_key = "~/.iroha/keys/acme-owner.key"
account_alias = "treasury"
max_fee = "50"

[committee]
source = "owner"

[ssh]
identity = "~/.ssh/acme_deploy_ed25519.pub"
user = "deploy"
become = "sudo"

[edge]                               # optional public Torii for the lane (manifest torii_url)
host = "dsv1.acme.example"
host_key = "ssh-ed25519 AAAA...dsv1"
domain = "ds.acme.example"           # per-node https://acme-1.ds.acme.example ...
tls_certificate = "/etc/letsencrypt/live/ds.acme.example/fullchain.pem"
tls_private_key = "/etc/letsencrypt/live/ds.acme.example/privkey.pem"

[[committee.node]]
name = "acme-1"
host = "dsv1.acme.example"
host_key = "ssh-ed25519 AAAA...dsv1"
[[committee.node]]
name = "acme-2"
host = "dsv2.acme.example"
host_key = "ssh-ed25519 AAAA...dsv2"
[[committee.node]]
name = "acme-3"
host = "dsv3.acme.example"
host_key = "ssh-ed25519 AAAA...dsv3"
[[committee.node]]
name = "acme-4"
host = "dsv4.acme.example"
host_key = "ssh-ed25519 AAAA...dsv4"
```

For a local rehearsal, set `network = "../networks/dev.toml"` and remove the `host`, `[ssh]` and `[edge]` keys. The owner nodes then run as extra processes under the dev network's supervisor.

### 3.8 What the tool generates (never hand-edited)

**Per-node config.** Written to `/etc/iroha/taira/v1/config.toml` (0640 root:iroha). The plan records its hash.

```toml
# Generated by `iroha network apply` (op 01JAX...). Do not edit.
profile = "sora-nexus-v1"
validators = 4                                  # network roster, not the seed-peer count
chain = "fc56984b-2be7-431d-840e-21514d1883f0"
data_dir = "/var/lib/iroha/taira/v1"              # state/ and secrets/ are fixed subpaths
public_key = "ea0130..."                           # BLS; private part in secrets/validator.key
trusted_peers = ["ea0130...@taira-v1.sora.org:1337", "ea0130...@taira-v2.sora.org:1337",
                 "ea0130...@taira-v3.sora.org:1337", "ea0130...@taira-v4.sora.org:1337"]
trusted_peers_pop = [{ public_key = "ea0130...", pop_hex = "..." }]   # x4, from node cards

[network]
address = "addr:0.0.0.0:1337#BF18"
public_address = "addr:taira-v1.sora.org:1337#<crc>"

[torii]
address = "addr:127.0.0.1:8080#<crc>"             # reachable only through the local mTLS gateway

[torii.transport]
trusted_proxy_cidrs = ["127.0.0.1/32"]

[torii.operator_signatures]
allowed_public_keys = ["ed0120<controller operator key>"]

[torii.account_onboarding]
authority = "<onboarding authority account id from genesis>"   # key: secrets/authority/onboarding.key
[[torii.account_onboarding.credentials]]
id = "inori-app"
scope = { dataspace = "universal" }               # user.rs:18243-18251 table form
token_hash = "blake3:<hex>"

[genesis]
public_key = "ed0120<genesis key>"
expected_hash = "hash:<64 hex>#<crc>"
file = "/var/lib/iroha/taira/v1/genesis.nrt"

[soracloud_runtime.submission.signer]             # public binding; private key secrets/runtime_signer.key
handle = "<profile handle>"
authority = "<validator account id>"
algorithm = "ed25519"
public_key_hex = "<hex>"
revision = 1
policy_digest_hex = "<profile policy digest>"

[soracloud_runtime.inrou]
enabled = false        # when true: portable_vm_uid/gid = 70000(+k) and trusted_guest_{manifest_digest_hex,content_cid} for this
                       # node's ISA; never otherwise (actual.rs:373-379 rejects a disabled table carrying them)
```

Optional top-level `role` defaults to `validator`; use `observer` or `lane_validator` explicitly. See the parser-tested [validator template](../configs/validator.example.toml).

A few values are derived at load time and never written:
- the profile network discriminant and the selected Sumeragi role;
- secret file paths, including the onboarding and faucet authority key files;
- every state path;
- the transport and streaming public keys;
- the beacon provider binding.

The Soracloud signer's public binding is rendered, so the parse-time checks keep working: `production_mode` requires `submission.signer` (`actual.rs:254-274`). The daemon then checks that the secret file matches `public_key_hex`.

**Profile layout.** `crates/iroha_config/profiles/sora-nexus-v1.toml`, compiled in with `include_str!`.

```toml
[profile]
id = "sora-nexus-v1"
version = 1
chain_discriminant = 369                    # the profile's account literals are encoded for it
node_tunable = ["logger.level", "logger.filter"]

[genesis_recipe]  # genesis inputs the profile fixes -> consensus_digest
consensus_mode = "npos"
block_cadence_ms = 5000
epoch_length_blocks = 3600
# block_max_transactions, ivm_gas_limit_per_block, npos_min_self_bond

[static]      # consensus-bound, roster-independent -> consensus_digest
# 155 execution-policy fields (actual.rs:3639-4304), 59 AMX fields (actual.rs:5056-5260), pipeline.gas,
# crypto, zk, confidential, Nexus baseline catalog (core system lanes + public `nexus` lane only),
# sumeragi.keys and P2P frame caps. Block limits and payload geometry are signed chain parameters.

[derive]      # inputs to iroha_config::profile::derive(n) -> consensus_digest
authenticated_non_validator_sources = 4     # connections for authenticated observers (first come)
max_external_committee_peers = 12           # on-chain budget; committee_sources = n + 12
# [[derive.dataspace_catalog]]: baseline dataspaces; derive(n) adds fault_tolerance = f to each

[policy]      # not consensus-bound -> policy_digest (changes roll, never reset)
# Torii public ingress limits, MCP, storage budget/weights (from defaults.rs:97-160), WSV memory,
# Soracloud capacities, fail-closed egress, Inrou ceilings, snapshot.create_every_ms = 600000.

[host]        # host policy that is not node configuration -> policy_digest
systemd_memory_max = "4G"
systemd_cpu_quota = "200%"
p2p_port = 1337
torii_port = 8080

[role.validator]
soracloud_runtime.production_mode = true
[role.lane_validator]
soracloud_runtime.production_mode = false
[role.observer]
soracloud_runtime.production_mode = false
```

`derive(n)` reuses the existing localnet geometry derivation, moved out of `kagami localnet.rs`. It computes `f`, the `2f + 1` commit quorum and `network.max_total_connections` (D-4), adds `fault_tolerance = f` to every baseline dataspace, and pins genesis `npos.max_validators = n`, as `localnet.rs:3759` does today. Sumeragi itself takes no roster-dependent node configuration.

`sora-nexus-v1-qual` overrides only these: `epoch_length_blocks = 64`, `block_cadence_ms = 1000`, `snapshot.create_every_ms = 30000`, and a 512 MiB storage budget.

**Other generated records.**

`GENERATION` (Norito JSON):
```
{chain_id, network_id, generation, proven, created_at_ms, op_id}
```

`host-record.norito`:
```
{op_id, status: in_progress|sealed|rolled_back, prior_release, prior_config_sha256, prior_unit_sha256,
 prior_generation, prior_health: healthy|degraded|halted,
 state_action: none|moved_to_previous|checkpointed|fresh}
```

The network card is `NetworkCardV1 {chain_id, chain_discriminant, network_id, genesis_public_key, profile {id, roster_size, consensus_digest, policy_digest}, roster [{peer_id, pop, p2p_address, torii_url}], release {version, manifest_digest, bundle_url}, public_root, generation}`.

**Card anchor** (`networks/taira.card.toml`), written at seal:

```toml
# Written by `iroha network apply|reset` at seal. Public. Commit it (signed) so others can pin this generation.
network = "taira"
generation = 2
chain_id = "fc56984b-2be7-431d-840e-21514d1883f0"
network_id = "hash:<64 hex>#<crc>"
genesis_public_key = "ed0120..."
created_at = "2026-10-14T03:12:00Z"
profile = { id = "sora-nexus-v1", roster_size = 4, consensus_digest = "<hex>" }
roster = ["ea0130...", "ea0130...", "ea0130...", "ea0130..."]
public_root = "https://taira.sora.org"
```

---

## 4. Command reference

| Command | Purpose | Behaviour and exit codes |
|---|---|---|
| `iroha network plan <DEF> [--release V\|PATH] [--state DIR] [--repin <host>] [--json]` | Read-only preview. | 1. Loads the definition and profile and verifies the release.<br>2. Opens one pinned SSH session per host. Unpinned hosts get a fingerprint prompt, or ready-to-paste `host_key` lines for edge-bearing networks.<br>3. Runs agent `Facts` and reads attested chain facts.<br>4. Prints actions by resource, the strategy (`fresh`, `rolling`, `coordinated`, `remediate`, `restart`, `identity-move`) and blocking preconditions, or `requires reset` when the consensus digest changed.<br>5. `--repin` replaces one host pin after a rebuild (with a prompt).<br>Exit codes: 0 converged, 2 changes pending, 1 blocked. |
| `iroha network apply <DEF> [--release V\|PATH\|local] [--rotate <secret>] [--state DIR] [--yes]` | Converge: first deploy onto vacant hosts, upgrades, config, toggle, edge and grant changes, Inrou enablement, identity move, secret rotation. | 1. Takes the controller lock, plans, prints and asks y/N. `--yes` never accepts unpinned hosts.<br>2. Re-observes and compares the decision hash.<br>3. Runs idempotent actions in dependency order, in parallel across hosts. Creates genesis only if no node has a `GENERATION`.<br>4. Runs the gates. Any failure before proof captures diagnostics and rolls back automatically.<br>Exit codes: 0 sealed, 1 failed and rolled back (gate named), 3 rollback incomplete. |
| `iroha network reset <DEF> [--release …] [--state DIR] [--abort]` | The only ledger-destroying verb. Creates generation G+1 and moves G to `previous/G`. | 1. Shows the observed NetworkId, heights, retention effects, and the runtime dataspaces and external committee peers that the reset will destroy.<br>2. Requires typing the network name. `--yes` never skips this.<br>3. Before proof, failure restores G automatically. `--abort` restores from the host records on any machine holding the SSH key. |
| `iroha network verify <DEF\|URL> [--read-only] [--full] [--json]` | Optional on-demand diagnostics. Given a URL it replaces `iroha taira doctor`. | Runs the applicable read-only checks (§9). `--full` explicitly adds write, restart and boundary diagnostics G6–G8; `--read-only` always omits them. Exit 0 or 1, naming the node and predicate; the result never authorizes or blocks deployment. |
| `iroha network status <DEF\|URL> [--json] [--watch]` | Summary; never fails the shell. | Per node: release, height, lag, peers, readyz, blocks to the next pulse and session coverage, disk. Also any unfinished op and gateway and TLS expiry. |
| `iroha network up [<DEF>] [--nodes N] [--no-start] [--target host\|container] [--seed-file PATH\|--seed-fd N] [--genesis-time MS] [--state DIR]` | S3: local disposable network. | `apply` with the local driver. `--nodes` must be 3f+1. The seed options make every local key and the chain id deterministic, for fixtures and the scaling generator. `--target container` renders container-correct configs (§6.3) for `kagami docker`. |
| `iroha network down [<DEF>] [--keep-state] [--purge]` | Decommission. | Local: stops the supervisor and deletes state unless `--keep-state`.<br>Remote: stops, disables and removes units, gateways, edge config and watch timers. Data, secrets and releases are kept unless `--purge`, which requires typing the name. |
| `iroha dataspace plan <FILE> [--json]` | Read-only dataspace diff. | 1. Verifies and pins the parent card.<br>2. Checks the owner's permission, balance against the fee quote, the registration budget (`nexus.max_external_committee_peers`), name availability and lease expiry.<br>3. Detects a parent reset.<br>4. Prints the exact `[[grant]]` line to send the network admin when the permission is missing. |
| `iroha dataspace apply <FILE> [--yes]` | Converge a dataspace. | Owner committee: converges the owner hosts as `lane_validator` nodes and waits for sync. Then one once-only transaction, then G12. It also renews the lease, re-joins after a parent reset (requires typing the dataspace name) and rolls owner nodes to the parent's release. |
| `iroha dataspace status <FILE> [--json]` | Summary. | Lane id, committee liveness, lane tip, owner-node lag and release, lease expiry, fee balance. |
| `iroha dataspace down <FILE> [--purge]` | Decommission owner nodes. | Stops and removes the owner nodes. The on-chain dataspace is add-only and remains; its lane halts. |

`--rotate` values supported without a reset:
- `onboarding:<id>`: mint a new token, rolling restart.
- `operator`: new controller operator key, rolling restart.
- `admin`: the old admin grants the admin permission set to a new admin account, then revokes itself, as once-only writes.
- `gateway-certs`: new per-node and edge gateway certificates, rolling reload.

Any other value is refused with "requires reset in the first release (TODO T10)".

Hidden subcommands, never typed by operators:
- `iroha network agent --protocol 1`: the host executor.
- `iroha network supervise --state DIR`: the local parent process.
- `iroha network agent watch`: run by host timers.

Maintainer and CI only: `cargo xtask release --version V --target <triple>... --signing-key FILE --out dist/`.

`--release` accepts:
- a version, fetched from `[release].source`;
- a bundle path, whose signature is still verified;
- `local`, for the local driver only: the unsigned binaries next to the running `iroha`.

The controller and the agent must share `agent_protocol`. They do not need to share a commit.

---

## 5. Scenario flows

### S1-A. Public Taira first deploy from zero (the restore)

**Current state.** Taira has returned 502 since 2026-09-15. The height-3598 ledger on the MacStadium guest cannot be decoded by current code. That guest is not in the definition, so the tool never touches it, and it stays as a forensic archive until it is decommissioned by hand.

**One-time prerequisites, outside the tool:**
- Four Linux validator hosts (x86_64 or aarch64) with systemd, `nginx` and `openssl`. Each needs at least 4 vCPU, 8 GiB RAM and 60 GiB disk, and KVM if Inrou is on.
- One edge host with nginx and a certbot certificate covering `taira.sora.org`, `taira-validator-{1..4}.sora.org` and the explorer domain.
- DNS records.
- The deploy public key in `authorized_keys`: root with `restrict`, or a sudo user. The key is loaded into the operator's ssh-agent.
- Firewall rules (§7.4):
  - validators: tcp/1337 open to the Internet, tcp/8443 from the edge only, tcp/22 from the controller;
  - edge: tcp/443 open;
  - Torii tcp/8080 bound to loopback.

**Operator types:**

```
$ iroha network plan networks/taira.toml --release 2026.10.0    # first time: prints 5 host_key lines
  (compare with the provider console, paste into networks/taira.toml)
$ iroha network apply networks/taira.toml --release 2026.10.0   # shows the plan; answer y
```

**What the tool does:**

1. **Load.** Profile `sora-nexus-v1` and `derive(4)`. Download the bundle, verify `manifest.sig` against the compiled signers and every blob's sha256, check `agent_protocol`.
2. **Reach.** In parallel, one pinned SSH session per host. Run the POSIX prelude (§6.1). Stream the arch-matched `iroha` if it is absent, verify, rename, and exec `iroha network agent --protocol 1`.
3. **G0.**
   - arch matches the release;
   - bytes and inodes available;
   - ports free;
   - clock skew under 500 ms;
   - validator-to-validator P2P reachable;
   - at most f validators per host identity and per failure domain;
   - no `GENERATION` anywhere;
   - nginx and openssl present;
   - KVM API 12 when Inrou is on.
4. **Plan.** "No generation observed: create generation 1". The operator confirms.
5. **Install.** `PutBlob` and `EnsureRelease`. `EnsureLayout` creates the `iroha` system user, the directories, the journald `SystemMaxUse` drop-in and the logrotate check.
6. **Identity.** `GenerateIdentity` on each validator creates, all at 0600:
   - BLS key and PoP;
   - transport key;
   - streaming key;
   - runtime signer (the validator account and Soracloud signer);
   - a self-signed gateway TLS key and certificate.

   The edge generates its gateway client key and certificate. Only public node cards and certificates come back to the controller.
7. **Genesis.** Built in controller memory from:
   - the profile recipe, including `npos.max_validators = 4`, chain id and discriminant;
   - the node cards: roster, PoPs, lane-0 validator registrations, a Committee-role consensus key for every validator, with the ordered BLS topology and original PoPs defining validator generation zero;
   - fresh network authority keys: faucet, onboarding, SoraFS council;
   - the profile's admin grants. These include `CanAdministerDataspaceRegistration` and the genesis parameters `nexus.dataspace_registration = permissioned` and `nexus.max_external_committee_peers = 12`.
   - a fresh VRF epoch seed.

   The tool signs with a fresh genesis key, computes the NetworkId, and zeroizes the key.
8. **Beacon deal.** Core's signed all-edge DKG over the genesis session (`iroha_core::beacon::ceremony`): committee = n, threshold = f+1, the network's canonical genesis session and attempt ids, and the nominal phase windows 1–4 as a logical clock. The record binds heights only through the phase windows and `finalized_at_height`, and Core accepts the bootstrap `FinalizeGlobalBeaconKey` at any height at or after `finalized_at_height` inside the genesis authorization (`state/validator_committee.rs` `validate_beacon_finalization`).
   - Every seat signs its recipient key, dealer commitment, encrypted edges and acceptances with its own validator BLS key, which never leaves its host. So each validator runs its seat (`DealSeat`, one `LocalGlobalThresholdBeaconDkgSeatV1`) and the controller only relays the signed public frames through Core's reducer, phase by phase. No party holds another seat's share; each dealer polynomial is erased once its edges are sealed.
   - Each host encodes its own `beacon.cred` (`GlobalBeaconCeremonyPlanV1::seat_credential`) and returns only its public seat binding. The local driver (S3), which holds every key, runs `deal_global_beacon_at_logical_clock_v1` in process.
9. **Distribute.**
   - `WriteSecret` places the authority keys on every validator, then zeroizes the controller copies. Each `beacon.cred` is already on its own seat (step 8).
   - Writes `genesis.nrt`, `GENERATION{proven:false}` and `host-record{in_progress}`.
10. **Render and check.**
    - Render the configs, units and per-node gateways.
    - `CheckConfig` (`iroha3d --check-config`, which reads only the key files the configuration names, after their custody checks, and never opens the runtime-only secrets) with the new binary on every host.
    - `EnsureUnit`, installed but not yet enabled.
    - Start the validators.
11. **Mesh.** G1 identity. G2 readiness, where only `MissingSession` is tolerated. G3 equal heights, with each node seeing n−1 peers.
12. **Bootstrap heights.** Iroha makes no empty blocks. The authorized bootstrap account submits exact-wire journaled, fee-paying transactions until tip ≥ `finalized_at_height`, as required by beacon installation. This is a protocol action, without a G6 diagnostic prerequisite.
13. **Install the beacon.**
    - `SignInstallRange` on 2f+1 hosts, one agent call each: each host signs the lifecycle-certificate preimages for effective heights tip+1 … tip+16 with its own BLS key.
    - The controller assembles and submits the certificate for tip+1. `verify_threshold_key_lifecycle_certificate_v1` requires `effective_height == current_height` and exactly 2f+1 signatures (`state.rs:776-835`). If another block lands first, it submits the next pre-signed certificate.
    - The bootstrap account signs the transaction and pays its fee. The certificate is the authorization, as with today's canary-paid install (`taira_public_reset_beacon.rs:2519-2560`). Replay is impossible because a session installs only once.
    - Afterwards G2 is strict and G4 passes.
14. **Inrou**, when enabled: §5 S1-D and G10.
15. **Record serving state.** Beacon credentials are loaded at first start. Do not wait for a snapshot or run a restart proof before deployment; G7 remains an explicitly requested diagnostic.
16. **Pre-edge observation:** G1–G5 and G11, without G6–G8 diagnostics.
17. **Edge.** Render the per-node gateways (§6.1) and the edge: upstreams over mTLS, per-node vhosts, CORS allowlist, `X-Forwarded-For` overwrite, alias routes, explorer vhost with a generated `runtime-config.json` (chain id, NetworkId, Torii URL), and the `.well-known` card and genesis. `EnsureEdge` writes the config, runs `nginx -t` and reloads. G9 runs against the edge IP with pinned TLS SNI, so DNS can move afterwards.
18. **Seal.**
    - `GENERATION.proven = true`.
    - `systemctl enable` for units, gateways and nginx.
    - Watch timers on every host.
    - GC.
    - Write `networks/taira.card.toml`.
    - Print the NetworkId, the `client.toml` and token paths, and the reminder "commit the card anchor; back up `<state>/keys/`".

**On failure before step 18:**
- capture bounded diagnostics;
- stop the units;
- move the new state to `failed/<op>` (retention `failed_ops`);
- restore configs and units from the host records;
- leave the edge untouched;
- exit 1, naming the gate.

Re-running makes a fresh genesis.

### S1-B. Binary upgrade that preserves the ledger

```
$ iroha network apply networks/taira.toml --release 2026.10.1
```

**Compatibility probe.** `CheckConfig --json` runs with the new binary against the real rendered config on one host and returns `{config_fingerprint, protocol_version, wire_schema_hash, nexus_policy_digest, gas_schedule_hash, execution_policy_hash, nexus_amx_context_hash}`. The tool compares these against the live network, meaning the attested `SumeragiStatus` values and the genesis commitments:

- `execution_policy_hash` or `nexus_amx_context_hash` differs from genesis: `requires reset`. Nodes would refuse to start: `irohad` checks both against the authenticated genesis Sumeragi context.
- Handshake-bound values differ (config fingerprint, protocol, wire schema, nexus policy digest, gas schedule; checked by the `iroha_p2p` peer handshake): **coordinated**. A mixed cohort cannot form quorum.
- All equal: **rolling**. A `policy_digest`-only change is always rolling.

**Health classification** from G1–G4:
- **healthy**: all validators are live.
- **degraded**: at most f validators are stalled or lagging, and 2f+1 are live with G4 satisfied.
- **halted**: more than f are stalled.
- **BLOCKED**: there is no beacon session and the fresh-bootstrap window has closed, which is the 09-15 state. Only `reset` can recover it.

**Strategy `rolling`** (healthy). Canary order v4, v3, v2, v1. Before each restart, the G4 margin must hold (`blocks_to_pulse ≥ max(32, 3n)`); otherwise the tool first runs a supervised pulse crossing, driving writes until every validator is observed past the pulse with readyz 200. Then, for each node:
1. Stop.
2. `iroha3d --check-storage` with the new binary. The node must be stopped because Kura holds an exclusive store-root lock (`kura.rs:2514-2530, 2701`). It returns the tip, the Kura prefix hash at the latest snapshot height, and a snapshot-restore dry run. On failure: restart on the old release and abort with "release cannot open this ledger; use `iroha network reset`".
3. Swap the `release` symlink with `rename(2)` and start.
4. Catch up to lag ≤ 2. The prefix hash must equal the old binary's reading.
5. Record actual readiness and catch-up without a G6 write diagnostic.

Then G1–G5, and G9 and G10 when configured. A failure rolls back only the touched nodes.

**Strategy `remediate`** (degraded). The unhealthy nodes (at most f) contribute no liveness, so they are upgraded first: stop, check-storage, swap, start. Each must catch up under the new release within the catch-up budget. If one cannot, it is rolled back, left stopped and reported, and the healthy nodes are not touched. Otherwise the healthy nodes follow under the `rolling` rules. This is how a release that fixes a stall, such as validator 1 stuck at 1969, reaches the network.

**Strategy `coordinated`** (healthy, degraded or halted):
1. Edge to maintenance (503 with Retry-After), so user transactions are refused.
2. Stop all validators and record the tip.
3. `CheckpointState`: a same-filesystem copy of `state/` into `previous/checkpoint-<op>/`, using a reflink where the filesystem supports it and a full copy otherwise. G0 counts this space.
4. `--check-storage` on every node.
5. Swap all, start all.
6. Verify, then bring the edge live.

On failure, every node stops, its checkpoint and old release are restored, it starts, and G1–G3 are verified. The edge remains in maintenance throughout this operation; no G6 diagnostic writes are required. After seal, checkpoints are removed.

When owner dataspaces exist, the plan lists every lane whose committee runs a different release. For coordinated upgrades it warns that those lanes stall until their owners run `dataspace apply`.

### S1-C. Explicit ledger reset

```
$ iroha network reset networks/taira.toml [--release 2026.10.1]
```

The prompt shows:
- "generation 1 (NetworkId hash:9F2C…, heights 4127/4127/4127/4126, health: healthy) will be retired to previous/1";
- the retired ledger to be deleted on seal;
- "destroys 2 runtime dataspaces (acme, dpn) and 4 external committee peers";
- then "type `taira` to confirm".

**Steps:**
1. Record each node's `prior_health` in its host record.
2. Put the edge into maintenance and stop the validators.
3. `MoveStateToPrevious`, a same-filesystem rename.
4. Build a new genesis and a new beacon deal. Node identities are kept, so peer ids and DNS stay stable. Authority keys are fresh.
5. Run steps 9–18 of S1-A.

**Failure before proof:** stop, discard the new state, and restore the previous state, config, unit and release from the host records.
- If `prior_health` was healthy, the tool starts the old network, verifies G1–G3 and brings the edge live.
- If it was halted or undecodable, which is exactly the 09-15 state, the files are restored, the units are left stopped and the edge stays in maintenance. Exit 1 says "previous generation was not live; fix and re-run reset".

`reset --abort` performs the same restore after a controller crash.

### S1-D. Changes, rotation, hosts and decommissioning

- **Policy-only config** (operators, onboarding credentials, proxies, retention, monitor, `policy_digest`): rolling restart with the S1-B gates.
- **`[inrou] enabled = true`:**
  1. `EnsureInrouHost` checks KVM API 12, QEMU exit-with-parent and cgroup v2 controllers, installs the runtime root, and reserves uid/gid 70000(+k).
  2. `SetOwnership` re-owns `secrets/` and `state/` to root. The credential loader accepts only owner 0 or the euid (`runtime_credential.rs:112-132`), and Inrou requires euid 0 (`soracloud_runtime.rs:13956-13960`).
  3. Rolling restart with the Inrou table rendered.
  4. Stage, preseed, pins and service as once-only writes.
  5. G10.

  Disabling does the reverse. No reset is needed.
- **`[[grant]]` changes**: exact-set convergence. The admin issues grants and revokes as once-only writes. No restart.
- **`--rotate`**: see §4.
- **Changing `node.host` (identity move).** If the old host is reachable: stop the node there, stream its secrets from the old host through controller memory to the new host, provision, start (it block-syncs), verify, and retire the old directory. If the old host is unreachable: BLOCKED, "v2's validator key exists only on the lost host; Taira has no global validator rotation (fresh candidates are rejected, `staking.rs:777-787`), so this requires a reset".
- **Rebuilt host.** Its key no longer matches the pin, which is a hard stop. The operator updates `host_key` (edge-bearing networks) or runs `plan --repin <host>`. If the validator keys went with the old disk, the plan says "requires reset".
- **Observers.** Adding `[[node]] role = "observer"` provisions a syncing node (no Inrou, beacon or voting) that the edge can route explorer traffic to. No reset.
- **Consensus-bound change** (profile id, `consensus_digest`, chain id, discriminant, validator count): `requires reset`.
- **Decommission:** `iroha network down networks/taira.toml [--purge]`.

### S2a. Private dataspace on Taira's validators

```
$ iroha dataspace apply dataspaces/acme-on-taira.toml
```

1. **Card.**
   - Fetch `/.well-known/iroha/network-card.norito` and `genesis.nrt`.
   - Verify the genesis signature, that the genesis hash equals the NetworkId, and that the roster PoPs match genesis.
   - Collect fresh challenge-bound `latest` attestations until 2f+1 distinct roster members verify.
   - On first use, the prompt shows chain id, generation, NetworkId, creation time, roster peer ids and public root, and says "compare with `networks/taira.card.toml` in the iroha repository (signed commit) or the Taira operator's announcement". A `network_id` in the file, or `network` pointing at the anchor file, pins it without the prompt.
2. **Preflight.**
   - Owner account from `owner_key`.
   - `CanRegisterDataspace` present, or else print the exact `[[grant]]` line.
   - Balance against the quote; on a shortfall, print `musubi wallet fund`.
   - Name free.
3. **Plan.** "RegisterDataspaceV1 acme (restricted; committee = 4 Taira validators with live Committee keys; lane id assigned by Core), aliases acme and treasury@acme; quoted 12.3 ≤ 20". The prompt states plainly that restricted is not confidential (§11.4).
4. **One once-only transaction:** `[EnsureAlias(Create acme), EnsureAlias(Create treasury@acme), RegisterDataspaceV1{committee: Network}]`.
   - The prepared wire is journaled, submitted once, and resumed read-only until it is Applied or its TTL has provably expired.
   - `LifecycleAlreadyStaged` is a deterministic rejection (one lifecycle change per block, `runtime_catalog.rs:294-296`). The tool prepares a fresh transaction for a later block.
5. **G12.**

Taira operator actions: one `[[grant]]` line and one `apply`. There is no restart.

### S2b. Private dataspace with owner-brought validators

```
$ iroha dataspace apply dataspaces/acme.toml
```

1. **Card** as in S2a. The release is the card's release, and its bundle is verified against the compiled signers. The budget check requires `external committee peers + 4 ≤ nexus.max_external_committee_peers`.
2. **Owner hosts** are converged by the same engine with the `lane_validator` overlay:
   - Keys generated on each host: BLS+PoP, transport, streaming, account key, gateway certificate. No beacon credential, Soracloud production mode or Inrou.
   - `validators`, profile and chain values copied from the card. Handshake constants must match byte-for-byte (`peer.rs:11929-11965`).
   - `trusted_peers` = the Taira roster plus sibling owner nodes with PoPs.
   - `genesis.file` = the verified card genesis. `expected_hash` = the pinned NetworkId.
   - Operator allowlist = the owner's keys.
   - The optional owner `[edge]` with per-node gateways.
3. **Sync.**
   - Owner nodes dial Taira's public P2P and are admitted as authenticated NPoS observers (`iroha_p2p network.rs:15097-15102`).
   - Being absent from the roster, they run the global protocol as observers, which never vote (`specs/sumeragi.md` §1).
   - They replay the chain from genesis.
   - The tool waits until each owner node's signed `latest` attestation is within 2 blocks of the verified Taira tip.
4. **One transaction:** `[EnsureAlias…, Register<Account>×4, RegisterDataspaceV1{committee: Explicit([4 members])}]`.
   - Core registers the members as dataspace-scoped Committee peers, live at h+1 with `key_activation_lead_blocks = 1` (`parameter/system.rs:1291-1293`).
   - It validates the committee at authority height h+1 (`runtime_catalog.rs:291-293`) and installs the lane.
   - If the chain's lead is greater than 1, the tool stops (TODO T5).
5. **G12.** The owner nodes pass G1–G4 through their own attestations. Units are enabled and watch timers are installed on the owner hosts.

**Replacing an owner node** needs `SetDataspaceCommitteeV1` (P7). Until then the plan reports a committee change as unsupported. A 4-node committee tolerates one permanent loss; a second loss freezes the lane while the global chain continues.

### Dataspace lifecycle

- **Parent upgrades.** The card's release changes on every Taira `apply`. The owner hosts' watch timers alert when the local release differs from the card's. `dataspace apply` rolls the owner nodes: rolling for handshake-compatible releases, all at once otherwise (the lane is already stalled in that case).
- **Lease.** `status` warns when fewer than 60 days remain. `apply` renews as a once-only write within `max_fee`. Expiry follows existing SNS rules, which this design does not change.
- **Parent reset.** `dataspace plan` sees the card's NetworkId differ from the pin and reports "parent reset: dataspace, lease and grants no longer exist; re-register". `apply`, after the dataspace name is typed:
  1. moves the owner-node state to `previous/` using the same host records;
  2. re-pins the new card, which requires a prompt or an updated `network_id`;
  3. re-joins and re-registers, paying again.
- **Down.** `dataspace down` stops and removes the owner nodes (`--purge` also deletes data). The on-chain entry is add-only and remains; its lane halts.

### S3. Local devnet

```
$ cargo build --release -p irohad --bin iroha3d -p iroha_cli --bin iroha
$ target/release/iroha network up                   # or: up networks/dev.toml --nodes 7
$ target/release/iroha network verify dev --full    # optional pulse, epoch and restart diagnostics
$ target/release/iroha network down
```

`up` does the following:
- Uses the local driver under `~/.local/state/iroha/networks/dev/`.
- Generates identities, genesis and the beacon deal through the same code paths as Taira, with a fresh chain id, or a deterministic one from `--seed-file` or `--seed-fd`.
- Renders configs with `lifecycle.exit_on_stdin_close = true`.
- Spawns the detached `iroha network supervise`, which starts n `iroha3d` children.
- Drives the protocol-required bootstrap heights, installs the beacon, and observes G1–G5. G6–G8 run only when explicitly requested through `verify --full`.

It needs no root, KVM, pidfd or Python, and works on macOS and Linux, x86_64 and aarch64. `up` takes about 60–90 s and `verify --full` about 2 min. An `apply` after a rebuild exercises the upgrade strategies locally. `[inrou] enabled = true` is refused unless the machine runs Linux with KVM API 12 as root.

### Failure and recovery (all verbs)

- **Atomic host writes.** Files are written to a temporary name, fsynced and renamed. Blobs are content-addressed, and symlinks are swapped with `rename(2)`.
- **Controller interrupted.** Re-run the command; it re-observes and resumes from the journal. Ambiguous transactions resume read-only by hash across 2f+1 nodes:
  - committed means done;
  - rejected surfaces the error;
  - unknown waits for the TTL to provably expire.
- **Beacon deal interrupted** before the credentials were written: redo it with fresh randomness. The deal happens before start, so the pulse window is never at risk.
- **Rollback incomplete** (exit 3): the host records stay `in_progress`. Re-run, or `reset --abort`. A second controller that finds `in_progress` records may only run `--abort`.
- **State dir lost.**
  - `reset --abort` works from any machine that holds the SSH key.
  - Host-key pins are re-established from the definition, or by prompt.
  - The generated admin and operator keys are lost. `--rotate operator` recovers the operator key. A lost admin key is irrecoverable without a reset, which is why the plan reminds the operator to back up `keys/`.
  - Validator keys are unaffected.
- **Diagnostics.** Before any rollback, the tool captures at most 8 MiB per host into `<state>/ops/<op>/diagnostics/<host>/`:
  - `systemctl show`;
  - the last 2,000 journal lines;
  - `df` and `df -i`;
  - the agent facts;
  - every node's last signed attestation;
  - the failing predicate and its inputs.
- **Degradation after seal.** A watch alert arrives. Run `verify`, then `apply`, which restarts only unhealthy nodes, gated by horizon and catch-up. State is never wiped automatically.

---

## 6. Host and process model

### 6.1 Remote hosts (S1 validators, observers and edge; S2b owner nodes)

**Reach.** The controller runs anywhere on macOS or Linux. It spawns the system OpenSSH client; there is no Rust SSH dependency.

```
ssh -F /dev/null -o UserKnownHostsFile=<state>/known_hosts -o GlobalKnownHostsFile=/dev/null \
    -o StrictHostKeyChecking=yes -o UpdateHostKeys=no -o IdentitiesOnly=yes -o IdentityFile=<ssh.identity> \
    -o IdentityAgent=$SSH_AUTH_SOCK            # or IdentityAgent=none when ssh.agent = false
    -o ForwardAgent=no -o ForwardX11=no -o ClearAllForwardings=yes -o BatchMode=yes \
    -o ServerAliveInterval=15 -p <port> \
    [-o ProxyCommand="ssh -F /dev/null -o UserKnownHostsFile=<state>/known_hosts -o StrictHostKeyChecking=yes \
       -o IdentitiesOnly=yes -o IdentityFile=<ssh.identity> -o IdentityAgent=... -o BatchMode=yes -W %h:%p <jump>"] \
    <user>@<host>
```

- The jump host gets the same pinned options through an explicit `ProxyCommand`, because `-J` would not inherit them. Its key is pinned with `jump_host_key`.
- `known_hosts` is generated from the definition's pins. A changed key is a hard stop.
- There is one long-lived session per host per operation, and sessions run in parallel.
- Torii probes before cutover go through agent `ProbeLocal` and `SubmitLocal` to 127.0.0.1. No port forwarding is needed, so `authorized_keys restrict` works.

**Bootstrap prelude.** About 30 lines of embedded, idempotent POSIX sh. It:
1. reports `uname -sm`;
2. checks for `sha256sum`, `install` and `systemctl`;
3. creates `/opt/iroha/{releases,incoming}`;
4. streams the arch-matched agent if it is missing (`install -m0755 /dev/stdin`, `sha256sum -c`, rename);
5. execs `[sudo -n] /opt/iroha/releases/<id>/bin/iroha network agent --protocol 1`.

There is no preinstalled dispatcher, no `guard.json` and no dispatcher transition.

**Agent operations.** Norito request and response over stdio. Every operation is idempotent and checks its own post-condition.

| Group | Operations |
|---|---|
| Observe | `Facts`, `ConnectCheck(peers)`, `ProbeLocal(path)` (`/readyz` requested as `text/plain`), `SubmitLocal(bytes)` |
| Files | `PutBlob`, `EnsureRelease(manifest)`, `EnsureLayout`, `EnsureFile(path, sha, owner, mode)`, `EnsureUnit`, `SetOwnership(tree, user)` |
| Identity | `GenerateIdentity(node)` (only if absent; returns the card), `GenerateGatewayCert(role)` (`openssl req -x509` on the host; the key never leaves), `WriteSecret`, `ReadSecretsForMove` (identity move only), `DealSeat(plan, phase, frames)` (one signed all-edge DKG seat; writes `beacon.cred`, returns public frames and the seat binding), `SignInstallRange(node, bundle, heights)`, `SignCouncilStage(preimage)` |
| Process | `Service(start\|stop\|restart\|enable)`. It verifies `systemctl show` ActiveState, SubState, ExecMainPID, InvocationID, NRestarts and numeric ExecMainCode, treats an empty `/proc/<pid>/cmdline` as pending, and resolves `/proc/<pid>/exe` to confirm the release. |
| State | `CheckConfig(release)`, `CheckStorage(release)` (prefix hash and snapshot dry-run), `SwapRelease`, `CheckpointState`, `RestoreCheckpoint`, `MoveStateToPrevious(gen)`, `RestoreFromHostRecord`, `CollectDiagnostics(since)` |
| Inrou | `EnsureInrouHost`, `Preseed` (drives the release's `sorafs-node` locally), `StoppedInrouReconcile`. The last runs after every stop, restart or crash of an Inrou node and before the next start. It checks that no process runs under the reserved slot uid, that the node's Inrou cgroup subtree is empty (remaining QEMU processes in it are killed), that the per-slot iptables owner chains are removed and that `/run` slot locks are released. It is ported from `taira_public_reset_stopped_runtime.rs` and `taira_stopped_owner_maintenance.rs`. |
| Edge | `EnsureEdge(conf, live\|maintenance)` and `EnsureGateway(conf)`: write, `nginx -t`, reload, restore on failure |
| Housekeeping | `Gc(retention)`, `EnsureWatch(config, webhook bytes)` |

**Installed layout.** One validator per host by default.

```
/opt/iroha/releases/<release-id>/bin/{iroha3d,iroha,sorafs-node}   root:root 0755, nlink 1, copied never hardlinked
/opt/iroha/releases/<release-id>/share/inrou/<isa>/...              guest assets (Inrou releases)
/etc/iroha/<net>/<node>/config.toml (+ .prev)                       root:iroha 0640
/etc/iroha/<net>/<node>/gateway/{gateway.crt, gateway.key(0600), edge-client.pem}
/etc/iroha/<net>/edge/{client.crt, client.key(0600), validators.pem}            (edge host)
/var/lib/iroha/<net>/<node>/release -> /opt/iroha/releases/<id>     (+ release.prev)
/var/lib/iroha/<net>/<node>/secrets/                                0700; files 0600 owned by the service user:
    validator.key transport.key streaming.key runtime_signer.key beacon.cred
    authority/{faucet,onboarding,sorafs_council}.key
/var/lib/iroha/<net>/<node>/state/                                  Kura, snapshots, SoraFS, Torii, Inrou data
/var/lib/iroha/<net>/<node>/{GENERATION, host-record.norito, genesis.nrt}
/var/lib/iroha/<net>/<node>/previous/{<gen>, checkpoint-<op>}/      retired ledgers and upgrade checkpoints
/var/lib/iroha/<net>/<node>/failed/<op>/                            unproven generations (retention.failed_ops)
/etc/systemd/system/iroha-<net>-<node>.service, iroha-<net>-watch.{service,timer}
/etc/systemd/journald.conf.d/60-iroha.conf                          SystemMaxUse=<retention.journal_max>
/etc/nginx/conf.d/iroha-<net>-<node>-gateway.conf                   (validators and observers)
/etc/nginx/conf.d/iroha-<net>.conf (+ .prev), /var/www/iroha-<net>/.well-known/iroha/   (edge)
/etc/iroha/<net>/watch-webhook                                      0600 root (from monitor.webhook_file)
```

The Inrou self-executable check requires a root-owned, nlink-1, non-writable file named `iroha3d` (`soracloud_runtime.rs:224-241`), and this layout satisfies it.

**Unit.** Rendered in Rust; it replaces `scripts/taira_validator_unit.py`.

```
[Unit]
Description=Iroha <net> <node>
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=600
StartLimitBurst=3
[Service]
Type=exec
User=iroha                      # root when [inrou] enabled (daemon requires euid 0)
UMask=0077
WorkingDirectory=/var/lib/iroha/<net>/<node>
ExecStart=/var/lib/iroha/<net>/<node>/release/bin/iroha3d --config /etc/iroha/<net>/<node>/config.toml
Restart=on-failure
RestartSec=5
TimeoutStopSec=60
LimitNOFILE=65536
MemoryMax=4G                    # profile policy
CPUQuota=200%                   # profile policy
NoNewPrivileges=yes             # omitted for Inrou units
ProtectSystem=strict            # omitted for Inrou units
ReadWritePaths=/var/lib/iroha/<net>/<node>
[Install]
WantedBy=multi-user.target
```

**mTLS gateway** (`edge.upstream = "mtls"`).
- Torii binds 127.0.0.1:8080. Each validator host runs an nginx server block on `<address>:8443` using its own self-signed gateway certificate.
- The gateway uses `ssl_verify_client on` against the pinned edge client certificate and proxies to 127.0.0.1:8080, passing the edge's `X-Forwarded-For` through.
- The edge proxies with `proxy_ssl_verify on`, `proxy_ssl_trusted_certificate` set to the pinned node certificates, and its own client certificate.
- Torii trusts only `127.0.0.1/32` as a proxy. Validator Torii is never reachable from the network directly, and bearer tokens and operator-signed requests never cross a network in cleartext.
- `upstream = "private"` binds Torii to a private address instead. G0 then refuses any upstream address that is not RFC1918, ULA or 100.64/10.

**Atomic switch and rollback.**
- Releases and configs change by temporary file or symlink plus `rename(2)`, and `.prev` copies are kept.
- The host record is written before any mutation. Rollback reads it, so it needs neither the controller nor its journal.
- Rollback is forbidden once `GENERATION.proven` is set. After that, recovery goes forward by `apply`.

**Locking.**
- The controller flocks `<state>/lock`.
- The agent holds `flock /run/lock/iroha-<net>.lock` for the whole session. It is released if the session dies, so there are no leases or TTLs.

**Capacity** (G0, per filesystem).
- Remote nodes need free space ≥ storage budget × (1 + `previous_ledgers`) + state size (coordinated upgrades only) + `releases` × release size + 2 GiB, plus the Inrou image and stores when enabled, and at least 100k free inodes.
- The local and container drivers use the qual profile's 512 MiB budget with no previous-ledger or checkpoint reservation, so 4 nodes fit a CI runner in about 4 GiB.
- The daemon logs only to journald, which is capped. nginx uses distro logrotate, which the agent checks is present.
- GC removes unreferenced releases and retired or failed state beyond retention.

**Watch timers.** On every host, every `interval`, `iroha network agent watch` checks:
- unit state and the NRestarts delta;
- disk and inodes;
- local `/readyz`;
- local height advancing while the queue is non-empty;
- gateway and TLS certificate expiry;
- on owner hosts, whether the card's release differs from the local release.

The edge host (or v1 when there is no edge) also runs cluster-level G1–G4 and G9 read-only. Failures go to journald and to the webhook, debounced to one alert per condition per hour. This closes I6 (a stall nobody noticed) and I8 (disk exhaustion).

**Co-hosting and failure domains.** Co-hosting works with per-node ports and Inrou slot 70000+k. Remote definitions refuse more than f validators per host identity or per `failure_domain`. The edge may share a host with one validator.

### 6.2 Local driver (S3, local S2b rehearsals)

- The same agent operations run in-process against `<state>/local/<node>/{config.toml, secrets/, state/, GENERATION, iroha3d.log}`. There is no root and no systemd.
- `up` spawns `iroha network supervise --state <dir>` detached, with `setsid`, a double fork, `supervisor.log` and a `supervisor.lock` flock.
- The supervisor is the direct parent of every `iroha3d`, so `waitpid` gives exact process identity on macOS and Linux: no pidfd, no pid-reuse race, no Python.
- Each child's stdin is a pipe held by the supervisor, with `lifecycle.exit_on_stdin_close = true`, so children exit even if the supervisor is killed with SIGKILL.
- Control runs over `<state>/supervisor.sock` (0600, Norito): `Status`, `Start`, `Stop`, `Restart`, `Shutdown`.
- Crash policy: 3 restarts in 60 s, then the node is left stopped and reported. Logs rotate at 64 MiB × 3.

### 6.3 Container render mode

`iroha network up <DEF> --no-start --target container` renders `<state>/container/<node>/` with:
- binds on 0.0.0.0 and public addresses `<node>:1337` (compose service names);
- `data_dir = /var/lib/iroha` and secrets under `/var/lib/iroha/secrets` (mounted files);
- no `exit_on_stdin_close`.

`kagami docker --state <dir> --out <compose.yml>` turns this into compose.

The committed fixture `defaults/docker-compose.yml` (4 peers, dev-only keys from a fixed `--seed-file`, fixed `--genesis-time`) replaces the byte-identical `docker-compose.local.yml` and `docker-compose.single.yml`. A CI check regenerates it and requires byte equality. The JS and Python SDK harnesses, the `iroha_swarm` test, `consistency.sh`, the pre-commit sample and `pr_docker_compose.yml` all move to it (§12).

---

## 7. Security and custody

### 7.1 What replaces the envelope, dispatcher and guards

**Deleted:**
- `AuthorizationEnvelopeV1`: an owner Ed25519 signature over the inventory, with a nonce, a 15-minute window and a lease of up to 12 h (`taira_public_reset.rs:1219-1258, 1576-1681`);
- the root dispatcher that re-verified it on every SSH request (`host.rs:3215-3355`);
- 5 `guard.json` files and the ~4.98k-line dispatcher transition;
- source closures, receipt chains and operator-computed expected hashes.

| Property | Before | After | Why it holds |
|---|---|---|---|
| Who may mutate hosts | Owner signature re-checked by a root dispatcher | The SSH deploy key, held in ssh-agent (hardware or passphrase keys allowed; required for edge-bearing networks), pinned host keys (no trust on first use for public networks), and interactive plan approval bound to the decision hash | A holder of root SSH could already replace the dispatcher, which is why the transition ceremony existed. The check never constrained that principal. It only added a 15-minute race and about 11 tooling failures. |
| Artifact integrity | Source closure re-hashed 7–8× | Signed `ReleaseManifestV1` checked against compiled signers; sha256 per blob on controller and host; G1 build fingerprint `H(version‖commit)` equal to the manifest (`release_identity.rs:100-108`) | Stronger: the bytes that run are the bytes that were signed. |
| Network identity | Hand-copied NetworkId | Genesis signature plus a mandatory independent `expected_hash` (`user.rs:6150-6176`) derived by the tool; the card verified against genesis and 2f+1 attestations; the committed card anchor | Protocol unchanged; transcription removed. |
| Peer identity | Hand-copied ids | On-host keygen; PoPs verified at genesis build; `trusted_peers_pop` enforced by the node | Unchanged. |
| Replay | Envelope nonce | No replayable deploy artifact. On-chain: TTL, NetworkId binding (`transaction/signed.rs:435`), hash dedupe, faucet claim markers, operator nonce cache (`actual.rs:8341-8357`), install-once beacon sessions | Unchanged. |
| Exclusion and rollback | 4 locks, 4 journals | Controller flock, per-host session flock, host records, proven boundary | Kept, simpler. |
| Revocation | Trusted-key JSON | Host-key change is a hard stop; release signers in `[release].signers` or the compiled list; on-chain revoke unchanged; `[[grant]]` exact-set revokes | Unchanged for the protocol. |

Recommended outside the tool: `restrict,from="<controller IP>"` on the deploy key.

### 7.2 Key generation and custody

| Key | Generated where | Custody and rotation |
|---|---|---|
| Genesis key | Controller memory, once per generation | Signs once, then zeroized. |
| Validator BLS+PoP, transport, streaming, runtime signer | On the validator host | 0600 in `secrets/`. Never leaves the host except in an identity move (through controller memory, then zeroized). Persists across resets. Rotating it requires a reset (no global validator rotation). |
| Gateway TLS keys (nodes, edge client) | On each host | Only certificates leave the host. `--rotate gateway-certs`; the watch timer warns at 30 days. |
| Beacon seat credentials | On each validator host (`DealSeat`; its own share only) | Written to `secrets/beacon.cred` by the seat itself. Never leave the host. |
| Install-certificate signatures | On each host (`SignInstallRange`) | Only signatures leave the host. |
| Network authority keys (faucet, onboarding, SoraFS council) | Controller memory at genesis | `WriteSecret` to every validator, then zeroized. Rotation requires a reset in the first release (TODO T10). |
| Admin key | `admin_key`, or generated into `<state>/keys/` | Operator custody; back it up. `--rotate admin`. |
| Controller operator key | `<state>/keys/operator.key` | Allowlisted on every node; verify never needs it. `--rotate operator`. |
| Onboarding tokens | Minted by the tool | Plaintext written once to `<state>/credentials/` (0600); only the blake3 hash goes into configs. `--rotate onboarding:<id>`. |
| Canary key | Fresh per run, in memory | Funded by the PoW faucet; also pays for the beacon install. |
| Dataspace owner key and owner node keys | The owner's file / owner hosts | The Taira operator never sees them. |
| Release signing keys | CI secret (gated builds) and a maintainer key | Public keys compiled into `iroha` and overridable per definition. |

### 7.3 How secrets reach the daemon

The runtime-signer and beacon descriptors 198/200 are deleted, together with `take_inherited_private_file` (`taira_runtime_signer.rs:460-486`), the inline-Python launcher (`scripts/taira_validator_unit.py:21-116`) and `iroha3d_taira`.

The stock `iroha3d` opens fixed names under `<data_dir>/secrets/` through `irohad::node_secrets`, using the existing `load_bounded_runtime_credential_v1` (`runtime_credential.rs`). It checks:
- `O_NOFOLLOW`, regular file, nlink 1;
- owner 0 or euid, owner-only mode (no group, other, setuid, setgid or sticky bits; the tool writes 0600);
- no symlinked, foreign-owned or group/world-writable ancestor directory. The secrets path is walked as written before it is canonicalized: a symlinked component is admitted only when the link and its directory are root-owned and not group- or world-writable (system links such as macOS `/var`), so a symlinked `data_dir`, `secrets` directory or user-owned ancestor is refused;
- exact size (`runtime_signer.key` 71 bytes; `beacon.cred` bounded by the credential ceiling);
- and zeroizes the buffer after parsing.

It then:
- verifies each loaded key against the public binding in the config:
  - the Soracloud signer (`runtime_signer.key`, required whenever `soracloud_runtime.submission.signer` is set, which `production_mode` requires) must be the binding's Ed25519 key and account, with handle `software://iroha/node-secrets/runtime-signer/<public key hex>`, revision 1 and the compiled policy digest; these live in `iroha_config::parameters::actual::node_runtime_signer::{handle_v1, REVISION_V1, policy_digest_v1}` so the renderer (which never depends on irohad) emits exactly these values;
  - the onboarding authority (`authority/onboarding.key`, when onboarding reads it from that path) must be the signatory of `torii.account_onboarding.authority`;
- derives the beacon provider binding from the credential header (`iroha_core::beacon::credential::global_beacon_partial_signer_credential_header_v1`); `beacon.cred` is admitted only on a validator, and a configured `sumeragi.global_beacon_partial_signer_provider_*` binding must equal the header.

`node_secrets` resolves only the Soracloud signer and beacon provider roles; a `data_dir` node whose configuration requests another runtime-provider role is rejected (TODO: compose the stock broker once a profile enables one). Launchers that bring their own registry (`iroha3d_taira` until P8) do not use it.

The key files the configuration parser reads (`validator.key`, `transport.key`, `streaming.key` and the `authority/*.key` network-authority keys) pass the same custody checks (`node_secrets::verify_config_key_custody`) whenever the node file is loaded, before the parser reads them; `--check-config` and `--check-storage` therefore read those key files, but never open the runtime-only secrets (`runtime_signer.key`, `beacon.cred`). The parser reads each key file into a zeroizing buffer. The FD transport's "consumed after load" property is dropped: root can read either form, and that transport caused incident I2-65 and required python3 on every host.

### 7.4 Network exposure

- **Validator P2P tcp/1337 is public.** S2b owner nodes and observers have to reach it, and NPoS admits authenticated observers.
- **What bounds the exposure:**
  - per-IP and per-prefix accept throttling and `max_incoming` in `iroha_p2p`;
  - the 97-connection core cap;
  - Sumeragi's bounded ingress: each consensus instance bounds ingress per `(peer, traffic class)` and serves peers round-robin within a class, so an observer flood cannot starve committee traffic; `network.max_total_connections` leaves room for only the `authenticated_non_validator_sources` allowance beyond the committee (§11.2, D-4).
- **Deferred:** a connection-slot reservation for topology and committee peers (T8). The exposure exists today for any NPoS network, and S2b inherits it.
- **Torii** is loopback-only behind the mTLS gateway (or on a private address). Only the edge's tcp/443 is public.
- **G9** probes P2P reachability from the controller's vantage point for every validator whenever S2b dataspaces or observers exist.

### 7.5 Trust anchors

- Hosts are pinned by the definition. Edge-bearing networks require the pins.
- The network is pinned by the card anchor (a committed, signed file), by `network_id`, or by the first-use prompt, which shows chain id, generation, NetworkId, creation time, roster and root and names where to compare them.
- The NetworkId changes on every reset. Pins therefore fail loudly with "parent reset", and the anchor file in the repository is updated in the same commit series as the reset.

---

## 8. Release model

**Separation.** Only `cargo xtask release`, run in CI or on a maintainer machine, invokes Cargo. `apply` consumes bundles and never builds, tests or reads source. This implements `roadmap.md:142`.

**Build** (`xtask/src/release.rs`):
- `cargo build --locked --profile release`, with cargo-zigbuild for cross targets.
- Node targets `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`: `iroha3d`, `iroha`, `sorafs-node`.
- Controller targets, built in CI on macOS runners: `aarch64-apple-darwin`, `x86_64-apple-darwin` and both Linux targets, each with `iroha` and `musubi`. `musubi` replaces the end-user `iroha taira account`; `specs/musubi.md:574` is updated.
- Inrou guest assets come from a CI job running `scripts/ci/prepare_inrou_portable_guest_assets.py`. It is kept as a CI-only build step (TODO: port to xtask).

**Artifact.** `iroha-<version>.tar` contains `blobs/<sha256>`, `manifest.norito` and `manifest.sig`.

```
ReleaseManifestV1 {
  version, commit, tree, rustc, built_at_ms,
  targets: {triple: {files: [{path, sha256, size, mode}], cargo_features, build_fingerprint}},
  controller_targets: {triple: {files: [...]}},
  agent_protocol: u16,
  wire_schema_hash: [u8; 32],
  profiles: [{id, consensus_digest, policy_digest}],
  inrou: {isa: {guest_manifest_digest, guest_cid, runtime_root_sha256}}   // map keyed by ISA
}
manifest.sig = Ed25519("iroha.release.v1\0" || canonical Norito(manifest))
```

- The release id is the sha256 of the manifest.
- `build_fingerprint` = `H(version‖commit)` (`release_identity.rs:100-108`). Features and target are compared separately against `/status.build`.
- `wire_schema_hash` comes from `iroha_core::release_identity::wire_schema_hash()`, and both binaries expose it. It hashes the compiled `iroha_schema` descriptions of three wire roots, in order the block wire (`SignedBlock`, `iroha_data_model::wire_schema::covered_wire_schema()`), the consensus wire (`iroha_sumeragi::message::WireMessage` and native `Evidence`, including their bounded byte domains), and the canonical compact `ExecutionResultCommitment` payload carried by result witnesses, plus the IVM `abi_hash`, through `iroha_data_model::wire_schema::wire_schema_hash_of(roots, ivm_abi_hash)`. The ABI hash is an argument because `ivm_abi` depends on the data model; the executable-facing function supplies `compute_abi_hash(AbiV1)`. The value is target-independent but feature-dependent (the crypto `Algorithm` schema lists its `bls`, `gost` and `sm` variants only when compiled in), so xtask reads it from a host-native build of the same commit with the release feature set, and `iroha3d` reports it in `/status.build`. Each root is rendered against its own types, because the two wires define different types under the same schema identifiers (both define a `BlockHeader`); within a root, entries are ordered by schema identifier and then by their full rendering, so the value never depends on process-local `TypeId`s.

**Integrity checks:**
- the controller verifies the signature and every blob;
- hosts verify each sha256 before the rename;
- G1 checks the fingerprint, commit, features and target;
- xtask refuses a set of binaries whose commits differ.

**Optional engineering diagnostics.** These run independently of release signing and deployment:
1. `cargo nextest run --profile release-gate`. Filtersets in `.config/nextest.toml` replace the 1,211 hand-listed names in `taira_release_check.py`.
2. **Engine self-test** on the artifacts: `iroha network up networks/ci.toml --release ./dist/iroha-<v>.tar && iroha network verify ci --full && iroha network down ci`. That is a real 4-peer `sora-nexus-v1-qual` network with the beacon, snapshot-restore restarts, a pulse crossing and an epoch boundary.
3. **Upgrade job:** `up` on the previous release, then `apply --release <new>`, then verify. It exercises the strategy decision, `--check-storage` and the prefix-hash comparison.
4. **Container job:** regenerate `defaults/docker-compose.yml` and require byte equality, then boot it.
5. An aarch64 KVM runner with `--inrou`, triggered by Inrou paths and nightly.

**Restore path.** Until P4, the maintainer runs `cargo xtask release … --signing-key ~/.iroha/keys/maintainer-release.key`. The self-test is optional and does not block restoring Taira.

`scripts/run_release_pipeline.py` (2,169 lines, the image and bundle publisher) stays. TODO(P8): make it consume the xtask bundle.

---

## 9. Verification model

There is one implementation, `iroha_deploy::verify`, running in-process. Each gate returns `{gate, subject, predicate, observed, expected}`, and the result is journaled and printed.

| Gate | Checks |
|---|---|
| **G0 Preconditions** | Arch; per-driver capacity; ports; clock skew under 500 ms; P2P reachability; at most f validators per host identity or failure domain; KVM API 12 and a guest per validator ISA when Inrou is on; nginx and openssl; private-upstream addresses. |
| **G1 Identity** | Fresh challenge-bound `GET /v1/bridge/finality/attestation/latest` from every node: signed by the expected peer key, carrying the expected NetworkId and genesis hash, with a build fingerprint equal to `H(version‖commit)` from the manifest. `/status.build` features and target must match the manifest. Config fingerprints must be equal across validators. |
| **G2 Readiness and mesh** | `/readyz` (`text/plain`) returns 200. This already includes beacon readiness (`iroha_torii/src/lib.rs:14080-14085`). Only `MissingSession` is tolerated, and only before the beacon install in a fresh generation. Peers ≥ n−1. |
| **G3 Liveness** | Two samples at least 2× cadence apart. Lag ≤ 2. A node that does not advance while others do is named. `restart_required = false`. `no_progress_age` is bounded while queues are non-empty. Equal heights on an idle chain count as healthy. |
| **G4 Beacon horizon** | Taken from the signed `SumeragiStatus.beacon_horizon`: `session_covers_next_pulse` and `local_provider_ready`. Before any restart, `blocks_to_pulse ≥ margin`; otherwise a supervised crossing runs first. BLOCKED when there is no session and the bootstrap window has closed. |
| **G5 Finality** | Verify every contiguous native successor from an independently selected complete `SumeragiFinalityCheckpoint` in `checkpoint.norito`, with exact 2f+1 CommitQC signers from each authenticated scheduling epoch. Require a fresh challenge-bound quorum of the final committee. Proof count, canonical block bytes and peer reads are bounded per observation; failed observations do not publish a checkpoint. |
| **G6 Applied write** | Ephemeral key, PoW faucet claim, `Log` transaction, all exact-wire journaled through `iroha_operation_journal`. Applied on every validator with committed wire equal to prepared wire. One work-scaled deadline, honouring `Retry-After`. Onboarding is exercised when a credential exists. |
| **G7 Restart proof** | Wait for a snapshot newer than each node's start, then restart the nodes one at a time. Each must restore from the snapshot and pass G2, G3 and G6. |
| **G8 Pulse crossing** | Runs on qual and dev profiles, or when `blocks_to_pulse ≤ 200`. Writes drive the chain across the next mandatory pulse and an epoch boundary. `/readyz` stays 200. On `sora-nexus-v1` with a distant pulse it is skipped with a note. |
| **G9 Public service** | Actual primary ingress readiness, expected release and network identity, valid TLS and curated MCP health. Runs against the edge IP with pinned SNI before DNS moves. The broad doctor, product-route posture, explorer configuration, expiry-horizon and external-probe exercises remain separately requested optional diagnostics. |
| **G10 Inrou** | Replicas equal the number of validators, decoded with the typed `/v1/soracloud/status` DTO. Replica identities are distinct and manifest digests equal the per-ISA release pin. `StoppedInrouReconcile` stays clean. |
| **G11 Host health** | Headroom; journald cap; units enabled after seal; NRestarts delta; gateway and TLS certificate expiry; no foreign process on managed ports. |
| **G12 Dataspace** | Actual registration is committed. Catalog entry and active native lane match the expected committee and scope. Supplied lane certificates verify exactly 2f+1 signers from that committee. Routing, read permissions and budget accounting follow committed state. Additional owner-write exercises are optional diagnostics. |

**When each gate runs:**
G6–G8 are optional engineering diagnostics. They run only when explicitly requested through
`verify`; their absence or verdict never blocks signing, `apply`, `reset`, sealing or public
cutover on Taira or production. Protocol-required bootstrap transactions remain ordinary
authenticated chain actions; they do not require a canary, restart rehearsal or boundary
crossing test before deployment.

- `plan`: G0–G5 and G11, read-only.
- `apply` on a fresh generation: G0; after start G1–G3; strict G2 and G4 after the install; G10; G9; then seal.
- `apply` for an upgrade or config change:
  1. G0–G5 and G11, then classification.
  2. The G4 margin before each restart.
  3. `--check-storage`.
  4. Record the actual node start and serving state without a write diagnostic.
  5. G1–G5, G9 and G10.
- `reset`: the same as a fresh generation.
- `verify`: every applicable read-only check. An explicit write diagnostic adds G6;
  `--full` adds G6–G8. `--read-only` always omits G6–G8.
- `status`: displays G1–G4 and G11.
- Dataspace: G1–G5 against the parent over public routes only, G1–G4 on the owner nodes, and G12.

---

## 10. Node and config changes

1. **Compiled profiles** (`iroha_config::profile`, new).
   - Files: `crates/iroha_config/profiles/{sora-nexus-v1,sora-nexus-v1-qual,iroha-dev-v1}.toml`, each with `static`, `derive`, `policy` and `role.*` sections.
   - A node file that sets `profile` and `validators` (with optional `role`, default `validator`) makes irohad build `ConfigReader` sources in this order: defaults, then `static`, then `derive(n)`, then `policy`, then the role overlay, then the node file (`iroha_config_base/src/read.rs:527-560`).
   - The node file may contain only the per-node allowlist:
     - `chain`, `data_dir`, `public_key`, `trusted_peers`, `trusted_peers_pop`;
     - `network.{address,public_address}`;
     - `torii.{address,transport.trusted_proxy_cidrs,operator_signatures.allowed_public_keys,account_onboarding.{authority,credentials}}`;
     - the faucet authority id;
     - `genesis.*`;
     - `soracloud_runtime.submission.signer` (public binding);
     - `soracloud_runtime.inrou.{enabled,portable_vm_uid,portable_vm_gid,trusted_guest_manifest_digest_hex,trusted_guest_content_cid}`;
     - `lifecycle.exit_on_stdin_close`;
     - `node_tunable`.

     Anything else is a parse error. Files without `profile` stay ordinary flat configs.
   - Node-bound templates: the profile's `torii.faucet` and `torii.account_onboarding` sections apply only when the node file binds that section's `authority`. A bound section's key comes from its fixed `<data_dir>/secrets/authority/*.key` file, and the parser rejects a key that does not sign for the bound authority.
   - `NodeSecretFile::SorafsCouncilAuthority` names `authority/sorafs_council.key` in the fixed layout the deploy engine writes; no node configuration key reads it (the node verifies council signatures with public `trusted_council_keys`), so the node never opens it.
   - Profiles replace the `iroha3d_taira` exact-match guards (`taira_runtime_signer.rs:126-298`). Genesis-bound hashes (checked by `irohad` against the authenticated genesis Sumeragi context) and the `iroha_p2p` peer handshake still catch any divergence.
   - `--config-blake3` stays, because the node file is flat.
2. **`data_dir`** (user, actual, defaults). A relative `data_dir` resolves against the directory of the file that sets it and is then made absolute against the working directory, so every derived path is absolute; the loader writes the resolved value to its own source, and the parser rejects a `data_dir` read without the loader (`ParseError::InvalidDataDir`). Every state path defaults under `<data_dir>/state/`. Secret paths default to fixed `<data_dir>/secrets/*` names, including `torii.account_onboarding.private_key_file` and the faucet authority key. This replaces the 11 paths rewritten by `validator_config.rs:139-190`.
3. **`irohad::node_secrets`** (about 500 lines). Builds `IrohaRuntimeDeps` for the Soracloud signer (when `production_mode` is set) and the beacon partial signer (when `beacon.cred` exists). It verifies each against the rendered public binding.
4. **Beacon ceremony extraction (P1).**
   - `encode_global_beacon_partial_signer_credential_v1`, `global_beacon_partial_signer_inventory_digest_v1` and `RuntimeGlobalBeaconShareProvisioningV1` move from `irohad/src/external_software_signer/consensus_threshold.rs:116,509` to `iroha_core::beacon::credential`.
   - The Provision, SignInstall and Assemble core moves from `beacon_bootstrap.rs` to `iroha_core::beacon::ceremony`. It is generalized from the hard-coded 4/2/quorum-3 and the Taira chain id (`beacon_bootstrap.rs:241-262, 455-510`) to n, f+1 and 2f+1.
   - Implemented on Core's signed all-edge DKG (the central dealer is gone): `global_beacon_genesis_dkg_session_v1` (canonical genesis session and attempt ids, which irohad's genesis seat also uses), `GlobalBeaconCeremonyPlanV1` (roster, handles, revision; `seat_credential` encodes one seat's credential), `deal_global_beacon_at_logical_clock_v1` (every seat in process, one `LocalGlobalThresholdBeaconDkgSeatV1` per validator key) and `GlobalBeaconInstallContextV1` (`FinalizeGlobalBeaconKey` drafts, per-host range signing and exact 2f+1 assembly). TODO(P3): the per-phase relay API behind `DealSeat` for remote hosts.
   - The irohad `beacon-bootstrap` subcommand no longer has a centralized dealer: it runs the signed all-edge per-seat DKG (one `provision-*-seat` process per seat over Core's `LocalGlobalThresholdBeaconDkgSeatV1`) and encodes seat credentials with `iroha_core::beacon::credential`. The cutover (P8) deletes it. `iroha_deploy` never depends on irohad.
5. **`iroha3d --check-storage`.** Takes the store-root lock, opens Kura and the newest snapshot read-only with this build's decoders, and returns `{tip_height, tip_hash, prefix_hash_at_snapshot_height, snapshot_restore_dry_run: ok|error}`. `--check-config --json` prints the seven compatibility values listed in S1-B.
   - Implementation (`irohad::compatibility_probe`): Kura is opened in emergency-Fast mode, which takes the store-root lock through Kura's own opener, validates the durable commit marker and maps the hash journal without repairing or publishing anything. Every retained block body up to the tip is decoded with this build and checked against the hash journal and its parent. The newest snapshot is checked using a temporary scratch Kura. A positive-height snapshot reports `NativeExecutionReplayRequired`: its signature does not authenticate the complete World against native witnessed-write commitments. Normal Strict startup needs the original signed genesis and complete native certified replay history.
   - The report also carries `snapshot_height` and `snapshot_restore_error`; hashes are lowercase hex; an absent store reports height 0; an absent or disabled snapshot is `ok` with `snapshot_height = null`. The exit status is nonzero when the store cannot be read (no JSON) or the dry run fails (JSON first). Retired snapshot-import markers are rejected rather than converted into a trust root.
   - `--check-config --json` adds `status` (`ready`/`pending`). The genesis-bound values (`config_fingerprint`, `execution_policy_hash`, `nexus_amx_context_hash`) are `null` without a local signed genesis. `nexus_policy_digest` is computed from the rendered configuration's Nexus section with its frozen lane-manifest and compliance digests.
6. **Signed beacon horizon.** `SumeragiStatus` gains `beacon_horizon: Option<BeaconHorizonStatusV1 {epoch_length_blocks, next_required_pulse_height, active_session_id, session_covers_next_pulse, local_provider_ready}>` (explicit `null` until serialized activation of that exact height has published it; G4 treats `null` as not yet observable; the epoch length and the next pulse both come from the same frozen `HeightContext`, the epoch length being the span of its authenticated validator epoch authorization, so an `NPoS` horizon is published from the genesis height on; validation rejects a zero `NPoS` epoch length and a non-zero permissioned one), filled from the authenticated beacon height binding. It is embedded in the signed `BridgeFinalityAttestationBodyV1` (`bridge.rs:746-768`), so G4 works over public routes. Norito roundtrip tests are added.
7. **Torii.**
   - A `latest` selector for `/v1/bridge/finality/attestation/{height|latest}` (`routing.rs:6377-6420`; descriptor `route_catalog.rs:2677-2682`).
   - `/status.build.wire_schema_hash`.
   - `GET /v1/nexus/lanes/{lane_id}/certificate/latest` (P6), which is public, rate-limited, and returns hashes and QCs only.
8. **`[lifecycle] exit_on_stdin_close: bool = false`.** Set only by the local renderer.
9. **Kura.** Delete the public-reset marker admission (`kura/lane_geometry.rs:1540-1548, 1630-1700`) and its tests (`03_gc_and_startup.rs:1757-1790`).
10. **Delete at the cutover (P8):**
    - the `iroha3d_taira` binary (`Cargo.toml` `[[bin]]` 116-119; `src/bin/iroha3d_taira.rs`);
    - `taira_runtime_signer.rs`;
    - `defaults::taira` (`defaults.rs:97-160`);
    - the `Dockerfile` `iroha3d_taira` entry and the `CONFIG_PROFILE=taira` branches;
    - the `scripts/docker_entrypoint.sh:178` taira branch, which becomes `exec iroha3d --config`;
    - the Inrou self-exe name match, which becomes `iroha3d` only (`soracloud_runtime.rs:224-241`).
11. **Nexus flat configs and `--sora` (out of scope).** Minamoto is untouched. `--sora`, `IROHA_SORA_PROFILE`, `requires_sora_profile` and `Config::apply_sora_profile` stay as they are, together with `defaults/nexus/config.toml` and `configs/soranexus/nexus/config.toml`. Profiles never set `--sora`, and a node file that sets `profile` must not be started with `--sora` (parse error).
12. **kagami.**
    - `kagami localnet up/status/logs/down/reset` calls the shared native process owner. `kagami localnet generate` is the explicit operator bundle generator; no old positional form or `localnet-wizard` alias remains. The superseded `localnet_tui.rs` and frontend-owned generation implementation are removed.
    - The canonical genesis and rendering implementation now lives in `iroha_deploy::{genesis, localnet}`. Profile consolidation into `iroha_config::profile::derive`, retirement of the chain-id Taira branch and generated script transport, and complete Committee-role key custody remain operator-engine work. Deterministic fixtures retain `--seed` and scaling layouts; managed developer generations use fresh keys.
    - Delete the `iroha3-taira` `GenesisProfile` and `RETIRED_PUBLIC_CHAIN_ID_ALIASES`.
    - `kagami docker` reads the container render mode.
    - `privacy_bootstrap` `include_bytes!` of the Taira config and template (`privacy_bootstrap/release.rs:55-68`) is re-pointed to the profile files. The privacy plan and NEVO files move to `configs/soranexus/privacy/`.
13. **Also (P6):** the committee connection budget, topology sync and permissions (§11.2).

**The seven Taira definitions become one profile plus `networks/taira.toml`.**
- The config and genesis template, the kagami hidden branch, `defaults::taira`, the `iroha3d_taira` guards, the Python copies (`taira_devnet.py:142-169`, `taira_constants.py`), the CLI constants (`taira_public_reset.rs:39-56`, `taira.rs:53-57`, `taira_dataspace_deploy.rs:1166-1173`) and the rewrite stages are all deleted.
- The drifted dpn, is2 and cbsi catalog is not carried over.
- Consumers read the verified card: the five SoraFS scripts use `iroha network status https://taira.sora.org --json`. The SDK `TairaTestnetProfile` copies and the chain-id literals are re-pointed in P8.

---

## 11. Dataspace protocol changes (P6) and deferrals

### 11.1 What Core already supports

- A lane manifest may bind any exact 3f+1 set (f ≥ 1, at most 128) of registered accounts to peers in `world.peers` that hold live Committee-role keys and valid PoPs (`runtime_catalog.rs:85-147`; `runtime_overlay.rs:96-139`).
- `RegisterCommitteePeerWithPop` never adds global voting power.
- An exact 3f+1 lane committee needs no beacon (`lane_authority.rs:609-620`).
- A stalled lane blocks only itself.
- Torii routes lane work to the canonical committee over P2P, or over the manifest `torii_url`.

### 11.2 What must land (P6, in the release genesis)

**D-1. `RegisterDataspaceV1`** (consensus-affecting, size L).

Placement:
- data model: `crates/iroha_data_model/src/isi/nexus.rs`, registered in `isi/registry/wire_ids.rs` and `generated_record_inventory.rs`;
- execution: `crates/iroha_core/src/smartcontracts/isi/dataspace.rs`;
- Initial-executor classification: `crates/iroha_core/src/executor_initial_permission_authority.rs`;
- fee class: `validation_fee.rs`.

The type is `RegisterDataspaceV1 {name, visibility, committee: DataspaceCommitteeV1}`, with `DataspaceCommitteeV1 = Network | Explicit(Vec<CommitteeMemberV1 {validator, peer, pop, torii_url: Option<Url>}>)`.

Core executes it atomically:
1. The authority holds `CanRegisterDataspace` and owns the active SNS lease for `name`, created earlier in the same transaction (lookup `alias_setup.rs:1073-1093`). `DataSpaceId` is derived from the name hash.
2. **Explicit committee:** n = 3f+1 with 4 ≤ n ≤ 128. The existing dataspace-scoped committee peers plus n must not exceed the genesis parameter `nexus.max_external_committee_peers`. Each member is registered as a dataspace-scoped Committee peer by reusing `prepare/commit_peer_identity_with_pop` (`world.rs:17033-17245`), failing closed if a key would not be live at h+1. **Consent rule:** reject a peer already bound by another dataspace, and a peer that is neither registered by this instruction nor a global validator.
3. **`Network` committee:** the current global validators that hold live Committee keys, bound with their lane-0 accounts.
4. The lane id is deterministic: the lowest free id outside the autoscale range. Only FullReplica is accepted.
5. `stage_consensus_catalog_transition` (`runtime_catalog.rs:274-496`) runs with expected hashes read from the same state, so callers supply no CAS.
6. The owner is granted `CanManageDataspace{ds}`, `CanReadRestrictedDataspace{ds}` and `CanPublishSpaceDirectoryManifest{ds}`.

The `nexus_catalog_transition_v1` `SetParameter` path is deleted (`world.rs:20814-20871` and its `visit_set_parameter` branch). `iroha_test_network/tests/support/{runtime_catalog_transition.rs, catalog_recovery.rs}` are ported to the ISI.

**D-2. Permissions** (consensus-affecting, size M). New tokens in `iroha_executor_data_model/src/permission.rs`:
- `CanAdministerDataspaceRegistration`: a unit token granted to the admin in genesis. Its holders may grant it on.
- `CanRegisterDataspace`: a unit token granted and revoked only by holders of the administer token. This follows the existing `DpnAdmin` pattern (`executor_initial_permission_authority.rs:600-622`), and it makes `[[grant]]` exact-set revocation well defined.
- `CanManageDataspace{ds}`: grantable and revocable by its holders. It authorizes grant and revoke of:
  - `CanReadRestrictedDataspace{ds}`, which is genesis-only today (`INITIAL_GENESIS_ONLY_PERMISSION_NAMES` in `executor_initial_permission_authority.rs`);
  - `CanPublishSpaceDirectoryManifest{ds}` and its variants, which have no post-genesis first grant today (`executor_initial_permission_authority.rs:624-627`).

`CanManagePeers` stays global and remains governance's emergency stop: unregistering a committee peer halts its lane fail-closed. **Every rule lands in Core's single native authority, `executor_initial_permission_authority.rs`, with positive and negative test matrices in `iroha_core`.**

**D-3. Genesis from the profile** (consensus-affecting, size S). The genesis has:
- Committee-role keys for every validator;
- a baseline catalog of core lanes plus the public `nexus` lane, with no manifest directory.

It also has:
- `CanAdministerDataspaceRegistration` for the admin;
- `nexus.dataspace_registration = permissioned`;
- `nexus.max_external_committee_peers = 12`.

**D-4. Committee connection budget** (non-consensus, size S).
- `derive(n)` computes `committee_sources = n + max_external_committee_peers` and `network.max_total_connections = (n − 1) + max_external_committee_peers + authenticated_non_validator_sources`, so every other validator, every external committee peer within the on-chain budget and the profile's authenticated non-validator allowance (4) can hold a connection.
- Sumeragi needs no ingress byte partition or committee source class: each consensus instance bounds ingress per `(peer, traffic class)`, serves peers round-robin within a class, and owns its queues and network quotas (`specs/sumeragi.md` §12.3 O6, O8, O9), so an observer flood cannot starve a lane committee.
- The on-chain budget (D-1) and the connection budget come from the same profile number. `dataspace plan` refuses once the budget is used up. `sora-nexus-v1` allows 12 external peers, meaning three owner committees of 4.

**D-5. Topology sync** (non-consensus, size M).
- `irohad/src/main/peers_gossiper_topology_sync.rs:40-50` publishes `commit_topology ∪ live manifest-bound committee peers`.
- Sends to disconnected committee peers are then deferred instead of dropped (`network.rs:14360-14370`).
- Owner nodes dial Taira, with seeds taken from the card.

**D-6. Public verification routes** (non-consensus, size M): the `latest` attestation selector (P1) and the lane certificate route (§10.7).

**D-7. N-validator light verifier** (non-consensus, size L).
- Copied in P0 into `iroha_deploy::verify::finality` and generalized from `taira_authenticated_height.rs` and `taira_dataspace_deploy_finality.rs`, which were hard-coded to 4 peers and 3 signers (`finality.rs:23,140,211`). The frozen `iroha_cli` originals are deleted in P8.
- Anchored in the pinned card (until the card exists, an authenticated genesis) and in `checkpoint.norito`.
- Verifies every native successor, including complete epoch, generation, schedule and parent-result bindings. The canonical checkpoint is `SumeragiFinalityCheckpoint`; old epoch-skipping and scalar-context checkpoint layouts are absent.
- Requires 2f+1 distinct current committee members' fresh challenge-bound native attestations. After compact checkpoint import, a member at the immediately preceding height can count only against its exact retained decision and authenticated parent. During an observation, earlier immutable responses also count if their complete original decisions were verified while advancing the contiguous prefix; this preserves progress when reads straddle a boundary. At most one verified outcome per queried peer is retained until that observation ends. An arbitrary proof from the same epoch cannot establish prefix membership.
- Genesis execution has no QC. Initializing from signed genesis does not authenticate its outputs; a certified successor or independent fresh committee attestations are required. A peer's supplied proof or checkpoint cannot select its own trust root.
- The current implementation caps an observation at 4,096 successor proofs, 64 MiB of canonical block frames and 124 distinct queried peers (`MAX_OBSERVATION_PEERS`, four times the 31-member committee maximum). Advance and observation publish a checkpoint atomically only after their required verification succeeds. The HTTP source remains TODO(P2).
- Portable verifier fixtures cover genuine BLS signatures over synthetic execution results, including 4→7→4 proof chains. They do not qualify World execution, XOR custody, beacon DKG, or live multi-peer transitions. Verifying native lane evidence against its authenticated owner remains part of the lane route gate (P6).
- Drops the node, build and config fingerprint pins and the per-height proof journal.

**D-8. Owner nodes** run stock `iroha3d` with `role = "lane_validator"`, which derives `sumeragi.role = "validator"`.

### 11.3 Deferred TODOs, in priority order

- **T1 (P7, consensus-affecting): `SetDataspaceCommitteeV1 {dataspace, members}`.** Authorized by `CanManageDataspace{ds}`, with the same f and lane. It needs the add-only rule (`runtime_catalog.rs:180-184, 213-222`) relaxed for binding-only revisions, and the frozen-successor handoff so that in-flight sessions finish under the old committee.
- **T2:** restricted gossip targets `commit_topology ∪ resolved lane committee`. The commit topology must be kept, because every node follows every public lane and the global chain merges the certified lane blocks by reference (`specs/sumeragi_lanes.md` §4.1; `gossiper.rs`).
- **T3:** a manifest `p2p_address` dial hint for owner nodes behind strict inbound firewalls.
- **T4:** a dynamic external-peer budget. The first release uses the static genesis parameter.
- **T5:** scheduled lane activation when `key_activation_lead_blocks > 1`. Until then the tool fails closed.
- **T6:** recovery from total committee loss and abandonment of stuck sessions.
- **T7:** delete `AliasDataspaceBootstrapGrantV1` and its `SetParameter` path once no baseline dataspace needs it.
- **T8:** P2P connection-slot reservation for topology and committee peers.
- **T9:** confidentiality through CommitmentOnly or private execution. This is a separate protocol.
- **T10:** rotation of genesis-anchored network authority keys without a reset.
- **T11:** refreshing S2a bindings when Taira's roster changes. This depends on global validator rotation.

### 11.4 What "restricted" honestly means

- Lanes are FullReplica. Every Taira validator, every owner node and every observer executes and stores restricted-lane data. Certified-body serving checks neither membership nor visibility (`serve` in `crates/iroha_core/src/sumeragi/driver/serve.rs`).
- "Restricted" means Torii read filtering, the restricted gossip plane and admin-managed committees. It does not mean confidentiality from Taira operators or observers.
- The plan output and the docs say this plainly.
- S2b adds narrower guarantees: the owner's 2f+1 certify every lane height, and the lane's authoritative Torii endpoints are the owner's own.

### 11.5 Tests

- **Core unit tests:**
  - S2a and S2b happy paths, including register-and-live at h+1 in one transaction;
  - fail closed when lead > 1, when the authority is not the lease owner, when the permission is missing, and when the budget is exceeded;
  - key collision, a peer bound to a foreign dataspace, n ≠ 3f+1, and CommitmentOnly rejection;
  - lane-id determinism, and `LifecycleAlreadyStaged` for two creations in one block.
- **Norito roundtrips** for every new type.
- **Executor and Core-mirror matrices** with identical fixtures. They must show that `CanManageDataspace{a}` grants nothing over b, no `CanManagePeers` and no `SetParameter`.
- **Ingress class tests.** Observers cannot exhaust committee capacity. A config with differing capacities is rejected at the handshake.
- **Integration test** (`integration_tests/tests/nexus/dataspace_owner_committee.rs`): 4 global validators plus 4 committee nodes, with the committee peers not in the global validators' trusted peers.
  - A restricted transaction submitted through a global validator is proxied to the owners.
  - Stopping 1 owner node keeps the lane live.
  - Stopping 2 halts the lane while global finality continues.
  - Restarting all the owner nodes recovers the lane.
  - A second run uses `committee = network`.

---

## 12. Deletion list

Line counts come from `wc -l` on this branch unless marked ~. Everything below is deleted at the **cutover (P8)** unless another phase is given. Every consumer is ported before that change or within it.

| What | Lines | Replaced by | Phase |
|---|---|---|---|
| `crates/iroha_cli/src/taira_public_reset*.rs` (32 files) + `taira_stopped_owner_maintenance.rs` | 57,288 + 562 | `iroha_deploy::{plan, converge, journal, driver::ssh, agent, render, beacon}` | P8 |
| `taira.rs` (write-canary, inrou-*, doctor dispatch, account, Soracloud JSON validators) + `taira_canary_deadline_tests.rs` | 13,533 + 295 (≈1.4k doctor checks move to `verify::public`) | `iroha_deploy::verify` (G6, G9, G10), later `iroha_deploy::inrou` | P8 |
| `taira_onboarding.rs`, `taira_doctor_accounts.rs` + tests | 799 | musubi (shipped in the controller bundle); G9 | P8 |
| `taira_dataspace_deploy.rs`, `_finality.rs`, `_manifest.rs`, `_profile.rs`, `_finality_tests.rs` (coupled to public-reset; never completed a deploy) | 6,425 | `iroha dataspace` (P6) | P8 |
| `taira_authenticated_height.rs` + tests | 1,709 (copied and generalized in P0) | `iroha_deploy::verify::finality` | P8 |
| Taira items in `crates/iroha_cli/src/soracloud.rs` (`TAIRA_INROU_*` :508-558, stage/binder :6760-9577, `TairaMutationBindingV1` :18995-19420, ~63 tests; the `defaults::taira` users) | ~8,300 | `iroha_deploy::inrou` (P5) | P8 |
| `operator_key.rs` FD loader (:29-150), `main_shared.rs` taira modules and dispatch (:33-35, 1274-1292, 1461-1477, 1515-1604) | ~420 | File loader; `network` and `dataspace` modules | P8 |
| `crates/iroha_cli/bins/src/bin/taira_fee_sponsor_program.rs` | 517 | nothing (no callers) | P8 |
| `crates/irohad/bins/src/bin/iroha3d_taira.rs` + `taira_runtime_signer.rs` | 12 + 2,007 | `irohad::node_secrets` | P8 |
| `beacon_bootstrap.rs` daemon subcommand + tests | 1,093 + 676 (≈1.1k core moved in P1) | `iroha_core::beacon::ceremony` | P8 |
| `defaults::taira` | ~70 | Profiles | P8 |
| Kura public-reset marker (`lane_geometry.rs` :1540-1548, 1630-1700) + tests | ~190 | `GENERATION` outside the store root | P8 |
| `crates/iroha_kagami/src/localnet.rs` + `localnet/` + `localnet_tui.rs` | 16,690 (≈5k moved) | `iroha_deploy`, `iroha network up` | P8 |
| `xtask/src/kagami_profiles.rs` + dir, `defaults/kagami/{iroha3-dev,iroha3-nexus}`, `scripts/kagami_profile_owner.py` | 3,891 + ~150 | Profiles, `networks/*.toml` | P8 |
| `configs/soranexus/taira/*` (config, genesis template, roster example, dns, explorer runtime config, canary client, sorafs sites, install script + mock test, explorer nginx, `__pycache__`); README 815 → ~60 | 3,976 + 755 | Profile, definition, `render::edge`, card | P8 |
| `scripts/taira_devnet.py`, `taira_retry.py`, `taira_update.py`, `taira_update_guest.py` | 8,399 + 5,608 + 584 + 1,516 | `up`/`verify`/`down`; resume; `apply --release` | P8 |
| `scripts/taira_release.py`, `taira_release_check.py`, `taira_cargo_cache.py`, `taira_cargo_artifact.py`, `taira_source_observation.py`, `check_taira_initial_executor.py` | 7,401 | `cargo xtask release`; optional nextest diagnostics (CI switched in P0) | P8 |
| `scripts/taira_release_transfer.py`, `taira_source_capture.py`, `taira_retained_release.py`, `taira_retained_source.py`, `taira_signer_observation.py`, `taira_disk_capacity.py`, `taira_nginx_logrotate.py` | 5,288 | Upload, GC, G0/G11, G1, logrotate | P8 |
| `scripts/taira_validator_unit.py` (+ `include_str!` at `taira_public_reset_validator_units.rs:11-12`), `taira_constants.py`, `render_taira_edge_nginx_conf.py` | 209 + 64 + 1,143 | `render::{unit, edge}`, card | P8 |
| Python tests for all of the above | 28,462 | Rust tests in `iroha_deploy` | P8 |
| `scripts/deploy_localnet.sh`, `run_local_swarm.sh`, `custom_network_test.py` + tests | ~1,750 | `iroha network up` | P8 |
| `defaults/docker-compose.local.yml`, `docker-compose.single.yml` | 446 | Generated `defaults/docker-compose.yml` (§6.3) | P8 |
| kagami `--private-dataspace` presets + tests | ~1,000 | Dataspace definitions | P8 |
| `scripts/nexus/lane_bootstrap.py`, `scripts/nexus_lane_bootstrap.sh` | 667 | `iroha dataspace apply` | P6 |
| `docs/source/taira_{release,release_check,release_transfer,retained_release,retained_source,retry,disk_capacity,dataspace_deploy}.md`, `PUBLIC_RESET_BEACON.md`, `DISPATCHER_TRANSITION.md` | 2,550 | `crates/iroha_deploy/README.md` and the iroha-docs guide | P8 |

**Totals:**
- Rust CLI ≈ 89k (≈9k moved);
- irohad and core ≈ 2.5k;
- kagami and xtask ≈ 20.7k (≈5k moved);
- Python scripts ≈ 30.1k;
- Python tests ≈ 28.5k;
- shell ≈ 3.3k;
- configs and docs ≈ 7.3k.

**Porting, all in P2 unless marked P8:**
- `iroha_test_network`: `production_beacon_prepare.rs:305`, `production_beacon_bootstrap.rs:579,622,1709`, `dataspace_deploy_cli.rs`, the `iroha3d_taira` build selection (`lib.rs:1110-1195`) and `build_resolution_tests.rs` (P8).
- `main_shared_tests.rs:903-1443`, `cli_smoke.rs:479-600` (P8).
- `.github/workflows/workspace_release.yml:96-143` and `pytests/scripts/workspace_release_gate_test.py` (P0).
- `pr.yml:287,318` and `scripts/check_nexus_provisioning_templates.py:18-31`: drop the Taira and `defaults/kagami` templates, check the explicit nexus files and the profile files instead.
- `pr_docker_compose.yml:50-85`, `publish.yml:72`.
- `integration_tests/tests/sumeragi_kagami_localnet.rs:192-202`: move to `iroha network up` with `--seed-file`.
- `run_10k_localnet.sh`, `run_100tps_profile_localnet.sh`: move to `networks/perf-*.toml`.
- `javascript/iroha_js/scripts/run_integration.mjs:18`, `python/iroha_python/scripts/run_integration.py:25`, `crates/iroha_swarm/tests/default_compose_soranet.rs:155-156`, `scripts/tests/consistency.sh:138-139`, `hooks/pre-commit.sample:44-48`: move to the generated `defaults/docker-compose.yml`.
- `crates/iroha_config/tests/taira_config_contracts.rs`, `iroha_config/tests/fixtures.rs`, `crates/iroha_genesis/src/lib.rs:3333-3475`, `crates/iroha_kagami/src/{wizard.rs:1883-1900, genesis/sign.rs:1785,2363}`: move to profile fixtures.
- `scripts/docker_entrypoint.sh` and `scripts/tests/docker_entrypoint_test.py` (P8).
- Release scripts that list `iroha3d_taira`: `sumeragi_prebuilt_bundle.{py,sh}`, `panic_recovery_boundaries.inventory` and their pytests. They move to `iroha3d` (P8).
- `mobile_sdk_artifacts.yml:48-49`, `sorafs-orchestrator-sdk.yml:14-15` path filters, `scripts/check_workspace_target_inventory.py` and its test, and SoraFS users of `taira_constants` (P8).
- `status.md:59` link (P0).
- `AGENTS.md` Taira bullets and `skills/sora-taira-testnet/SKILL.md` (P8, text proposed in §13).

**Edge-case fixes that become named tests** in the agent or verify code before their source is deleted:
- `text/plain` `/readyz`;
- the empty `/proc/<pid>/cmdline` window;
- numeric ExecMainCode;
- QEMU exit-with-parent, and QEMU exe as a directory (the orphan outside the cgroup);
- mesh before write;
- `Retry-After` on 429;
- MCP pagination bound;
- the onboarding permission set;
- faucet predecessor policy;
- stopped-owner reconciliation.

---

## 13. Phased implementation plan

**Release rule.** Everything in this document ships in **one release**:
- the engine;
- the local, container and SSH drivers;
- Inrou;
- the dataspace protocol and tooling;
- committee rotation;
- the deletions.

All phases land on the `network-deploy` branch, and nothing is released or deployed to Taira until P9. From P0 on, the old Taira toolchain is frozen: no fixes, no new features. P8 deletes it on the branch, so the release carries only the new path.

Taira gets exactly one ledger replacement: the P9 restore. Its genesis already carries the dataspace protocol content (D-3), and Inrou is on from the start. Focused tests, lint and formatting checks are engineering diagnostics; their completion or verdict is never a signing or deployment prerequisite for Taira or production.

Line estimates count new or moved production lines. Tests are extra: about 12k lines for tooling and about 5k for the protocol.

**P0. Extraction and CI unblock** (~2.0k).
- `crates/iroha_deploy` with crate docs, the network and dataspace definition parsers, and their tests.
- The finality verifier is copied into `iroha_deploy::verify::finality` and generalized: N = 3f+1, 2f+1 attestations, checkpoint. The frozen `iroha_cli` originals stay until P8.
- Shared genesis fixtures are not moved in P0: they are rebuilt from the P1 profiles, so they move to profile fixtures in P2 (§12 porting list).
- An optional nextest diagnostic profile. `workspace_release.yml` and its source guard keep diagnostics independent of release builds.
- `status.md:59` is fixed.
- Exit: CI runs no Python census.

**P1. Node surface** (~4.0k: 1.5k node, 2.5k tooling).
- Profiles with `derive(n)`, both digests, the allowlist and the role overlays.
- `data_dir`.
- `node_secrets`, with public-binding checks.
- `--check-storage` and `--check-config --json`.
- `beacon_horizon`, the `latest` selector, `wire_schema_hash` and `exit_on_stdin_close`.
- The beacon credential and ceremony move into `iroha_core::beacon`. The irohad subcommand keeps its per-seat DKG and uses the Core credential codec.
- `iroha_operation_journal` owns the shared storage API; signing and authority remain in its consumers.
- **Golden parity.** With fixed seeds, the `sora-nexus-v1` render plus genesis must match today's kagami Taira `execution_policy_hash` and `nexus_amx_context_hash`. The only exceptions are the listed intentional differences: the catalog, the cadence and Authenticated capacity 4.
  - Implemented as the kagami unit tests `localnet::profile_golden_parity_tests`: they restage kagami's signed Taira genesis under the profile render and compare both hashes, and check the genesis recipe against kagami's signed genesis parameters. TODO(P8): move them to `iroha_deploy` with kagami's two hashes pinned.
  - "The catalog" is `nexus.{lane_catalog, lane_config, dataspace_catalog, routing_policy, registry}` plus the governance modules its restricted lanes name (`nexus.governance`).
  - Authenticated capacity 4 enters neither hash.
  - The test found one more difference, which the list above lacked: the protocol custody account (gas technical account, fee sink, sponsor-vault custody, stake escrow, slash sink). Kagami derives a keyless account from each genesis public key; a compiled profile cannot know that key, so it fixes one keyless account, `iroha_config::profile::protocol_custody_account`. The test proves both sides are those keyless derivations and then normalizes them. Decision (P1 review): this is an intentional difference. No protocol custody role, `gov.*` account, treasury or VPN operator in a compiled profile may name a signing key, least of all a published sample key; each is a deterministic keyless account derived per base profile, and golden parity normalizes exactly these roles after asserting their keyless (profile) or sample-key (kagami governance) provenance.
  - It also found two profile bugs, now fixed: the custody roles used the published sample key (`iroha_test_samples` ALICE), and `crypto.curves.allowed_curve_ids` fell back to the code default `[1, 4]`, dropping bls_normal (3) that Taira allows. Every compiled profile now sets `allowed_curve_ids = []` so parsing derives it from `allowed_signing` (the dev profile had the same bug).
  - Governance accounts (security fix, an intentional difference): kagami's Taira names the published sample key for every governance escrow, receiver, viral pool and the SoraFS pin-fee treasury (and the VPN operator). The profile gives each role its own keyless account, `iroha_config::profile::keyless_role_account`; the test proves kagami's side is the sample account and the profile's the keyless derivation, then normalizes them. TODO(P2): the genesis builder registers these accounts.
- A drift test checks that profile values equal `defaults::taira` until the cutover deletes it (`iroha_config` `profile::tests::sora_nexus_v1_policy_matches_defaults_taira`).
- **Beacon pre-deal proof test.** A deal made against a logical clock must install on a fresh 4-peer network, and a node started with `beacon.cred` before the install must become ready right after it. TODO boundary: if Core rejects this, fall back to dealing against live heights driven by G6 writes, plus one rolling restart to load the credentials (about 3 minutes extra).
  - Proven, so the fallback is not needed. The test is `iroha_test_network` `four_peer_sora_nexus_qual_predealt_beacon_installs_without_restart` (`tests/sora_nexus_profile_network.rs`), on four `sora-nexus-v1-qual` validators.
  - TODO: re-prove on the new Sumeragi node. The daemon now runs `iroha_core::sumeragi::node`, which publishes no signed v2 status and applies no beacon effects yet, so the rebased test deals, admits and meshes all four validators and then stops at the first signed-attestation read (`consensus_uninitialized`). The test reads each validator's status from its challenge-bound `/v1/bridge/finality/attestation/{height}`, because `/v1/sumeragi/status` now serves the node's `SumeragiStatus`.
  - It deals in process with `iroha_core::beacon::ceremony` against the genesis session's nominal windows 1–4 before the first start (each seat runs Core's signed all-edge DKG with its own validator key), and each validator reads its `beacon.cred` from `data_dir` at that start.
  - Before the install, `/readyz` is 503 and the signed horizon names no session. `Log` transactions drive the tip to `finalized_at_height`. Three validators pre-sign 16 heights each, and the certificate for the next height installs.
  - At the install height, with no further block, every validator reports `local_provider_ready` and `/readyz` is 200. The pulse at the first mandatory height (63) verifies against the session in all four Kura stores.
  - From height 1 on, every validator's signed horizon reports the frozen context's epoch length (64) beside the scheduled pulse; every validator's `--check-config --json` values equal its live `SumeragiStatus` and the signed genesis context.
  - After the stop, `--check-storage` on every validator restores its newest signed snapshot (written by the qualification cadence) and reconciles every retained block hash with Kura; the report is `ok` with a non-null `snapshot_height`.
  - Its genesis is kagami's Taira output re-targeted to the profile (Taira-only catalog content removed, custody account replaced, qual epoch), signed against the flattened profile render. TODO(P2): use the engine's genesis builder.
- Unprivileged start is verified on macOS arm64 and on Linux x86_64 and aarch64, including `production_mode` on macOS.
  - macOS arm64: verified by the same test. The stock `iroha3d` runs four validator-overlay (`production_mode`) profile nodes as a normal user, with every secret in `data_dir/secrets/`. TODO: Linux x86_64 and aarch64 were not run in P1.

**P2. Engine, local driver and S3** (~10k, of which ≈5k is moved).
- Plan and diff with the decision hash; the converge executor; the journal and host records; the once-only reconciler.
- Identity and genesis (moved from kagami); the beacon dealer; the renderers; container mode.
- Verify gates G0–G8 and G11; the local driver and `supervise`.
- CLI `plan`, `apply`, `verify`, `status`, `up` and `down` for local definitions, with `--seed-file`, `--seed-fd`, `--genesis-time` and `[scaling]`.
- `networks/{dev,ci,perf-10k}.toml` and the generated `defaults/docker-compose.yml`.
- Every local-network consumer in §12 is ported onto the new engine while kagami localnet still exists, and the shared genesis fixtures move to profile fixtures.
- Exit criteria:
  - `iroha network up && verify --full && down` passes unprivileged on macOS and Linux (x86_64 and aarch64) and crosses a pulse;
  - the compose job and the SDK harnesses pass on the generated fixture.

**P3. SSH driver, agent, edge and upgrade strategies** (~6k).
- The OpenSSH driver (agent mode, ProxyCommand pinning), the prelude and the agent operations.
- The unit, gateway and edge renderers.
- `reset` and `reset --abort`; the rolling, coordinated (with checkpoint) and remediate strategies; identity move.
- The `[[grant]]` machinery, `--rotate`, G9, G11, watch timers and remote `down`.
- A minimal `cargo xtask release`, signed with the maintainer key.
- An SSH-to-container CI driver that rehearses fresh, rolling, coordinated, remediate and reset on 4 containers.
- Exit: every strategy passes against containers.

**P4. Signed CI release pipeline** (~1.0k).
- `.github/workflows/release.yml`, containing:
  - authenticated source and build checks;
  - optional engine self-test, upgrade and container diagnostic jobs that do not gate signing or deployment;
  - controller builds, including musubi;
  - the Inrou asset job;
  - CI-key signing.
- Exit: a CI-signed bundle drives the container rehearsal and the engine self-test.

**P5. Inrou module** (~3.0k).
- `iroha_deploy::inrou`:
  - host prerequisites, a Rust port of `package_inrou_runtime_v1.py` that the Dockerfile also uses;
  - `SetOwnership`;
  - `StoppedInrouReconcile`;
  - in-memory staging from the per-ISA guest assets;
  - council signing on the host;
  - preseed;
  - pins and the service as once-only writes;
  - G10.
- Exit: on an aarch64 KVM runner, a fresh generation with `[inrou] enabled = true` passes G10, and a rolling toggle off and back on passes as well.

**P6. Dataspace protocol and tooling** (~6.5k: 4k protocol, 2.5k tooling).
- D-1 to D-8, `iroha_deploy::dataspace`, `iroha dataspace plan|apply|status|down` and G12.
- `lane_bootstrap.py` and `.sh` are deleted.
- S2a and S2b are rehearsed locally (owner nodes under the dev supervisor) and against the SSH container harness.
- Exit: S2a and S2b each complete with one command against a staging network.

**P7. Committee rotation** (~2.5k protocol).
- T1: `SetDataspaceCommitteeV1` with the frozen-successor handoff, plus scoped peer unregistration.
- The engine plans committee changes.
- Exit: replace a failed owner node by editing the definition and running `apply`, with no reset.

**P8. Cutover, consumers and docs.**
- Delete everything listed in §12 and port every remaining consumer (§12).
- Rewrite the `AGENTS.md` Taira bullets and `skills/sora-taira-testnet/SKILL.md`.
- Write the iroha-docs operator guide and rewrite the 85 doctor pages and the 22 write-canary pages.
- Update the READMEs, `status.md` and `roadmap.md`.
- Re-point the SDK profile constants and chain-id literals to the card.
- TODOs: `run_release_pipeline.py` consumes the xtask bundle; the Bootle/Lantern broker and `kagami privacy-bootstrap *-taira-v1` become profile-driven.
- Exit: no reference to deleted commands remains in the repository, and the full workspace test suite passes.

**P9. Release and the single Taira restore.**
- A staging rehearsal on remote hosts: fresh generation, rolling upgrade, coordinated upgrade, reset, S2a and S2b.
- `iroha network apply networks/taira.toml --release <release>` creates generation 1 on 4 separate hosts plus the edge, with Inrou on. The retired MacStadium ledger is not touched.
- Commit `networks/taira.card.toml`.
- Re-register the customer dataspaces that used to be baked into genesis (is, dpn, paynet, sbp, cbuae, is2, cbsi) with `iroha dataspace apply dataspaces/<name>.toml`, committee = network. Each owner account gets its `[[grant]]` line first, so no dataspace is ever missing from the released network.
- Exit: Taira is live and all customer dataspaces are registered. `iroha network verify https://taira.sora.org --full` and `iroha dataspace status` pass for each of them.

**Proposed `AGENTS.md` replacement bullets** (land in P8):
- For a disposable local network, use `iroha network up` (unprivileged; add `--inrou` only on Linux with KVM as root), then `verify --full` and `down`.
- For public Taira diagnostics, use `iroha network verify https://taira.sora.org` (read-only with `--read-only`). Deploys use `iroha network apply|reset networks/taira.toml`. Signed writes are journaled as exact wire in-process; never replace them with blind resubmission.
- Keep the controller state dir, SSH keys and onboarding tokens runtime-only and outside the repository.

---

## 14. Before and after

| Measure | Before | After |
|---|---|---|
| S1 first deploy: commands | ~25 native invocations, Python release, transfer and edge scripts, undocumented root bootstrap | `plan` once (pin host keys), then `apply networks/taira.toml --release V` |
| S1 hand-written inputs | ~238-value intent, known_hosts ×5, trusted-key JSON, transfer, capacity and retry plans, roster TOML, token and hash pairing, ~118 flags | One ~50-line file (5 pasted host keys); the SSH key already exists |
| S1 real decisions | ~24, buried among ~238 values | ~12: 5 hosts, release, Inrou, edge domain/TLS/CORS, onboarding ids, webhook, grants |
| Typed hashes | Many | 0 (host keys are pasted from scan output after comparison) |
| S1 wall-clock | 1–3 h per attempt; ~91 h over 32 attempts | ~20–30 min with Inrou off, ~35–45 min with it on; a failed attempt costs a ~5 min rollback, not a rebuild |
| S1 upgrade | Python updater with no beacon awareness (caused 09-15) | 1 command with horizon, lag, compatibility, storage and prefix gates; rolling, coordinated or remediate; ~10–20 min |
| S1 reset | Full prepare chain plus `taira_retry.py` | `reset` plus typing the name; ~20–35 min; automatic restore, health-aware |
| S2a | Never completed; needed the Taira operator key and genesis-only permissions | ~8-line file, 1 command, one `[[grant]]` |
| S2b | Impossible | ~35-line file, 1 command; no Taira action beyond the grant |
| S3 | Root, aarch64 KVM, 4 NSS users, guest assets, branch pin, Python | `iroha network up`; unprivileged; macOS and Linux; deterministic fixtures and container mode |
| Operator verbs | ~40 `taira` leaves, ~20 Python entry points, 7 local launchers | 11 (3 used routinely: `apply`, `verify`, `status`) |
| Tooling lines | ~153k (+16.7k kagami localnet, +3.9k profiles) | ~27k production (≈9k moved) + ~12k tests; node and protocol features ~8k + ~5k tests, counted separately |
| Record schemas | 83 bespoke | 10: definition, dataspace definition, `ReleaseManifestV1`, `OpJournalV1`, `HostRecordV1`, `GenerationMarkerV1`, agent request/response, `NodeCardV1`, `NetworkCardV1`, card anchor |
| Journals and locks | 4 journals, 4 locks | 1 journal per operation plus host records; 1 controller lock plus 1 per-host session lock |
| Taira definitions | 7, disagreeing | 1 profile, 1 definition file, 1 generated anchor |
| Python on hosts | Required | None |

---

## 15. What remains hard, and risks

**Honest limits.**
1. Consensus-digest changes still need a reset in the first release. So do lost validator keys and authority-key rotation. One reset is planned: the P9 restore.
2. The beacon DKG needs every seat: one missing, invalid or late edge aborts the attempt. The genesis session identity is canonical and published frames are never rerolled, so a remote genesis deal that fails after publishing needs a fresh genesis. Pre-dealing depends on the P1 proof test, and a fallback is specified.
3. Owner committees:
   - each needs four full Taira replicas, whose replay grows with chain height;
   - rotation arrives only in P7;
   - "restricted" is not confidential;
   - at most three owner committees fit the `sora-nexus-v1` budget;
   - the multi-lane runtime has open qualification gates (roadmap N12, `specs/sumeragi_lanes.md`), so S2b will surface node bugs.
4. Owner nodes follow Taira's release in lock-step. A coordinated Taira upgrade stalls owner lanes until each owner runs `dataspace apply`.
5. The SSH deploy key, held in an agent, is the only mutation authority. Two-person approval (a signed plan) would be a follow-up.
6. Inrou validators run as root.
7. The CI release key is a supply-chain root.
8. Taira stays down until the whole release is ready, because everything ships together (approved).

**Risks and mitigations.**

| Risk | Mitigation |
|---|---|
| Deleting ~150k lines loses edge-case fixes | Each fix becomes a named test first (§12). Consumers are ported before the cutover, and container rehearsals cover every strategy. |
| An upgrade is misjudged as rolling | The seven-value predicate, canary order, `--check-storage` with the prefix hash, per-node rollback, the CI upgrade job, and coordinated checkpoints. |
| Executor and Core disagree on permissions | Identical matrices on both sides (D-2). |
| Observer floods on public P2P | Accept throttling, per-peer bounded Sumeragi ingress and the connection budget (D-4), and T8. |
| Beacon install race | Pre-signed certificates for a range of heights, submitted before the edge exists. Install happens once. |
| Trust in the card | Genesis plus 2f+1 attestations, the committed signed anchor, and the `network_id` pin. |
| Two operators with different state dirs | Per-host session locks, the decision hash, and `in_progress` host records. |
| The cutover is large | P3 rehearses every strategy against containers, and P9 rehearses the complete release on staging hosts before it touches Taira. |
| The Taira outage continues until the release | Approved trade-off for a single release and a single reset. |
| Docs churn | `AGENTS.md`, `SKILL.md` and iroha-docs change together in P8. |

---

## 16. Open questions

1. Should a published snapshot bootstrap for joiners (owner nodes, observers) become a follow-up protocol change, given that replay grows with chain height?
2. Should release-signer revocation later bind to the not-yet-admitted SoraFS release-manifest authority (`crates/iroha_data_model/src/sorafs/release_manifest_authority.rs`)?
3. Should Inrou ever be supported for owner lane validators? That would need Soracloud placement beyond global validators.
4. What should the long-term value of `max_external_committee_peers` be? It is 12 here, and it trades validator connection slots against the number of owner committees.
