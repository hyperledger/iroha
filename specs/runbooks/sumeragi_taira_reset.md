# Sumeragi Taira reset runbook

Operator obligations of Sumeragi for a Taira reset: a fresh genesis with the current consensus
parameters, the validators' consensus keys and their safety-record provenance
(`specs/sumeragi.md` §7.4), key rotation (§7.4 **Keys**, §10.4) and governance-owned deployment
policy (§13.5, §14 item 5; goal S7 in `specs/sumeragi_goals.md`).

The public reset itself — inventory, authorization, release artifacts, onboarding and write
canaries — is owned by the same-revision `iroha taira public-reset preflight` and
`iroha taira public-reset apply` workflow (`skills/sora-taira-testnet/SKILL.md`). This runbook
states what that reset must satisfy for consensus; it does not replace it.

The compiled public-reset/build/transfer corridor described here currently requires the
MacStadium Dublin AArch64 Linux guest and its independently admitted native Mac edge. It does
not support an OVH x86_64 target. Reconcile the actual serving deployment and operator's
retained completion records before selecting this corridor or proposing a new reset; an
already completed reset is not a reason to execute these commands again. A different host or
architecture requires its own reviewed operator authority and supported current workflow,
not changed provider labels, target hashes or copied signatures.

## 1. Deployment policy and optional fault diagnostics

On-chain governance owns deployment policy for Taira and production (§13.5). There is no
mandatory regression suite, 24-hour fault test, fixed soak duration or soak-verdict prerequisite
for a reset or deployment.
The native reset still enforces signed control authority, authenticated genesis and committee,
safety-record provenance and custody, and reports actual service readiness. Write, restart,
pulse-crossing and epoch-boundary exercises are optional diagnostics, never reset or deployment
prerequisites.

Operators may run multi-process fault diagnostics with P2P loss/delay, crashes, restarts and
disk exhaustion. Section 8 describes the optional harness and its O-AGR, O-SIGN, O-LIVE and
O-PERF verdicts; those diagnostics do not authorize or block a cutover.

## 2. Committee

- The global committee is exactly `3f + 1` validators with `1 <= f <= 10` (4, 7, …, 31); genesis
  rejects any other size. Every certificate carries exactly `q = n - f = 2f + 1` votes.
- Each validator has one consensus key: a BLS-normal key pair with a proof of possession. The
  node signs with the key pair of its configuration (top-level `public_key` / `private_key`),
  which is also its P2P peer identity.
- Keys that no longer sign but whose records must stay are listed in `[sumeragi] retired_keys`
  (§6).

## 3. Consensus keys: generated on the validator host

Generate each validator's key on its own host, into an owner-only directory, and never copy the
private key anywhere else:

```bash
kagami keys --algorithm bls_normal --pop --out-dir /var/lib/taira/<role>/consensus-key
# writes public.key, private.key (never printed) and pop.hex into a new owner-only directory
```

Only `public.key` and `pop.hex` leave the host (they go into the genesis topology). Put the key
pair into the validator's configuration (`public_key`, `private_key`).

Provenance note (current truth): the installation log records whether a key was generated on
the node or imported, and a key generated on the node gets its initial records automatically.
No operator command registers a key as generated on the node in this release (the store
function `iroha_core::sumeragi::records::register_generated_key` has no caller), so every key
generated with `kagami keys` counts as **imported** and a fresh chain needs the explicit
fresh-key assertion of §5.

## 4. Fresh genesis

Chain parameters come from genesis and committed state only; every validator uses the same
ones. For the fresh Phase A public reset, use the authenticated same-revision Kagami on the
approved Linux guest through the maintained native invocation transport:

```sh
kagami localnet --peers 4 \
  --chain-id fc56984b-2be7-431d-840e-21514d1883f0 \
  --chain-discriminant 369 --sora-profile nexus --consensus-mode npos \
  --bind-host 127.0.0.1 --public-host 127.0.0.1 \
  --base-api-port 8080 --base-p2p-port 1337 \
  --out-dir /private/runtime/taira-public-reset/REVIEWED_FRESH_RUN/network
```

This command generates private keys and signs genesis; run it only with the reset owner's
authorization. Select a fresh owner-private run directory, omit `--seed` and sample/application
asset options, and keep its private output on that guest. It does not start validators. The
generator constructs the current bootstrap, exact BLS topology/PoPs and lane policy, executes
genesis under the staged configuration, and publishes `genesis.json`, `genesis.signed.nrt`,
the checked identity files and `nexus-amx-context.v1.bin`. Validators select the published
identity with `genesis.expected_hash_file`.

Review the complete catalog before authorization: lanes 0–2 are universal/Public; lane 3 is
dpn/Restricted, 4 is is2/Restricted, 5 is bpng/Public, 6 is cbsi/Restricted and 7 is
is/Restricted. Participant dataspace identities come from the full canonical SNS alias hashes;
BPNG is `8648377547929788715`. BPNG routes by its target dataspace. The four restricted
participants retain their explicit account routes and Parliament manifests. No autoscale
range may consume a participant lane.

Do not substitute `configs/soranexus/taira/genesis.template.json` or old signed captures for
this generated bundle. The retained template has separate privacy-bootstrap consumers and
contains old application assets; it is not the Phase A reset input. A separately selected
privacy/NEVO release needs its own reviewed current template and authority before use. Preserve
the Phase A restricted-home asset guard: create no assets in restricted participant dataspaces.
Register fresh BPNG application assets later through their actual owner and retain the resulting
IDs and finality; neither this runbook nor a past chain supplies those IDs.

Use `iroha taira public-reset prepare-public-inputs` to export the six public artifacts,
including the exact context preimage, then the maintained configuration, unit, inventory and
authorization commands in `docs/source/taira_release.md`. The public export authenticates
the generated bytes; installed-release, reset and current-state admission remain separate.

The Sumeragi chain parameters (`SumeragiParameters` in the data model, defaults of §9.3) are:
`block_cadence_ms` 1000 (the target block time, frozen at genesis), `payload_retry_interval_ms`
5000 (never below the cadence), `exec_budget_ms` (`E_max`) 4000, `apply_budget_ms` (`A_max`)
1000, `max_block_bytes` 4 MiB, `epoch_length_blocks` 3600 and `demotion_window` 128 (a genesis
constant, at least `4n`). The node-local `[sumeragi]` overrides (`view_timeout_base_ms`,
`view_timeout_max_ms`, `start_level_cap`, `start_level_decay_after`, `rebroadcast_interval_ms`,
`status_keepalive_ms`, `build_timeout_ms`, `fetch_retry_ms`, `sync_batch`, `sync_retry_ms`,
`sync_max_bytes`, `max_observers`) stay unset: the node derives the §9.3 defaults for the
committee size and validates the set against the chain parameters at startup (§9.4). Idle
chains create no blocks; there is no empty-block setting.

Check a validator's configuration and the published genesis without starting the node:
`iroha3d --config <config> --check-config` (add `--sora` for Taira).

## 5. First boot: installation log, store id, initial records

Every validator's files (paths are `[sumeragi]` keys; the defaults are siblings of
`[kura] store_dir`):

| Path | Contents | Backup |
|---|---|---|
| `records_dir` (default `<store dir>-sumeragi-records`) | one safety record per `(instance, key)`: `<instance hex>/<H(key) hex>.record`, and the random 128-bit store id in `store_id` | **never** backed up, restored, copied or moved with a key |
| `installation_log` (default `<store dir>-sumeragi-installation.log`, outside `records_dir`) | append-only: one entry per key (generated or imported) and per `(instance, key)` ever started, each with a fresh store id | with the key store |
| `[kura] store_dir` and its sibling `<store dir>-sumeragi-bodies` | committed blocks with their CommitQCs; bodies of accepted, unapplied blocks | optional |

At every start the node first compares `records_dir/store_id` with the store id of the log's
newest entry. If they differ, or one is missing while the log has entries, the log does not
describe these record files, and the node durably marks every key as imported (§7.4 rule 3).
Then, for each `(instance, key)` the log does not list yet, the installation event appends the
entry and — only for a generated key or under the operator's assertion — first writes the
initial record `{instance, key, height: genesis}`. It never replaces an existing record file.
Once the entry exists, a missing record is `Absent` and never re-created.

On the reset's first boot of the new chain, start every validator exactly once with the
assertion that its key never signed for this chain:

```bash
iroha3d --config <config> --sumeragi-assert-fresh-key      # Taira: iroha3d_taira --config <config> --sora --sumeragi-assert-fresh-key
```

The node logs the warning `operator asserts that the node's consensus keys never signed for this
instance` when it applies the assertion. The flag is a one-shot command-line argument, never a
configuration key: every later start omits it, and it is never passed after a data loss (a
restored or lost record store must anchor through probes, §7.4 R2). Lane instances need no
assertion: a node whose installation log lists the global instance for its key writes the
initial record of every new lane incarnation itself.

A first boot without the assertion writes the `(instance, key)` entry without a record: the key
stays unanchored, and when no validator of a fresh chain holds a record, none answers probes and
the chain never commits. The only recovery before any block commits is to stop every
validator, delete its `records_dir` and `installation_log` (nothing was signed) and repeat the
first boot with the assertion.

`kagami localnet` start scripts pass the assertion only when a peer's
`state/peer<i>/sumeragi-records` directory does not exist yet. That inference is for disposable
networks only: a production launcher must not derive the assertion from a missing directory,
because a lost record store looks the same.

### Taira validator units: the first-boot step

Every Taira validator unit rendered by `scripts/taira_validator_unit.py` (embedded in
`iroha taira public-reset prepare-validator-units`; initial and beacon units alike) starts
`iroha3d_taira --config … --sora` and adds `--sumeragi-assert-fresh-key` only when its launcher
consumes the one-shot token `/var/lib/taira/<role>/sumeragi-first-boot`.
`iroha taira public-reset apply` creates and syncs this empty root-owned, mode-0600 token
with the fresh state's authorization markers during `Reset`. It refuses to arm over native
record, installation-log or body-store history, or after any complete or partial durable
`Start` manager intent. A retry can finish token publication before Start; it never recreates
a consumed token after Start may have run.

For independently authorized manual provisioning, the equivalent host steps are:

1. Stop the validator and put the reset's fresh state root `/var/lib/taira/<role>` in place
   (owned by root, writable by nobody else).
2. As root on the validator host, arm the first boot with the deployed revision's script (the
   bytes its signed source manifest binds and `prepare-validator-units` embeds):
   `python3 scripts/taira_validator_unit.py --arm-first-boot --role <role>`. It refuses unless the
   state root is as in step 1 and neither the configured `records_dir`
   (`/var/lib/taira/<role>/sumeragi-records`) nor `installation_log`
   (`/var/lib/taira/<role>/sumeragi-installation.log`) exists. It never replaces a token; it
   creates an empty, root-owned, mode-0600 token and syncs it with its directory.
3. Start the unit: `systemctl start iroha3d-<role>.service`.

At every start the launcher looks for the token before it stages any signer descriptor:

- Without a token it starts the daemon without the flag: every restart, `Restart=on-failure`,
  reboot and daemon update. Missing history never authorizes the assertion, so losing
  `records_dir` and the installation log never renews it.
- With a token it requires a regular, root-owned, mode-0600, single-link, empty file in a
  root-owned state root that nobody else can write, and the absence of both history paths.
  Otherwise it refuses to start and keeps the token, and every `Restart=on-failure` retry refuses
  again until an operator investigates and removes the token.
- After staging it checks the token again, removes it, syncs the state root and only then execs
  `iroha3d_taira --config … --sora --sumeragi-assert-fresh-key`. If the exec itself fails, it
  restores the token for the next start. A daemon that exits before it writes its installation
  log has consumed the token all the same: its next start (an automatic
  `Restart=on-failure` retry included) writes the
  `(instance, key)` entry without a record, as a first boot without the assertion does (see
  above for the recovery).

The public-reset host validates the original token before preparing the first Start, and
recovery resumes only its durable manager operation. Daemon attestation requires the token
to be consumed and binds an optional exact `--sumeragi-assert-fresh-key` suffix to that
authorization's initial process; a prepared beacon transition or restart ends that allowance. A subsequent reset
can admit the suffix in its signed predecessor argv. Rollback starts the retained predecessor
without reasserting freshness and verifies that change against its own durable start evidence.
The exact reset/quarantine closure admits only the token and its bounded publication slot,
the `sumeragi-records` and `storage-sumeragi-bodies` directories and the
`sumeragi-installation.log` regular file beside the existing generated entries. Each native
entry must have root custody, the expected type and non-writable group/other modes; token
and log files must have one link. Token slots cannot coexist with native history. These
checks authorize quarantine of the fresh root, not restoration or trust of safety history.

After native beacon activation, the signed predecessor closure names
`<selected-release>/config/beacon.toml` and the exact matching
`<service>/current/config/beacon.toml` argv. Initial predecessors use `config.toml` in
those same positions. Runtime capture preserves that choice from the installed launcher,
resolves the native daemon selector against the selected release, and hashes the actual
configuration. Dispatcher transition and reset admission require the same selected-release
path, source identity and signed bytes; neither substitutes the initial configuration for an
active beacon provider nor admits an arbitrary configuration filename.

## 6. Backups, restores and retired records

- Back up the configuration, the consensus key pair and the installation log together (the
  key store). Optionally back up the Kura store.
- Never back up, restore or copy `records_dir` (record files and `store_id`). A rolled-back
  record would let a key sign again below its real history (§7.4 rule 1).
- Restoring a key store from a backup is safe: when the restored installation log is older than
  the record store, its newest store id no longer matches `records_dir/store_id` and the node
  marks every key imported. Missing records are then `Absent`; the key probes (§6.11) and anchors
  after `2f + 1` fresh replies of the next height's committee, abstaining through `t' + 2`.
  Never pass `--sumeragi-assert-fresh-key` after a restore.
- A restored or older Kura store is safe as well: a record ahead of the block store makes the key
  abstain and the node sync (§7.4 R5, R6).
- Retired keys are kept for good: once a key is listed in `[sumeragi] retired_keys` it stays
  there, and its record files and log entries are never deleted. A dropped record would be
  `Absent` at every later restart and leave the node unable to answer probes (§7.4 **Keys**).

## 7. Key rotation at a single height

A validator's old key is replaced by its new key at one height; a committee never contains both
keys of one validator (two configured keys in one committee make the node sign with neither,
`LocalFault(KeyConflict)`).

1. Generate the new key on the validator host (§3).
2. Register the new key with its proof of possession
   (`iroha ledger peer register --key <public key> --pop <hex>`, with the required
   `--fee-payer`). Registering never changes voting membership.
3. The committee changes only at an epoch boundary `B`, through the authenticated successor
   context certified by the current quorum (§10.2–§10.4): from `B + 1` the committee lists the
   new key in the validator's seat instead of the old one.
4. On the node, switch keys at the boundary: configure the new key pair (`public_key`,
   `private_key`), add the old public key to `[sumeragi] retired_keys` and restart without
   `--sumeragi-assert-fresh-key`. The node signs with the old key only while it is configured,
   so heights between the restart and `B + 1` (or after `B + 1` until the restart) count as a
   crashed member; keep that gap short. The new key has no record for the instance and anchors
   through probes (§7.4 R2).
5. Keep the old key in `retired_keys` for good (§6).

## 8. Optional fault diagnostics: running and reading the verdict

`scripts/sumeragi_soak.py` runs a real multi-process `kagami localnet`, offers a steady `Log`
transaction load through the CLI, injects faults and judges the run only from the nodes' logs.
Each peer logs JSON with the audit filter `iroha_core::sumeragi::driver::audit=debug`: the
executor worker logs `sumeragi block applied` for every applied block of every instance and the
persistence worker logs `sumeragi record durable` for every durable safety record
(`crates/iroha_core/src/sumeragi/driver/audit.rs`). The soak exports `LOG_FORMAT`, `LOG_LEVEL`
and `LOG_FILTER` with the same values to the start script, because a node's environment
overrides its configuration file. It also changes only node-local settings, never anything the
signed genesis execution policy covers (fees, for example): an explicit
`[nexus.storage] local_budget_bytes` (`--storage-budget-mb`, below `--disk-size-mb`; without it a
node on a nearly full disk derives no budget and refuses to start; Kura gets a quarter of it and
keeps about 1 KiB per committed transaction, so the long profile's 12 GiB hold a day at its 20
transactions per second, and a Kura over its share stops applying blocks), and
`[sccp.light_client_keeper] enabled = false` (the keeper polls public Ethereum RPC endpoints by
default).

For an optional long diagnostic, build release binaries once and select either committee size
(the profiles' O-PERF
thresholds assume release binaries; a debug build on a busy host misses the gap and latency
thresholds even without faults). The profile named `gate` selects diagnostic defaults; it
does not authorize or block a Taira or production cutover:

```bash
cargo build --release -p irohad --bin iroha3d -p iroha_kagami --bin kagami -p iroha_cli --bin iroha
python3 scripts/sumeragi_soak.py --profile gate --validators 4  --seed 1 --bin-dir target/release --out artifacts/sumeragi-soak/gate-n4
python3 scripts/sumeragi_soak.py --profile gate --validators 22 --seed 1 --bin-dir target/release --out artifacts/sumeragi-soak/gate-n22
```

- Faults (`--faults kill,disk,net`): `kill -9` of up to `--max-kill` validators (at most `f`) and a
  restart through the start script; disk full on one peer (`--disk-node`, default the last),
  whose Kura store, bodies, records and installation log live on a size-limited volume that
  the fault fills until `ENOSPC`; P2P loss drawn from `--loss` (default 10–30 %) with delay
  spikes. Windows never overlap and are separated by fault-free gaps.
- Network faults: on Linux (`--net-mode netem`, the default there) the soak re-executes itself
  in `unshare --user --map-root-user --net --mount` and applies `tc netem` to the loopback P2P
  ports only (needs the `sch_netem` module and unprivileged user namespaces); the disk volume is
  a size-limited `tmpfs`, which holds the disk peer's state in memory and fills
  `--disk-size-mb` of it during a disk fault. On macOS (`--net-mode proxy`) a userspace TCP proxy sits in front of
  every P2P port: it delays every chunk, turns loss into retransmission delays and resets
  connections with a small probability, and the disk volume is an `hdiutil` HFS+ image. The
  module documentation of `scripts/sumeragi_soak_faults.py` lists the differences.
- `--seed` makes the fault plan and link noise reproducible; the run directory keeps
  `run.json` (options, plan), `timeline.json` (fault windows, process lifetimes), `load.json`,
  every boot's log under `logs/peer<i>/boot<k>.log` and `verdict.json`.
- `python3 scripts/sumeragi_soak.py --analyze <run dir>` recomputes the verdict from the logs.
- Load: the CLI's `ping` (`Log`) transactions at `--load-tps`, paid by the generated client
  account. Before the load starts, the genesis account (which registered the fee asset in
  genesis) mints `--fund` of the fee asset to that account (default 1,000,000): its genesis
  allocation of 10 lasts minutes at the default fee schedule (about 0.002 per transaction), and
  zero fees are not an option because the fee schedule is part of the signed execution policy.
- A peer that exits while the network starts, or by itself later, is started again; every such
  exit stays in the timeline and fails O-LIVE (`unexpected-exit`, with the boot's log under
  `logs/`).

The exit status is 0 only when every oracle holds, 1 on a violation and 2 when the harness
failed. `verdict.json` has `ok`, one entry per oracle with its `violations` and what it
`checked`, `harness` problems (unparsed audit lines, a node without applied or durable-record
lines — a blind oracle fails the run) and per-node observations (local faults, evidence,
persistence retries, panics):

- **O-AGR**: every `(instance, height)` has one `(block, result)` on every node and across
  restarts; within a process lifetime heights are contiguous, and across a restart at most the
  one height applied but not yet logged when the process died is missing.
- **O-SIGN**: per key, no two different proposals, Prepares, locks or timeouts at one
  `(instance, height, view)`; no new Prepare at or below a timeout view the key already made
  durable; no new timeout carrying a PrepareQC below a durable lock; no durable record that goes
  backwards (a rollback). A Commit vote is durable only as the record's lock, which a node also
  adopts from certificates it did not vote for, so "no Commit at or below a timeout view" is
  judged by the simulator's O-SIGN, not from logs.
- **O-LIVE**: after every heal, each node commits a new height of the global chain within the
  bound and again within every later window of the bound until the next fault; no node exits
  unless it was killed or its disk was full. The gate uses `B_live` of §8.2 for the committee
  size (about 12 minutes at `n = 4`, 16 at `n = 22`, at most 18 for 31 validators, with one sync
  batch of lag); `--live-bound` sets a stricter bound. Only a fault-free interval at least as long
  as the bound can show a stall, so the final one (`--final-quiet`, 20 minutes for the gate) must
  be: the soak refuses shorter settings, and a run without such an interval fails as a harness
  problem (`no-interval-judged-by-o-live`). Stalls inside the shorter gaps between faults fail
  O-PERF's largest-gap threshold instead.
- **O-PERF**: in fault-free intervals, after `--warmup-heights` commits (Appendix E8), the p99 and
  the largest commit gap, the p99 of client-observed commit latency and the committed
  transactions per second against `--max-gap-p99-ms`, `--max-gap-ms`,
  `--max-latency-p99-ms` and `--min-tps`.

The P2P lane soak (`integration_tests/tests/sumeragi_lanes_soak.rs`, ignored by default) runs
four validators with a fixed and an elastic lane under sustained load and restarts; the nightly
workflow `.github/workflows/nightly_sumeragi_soak.yml` runs a smoke-length diagnostic and the
lane soak, with an optional longer diagnostic on manual dispatch. These runs are engineering
evidence, not deployment gates.
