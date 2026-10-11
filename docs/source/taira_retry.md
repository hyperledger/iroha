# Retry a rolled-back Taira deployment

`scripts/taira_retry.py` retries a completely rolled-back, initially vacant
four-validator deployment using its existing immutable build and transfer
receipts. It creates a fresh deployment identity and authorization nonce, retires
the completed attempt's custody, and runs native assemble, authorize, preflight,
and apply. It then verifies signer continuity and boot persistence. It does not
build or transfer unchanged binaries or source.

For a changed release, freeze the source once and run `scripts/taira_release.py
prepare` with the existing warm Cargo lane. Preparation builds the signed source
and captures the release artifacts without running regression tests. It records
`native_check_scope: "build-only"` and `checks.passed: false`; optional Basic,
Full and focused diagnostics use the standalone `check` command. Regression
success is not a deployment prerequisite. Keep each lane's Cargo home, profile
and source location consistent so subsequent builds reuse its artifacts.

Preparation retains exact source, tool, environment and artifact identities.
Only an immutable completed capture can reuse a successful build; partial
attempts remain retained while Cargo reuses its warm cache. No pre-network or
independent-test checkpoint is produced. Completed preparation does not establish
deployment readiness: signed native authorization, preflight, canary, finality,
readiness and restart checks still run during deployment.

Retirement joins the coordinator and host-action locks, then the shared
`/var/lib/taira-deployment/.deployment.lock`. The root-owned mode0600 lock must
already exist under a mode0700 root. A held or missing lock, retained
`.reset-owner.json`, or retired epoch-worker state or service stops retirement
without creating or removing authority. Locks remain held through rechecks,
control archival and public artifact cleanup so reset or updater work cannot
interleave after rollback.

After an operator has prepared one owner-only runtime plan, each retry is:

```sh
python3 scripts/taira_retry.py \
  --plan /private/runtime/taira-retry/operator-plan.json \
  --output-root /private/runtime/taira-retry/local-evidence
```

The plan must be an owner-only regular JSON file. The existing output directory
must be owned by the caller with mode `0700`. The command creates a new evidence
directory for each invocation and reports the current phase and elapsed time
every 30 seconds. Native failures report an operation and errno when available;
arbitrary stderr stays in the private log path.
Remote SSH commands also report their phase and private evidence directory when
submitted. A nonzero SSH exit reports its code and directory without relaying
the remote stdout or stderr, and never triggers an automatic replay.

The approved guest must provide executable `/usr/bin/curl`; both guest entry
points check this prerequisite before deployment work or output creation.

## Operator plan

The plan schema is `taira.same-artifact-retry.v1`. All values describe public
identities, paths and receipt pins. Never put signing keys, peer TOML contents,
passwords, tokens or request headers in the plan.

| Field | Value |
| --- | --- |
| `schema` | `taira.same-artifact-retry.v1` |
| `preparation` | `{ "path": "/absolute/local/result.json", "sha256": "actual raw receipt SHA-256" }` from a successful maintained `taira_release.py prepare` |
| `binary_transfer` | Same reference shape, pointing at the actual completed binary transfer JSON |
| `source_transfer` | Same reference shape, pointing at the actual completed signed source transfer JSON |
| `guest_ssh`, `backing_ssh` | `{ "argv": ["/usr/bin/ssh", "...", "/usr/bin/python3 -I -"], "pins": [{ "path": "/absolute/public/known_hosts", "sha256": "actual SHA-256" }] }` |
| `backing_path` | The approved backing host's absolute directory containing the VM sparse disk |
| `guest` | The runtime fields below, using absolute paths on the approved guest |

Each SSH invocation must use `-F /dev/null`, an explicit `-i` path, strict host-key
checking, batch mode, an explicit public `UserKnownHostsFile`, no global host-key
file, no agent forwarding, no host-key updates and no DNS host-key lookup. The
outer connection also requires `IdentityAgent=none`. A jump route may contain
one fixed `/usr/bin/ssh ... -W destination:22` proxy. The pin list must match
exactly the public host-key files used by those hops. Arbitrary shell proxies,
ambient SSH configuration, extra pins and duplicate options are rejected.

The `guest` object contains exactly these fields:

- Paths: `runtime_root`, `previous_inventory`, `source_manifest`,
  `trusted_public_key`, `signing_key`, `ssh_identity`.
- Public helper references `{ "path": "...", "sha256": "..." }`:
  `guard_support`, `unit_renderer`, `local_node`. These refer to the existing
  admitted owner-guard, service-unit renderer and native Inrou controller helpers.
- `expected_mac`: the actual approved guest's lowercase colon-delimited MAC.
- `retired_public_imports`: an explicit list, empty when no older imports are
  superseded, with at most four entries. Each entry names `inventory`,
  `retirement`, `binary_manifest` and `source_manifest` using the public
  `{ "path": "...", "sha256": "..." }` reference shape, plus `source_pack`
  pointing to that source manifest's sibling `source.pack`.

Use the preceding native assembly's actual inventory and the imported source's
actual `verified-manifest.json` path. The command derives the retry directory,
binary manifest, native local arguments, original preparation directory and
native known-hosts path from these receipts. It locates the actual native terminal
by deployment identity. Runtime paths, topology, initial state, source identity,
artifact identity and endpoint guard pins remain exact. Native assemble derives
and validates every new inventory field; cloning JSON alone never admits an
attempt. No per-attempt directory names, nonces or capacity figures need editing.

Each of the four ordered `validator_clients` requires an explicit public
`probe_origin`, for example `http://127.0.0.1:18081/`. Use four distinct actual
Torii ports on the approved cohosted validator machine. Native assembly joins
each origin to its signed validator config; the retry producer rejects missing
or ambiguous origins before retirement. Configs bind validator slots 1–4 to
the dedicated Inrou UID/GID pairs 70000–70003 only for `full_inrou`. Candidate
`core_testnet` configs require Inrou disabled. Native stopped-owner recovery still
admits and cleans any enabled prior runtime before replacing its state. Old inventories and journals do
not gain a compatibility path: prepare the current first-release inventory and
use a fresh attempt for the current execution plan.

The inventory also requires a canonical Ed25519 `operator_public_key`, and the
retained native input list requires `--validator-operator-key PATH` before
`--validator-unit`. This path identifies the same dedicated owner-private
operator key admitted with all four validator configs. The native
`iroha taira public-reset operator-keygen --private-key-file PATH` command creates
a fresh key outside repositories and prints only its public identity and path;
`config-rebase --operator-public-key PUBLIC_KEY` installs that identity while
rebasing retained validator configs. Retry keeps the key unchanged and rejects
missing or noncanonical public identity before retirement. Native assembly and
child descriptor custody verify the actual credential; Python reads no key bytes.

Native apply runs the prepared application canary and real four-validator DKG
ceremony before readiness-dependent four-peer convergence. The committed
certificate is installed, then all four `BeaconActivate` actions install the
matching provider custody before restart proof. Scheduling epochs retain the
incumbent authenticated authority generation. `core_testnet` qualifies prepared
application mutations and one validator restart. `full_inrou` also requires
Inrou runtime health and four ordered restart waves through direct endpoints
before staging or switching the public edge. The same retained mutation and
restart evidence flows into the release proof. After cutover, `EdgeVerify`
proves public HTTPS, discovery and doctor checks. Candidate failures remain
before public cutover; failed rollback remains resumable and must be verified
complete before another attempt.

The preceding assembly's `native-local-args.json` is a closed, ordered path
list: `--public-inputs`, `--runtime-client-config`, four
`--validator-client-config` paths, `--validator-operator-key`,
`--onboarding-token`, optional `--inrou-stage-dir` for full scope, four
`--validator-unit` paths, `--native-edge-capability`, and `--known-hosts`. The public bundle
remains `<prep>/public-inputs`. Retired epoch worker plans, administrator flags,
and separate seed batches are rejected. Validator signer custody stays protected
through retry and public-import cleanup.

Each attempt projects the closed topology intent, derives the native public
genesis bundle, and prepares beacon inputs. It checks the nonce and exact seat
census, then renders the four final FD200 units from the pinned initial units.
Native `assemble` and `authorize` consume the same derived arguments and verify
all context and credential bindings before signing.

1. Project `topology-intent.json` using only the closed native
   `iroha.taira.public-reset.topology-intent.v1` fields. It contains no computed
   release, artifact or config hashes, fingerprints, or generated beacon plan.
2. Run `prepare-public-inputs --localnet-dir <prep>/network --intent
   <attempt>/assembly/topology-intent.json --output-dir
   <attempt>/assembly/public-inputs`.
3. Run `prepare-beacon-inputs --intent ... --public-inputs ... --output ...`.
   Check its nonce and four-seat census, then use the pinned renderer and
   separately authenticated retained unit hashes to produce four mode0644
   FD200 units selecting `beacon.toml`.
4. Run `assemble --intent ...`, then `authorize` with identical current assembly
   arguments. Native assembly rederives the context, beacon plan and credential
   joins before signing authority is opened.

`native-retained-args.json` preserves the prior path record;
`native-local-args.json` preserves original preparation paths. The separate
`native-assembly-args.json` selects the fresh public bundle, beacon request and
four final units. Apply receives actual runtime paths without generated-plan,
public-bundle or unit flags. Python reads public intent and unit bytes; native
code owns credential and signer custody admission. Missing current inputs or
failed preparation stops before authorization or apply. The shared deployment
lock and durable reset owner prevent updates between reset calls. Existing
retired worker state or service files require reconciliation before retirement.

After apply, signer continuity and boot checks first require the exact native
completed and deployment-proven receipts. They bind each owner-only beacon
activation record to that authorization, nonce/session, common bundle and signed
final unit. Only the native-derived config hash and `beacon.toml` process binding
replace the initial config binding; signer metadata and native identity fingerprints
remain checked. An activation marker alone cannot authorize success. Preapply
resumption preserves the attempt nonce, archives its incomplete preparation, and
regenerates those public outputs. Completed apply resumes only postconditions. `core_testnet` forbids `--inrou-stage-dir` and requires explicit `null` for
both `inrou_canary` and `inrou_stage_tree_sha256`. `full_inrou` requires the stage
argument and the complete matching native stage object and hash. The old `inrou`
spelling is rejected.

The signed scope also selects the native journal sequence: core has 14 steps and
no Preseed step; full has 15. The durable Seal cursor is 12 for core and 13 for
full. Reopening and completed-receipt checks use the same immutable scope;
indices from another scope cannot be reused as recovery authority.

Read-only admission measures the complete native artifact closure, including
same-release Kagami and all four validator unit files. Core computes `3A + 2 GiB guest headroom` and does not open,
walk or measure an Inrou stage, SF1 manifest, guest image or runtime directory.
Each config is charged at the native 1 MiB materialization limit. Both scopes
also charge the full additional guest allocation on the physical backing host,
plus a separate 2 GiB reserve.

Full additionally reads the small public container/service manifests and bounded
bundle archive metadata, never peer config contents. Its three tiny SoraFS
manifest hashes must match native SF1 admission before using the 64 KiB chunk
bound. The shared `derive_capacity` calculates `3A + 2S + 4P + 4R`, plus guest
headroom. `R` includes each replica's guest hydration, writable root/data lease
maxima, ephemeral storage and bundle cache/block/extraction publication copies.
Unknown layouts or additional service artifacts fail closed. See
[`taira_disk_capacity.md`](taira_disk_capacity.md) for allocation definitions.

Retirement first admits one dispatcher copy and up to 64 MiB of publication
and cleanup records, plus the existing guest and backing reserves. After the
native rolled-back terminal and retired custody are verified under their locks,
it prunes the exact disposable executable copies. Only a `full_inrou` attempt
also prunes guest-image copies, including the three public payloads in the
archived physical host's `inrou-stage-v1/<nonce>`, and chunks of its three admitted
public SoraFS manifests. Core neither reads nor deletes these unrelated Inrou
paths. Runtime keys and configs, unrelated
manifests, storage metadata and native history remain intact. Unadmitted partial
ingestion data is preserved. An owner-only intent makes interrupted unlink and
trim operations resumable.

The same retirement owner also removes explicitly superseded public imports.
Their completed native retirement and transfer receipts must agree on the old
inventory, signed source tree and canonical binaries. Current candidate and
replay inputs remain protected. Source removal admits the complete tracked path
set and import-created Git metadata, checks process and mount references, and
uses a durable quarantine intent so interrupted deletion can resume. Canonical
binary and transport-pack removal requires exact file custody. Import manifests,
source closure records, native authority and terminal receipts are retained;
release-number patterns never select deletion targets.

After pruning, native `sync -f` flushes the runtime filesystem before `fstrim`
requests discard of freed blocks. Each command has a 60-second timeout. Both
operations repeat on resume, and either failure stops the attempt. Fresh guest
and physical backing observations must admit the full next-deployment peak
before assembly or apply. Retirement
admission cannot authorize deployment. The command checks the guest again before
assembly, authorization and apply; it neither reserves space nor credits
anticipated cleanup. During native apply,
the 30-second heartbeat includes only the current native phase, step, touched
validator count and edge flag. It never prints journal nonces or failure text,
and progress reporting does not hash artifacts.

## Interrupted attempts

The remote `attempts_root/latest.json` tracks the attempt automatically. Repeating
the command after a failure before native apply resumes that same attempt and
nonce. Existing preapply evidence is retained before assemble and authorize run
again. Completed retirement is reattested under the same custody locks.
Native rollback failure history remains after a successful resume. Retirement
requires the exact rolled-back terminal and completed host counters; historical
failure entries do not turn a completed recovery into an unfinished rollback.

An exclusive, durable `apply-started.json` is published before native apply is
spawned. Once it exists, the command requires that exact attempt's real native
rolled-back terminal before allocating another attempt. A process exit, a helper
failure file or an absent current journal never proves rollback. The command
never automatically resubmits a possibly mutating apply.

If native apply completed but a later check failed, repeating the same command
resumes only signer verification, boot persistence and public validation. This path
requires the exact native `completed` and `deployment-proven` records, the same
inventory and authorization, and the original native preflight report bound to
the durable apply marker. Wrapper status or an apply exit code cannot grant it.
It holds the native coordinator lock, keeps the original nonce and prestart
record, and archives incomplete observations before repeating postconditions.
It performs no retirement, assembly, authorization or apply.

The `signer-pre` phase binds the four genesis topology peers to distinct retained
FD198 runtime signer files using owner, mode, size and inode metadata, without
reading key bytes. The `signer-post` phase rechecks that custody against the
completed beacon deployment and records `signer-continuity/signer-authority-receipt.json`.

Signer verification uses `taira_signer_observation.py` to read the public committed
height and request a fresh challenge-bound finality attestation. The attestation
supplies the applied status; the check needs no operator credentials. The observer
requires the producer's canonical 64-character uppercase hexadecimal JSON challenge
string, and its test fixture uses that same wire format. It retains
process, executable, listener and configuration identity checks. Only native
`sha256sum` consumes the held configuration descriptor; Python never reads the
private TOML. Transient startup responses have three attempts within a shared
30-second deadline, while invalid identities and successful malformed responses
fail immediately.

Boot persistence repairs an enabled nginx link to `/usr/lib/systemd/system/nginx.service`
by running `systemctl reenable /etc/systemd/system/nginx.service` against the
authenticated installed fragment. It records intent before the repair, requires
the canonical link afterward, and verifies unchanged live processes and fragments;
it does not restart services.

Because the deployment's files already exist, the completed route admits only
64 MiB for remaining evidence plus guest/backing reserves, instead of charging
another full rollout. A conflicting or missing native terminal cannot receive
that capacity exception. Public validation uses the exact released CLI doctor
and anonymous requests to verify the returned source revision, committed tip,
NetworkId and curated `iroha.health` result.

The retirement path admits all four completed validator rollbacks and a completed
edge rollback when the edge was touched. Original state roots must be empty,
selectors absent and services inactive. It retains native journal bytes, terminal
history, rollback receipts and private runtime inputs. Earlier partial rollback,
non-vacant topology or pending recovery requires the corresponding native
recovery workflow; the retry command refuses to manufacture completion.

Signing material is opened as a strict inherited read-only descriptor and passed
to native authorization. Python never reads the signing key or peer config
contents. The operation keeps the same source and artifacts; a changed build uses
the release preparation and transfer workflow instead.

A successful retry result proves native apply, signer continuity, boot persistence
and public doctor/source/network/MCP health. Its
`public_application_validation_completed` remains `false`: the application's
own end-to-end acceptance check is separate and must use the released revision
and actual NetworkId.

Run the focused offline tests without Cargo or SSH:

```sh
python3 -B -m unittest discover -s scripts/tests -p 'taira_retry_test.py'
python3 -B -m unittest discover -s scripts/tests -p 'taira_signer_observation_test.py'
```
