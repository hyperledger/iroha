# Prepared Taira transfer

`scripts/taira_release_transfer.py` imports the four executables from a completed
`taira_release.py prepare` result, its public check/build evidence and the exact signed Git source into fresh,
inactive custody on the approved MacStadium Dublin Linux guest. It runs no
validator, deployment, reset, service, transaction or activation command.

Prerequisites: Python 3.11+, Git and GnuPG locally; AArch64 Linux root with Python,
Git and GnuPG on the guest; an existing guest-owned mode 0700 runtime directory;
and the explicitly approved, pinned guest and Mac backing-host SSH routes. The
local evidence parent must be an existing mode 0700 directory with safe ancestors.
The driver and all its controller dependencies must match the same signed commit
as the completed preparation. Use the full GPG signing-key fingerprint. The
source owner carries only the exported public key and verifies the actual commit
signature again in an isolated keyring on import.

Run from the canonical `optimizations` checkout:

```sh
python3 -B scripts/taira_release_transfer.py \
  --repo-root /Users/takemiyamakoto/dev/iroha \
  --plan /absolute/private/transfer-plan.json \
  --output-dir /absolute/private/fresh-transfer-evidence
```

The owner-private mode 0600 plan has exactly these fields:

| Field | Required value |
| --- | --- |
| `schema` | `taira.release-transfer.v1` |
| `provider` | `macstadium-dublin` |
| `preparation` | `{ "path": "/absolute/preparation/result.json", "sha256": "actual SHA256 of that file" }` |
| `expected_commit` | Full 40-character signed Git commit |
| `expected_signer` | Full uppercase GPG signing-key fingerprint |
| `runtime_root` | Existing approved private guest runtime directory |
| `backing_path` | Explicit approved Mac directory containing the guest disk |
| `guest_ssh`, `backing_ssh` | Exact pinned route objects documented for [Taira retry](taira_retry.md), ending in `/usr/bin/python3 -I -` |

Routes require explicit identity paths, strict host-key checks, the exact pinned
public known-host files, no ambient SSH configuration, and no agent forwarding.
The driver validates that fixed route, then substitutes only its own constant
Python bootstrap command to carry a bounded binary stream. It accepts no remote
command from the plan. SSH handles its authentication; the driver reads no
runtime private key, token, password or validator configuration.

Before remote I/O, the command verifies the signed controller sources, the exact
preparation request/result/capture and its actual typed check evidence, the
frozen source snapshot, and all four captured ELF hashes and headers against the exact target in the
preparation result. Both `aarch64-unknown-linux-gnu` and
`x86_64-unknown-linux-gnu` are artifact targets; the pinned result digest binds
that selection through transfer and native invocation records. The current
MacStadium receiver and native execution authority remain AArch64-only. An x86
artifact cannot execute there, and this artifact policy does not admit OVH or
change a signed host pair. The original
mode 0500 captures are retained unchanged. The signed-source owner exports only
the selected commit and complete tree/object closure, excluding parent history,
working-tree changes and gitlink contents.

Current `prepare` always records `native_check_scope: "build-only"` and
`checks.passed: false` because regression checks were not run. Transfer preserves
the actual boolean and request bytes. Retained `basic`, `full` and `build-only`
scopes classify their evidence; neither transfer nor the same-revision
owner-signed dispatcher transition requires regression success as deployment
authority. Neither can convert a failed check into a pass. Native deployment
preflight, finality, readiness, authorization and artifact/source custody remain mandatory.
Write canaries, restart rehearsals and broad public-doctor suites are optional engineering
diagnostics, never signing, transfer or deployment prerequisites.
Authenticated bootstrap transactions still advance the committed heights required by beacon
installation; their actual Applied receipts are protocol state, not diagnostic verdicts.

Source readers retain bounded lookahead across Git headers and adjacent pack
objects. Pack inflation consumes each input byte once before the independent
whole-pack checksum pass; small objects do not trigger repeated large disk
reads. Object lengths, identities, hashes, deadlines and file custody checks
remain mandatory on every verification pass.

The shared capacity checker first probes the Mac backing host, then the guest's
actual filesystem, then rechecks the Mac against the guest's full allocation
bound. The receiver rechecks guest capacity under its private import lock before
writing payloads. Capacity observations are not reservations. Required space
includes retained transport files, materialized source and Git objects, metadata,
filesystem allocation slack and operating headroom; nothing is deleted.

The guest creates `release-import-COMMIT-RESULT_SHA256` under `runtime_root`.
Executables are independent, single-link mode 0755 files in `artifacts/bin`.
`source/source` is the verified, clean, shallow signed source artifact. Transport
files remain in mode 0600 `source/source.pack` (the retained-import retirement
contract) and mode 0400 `source/source-capture.json`. The same import carries
mode 0400 `preparation/result.json`, `preparation/request.json`,
`preparation/checks.json` and `preparation/capture.json`; the latter is the exact
completed attempt capture and must match the result bytes. These files retain
the original producer records without rewriting their local build paths. The
closed stream requires all ten payloads; a six-payload import is incomplete.
Their bytes, file entries and parent directory are included in capacity admission.
No separate proof upload is required. No tar
extraction is used. Each stream length and SHA256 is checked before publication.

Only after revalidating every file and the actual Git signature does the receiver
publish `artifacts/verified-manifest.json`, `source/verified-manifest.json` and
`completed.json`. Local `binary-transfer.json`, `source-transfer.json` and
`completed.json` retain the exact returned receipts and remote receipt pins.
`activated` remains false; these are import observations, not deployment success.

Repeating the same plan with a fresh local evidence directory revalidates the
completed guest import without overwriting it. It still authenticates the
incoming stream. A changed request, corrupted existing file, unexpected entry,
partial import, hardlink, symlink substitution or unsafe mode fails closed.
Partial files and logs remain for diagnosis; this command does not repair or
adopt them. Keep failure evidence and select a separately reviewed destination
only after resolving the cause.

Next use the same-revision guest `iroha taira public-reset source-manifest` and
native public-input/configuration, supervisor-plan and inventory assembly
commands documented in [Taira release](taira_release.md). Native assembly derives
its own pins from the actual imported files. The transfer receipts can later be
consumed by the unchanged-artifact retry controller once a matching native
inventory exists; transfer does not construct that inventory or authorize a reset.

## Invoke an imported native tool

Use the same maintained controller with an explicit, mutually exclusive mode:

```sh
python3 -B scripts/taira_release_transfer.py \
  --repo-root /Users/takemiyamakoto/dev/iroha \
  --native-plan /absolute/private/native-invocation.json \
  --output-dir /absolute/private/fresh-native-evidence
```

This selects only the imported `iroha` or `kagami` executable from authenticated
receipts. It provides transport, descriptor custody and process observation;
native commands still own preparation, authorization, reset and recovery. There
is no shell-command field, daemon launcher, service controller or automatic retry.
The normal import `--plan` contract and its inactive result are unchanged.

The mode 0600 plan is a closed JSON object with exactly these fields:

| Field | Value |
| --- | --- |
| `schema`, `provider` | `taira.native-invocation.v1`, `macstadium-dublin` |
| `invocation_id` | Fresh random 32-character lowercase hexadecimal ID |
| `expected_commit`, `expected_signer` | Exact signed source commit and full GPG signer fingerprint |
| `descriptor` | Path/SHA256 reference to the independently approved mode 0600 `taira.runtime-deployment.v1` descriptor; it supplies the pinned SSH route |
| `preparation` | Path/SHA256 reference to the completed preparation's `result.json` |
| `import_request`, `import_completed` | Path/SHA256 references to `request.json` and `completed.json` in the successful **local transfer evidence directory** |
| `program` | `iroha` or `kagami`, never an executable path |
| `argv` | Native argument array, without argv[0]; at most 128 entries, 8 KiB each, 64 KiB total; no control characters |
| `files` | Array of `{ "fd": 198, "path": "/private/runtime/taira-public-reset/.../config.toml" }` mappings; at most 16 distinct descriptors in 3–65535 |
| `stdout_file` | `null` for bounded public output, or a fresh absolute guest-private output file |
| `timeout_seconds` | Explicit native deadline, 1–86400 seconds |

Each path/SHA256 reference has exactly `path` and `sha256` fields. Binary hashes
and the import root are derived from the receipts, not maintained separately for
each invocation. The controller authenticates its signed source and the bounded
preparation/request/check-evidence/completion records, then rehashes only the selected
guest ELF. It does **not** revalidate all other imported payloads or traverse the
source tree on each command. Native source-manifest and assembly retain their own
source checks; an invocation receipt is not renewed whole-import qualification.

Runtime inputs remain on the guest. Opened inputs must be read-only, regular,
single-link, owner-controlled mode 0400/0600 files beneath the approved runtime
root, with safe directory ancestry and a mode 0700 immediate parent. The transport
does not read them. Use the corresponding native `--config-fd`,
`--signing-key-fd` or other descriptor argument. Source descriptors and the
verified executable are protected from remapping collisions; the child closes
all unrelated descriptors and executes the held ELF descriptor with a fixed
environment. Neither key bytes nor private configurations belong in the plan.

Select `stdout_file` for any command whose output may be private. The native
child writes stdout directly to that fresh mode 0600 guest file and stderr
directly to its private guest attempt; Python reads neither stream and returns
neither stream's bytes. For explicitly public commands, null captures at most
256 KiB per stream, returns base64 bytes and reports truncation. These public
bytes are also retained in private guest evidence. This mode is suitable for
public native help, manifests and observations; it is not a secret-output mode.

Before SSH, the controller durably creates local `plan.json` and `started.json`.
Before execution, the guest exclusively creates
`native-invocations/INVOCATION_ID` and retains the admitted request and start
record. Reusing an invocation ID cannot launch again, even with different
arguments or a fresh local output directory. Use a new ID for an intentional
repeat of a read-only observation. For a mutation, inspect and resume the exact
native operation journal after ambiguity; a fresh transport ID is not permission
to reconstruct or resubmit an attempted mutation.

`result.json` records `process-exited` with the exact native exit code, or
`indeterminate` after a deadline/transport/observation failure. Deadline handling
stops only this invocation's direct controller child; remote work it previously
started may already have taken effect. No validator or service is signalled.
Transport has a 30-second observation allowance beyond the native deadline.
The wrapper exits nonzero for native failure or an indeterminate result. Even
exit zero proves only process completion: require native reset completion or
the exact transaction's verified Applied evidence for the actual operation.

Public-reset preflight/apply and dispatcher transitions require the Linux guest;
the Mac CLI cannot substitute for their descriptor and root custody. Current Mac
Musubi can independently perform the ordinary wallet/deploy/call demonstration
against public Taira. Musubi is not part of this four-binary import contract.

Offline checks (no SSH or Cargo):

```sh
python3 -B -m unittest discover -s pytests/scripts -p 'test_taira_release_transfer.py'
python3 -B -m unittest discover -s pytests/scripts -p 'test_taira_source_capture.py'
```
