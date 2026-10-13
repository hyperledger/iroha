# Standalone in-memory entry

This separately prepared diagnostic moves regular-file retrieval out of the
worker's charged execution. It preserves the frozen `resource_contract` sources
and reuses their allocator, reservation, mapping, supplied stack and join.
Fatal exhaustion now publishes to a shared control page and immediately exits,
without writing to an output sink. Old binary evidence does not qualify the new binary.

`staging::from_path` opens a regular file, retrieves at most 425,984 bytes and
checks the announced length. It drops the `File` before returning owned bytes.
Retrieval may block or retry; it has no promised verification-time bound.
Staging errors have zero charge and start no worker. Same-length concurrent
file writes can change the retrieved bytes; the verifier receives exactly the
completed immutable staging buffer, without a claim of an atomic file snapshot.

The derived `workspace::run(Options { record: &[u8], ... })` is synchronous and
one-shot in a fresh standalone process. The driver starts one verifier worker
and does no concurrent application work; the allocator contract still requires
no unrelated default-allocator activity while `ACTIVE` is true. This internal
entry is not an embeddable concurrent service. Its private native request derives
both pointer and length from that
same borrow. The worker checks its supplied stack, reserves the actual slice
length, enables the arena, creates its owned bounded copy, verifies and drops
that copy before disabling the arena. The supervisor retains the staging owner
until `run` has joined any started worker and cleared `ACTIVE`, including
returning errors. Fatal exhaustion or join failure exits the diagnostic child;
it does not report an invalid proof or promise Rust destructor cleanup.

The borrowed caller input and its unused capacity remain caller-owned outside
the charged workspace. The arena-owned copy is included. The reused fixed
mapping bounds the Rust heap, allocator metadata, control partition, supplied
worker stack and guards under its platform premises. This does not establish a
complete 64 MiB certificate for native runtime, TLS, loader, supervisor stack,
panic or exceptional behavior. Both qualification flags remain false.

Before staging or starting the worker, the external supervisor supplies exactly
one fresh zeroed native page through `--fatal-fd FD`. It creates a mode-0600,
unlinked regular file, retains its own handle, and passes an inherited `O_RDWR`
descriptor numbered at least three. The child validates the file's type, owner,
permissions, link count, access and exact page length, then maps it shared and
closes its descriptor. The mapping lives until child process exit. This extra
page is explicitly included in `workspace_reserved_bytes` and separately reported
as `fatal_control_reserved_bytes`; it is not hidden in caller overhead.

The first 32 bytes are four native-endian, aligned atomic `u64` words: magic
`0x5041524c46415431`, state, charged units and charged bytes. States are setup (1),
admitted (2) and exhausted (3). All remaining page bytes stay zero. This fixed
same-host control layout is not a serialized or production protocol. The sole
worker stores the exact reservation debit and release-publishes state 2 before
enabling the arena; exhaustion release-publishes state 3 and calls `_exit(73)`.
It does not format, write, unwind or promise destructors. The supervisor neither
mutates nor truncates the file, and reads only after child death. It accepts
resource exhaustion only for exit 73 with the exact magic, exhausted marker and
debit. Missing or corrupt evidence remains a worker error with no refund.
Result formatting and external output happen in the supervisor after the charged
worker has ended. Normal result output already occurs after arena deactivation.

Prepare a fresh standalone crate from the repository root:

```sh
python3 scripts/prepare_parliament_ballot_memory_entry.py --output /tmp/memory-entry-source
cargo metadata --manifest-path /tmp/memory-entry-source/Cargo.toml --format-version 1 > /tmp/memory-entry-metadata.json
python3 scripts/prepare_parliament_ballot_memory_entry.py --check-lock /tmp/memory-entry-source/root-Cargo.lock.template /tmp/memory-entry-source/Cargo.lock
cargo test --release --locked --manifest-path /tmp/memory-entry-source/Cargo.toml
```

The preparer refuses changed frozen modules or an existing output directory,
retains the exact derivation, and leaves the root manifest and lock unchanged.
The lock check compares package identity membership; it does not claim feature,
dependency-edge or build parity. Use a separately retained build receipt and
campaign for qualification evidence. Only 64-bit Linux and macOS are supported.

The CLI accepts `candidate|comparator registration|vote INPUT --fatal-fd FD` followed by
explicit `--heap-limit`, `--units` and `--input-bytes` controls. Replacing
`INPUT` with `--borrowed-oversize --input-bytes 425985` supplies a real caller
slice one byte above the service cap without file staging, testing the worker's
independent rejection before copying. Use `./--borrowed-oversize` for a file
with that literal name. `--help` lists the controls.

The [separate build and campaign evidence](../../../../docs/validation/parliament_ballot_memory_entry/README.md)
records the earlier source's 16 release Rust tests per mode and 122 successful
observations. Those frozen binaries still used stdout on exhaustion; that
evidence does not transfer to this shared-control revision.

The [shared-control build and campaign](../../../../docs/validation/parliament_ballot_fatal_control/README.md)
records 17 Rust tests per mode, strict Clippy, 122 source-bound observations and
real full/broken-output controls. Supervisor regressions reject missing/corrupt
control, contradictory normal debits and timeout races while preserving raw
evidence. These checks support this revision only.

TODO: resolve the complete
workspace/runtime boundary, and finish the named hardware and independent
review requirements before any production integration.
