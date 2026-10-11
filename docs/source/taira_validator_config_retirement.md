# Native validator config retirement

`iroha taira retire-validator-config --action prepare|install|restore --request-fd FD`
implements the routine updater's one supported schema retirement: removing the
`zk.halo2` TOML table. It does not add legacy parsing to the node. Every other
TOML value survives unchanged; `extends` and `profile` are refused. The current
environment-free node schema validates the projection. A config without the
table is a byte-exact no-op, including its installed inode and metadata.

The inherited root-private request has schema
`taira.validator-config-retirement.request.v1` and exactly
`schema`, `operation_directory`, and `owner`. The owner is the existing routine
updater identity: PID, process start time, exact Python argv and exclusive lock
device/inode. Each action checks the live direct parent, the exclusive flock,
the immutable v2 update plan, the compiled candidate identity and retained
config selectors. No client credentials are loaded. Only Native code reads
private config bodies; Python consumes metadata receipts.

Preparation creates fresh 0600 siblings beside each original config:
`.FILENAME.OPERATION.retirement-original` and
`.FILENAME.OPERATION.retirement-next`. Original files, service units, state roots
and selectors remain untouched. The guest checks the candidate against these
staged files before stopping validators. Each input/output is bounded to 1 MiB.

Install requires all four stopped checkpoints and completed stopped-owner
maintenance, observes vacant systemd/cgroups and binds loaded fragments with no
drop-ins. All four configs are admitted before the first replacement. Each
changed config is installed through an atomic sibling rename followed by parent
fsync; source paths and unit config arguments stay unchanged. The original copy
is retained. A crash between renames can leave a mixed stopped cohort; it cannot
be treated as a completed update. The same Native operation can recognize a
renamed staged inode and its exact projected bytes when explicitly reconciled.

Restore is permitted only before any `start-intent.json`; an existing
`failure.json` does not prevent it. Each replacement's inode is recorded in a
durable per-role `config-retirement-restore-ROLE.json` intent before its atomic
rename. A partial restore can therefore recognize already-restored inodes and
continue under the same updater custody. Unbound orphan staging, changed bytes,
unknown inode replacements, incomplete receipts, or owner loss fail closed.
Preparation interrupted before its receipt leaves untouched originals and
unselected private siblings. Completed action receipts are never overwritten.
These actions never start validators or rewrite ledger, keys, genesis, peer
trust, or deployment selection records.

Atomic restoration preserves original bytes but produces fresh file metadata.
A stopped rollback therefore requires explicit maintained reconciliation using
the genuine restored receipt; the old completed deployment's config stamps
cannot be reused as if unchanged. No automatic old-runtime restart is implied.

Native publishes `config-retirement-prepared.json`,
`config-retirement-installed.json`, or `config-retirement-restored.json` before
printing the same JSON plus LF. Their schemas are respectively
`taira.validator-config-retirement.prepared.v1`, `.installed.v1`, `.restored.v1`.
Each contains exactly `schema`, `operation`, `source_commit`, `network_id`, and
four ordered `rows`. Each row contains `role`, `source_path`, `staged_path`,
`original_path`, `changed`, `source_sha256`, `output_sha256`, `before_stamp`, and
`staged_stamp`. Install adds `installed_stamp`; restore adds `restored_stamp`.
Stamps use the updater's nine-field order: device, inode, mode, uid, gid, link
count, byte length, mtime nanoseconds, ctime nanoseconds. Rename may change ctime;
all other prepared inode metadata remains bound.

The runtime-update verifier holds both preparation and installation receipts,
joins the exact old/new stamp transition, and independently reads the retained
original and installed config through Native custody to reproduce the exact
projection. It still requires unchanged state roots, config selectors, unit
arguments other than the daemon path, and original peer config fingerprints.
Absent retirement receipts, the ordinary unchanged-config rule remains strict.
