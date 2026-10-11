# Native filesystem custody

`iroha_fs` owns the native filesystem boundary shared by CLI workspaces, contract
artifacts, SDK key loading and daemon credentials. It owns no codec, secret format,
network policy, process signalling or persistent PID authority.

- `PrivateDirectory` requires current-user private custody. `OwnerDirectory`
  admits reader-shared project directories while refusing foreign mutation.
  Both retain ancestor authority and create private files/directories.
  `OwnerDirectory::open_private_child` and its optional form share the original
  ancestor handles while enforcing private child custody. Optional admission
  accepts absence only at the first native child open.
- `read_private` and `read_regular` perform bounded, stable descriptor reads into
  zeroizing allocations. `RetainedFile` supports streaming with explicit custody
  revalidation; `seal` freezes a completed writer's observation without reopening.
- Immutable journals use `open_exact` to reject all directory redirects and
  noncanonical spelling. `visit_private_files` streams bounded metadata, including
  incomplete private tombstones, without collecting names or reading bodies.
  Relative retained files share the existing ancestor handles.
- `read_tree_scope` shares only an identical retained ancestry prefix. Its
  `read_scope` callback brackets one directory's ordered reads and bounded
  inventories with fresh entry and exit checks; persistent exit custody errors
  take precedence over every ordinary callback result. Each leaf and inventory
  keeps its native admission and snapshot checks. Directory changes restored
  before exit can be unobserved: this is a closed read operation, not an atomic
  filesystem snapshot. Views expose no descriptors, paths or mutation methods.
- `PendingPrivateFile` permits bounded Write/Seek without exposing its descriptor.
  Consuming `seal_read_only` enforces exact Unix `0400` or a protected owner-read-only
  Windows DACL and returns opaque `SealedPrivateFile` with only Read/Seek. Recovery
  through `open_retained_read_only` rejects writable or oversized files. `publish_new_name` consumes
  the exact sealed creator for durable no-replace sibling publication; failures
  preserve evidence for reconciliation. Original descriptor rights stay private
  through publication; no writable handle can escape from either capability.
- File publication stages and syncs before atomic replacement. Directory
  publication consumes the retained source, requires an absent destination, and
  rejects live descendants. A failure after publication requires reconciliation.
- Advisory `open_lock` returns an unlocked persistent file. The caller acquires
  `File::try_lock`. Managed children use `open_ownership_lock`: Windows also
  retains a writer-sharing fence through inherited duplicates, independent of a
  process-scoped byte-range lock.
- Reset holds the caller's operation/runtime locks and clears contents through
  retained authority, preserving those exact lock names. Unsafe entries cause an
  error and may leave a partially cleared directory.

Unix admission uses owner modes, no-follow descriptor-relative operations,
single-link files, metadata/namespace revalidation and directory `fsync`.
Root-owned sticky temporary ancestors and immutable root-owned system aliases
are admitted by general paths; `open_exact` rejects aliases. macOS extended ACL
grants are checked separately from mode bits.

Windows admission requires a local NTFS volume, protected current-user DACLs for
private material, safe system/current-user ancestors, no reparse points, and
single-link files. Ancestor handles deny delete sharing. Publication retains the
exact source identity, renames by handle and uses write-through metadata plus
file flushing. This follows the NTFS behavior documented in
[Microsoft's file caching contract](https://learn.microsoft.com/en-us/windows/win32/fileio/file-caching).
Append-only Windows logs use write-through instead of requesting general write
authority for a later `FlushFileBuffers` call.

All platforms assume the operating system and storage honor their native
access-control and durability contracts. Privileged administrators and another
process already running as the same user are not separate secret principals.
Namespace changes are rejected; this crate does not provide a second user sandbox.

Run `cargo test -p iroha_fs` on each native release runner. Cross-target
`cargo clippy -p iroha_fs --all-targets --target <target> -- -D warnings` checks
platform compilation but does not qualify native ACL, sharing, rename, or crash
durability behavior. Windows-specific tests include protected DACL admission and
inherited-handle fencing; release qualification must execute them on Windows.

Private-file admission costs are derived in
[PRIVATE_FILE_ACCOUNTING.md](PRIVATE_FILE_ACCOUNTING.md). These are finite local
resource charges, not consensus parameters or native-platform qualification.
