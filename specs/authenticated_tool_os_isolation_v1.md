# Authenticated tool OS isolation v1

`iroha_authenticated_tool_controller` is the repository-owned implementation
of `iroha.authenticated-tool-os-isolation.v1`. It is an explicit `dev-tools`
binary target in the existing `iroha_kagami` crate; production packaging must
build it with `--locked --release --features dev-tools`, install it as a
root-custodied executable, and pin its SHA-256 in the release-controller trust
record. A checkout path or an unreviewed locally rebuilt binary is not a
production trust root.

The isolated execution surface is `run-v1`. No first-release production
protocol grants monetary or consensus authority through this controller.
`qualify-host-v1` accepts no arguments and runs the controller's built-in
hostile host suite. Its internal adversarial payload, `qualification-probe-v1`,
must not be granted as a standalone privileged sudo command. Unknown, duplicate,
inapplicable, missing, non-canonical, or oversized inputs fail with status
`125`. Policy limits fail with status `124`; otherwise the tool's status and
separate stdout/stderr byte streams are forwarded exactly. Tool stdin is
always a fresh `/dev/null`, never an inherited caller data channel.

The request protocol intentionally does not carry an expected tool digest.
The trusted caller must authenticate the digest and provide a private snapshot.
The controller then validates the
complete runtime/root-custodied parent chain and proves that snapshot's identity
and SHA-256 remain unchanged across execution. This divides trust without
letting an untrusted request choose its own supposedly expected digest.
The request does carry the launcher's attested numeric UID and GID; the
controller requires exact equality with both the real and effective runtime
credentials before it creates the job.

## macOS backend

The qualified macOS backend requires the root-owned immutable
`/usr/bin/sandbox-exec`. It authenticates the tool's canonical path, safe
ownership/mode/link identity, and SHA-256 before and after execution; starts it
at the exact canonical working directory with the caller's fixed sanitized
environment; requires `LANG=LC_ALL=C`, `PATH=/usr/bin:/bin`, a canonical
runtime/root-custodied `TMPDIR`, optional canonical `HOME`, and, when present,
`PYTHONDONTWRITEBYTECODE=1`; refuses inherited descriptors above stderr; applies a private
umask, zero core-dump limit, and file-size resource limit; and executes it as
the leader of a fresh session/process group under a generated Seatbelt profile.
The executable and every parent directory must also have no extended macOS ACL;
mode bits alone are not accepted as proof of custody.

Darwin has no `PR_SET_NO_NEW_PRIVS`. The v1 no-new-privileges invariant is
therefore discharged compositionally: the controller rejects a set-id origin,
requires equal real/effective user and group identities, rejects setuid/setgid
tool bits, denies tool forks, and permits `exec` only of that same authenticated
non-setid image. A non-root hostile qualification also proves that the image
cannot acquire uid 0. A root runtime already holds the contract's maximum
attested identity and cannot acquire a higher Unix identity.

The generated profile starts from `deny default`, so ambient Mach services are
not an escape hatch. Every request must select
`--deny-read-outside-allowlist`; there is no ambient filesystem-read mode. The
controller grants file data only for the authenticated executable, explicit
`--readable-file` paths, exact `--readable-directory` entries, writable output
files, and the fixed immutable Apple runtime roots under `/usr/lib`,
`/System/Library`, and the OS Cryptex System Library. Exact ancestor directories
receive metadata-only access for pathname lookup. Darwin additionally requires
data access to the filesystem-root directory during `execve`, which can expose
top-level names but not the contents or metadata of unlisted files below them.
`/dev/null`, `/dev/random`, and `/dev/urandom` are the only device read grants.
Operator homes, SSH material, key stores, `/etc`, `/private`, `/var`, and other
ambient paths remain denied unless the trusted caller names one exact input.
The only sysctl grants are `hw.memsize`, required by the verifier's native
memory guard, plus `hw.pagesize` and `hw.pagesize_compat`, required by the Rust
runtime's stack-guard setup; process-table, hostname, and other ambient sysctl
data remain denied.

Seatbelt also denies network operations, tool forks, execution of any
different image, every write outside the exact direct-child allowlist,
unlink/rename, hard links, clones, symlinks, directories, sockets, FIFOs, and
device nodes.
The deny-all mode permits no filesystem writes. Allowlisted outputs must remain
private, single-link regular files owned by the runtime identity. The
controller continuously validates each per-file ceiling, the combined output
ceiling, the complete live root, and protected entry identities. Because
unlink is denied in the kernel, an isolated tool cannot hide charged bytes in
an open-unlinked file.

A controller-owned watchdog is a sibling of the isolated job, not a child of
the tool. It receives no release data. Unexpected controller death closes its
private pipe, causing it to terminate both the original isolated process group
and the still-unreaped leader PID. Signaling both closes a process-group-change
escape; the tool starts as a session leader and therefore cannot move itself to
another group, while the kernel-level fork denial prevents an untracked descendant.
Normal return requires the leader reaped, the original group empty, and the
watchdog reaped.

`run-v1` retains a generic direct-output isolation contract for a future trusted
caller. Before Seatbelt starts, the controller securely pre-creates every absent
allowlisted output as a private regular file; the profile then grants data
writes but denies all file creation. An isolated tool must truncate/write those
files and must not require create-new or temporary rename/unlink publication.
The caller remains responsible for validating the results and performing any
authenticated atomic publication after the controller returns. No current
first-release production caller uses this writable-output mode.

There is no current first-release production caller. Any future caller must
define an exact read/write policy and independently authenticate and publish its
result; controller success by itself confers no protocol authority.

## Linux backend

Linux requests currently fail closed with status `125`. Do not deploy the
macOS binary on a Linux promotion host or substitute a Bubblewrap-only wrapper:
the Linux backend still requires independently qualified Landlock path rules,
seccomp process/network/link denial, a delegated cgroup-v2 job with kill and
storage accounting, and hostile forced-controller-death evidence. This is an
explicit remaining production gap, not a developer fallback.

## Qualification and provisioning

Run the dependency-free unit and hostile host suite on every controller build:

```bash
ci/check_authenticated_tool_controller.sh
```

On macOS this first runs the same built-in `qualify-host-v1` entry point used by
protected hosts and then exercises the external hostile suite. Together they
cover successful exact write/output/status forwarding;
exact-input reads plus denial of an unlisted same-directory file,
`/etc/passwd`, and an ambient sysctl; direct writes plus explicit rejection of
create-new signer semantics; network, spawn, fork, `setsid`, ambient write, unlink,
rename, hard-link, symlink and FIFO denial; output and wall-time bounds; and watchdog cleanup
after forced controller death. They also force both the cumulative writable-file
quota and the complete live write-root quota past their limits and require an
exact status-`124` refusal. Production provisioning, if introduced, must
authenticate the source-built image, install that exact byte string as a
root-custodied mode-`0555` executable, verify post-install identity and byte
equality, and run `qualify-host-v1` on the protected kernel. A non-root identity
must not be able to modify the executable or any parent directory in its chain.
