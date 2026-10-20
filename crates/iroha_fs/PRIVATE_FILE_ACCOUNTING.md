# Private-file admission accounting

The private journal calls the shared filesystem owner after reserving local
resources. This table derives conservative charges from the implementation in
`unix.rs`, `windows.rs`, and their `private_files.rs` modules. It is not a bound
on elapsed time, kernel-internal work, interrupted-call retries, or filesystem
honesty. A filesystem probe means one owner-issued open, metadata/identity/ACL
request, lock operation, metadata update, rename, or synchronization. Streaming
body reads/writes are bounded separately by the receipt byte ceiling. Directory
iteration charges one request per yielded entry plus the final/overflow request.
In-memory ACL traversal and access-token queries use the scratch/handle allowance.

Let `d` be the number of retained ancestor objects, including the root. For an
exact path with `n` normal components, `d = n + 1`; Windows's drive prefix and
root name refer to one root object. Let `E` include every inspected directory
entry and the final/overflow entry. General paths can resolve trusted system
aliases; these equations require `PrivateDirectory::open_exact`, which rejects
aliases before following them.

| Successful operation, excluding caller work | Linux | macOS | Windows NTFS |
| --- | ---: | ---: | ---: |
| Directory revalidation | `5d` | `7d` | `9d` |
| Open existing exact directory | `7d` | `10d` | `14d + 1` |
| Open private read handle | `10d + 5` | `14d + 6` | `18d + 5` |
| Open/create ownership lock | `10d + 7` | `14d + 8` | `18d + 8` |
| Strict retained file revalidation | `10d + 6` | `14d + 9` | `18d + 10` |
| Strict retained snapshot | `20d + 14` | `28d + 21` | `36d + 24` |
| Relative private creation | `20d + 10` | `28d + 13` | `36d + 17` |
| Strict creator seal | `25d + 17` | `35d + 24` | `45d + 30` |
| Sealed creator no-replace publication | `25d + 16` | `35d + 23` | `45d + 32` |
| Open strict retained reader | `25d + 15` | `35d + 22` | `27d + 17` |
| Bounded private metadata scan | `8E + 20d + 16` | `8E + 20d + 16` | `8E + 20d + 16` |

These are admission ceilings, not instrumentation assertions. Failure normally
shortens a path; the scan includes an overflow entry so rejection at the count
boundary remains funded. Unsupported Unix metadata-only open behavior fails
closed; the native qualification targets remain Linux, macOS and Windows.

## Derivation

Unix directory validation performs one descriptor metadata read; macOS also
reads the descriptor ACL. Each ancestor revalidation opens and validates its
current name and compares that identity with the identity the held object had
when it was admitted (a held descriptor's identity cannot change): three probes
on Linux and four on macOS. Only a refused ancestor also validates the held
object, so the original error is reported; a walk therefore never exceeds the
five probes on Linux and seven on macOS charged here per ancestor. Denote this
whole ancestry ceiling by `D`, and one file
validation by `V` (`1` on Linux, `2` on macOS). A generic retained revalidation
costs `2D + 2V + 3`; a strict one adds one `V`. The three fixed calls are two
identity reads and one named open. A strict snapshot invokes two strict
revalidations, then one `V` and one explicit retained identity read. Relative
creation costs `4D + 3V + 7`; strict platform sealing and publication each cost
`5D + 7V + 9`; platform strict reader construction costs `5D + 7V + 7`.
The opaque strict seal and reader constructors each add one extent check. Directory sync
itself costs `D + 1`.

Windows's snapshot requests basic information, standard information, ACL/owner
information and file identity: four probes. Each ancestor revalidation performs
two snapshots and one named open: nine probes. Generic retained revalidation
costs `18d + 9`; strict revalidation adds one exact read-only DACL request. A
snapshot wraps a four-probe snapshot in two strict revalidations. Directory
sync costs `9d + 2` (revalidation, basic-information read, metadata update).
The opaque creator retains the original write/DACL/delete rights privately; strict sealing
adds the protected DACL update and verification. Strict readers share those
already-held rights without obtaining write access themselves. File publication
uses one rename request on the retained source handle.

The fused scan performs two ancestry revalidations, two directory snapshots,
and one bounded native iterator. Linux opens each entry with its metadata checks.
macOS uses one descriptor-relative `getattrlistat` call per checked basename with
`FSOPT_NOFOLLOW | FSOPT_REPORT_FULLSIZE`: mandatory object/owner/mode/link/data-length
and extended-security attributes arrive in one bounded response. The fixed attribute
request deliberately excludes options that skip unsupported attributes or fill defaults;
native errors and incomplete fixed layouts fail closed. A zero-length security attribute means no ACL; any
nonempty security attribute must contain the complete bounded native filesec before
ACL import and grant validation. This does not require file-data read permission and
does not repair mode-000 tombstones. It replaces the incorrect `O_EVTONLY` assumption.
The 8192-byte attribute buffer and at most 128 native ACL entries fit the existing
256-KiB scratch reservation; macOS entry work decreases and all portable ceilings
remain unchanged.
Windows's seven per-entry calls (iteration, open, four snapshot calls, strict
ACL read) determine the portable eight-probe entry allowance. Sixteen fixed
probes cover opening/closing out the enumeration and the directory snapshots.
The scan performs no file-body reads or per-entry ancestry walks.

## Retained memory and handles

Each ancestor owns a complete prefix `PathBuf` in an `Arc<Link>`. For an admitted
path of `p` encoded bytes, reserve `2*p*d + 256*d + 4096` bytes for this ancestry
and path construction, rather than multiplying the final path by a small fixed
constant. The factor two covers native path storage/capacity on the supported
hosts; the fixed per-link allowance covers the Arc, link, handle and vector
storage. A relative retained file clones only the Arc-pointer vector and stores
one portable filename: reserve `16*d + 2048` additional bytes and one persistent
file handle. The opaque pending writer retains its original byte ceiling and cursor; bounded
Write/Seek cannot create an extent beyond that ceiling, even through sparse
writes. Strict sealing consumes that writer into a read/seek-only capability.
Recovery rechecks the requested byte ceiling, and neither type exposes a raw
file/handle or clone. The caller separately funds its retained receipt buffer.

Open, scan and inspection operations each reserve 256 KiB of native scratch
space for a directory buffer, temporary path/name conversions and native
security descriptor/SID allocations (a native ACL alone can approach 64 KiB).
Pending-ID collections and body-read buffers are additional explicit caller
charges. One scan/inspection uses at most four transient native handles beyond
retained directory/file/lock handles, covering the iterator, metadata probe and
Windows access-token lookups. Retained ancestor handles are shared, never
reopened as a second lineage for each receipt.

## Journal composition

The journal's exact lock/lineage check costs at most `36d + 9`: two explicit
directory revalidations, one private lock-name open, and four identity/length
reads. Opening the journal through initial lock acquisition and that check costs
`68d + 20`; its subsequent inventory uses a separate released/reacquired lease.
A scan including the two journal lineage checks costs `8E + 92d + 34`.
A bounded stable receipt read costs `72d + 49` plus separately funded body I/O.
The largest single inspection is pending creation, seal, stable read and
publication: `198d + 128`. This also covers recovery (`143d + 80`, conservatively
combining the macOS reader ceiling with Windows read/lineage ceilings) and a
pinned recheck (`144d + 67`). Inspection is dropped before acquiring a separate
pinned-recheck reservation.

At the journal's maximum 64 normal components, `d = 65`. A full 65,536-receipt
scan also counts the lock and overflow slot: `E = 65,538`, giving 530,318 probes.
The handle minimum is 65 ancestors, one lock, one receipt and four transient
handles: 71. The journal/configuration owner derives the resident minimum from
its simultaneous ancestry, scratch, retained/reread receipt and pending-ID
reservations, and tests exact limits and one-below refusals. None of these local
resource limits changes receipt validity or grants signing authority.
