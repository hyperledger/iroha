---
title: Musubi V1 Kotodama Package Ecosystem
---

# Musubi V1 Kotodama Package Ecosystem

Musubi is the first-release package ecosystem for Kotodama source packages.
It provides Cargo-style manifests, workspaces, dependency resolution,
lockfiles, packaging, fetching, testing, publishing, ownership, and registry
operations while keeping every consensus-visible identity and decision
deterministic.

This document specifies V1. The earlier pre-release Musubi registry, wire
types, CLI aliases, lock formats, cache layout, and Torii upload workflow are
retired. Nodes must refuse launch when legacy Musubi registry records remain;
operators reset disposable pre-release state explicitly. No compatibility
decoder or automatic cache deletion is provided.

The replication-order lifecycle tombstone is part of that hard reset.
First-release `Retired` records retain the exact historical completed-provider
set; a snapshot containing the earlier key-only retired variant belongs to the
disposed pre-release domain and must be reset, not decoded or migrated.

## Identity and namespace binding

A canonical public namespace is registered once as a
`MusubiNamespaceBindingV1`. The record binds:

- canonical namespace text;
- a stable home `DataSpaceId`;
- either dataspace-root or domain scope; and
- the namespace generation used by delegations.

Bindings are immutable. A package has the structural identity
`MusubiPackageIdV1 { home_dataspace, scope, name }`; changing an SNS or domain
owner does not change an existing package or its governance. User interfaces
render and accept `namespace/package`, resolving the namespace through the
binding registry before an identifier enters an instruction or lockfile.

Package and namespace names are canonical lowercase portable names. Global
aliases are a distinct convenience layer. Alias text is lowercase ASCII kebab
case, one through 32 bytes, and never appears as package identity in a
published manifest or lock.

## Versions and requirements

`MusubiVersionV1` stores `major`, `minor`, `patch`, and structured prerelease
identifiers. It does not store a version string. Parsing rejects:

- build metadata;
- integer overflow;
- leading zeroes in core or numeric prerelease identifiers;
- empty or non-ASCII identifiers; and
- any spelling that does not round-trip to the canonical display form.

`MusubiVersionReqV1` is a canonical comparator AST. V1 accepts Cargo-style
bare/caret, tilde, wildcard, explicit exact, and comma-separated comparator
requirements. Bare versions have caret semantics; exact versions require
`=`. Equivalent accepted input produces identical Norito bytes: sorting and
deduplication happen before encoding, and a deduplicated singleton equality
uses `Exact` rather than a second comparator-list representation. Caret and
tilde matching compares compatible core prefixes directly, so a `u64`
component at its maximum retains Cargo's conceptual upper bound instead of
becoming unbounded. Requirement strings reject surrounding whitespace across
all SDKs; ASCII space around comma-separated comparator items is discarded
before the canonical AST is built, while alternate Unicode whitespace is
rejected. A prerelease candidate is eligible only when a comparator in the
requirement names a prerelease with the same major, minor, and patch tuple.

Published normal dependencies retain version requirements. Exact selections
belong to consumer locks and to the bounded verification proof supplied for a
publication.

## Archives and releases

`MusubiArchiveCommitmentV1` binds all material needed to reproduce and verify
a package:

- canonical SoraFS root CID and chunker handle;
- ordered chunk-plan digest and PoR root;
- full uncompressed bundle payload length (the descriptor separately binds source-only bytes);
- CAR digest and size;
- semantic bundle, normalized source-tree, and typed descriptor digests; and
- bounded file and chunk counts.

`ArchiveId` is the BLAKE3-256 digest of the domain separator followed by the
canonical Norito encoding of this commitment. Every zero, substituted, or
out-of-bounds commitment is rejected before state mutation.

The bundle contains `MusubiSemanticReleaseManifestV1`, which commits to every
semantic release field except the archive storage binding. Its domain-separated
digest is carried by the staging receipt, artifact descriptor, and provider
attestations. After the bundle and archive commitment have produced an
`ArchiveId`, `MusubiReleaseManifestV1` combines that semantic manifest with the
`ArchiveId`; the immutable registry release digest covers this complete
manifest. This two-stage commitment avoids circular hashing without weakening
the binding between release content and its selected canonical archive.

Archive location records are separate from archive commitments. A location
binds an `ArchiveId` to one renewable SoraFS pin and replication order. A
release never depends on one expiring pin. A location is selectable only after
the pin is finalized and approved and the replication order has distinct,
validated provider completions satisfying registry quorum.

`MusubiReleaseManifestV1` is immutable and contains:

- the exact release id;
- Kotodama edition;
- IVM ABI version 1 and exact ABI hash;
- bounded normal dependency requirements;
- typed-interface digest;
- immutable release metadata;
- `ArchiveId`; and
- the digest of the normalized publication verification lock.

The publisher supplies a bounded exact resolution proof. Core validates that
every selected node exists at the claimed finalized registry snapshot, every
edge satisfies the published requirement, every digest and ABI binding
matches, each parent-local alias occurs exactly once, the graph is acyclic, and
the graph remains within 1,024 nodes and depth 64. Multiple versions of one
package therefore use distinct aliases at any shared parent. This proof does
not become a global resolution for consumers.

The snapshot's height, block hash, and resolver-index revision are one
authenticated tuple. Core retains an unpruned ordered checkpoint store keyed by
resolver revision. Genesis records the block-final revision; later blocks add
one activation anchor only when their final revision is new, so unchanged
blocks remain sparse and intermediate revisions created within one block are
not claimable. Publication exact-loads the claimed revision, verifies that
activation anchor against the canonical block-hash log, requires its height not
to exceed the claimed height, and requires the first higher checkpoint (when
present) to activate strictly after the claimed height. The claimed tuple and
that successor's own anchor are canonical-checked independently. Resolver rows
also canonical-check their archive-availability anchor at its own finalized
height. Comparing rows only with the current revision is not sufficient proof
that they existed at a historical snapshot.

Release content and its release digest are immutable. The following mutable
states are independent:

- reversible owner-authorized yank state;
- derived storage/quorum availability; and
- Parliament-authorized artifact takedown.

Fresh resolution excludes yanked, below-quorum, and governed-unavailable
releases. A lock may continue fetching a yanked or degraded release while at
least one valid location remains. Takedown makes the artifact unavailable.

## Package governance

The first publication may claim an absent package only when the transaction
authority owns the bound namespace or presents a generation-bound namespace
delegation. The claim creates package-scoped governance with that authority as
the first accepted owner.

Later namespace ownership changes do not grant package authority. Package
members have accepted roles. Owner is a role and at least one owner must
remain. Maintainer capabilities independently cover publish, yank, metadata,
and archive-location management. Before an archive is referenced by any
release, its registrant may establish the initial location. Once releases
reference it, that bootstrap authority ends: every archive-location mutation
requires the current archive-location capability for every referencing
package, so removal or Parliament recovery cannot leave a former registrant
with latent storage authority.

Invitations are explicit and must be accepted by the invited account. Invite,
accept, role, removal, metadata, and ownership operations use compare-and-set
governance or metadata revisions. Stale revisions fail without mutation.
Every package-governance revision advance deterministically rebases all other
still-pending, unexpired invitations to the successor revision; the invitation
being accepted or revoked becomes terminal in the same mutation. A client that
races another governance mutation must therefore retry acceptance with the new
package revision, while concurrent invitations remain independently usable.

Sora Parliament recovery consumes an enacted decision bound to the exact
action digest. Core verifies the existing enactment delay and records the
decision as consumed so it cannot be replayed. The three exceptional recovery
actions cover package ownership, alias retargeting, and artifact takedown. A
separate Parliament action may prospectively replace the registry admission
and alias-pricing policy. Ordinary owners cannot invoke any Parliament-only
action. For an artifact takedown, the authoritative height relation is
`decision.enacted_at_height < decision.execute_after_height <=
consumption.consumed_at_height == takedown.applied_at_height ==
event.finalized_height`; the persisted takedown never relabels the earlier
Parliament enactment height as the later application height.

## Permanent global aliases

Alias registration requires:

- an unregistered canonical alias;
- authority as an accepted package owner;
- at least one active release;
- the exact expected pricing-policy revision; and
- atomic payment in XOR.

Genesis prices, in whole XOR, are 1,000 for length one, 200 for length two, 40
for length three, 8 for length four, and 1 for lengths five through 32.
Parliament may change prices for future registrations only. An alias is never
recycled. Normal package governance cannot retarget it. A Parliament recovery
retarget appends immutable history and preserves every prior target.

## Registry state and queries

Authoritative namespace, package, release, metadata, member, and invite
records live in typed ordered `mv::Storage` keyed by their stable home
dataspace identity. The universal dataspace contains only compact resolver
rows, archive/location records, reverse references, the public directory, and
the alias registry.

Publication, yank changes, metadata projection, and availability changes
update home and universal records atomically through Native AMX. No Musubi
state is encoded into `smart_contract_state`, stored in a global vector, or
recovered by scanning unrelated state. Exact resolution reads only the
universal sparse index.

The universal `musubi_replication_shortfall_releases` cell is the exact sum of
archive reverse-reference lengths for every archive whose authoritative
availability is not `Selectable`. It therefore deliberately includes yanked
and Parliament-taken-down releases while they remain bound to a non-selectable
archive; this is a storage-risk aggregate, not a fresh-candidate count. Checked
deltas apply only when an archive crosses the selectable boundary, snapshot
validation recomputes the invariant while validating reverse references, and
the process gauge is seeded directly from the persisted cell and synchronized
only after the world-state commit succeeds.

A source-level routing regression pins release publication to the universal
coordinator with the package home dataspace as its exact participant. Snapshot
validation fault-cut regressions reject one-sided release, reverse-reference,
resolver-row, and public-directory projections while accepting exact replay. A
four-peer below-quorum queue-journal crash/restart smoke is defined to queue a
structurally valid publication for an unavailable archive, restart every peer,
require one canonical finalized-replication-quorum rejection, and assert that
the package, release, resolver row, public-directory row, and archive reverse
reference remain absent on every peer at one finalized snapshot. The smoke
controls the durable queue boundary only; it does not pause a publication after
PrepareQC, after CommitQC, or immediately before world commit. The non-shipping
adversarial-test daemon now has source-bound, one-shot abort hooks at those
three exact Core insertion points. Each hook fsyncs and reads back a canonical
Norito acknowledgement before aborting, and the acknowledgement suppresses an
identical cut after restart. The integration gate now drives a selectable
three-replica publication through every hook without synthetic storage state:
each cut receives a fresh four-peer DA/RBC network, a canonical paid pin,
three admitted providers and governed completion authorities, one canonical
three-assignment replication order, three completions bound to a real finalized
anchor on the exact genesis-derived `NetworkId`, and provider-owner signatures
over the exact parsed bundle. The
PrepareQC and CommitQC cuts target the deterministic autonomous universal-lane
author derived from the durable lane frontier; the other three peers must keep
the release absent until that sole author restarts. The pre-world-commit cut
instead requires the other three peers to finalize while the target is down.
After restart, a finalized barrier requires every peer to expose the same
complete package, release, resolver, directory, location, and retention tuple
with exactly one successful publication occurrence. The gate has source
implementation coverage but still requires an execution receipt once the
unrelated workspace compilation failures are cleared.

Snapshot loading reserves the complete generic `musubi` state-path namespace:
the bare name and `_`, `/`, `.`, or `:` descendants are rejected as legacy
pre-release state. This prevents an unenumerated retired record shape from
bypassing the reset check.

V1 exposes twelve typed query families: exact package, exact release, exact
provider-bundle attestation, resolver index, versions, maintainers, archive
locations, archive retention, alias, alias history, ordered prefix, and search.
Resolver pages default to 50 entries. A continuation cursor binds finalized
height and hash, the canonical query hash, the last returned key, index
revision, and caller when authorization affects output. A changed anchor,
query, revision, caller, or boundary is an explicit stale-cursor error.

Finalized cursor keys are bounded by their canonical producer, not by a legacy
fixed text guess. V1 permits up to 1,102 bytes for a maximal structured SemVer,
320 for an ordered package selector, 129 for an archive/location pair, and 53
for an alias-history key. Maintainer keys retain their parity-stable
`hex(account)|accepted` or `hex(account)|pending-<invite>` form; the bounded
8 KiB canonical account identity gives the shared conservative cursor ceiling
of 16,457 UTF-8 bytes. Rust, Kotlin, Java, Swift, and the OpenAPI source use the
same ceiling. Ordered-prefix input remains independently bounded to the
canonical 320-byte selector maximum. A maintainer cursor's raw account payload
is an exact equality token, not a sortable byte encoding: clients decode and
re-encode its canonical lowercase-hex `AccountId` payload and reject the
boundary if it recurs anywhere in the response, while page items themselves
remain ordered by the structural `AccountId` and invitation key.

Every resolver-index, version, maintainer, alias-history, ordered-prefix, and
search page echoes the exact bounded request object that produced it, including
its structural selector or terms and page controls. This response context is
required even for an empty first page, so clients compare canonical fields
directly instead of attempting to reproduce a Norito query hash or infer an
identity from result rows. Page validation requires every row to match the
echoed package, requirement, alias, or complete prefix; enforces the requested
effective limit; and binds a continuation cursor to the exact final row. A
resolver-index page may stop before its requested item limit when another
canonical Norito JSON row would exceed the 24 MiB resolver-items budget; its
cursor binds that nonempty short page and the next request resumes strictly
after its final structured version. Every other page family permits a next
cursor only on an exactly full page. Version and resolver cursor advancement
uses structured SemVer, including prereleases, rather than lexical version
text. Ordered-prefix text is canonical `namespace/package-prefix` syntax and
remains present when no package matches. Search echoes the original bounded
query text, preserving first-page identity before a search cursor exists.

Cache pruning uses a separate exact archive-retention query, bounded to 100
sorted, distinct `ArchiveId` values. The first response establishes the exact
genesis-derived `NetworkId` and finalized registry snapshot; every later
request carries that snapshot as `expected_snapshot`, and the client rejects
any network, anchor, or response-identity mismatch before changing the cache. The response also
carries the consensus-committed creation time of that exact finalized block;
publication may use it only with an exact `RetainUnknown` decision and never as
a local-clock substitute. The query performs
only direct archive, reverse-reference, release, and availability lookups. An
unknown archive is retained fail-closed because the cache is not chain-scoped.
A governance-available active or yanked release retains its archive regardless
of replication health. Only a registered archive with no release references,
or one whose every reference has an enacted Parliament takedown, receives an
explicit prune disposition.

Description and keyword search is a rebuildable projection of finalized
package claims and metadata-change events. Startup and lag recovery rebuild it
from one finalized state view; steady state applies only finalized events. The
bounded query is normalized into sorted exact Unicode-lowercase tokens, with
ASCII hyphenated terms also contributing their component words. Results are
ordered by structural package ID and use a search-specific cursor bound to the
finalized height/hash, canonical query hash, last package, and process-local
projection revision. Rebuilds therefore make old search cursors explicitly
stale. Projection anchors never regress; multiple search events in one block
must carry the same finalized hash and each distinct change advances the local
revision. Prefix, edit-distance, fuzzy, or partial matches are not performed, and
neither search results nor projection revisions ever affect resolution.

## SDK mutation framing

Typed SDK mutation builders encode the concrete Rust instruction payload with
the default `COMPACT_LEN` layout and frame it under the exact registered Rust
type-name schema. A transaction embeds that concrete frame in the dynamic
`InstructionBox` pair `(wire_id: String, payload: Vec<u8>)`; it does not add an
outer `InstructionBox` header inside the executable. APIs that return a
standalone `InstructionBox` frame use the exact tuple schema name
`(alloc::string::String, alloc::vec::Vec<u8>)`.

The Rust-owned fixture at `fixtures/musubi/instructions_v1.json` locks the
semantic value, wire id, schema name/hash, bare concrete payload, concrete
frame, inline pair, and standalone frame. Its nineteen cases cover namespace
registration; maintainer invitation, acceptance, revocation, role replacement,
and removal; global-alias registration; exact release-digest assertion;
archive registration, immutable provider-bundle-attestation registration, and
location addition or renewal; archive-location retirement; release publication
and reversible yank state; package metadata replacement; and Parliament-enacted package ownership recovery,
permanent-alias retargeting, artifact takedown, and registry-policy replacement
across Rust, Kotlin, Java, and Swift. An already-framed generic instruction
wrapper is not typed field-to-Norito support.

Swift additionally embeds all nineteen fixture cases in one real signed batch
and extracts each inline pair at the executable boundary. That regression locks
the compact `ChainId` and `TransactionSignature` tuple wrappers while retaining
fixed-width sequence and byte-vector counts required by Norito V1.

## `Musubi.toml` and workspaces

Every manifest declares `manifest-version = 1`. Unknown or duplicate fields
are errors at every nesting level. A package manifest supports package
metadata, a configurable library directory, explicit exports, optional local
contract targets, tests, readme, license, repository, keywords, and positive
include additions.

`musubi new` creates a contract package named after its directory: a counter
seiyaku with state, `hajimari`, an authorized `kotoage fn`, a `view fn` and an error
enum, four standalone tests, a README and `.gitignore`. `--namespace` defaults to
`local`, which `musubi publish` refuses until `[package] namespace` names a
registry namespace.
`--template library` creates a library module with a TODO-marked unit-returning
function for each requested export. Export names must be canonical Kotodama
identifiers permitted for those generated declarations. `musubi init` preserves
existing source; it generates the selected template sources only when absent.
A conflicting source created concurrently is never
overwritten, and a source selected for preservation cannot silently become a
generated replacement if it disappears.

Each named `[[contract]]` target identifies one regular `.ko` source file and
one `.to` artifact. The declared name is retained across check, build, network
binding, deploy, and view. Contract directory discovery and generated ordinal
target names are not supported. Packaging and publication enforce the same
exact-file source identity as local compilation.

A declared test target may name one `.ko` file or a directory. Directory
targets expand to a bytewise-sorted, portable set of direct `.ko` roots under
the package, bounded by the V1 file/source limits. The runner reads each stable
regular source once through a singly linked, no-follow final-component
descriptor and passes its text through the structured compiler API; it never
reopens the diagnostic path or discovers ambient siblings. A standalone `koto_test` module may target a contract explicitly declared in the same
package manifest. Its relative target is normalized within the package; undeclared,
escaping, indirect, or unsafe target paths are rejected. Both sources are read once
and the compiler receives their immutable source units with the same exact package
imports. No ambient sibling discovery is performed. The named-path and
descriptor identities must match before and after the bounded read, so a raced
regular-file replacement is rejected. Each source is at
most 16 MiB, the complete declared set is at most 64 MiB and 4,096 filesystem
entries, and traversal is at most 64 directory levels. Unix and Windows use
the shared `iroha_fs` native owner: each directory retains its exact ancestor
and object authority across bounded pre/post entry enumeration, and each file
is read from its retained descriptor between exact native snapshots. Unix
no-follow, nonblocking opens reject substituted symlinks and special files;
Windows retained native handles reject reparse points and unsafe sharing.
This provides stable per-file source snapshots, not an atomic snapshot of a
concurrently edited workspace. Native Windows execution remains unqualified;
other targets fail closed before reading. Symlinks, reparse points,
hardlinks, special files, portable-name collisions, sensitive paths, and
generated/VCS/config roots follow the same fail-closed positive-set policy as
packaging.

A workspace root may be virtual or also contain a package. It supports
portable member, default-member, and exclude paths plus
`[workspace.package]` and `[workspace.dependencies]`. A workspace has exactly
one root `Musubi.lock`. Commands discover the nearest ancestor manifest and
then the owning workspace.

Every local `Musubi.toml` source read is capped at 1 MiB. Unix uses the singly
linked, no-follow, nonblocking final-component reader before UTF-8 and strict
TOML parsing; Windows uses the shared `iroha_fs` retained native reader.
Other targets fail closed before reading. A final-component identity swap or
special-file substitution is rejected without contributing parser input. The Unix
local-manifest reader's canonical and no-symlink ancestor checks remain path-based:
they detect ordinary drift but do not claim to close a deliberately timed
ancestor-directory ABA.

V1 dependency kinds are registry, path, and development. A dependency may be
renamed and may inherit with `{ workspace = true }`. V1 rejects git, optional,
feature, build, and target-specific dependencies.

A path dependency points to a validated local package manifest. A publishable
normal path dependency also declares its canonical registry package and
version requirement. Packaging removes the path, resolves the registry
release, and compiler-checks again from the clean packaged tree. Development
dependencies apply only to selected workspace roots and never propagate.

The compiler bridge derives canonical package identities through one shared
encoder used by builds, packaged publication checks, and workspace tests.
The BLAKE3 derive-key context is `iroha.musubi.kotodama-package-identity.v1`.
Each input field has a little-endian `u64` byte-length prefix. Local inputs are
`local`, namespace, name, and canonical version text. Registry inputs are
`registry`, the little-endian `u64` home dataspace, `root` or `domain`, domain
text (empty for root scope), name, and canonical version text. The resulting
compiler identity is `musubi/local/<lowercase-hex-digest>` or
`musubi/registry/<lowercase-hex-digest>`. Imports use the same encoder as their
selected package. Display labels, import aliases, and filesystem paths do not
define nominal type identity; the compiler's canonical grammar remains strict.

Clean publication validation reads only the immutable `PackagePlan`: it
recomputes the typed interface of every authenticated exact registry node,
validates the library graph, and compiler-checks every declared contract and
test root from the packaged bytes. It never reopens a workspace path. Tests are
compiled in test mode but are not executed during packaging, and their sources
do not affect the library interface digest. Because the V1 verification lock
contains only the release's normal dependency graph, a packaged test that
requires a development-only import fails with an explicit non-propagation
diagnostic instead of consulting local development state.

Focused manifest edits preserve comments and unrelated formatting. Paths are
portable, relative to their defining root, and cannot escape that root.

## `Musubi.lock`

The only accepted schema begins with:

```toml
schema = "musubi-lock"
version = 1
```

Every lock declares `context = "local"` or `context = "registry"`.
A local lock records a domain-separated `graph-digest` over the selected roots,
reachable package identities and versions, ABI/edition, and effective dependency
aliases, kinds, and local paths. Source edits and manifest formatting do not change
that graph. Local locks contain no registry nodes, deployment identity, or snapshot.
They cannot produce publication verification evidence.

A registry lock records one exact genesis-derived `network-id` and the finalized
registry height/hash and index revision at which the graph last changed. The two
context field sets are mutually exclusive; there is no compatibility parser for
unlabelled locks. Nodes contain exact structural
package id and version, immutable release digest, `ArchiveId`, source and
interface digests, and ABI binding. Parent-local edges contain the import
alias, child node, and dependency kind. Aliases are unique within each parent;
multiple versions of one package remain valid when they use distinct aliases.

Unsigned integer identity and snapshot fields are decimal strings encoded as
`"0"` or an ASCII digit sequence whose first digit is non-zero; signs and
alternate spellings are rejected rather than normalized while parsing.

The lock contains no cache paths, source plans, timestamps, credentials,
provider URLs, bearer tokens, or process-local data. Parsing any pre-release
lock format returns a regenerate instruction. `--locked` never rewrites an
invalid or stale lock.

The first-release consumer-lock corridor is bounded independently from
published verification locks: the UTF-8 document is at most 128 MiB, contains
at most 257 total local roots, and contains at most 512 dependency edges in
total, in addition to the per-parent 256-edge, 1,024-node, and depth-64 graph
limits. Selected workspace members and every recursively reachable local path
package share the 257-root budget; path packages do not extend it. `parse`
rejects the byte ceiling before TOML allocation. Local-package collection and
direct resolver input enforce the root ceiling. Resolver search shares heavy
branch payloads and accounts for exact edges branch by branch, so its recursive
depth cannot exceed 512 edge-bearing calls plus one terminal call, and an
oversized preferred release can backtrack to a valid lower-edge release.
One resolution evaluates at most 16,384 candidate branches; exhausting that
deterministic fuel corridor is a resource-limit failure, not an assertion that
the version graph was exhaustively proven unsatisfiable. One unit is charged
when each ordered candidate-loop iteration begins, including candidates then
rejected for cycle, depth, node, or edge limits. Zero-candidate terminal tasks
consume no unit, and failed branches never restore fuel.
Sparse-index collection and direct resolver input independently cap candidate
row occurrences and candidate dependency occurrences at 16,384; duplicate
rows still consume the live collection-work budget. Construction preflights
collection counts before sorting, and canonical rendering uses a bounded
formatter that cannot grow beyond the rendered-byte ceiling. Publication
packaging caps the semantic-release Norito payload, deterministic
verification-lock TOML, and exact verification-lock Norito payload at 2 MiB
each, matching provider verification and immutable-cache metadata admission.
The TOML formatter stops at that aggregate ceiling, and package admission
counts each exact canonical bare Norito payload before allocating its encoded
buffer or computing a bound digest.
Package collection retains its project root through `iroha_fs::OwnerDirectory`
and reads bounded sources through the shared native regular-file reader on Unix
and Windows. Each read validates ancestors, single-link custody and exact file
identity. The separate Unix local-manifest reader retains the ancestor limitation
described above. Native Windows runtime qualification remains outstanding.

Lock writes use a same-directory private temporary file, flush and fsync the
file, atomically rename, and fsync the parent directory. The previous complete
lock remains visible after every failed write phase.

## Resolver

Resolution is deterministic backtracking over ordered registry snapshots. It
uses this preference order:

1. an already-selected compatible version;
2. a still-valid selection preserved from the lock; and
3. remaining candidates in descending SemVer order.

Input and query ordering cannot affect the result. Parallel versions are
allowed when constraints cannot converge. The resolver backtracks across
parent candidates, detects dependency cycles, and reports the minimal stable
conflict chain.

Every still-valid locked selection remains fixed unless explicitly targeted,
including a yanked locked release. `update -p PACKAGE[@VERSION]` unlocks the
target and only nodes forced to change; `--precise VERSION` adds the exact
target constraint to every prior parent-local occurrence of that locked node.
The constraint remains binding when satisfying it forces backtracking to a
different parent release; an unrelated parallel occurrence cannot satisfy it,
and it never degrades into a candidate preference. Terminal enforcement replays
the prior target-bearing structure over the completed graph, including exact
old parents reached through renamed incoming edges and descendants of an
already-selected replacement. A prior occurrence unreachable from every
selected workspace root makes the targeted request invalid. Precise conflicts
name the minimal selected/current root-to-terminal branch rather than an
unselected prior parent. Fresh candidates exclude yanked, takedown, and
below-quorum rows.

## Command contract

The first-release command groups are:

- Project: `new`, `init`, `add`, `remove`, `metadata`, `tree`.
- Build: `fetch`, `check`, `build`, `test`, `package`.
- Contract runtime: `network configure|list`, `deploy`, and `view`.
- Developer custody and transactions: `wallet create|import|list|show|balance|fund|send|namespace`.
- Registry: `publish`, `search`, `info`, `versions`, `yank`, `unyank`.
- Governance: `owner invite|accept|list|set-role|remove` and
  `alias register|resolve|info|history`.
- Maintenance: `update` and `cache verify|repair|prune`.

The retired `install`, `pack`, short-alias `set`, cache `import`, and public
Torii upload workflows are not aliases.

### Developer wallet boundary

`iroha_wallet` owns persistent developer custody and the recoverable account-operation
lifecycle. Musubi selects inputs and renders results; it uses the native SDK to discover
network policy, construct and verify transactions, quote fees, and observe finality.
The ordinary `iroha taira account` adapter shares the same onboarding/faucet owner.
The public-reset coordinator retains its separate durable protocol and consumes the
same bounded faucet proof-of-work implementation.

The default wallet name is `default`. Its store is the platform user-data directory
outside Git repositories and Musubi packages; `--wallet-dir` selects an explicit
absolute directory. Each immutable named wallet binds a native signer to the exact
genesis-derived `NetworkId`, chain label, Torii root and account-address profile.
The SDK's shared account-service endpoint validator permits HTTPS or explicit
loopback HTTP, rejects URL credentials/query/fragment fields and bounds the URL to
2,048 bytes. Custody imports and network discovery use that same validator.
Taira discovery requires its canonical chain label and profile 369. A public endpoint
response supplies the current deployment identity; an explicitly expected identity
must agree before creation. Wallet generation alone neither registers an account nor
funds it.

Wallet directories have mode 0700 and newly written regular files have mode 0600;
owner-read-only mode 0400 is also accepted when reading private files. Creation
publishes a complete private directory atomically without replacing an existing name.
Key reads are bounded, current-owner, single-link and descriptor-relative with
no-follow checks. The canonical native `account.private_key_file` reader enforces
these key-file constraints for every SDK consumer. Wallet imports accept an
owner-private native key file or native client configuration; signing material never
appears in argv, public wallet information, project bindings or operation reports.
Native client imports retain the signer and exact network context while using native
wallet defaults; unrelated publication sidecars and separate Basic Auth credentials
are not imported. Public `list` and `show` do not load a private key. Custody uses
`iroha_fs` on Unix and Windows; Windows retains file identities and protected
owner ACLs. Native Windows execution remains a separate qualification gate.

`network configure taira --wallet default` records the selected wallet's native client
file reference. A new binding defaults to authority-paid deployment fees; explicit
sponsorship selects an exact immutable program revision. Updating an existing binding
without `--wallet`, `--wallet-dir` or `--config` retains its selected client. Omitted
fee selection also preserves the binding's existing policy. Project bindings contain
no signing material. Public target aliases remain independent from the package namespace.

Build next-step guidance retains the canonical project manifest, selected network and
exact client reference. An unbound Taira project points to integrated wallet creation,
funding and paid namespace setup; custom networks do not receive a Taira faucet
instruction. Deployment preparation and prior-journal recovery print a continuation
with that same manifest/network/client selection. Each preflight transaction shows
its quoted fee bounds and authority payer or exact sponsor program/revision.

Authenticated registry readers and signers also select the platform wallet named
`default` when no selector is supplied. `--wallet` and `--wallet-dir` select other
integrated custody and are mutually exclusive with native `--config`. Package
publication, recovery and resume inherit an available workspace default network
binding; explicit selectors must agree with that binding's pinned genesis identity
and profile. They share one bounded configuration
image and the canonical native key reader; an implicit working-directory `client.toml`
is not another credential source. Explicit native configuration remains available for
operator contexts. Registry publication additionally requires explicit storage service
routing, provider policy and any namespace delegation. Wallet creation does not invent
those settings, and contract deployment does not require registry publication.

When a new transaction is required, `fund`, `send` and `namespace` prepare one durable
signed transaction and submit that exact envelope. `--prepare` stops after preparation; `--submit <journal>`
dispatches wholly unattempted work, while an existing attempt is reconciled by hash.
`--resume <journal>` only reconciles the retained operation. Recovery validates the
selected command kind, network, endpoint, authority, signed terms and fee quote.
Wallet-owned operation directories remove the need to choose a journal path for
every new operation. Testnet funding uses the discovered policy's issuer and amount
and requires the canonical XOR asset. Transfer fees use the selected payer and
SDK-quoted limits in the signed envelope. An HTTP acknowledgement is not completion:
success requires the exact globally Applied transaction and matching committed wire,
or the operation-specific authenticated already-present proof.

These are source ownership and behavior constraints. Current test qualification and
the remaining public Taira admission, funding, deployment and recording gates are
tracked in [the workflow goal ledger](musubi_taira_workflow_goals.md).

### Compilation and registry commands

`fetch`, `check`, `build`, and `test` resolve and atomically update the lock
when permitted, then fetch missing archives. A graph containing only local packages
and path dependencies needs no signer, client config, resolver cache, or network
request, including its first `--offline` run. A missing or changed local lock still
fails under `--locked`/`--frozen`. The compiler revalidates the local graph commitment
before accepting it. A path dependency's registry publication fallback does not
replace its local source during workspace development. Registry dependencies retain
exact finalized resolution and immutable archive authentication. Packaging and
publication explicitly require registry context, even for dependency-free packages.

Local compilation uses the selected network's account-address profile: the
explicitly selected client's public account profile, the built-in profile of a
named network, or `--chain-discriminant`. Without a selected network or a
workspace default binding, `check`, `build` and `test` use the data-model default
profile (SORA, `0x02F1` = 753), the same default `koto` uses.
`--chain-discriminant` selects a local compiler input and must agree with an
explicitly supplied client configuration or the authenticated registry profile.
A local graph resolved without any of these, as by `fetch` or `update` without a
client configuration, carries no address profile; no default network is assumed.
Purely local commands never construct a signer. `--locked` forbids graph changes;
for registry dependencies, `--offline` uses only cached index and archives.
`--frozen` combines both constraints. Workspace selection follows default members,
`--workspace`, `--exclude`, and `-p`.

Offline resolver snapshots are canonical, bounded, and committed under a
domain-separated digest after all captured pages agree on one exact `NetworkId`,
finalized block, and index revision. Within one deployment, cached index
revisions must be nondecreasing as finalized height advances; a higher block
with a lower revision is rejected and can never satisfy a lock freshness check.
At the same finalized height and block hash, lock compatibility requires the
exact same index revision. Until finalized query responses carry portable
consensus inclusion proofs, the cache remains rooted in the validated online
read and private cache identity.

Purely local commands do not load a signer. Every network registry read requires the exact
`NetworkId`, canonical account, and matching private key from an explicit native configuration
or the default developer wallet; it signs the exact raw POST body/path with fresh one-shot authentication. Mutation
credentials use the same configuration boundary. Secrets and stream tokens are rejected on argv
and are never persisted. Human output has deterministic stdout/stderr separation; JSON output is
one document with a stable schema and error code.

Rust, Kotlin, Java, and Swift authenticated-query clients reject caller-injected legacy witness
proofs, disable redirect/retry replay, and apply a Musubi-specific 32 MiB response ceiling. An
exact-release JSON response repeats the bounded
dependency vector in the authoritative home record and the universal resolver
row, so a consensus-legal publication admitted by the default 10 MiB
transaction corridor can exceed the retired 8 MiB client limit. The 32 MiB
ceiling retains headroom for the escape-heavy full-256-dependency exact-release
fixture while remaining below the shared Rust HTTP client's 64 MiB default.
Resolver-index production separately caps the canonical JSON array payload at
24 MiB, validates the complete serialized page against the 32 MiB ceiling, and
uses the final returned version as a continuation when byte budgeting produces
a short page.

The JSON envelope is `schema = "musubi-cli-output"`, `version = 1`, and carries
one command result. Publish success data is a discriminated union. A detached
result has `status = "detached"`, the operation id, `phase = "seed-ingress"`,
the canonical namespaced `namespace/package@version` release label, and its
separately named `structural_release`. A completed result has
`status = "complete"` and retains both release forms, then exposes the operation
id, exact genesis-derived `NetworkId`, finalized snapshot, immutable release digest,
`ArchiveId`, both canonical projection digests, checkpoint digest, and the AMX
instruction digest, payload transaction hash, and applied height. Digests and
hashes are lowercase fixed-width hexadecimal. Heights and revisions are exact
unsigned JSON integers. The complete result is identical for an ordinary
publish and a completed resume.

The completed JSON receipt is the compact local checkpoint projection; it does
not copy the potentially large home-dataspace or universal-index records to
stdout. Its checkpoint digest is a commitment to the exact response already
validated by the publisher, not an authenticated finalized-query receipt or an
independent chain proof. `status = "complete"` proves the immutable publication
claim completed, but does not assert that a later yank, governed takedown, or
replica degradation left the release fresh-selectable. Runtime configuration,
credentials, authorization material, service endpoints, journal paths, and CAR
paths are absent from both success variants.

## Packaging and cache

Packaging starts from a positive set: canonicalized `Musubi.toml`, a generated
verification lock, declared library/contract/test roots, declared readme and
license files, and explicit include additions. It never starts by recursively
including the project and subtracting a denylist.

Generated, VCS, and configuration roots are always excluded. Packaging rejects
symlinks, hardlinks, special files, non-UTF-8 paths, traversal, portable
reserved names, Unicode/case collisions, and known credential/private-key
paths or contents. SoraFS CAR portable-path and chunk-plan validation applies
before commitments are calculated.

The package reader retains and revalidates the opened final-file identity, so a
leaf replacement cannot change the bytes admitted to the immutable plan.
Ancestor-directory confinement still uses path-based checks before and after
that open, however. A deliberately timed ancestor ABA replacement therefore
remains a release gate until package traversal is handle-relative and enforces
no-follow/open-beneath semantics for every component on each supported host.

The canonical bundle contains the semantic release manifest, typed artifact
descriptor, normalized source tree, and verification lock. Provider validation
attests successful parsing and verification of that bundle, not storage of an
opaque byte string. The shared verifier rejects a lock that contains the root,
an unreachable node, or a propagated development edge, and requires every
published direct dependency to match one normal root edge by alias, package,
requirement, and exact selected node. Semantic manifests, exact proof nodes,
resolver rows, and consumer lock roots all reject duplicate parent-local
aliases instead of depending on map overwrite behavior.

Every mandatory metadata file is nonempty. The artifact descriptor is capped at
64 KiB; the semantic release and exact verification lock are each capped at
2 MiB. Their data-model entry points decode one exact bare-Norito slice under
fixed field, element, allocation, and depth limits, validate the typed value,
and compare its canonical re-encoding directly with the input without first
materializing a second complete top-level metadata vector. The derived encoder
can transiently buffer one length-delimited field, bounded by the same file
ceiling. Providers and immutable-cache readers use only these shared entry
points. Malformed, trailing, noncanonical, length-bomb, and oversized inputs
collapse to stable payload-free boundary errors before any cross-binding or
cache mutation.

Authenticated fetches reject oversized JSON nesting, token inventories,
strings, and unquoted scalar literals before constructing a Norito JSON DOM.
On an online cache miss, an exact locked fetch also binds the finalized
archive-location page to the lock's `NetworkId` and snapshot floor
before contacting a provider. Equal finalized heights require the exact lock
snapshot; later heights must not regress the resolver-index revision. A valid
global content-addressed cache hit remains registry-independent because the
exact bundle is revalidated against every locked node that consumes it.
Online resolution anchors the selected `client.toml` path once, then reads one
bounded, singly linked image and parses both the authenticated registry signer/context
and the secret-free fetch configuration from those exact bytes. Unix uses the
nonblocking, no-follow final-component reader; Windows uses retained `iroha_fs`
handles. Other targets fail closed before that read. The fetch subtree requires the exact `NetworkId` plus
each provider's canonical operator public key and a private-key file; legacy
API-token and bearer fields are rejected. Bounded 0600, no-follow operator-key
files, DNS answers, and redirect-free HTTP clients are loaded only after an
immutable-cache miss; the raw configuration image is not retained in the graph.
Fresh publication retains only process-local, nonserializable provenance for
that anchored image. After clean-package validation it securely rereads the
file, compares a domain-separated digest before reconstructing any signer or mutation runtime
fields, and constructs the registry reader, signer, and publication
services from the matching bytes. Resume has no earlier resolver image to bind
and constructs those three boundaries from one current secure read; neither
path persists or reports configuration bytes, paths, or digests.
The canonical CAR bridge has a four-frame queue, accounts the consumer-owned
frame and a producer frame blocked on that queue, and closes and joins its
worker on success, error, or reader drop. Cache admission separately bounds
retained plan allocation and SoraFS ingest estimates. These are deterministic
logical-allocation controls; deployment-equivalent HTTP/TLS, JSON-DOM, cache,
allocator, thread-stack, and operating-system RSS qualification remains a
release gate.

The user cache path is derived only from the trusted root and archive id:

```text
registry-v1/<archive-id>/src
```

Extraction streams into a private sibling with no-follow/create-new file
creation, verifies every commitment, fsyncs files and directories, then
renames into an absent immutable destination. Verified `.payload.*.partial`
files and failed or race-losing `.src.*.partial` trees are retained: safe
automatic destructive cleanup requires an atomic handle-relative
compare-and-delete primitive that `std` does not expose. Repair validates the
finalized commitment and file plan before classifying any local entry as corrupt, and
quarantines only structurally validated descendants; invalid registry inputs
leave the cache untouched. Lock-controlled deletion, arbitrary replacement,
and cache import do not exist.

Private resolver-catalog reads retain `iroha_fs::PrivateDirectory` on Unix and
Windows. Unix walks ancestors through descriptor-relative no-follow opens and
opens final leaves nonblockingly; Windows retains native non-delete-sharing
handles and rejects reparse points. Bounded single-link reads revalidate root,
ancestor and file identities before accepting bytes or absence.

Cache access and package planning use the shared native directory owner on Unix
and Windows. Publication retains the exact source directory and uses the native
no-replace sibling operation, preserving its identity across publication. Source
support does not establish native Windows execution or signed release qualification.

Unix install has a subprocess abrupt-exit matrix at the payload write and
sync, source chunk and file sync, verified-payload retention, source-tree verification and
sync, directory publication, and archive-directory sync boundaries. Reopen
must either find no published `src` or fully reverify it, and retry must
converge. This is process-crash evidence, not yet the complete power-loss,
disk-full, or crash-at-every-write campaign. Those campaigns and corresponding
native Windows execution remain qualification requirements.

`musubi cache prune` inventories canonical cache identities and obtains the
bounded finalized decisions above. `--dry-run` reports the complete decisions
and explicit candidates without mutation. A non-empty live prune fails after
classification but before inspecting, isolating, chmodding, or removing any
candidate on every platform; automatic deletion remains disabled until the
workspace has atomic handle-relative compare-and-delete.

## Publication state machine

Production publication is resumable and idempotent:

1. Validate and compiler-check the clean package and exact proof graph.
2. Stage the CAR through admitted authenticated SoraFS seed ingress and obtain
   a signed expiring receipt bound to the exact genesis-derived `NetworkId`,
   publisher, broker/provider,
   manifest, archive, body digest and length, nonce, and expiry.
3. Register or reuse the exact archive and permanent registry-grade pin.
4. Wait for finalized approval and distinct provider validations/completions;
   each provider registers its one signed parsed-bundle attestation under the
   immutable `(archive, replication order, provider)` key.
5. Add the renewable location using the sorted provider identities and one
   archive/order-bound aggregate digest of those finalized attestations,
   require three healthy replicas, and read back through two distinct providers.
6. Submit the package claim and immutable release through Native AMX.
7. Wait for finality and verify the exact universal resolver row.

The client and publication engine share the fixed 30-second service-clock lead
policy for a newly issued seed receipt. A correctly signed receipt issued ahead
within that bound is journaled, but archive-registration preparation remains
`Pending` without rewriting the journal until the local trusted clock reaches
its issue time. A receipt beyond the bound is rejected before persistence;
only a receipt whose inclusive validity window has elapsed is discarded and
restaged.

The publication proof resolver may retain an existing lock edge only while its
row remains fresh-selectable; yanked, below-quorum, unavailable, or governed
takedown rows require a new proof graph (and make `--locked` fail). The proof's
snapshot must be a canonical finalized ancestor on the exact network, and its
index revision must match the sparse finalized checkpoint for that ancestor.
This permits replication and readback blocks to finalize without invalidating
the operation. Core exposes this exact ancestor and revision-activation check
as `validate_musubi_registry_snapshot_history_v1` so daemon-side finality
readers consume one consistent state view and cannot drift from publication
consensus. Core still revalidates every exact proof row, its nested storage and
yank anchors, and fresh-selection state against current authoritative registry
state when it executes the release claim.

The operation journal contains no secrets and is safe to resume. `publish
--detach` may return the operation id; ordinary `publish` succeeds only after
step seven. Retrying identical commitments is idempotent. Reusing a package
version with different commitments is permanently rejected.
Archive-registration evidence must retain the exact staged receipt from that
operation, including its nonce; another independently valid broker receipt
cannot cross the registration boundary.
Phase three persists a canonical registration intent containing the exact
instruction digest, receipt, fee-quoted signed transaction, and transaction
hash before registry submission. Recovery verifies the returned and status
hashes, requires authoritative applied-height evidence, queries a finalized
archive page covering that height, and persists the authoritative record before
pin coordination begins. The journal retains at most eight contiguous,
append-only attempts. Pending, absent, or transport-unknown transactions are
never replaced. An attempt becomes replaceable only with a finalized
`RetainUnknown` archive decision and either authoritative `Expired` status or a
consensus-committed finalized block time strictly after the exact signed
transaction/receipt validity deadline. A cache-only expiry observation is not
terminal evidence, and an authoritative generic rejection remains permanent.
Pin coordination authenticates the finalized transaction hash, exact `NetworkId`,
snapshot, immutable archive-registration projection, and verification-lock
digest rather than a new live seed receipt, and it rejects fewer than three
finalized parsed-bundle attestations. Each proof is an
immutable universal record keyed by archive, replication order, and provider;
the record retains the complete signed attestation and a domain-separated
digest, while location records and public pages retain only the sorted provider
identities and aggregate attestation-set digest. Core exact-reads and revalidates
every provider record, then recomputes the archive/order-bound set digest against
the complete finalized SoraFS completion set before accepting a location Add.
The projection contains the archive id,
commitment, original staging receipt, registrant, and registration height but
deliberately excludes the renewable location revision and location identities.
The daemon-owned read-only finality adapter captures one coherent Core query
view, applies the consensus snapshot-history validator, loads the exact
registration-height Kura block and canonical hash, and requires one unique,
non-rejected signed transaction whose sole native instruction, authority,
`NetworkId`, receipt, commitment, and policy revision reproduce the evidence.
It then compares the immutable projection from the current exact archive read
and returns that current mutable record for location CAS. Only a snapshot
height or resolver revision beyond the captured local view is retryable;
missing, rejected, forked, or substituted evidence fails permanently. The
adapter performs no SoraFS or registry mutation and does not activate the stock
service.

The daemon finality fixture now publishes its executed genesis and archive
registration through a test-feature State owner that consumes the actual
execution witness, an externally signed V2 finality artifact, and Kura's exact
durable receipt before State publication. The focused daemon finality suite
passes 12/12, including missing-finality refusal, current location and owner
substitution, signed provider-attestation substitution, and reader restart.
This fixture does not establish a complete authenticated State root or qualify
production finality ownership. Stock publication stays closed until the
remaining State-root, custody, provider, and network gates below are met.

The daemon's local publication factory wraps its deployment-selected storage
coordinator with a mandatory finalized-registration preflight. Before an
effectful coordinator receives a request, the wrapper validates the request and
re-reads the exact registration through the daemon-owned State/Kura finality
adapter, including network, transaction, immutable registration projection,
snapshot, and policy revision. A locally future finalized view is retryable;
malformed, absent, substituted, or uncertified evidence is permanent. The
service also invokes the wrapper's read-only check before returning a journal-
cached storage response, so replay cannot bypass the current State/Kura check
or repeat pin and replication effects. The V1 backend trait requires this
read-only check for every implementation. The wrapper does not itself pin,
order, or replicate data and does not enable stock publication; those effects
still require the qualified deployment coordinator and the remaining complete
State-root and provider gates. The focused daemon preflight test passes after
the cached-response change; the full service library passes 82 tests with one
explicit fixture exporter ignored.

Archive locations use a separate append-only journal of at most eight one-based
generations. Before submitting a location Add, the publisher persists the
complete finalized preparation page, current location-set CAS revision,
never-before-used stable location ID, compact provider-attestation set digest,
exact instruction digest, fee-quoted signed transaction, and transaction hash.
Before that compact Add is prepared, a compact immutable set descriptor and one
exact signed registration transaction per provider are installed as
operation/generation-bound, no-replace sidecars. Recovery exact-queries the
finalized audit record first and otherwise replays only the stored transaction;
coordinator-set, instruction, signature, or sidecar substitution fails closed.
The main operation journal retains only a domain-separated hash of the complete
set sidecar and an append-only identity/hash anchor for each expected transaction
sidecar. Installing a sidecar and durably appending its main-journal anchor are
separate advances; no provider registration may be submitted in the same
advance that first exposes its anchor. Once anchored, a missing, reordered,
substituted, or partially reproduced sidecar is a permanent integrity failure
and is never recreated from coordinator input. A finalized rejection may append
another bounded signed attempt only when its non-zero rejection height is
covered by a complete finalized archive page whose location-set revision
strictly exceeds the rejected compare-and-set revision.
The private
storage-coordination replay journal uses the generation as part of its durable
idempotency key, and every request carries the sorted IDs of prior generations;
the coordinator must not return one of them. A later generation is accepted
only after the prior generation has immutable terminal evidence, and its
preparation page must equal or advance that terminal finalized state without
resurrecting any prior identity.

Provider readback replay keys are independently domain-separated hashes of the
exact `(location_id, location_revision, provider_id)` tuple. Replacing a
location or renewing the same stable location therefore gets a new bounded
durable result, while changing any other request field under an existing tuple
is an idempotency conflict. The journal retains a fixed protocol-sized history
large enough for two distinct readbacks in every one of the eight publication
location generations; restart preserves both cached results and conflicts.

An identical active-location Add is a validated no-op before the consumed
location-set CAS revision, so a lost response recovers the exact journaled
transaction rather than building another mutation. For an absent target, the
publisher obtains the current CAS revision from a complete finalized location
page rather than trusting the coordinator's cached revision. A finalized CAS
rejection may rotate only when the covering complete page also proves a later
revision and absence. An applied transaction may rotate only when its applied
height is covered and a still-later revision proves that the identity was
retired. Expiry likewise requires authoritative exact-transaction status and
finalized absence. Unknown, pending, lagging, or coordinator-only claims never
rotate, and a same-ID content conflict remains permanent.

After a generation is finalized active, every replication poll, provider
readback, and release submission rechecks the complete finalized directory. A
later height and revision that omit the stable ID append exact retirement
evidence, clear replication and readback checkpoints, and return to location
coordination for the next bounded generation. Release rejection gets one typed
post-rejection location check; only exact retirement evidence permits rotation.
The journal retains the complete healthy directory page as the replication
floor, not only its target location record. A finalized page may not regress
height, resolver index, archive revision, or the active location revision.
Equal finalized heights require the exact same snapshot; an equal snapshot or
equal archive revision requires the exact same archive directory. Retirement
must be a later page state with an archive revision beyond the complete
journaled floor. The first applied target revision (`expected + 1`) must exactly
reproduce the signed intent fields and application height. A lower healthy or
retirement page observed after a later one was journaled is a retryable stale
poll and never overwrites the journal; the exact journaled record or a higher
revision at a non-regressing page and location height may resume.
A healthy same-ID renewal resumes from its current finalized pin, order, epochs,
provider identities, and attestation-set digest. Core resolves their immutable records and
requires the full proofs to still bind the exact `NetworkId`, archive, bundle, source,
semantic manifest, verification lock, and replication order. Production
qualification still must exercise the real fee-quote and
submission transport at every location-generation crash boundary.

Before a release transaction may be sent, the publisher must durably append a
compact exact-signed intent. The envelope retains every non-derived payload and
authorization field (creation time, non-zero lifetime, nonce, fee intent,
primary signature, and the optional canonical multisig proof) and reconstructs
the exact `NetworkId`, publisher, sole `PublishMusubiReleaseV1` instruction, empty metadata,
and absent attachments from the immutable operation request. The intent binds
both the payload-only transaction hash and a domain-separated digest of the
complete fixed-V1 signed wire. The registry's authoritative status identifies
the payload transaction hash; the authorization-inclusive wire digest is a
local durable replay binding, not consensus evidence that one particular
signature bundle was committed. Status recovery must reconstruct this exact
local transaction, query authoritative payload status before any send, and
resubmit the same bytes while it is live; it must never sign a replacement for
an absent, pending, or transport-unknown attempt.

Release attempts are one-based, append-only, and bounded to eight. A replacement
intent requires a durable terminal outcome plus synchronized finalized evidence
that the exact package version is absent from an empty universal resolver page
and that the archive retention response uses the same snapshot and consensus
time. Expiry needs authoritative expired status or consensus time strictly past
the signature-bound deadline. Rejection additionally requires a covering
higher healthy revision of the same location, or finalized retirement followed
by a later location generation. An identical already-published release is not
proof that this payload applied. Without `Applied` status for the journaled
payload hash, the attempt never synthesizes application evidence. When status
is `Absent`, a finalized same-publisher release whose complete commitments
match may still take Core's idempotent path by replaying the journaled bytes;
a different publisher or any commitment conflict is permanent. Before that
absent transaction is sent or replayed, a fresh finalized replication query
must reproduce the selected location record byte-for-byte from the signed
readback floor. A stale page, retirement, or same-ID renewal therefore leaves
the exact intent durable and unsent. A stale `Pending` status cannot outlive the
signature-bound deadline once synchronized finalized absence and consensus
time prove terminal expiry.

The current 16 MiB journal enforces derived, disjoint budgets for non-release
state, eight release attempts, and final submission plus a compact completion
checkpoint. The full paired home/universal response is bounded and validated at
finality but is not copied into the durable frame. Completion instead retains
the request-derived operation id, exact genesis-derived `NetworkId`, the covering
snapshot, structural release and archive identity, the complete immutable
release-manifest digest,
domain-separated canonical digests of both verified projections, and a
self-digest over the complete checkpoint. The operation id binds the public
anti-replay nonce and all other immutable request fields. The checkpoint is
append-only once persisted. A later paired yank,
unyank, governed takedown, or below-quorum storage projection may therefore
complete verification of the already-applied immutable release claim; it is not
misrepresented as proof that the release remains fresh-selectable.

The compact checkpoint is a local commitment to the full response verified at
creation time; its public self-digest is not an authenticated finalized-query
receipt. A completed resume therefore trusts the private journal's protected
storage boundary. Deployments must place that journal below a trusted,
non-replaceable ancestor with rollback-resistant storage or a sealed monotonic
head. A deployment that admits external journal replacement must instead retain
signed finalized-query evidence or requery and rebuild the checkpoint before
returning success.
Complete operational-shape location pages are retained directly. A fixed-bound
audit found that the former 64-provider, 64-approval location shape is not a
consensus-legal V1 maximum: with an 8 KiB canonical account bound and the
3,309-byte maximum supported approval payload, one `AddMusubiArchiveLocationV1`
can approach 28.8 MiB and a four-location response can approach 115.6 MiB,
already exceeding the 10 MiB transaction and 16 MiB block-body corridors.
The V1 wire schema therefore registers each at-most-1-MiB provider proof in a
separate transaction and stores only the provider list plus aggregate set digest
in the location. Core requires every proof registration to finalize in an
earlier block and exposes one exact audit query. This makes the location
instruction and four-location page compact independently of approval geometry;
the production release prepare/status/submit path now uses the compact durable
intent and reconstructs the exact Torii request body for status-first replay.
Descriptor-relative filesystem qualification of the publisher sidecars, real
fee-quote/submission transport exercises, crash/fault injection, and
rollback-resistant checkpoint storage remain release gates.

Final verification requires the exact-release response's `NetworkId` to match
the immutable publication request before retaining that one exact identity in
operation evidence. It also journals the Native AMX transaction's authoritative applied
height and requires the final snapshot to cover it. An exact-looking release
row returned by another network incarnation, or from before that application, is
rejected even when its package, version, and content digests happen to match. A
row revision may precede the page's current global index revision when an
unrelated later mutation did not rewrite that exact row.

Core plans and validates the successor package-governance revision, pending
invitation rebases or expirations, resolver-index revision, exact archive
reverse references, resolver row, and public-directory entry before the first
publication write. The final apply phase is infallible, so any stale, malformed,
bounded-capacity, or revision-overflow failure leaves the package and its
pending invitations at the same compare-and-set revision.

The private publication control plane is selected only by the platform Iroha
`client.toml`; project manifests, lockfiles, journals, and argv never contain
its endpoints or credentials. The optional strict `[musubi.publication]`
table contains `seed_ingress_url`, `storage_coordinator_url`,
`ingress_broker`, `seed_provider`, `expected_policy_revision`, an optional
bounded `request_timeout_ms`, at least two distinct `provider_gateways`, and
an optional `namespace_delegation_file`. Unknown fields fail configuration
loading. Service and provider URLs are credential-free HTTPS bases with
redirects and ambient proxies disabled. The delegation file is a bounded,
canonical Norito `MusubiNamespaceDelegationV1` whose delegate must be the
configured publisher; it is public authorization material, not a signing key.

Every private request uses a fixed route and a short-lived, domain-separated,
bounded controller-approval set over the exact `NetworkId`, publisher, operation id,
operation kind, typed request digest, and validity window. Approvals are
strictly key-ordered and distinct; a single controller requires its one exact
key, while a multisig controller requires valid member signatures meeting its
weighted threshold. A decoded multisig policy is reconstructed through its V1
validator before quorum calculation, so malformed versions, members, weights,
ordering, or thresholds cannot become publication authority. The verifier
rejects a zero trusted time or any requested future-clock allowance above the
fixed 30-second V1 maximum; a caller cannot widen that protocol bound. The
client constructs every payload field and an injected qualified signing
provider returns only approvals, which the client verifies before building a
request. Any deployment-owned provider must implement that same boundary. The client owns the authorization timestamp,
maintains a non-regressing clock
floor shared by its clones, resamples after the external signer returns, and
rejects an authorization whose lifetime was consumed during signing. The
platform `KeyPair` adapter remains single-key only. Seed ingress carries small
canonical request metadata separately from a versioned plan-and-CAR envelope.
The approvals bind the complete archive commitment plus the
domain-separated digest and exact length of the canonical Norito plan witness;
the envelope carries fixed magic/version bytes, the plan and CAR lengths, the
exact witness, and the exact CAR.
The retired public Torii SoraFS upload route is not a fallback. After
clean-package compiler validation, fresh `publish --detach` first persists the
secret-free operation journal as its recovery anchor, then verifies and
immutably installs the exact plan sidecar before the CAR. A crash can therefore
leave a small discoverable journal, optionally with its plan, awaiting the
remaining sidecar, but never an unindexed CAR. `publish --recover OPERATION_ID`
is the bounded workspace-reconstruction recovery path: it accepts only a
pristine Validation-phase, revision-one journal, derives the exact package
selector and verification graph from that journal without reading or rewriting
the workspace lock, rebuilds the clean package, and requires exact publication
and archive-commitment equality. Under the operation lock it reloads the
unchanged journal and idempotently reuses or installs only that operation's
immutable sidecars. Local recovery reads only the public address profile from one
bounded platform configuration image and verifies the exact cached archives before
constructing any signer or transport. An offline cache miss fails immediately;
an online miss loads the authenticated registry reader and storage configuration
from that same image. Recovery never submits a mutation or advances publication;
the user subsequently invokes `--resume`. An advanced journal,
substituted workspace, stale revision, or mismatched existing sidecar fails
closed. Normal resume never reconstructs unpublished workspace state.
Journal, staged-CAR, plan, and operation-lock custody uses the shared native
`iroha_fs` owner on Unix and Windows. The journal directory is private from
creation, and recovery retains ancestors, checks owner access and rejects links
and changed object identities. Unix reads use no-follow and nonblocking opens,
so a substituted FIFO or device cannot block the publisher. Windows uses
protected owner DACLs, reparse rejection and retained non-delete-sharing handles
on NTFS. CAR reads remain streaming and validate their original snapshot at the
exact committed length; plan reconstruction validates the length before allocating.
Journal publication uses native atomic replacement and durability boundaries,
with the same exclusive operation lock and revision CAS on both platforms.
Native Windows execution and signed release qualification remain outstanding.

The server counterpart is a transport-independent, closed three-route core.
It accepts only exact `POST` routes and canonical bounded Norito authorization
and request encodings,
checks exact `NetworkId`/publisher/operation identity and bounded clock skew,
authenticates before parsing the bounded envelope, then canonically
decodes/re-encodes the plan and reproduces the CAR, root, chunk-plan, PoR,
source-tree, descriptor, semantic-manifest, verification-lock, and bundle
commitments before any journal reservation or backend call. It returns only
canonical typed success or redacted error bodies. Its injected
crash-safe journal atomically consumes authorizations, binds each operation ID
to one genesis-derived `NetworkId`, publisher, and immutable archive/CAR
commitment, rejects equivocation, and reuses an exact completed result. When
replaying a completed seed result, the backend re-reads the retained exact
operation, binding, plan, and CAR before the journaled receipt is returned; a
missing or substituted staged file fails closed and is never recreated by that
read-only check. When only a completed seed receipt has expired, a fresh exact
authorization may atomically reopen that same request: ingress idempotently
confirms the same CAR and the broker replaces only the expired receipt, while a
failure restores the prior completed record. This refresh cannot alter the
operation binding or typed request digest. Seed ingress, permanent
pin/replication coordination, and provider readback are separate injected
backend traits. The service, rather than the signer, constructs the exact
bounded receipt payload and expiry after staging. An injected signing-provider
trait returns only controller approvals; the service assembles and verifies the
receipt against the exact binding and trusted time before journal commit. This
boundary admits deployment-owned collection implementations without giving them authority to
substitute receipt fields. The in-process `KeyPair`
implementation is explicitly a software adapter for focused tests and
controlled development deployments. Private request objects carry no
caller-supplied time. The service samples its injected fail-closed,
non-regressing trusted clock at authorization admission, again after CAR
staging to set receipt issuance and expiry, and after approvals return before
commit. An authorization that was live when atomically admitted need not remain
live during signing-provider work, but a receipt whose lifetime is consumed by
signing is aborted and never cached. The injected production clock must retain
a rollback-resistant time floor across service restarts; the core also rejects
regression within one process. Service construction also requires the
signing provider's broker and seed backend's provider identity to equal the
public deployment configuration, and rejects a multisig broker when its
highest-weight subset within the 64-approval receipt bound cannot meet the
controller threshold.

Stock `irohad` opens no listener for these routes. An injecting launcher supplies
a one-shot deployment factory. After trusted startup replay and SoraFS node
construction, `irohad` passes that factory the exact genesis-derived `NetworkId` and
live finalized-state, transaction-queue, and SoraFS handles. The factory must
assemble the service core, crash-safe journal, qualified deployment-selected
signing provider, SoraFS backends, and qualified private HTTPS/TLS ingress; its runner then joins
the daemon supervisor. TLS material and backend credentials never enter
argv, project files, publication journals, Torii, or the daemon-private runtime
provider broker. The gated daemon readback adapter binds the configured gateway
hostname to a council-admitted signed provider advert. Live council refresh and
the concrete signer/storage adapters remain deployment qualification gates.
Provider implementation details remain deployment-owned.
The stock tree now supplies the read-only authoritative finalized
archive-registration reader described above, bound to the factory context's
exact `NetworkId` and `Arc<State>`. It still does not supply the effectful
storage coordinator or production pin/replication backend that must consume
that result before coordinating SoraFS. The latest-state archive record is
sufficient for the immutable projection because Core never mutates those
fields after registration; historical mutable location state is no longer
part of the request contract. Trait injection and authenticated requester
bytes alone are not finality evidence.

The daemon now has a bounded local factory for the protocol core. It reopens
the original journal, handle-pinned seed store, and durable clock, binds the
authenticated provider-fetch client to the live daemon network, and passes the
finalized reader to the injected storage coordinator. A non-secret
`iroha_config` supplies the custody root, durable journal and seed-retention
limits, authorization clock skew, and receipt lifetime. The factory derives
separate journal, seed, and clock paths from that root; only the public live
network, broker, and provider identities enter as explicit runtime inputs;
signing keys and provider operator credentials remain runtime-owned. The
service retains the only seed-staging authority. The storage builder receives
a read-only finalized-seed capability bound to the same daemon reader and seed
owner. It checks the exact current State/Kura registration before taking the
seed lock, then returns one bounded, non-clone lease over the verified plan and
CAR. A second concurrent materialization is refused until the lease drops;
the caller cannot substitute its own finality reader or use a cached journal
response to obtain unfinalized seed bytes. This is a read boundary for a
future paid pin coordinator, not an effectful pin or replication runner. The
daemon also exposes a read-only signed pin-registration recovery reader. In one
State query view it reauthenticates the source archive, requires the exact
signed sole-`RegisterPinManifest` transaction and canonical manifest to match
the archive CID, chunker, POR, CAR digest and size, then verifies the unique
successful network output in a Kura-finalized block and the current non-retired
pin record with its public fee payer. Three focused daemon tests cover the
signed-intent, current-record and output boundaries. The reader cannot sign,
submit an intent, prove current governance/pricing and configured paid-pin
policy, approve a pending pin, or cause replication. The purpose-bound paid-pin
signer preserves original State allocation refusals through its initial read,
captured-view read and final recheck; locally future evidence remains distinct
from invalid finality. These outcomes do not authorize replacement signing.
Retaining an already signed transaction across a refused final recheck still
requires the durable outbox/control handoff before production activation.
A separate Unix outbox substrate
can retain the exact signed V1 pin transaction in an immutable, bounded,
process-exclusive, owner-only directory before any Queue effect. Its canonical
owner marker binds the network, exact public paid-pin authority, fresh signing
session identity, storage tier,
retention horizon and limits. Isolated stage, reopen and recovery controls reauthenticate every
retained source registration through the daemon-owned finalized reader. The
manifest must name at least three replicas, the configured tier and the exact
retention epoch derived from the signed creation time, fixed transaction TTL
and configured horizon. Reopen rejects missing markers, interrupted writes,
changed records or a changed paid-pin policy; exact retries are idempotent,
and conflicting operation IDs or signed wires close in isolated controls. The
daemon-facing outbox constructor returns `MissingFinalizedAnchor` even for a
locally valid inventory. The first-release native `AdvanceMusubiPinOutboxV1`
instruction ratchets a publisher-owned State high-water under exact network,
signer, session, contiguous revision, and predecessor inventory digest. Both
Advance and `CheckMusubiPinOutboxV1` require a sole direct signed Ed25519 External
transaction in the original Global root, without attachments or multisig.
Mixed batches, sealed reveals, contract calls and nested effects cannot acquire
the one-use original input binding. Advance records the original signed intent
hash and actual execution height.

Check signs an explicit nonzero session, complete inventory digest, fresh
challenge, exact native committed floor and either authority-wide `Absent` or
`Present` with the entire expected high-water row. Absence never filters by
session or inventory. Present compares every field, including the original
advance's transaction hash and height. The canonical Check frame is bounded to
4 KiB and the original signed External envelope to 64 KiB. Floor authentication
uses the original State execution tip and exact reverse native ancestry, with
bounded relative source work and cumulative physical frame bytes; chain height
alone does not make a recent Check unavailable. A malformed signed floor or a
different authenticated context is a deterministic rejection. Missing, corrupt
or locally over-budget original history defers execution without a committed
result, fee, gas charge or published overlay, preserving an earlier local
allocation refusal and its original wake source. A successful Check does not
modify the high-water row.

The canonical State table is required in snapshots. The daemon's historical reader
checks the current row against its original successful signed Advance. Core now
also owns a fresh Check readback: independent network, chain and floor inputs are
verified through original native execution and the Global instance before the
exact signed Check is bound. One bounded ascending continuation compares each
receipt to its original executed result before exposure. A final read reauthenticates
the successful Check and compares the entire authority-keyed current row under a
short same-generation publication fence. A different State handle is refused even
when its bytes match. The opaque consumed result is read-only and grants no Queue,
signing or replacement-custody authority. Failed reads retain the unchanged paid
Check, challenge and absolute deadline; retry discards an old verified cut and must
verify fresh native history, without re-signing or resubmitting. These source
boundaries still require current-candidate native test execution.

After the observer returns its exact reply, the shared stream-token signer runtime
retains completed evidence in its receiving continuation. One move-only phase keeps that reply, the
original challenged expectation and native Pending with its absolute deadline, and
borrows the original receipt, token, prepared operation and custody markers. Original
canonical decoder, bounded-encoder and allocation refusals have typed local outcomes;
malformed or invalid evidence retains its semantic rejection. The three evidence verifiers
mutably borrow the caller-owned expectation and return only the original admission error.
The private attempt is retired before verification begins; success, completed rejection and
unwind leave it retired. Only an original retryable local admission result restores readiness
for the same request and reply. Repeated use is rejected before decoding, without allocating
or reconstructing the expectation. Bounded local backoff
revalidates the same returned bytes and fresh handles/time without holding a State
view or history lock. Separate authentication, native-verification and acceptance
owners prevent token release before every phase succeeds. Daemon and broker service
mappings distinguish operational unavailability from semantic rejection, but those
fixed errors alone do not retain a continuation or authorize producer replay.

The native completed-observation producer separately retains its actual verified
Check and charged canonical frame through unsigned body construction, fallible
signing-payload encoding, one observer signature, signed-frame encoding, and the
late native floor/time check. It copies the absolute deadline only from the exact
Prepared Check before consumption. Original evidence-admission or native execution
refusals keep the same owner; bounded local backoff neither reobserves nor signs or
submits another transaction. A successful signature is retained across later
encoding/refusal, and cryptographic signing failures remain terminal because they
carry no trusted allocation provenance. Once encoded, the exact reply buffer stays
owned through the late check. This Check and Torii's separately prepared Check are
distinct operations; neither is a substitute for the other.

The broker observer client retains one fully received response frame with its
original operation request, admission permit, locked connection and absolute
15-second call deadline. Its receiving stage preserves successful frame, response,
reply and observation decoding phases while retrying only original typed local
codec or bounded-encoding refusals. It validates the same envelope and request
binding, transfers the same reply leaves, and never performs another request,
observe, sign, submit or socket read. Protocol ceilings, malformed results and
immutable metadata changes remain terminal. Other broker capability routes keep
their existing semantic validation and do not inherit this observer continuation.

Combined `finalize_check` signing/submission, server post-observe/pre-write reply
custody, and partial socket I/O still have transport-custody gaps. The server needs
an absolute request bound established before provider dispatch; per-I/O timeouts
cannot be reset into a completed-reply retry deadline. Nested receipt/custody codec provenance, late consumer
native/current-State acceptance refusal ownership, and original-pool funding for
existing buffers, serializer/decoder scratch and native proof graphs also remain
open. These process-local continuations do not establish durable publication
recovery. Stock publication remains closed.

Local custody computes
a domain-separated digest of the entire owner marker and sorted immutable signed-intent
inventory; isolated rollback tests show an older, well-formed directory differs from a later
high-water. The effectful stage → finalized advance → same-view inventory
comparison → Queue sequence is not yet owned and qualified, so these components
do not authorize production recovery or Queue effects. Before effects, recovery
also needs an independently current network-finality checkpoint: an internally
consistent rollback of both local State and Kura cannot be detected from that
old local view alone. A separate read-only
recovery join looks up the original signed wire by
operation ID and refuses a
different source, network or pin authority. It reports pin completion only
when the same-view State/Kura reader proves the exact successful transaction
and current non-retired fee-paid pin record. Neither custody nor recovery
submits to Queue or claims provider publication. Deployment-sealed monotonic
lineage, current fee and governance rechecks at admission, Queue submission,
replication/provider completion, and physical network qualification still
precede stock publication activation.

The remaining Queue handoff needs a separate durable control journal for exact signed
Advance and Check transactions; control bytes cannot be included in the pin inventory
whose digest they sign. The native filesystem substrate can now borrow the existing
private-directory authority and caller-owned basename for an opaque retained file,
without cloning retained Rust lineage or names. It shares the owned file's strict
custody checks, bounded I/O, consuming seal and one-use no-replace publication on
Unix and Windows. Windows retains protected owner-only DACLs, reparse rejection,
non-delete-sharing directory handles and publication through the original file handle.
This does not fund the original directory, native ACL/directory scratch, inventory
or recovery storage; the original caller's complete resource admission and native
Windows execution qualification remain open. The control journal is still unlinked.
Restart must reconcile those originals and acquire a newly
challenged native Check. The final handoff must consume live verified Check custody
and retain the exact pin and pending Check on refusal. Its shared Queue owner must
reserve insertion storage and fee custody before publication, then acquire commit,
lifecycle and Queue guards in that order; it must publish notifications after release.
The existing enqueue routine still allocates during insertion, so merely exposing its
prepared admission or passing a callback under the State fence does not close this gate.
Installed-executor preflight must also preserve typed allocation/codec refusals before
this handoff can enable production publication.

The Unix clock and journal child reads, bounded enumeration, lock creation,
pending-file creation, state replacement, and stale-file removal now use each
owner's pinned directory handle. Focused clock controls pass 15/15 and journal
controls pass 14/14, including configured-path replacement, restart, rollback,
and replay recovery. The refreshed final-V1 publication frame fixture and
service library pass 82/82. The daemon publication module passes 41/41 focused
controls, including the finalized seed lease and effect preflight. Deployment-sealed monotonic CAS, finalized lineage binding,
and filesystem qualification on other supported platforms remain open before
production custody is qualified.
The readback backend fetches the exact provider manifest and plan, consumes the
committed-size CAR through EOF, and repeats complete bundle, semantic-release,
and verification-lock checks. The readback request now carries the exact
finalized registration and policy revision. Before and after transport, the
daemon reader verifies that registration against its result-bearing Kura block,
pins one coherent current State view for the archive/location/provider-owner
rows, verifies the complete signed provider-attestation set and current owner
against its immutable completion, checks the finalized tip, and requires the
configured HTTPS origin to equal a
council-admitted provider advert endpoint with the needed capabilities. The
request is retried when the local finalized cut or admitted advert is not yet
available. An exact cached readback response is replayed only after a fresh,
read-only check of that current finalized target and admitted endpoint; the
historical response bytes are unchanged. This uses State's committed-world
ownership; a complete State-root
witness is still a separate gate. The shared provider-attestation and replication-order
binding helpers retain static model rejection reasons while borrowing the same
World rows. Instruction callers materialize the same invariant diagnostic only
at their completed-result boundary; current-provider reads retain their existing
semantic `None` behavior. This removes helper diagnostic allocations, not the
ordinary signature caches, backend/codec error allocations, or their outstanding
State execution-pool custody. A future local resource refusal must propagate as
a typed deferral through every consumer and cannot become unavailable evidence.
These adapters do not install a listener.
Effectful provider coordination, independent replica readbacks, live council
admission refresh, qualified receipt-signer custody, and stock activation
still gate production publication. A deployment may inject the daemon's
prebound private TLS ingress builder with an in-memory server identity;
`iroha_config` supplies the bind socket and a maximum of four concurrent
requests. This dedicated listener accepts only the three exact
`/v1/musubi/publication/...` paths; prefixed paths and query strings refuse.
The builder disables TLS early
data, serves only the three closed HTTP/1.1 routes, rejects duplicate
security-sensitive headers, and bounds header and body reads before handing
the exact request to the service core. On supervised shutdown it drains
in-flight blocking service calls. If the supervisor's bounded wait expires,
the blocking call still retains the service and its durable custody until it
finishes. Focused controls cover all three fixed paths, rejected prefixes and
queries, configuration projection, invalid geometry and shutdown custody.
Runtime TLS credentials, certificate
rotation, provider coordination, and live network qualification remain
deployment gates; the stock daemon opens no publication listener.

The production adapter dependency order is therefore explicit and fail-closed.
The plan-bearing seed boundary is implemented in the stock service core. A
maximal 16,384-chunk witness needs at least 720,896 bytes for offset, length,
and digest fields alone, before file records and Norito framing, so it is
carried in the bounded body envelope rather than the 64 KiB authenticated
metadata header. The publisher persists the canonical witness as an immutable
operation sidecar beside the CAR; detach and resume reproduce the same request
without putting either byte stream or a path in the secret-free journal. The
service rejects the retired raw-CAR media type without compatibility, resolves
the exact registered chunker from the commitment, enforces file/chunk/heap and
decode bounds, and invokes the reusable provider-grade Musubi verifier in
`sorafs_car::musubi::MusubiBundleVerifierV1`. That verifier validates the
canonical CAR and plan plus every nested bundle commitment before the service
calls the admitted seed backend with the verified `CarBuildPlan` and CAR. Its
provider-oriented fresh-reader entry point performs three bounded passes: it
reconstructs the canonical CAR into a sink, verifies the chunk plan and PoR,
then parses and binds the semantic bundle. Every pass requires exact EOF and is
independently tied to the same commitment, so truncation, trailing bytes, and
between-pass substitution fail closed without materializing the CAR. This path
is for an authenticated extraction or an admitted chunk store; a raw provider
CAR must still cross the complete canonical-CAR verifier because payload-only
readers cannot observe noncanonical container headers, indexes, or trailing CAR
bytes. The shared semantic-release and lock decoders each admit at most 48 MiB
of cumulative Norito allocation accounting, including nested field charges and
whole-input realignment. The provider drops its 32 MiB PoR store before bundle
parsing in both entry points. Those deterministic controls do not by themselves
prove whole-process RSS below 64 MiB; supported-target measurement remains a
release qualification item. The generic 512 MiB chunk-store admission ceiling
is separate from this provider path.
The embedded SoraFS node exposes the matching digest-selected read boundary as
a callback-scoped lifecycle lease. It reveals no storage path, blocks eviction
for the callback, admits and accounts every verified chunk through the local
fetch scheduler, caches only the current verified chunk, and permits exactly
the three byte-zero readers needed by this verifier. The higher-ranked callback
lifetime prevents either the lease or a reader from escaping. Digest selection
uses the canonical manifest-map key rather than a manifest scan, acquisition
errors are path-free, and a reader returns at every chunk boundary so a later
scheduler or integrity failure cannot discard already-reported bytes. Eviction
installs a transient exclusive retirement intent that rejects new leases, then
drops global storage state before waiting for existing lifecycle readers. A
failed verified chunk is conservatively charged at its admitted length so
corrupt-read retries cannot refund the byte-rate budget. The callback must use
only the lease and its readers and must not re-enter other node-storage methods.
This is a local verification primitive only; it neither issues a provider
attestation nor turns an ordinary storage completion into one. The
pre-completion projection prerequisite is implemented:
`IssueReplicationOrder` can atomically bind an already-registered `ArchiveId`
and its complete immutable `MusubiArchiveCommitmentV1` before provider
completion. The consensus lifecycle then advances from pre-location to active
and finally to a permanent retired tombstone. Snapshot loading revalidates the
canonical order, pin, archive, complete commitment, bidirectional purpose
marker, and, for active or retired records, the exact completed-provider set.
Generic SoraFS orders carry neither the marker nor a Musubi binding.

The durable and runtime-only bindings must not be conflated. The
provider-indexed archive projection retains its configuration label for lookup,
an exact finalized anchor, and current completion state; that label is not a
signing or replay domain. The outbox
authorization separately persists a bounded
`FinalizedProviderIngestMusubiContextV1` containing the exact `NetworkId` and
`ArchiveId`; that context participates in the job ID and immutable binding, so
a generic job cannot be upgraded with an informational Musubi value and a
Musubi job cannot be downgraded by omitting one. The V5 checkpoint is the sole
receipt-bearing layout and rejects every other discriminator, including the
retired V4 layout whose public receipt codec could be used to fabricate
field-shaped verifier evidence.

The runtime's opaque pre-completion claim binds the exact `NetworkId`, local
provider, finalized archive cursor, replication order,
`ArchiveId`, and complete commitment. Its factory authenticates the configured
finalized-ledger implementation boundary, not arbitrary bytes. Production
wiring gives that capability only to the qualified archive-backed reader. The
private broker transports only a checked informational projection of the claim
under the source-fetch operation. Authorization matching is monotonic from the
retained admission cursor: a later finalized height may refresh the claim or
receipt, an equal height must reproduce the exact block hash, and a lower height
or equal-height fork is rejected.

Both existing and newly ingested Musubi payloads are then selected by canonical
manifest digest, held under the callback-scoped lifecycle lease, reconstructed
with the exact registered CAR plan, and passed through all three fresh-reader
verifier passes. The resulting bounded receipt retains exact network/provider,
the admission cursor, order/manifest/archive/commitment, and the parsed semantic
release and verification-lock digests. The V5 provider-ingest checkpoint carries
that receipt through local and finalized states. The public receipt has no
Norito encode or decode implementation; only a crate-private DTO is persisted
inside the sealed V5 checkpoint, then revalidated against the retained
authorization before projection. A restart cannot prepare a
completion for a Musubi row whose local state lacks the exact receipt. This is
still pre-completion evidence: it contains no finalized provider-completion row
and cannot authorize a provider attestation.

Source acquisition also releases every claimed job before reporting a request
construction failure. A valid local-only, one-replica order with no remote
sources moves to `RetryScheduled(SourceUnavailable)` without attempting a
fetch, while any other malformed request shape moves to
`RetryScheduled(SourceRejected)` before the protocol error is returned. Neither
path leaves a durable `SourceClaimed` row waiting only for lease expiry.

After the local provider's completion is finalized, the finalized reader can
seal a distinct opaque `ProviderIngestFinalizedMusubiCompletionClaimV1` only
from that exact completed order row. It has no public constructor or wire
codec. The only downstream-visible request-minting boundary is the doc-hidden
`NodeHandle::verify_provider_ingest_completed_musubi_capture_bundle`. It first
rejects an unbound or foreign process-local store-instance marker, then enters
the callback-scoped lifecycle lease. The lease's crate-private
`AdmittedPayloadReadLeaseV1::verify_completed_musubi_bundle` accepts the
retained authorization, opaque completed claim, and exact reconstruction plan,
checks them against the lifecycle-leased admitted manifest and payload digest,
and opens all three verifier readers itself; `NodeHandle` also rechecks the
marker on the returned request. The raw verifier-evidence constructor is
crate-private, so evidence retained before completion cannot be combined with
a later claim by daemon or downstream code. The resulting
`ProviderIngestMusubiAttestationApprovalRequestV1` binds the unsigned
attestation payload, a stable completed-row evidence digest, the separately
retained observation cursor, and governed signer policy. The digest covers the
exact `NetworkId`, provider, order, archive commitment, and finalized
completion row but deliberately excludes only the observation cursor. A fresh
request for the same row at a later finalized head therefore reuses the same
approval identity and may satisfy the retained intent; the stored cursor is a
floor, an equal height must reproduce its hash, and a lower height or
equal-height fork fails. The request remains nonserializable and externally
inert: constructing it performs no signing, registration, or runtime handoff.

`ProviderIngestCompletedMusubiCaptureScannerV1` is the effect-free bridge from
finalized completion rows to those opaque claims. The capture-only
`ProviderIngestCompletedMusubiSignedCaptureLedgerV1` receives no claim factory
and cannot return a claim. It accepts only the scanner's exact bounded request
and returns an untrusted signed page. The scanner pins one immutable reader
session binding: the V1 domain, exact `NetworkId`, provider ID, ephemeral
Ed25519 public key, and a non-zero reader-session epoch. Every request also
binds the exact finalized cursor, continuation order ID, checked `u16` limit,
and a scanner-owned non-zero generation. The signed transcript uses canonical
Norito components with explicit field tags, row indices, and lengths under one
16 MiB cumulative bound. It commits the request, complete page header, every
pin/order/archive/owner/authority/epoch/transaction field in row order, and the
continuation. The scanner reconstructs and verifies that transcript before it
validates or seals any row, then privately creates a fresh factory and
revalidates the resulting assignments and claims. It commits its generation
and cursors only after the full operation succeeds; rollback restores both.

The concrete daemon reader owns the corresponding private ephemeral key and
creates it lazily, so ordinary provider-ingest startup remains unchanged while
activation is closed. Its blocking read/sign section serializes requests and
retains one exact signed response. A lost or cancelled response can therefore
retry the same request and generation byte-for-byte even if the archive head
advances; a different request at the same generation, an old generation, or a
skipped generation fails. A successful next generation performs a fresh
replay-safe archive read. The private key and an unbound raw-page accessor
never cross this boundary; the resulting private-field projection travels only
inside the untrusted signed envelope that the scanner independently verifies.

The generic production scanner builder is gone. A private, clone-shared `Arc`
identity is created only for a handle with both storage and the provider-ingest
outbox, and identifies that process-local `NodeHandle` incarnation through the
completed claim, capture candidate, and unsigned approval request. Its atomic
capture tenure can be taken only once across all handle clones and never resets
after failure or drop; a separately constructed handle or restart gets a fresh,
independent marker and tenure. Generic finalized-ledger claims are unbound and
cannot mint a request. Reconciliation rejects a foreign scanner before a signed
page request, while a foreign or unbound claim fails before lifecycle-lease or
payload-reader I/O. The marker has no codec, stable bytes, hash, or Debug
disclosure and is excluded from the completion digest and approval ID. Those
stable identities can therefore be rederived after restart, but the
marker-bearing claim and request must be freshly reconstructed.

`PreparedProviderIngestFinalizedArchiveV1` now owns its capture reader as one
movable concrete value with no cloneable accessor. A private `irohad` composer
moves that exact reader into the doc-hidden non-generic
`ProviderIngestCompletedMusubiCaptureCoordinatorV1` and retains the tenure on
`Iroha`. Acquisition does not consult the reader. Scanner/session binding is
lazy, so height-zero startup can remain pending; retry uses the same retained
reader and its lazy signer session, while a second caller cannot substitute
another reader. The coordinator exposes no public page, claim, approval, or
effect-driving operation. The marker alone still does not authenticate Kura,
State, or runtime-provider slots, and a custom launcher remains its own outer
trust root. Qualified effects, broker readiness, supervision, and deployment
gates remain separate.

A crate-private one-page reconciliation primitive snapshots scanner progress,
reconstructs the exact admitted CAR plan by manifest digest, reruns all bundle
verification under the callback-scoped lifecycle lease, classifies any retained
journal intent, and performs a qualified exact slot-59 inventory lookup before
enqueue. The inventory qualification is sampled before and after its exact
`get` under one timeout. A valid existing attestation whose payload exactly
matches the request suppresses enqueue, absence proceeds, and conflict,
qualification drift, rejection, or timeout fails closed. Only an absent request
is idempotently enqueued. A drop guard restores scanner progress, including its
generation, on cancellation and on every plan, verification, inventory, or
journal failure, so replay cannot skip a partially enqueued suffix. This is not
a durable deduplication boundary:
delivered rows may be pruned for capacity, and scanner progress is process-local.
The primitive performs no signing, inventory mutation, transaction submission,
or registry mutation and is not wired to a daemon child while qualified effect
composition remains open.

`irohad` prepares a third finalized-archive reader specifically for capture,
separate from the public and provider-ingest runtime readers. The underlying
archive lookup is replay-safe and does not advance the adapter's stateful
`active` cursor: a fresh read selects the visible finalized archive key, while
a continuation resolves the exact height/hash and reconstructs its core cursor
through a bounded first-page provider-state-root lookup. The stateful and
replay-safe APIs reject cross-use. The private signed-reader session wraps that
lookup with the exact-generation response cache described above and exposes no
raw capture accessor. The scanner separately retains the in-progress page
cursor, a monotonic finalized high-water, the last completely scanned cursor,
and its request generation. During one scanner lifetime, every subsequent
fresh scan at the same finalized head performs one bounded fully validated
first-page probe whose candidates are suppressed into an empty terminal page;
the successful probe still advances the generation, and a later head resumes
ordinary paging. This is not a persisted no-work watermark: restart creates a
new scanner and rescans the current finalized head.

The provider-attestation foundation is also implemented as an inert library
boundary. `MusubiProviderAttestationSignerV1` can approve only an opaque request
and exposes no transaction, queue, or registry API. Its signing helper
requires a production runtime handle, exact provider-owner authority, a
non-zero deployment-adapter revision and independently governed adapter-policy
digest, a domain-separated controller-policy digest over that exact `AccountId`
controller, and the governed signer policy and current eligibility both before
and after a bounded signing call. It rejects substituted payloads or approval
quorums. The adapter-policy digest is a separate binding, but semantic
independence does not require its bytes to differ from another policy digest.
An unchanged qualified signer must return the same canonical,
controller-key-sorted approval set for an exact retry, so timeout recovery
cannot choose another otherwise-valid multisig subset. This is a contract for
a deployment signer, not a stock concrete custody implementation. A private
daemon wrapper now pins the exact configured handle/revision/adapter-policy
digest, genesis-derived `NetworkId`, and local provider ID. It also reads the
finalized `State::provider_owners()` authority before and after the external
approval and rejects owner or adapter drift and substituted output. The sealed-
clock journal signing driver remains crate-private, and the wrapper is not
instantiated while activation is gated.

The public `MusubiProviderAttestationJournalRuntimeV1` type supplies the bounded
restart state machine, but its constructor, raw checkpoint snapshot, CAS
outcome/error types, store trait, and transition engine are crate-private. The
store must make a replacement durable before reporting success. An exact
successor already installed before cancellation or response loss is accepted
as `Stored` on retry even when the caller still presents its old predecessor;
a different successor at that predecessor conflicts. A private canonical
checkpoint records `AwaitingApproval`, claimed, approved, handoff, delivered,
and dead-letter states. Stable approval identities bind the attestation key,
payload signing hash, completed-row evidence digest, and signer policy; the
opaque request and credentials are never persisted, so approval after restart
requires a fresh completed claim and lifecycle-leased verification. Checkpoint
admission enforces byte, entry, decoder, and CAS-retry bounds, reserves a fixed
worst-case future-state footprint for each active entry plus the checkpoint
header, and proves writer output can be bounded-decoded back to the same
canonical value. Capacity pruning removes only the oldest delivered entries;
active work and dead letters are retained. The raw transition engine and every
API which accepts a caller-supplied UNIX timestamp are crate-private; the
daemon-facing runtime privately selects its qualified clock and exposes no timestamp
parameter. Native software custody uses a crash-durable host-time floor; separately authenticated
external clock semantics remain distinct. Neither host UTC nor local inventory proves finality.

The nested
`[sorafs.storage.provider_ingest_runtime.provider_attestation_journal]`
configuration is a bounded activation request, not an active worker. It is off
by default. `max_entries` is an independent count cap of 1--4,096 (default
1,024), while `checkpoint_max_bytes` is an independent viable byte cap of
4--128 MiB (default 64 MiB); the journal still rejects a write that exceeds
either cap. Enabling requires three complete public qualification triplets:
`clock_{handle,revision,policy_digest_hex}`,
`approval_signer_{handle,revision,policy_digest_hex}`, and
`inventory_{handle,revision,policy_digest_hex}`. Handles must use the canonical
non-test production grammar, revisions and digests must be non-zero, and the
digests must be canonical lowercase hexadecimal. The triplets have no defaults
and every binding field is forbidden while the table is disabled. Paths,
deployment nonces, endpoints, credentials, tokens, and keys remain absent.
Native completion-credential selection binds three fixed native effects. Explicit provisioning
atomically publishes all initial files under `provider-attestation-native`; ordinary startup refuses
missing or changed history. Native `iroha_fs` custody and one retained ownership lock fence journal,
clock and immutable signed inventory. Bounded blocking jobs retain the same ownership and admission
permit through actual completion even if the caller is canceled. The existing journal/capture loop
reverifies the admitted bundle and current full completion authority before deterministic approval.
The native daemon supervises that loop and lends the same inventory read side to the publication
factory. Inventory is local retention only: the existing archive-manager publication journal owns
Register signing and independent native inclusion. No single-provider result meets Musubi's
three-distinct-provider publication floor.

External selection still projects to runtime-provider slots 57--59 and retains independently
qualified seal/signer/inventory semantics. It is not relabeled native software custody. Stock native
startup rejects injected external substitutions, and non-native journal activation remains closed.

`MusubiProviderAttestationJournalFileStoreV1` is the inert public local-store
adapter for that CAS contract. On Linux and macOS it binds one root-fenced
two-slot layout with a fixed 128 MiB checkpoint/payload ceiling to the exact
genesis-derived `NetworkId` and provider ID. Descriptor-relative identity
checks, canonical checkpoint and generation validation, durable two-slot
commits, process-local single flight, and nonblocking normal-operation OS locks
reject online path/link substitution, torn writes, divergent lineage, and
concurrent successor installation. Its cross-process initialization lock uses
a fixed five-second deadline and ten-millisecond retry cadence, so daemon
startup cannot wait indefinitely. Composite sealed loads and mutations also
take a process-owned permit and a nonblocking cross-process lease on that exact
initialization-lock identity, which is committed in the immutable two-slot
headers and reopened existing-only below the retained journal directory. The
lease spans the external operation and local reconciliation, returns
`Unavailable` on contention, and is released on cancellation; an exact retry
after cancellation can finish the bounded local repair. Unlink/recreate cannot
split cooperating writers onto two accepted lock identities.

Slot 57's time namespace binds a small canonical generation/predecessor/floor
record to the exact `NetworkId` and provider scope. Its separate
checkpoint namespace binds that `NetworkId`, provider, and the exact
`MusubiProviderAttestationJournalPolicyV1::digest()` into a canonical scope,
then links canonical checkpoint-head records by their domain-separated Norito
digests. Hashing uses canonical encoding rather than ambient codec flags. The
explicit initialization path first proves the local cache empty and installs
the unique generation-one empty `H0` (`head = None`) after the time seal exists.
An identical `H0` is an idempotent retry. Ordinary open requires an existing
external `H0` or later head, never creates one, and never promotes local bytes.

Each journal mutation stores and exactly reads back the immutable checkpoint
blob under its existing checkpoint revision, advances and exactly reads back
the predecessor-linked external head, and only then advances the local two-slot
cache. The provider must retain the current head, its direct predecessor, and
every blob either can reference. The external head and named blob are
authoritative: an exact local match is accepted, while only an authenticated
exact direct predecessor can be repaired forward from the retained predecessor
record and blob. A deeper rollback, local state ahead of or forked from the
head, a missing/substituted blob, policy or scope drift, or unresolved mutation
ambiguity fails closed. A head's observed time must not exceed the separately
sealed time floor. Consequently, restoring or arbitrarily replacing only the
local file-store cache cannot make an older checkpoint authoritative.

The raw checkpoint snapshot/CAS contract, checkpoint-head orchestration, sealed
store wrapper, transition engine, and runtime constructor remain crate-private.
The public file-store initialization/open paths consume the store, enforce the
exact scope and retained policy, and return only the bounded journal runtime.
The implementation remains inert and is not wired into stock `irohad`; targets
other than Linux and macOS fail closed.

Restart discovery uses exclusive `(insertion sequence, approval ID)` pages for
due approvals, due handoffs, and dead letters. Claims are fenced by the exact
owner, entry generation, and absolute UNIX-millisecond lease. Every timed
mutation advances a persisted non-regressing UNIX-time floor; zero, rollback,
expired, wrong-owner, wrong-generation, or otherwise stale claims fail before
transition. Retry exhaustion and permanent failures retain their bounded
reason, attempt count, terminal time, and, for handoff failures, the complete
approved attestation. Operators can generation-fence either requeue or explicit
acknowledgement; handoff recovery reuses the retained attestation without
signing again.

Canonical inventory items bind exact `NetworkId`, archive/order, provider key,
complete attestation digest, and a stable handoff ID. The public sink contract
is idempotent: an exact replay returns the same non-zero inventory revision and
a different digest at the same immutable scope/key conflicts. Only the journal
turns that revision into an opaque local acknowledgement. The receipt has no
public constructor or Norito codec and is persisted through a private DTO.
Raw approval storage and final delivery transitions are crate-private, and the
inventory delivery driver accepts only the public runtime supertrait over the
sink and reader. That runtime adds a production handle, non-zero adapter
revision and policy digest, and a bounded payload-free readiness probe. The
driver fences those values and readiness around `put` plus exact readback. A
private daemon inventory wrapper now compares the exact configured
handle/revision/policy digest before and after every fallible call, including
readiness. It restricts put/get items and keys to the local provider and
validates every scope and returned value against the exact configured
`NetworkId` and requested archive/order. It intentionally performs no
`State::provider_owners()` lookup; ownership fencing belongs to the approval
signer. The wrapper and driver remain uninstantiated. The public contracts are
not an active network handoff or remote-authentication implementation, and
expose no transaction, queue, or registry mutation surface. Public readback
construction performs structural validation only; the deployment adapter
remains responsible for authenticating its source.

The reconciliation primitive uses the qualified slot-59 reader to authenticate
an exact scope/key result after rederiving and verifying the request. It samples
qualification before and after one exact `get` under the journal timeout. An
existing valid attestation must carry the exact current request payload to
suppress admission, absence permits enqueue, and any other item at that
immutable key, qualification drift, rejection, or timeout fails closed. This
still is not a long-lived deduplication guarantee once both the journal entry
and external inventory item are absent. The existing handoff driver performs
`put` followed by authenticated exact readback after approval.

The remaining deployment dependencies are:

1. extend the retained non-generic daemon coordinator from its implemented
   take-once `NodeHandle` plus exact prepared-reader tenure to exclusive
   ownership of the crate-private effect drivers, then wire the signed reader's
   finalized-completion capture/reconciliation child to enqueue and rediscover
   journal work. The
   child must rederive each request through the lifecycle lease, exact-read the
   authenticated slot-59 inventory before enqueue with the match, absence, and
   conflict behavior above, operate claims and dead-letter recovery, provision
   the local two-slot adapter, and bind it to a qualified combined slot-57
   provider for the separate sealed time/head namespaces and immutable
   checkpoint blobs;
2. provide and qualify the deployment-selected approval-only signer adapter,
   including replay stability, timeout, revocation, and controller
   policy changes. Storage completion, the pre-completion claim or receipt,
   and publisher-supplied registration evidence alone never authorize an
   attestation. Every signing implementation must satisfy the same provider contract;
3. qualify the adapter's bounded initialization and header-bound composite
   lease plus its Linux/macOS durability, corruption, capacity,
   concurrent-resume, cancellation, and crash-at-every-transition behavior.
   Run exactly one rooted runtime session for each external provider scope
   across machines, or require the provider to enforce an equivalent
   authenticated session fence; the local OS lease coordinates only processes
   sharing the same state root;
4. provide the authenticated and qualified provider-inventory/coordinator
   transport and activate the crate-private delivery driver. The coordinator
   independently retrieves a cryptographically verified V2-finality artifact,
   requires its execution commitment to match the exact result-bearing Kura
   block wire, and verifies the exact finalized archive-registration transaction, submits
   or reconciles canonical pin and replication operations, waits for each
   distinct provider completion, and returns the complete bounded provider
   attestations plus authoritative current archive/location state; the publisher
   durably registers those proofs one transaction at a time before the compact
   location CAS. Providers must not mutate the attestation registry directly;
5. qualify the daemon's current-State and admitted-advert-bound provider
   readback against independent replicas, live council admission refresh, and
   complete finalized State-root witnesses. Its fetch client denies redirects,
   pins bounded public DNS/IP answers, streams a committed-size CAR, and invokes
   the shared full-bundle verifier; and
6. supply the concrete combined time/head/blob durability provider, signer, and
   inventory providers, broker support, bounded readiness, supervised
   restart/shutdown behavior, and crash, cancellation, revocation, corruption,
   concurrent-resume, and platform chaos qualification. Resolve public policy
   and identity bindings through `iroha_config`, resolve credentials and
   signing keys only from deployment runtime providers, and remove the shared
   daemon pre-supervisor rejection only after the coordinator owns these
   boundaries.

`run_with_musubi_publication` is only the late-bound factory and supervisor
injection boundary; it is
not a production backend or finality adapter. Until the remaining deployment
dependencies are present and qualified, the stock launch must remain
`Unavailable`. An
in-memory adapter, latest-state query without transaction inclusion proof,
publisher-supplied evidence, ordinary SoraFS storage completion, or the retired
public Torii upload route cannot satisfy this boundary.

Active and yanked releases cannot lose their last healthy archive location.
Explicit location retirement or underlying pin/order invalidation must leave
at least three distinct current providers across the archive's remaining
locations. Deliberate provider removal may reduce that count while at least one
valid provider remains, matching the replica-degradation rule below.
Replica degradation removes a row from fresh selection and emits an alert but
does not rewrite release content. Before either updating availability or taking
an unchanged-state fast path, Core validates the archive record and embedded
identity, every active location's structure and exact storage key, the reverse
references, authoritative releases, resolver rows, and referenced packages.
Any divergence fails without advancing the resolver revision or projection.

## Policy, limits, and operations

`MusubiRegistryPolicyV1` has `Closed`, `Allowlisted`, and `Open` admission.
Closing blocks new archives, releases, and aliases only. Reads, repair, owner
recovery, and yank/unyank remain available. Policy is configuration/governance
state with deterministic defaults, never an environment toggle.

First-release defaults are:

- source payload: 64 MiB;
- bundle payload, including the three mandatory metadata entries: 96 MiB;
- CAR: 96 MiB;
- files: 4,096;
- chunks: 16,384;
- dependencies: 256;
- exports: 1,024;
- resolver graph: 1,024 nodes, depth 64;
- archive locations: four;
- fresh-selection replica quorum: three; and
- query page: 50.

Rust, OpenAPI, Kotlin, Java, and Swift validate the same archive bundle
ceiling. Their focused boundaries accept 64 MiB plus one byte as metadata
headroom and reject 96 MiB plus one byte.

Consensus maxima are fixed and may be larger than local CLI defaults. Every
hash, ordering, resolver choice, and state transition is hardware-independent.

Bounded events plus low-cardinality metric, dashboard, alert, and runbook
contracts cover publication phase age, replication shortfall, ingest
deadletters, integrity failures, cache corruption, stale cursors, unauthorized
governance attempts, and storage pressure. Only an authoritative long-lived
producer may materialize a series. Core, Torii, and the injected private
publication service produce their owned transition/rejection signals; journal
phase age, cache/capacity, selected-root storage, consumer fetch, restart-safe
shortfall alert qualification, and the remaining long-lived producer wiring
remain operational release gates. Paged Musubi queries preserve exact cursor
failures inside Core and map them to Torii's bounded metric reasons without
changing the public `Expired` query-error wire. An absent series is unknown,
not healthy.
Rollout proceeds
through a four-peer devnet, a five-to-ten namespace Taira allowlist with a
two-week soak, and a 30-day invite beta. Open admission requires zero
critical/high findings, completed recovery drills, load and chaos success, and
sustained SLO evidence.
