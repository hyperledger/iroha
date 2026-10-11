# Kotodama V1 redesign implementation and acceptance

This is the execution ledger for the approved first-release syntax and usability
redesign. The canonical rules live in [the grammar](kotodama_grammar.md),
[numeric V1](kotodama_numeric_v1.md), and the IVM ABI schema/syscall sources.
Only the final ABI V1 design ships: no compatibility parser, call aliases,
edition switch, or alternative retired runtime path. Japanese branding remains
`seiyaku`/`誓約`, `kotoage`/`言挙げ`, `hajimari`/`始まり`, and `kaizen`/`改善`.

The [syntax and developer-experience goals](kotodama_devex_goals.md) track the
subsequent critique, unfinished integration and first-release semantic changes.
The implementation rows below do not close those additional goals.

## Active implementation milestones

| Milestone | Implementation | Required closure evidence |
| --- | --- | --- |
| Declaration and value semantics | Explicit named/positional modes, named struct patterns, composable Unit, shared declaration includes, explicit local/package exports, imported value types and authenticated static error text are implemented. | Fresh compiler tests: signature-only label changes, source-order evaluation, exact per-file diagnostics, stable local/package nominal identities, unchanged schemas after error wording edits, and identical artifacts after declaration splitting. |
| Collections and arithmetic | Checked/fallible list mutation, Result obligations, fused rounding, cursor types, bounded list loops, STATE_SCAN and seek-based hosts are implemented. | Four-validator execution; compiler/VM/Core tests cover rollback, unchanged fallible mutation, no implicit Result loss, rounding modes, representable fused results with large intermediates, pagination bounds and gas. |
| Shared boundaries and rejection | Unit/error schemas, signed descriptors, exact abort propagation, explicit rejection selectors and maintained SDK record consumers are implemented. Cursor schema propagation is implemented. | State/argument/return/nested-call roundtrips and malformed identity/schema/code rejection on the final ABI; wrong-stage test failures and restoration. |
| Authoring and onboarding | Immutable editor snapshot, semantic LSP, rich diagnostics, packaged editor client and staged standalone-test validation are implemented. | Fresh editor, CLI/LSP, offline-project and updated tutorial checks; network invocation remains part of release qualification. |
| Final release assets and qualification | Final V1 artifacts and the packaged editor client are implemented. | Fresh installed-artifact admission/runtime checks, combined Core/native SDK consumers, four-validator integration, then workspace validation. |

No milestone is closed by source implementation or by a test result from an
earlier schema revision. Tests requiring node consensus use four validators and mandatory
signed RS16 availability.

## Qualification boundary

Implementation milestones do not qualify the current release candidate. Compile
and run the affected compiler, VM, Core and maintained SDK consumers against one
canonical ABI V1 artifact set, including four-validator execution, restart and
installed native artifacts. The [native publication contract](../docs/norito_bridge_release.md)
owns release source and artifact provenance requirements.

## Instance storage and lifecycle replacement

Activation compares the complete admitted old and replacement `CNTR` state
descriptors. Every existing durable key retains its exact type, including map
key/value types, nominal identities, field order and list capacities. Removed,
renamed or retyped keys are rejected. Added maps begin empty. Added scalar keys
require `kaizen`/`改善`; before completing the hook, both native apply paths check
that each scalar has a present canonical value matching its exact replacement
schema. Successful noncommitting lifecycle simulations perform the same check
without consuming the pending hook. A staged deletion or wrong-schema value
fails this check. A canonical outer `Result::err` discards staged effects and
leaves the hook pending for another invocation. The compiler upgrade check
reports structural compatibility and initialization obligations; it does not
prove runtime initialization or execute the migration.

The required lifecycle `retained_code_hash` identifies the last bound complete
artifact, including an artifact with an unfinished hook. Suspension retains
this identity and the pending hook. Resuming the same artifact preserves an
unfinished hook and never replays a completed `hajimari`/`始まり`. Replacing a
suspended artifact uses the same state comparison as an active replacement;
replacement is forbidden while a hook is pending. Prepared authorization also
binds the lifecycle revision, so suspension and resumption invalidate previously
prepared effects even when the address, artifact and pending hook are unchanged.

## Ordinary enum identity

Ordinary `enum` and `error enum` share declaration, variant and exhaustive
pattern machinery, but have distinct nominal type descriptors and value atoms.
Both use explicit nonzero u32 codes with unique names and at most 256 variants.
Only error enums are raisable; ordinary enums remain valid values in either
`Result` branch. JSON uses exact variant-name strings, never numeric codes.

The required signed `enum_types` table is sorted by nominal identity and is
separate from `error_types`. It contains at most 256 declarations and 64 KiB of
canonical framed data. Every referenced ordinary enum descriptor in public,
callable, state and event schemas must exactly match its declaration. Boundary
nodes, state atoms, callable tags and schema hashes distinguish the two enum
kinds. Upgrades preserve the entire stored descriptor, including codes.

## Qualified products and imported calls

Every named product retains its declaring identity: `Unit::Type`, a locked
`package@revision::Unit::Type`, or the existing owner-bound local module path.
Unqualified struct identities are rejected in public, callable and durable
schemas. Compiler-owned query products use `kotodama::AccountView` and the
corresponding qualified view, `QueryPage` and `StatePage` identities; their source
spellings remain the familiar prelude type names. Reserved products still require
their complete canonical field and child-type shapes. An event payload is a
qualified product ending in its separately declared event name.

Imported interfaces come from complete admitted `.to` artifacts in the owning
source package's immutable artifact inventory. The inventory participates in
source identity and shares the source graph's input-count and byte limits.
Bindings retain the full artifact hash and the ordinal of the signed entrypoint.
A display alias cannot erase the nominal identity or choose between conflicting
schemas. Explicit type bindings select the exact canonical identity when shortened
paths would be ambiguous.

`CALL_CONTRACT` (`0xA9`) accepts the address Blob in `r10`, canonical NoritoBytes
`ContractCallBindingV1 { code_hash, entrypoint }` in `r11`, argument table/base
and exact word count in `r12`/`r13`, and a caller-owned writable result table/base
and exact word count in `r14`/`r15`. Empty arguments use `0, 0`; Unit results
occupy one zero word. All descriptors and transferred values are public. The
host preserves the six descriptor registers and writes only the result table
and newly allocated payloads. There is no selector-string or fixed-quantity
alternative.

The host resolves the live code identity, lifecycle and permission before
capturing arguments. Captured records retain their original execution-pool
charges through materialization. Child execution, input and result work share
the caller's gas budget. A failed result validation or local allocation refusal
rolls back the child; an outer `Result::err` also rolls back its descendants while
preserving the returned value and read dependencies. Views cannot enter mutating
entrypoints, lifecycle hooks cannot be nested, and active-instance re-entry is
rejected even through a view.

## Private sum payload addressing

`Option<T>` and `Result<T, E>` carry one heap handle through the V1 call table.
Their allocation holds the tag and the larger flattened payload; only the active
payload is written or read. Private product payloads can cross the 32 KiB signed
instruction-offset boundary: lowering computes the full address before the same
checked load/store. This does not change the 8,192-word call-table limit or the
existing public record, schema-node and schema-depth limits.

## Complete callable schemas

`EmbeddedCallableV1` carries an argument forest and one result tree, each a flat
preorder `CallSchemaV1` tape. Inline children preserve nominal products, finite
ordinary enum and error descriptors, both Result branches, List capacity and
element type, complete scalar-or-tuple cursor key schemas, and private numeric
roles. There are no child references or erased Sum/List roles. Table counts are
derived from the schema; Unit and empty named
products occupy one zero word. Private tapes permit 250,000 nodes and depth 256;
public records retain their existing 256-node limit. Each table remains bounded
to 8,192 words, independently of a handle's checked payload allocation size.

The sole callable wire body is `CS1\0`, a fixed little-endian `u64` node
count, then complete preorder nodes with one-byte tags. Struct names and ordered
field names use canonical Norito String and Vec<String>; nominal enums and errors retain
the complete length-prefixed canonical descriptor. Cursor nodes likewise retain
the complete length-prefixed canonical `EntrypointValueTypeV1` key schema.
Tuple arity is `u32`, List capacity and public scalar kinds are `u8`, and
internal/private pointer types are `u16`. Child length prefixes follow the
enclosing advertised Norito flags. The
node vector has no per-node enum-field wrappers or retained sequence span plan.
Decoding charges cumulative elements and the real node Vec backing before
allocation, preserves charged canonical string/error decoding, then validates
the complete forest. The former generic-vector wire body is rejected directly.

The JavaScript artifact boundary reads this same complete tape, including
reserved query-view shapes, nominal error catalogs, complete cursor key schemas
and private resource restrictions. Its bounded iterative traversal keeps the private limits
separate from public-record limits and rejects the retired shallow-role layout.
Structural validation of compiler output does not replace native artifact
admission or execution-proof verification.

Validation derives subtree ends and widths without allocating, and can fill
caller-funded traversal storage. Runtime traversal charges one gas before each
visited schema node, eight before each occupied scalar or handle word, eight
for a sum tag or sixteen for a List header, followed by existing staged pointer
validation charges. It checks the full reserved aggregate footprint and exact
List capacity, then visits only the active branch or logical List elements.
Inactive payloads and unused List capacity are not interpreted as values.
Authenticated callable lookup and these complete scans still require integration
with the production execution-proof relation; native validation is not proof
qualification.

## Bounded live scan contract

`STATE_SCAN = 0x010038` consumes `r10` canonical NoritoBytes(StatePath map),
`r11` canonical NoritoBytes(StateCursorV1) or zero, and raw `r12` limit 1..64.
`r13`, `r14`, and `r15` are zero. It returns `r10` canonical
NoritoBytes(Vec<StatePath>), `r11` next cursor or zero, `r12` selected count,
and `r13` examined count. Every input/output is public under the strict pointer
ABI policy. Admission marks this as a durable-state read; proven map prefixes
produce wildcard read metadata, while unresolved accesses serialize.

A cursor binds the authoritative host instance, map name, exact key/value schema
hash, complete key-schema hash and last examined canonical map path. Its canonical Norito frame
is at most 64 KiB. Every cursor node in the complete callable schema retains its
declared scalar or tuple key tree in `CallTypeNodeV1::StateCursor(EntrypointValueTypeV1)`,
including nodes below `Option`, `Result` and `List`. Argument and result validation
reject a canonical frame carrying a different key-schema hash. Keys contain only
supported scalar leaves and tuples of at least two elements; `Json` and live
handles are invalid. Scalar and tuple storage keys both use a canonical
`StateValueRecordV1` carrying the exact key schema hash.
The schema hash uses
`KOTODAMA_STATE_MAP_CURSOR_SCHEMA_V1\0` plus the complete canonical Norito
EmbeddedStateType::StateMap frame. Type identity and map position do not confer
authorization. Hosts validate the current declaration and read permissions on
every call. Production instance binding comes from the authenticated contract
address namespace; isolated local hosts receive a deterministic instance context.

Backing storage and overlays seek strictly after the cursor and merge in canonical
path order. Each distinct merged position consumes one candidate, including a
tombstone. The scan stops immediately after 64 candidates or N live keys; it
neither counts the map nor probes for another position. A bounded page carries
its last examined position even when its continuation will be an empty terminal
page. Deleted cursor keys remain valid. Later calls read current invocation
state and overlay; insertions before the cursor are not revisited. Values are
materialized only for selected keys, at most N, using their signed schemas.
