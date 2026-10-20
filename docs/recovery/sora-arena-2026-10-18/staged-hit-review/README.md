# Review-only native staged-hit candidate

This bundle contains an eight-file native component patch against commit
`8209033deae7409d800fcc576a63609a0c2c5f9d`. It was prepared outside the native
checkout. No native source, index, configuration, refs or commit were changed,
and no build was launched. Captured native guards before and after are equal.

- `native-staged-hit.patch`: four new AIR/adapter files, the shared fixture,
  complete existing changes to `integer_air.rs` and `checked_integer_air.rs`,
  and only the required five-line module registration from base `mod.rs`.
- `component-readme.patch`: optional new source-adjacent component note; it
  modifies none of the dirty native documentation.
- `manifest.json`: exact base Git tree and file blobs, base/candidate/observed
  SHA-256 hashes, unchanged native dependency hashes, exclusions, and evidence
  scope. The selected-file SHA-256 is not a Git tree ID.
- `base-snapshot/` and `candidate-files/`: review copies only.
- `apply-check.json`: successful read-only `git apply --check` checks against
  copied base files, with whitespace errors rejected. No patch was applied to
  the native checkout. `prepare_candidate.py` documents the construction.

The isolated candidate has NOT been built or tested. A full dirty-tree Core
integration run after the Copy fixes passed 2 tests with 1 ignored; it does not
qualify this isolated patch or prove the final source. The proof already run
used a source-sealed harness extracted from the full dirty native checkout,
with prebuilt pinned dependencies. Its complete artifact hashes were checked while creating this bundle. The
final candidate changes three Copy derives and refreshes only the source-hash
metadata in the fixture; all case bytes are identical. The two differing source
hashes and earlier fixture hash are recorded in the manifest. Final-source
proof regeneration is pending and was not started, following the user's stop
instruction. That earlier proof establishes
only one conditional public-snapshot ray-selection computation. It does not
prove authenticated World state, legal attack initiation, damage, a kill,
settlement, or a full 12-player match. Registration and qualification stay false.

The code dependency closure is eight files plus unchanged native dependencies
already in the base. Compilation remains unvalidated. Reproducing the separate
game runner additionally requires the current untracked native helper
`scripts/check_arena_geometry_stark.py`; this bundle records its exact hash but
does not silently include it. The helper, dependencies and full-tree evidence
must not be mistaken for artifacts supplied by the isolated patch.

Shared `integer_air.rs` is hashed by the Race source inventory, so this patch
changes the derived Race profile identity even though `proof.rs` is excluded.
The base Race qualification flag is already false. No backward-compatibility
aliases, historical-ID fallbacks or decoder paths were added.

GPG is absent from PATH in this environment. No unsigned native commit was
created and signing was not bypassed. A signed commit and isolated candidate
build/test qualification remain integration work. See `native-review-state.json`
for the observed branch, index, signing settings and exact repository policy.
The safe options are a signed commit using the configured local signing
identity once available, or preservation of this patch for a local maintainer
to review and commit with signing. Disabling signing is not an option.
