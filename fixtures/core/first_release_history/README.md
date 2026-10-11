# Pinned first-release history

These canonical frames contain the node-test genesis and two certified `Log`
blocks from four validators. The manifest pins their bytes, block hashes,
complete World root and execution tip. Strict replay must reproduce every
stored certificate and the pinned State.

The genesis uses the compiled SCCP profiles and confidential-policy digest,
and omits the retired `kagemusha_mint_finality` parameter. Its certified World schema
includes the canonical `world.asset_definition_direct_homes` table. Adding that
table changes the schema commitment even when it has no rows and requires a fresh
genesis cutover. This history was generated through
`capture_pinned_first_release_history` with the current strict genesis model and
four real validators. Its digest is recorded in
`specs/first_release_history_cutover.json`. Strict replay rejects certificates made
under the previous World schema; no compatibility decoder or root translation is
kept. This local fixture cutover does not reset or change a live network.

Declared cutover: by that effect on the stored history this is the surface
`execution_root` of the contract table (certified execution result), whose
cutover is `fresh_genesis`. The regenerated manifest pins new frames, block
hashes and certified result; the frame sizes and the complete World root are
those of the previous pin.

The producer, replay check and regeneration procedure are defined in
[`specs/first_release_history_cutover.md`](../../../specs/first_release_history_cutover.md).
