# Pinned first-release history

These canonical frames contain the node-test genesis and two certified `Log`
blocks from four validators. The manifest pins their bytes, block hashes,
complete World root and execution tip. Strict replay must reproduce every
stored certificate and the pinned State.

The history uses the fixed 221-byte SCCP finality header followed by the canonical
execution-result body. Its World schema includes SCCP committee generations,
liability clock, degradation state, retained anchor state, `merge_hint_roots`
and `merge_global_state_root`. Native proposal, vote, timeout, echo and
signed-availability messages use the allowlisted SHA-256/DST_SIG consensus suite.
Changes to these canonical wire, State or signature formats require a fresh
genesis and store for this first release.

The 2026-10-20 capture was produced by `capture_pinned_first_release_history`
with four real validators, the current compiled SCCP profiles and the
confidential-policy digest. Its signed genesis uses a 16 MiB block cap,
10 MiB transaction cap and 64 KiB block reserve. Strict replay reproduces the
pinned World root and execution tip and rejects altered stored frames. Its digest
is recorded in `specs/first_release_history_cutover.json`.

This local fixture cutover does not reset or change a live network. The producer,
replay check and regeneration procedure are defined in
[`specs/first_release_history_cutover.md`](../../../specs/first_release_history_cutover.md).
