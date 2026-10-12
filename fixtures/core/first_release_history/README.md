# Pinned first-release history

These canonical frames contain the node-test genesis and two certified `Log`
blocks from four validators. The manifest pins their bytes, block hashes,
complete World root and execution tip. Strict replay must reproduce every
stored certificate and the pinned State.

This history uses the fixed 221-byte SCCP finality header followed by the canonical
execution-result body. Its World schema includes the original SCCP committee
generations, liability clock, degradation state and retained anchor state.
Native proposal, vote, timeout, echo and signed-availability messages use the
allowlisted SHA-256/DST_SIG consensus suite; their old generic BLS signatures
are rejected. These wire, State and signature changes require a fresh genesis;
the previous history is not decoded or translated by the current binary. The history was produced by
`capture_pinned_first_release_history` with four real validators, the current
compiled SCCP profiles and the confidential-policy digest. Its digest is recorded
in `specs/first_release_history_cutover.json`.

This local fixture cutover does not reset or change a live network. The producer,
replay check and regeneration procedure are defined in
[`specs/first_release_history_cutover.md`](../../../specs/first_release_history_cutover.md).
