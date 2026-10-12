# Pinned first-release history

These canonical frames contain the node-test genesis and two certified `Log`
blocks committed by four validators. The manifest pins their exact bytes, block
hashes, complete World root and execution tip. Strict replay must reproduce the
stored certificates and pinned State.

The 2026-10-12 capture comes from the actual
`capture_pinned_first_release_history` exporter. Its current World schema includes
native SCCP committee-generation, liability-clock, degraded-state and anchor
custody. Certified results carry the sole `CertifiedResultV1` fixed `X || body`
preimage with raw SHA-256 result identity. Native consensus signatures use the
allowlisted-preimage SHA-256 / `DST_SIG` suite.

This replaces the previous pin with an explicitly incompatible first-release
history. The declared surfaces are `state_layout` and `execution_root`, both
requiring `fresh_genesis`. No previous-history replay, root translation, alternate
decoder or dual signature verifier is provided. The new manifest records the
actual regenerated frame sizes and World root; they are not inherited from the
previous pin. This fixture change does not reset a live network or qualify SCCP
destination launch.

The digest is recorded in `specs/first_release_history_cutover.json`. The
producer, replay check and regeneration procedure are defined in
[`specs/first_release_history_cutover.md`](../../../specs/first_release_history_cutover.md).
