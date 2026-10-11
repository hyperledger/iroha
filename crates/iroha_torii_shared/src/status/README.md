# Status wire ownership

`iroha_torii_shared::status` is the canonical Rust import path for the Torii
`/status` response and its capability snapshots. Private modules group common,
consensus, Nexus, governance, gossip, and Taikai records. The DTOs depend on the
codec and schema library; they do not collect metrics or read node configuration.

`iroha_telemetry::metrics::Metrics::status_snapshot()` collects live node values,
including build metadata and compiled cryptographic capabilities. Configuration
conversions for Nexus routing are implemented by `iroha_config`. A default DTO
contains empty values; it cannot discover the capabilities of the serving node.

`fixtures/torii/status_wire_golden.v1.json` records fully populated JSON values,
complete Norito frames, and serialization/deserialization schema identifiers for
all named payloads. Historical owners were captured before extraction; current
first-release DTO changes use scoped recaptures from the compiled Rust codec.
`examples/capture_diagnostic_status_wire.rs` captures `DiagnosticTraceStatus`,
`CryptoStatus`, and the enclosing `Status` after local trace settings replaced
the retired proof-engine status. The identity fixture records capture hashes. `tests/status_wire.rs` verifies these frames and roundtrips without
regenerating them. The explicit schema identifier strings are wire identities,
independent of the Rust modules containing the records. Field order and existing
Norito attributes remain part of that contract.

Arbitrary generic envelope identities (for example a standalone `Vec<Status>`
frame) still require the foundational Norito canonical schema-name work. The
named-payload golden tests do not qualify those generic envelope headers.
