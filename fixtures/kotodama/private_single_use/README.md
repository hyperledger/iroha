# Native private-call comparison fixtures

Each row binds one complete `.ko` source to two artifacts emitted by the same compiler. The scoped compiler test guard retains ordinary private calls for the first artifact; the second moves each eligible sole-call helper body once. Both use identical source, ABI, declaration roots and public permissions. No alternate compiler mode or VM is involved.

`cases.rs` owns the complete source inventory and actual execution expectations. The compiler parity gate recompiles both variants and requires byte-for-byte agreement with `native_v1.tsv`. The maintained IVM group 05 consumer admits both native artifacts and executes constructors and public entrypoints through `DefaultHost` and `CoreHost`, checking typed results, all durable effects and exact checked faults. The production Core payout and default-fee qualification remain separate mandatory gates.

To regenerate, explicitly run `compiler::single_use_fixtures::capture_private_single_use_native_pairs` with `--exact --ignored --nocapture` from the current compiler test artifact. Save only the six tab-separated fields after `PRIVATE_SINGLE_USE_NATIVE`, in emitted case order. They are case identity, complete source hash, complete before/after artifact hashes and canonical before/after artifact hex. The fixture parser rejects missing, extra, duplicate, altered or oversized rows. The producer is maintenance, not a qualification test.

The checked-in seven rows are the output of that producer on the current compiler and sources; the compiler parity gate and the five IVM group 05 consumers pass on them. No binary bytes are fabricated or borrowed from another compiler artifact.

TODO: run the production Core payout and default-fee qualification on this capture; they are separate mandatory gates and no result of this directory establishes them.
