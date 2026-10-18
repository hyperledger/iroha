# Explicit chronological oracle-log circuit

This bundle preserves the conditional construction in
[`parliament_ballot_b6_oracle_log_circuit.md`](../../../specs/parliament_ballot_b6_oracle_log_circuit.md),
its source-pinned accounting helper, and 21 finite circuit/refusal tests.
Root and ownership completed automated local consistency reviews; neither
is an independent cryptographic review or an owner qualification attestation.

The construction scans every fixed log slot, preserves the latest matching
write, and restores all work registers. It has explicit reversible append
costs and uses two unconditional base-oracle calls per lookup. Full message
tails reach the base oracle, even though equality compares a bounded head
and length. The exact X/CNOT/Toffoli counts and a specified five-two-qubit
Toffoli conversion are separate from base-oracle implementation costs.
It assumes no quantum RAM, free memory lookup, or implicit address routing.

`report.json` uses illustrative `T=2^44`, `Q_ext=2^64`, `b=64`.
`zero-request-report.json` uses `T=0`, `Q_ext=7`, `b=64` and still charges
enabled base dispatch. The large gate total is an upper bound for this
particular padded fixed-scan construction. It is neither a lower bound on
other constructions nor proof that the full B6.1 budget is satisfied or
impossible. Primitive calls and gates are different units.

The receipt binds 65 earlier frozen inputs before and after capture, plus
the executing helper/test/spec identities. `sources/` preserves exact
copies of those three new artifacts. These copies are provenance snapshots;
the reproduction commands use their canonical repository paths. The
captured `--require-qualified` run exits 2 and has exactly the ordinary
report's stdout. No previous frozen artifact or production gate is changed.

From the repository root:

```sh
.venv/bin/python -m pytest -q scripts/tests/parliament_ballot_oracle_log_circuit_test.py
.venv/bin/python scripts/parliament_ballot_oracle_log_circuit.py --root . --request-cap 17592186044416 --external-query-cap 18446744073709551616 --length-bits 64
.venv/bin/python scripts/parliament_ballot_oracle_log_circuit.py --root . --request-cap 0 --external-query-cap 7 --length-bits 64
```

`SHA256SUMS` uses repository-relative paths and excludes itself. It binds
the three canonical new artifacts as well as their snapshots and the
bundle's reports, receipt, commands and logs. Reproduce its check with
`shasum -a 256 -c docs/validation/parliament_ballot_oracle_log_circuit/SHA256SUMS`.

The mathematical entry from real primitive calls, quantitative primitive
advantages, complete reduction costs, base-oracle implementation, physical
memory/routing/error correction, and independent review remain open.
Logical circuit wires do not certify the physical 64 MiB verifier
workspace. Full-resource and production qualification remain false.
