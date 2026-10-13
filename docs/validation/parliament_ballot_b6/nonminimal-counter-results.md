# Valid non-minimal counter regression

The standalone verifier accepts a valid later counter without requiring the
prover's first-acceptable-counter rule. Four constructive tests cover both rows
and both roles; vote cases use a three-seat list. Portable and accelerated runs
each pass all four tests with identical pinned later-proof digests.

| Row | Role | First acceptable counter | Second acceptable counter |
| --- | --- | ---: | ---: |
| Candidate | Registration | 232 | 336 |
| Comparator | Registration | 279 | 563 |
| Candidate | Vote, S=3 | 296 | 649 |
| Comparator | Vote, S=3 | 1007 | 1837 |

The test uses existing independent Python fixture intermediates and original
proofs. It verifies the original proof, regenerates its BAVC commitment and
original opening, checks all seven fixed QuickSilver coefficients, and enumerates
the bounded interval through the pinned second counter. Reopening the same
commitment at the later challenge produces an accepted proof. Changing only the
original counter rejects. The proof prefix remains unchanged, as do its IV and
salt. Each later proof's 64-byte SHAKE256 digest is pinned in the test and printed
in both run logs.

This is component acceptance coverage. It does not independently reimplement the
later proof construction, instrument verifier challenge-call counts, or qualify
the cryptographic construction or any hardware. The single counter evaluation
is a separate source-inspection fact. No library, protocol, production gate,
existing raw fixture, or historical measured-source manifest changes here.

The focused release-profile tests passed in 16.48 seconds portable and 3.14
seconds accelerated, as reported by the test harness. These durations are not
benchmark measurements. Strict Clippy with `-D warnings` passed in both modes;
the new test passed scoped Rustfmt. A separate read-only review found no
actionable defect.

Exact commands, compiler identity, binary hashes and scope limits are in
[`nonminimal-counter-receipt.json`](nonminimal-counter-receipt.json). Builds use
the `parliament-ballot` target slot and `--stable-local-metadata`, setting
`VERGEN_GIT_SHA=local-fast-build`; they are local regression artifacts, not release
or hardware qualification artifacts. The 92-file
[`nonminimal-counter-source.sha256`](nonminimal-counter-source.sha256) includes
the 81 source/build inputs of the reviewed standalone resource model, the new
test and shared support, eight original fixture files, and the Cargo wrapper.
It is not a complete transitive dependency/toolchain closure.

Raw outputs:

- [Portable tests](nonminimal-counter-portable.txt)
- [Accelerated tests](nonminimal-counter-accel.txt)
- [Portable Clippy](nonminimal-counter-clippy-portable.txt)
- [Accelerated Clippy](nonminimal-counter-clippy-accel.txt)

Run `shasum -a 256 -c
docs/validation/parliament_ballot_b6/nonminimal-counter-source.sha256` from the
repository root to check the source snapshot.
