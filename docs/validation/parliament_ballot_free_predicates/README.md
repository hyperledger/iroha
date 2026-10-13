# Frozen System-free routing predicates

The twenty local checks pass for the original portable and accelerated ARM64
workers: ten explicit `free` frontiers per image in the earlier conditional
`Reservation::verify` graph. Each site forwards the same tested pointer to
System only through a null-arena or failed-range arm. **All ten unconditional
free frontiers per image remain OPEN.** The analysis does not prove that any
particular pointer is a live arena allocation.

The separate [report](analysis/report.json) retains all twenty instruction
snippets, private arena symbol identity, pointer origins, container word guards,
CFG checks, binary hashes and before/after input guards. The
[helper](../../../scripts/parliament_ballot_free_predicates.py) reads the frozen
[stack](../parliament_ballot_compiled_stack/README.md),
[failure-frontier](../parliament_ballot_stack_frontiers/README.md) and
[activation](../parliament_ballot_allocator_activation/README.md) evidence.
It never rebuilds or executes a worker, changes prior reports, or recomputes the
old manifests around new source.

## Exact local result

The two images identify the private `ARENA` symbol at `0x1000d4d48`. Every checked
routing block acquires that pointer, sends null to System, and otherwise uses
the same spin-lock sequence. The compiled loads read a heap word at offset 0
and byte count at offset 16; the lock byte is at offset 80. These offsets describe
the frozen machine code, not a stable Rust field-layout ABI. The pinned source
contains the expression `address >= start && address - start < inner.bytes`.

Let `P` be the tested pointer word, `H` the loaded heap word and `N` the loaded
byte count. The instruction sequence is:

- `SUBS P-H` sets carry iff unsigned `P >= H`.
- `CCMP difference,N,#2,HS` compares the difference only when carry is set.
  Otherwise it installs `NZCV=0010`, whose carry bit is set.
- `B.LO` selects the arena arm iff the final carry is clear.

The resulting arena predicate is exactly `P >= H && P-H < N`. When `P < H`,
the fallback flags reject the wrapped subtraction result. The check never forms
`H+N`, so it does not assume that addition cannot overflow. Null or a failed
predicate selects the System arm if the local path terminates ordinarily.
The four comparison classes are recorded explicitly; tests compare them with
an independently implemented extended-subtraction carry calculation, exhaustively
for four-bit words and at selected 64-bit boundaries.

The helper matches the entire acquire/lock/test/forwarding block, including
instructions between the flag-setting operations. It requires the acquire and
System pointer move to dominate the listed `free`, rejects an incoming CFG edge
into the middle of the block, rejects a bypass of the range branch on the
non-null arm, and checks that the in-range successor cannot reach that same
System site. The branch target must resolve to the imported `_free` symbol in
the frozen stub table. Unexpected instructions, operands, targets, aliases or
paths produce UNKNOWN.

There are eight statement pointer-word sites per image: one `VoteStatement`,
six `RegistrationContext`, and one `RegistrationStatement`. Their capacity-word
loads have **eleven branch guards**, since registration context fields 2, 4 and
6 each have an additional reload/`CBNZ` entry after the preceding field's arena
release. The guard set cuts every ordinary path to the relevant pointer load;
a claim that one lexical `CBZ` dominates each load would be incorrect. The other
two sites originate from the deallocation or reallocation ABI input pointer.
Register-preservation checks retain the ordinary callee-saved-register premise
across calls. The separate [source ownership audit](../parliament_ballot_ownership/README.md)
explains the seven registration owners versus one vote owner; these are
alternative roles, not eight simultaneous statement owners.

## Remaining obligation

Range membership is weaker than live-allocation provenance. A correct layout,
allocation lifetime, non-null arena lifetime, stable arena bounds and intact
private state remain premises. The helper does not connect every emitted
`free` operand to its originating allocation for all inputs. It also does not
prove callback or other-thread noninterference, lock termination, memory safety,
compiler correctness, native endpoint resource bounds, absence of traps, or
exceptional/unwind behavior. The prior provider and failure-frontier limitations
remain unchanged.

TODO: establish the universal ownership/noninterference obligations and bound
native and exceptional execution. This analysis removes zero unconditional
frontiers, assigns no complete stack or workspace bound, and leaves
`profile_qualified` and `complete_workspace_certificate` false.

## Validation and reproduction

The 32 focused tests pass. Independent review found and corrected two pointer-origin
labeling gaps: a changed pre-copy `x0` and a mismatched container base. Regression
tests now require entry-to-copy preservation and a common original object for
capacity and pointer loads. The final reviewed helper and test hashes are pinned
in the receipt.

The tests include both frozen images, symbol and native-target mutations,
range polarity/fallback/flag-clobber changes, wrong pointer forwarding, lock
register aliasing, capacity guards including the alternate joins, ABI input
changes, artificial CFG bypasses, pointer preservation through diamond paths,
unknown write shapes, missing evidence, and refusal to overwrite an output.

```sh
python3.11 -m pytest -q scripts/tests/parliament_ballot_free_predicates_test.py
python3.11 scripts/parliament_ballot_free_predicates.py \
  --output /tmp/parliament-free-predicates-new
shasum -a 256 -c docs/validation/parliament_ballot_free_predicates/SHA256SUMS
```

The output directory must be new. [validation-receipt.json](validation-receipt.json)
and [SHA256SUMS](SHA256SUMS) identify the final helper, tests, checks and report.
This is bounded engineering evidence, not an ISA proof or independent unsafe-code
qualification.
