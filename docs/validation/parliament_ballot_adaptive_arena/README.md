# Conditional online typed-body arena evidence

This docs-ready package is staged for
`docs/validation/parliament_ballot_adaptive_arena`. It has not been published.
It preserves a fixed logical arena, actual source-component relocation, and
separately bounded valid/invalid/query bodies. It does not establish the full
adaptive proof game, entry/witness/controller costs, a primitive bridge,
physical initialization/workspace, current-candidate qualification, owner
acceptance, or independent cryptographic review. Production remains gated.

The current candidate has **58 owned tests** and **50 independent
tests**. The original55-test candidate and its review remain separate historical
records. A still earlier failed instrumentation capture (52 passed,3 failed)
is preserved separately: the new factory-identity guard intercepted sentinel
mocks before the exhausted-budget check. The revised interface checks exhausted
caps first; admitted operations still verify selected sources. None of these
receipts has been rewritten into the final candidate's evidence.

The sealed entry audit preserves all21 inspected source pins plus its four
records. Current sources additionally require an initially zero shared log and
counter, initial/boundary-clean K, external noninterference with persistent and
private registers, and the source components' actual contracts. Coin/purifier
zero-input counts and shared log/counter/work counts are distinct. Their sum
describes the logical zero-state input required for the explicit H/CX
construction. Supplied Bell-state acknowledgment is an unchecked premise,
not a claim of zero coins or physical preparation.

## Scope and preserved evidence

T valid supported bodies, I invalid supported typed bodies, Q external combined
lookups, query byte capacity C, width b, rejected-length envelope J, row and
log policy are explicit proposal parameters. N=(T+I)(2^20+2) is recomputed for
all W/L0 costs. No I is inferred from valid-only T; Q does not bound C or identify
the theorem's oracle-query convention. Rejected VOTE input retains3608+1024n
bits. Its cost maximum uses an attaining popcount witness rather than J alone.
Coordinatewise gate upper vectors and scalar elementary maxima stay separate.

All public/coin/output/purifier/query slots and shared clean work are fixed before
online shape selection. Actual rejected-size streams execute with output-driven
next selection and component inverses. Independent controls include a zero-log
two-query joint-state test. Full-M REG/VOTE factories are checked through
metadata and short prefixes; their complete streams are not executed. Reversing
the retained component trace does not reverse intervening external writes,
measurements, selections or controller history. No coin-unpreparation claim is
made. Iterator consumption is bookkeeping, not physical execution evidence.

`capture/`, `review/capture/`, `prior55/`, `prior-review/`, `failed-attempt/` and
`audit/` preserve original records. `logical-manifests.json` maps every original
manifest member to its exact archived or replay-input bytes, including older
source versions. Templates are inert archives. `inventory.json` identifies
their origin, while the outer `SHA256SUMS` seals the package.

## Exact replay dependencies

The complete current review restores 189 selected files; the
current and prior owner captures each restore172. The audit restores25 inputs.
154 common source files come from three already-published dependency packages:
`parliament_ballot_request_machine`, `parliament_ballot_lifetime_ledger` and
`parliament_ballot_content_resources`. `dependencies.json` pins each entire
dependency manifest. All other required source bytes, including the family
envelope, sequence and coin schema, are archived locally. There are no
unpublished package dependencies. This is selected-source replay, not the full
interpreter/standard-library dependency closure.

The live `crates/iroha_parliament_ballot_proof/Cargo.toml` differs from the frozen
catalog. Live replay refuses without JSON. Historical restoration retains the
original Cargo identity; it does not repair, repin or qualify the current native
candidate. Publication must wait for the owner's SCCP hold to be released.

Authenticate the outer manifest against the separately supplied package seal
and authenticate the helper **before executing it**. This example uses the
pinned helper bytes and lets the helper verify the supplied outer manifest,
all dependency members, replay inputs, original manifests and audit pins before
writing an absent destination:

```python
from pathlib import Path
import hashlib, sys
package = Path("/absolute/path/to/this/package")
repository = Path("/absolute/path/to/iroha")
destination = Path("/absolute/path/to/absent/replay-root")
manifest_sha256 = "<outer SHA256SUMS hash from the trusted package seal>"
helper = package / "restore.py.template"
raw = helper.read_bytes()
assert hashlib.sha256(raw).hexdigest() == "07602f963b6208cdf0cd44ca1f0ad3226a75bc8039aa1c033b15f62c393f932b"
sys.argv = [str(helper), "--package", str(package), "--repository", str(repository),
            "--destination", str(destination), "--manifest-sha256", manifest_sha256,
            "--source-set", "review"]
exec(compile(raw, str(helper), "exec"), {"__name__": "__main__", "__file__": str(helper)})
```

Named source sets are `review` (current merged review), `owner` (current58),
`prior55`, `prior-review`, `failed-attempt`, and `audit`. The restore helper
refuses an existing destination and verifies every recorded original manifest
regardless of the chosen input set. Historical failures are for inspection,
not qualifying controls. After restoring, the recorded owned pytest command
and independent `run_tests.py` can be replayed from that root. Package validation
records exact ordered collection/execution membership and keeps its results
separate from the original captures.

TODO: authenticated/priced entry and controller, unsupported/raw paths, full
cq and primitive proofs, owner acceptance, independent cryptographic review,
and physical/current-candidate qualification remain open.
