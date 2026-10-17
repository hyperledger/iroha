# B6 mathematical request-machine implementation

This milestone implements a source-bound Boolean-circuit model of one atomic
IdealFrontierSim request, with explicit gates, oracle calls, retained inputs,
intermediate lifetimes, canonical transcript writes, return projection and cleanup.
It is substantive simulator implementation progress; it does not qualify B6.1,
the current native candidate, or production. All whole-qualification flags remain false.
This record describes the captured mathematical implementation. The earlier frozen
`coverage.json`, `machine.py`, `README.md` and five-stage progress reports remain
historical checkpoints; their open-stage descriptions are not this milestone's inventory.

## Implemented scope

- P1 constructs the actual profile/namespace/statement frames using concrete SHA3,
  SHAKE circuits; Hmu/H4 use the separately supplied ideal F interface.
- S0 scans both bounded challenge tapes, retains first acceptance or the certified
  zero fallback, and produces the primary write prefix, counts, counter and exhaustion.
- B0/B1/V0/V1 are joined: the same selected challenge determines opening geometry,
  frontier routing, hidden indices, revealed seeds, concrete-AES expansion and CRT/VOLE.
- R0/R1 implement the source consistency and QuickSilver public response equations,
  actual ten-mask order, field arithmetic, relation streams and fixed-program error tags.
- W0 prepares exact domain-last frames, conditionally appends challenge1/2 and the
  active primary prefix, retains overwritten chronology, and charges disabled scans.
- E0 copies the source proof layout or primary-exhaustion return; the request join
  clears all derived stages in reverse dependency order using retained original inputs.
- Fixed-shape VOTE content handling for actual list counts 3..1000 now joins P0,
  totalized P1, the generator, validity-controlled writes and the typed return union.
  Rejected content contributes only the first public error, leaves log/counter unchanged,
  and contributes zero proof/length/last bits. Full temporary computation is charged.
- A separate typed VOTE header circuit checks vote value before the full 64-bit actual
  length, preserves source error payloads, and routes lengths 3..1000 to content checks.
  It trusts metadata of the same typed Vec; it does not parse/authenticate a wire request.
- L0 implements a lazy full-message chronological lookup with latest-match selection,
  full-key length comparison, long-message tails, two unconditional F calls and cleanup.
  Fixed-length family adapters and L0 are not yet joined into the full adaptive driver.
- The VOTE families share an explicit `253 + 8*proof_bytes` result register.
  Bounded content errors zero-extend both usize fields to 64 bits by static wire
  relocation. Rejected-size families preserve the full typed statement, read only
  its vote byte, and prepare the fixed actual length explicitly. Their cost is
  `5881 + 2*popcount(n)` elementary gates, 519 clean work bits and zero F calls.
  The borrowed list still counts as `1024*n` input bits; no large list is allocated
  by the metadata calculation. Classical selection must use the same authenticated
  typed descriptor. The adapters do not validate an untrusted length header.

The source role/row and supplied length family are classical typed API choices.
There is no invented invalid-row error or free pointer/length authentication.
The content return is a mathematical tagged register, not a new Rust enum/wire format;
XOR into an arbitrary target means zero contribution on rejection, not erasing that target.

## Exact accepted-request observations

The [accepted-request observation](capture/source/target/parliament-ideal-machine-stage/request-accepted-observation.json.template) binds 38 selected semantic inputs and 30 selected
implementation/dependency identities. Its four cases use M=2^20, T=2^44, b=64 and
N=T*(M+2) log slots. REG uses body4096 and six context256 lengths; VOTE uses 1000 entries.
They are exact metadata observations of the defined construction, **not a family maximum**.
The elementary convention is X+CNOT+5*Toffoli; F calls remain a separate resource unit.

| Row / role | Elementary gates per request | F calls | Total logical bits |
|---|---:|---:|---:|
| candidate REG | 166702860207775482406549993594785 | 6200 | 31790755097454965692929235 |
| candidate VOTE | 166702860207775482442106240502206 | 6200 | 31790755097454965700623659 |
| comparator REG | 166702860207775484234650177080306 | 5960 | 31790755097454971262262627 |
| comparator VOTE | 166702860207775484569800976451843 | 5960 | 31790755097454971269568443 |

The shared persistent log occupies 31790755097454963270352896 bits plus a 65-bit counter.
Each request count includes original public/private inputs, one caller return, all retained
stage outputs and the maximum reused scratch; W/E borrow fields without duplicate allocation.
Private input bits are 512*M+256*T_open+896*tau+tau*ell+10*g+736*8, including both full tapes.
F counts are 2*(8+8*tau+12+4*g), including the entire generator inverse; W/E add zero calls.
These accepted-only observations do not price P0/header handling or external L0 queries.
A separate real-factory content observation uses candidate VOTE/count3/M=1/T=1 only;
its reduced trial cap is a wiring/resource check, not full-cap execution or a new bound.

## Joint-state and accounting premises

All fixed/variable-length oracle instructions refer to one immutable function F on full
messages, with source-domain-padded 264-byte responses. H5 has exactly ten native bits.
Unknown/empty addresses require an explicit experiment-supplied total completion;
its acceptance is not established here. Concrete public hashes are not ideal-oracle calls.
Generator reads end in domains 0/1/4/5/8; programming ends in 9/10/11. With the canonical
log invariant and no adversary interleaving inside a request, generator uncomputation sees
unchanged responses. Appends use their true inverse, not a fictitious XOR-log inverse.
Phase-free basis maps extend linearly to correlated input/oracle/adversary registers under
these component contracts. Rejection's charged temporary F calls cancel jointly on cleanup.
Original coins stay retained; discarding a classical private mixture is not a free coherent
reset or permission to omit purifying registers in a fully coherent lifetime model.
The circuit has fixed scans and wire maps, not unit-cost quantum RAM or an unpriced native call.

## Captured evidence

The final captured suite passed **350 tests and 74 subtests**, with no failures,
errors or skips. Collection and execution used the same ordered 350 parent
identities. All 152 selected source files were unchanged in both the live
selection and the captured execution tree. This is a selected source inventory,
not a complete compiler/runtime dependency closure. The final receipt SHA-256 is
`a2461d6bc5b1ee066dcaa6a48bf3fe5639d0b886da6512358e5dd0c6eb835e69`.

The initial attempt also passed 350 tests and 74 subtests, but its wrapper
rejected the receipt because it misclassified subtest reports as duplicate
parents. That full attempt is retained in `attempts/attempt-1.tar.gz`. The
observer now distinguishes both kinds explicitly; two separate controls
verify passing subtests and preservation of an injected failing subtest.
The corrected capture was run afresh from its own source snapshot.
The current source snapshot is under `capture/source/`; source files have a
`.template` suffix to avoid repository-wide test or build discovery. Their bytes
are unchanged. `inventory.json` maps every copied artifact to its original path
and hash; `SHA256SUMS` authenticates the published layout. Original capture
manifests retain their original logical paths and hashes.
Retained review notes preserve their original bytes and local links; some of
those historical links need the restored source layout or the path mapping in
`inventory.json`. The links in this main record point into the published layout.

The central joins are the [accepted request](capture/source/target/parliament-ideal-machine-stage/request_transition.py.template),
[content rejection](capture/source/target/parliament-ideal-machine-stage/content_request.py.template),
[VOTE family adapters](capture/source/target/parliament-ideal-machine-stage/request_family.py.template)
and [full-message lookup](capture/source/target/parliament-ideal-machine-stage/l0_machine.py.template).

The independent reviews cover accepted-resource arithmetic, field wiring,
chronological writes, returns, full-message lookup, rejection wrappers, joined
content requests and the common error union. The AES, Keccak, public-framing
and response/lookup captures are retained with their original manifests.
These are local implementation reviews, not external cryptographic reviews.
The accepted resource report remains limited to its four cases. No actual
production-size elementary stream was executed.

The historical five-stage coverage report remains archived unchanged; its old
open-stage list is superseded by the implementation inventory above. Neither
report claims a complete adaptive experiment or a qualified profile.

## Remaining work before a complete B6.1 resource/qualification claim

TODO: compose the fixed families, authenticated classical selection, content/REG requests and L0
into the T-request/Q-query adaptive experiment, with full query-length/encoding conventions,
all error paths, caller/adversary storage and persistent history. Prove any family-wide maxima.
TODO: account initialization, fresh-input preparation, public descriptor authentication, all
retained/purifying coins, immutable-base-oracle state and costs, and external adversary work.
Per-request work with a lifetime-capacity log is not the complete T-request gate total.
TODO: establish actual-input PRG/primitive entry bridges, collision/cache consistency and the
accepted primitive-interface/resource assumptions; derive advantages without inserting guesses.
TODO: complete required owner/independent cryptographic review and the separate current-candidate
native, 64 MiB verifier-workspace and specified hardware qualification. These enormous logical
simulator registers neither measure nor satisfy that physical verifier contract. Production stays gated.

## Replaying the captured source suite

The snapshot runs independently of the mutable checkout's selected files.
From the repository root, restore it into a new ignored directory. The code
below verifies every copied source byte before writing it; it refuses an
existing destination. It does not install, build or enable production code.

```python
from pathlib import Path
import hashlib, json
capture = Path("docs/validation/parliament_ballot_request_machine/capture")
receipt = json.loads((capture / "receipt.json").read_text())
destination = Path("target/parliament-request-machine-replay")
inputs = []
for name, digest in receipt["source_sha256_before"].items():
    relative = Path(name)
    assert not relative.is_absolute() and ".." not in relative.parts
    data = (capture / "source" / (name + ".template")).read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest, name
    inputs.append((relative, data))
destination.mkdir(exist_ok=False)
for relative, data in inputs:
    path = destination / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
```

Then run the suite from `target/parliament-request-machine-replay` with a
Python 3.11 environment containing pytest 9.1.0, matching the local run and its
built-in subtest support. The captured command and exact
350 node identities are in the receipt; the following is a convenient replay,
not a replacement receipt or a new platform qualification:

```sh
PYTHONPATH=target/parliament-ideal-machine-stage \
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
PYTEST_ADDOPTS= PYTEST_PLUGINS= \
python3.11 -m pytest -q -o addopts= -p no:cacheprovider --noconftest \
  -k '' -m '' --maxfail=0 target/parliament-ideal-machine-stage/test_*.py
```
