# B6 reversible write-frame preparation

Status: **conditional component proposal; not qualified**. This prices the
preparation and cleanup of the incoming record used by the
[reversible chronological log](parliament_ballot_b6_oracle_log_circuit.md).
Its [helper](../scripts/parliament_ballot_write_framing.py) and
[tests](../scripts/tests/parliament_ballot_write_framing_test.py) leave that
frozen construction, the security ledger, and production gates unchanged.
The [retained evidence](../docs/validation/parliament_ballot_write_framing/README.md)
records the exact source scope and results. TODO: complete the other simulator
and reduction resources, actual-input bridges, and independent review before
qualification. This component supplies none of those missing conclusions.

## 1. Supplied-field boundary

The [ideal public sampler](parliament_ballot_b6_ideal_public_sampler.md)
generates classical transcript fields and sampled challenge values. This
proposal represents those already available values in named computational
basis registers. Their derivation, validation, storage, selection/addressing,
namespace digest computation, trial counter generation and schedule controller
are outside the framing operation. In particular, supplying those registers
is an explicit interface boundary, not a claim that the native Rust runtime
already implements this quantum operation or that getting those values is free.

The exact pinned source inventory includes
[`profile.rs`](../crates/iroha_parliament_ballot_proof/src/profile.rs),
[`transcript.rs`](../crates/iroha_zkp_vole/src/transcript.rs),
[`hash.rs`](../crates/iroha_zkp_vole/src/hash.rs),
[`proof.rs`](../crates/iroha_zkp_vole/src/proof.rs), and the row/parameter and
sampler accounting sources. The profile prefix is the 13 literal bytes
`PARL/FAEST/v1` followed by the supplied 64-byte namespace digest for the
selected row and role. The digest is copied as data; it is not independently
sampled or replaced with a different namespace. The field sequence follows the
actual backend hash input, whose domain byte is appended **last**. The backend
adds no per-field length prefixes or extra serialization header here.

For `e=ell/8`, `c=10*ceil(g/8)`, the three records are:

| Record | Key after the 77-byte profile prefix | Value bytes |
| --- | --- | --- |
| Challenge 1 | `mu[64]`, `commitment[64]`, `corrections[(tau-1)e]`, `mult_corrections[c]`, `iv_pre[16]`, `salt[32]`, byte `09` | 264 |
| Challenge 2 | `challenge_1[264]`, `u_tilde[128]`, recovered `d_tilde[128]`, `masked_witness[e]`, byte `0a` | 104 |
| Challenge 3 | `challenge_2[104]`, recovered `a0[32]`, six transmitted `coefficients[192]`, `counter_u32_le[4]`, byte `0b` | 32 |

The recovered `d_tilde` and `a0` are supplied outputs of the preceding public
reconstruction. This packing does not recompute them or replace them with
independent values. `proof.rs` supplies `a0` before the six transmitted
coefficients to `Challenge3::new`; omitting it would incorrectly shorten the
410-byte key by 32 bytes. The transcript trial counter is a distinct 32-bit
register from the log's append-position counter. Its four bytes are least
significant first, as in `update_u32_le`.

The candidate has `tau=33, g=704`; comparator has `tau=22, g=696`.
Registration has `e=4480`; vote has `e=6688`. Complete key lengths are:

| Row and role | Challenge 1 | Challenge 2 | Challenge 3 |
| --- | ---: | ---: | ---: |
| Candidate registration | 144494 | 5078 | 410 |
| Candidate vote | 215150 | 7286 | 410 |
| Comparator registration | 95204 | 5078 | 410 |
| Comparator vote | 141572 | 7286 | 410 |

All three key-length formulas and all four row/role pairs are cross-checked
against the frozen sampler accounting. This establishes reviewed source
correspondence under exact input hashes, not automatic extraction of Rust
semantics or correctness of the surrounding computation.

## 2. Fixed scatter and cleanup

Use the existing incoming-record register of the log construction:

```text
[length: b bits] [key: W bytes] [value: 264 bytes],
W = 215150, k = b+8W, v = 2112.
```

Length and byte bits are represented least significant first. This leading
length register is the log's comparison encoding, not an added backend hash
input. The staging register starts at zero. Its key length is the full framed
key length `K`; all key bytes after `K` and value bytes after the domain's
actual output length `V` remain zero. Thus the result has precisely the
canonical padding required by the prior log interface.

The scatter first applies X gates for the one bits in `K`, the constant
literal prefix and the trailing domain byte. It copies each supplied field
bit and each supplied value bit into its designated staging bit using CNOT.
All wire indices follow the fixed selected row/role/challenge layout. They do
not depend on the content of any transcript field, trial counter, sampled
value or log record. This does not price selection of that layout by the
surrounding classical controller.

Every target is a distinct staging bit; every source control is outside
staging. The source registers must also be disjoint from **every** log slot,
the append-position counter, and append scratch, and must not be modified
while append executes. A finite wiring validator checks these disjointness
conditions in the composed tests. No source field is used as an append
position counter or temporary work bit. Staging is reused exactly as the
append input, not allocated a second time.

The scatter gates commute because their distinct targets never serve as
controls. They are self-inverse; replaying the same stream is therefore its
inverse (the explicitly reversed stream is equivalent). Append uses incoming
bits only as controls and leaves them unchanged. Apply scatter, the prior
unchanged append circuit, then inverse scatter. On the prior blank-next-slot
and capacity invariant, the combined map is

```text
|fields, log, append_count, 0_staging, 0_work>
    -> |fields, append(log, record(fields)), append_count+1, 0_staging, 0_work>.
```

This preserves the source computational-basis labels and clears staging even
when the appended key duplicates an earlier key. The log keeps each prior
record; the existing newest-match lookup semantics are unchanged. The joint
circuit identity extends by linearity, but copying coherent source labels
can entangle them with the log. It does **not** assert preservation of the
source's standalone reduced quantum state for an arbitrary coherent input.
The sampler boundary here supplies classical fields; no new superposition
proof-request API is introduced.

For framing alone, `b>=18` holds every supported key length. Composition must
use the **same** `b` as the previous lookup/append construction. That combined
interface's conservative honest-read envelope is 6,882,996 bytes and requires
`b>=23`; still longer external queries require a correspondingly large
explicit finite domain. The report separately states whether its selected
width meets that earlier honest envelope. The illustrative composition uses
`b=64`. A framing-only `b=18` report does not qualify the combined interface.

## 3. Exact counts and conservative envelopes

Let `pc` denote population count and let `L` be the 13-byte literal prefix.
For one record of key length `K`, value length `V` and domain byte `D`,
preparation **plus** cleanup costs exactly:

```text
X     = 2*(pc(K) + sum(pc(byte) for byte in L) + pc(D)),
CNOT  = 16*(K-14+V),
Toffoli = 0, additional base-oracle calls = 0.                 (F-1)
```

There are `K-14` variable key bytes because only the literal prefix and domain
byte are constant; the supplied namespace digest is a copied field. Counts
are independent of all supplied field/value bits. No gates address canonical
padding bits. With X and CNOT already elementary one/two-qubit gates, their
sum is the exact framing gate count. A simpler upper bound is

```text
G_frame(K,V,b) <= 2*(b+8*(K+V)).                              (F-2)
```

These counts exclude the separately priced append circuit. They add zero
clean work wires and reuse its `k+v` incoming staging wires. Supplied field
registers are reported as an interface inventory; they are not added again
to the sampler's existing logical payload. Initialization, source storage
and all other state remain separate obligations.

For `a` primary trials, the schedule appends Challenge 1, Challenge 2 and
**all** `a` primary Challenge 3 values. It does not append auxiliary trial
values. Successful and exhausted schedules therefore have identical framing
counts at the same `a`. The reported five contracts per row/role include
first/last success, first/last auxiliary success, and full fallback. They are
conditional count contracts, not observed random executions or proofs that a
particular sequence of trials occurs.

Let `M=2^20` and use the frozen logical payload

```text
P(a) = K1+264 + K2+104 + 442*a.
```

For `T` sequential requests, a conservative upper bound is

```text
G_framing <= 2*T*((M+2)*b + 8*463693396).                      (F-3)
```

The tighter component bound takes the maximum exact (F-1) sum over each
supported row/role with `a=M`, then multiplies by `T`. At `b=64` its per-request
maximum is candidate vote: **7,291,167,830** elementary gates, comprising
106,954,966 X and 7,184,212,864 CNOT gates. These are counts for this explicit
packing construction, not a lower bound, a feasibility estimate, or AES/
Keccak primitive calls. They make no quantitative security claim.

This omitted component can be added once to the old overlay's elementary
gate upper bound when the shared register/width and schedule premises hold.
It leaves that construction's `2*(Q_ext+741*T)` base-query bound unchanged and
adds no log/staging memory. It does not modify the frozen security ledger's
different oracle inventory, or imply that the new subtotal is a complete
simulator, entry reduction, or adversary resource vector.

## 4. Validation and unresolved obligations

The helper checks the previous frozen receipts/reports/helper/spec identities
before parsing their metadata, then every retained source and both Rust source
memberships. It checks the inventory again after accounting. The append
emitter used by finite composition tests is loaded from its exact reviewed
bytes; the old helper and frozen artifacts are not edited. Qualification
requests always fail, and output creation refuses existing files.

Tests independently construct the expected source-ordered bytes for all 12
row/role/challenge layouts, test actual largest-frame scatter/inverse and
padded smaller frames, compare emitted gates to exact counts, and exercise
little-endian trial counters and source-domain separation. A finite three-slot
composition runs the actual previous append emitter, including repeated keys
and a later different counter. It checks unchanged source labels, unchanged
staging through append, zero staging/scratch afterward, exact retained records,
source/log/counter/scratch disjointness, and inversion of the whole operation.
Negative controls detect omitted cleanup, changed domain/endianness, dirty
initial staging, input drift, added sources, malformed dimensions and illegal
schedules. Finite tests supplement the all-width disjoint-scatter argument;
they alone are not a proof of arbitrary quantum implementations.

TODO: price source field generation and addressing, counter/controller work,
validation, full query registers, the base oracle, remaining simulator work,
all reductions/hybrid multiplicities and final comparisons. Primitive
advantages and actual-input entry bridges remain unresolved. Physical 64 MiB
verification workspace, hardware qualification and independent cryptographic
review are separate requirements. All full-resource and qualification flags
remain false; production stays gated.
