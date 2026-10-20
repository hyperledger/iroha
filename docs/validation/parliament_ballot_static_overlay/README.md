# B6 fixed-slot programming writer

The [component specification](../../../specs/parliament_ballot_b6_static_overlay.md)
and [implemented helper](../../../scripts/parliament_ballot_static_overlay.py)
replace variable-position append scans with fixed request/counter slots.
Earlier circuits and observations retain their original bytes and scope.
Development testing remains enabled; no profile or production activation is
qualified by this work.

## Implemented result

The lazy emitter writes one supplied record to one fixed vacant slot using
one CNOT and `k+v` Toffolis. Its supplied-field composition includes exact
transcript framing, validity/primary controls, trial constants and cleanup.
Inactive slots remain gaps. The existing coherent lookup selects the newest
active matching record, including when a later request has a shorter primary
prefix. No append-position counter or hidden QRAM access is introduced.

For candidate VOTE at `T=2^44`, `M=2^20` and a 64-bit length tag, the complete
supplied-field writer per invocation has:

| Resource | Exact count |
| --- | ---: |
| X gates | 127,926,486 |
| CNOT gates | 7,185,261,446 |
| Toffoli gates | 1,807,096,256,480 |
| Elementary gates (`X+CNOT+5*Toffoli`) | 9,042,794,470,332 |
| Base-oracle calls | 0 |
| Persistent log bits | 31,790,755,097,454,963,270,352,896 |

These counts price this writer, not a full request, family maximum or root
reduction. Persistent storage and the expensive coherent scan lookup remain.
Full-capacity outputs are symbolic metadata; the enormous gate streams were
not executed. No physical performance, workspace or cryptographic advantage
is inferred.

## Validation and provenance

```sh
python3.11 -B -m unittest scripts.tests.parliament_ballot_static_overlay_test -v
python3.11 -B scripts/parliament_ballot_static_overlay.py \
  --request-cap 17592186044416 --row candidate --role vote --length-bits 64
```

All **nine tests pass**. They exercise the emitted permutation, arbitrary
target XOR/inverse behavior, disabled slots, framing and clean work,
retained old counter entries, a correlated superposition write/lookup state,
full-capacity row/role metadata, source refusal and CLI behavior. Small trial
caps are explicitly synthetic circuit tests. The production metadata command
always uses `M=2^20`; `--require-qualified` exits 2.

The root capture ran the suite, help, four row/role metadata commands and the
qualification refusal. All 20 scoped source/antecedent/helper identities stayed
unchanged. The ordinary and refusal candidate-VOTE JSON outputs were identical.
Three local readers checked circuit/source correspondence, the storage/order
argument and the limited-independence research paragraph. This is local
consistency review, not independent cryptographic attestation.

The [receipt](receipt.json) and [input hashes](inputs.json) state the scope.
Retained outputs are [tests](tests.txt),
[candidate REG](candidate-registration.json), [candidate VOTE](candidate-vote.json),
[comparator REG](comparator-registration.json), [comparator VOTE](comparator-vote.json)
and [checks](checks.json). [SHA256SUMS](SHA256SUMS) also binds the helper,
tests and specification with repository-relative paths.

The helper itself authenticates two reused helper files. The capture's wider
20-input scope is still not a transitive interpreter/build dependency closure.
No Rust suite or physical-device run was needed or rerun for this mathematical
Python component. No older build is reauthenticated against current sources.

## Remaining boundary

The root/material source audit derives `Q_all+1445*T` semantic ordinary reads;
dispatch and compute/uncompute still need separate accounting. The component
receives a valid classical invocation ordinal, generated fields and flags.
It does not implement their controller or their source generation. A coherent
outer-call arena needs its `T+I` invalid-request allowance unless an explicitly
priced valid-ordinal controller replaces it.

TODO: integrate the complete root driver and total oracle dispatcher, bound
all external message/register sizes and base evaluations, and implement/price
the independent-function environment. Quantitative primitive premises,
complete runtime/hardware evidence and independent qualification remain open.
