# Independent conditional lifetime design review

Reviewed `target/parliament-lifetime-composition-stage/design.md` and the ten
selected source identities in `initial-read-pins.json`. This is a read-only
review of a conditional mathematical composition proposal. It does not certify
a driver, native execution, primitive entry bridge, or a uniform resource bound.
No captured machine file or tracked source was changed.

## Source correspondence and arithmetic

The proposed lifetime log capacity is `N=T*(2^20+2)` and the append counter width
`max(2,N.bit_length())` represents the full capacity. Every accepted generating
request makes at most `2^20+2` actual appends while paying for every fixed scan.
The request cap includes rejected requests; otherwise a separate rejected-call
cap is necessary. Starting from an empty canonical log, this gives sufficient
space before each of at most T calls. External L0 lookups do not append.

The nonzero-N L0 census agrees with its emitter's count expression: X is
`4*k*N+4*N+2`, CX is `4*k*N`, CCX is `N*(4*k+6+v)+v+2`, and there are two
unconditional calls to the provided F. Work is `2*N+k+v+2`. At zero capacity
there are v Toffolis, two F calls and v work bits. Query/enable/output registers
are additional caller interfaces; they do not belong in this scratch figure.

The original random input formula agrees with the source generator inventory.
The 384 iv_pre/salt bits and 5504 fixed challenge/response bits total 736 bytes.
The `(tau-1)*ell` correction bits plus ell masked-witness bits form `tau*ell`.
Both full schedule tapes contribute `512*M`; the remaining opening, hidden and
mask correction terms are retained separately. The generator's original input
count includes these coins, so extracting public U requires one subtraction,
not adding R to the entire original-input count again.

The complete request layout places its derived generator history H alongside a
shared work region S. Therefore a lifetime reusable region with size at least
`max(H_i+S_i, w_L)` can accommodate the stated clean component schedules. The
original coin and result slots remain outside it. Persistent log/counter and
oracle state are separate once-only regions. A disjoint allocation convention
is a legitimate conditional count; it does not implement routing or prove a
uniform preallocation over all adaptive branches.

## Adaptive state and boundary conditions

The design correctly distinguishes freshness at the entering history from
independence after conditioning on an entire completed adaptive trace. The
latter generally does not hold. A trace vector is resource bookkeeping, not a
replacement conditional sampling law. Applying each clean map at its entering
history, with the same F and no interleaving during the atomic request or L0
query, is the appropriate composition rule.

Neither equal return distributions nor the endpoint observations prove equality
of complete joint states. The log, append counter, F, private coins, caller
outputs, adversary state and reference must remain explicit. Preparing and
retaining coin purifiers adds resources; discarding classical random tapes is a
channel/environment assumption, not a unitary scratch reset.

The four captured accepted resource observations are four exact shapes. They
are not maxima over all registration lengths, list lengths, invalid content or
adaptive traces. A ledger may authenticate these cases and adjust the reviewed
W formula for a different common N/b; it must retain its narrower scope.
Accepted VOTE observations use the 97-bit return envelope. They do not include
the bounded-invalid-content P0/controller or its 253-bit common return union.

## Findings sent to the implementer

1. The sentence claiming preservation of arbitrary correlations “and aliases”
   must distinguish duplicate key values from physical wire aliasing. L0 has
   disjoint log, query, enable, response and scratch regions. Arbitrary
   correlations and entanglement across those regions are allowed; wire aliases
   are not covered.
2. Canonical query and active-record encoding must hold across the full support
   of the entering quantum state. A total completion of F on noncanonical
   encodings does not prove that L0's prefix comparison implements the intended
   overlay there, and it is not a free query-validation circuit.

The implementer agreed to both clarifications. Review of the forthcoming typed
ledger remains separate. Expected negative controls include wrong N/b/F,
unsupported source shapes, false source identities, source drift, result-width
confusion, capacity overflow, input/coin double counting and overlapping regions.

All whole-machine, primitive, physical workspace, current-candidate and
production qualification claims remain false.
