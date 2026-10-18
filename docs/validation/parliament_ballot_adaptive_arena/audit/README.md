# Conditional adaptive typed-body entry audit

This is a source-grounded proposal, not owner acceptance, a complete experiment
resource theorem, a cryptographic review, or production qualification. The
frozen family bounds, fixed-sequence binder and coin wrapper support the
conditional construction below. No broad adaptive game model is implemented by
this audit. `source-pins.json` identifies the inspected bytes; historical source
replay must preserve the existing catalog, including its Cargo identity. Live
candidate drift cannot be repaired by repinning those captures.

## Entry and composition boundary

Property 5 in `specs/parliament_ballot_proof_arguments.md` supplies adaptive
**classical atomic** `Prove(role,x,w_app)` requests. Both worlds first perform
public validation and the application relation check. Invalid requests return
the prescribed error without invoking the simulator. Therefore a public-valid,
witness-invalid request cannot run the accepted request body. Bounded invalid
VOTE content is supported by the source ContentFamily conditional contract;
that body overcomputes and cancels temporary/oracle work and preserves the log.
It does not implement the game's application-witness or raw-entry rejection.

The hidden-assignment deletion and hybrid-driver specifications count at most
T **valid** requests, require fresh independent private randomness and permit
adaptation to preceding observable execution. They do not infer any bound on
invalid calls, direct verification, raw parsing or context preparation. External
queries after the last request still count. Atomicity does not price internal
computation or erase earlier oracle queries.

Let T, I and Q be separately supplied caps on valid supported typed bodies,
invalid supported typed bodies, and external combined lookup calls. Let C be an
independent message-byte cap, with C >= 6,882,996 and C < 2^b. Canonical length
and zero padding must hold on the query's full coherent support. `F:variable`
must implement the same immutable F and agreed total completion as fixed F;
this is an external contract, not a free adapter. Q is not yet identified with
any cryptographic theorem's oracle-query convention.

## Explicit conservative geometry

Propose S=T+I, S<=2^64, N=S(M+2), M=2^20. This is an explicit additional
experiment policy, not an adopted theorem constant. Recompute all W and L0
costs at N and b. The current Sequence reserves M+2 for each generating call,
even public-invalid ContentFamily calls. Keeping N=T(M+2) while adding I calls
is not supported by that binder. A sharper policy would need an authenticated
entry classification and a new occupancy/admission proof; a caller validity
flag or unproved reservation refund is insufficient.

For S=0, only the actual zero-log lookup factory is applicable; skip all
request-family construction rather than silently changing S to one.

The typed domain is REG body 0..4096 and six contexts 0..256; VOTE content
3..1000; and rejected VOTE size n outside that interval, n<=J<=2^64-1.
The universal mathematical rejected-size choice J=2^64-1 is finite but does not
attest native Vec reachability. Its borrowed input is 3608+1024n bits and must
be charged. A smaller J is an explicit further policy. Finite I alone cannot
bound arbitrary raw input, witness checking, malformed proofs or optional
digest/verification helpers.

## Fixed arena before online choices

Choose one source row per arena. Allocate S disjoint request slots, Q disjoint
query slots, one shared log/counter, and one maximum boundary-clean work region
before any branch selection. Each request slot has public P*, original coins
R*, returned output O*, and retained purifier R* regions. Use source role
maxima, not a completed trace. For the candidate row, R*=538737664 and
O*=1864349; P*=max(46592,1027608,3608+1024J). Preserve each component's typed
return encoding within O*: padding does not unify REG and VOTE schemas.

Writing W=215150, v=2112 and d=max(2,bit_length(N)), the known register bound is

    N(1+b+8W+v) + d + S(P*+2R*+O*) + Q(b+8C+1+v) + K,

where K=max over allowed requests of retained_G+max(Gscratch,Wwork,Ework),
the actual L0 workspace, and rejected-size workspace 519. With S=0 omit all
request maxima. Control/history/descriptor storage and caller routing remain
outside this known arena rather than being assigned zero.

Relocate actual typed components by separately mapping their public and coin
input subintervals into fixed slots; public-length changes must never shift
coin addresses or earlier slot addresses. Log/counter map to their persistent
regions; retained G and clean scratch map to K. Fixed F operands are renamed;
each variable F input/output span must fit one contiguous mapped interval.
Caller public/query/XOR-target preparation is external. It may not alias
private coins, future purifiers, shared work, or log.

Prepare all S maximum private banks once: S R* Hadamards and S R* CNOTs,
2 S R* initially private clean coin/purifier bits, retaining every purifier and
unused bank. Do not condition preparation on a completed adaptive trace.
Under initial product freshness and noninterference, induction on the
classical history h leaves every unconsumed bank product with the cq entering
state. Classical branch selection cannot inspect a future bank; its chosen
prefix has the required uniform mixed marginal after the purifier is traced.
Each source atomic isometry restores K and preserves disjoint future banks.
This is a conditional component/cq composition lemma. A native/coherent
controller, its cost, and the complete game theorem remain open.

## Known gate bound and unknown terms

For each gate coordinate g, let V_g(N,b) be the valid REG/VOTE family maximum
and J_g(N,b,J) the bounded public-invalid VOTE/rejected-size maximum. Then

    body_g <= T V_g + I J_g + Q L0_g(N,b).

This statement is conditional on authentic entry classification. It does not
invoke accepted bodies on witness-invalid inputs or assign unsupported raw
paths zero work. A coarser bound S*max(V_g,J_g)+Q*L0_g is also valid. Preparation
H and CNOT counts are separate. Coordinatewise maxima need not be jointly
attained: REG's X maximum is at 4095/255, while its elementary and storage
maxima are at 4096/256. Preserve exact elementary maxima separately from the
elementary value of the synthetic coordinatewise upper vector.

For N>0, k=b+8W, L0 has X=4kN+4N+2, CX=4kN,
CCX=N(4k+6+v)+v+2, F=2 and clean work 2N+k+v+2.
For N=0: X=CX=0, CCX=v, F=2, work=v. Rejected-size elementary cost is
5881+2 popcount(n), work519, coins0, F0. Each external lookup charges two base
F calls. Request bodies additionally charge their own base calls; no theorem
query bound or primitive implementation follows from this ledger.

Unknown additive terms: entry/public/raw/witness/descriptor validation;
admission and adaptive selection/control/history; caller input and output
routing; context and direct verification counts; adversary work/state; base F
implementation/state; initialization/reset/physical layout; primitive bridge
and advantage bounds. Owner acceptance and independent cryptographic review
remain unaccepted.

## Minimal next implementation proposal

`Budget(T,I,Q,C,b,row,J,log_policy)` requires every cap and the explicit
`conservative-total-calls` policy. `ArenaPlan(budget,catalog)` allocates only
arithmetic intervals and bounds. Actual source factories build REG,
ContentFamily, rejected-size and lookup components. An online binder checks
source identity, widths, geometry and budgets before appending an immutable
chosen-call receipt. It accepts external entry-contract labels as premises,
not checked application truth. Unsupported entry classes are refused.

`emit_bound_call(receipt)` uses that component's real emitter and a fixed
relocation. `emit_chosen_inverse()` reverses the retained chosen trace and each
actual component inverse. It does not reverse the external controller or its
measurements. `emit_coin_preparation()` emits fixed H/CX banks and does not
allow repeated preparation under the online lifecycle.

Tests should cover selection after previous output, stable earlier mappings,
separate T/I/Q refusals before mutation, all-call source drift, actual source
factory metadata, exact versus upper maxima, S=0 lookup-only behavior, and
true inverse on retained chosen traces. No caller-supplied cost reports or
arbitrary component callbacks should be accepted by the source API.

TODO: implement and independently review that limited arena checker, then
address entry/controller costs and the full experiment only with explicit
additional contracts and evidence. All production and qualification flags
remain false.
