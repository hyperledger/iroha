# KAGEMUSHA A-split context framing v1

This record fixes the implementation framing of Lambda §2.8. It describes the
context and proof-ownership components in `iroha_kagemusha_proof::a_relation`.
Bootstrap now composes its genuine initial-state sigma, recursive proofs and
authenticated signed objects. This record does not establish qualification of
all operation variants, the final Omega artifacts, or native lineage acceptance.

`C = P_Fp(kgwctx_1, items)` commits the immutable operation context with the
ordinary RP57 domain/arity framing. Fixed-stage frames use the distinct
`kgwlink1` domain below. Both differ from the final lineage domain `kgwomg_1`.
`ContextPlan` fixes every presence flag, group length and ordering at keygen.
No stage accepts a witness-supplied list of obligations or object kinds.

The item order is:

1. Version `1`, operation code (one-based order of `ledger::Variant::ALL`),
   initial-stage schema marker `1`, predecessor-verification stage (`0` absent, otherwise
   the one-based stage), total stage count, total Q count, object count.
   Each stage then contributes its Q count and ordered Q indices, then its
   operation-task count and ordered task codes. Every Q index occurs once.
   `ContextPlan::with_operation_tasks` requires the complete named task set
   exactly once: Bootstrap state/authentication (codes1/2), Load recovery/
   authentication/current-credential (3/4/8), or Send objects/pending/fee-and-carry/
   own-authorization/consuming-proof (5/6/7/9/10).
   `LoadStagePlan` and `SendStagePlan` execute the groups assigned to their fixed
   stage. Each authorization task must share its owning signature-Q stage.
   Send's consuming-proof task must share the hard predecessor stage. A generic frame
   component has empty task lists and cannot qualify an operation artifact.
2. For each Q in descriptor order: complete base-field VK digest, descriptor
   digest low/high128 limbs, instance-column count, and each column length.
   For each object: its nonzero unique category tag and fixed byte capacity.
   A complete Receive task plan then appends its active-source representation
   marker `kgwcrcv1,4,3` (fixed object index4, three commitment words), typed-Q
   marker `kgwcqtp1`, and the result namespace `kgwrslt1`,
   count5 and the five ordered `(tag, zero-based owner stage)` pairs. Owner
   ordinals are checked u32 constants; this group is absent for other variants
   and generic frame-only components. It also fixes `kgwrpop1,35` for the
   original incoming Omega opening and `kgwrcls1` followed by the exact Omega,
   own-sigma and incoming-sigma `(k, descriptor-digest low128, high128)` triples.
3. Own statement26, followed by incoming statement26 exactly when that sigma
   slot exists.
4. Predecessor core33/rest8/public18 and both transported Pallas/Vesta claims
   when present, then successor
   core33/rest8/public18. State opening hashes and their public-header binding
   are constrained on the shared verifier hash lane.
5. Incoming original public18, its constrained encoding/version/width validity,
   Pallas claim and Vesta claim, when incoming Omega exists. Non-Receive frames
   additionally retain actual LE32 proof length and every original Omega
   message as two exact little-endian128-bit halves, with count fixed by the
   admitted descriptor. The high half is constrained as high127 + 2^127·top1;
   both halves are below2^128<Fp, preserving all256 bits of malformed encodings.
   The mandatory Receive active-source schema instead binds the original tape
   through fixed object index4 in item7; only its Proofs owner decodes messages.
6. Every Q instance, column-major in descriptor order. Non-Receive contexts
   encode every canonical scalar as low128/high127. Receive encodes declared
   Bounded and Bits0..253 instances as one native word after constraining the
   exact declared membership, so the integer is strictly below Fp; Field and
   wider bounds retain the two-limb representation. The fixed descriptor drives
   this framing, never a witness choice. Every stage rebinds the entire original list and
   copy-binds its fixed partition to its own hard verifier outputs. A previous
   stage's verification cannot be silently reassigned to the current stage.
7. For each object: authenticated-object digest, actual LE32 length, tape digest.
   The tape digest is `P_Fp(kgwctap1, [tag, capacity, chunks...])` over the exact
   `LE32(actual_length) || fixed_buffer` carrier, split into consecutive31-byte
   little-endian integers, with the final short chunk. Length and message bytes
   come from one constrained byte tape. A length above capacity is representable
   because a malformed incoming object must be able to produce a soft failure;
   this context layer does not claim to authenticate an object. Hard fixed-size
   own objects can instead use `from_exact_run`: the same semantic parser tape
   is reblocked with a pinned LE32 length, without assigning another byte copy.
   Total original-byte consumers use `from_active`: `ActiveBytes` proves the
   exact u32 length and a zero inactive suffix. Its separate-domain commitment
   is `P_Fp(kgwcact1, [tag, capacity, length,
   P_bytes(kgwcact1, LE32(length) || active_original_bytes)])`. This cannot
   substitute the padded descriptor-sized verifier view for the original
   short or overlong string. The raw Omega/sigma consuming digest similarly
   concatenates their active length-prefixed strings without intervening padding.
8. Mode triples Accept/Trivial/Corrected in order: incoming Pallas, incoming
   Omega opening, incoming Vesta, incoming sigma, omitting absent groups.
   The continuation retains and copy-binds these original public fields,
   claims, modes and corrections to its incoming verification and selection
   outputs. Non-Receive frames copy-bind proof messages; Receive copy-binds
   its active tape triple and fixed-owner opening under the mandatory exception
   in item5. Native correction coordinates follow for the first two, then foreign S6
   x/y coordinates for incoming Vesta. The sigma correction belongs to the hard
   Q relation and is not an unused A context field.

For a complete Receive task plan, exactly five boolean proposed result values
and the 35-word original incoming Omega opening follow the object commitments
and precede the modes. `ReceiveResultClaims`
checks their Boolean representation and owner schema but exposes no acceptance
verdict. Their typed owning stages must derive and bind all predicates; the
context commitment alone is not evidence that any predicate was executed.
The Proofs owner precedes the terminal stage and unconditionally binds every
opening cell to the total Omega verifier's actual output, including its fixed
dummy on failure. The terminal selection accepts only the opening retained by
the hard-verified resumed context. Effects belongs to the terminal stage.

A Pallas claim is `[source_k=16, Gx, Gy, u0_lo, u0_hi, ..., u15_lo, u15_hi]`.
A Vesta claim is `[Gx_lo,Gx_hi,Gy_lo,Gy_hi,u0,...,u15]`, with source k16 fixed.
Transport claims and correction coordinates are checked canonical cells; a
malformed incoming transport supplies its deterministic dummy and its decode
bit to the complete incoming-mode predicate. The context does not replace that
predicate or any operation, map, signature, selector or object-to-byte check.

The global four-bit sigma selector is the sorted wire `(tag,mask)` table:
Bootstrap0, Load1, Send masks0..7 at2..9, Receive masks0/1 at10/11,
ArchiveSent12, Unload13, the shared constrained RefreshPolicy union14, and
Retiring15. The five refresh A variants share tag7; separate unconstrained
refresh aliases do not fit this catalog. The circuit selector constrains the
same Send control-mask cells or Receive recorded-list predicate used by the
operation. Earlier Load selector5 diagnostics are not the canonical catalog.

`ContextPlan::with_schedule` fixes the ordered Q-index partition for each A
stage and the unique stage owning the hard predecessor P/opening pair. A1
requires at least one actual Pallas obligation. One opening is forwarded;
multiple claims require the fixed hard fold. A zero-Q first stage is permitted
only with the hard predecessor pair. It commits the exact Q frames and sigma
part before authentication of those Q frames; all deferred Q proofs remain
mandatory in their assigned later stages. An intermediate A/W proof alone
cannot accept a lineage.

For stage indices starting at one, let `P_i` be A_i's accumulated Pallas claim,
`V_i` be W_i's Vesta fold output, and `D_i` be A_i's internal digest. Every
nonterminal A_i, including A_1, emits:

```
C   = P_Fp(kgwctx_1, complete immutable items above)
D_i = P_Fp(kgwlink1, [1, variant, i, C, encode(P_i)])
```

A_i for i>1 computes C once from its exact source cells and recomputes
D_(i-1) using the carried P_(i-1). It hard-verifies the immediately preceding
stage's complete W key against that digest and the supplied V_(i-1). The
compiled schema and exact A/W key sequence fix every stage, Q partition and
owner. After its hard fold, it reuses the same C cells to emit D_i. Terminal
A instead emits the final lineage digest. Terminal, unknown and overflowing
indices cannot create an internal digest; carried P claims must be full k16.

By induction, collision resistance binds the same complete C and prior P to
W_(i-1)'s authenticated A_(i-1). That A proof enforces its own hard inputs and
fold. W_(i-1) folds its exact V part and A opening; A_i retains P_(i-1), the W
opening and every assigned new obligation. Consequently prior P/V obligations
remain in the two current accumulators. Rehashing a historical claim trace is
unnecessary. The implementation removes that trace and its private persisted
copies; there is no alternate legacy digest or decoder. The context-hash work
is fixed per stage rather than increasing with the continuation index.

This framing changes every staged source key. Captured prior proof results
remain scoped to their executables; all current sources, original imports and
proofs require fresh qualification. The uniform terminal frame and final
lineage transport have unchanged semantics.

Each internal A frame has the uniform69 layout with its `D_i`, current part and
explicit trivial absent slots. W1 folds the original sigma part plus the A1
opening and two fixed trivial slots. Later W_i folds `V_(i-1)` plus the A_i
opening and the two fillers. Thus the original sigma part and each A opening
occur exactly once. A_i for `i > 1` folds, in order, `P_(i-1)`, W_(i-1)'s opening,
the predecessor P/opening pair if assigned to this stage, the two mode-selected
incoming Pallas claims if terminal, and this stage's exact Q openings.

Only the last scheduled A stage returns opaque `FinalHalfCells`. It hashes the
final P claim with the successor public18 under `kgwomg_1`, and retains the last
W's V accumulator, actual predecessor V, and original incoming V with its mode
and correction in the final frame. Omega performs that Vesta selection and
retains the selected claim exactly once. Intermediate `ContinuationCells` cannot call the final-output API;
terminal output cannot be reinterpreted as an internal continuation. The closed
result owns its claims and provenance, so the output API cannot substitute a
different P claim or incoming frame after the checked fold. Every original
incoming field, decode bit, proof source, mode, correction and carried key is
rebound at terminal closure. The proof source is explicit messages outside the
complete Receive schema, and its exact active tape triple plus fixed-owner
opening within that schema.

The Load schedule is A1 (hard predecessor, D32 recovery and exact receipt
binding), W1, A2 (hard Q_sigma), W2, A3 (hard own receipt signature Q),
W3, A4 (hard current-credential and Enrollment-certificate signature Q).
Three signed object tapes and the exact 282-byte ordinary Load receipt enter
the same context. The receipt digest, scheme, asset, wallet, ordinal, amount
and charge are constrained to the exact Load effect. No finality source key,
proof or deferred finality claim enters the circuit.

The native owner verifies BLS finality and receipt inclusion before requesting
the signed Advance. Offline lineage authenticates this decision through that
credential-bound signature under the selected released-app/uncompromised-OS
assumption. It does not claim circuit verification of BLS. Current authorization
remains mandatory on every step. The changed A/W/Omega keys need current-candidate
qualification; see [native finality goals](kagemusha_native_finality_goals.md).

Send likewise
requires a separate own 2V/1F Q in addition to Q_sigma and its map/object tasks.
Its mandatory `SendProof` task binds `P_bytes(kgwprf_1, LE32||Ω||LE32||σ)`
to field9 of the exact receipt body retained by `C`. Ω includes the full
320-byte public transcript before `πΩ||accP||accV`. This task executes beside
the hard predecessor and links all original proof messages and both full-k16
claims. The separate signature-Q stage authenticates that same complete receipt
tape and enforces its operation/state/provider semantics. Neither task can be
omitted, and moving `SendProof` away from the predecessor stage is rejected.

The canonical mask0 component now proves the five-stage Send schedule with
genuine Bootstrap and Load predecessors. Under Q_sigma's two-bus profile and
A's four-bus profile, stage maxima are 50,098/56,018/57,868/61,864/60,051 rows;
all five source proofs are 8,480 bytes. The predecessor's two-terminal catalog
is rebuilt under its actual Omega digest and both source terminal keys and
descriptors remain equal. Every pending claim is independently decided.
This covers complete mask0 operation composition, not a final catalog: the
new Send terminal key still needs inclusion and root-digest rebuilding, all
other control masks remain, and the generic Omega transport is oversized.

Receive's task metadata defines eight mandatory groups, including five named
soft results (proofs, objects, signatures, nonmembership and recorded blacklist).
The private fixed five-owner plan rejects missing/doubled/relabelled groups;
its schema, five original Boolean claims and incoming opening enter `C`.
Typed producers now bind recursive proof verdicts/openings, exact active
Payment sources, original signature objects, unique consumed-credit/history
routes, own C4 and receipt authentication, and the terminal OQ-3/iff effects.
Their genuine complete stage chain and capacity remain unqualified; metadata
does not certify an allowed key actually executes its assigned producer.

Receive's first six object slots are Request, payer credential, Send receipt,
Payment, original active Omega and original active sigma. Both ordinary and
renewed variants then retain current credential/certificate/own receipt and
the original quoted credential/certificate, giving eleven slots. Payment's
Request, payer-credential and package content addresses are hard links to
the supplied tapes; the quoted credential and certificate must likewise open
the Request and credential references. An unrelated preimage cannot force a
burn. Ordinary versus renewed is hard-determined by the quoted/current
credential digests. Original signature/semantic/proof failures remain soft.
The own Receive effect is not a freely chosen soft input: credit, payer-wallet
and amount are hard projections of the exact Request. Own relation/scheme are
hard-bound to the authenticated receiver and pinned policy. A wrong original
Request asset or recipient remains soft, because the own asset/wallet are
already fixed by authenticated state. Otherwise a prover could pair a valid
fixed Payment with a different own effect merely to force a burn.

Canonical Payment envelopes reserve 1,723 bytes outside the two raw proofs,
leaving a joint 8,277-byte budget. The total incoming buffer bounds are therefore
8,597 bytes for Omega (including its 320-byte public transcript) and 8,277 bytes
for sigma, including cases where the other malformed proof is empty. Active
length and exact descriptor checks remain soft predicates; padding never enters
the original digest. The explicit descriptor-capacity chain is a smaller
composition diagnostic. A separate fixed-maximum chain must qualify these
canonical capacities before total ingestion is claimed. Inputs exceeding the
10,000-byte canonical envelope are rejected before Advance.

For this fixed eleven-slot Receive schema, continuations may retain opaque
proposals `(object digest, UInt32 original length, tape commitment)` instead
of decoding every unrelated object again. These proposals are not verified
objects or verdicts. The Objects owner derives slots1–6 from the exact original
tapes; Authorization derives slots7–11. The Proofs owner independently derives
the active Omega/sigma tape commitments and binds every original proof message,
claim and verifier input. It retains the proposed combined consuming digest in
slot5; only Objects derives that digest from both active originals. Signature
and history owners use a typed three-object projection and rebind its complete
triples to the same context. Dropping the Objects owner would therefore discard
a required predicate even if the isolated Proofs projection passed. Exact
eleven-slot metadata and the complete fixed task/result owner set are mandatory.

The genuine Receive stage measurement with the initial full-message context
passed A1 at 62,160 rows, but A2 (hard Q_sigma plus W) required 84,064 sponge
and 76,277 range rows. Its k18 diagnostic satisfied the predicate, and no
out-of-capacity A2 proof was generated. Receive now uses an explicitly framed
`kgwcrcv1` context representation, with no compatibility choice between layouts:

| Incoming context group | Initial measurement | Receive active-source schema |
| --- | --- | --- |
| Original public18, structural bit, P and V claims | Included | Unchanged |
| Decoded Omega message view | Length plus three limbs per 32-byte message | Not assigned or hashed by non-owners |
| Original active Omega tape | Fixed slot4 digest/length/tape triple | Same exact triple, mandatory |
| Original active sigma tape | Fixed slot5 triple and Q chunks | Unchanged |
| Q instances | Every scalar as low128/high127 | Exact checked Bounded/Bits0..253 as one Fp word; Field/wider values retain both limbs |
| Fixed keys/classes, statement/state, modes/corrections | Included | Unchanged |
| Five named results and full incoming opening | Included | Unchanged |

`ContextIncomingProof::ReceiveActive` is accepted only for the complete Receive
owner schema; an explicit message variant is rejected there. Proofs decodes and
verifies only the retained active original tape and equates its total opening
and verdict to the committed export, including on malformed inputs. Non-owner
stages cannot propose an alternative message view: that argument no longer
exists. W authenticates the exact unchanged context and fixed-stage carried claim;
terminal selection carries its active tape triple as provenance and consumes
only the authenticated opening. A different Q input still fails its hard
same-source digest/selector/chunk bindings and exact partition verification.
This is a context representation change, not a discharged proof obligation.
The active-tape projection passed native/circuit context parity and
known/unknown checks at A1 (44,363 rows); A2 still required 66,267 sponge and
74,350 range rows, so no A2 proof was generated. Exact typed-Q framing tests
reject Fq values p, p+1 and q−1 as single-word Fp aliases and reject declared
bit-width overflow, with known/unknown layout parity. Full chain capacity and
cross-stage qualification of the combined schema remain pending.

The Receive continuation candidate therefore uses explicit tagged four-bus
internal A keys and a tagged three-bus terminal A key. These are fixed circuit
profiles, not witness-selectable modes. Every W pins the exact preceding
internal descriptor and key; intermediate A and all W keys are excluded from
the final Omega allowlist. Only the terminal profile must match the common
admitted operation catalog. This staging changes no k16, transport, or final
Omega constraint. Genuine owner-chain proofs and cross-W foreign-key rejection
still must qualify this candidate.
The first such chain produced actual A1/A2 proofs at maxima39,035/65,012 and
rejected all33 object-commitment word substitutions, all five results, changed
Q chunks, source ordering, incoming opening, mode and statement across W.
Its Proofs stage still exceeded k16 (71,839 main, 70,633 sponge) with the
oversized generic incoming Omega. That run preceded the hard own-effect
projection correction and is capacity evidence only. The current candidate
uses the actual rooted compact receiver Bootstrap carrier; complete current
source closure, all later owners and terminal qualification remain open.

The explicit tagged three-bus A profile now fits the genuine four-stage Load
component using two-bus Q_sigma: maxima 55,611 / 61,808 / 57,646 / 58,164 rows,
with 7,744-byte source proofs. This candidate has 23 advice columns, 51 fixed,
57 advice queries, 16 equality columns, four lookups and degree8. Its rooted
Bootstrap predecessor uses the same profile; a common final Load catalog and
Omega root rebuilding are still required. Existing four-bus component evidence
does not imply these new keys are admitted.

A uniform final Omega catalog must exclude intermediate A/W keys and rebind the
normal Omega digest throughout the chain. Full-catalog admission, proof size,
time/RSS and cryptographic qualification remain separate gates.

The separate Bootstrap signature workload is a second Q leaf: its two variable
keys and one fixed key are not silently included in `Q_sigma`. Unsplit Bootstrap
with more than one Q hard-folds exactly its ordered Q openings, with no
predecessor slots. A single-Q component fixture still forwards its opening.
All Q openings have k16, so this fold needs no full-length filler. The split
component places `Q_sigma` in A1 and the signature Q in A2, where it is retained
alongside contextP and W's own opening.

Key construction is acyclic: source Q keys → A1 keys → W1 key → A2 keys →
W2 key → … → terminal A keys. A future W key cannot be an earlier A constant.
`WKey` is constructed by W-specific key generation and retains its exact
wrapped-stage class; `SplitPlan` accepts it only for the immediately following
stage of the same context schema. Every continuation pins its complete W key.
No witness or runtime terminal flag selects the stage class. The normal Omega key digest remains
carried in the public18 fields and pinned by native artifact admission as in
Lambda §2.6. The artifact builder must supply actual A1 keys for the stated context schema:
`WCircuit::new` accepts an admitted binding and key-digest catalog, and does not
prove that a caller-generated arbitrary circuit implements A1. This is the same
reviewed-artifact trust boundary as the final A allowlist. There is no native
acceptance entry point for W; a final verifier
must use its admitted final Omega key and recompute `kgwomg_1`.

The final Omega catalog must exclude every intermediate A key and all W keys.
This remains a reviewed artifact-admission requirement: typed internal wrappers
are not substitutes for building the complete final catalog and rebinding the
normal carried Omega digest.

Remaining qualification includes actual proofs for every stage of every split variant,
all operation/consumer constraints, independent missing-obligation and splice
mutations, the final native key-type/admission boundary, resource measurements,
and the broader cryptographic audit obligations in the soundness record.

The Bootstrap test `actual_split_chain_retains_context_wrapper_and_final_claims`
generates an actual Bootstrap sigma and recursive Q_sigma proof, then actual
native A1, W and A2 proofs, and independently decides the retained claims.
`admin_sigma::BootstrapCircuit` proves the exact initial zero-value state,
empty maps/counters, disabled controls, and state/statement/public bindings at
k12 with five advice columns (1,453 maximum rows, 6,133 assigned cells and a
3,296-byte PIPA-R proof). Its fixed sponge and glue phases share four columns;
the range lane is separate. Rehashed invalid initial states are rejected.

A2 hard-verifies a genuine 2-variable/1-fixed signature Q over the exact
receipt, credential and root certificate messages. `BootstrapObjects` binds
those opaque outputs to the same canonical object tapes committed by both
halves, requires all credential/evidence/current-state and receipt predicates,
and pins scheme/provider/root policy. The receipt's sigma-only proof digest
comes from the same length-prefixed chunks bound to Q_sigma. The credential's
enrollment ID equals the Bootstrap statement's first effect pair. The second
pair is the nonzero generation-zero enrollment-marker identity: its SHA-256
preimage and durable one-time installation remain G2/OQ-1 responsibilities.

The test rejects altered object/context/key/proof-length/proof bytes, a
variable certificate-root policy, swapped receipt/credential signature slots,
an omitted authentication schema, and every dropped Pallas obligation. The
known and unknown witness layouts agree. Full incoming-variant proof chains,
operation partitioning for other variants, final Omega/native admission and
resource/cryptographic qualification remain open.

This genuine Bootstrap composition occupies at most 38,961 advice rows in
A1 and 62,158 in A2 with the previous two-stage schema header. A1's other lanes peak at 35,372 sponge, 27,339 ECC and
14,749 foreign-field rows; A2 peaks at 54,688 ECC, 49,543 sponge and 20,006
foreign-field rows. Both fit k16. These are source-layout inventories, not
time or RSS qualification. Predecessor/incoming verification and other
operations' map work still require an explicit fixed partition.
