# KAGEMUSHA Λ and Ω proof construction V1

Status: design record, 2026-10-05, for [proposal](kagemusha_single_design_proposal.md)
revision 2026-10-05 and the [wallet wire record](kagemusha_wallet_wire_v1.md). It fixes how
the lineage relation Λ and its transport form Ω are proved on [PIPA-v1](plonk_ipa_v1.md):
circuit kinds, accumulation, the Ω bytes, the receiver's native work, per-operation budgets,
memory, the soundness argument, the gadget set and milestones M3–M5. The proposal and the
wire record govern protocol semantics and encodings; this record governs the proof
construction. It applies the third set of owner answers of 2026-10-05 (B1–B8, §1.1), which
the proposal and the wire record now carry (§12). Revision-4 native step proofs σ
(k12 without quota, k14 with the fixed quota array) and the M3 gadgets exist.
The recursive construction remains under implementation and unqualified. Every
figure carries a label:

- **[M]** measured with the native engine on the shared Apple-silicon Mac (20 CPUs, timings
  ±25%), or where stated in the [checklist](kagemusha_evidence_gate.md) §8;
- **[E]** estimated from the unit costs of §5.3 and the counts of §5.2;
- **[C]** exact arithmetic (the PIPA §7 byte formula, a lattice reduction), not a measurement;
- **[S]** read from source or spec text.

The thresholds of §10 select design fallbacks (for example the A-split of §2.8). They are
engineering checks, not release approvals.

Notation follows proposal §3 (σ, Λ, Ω, τ, folded head, decide, deferred values). Pallas has
base field Fp and scalar field Fq; Vesta has base field Fq and scalar field Fp; p < q < 2p
and q − p ≈ 2^86.16 [C]. A Vesta proof comes from an Fp circuit and has Fq commitment
coordinates; a Pallas proof comes from an Fq circuit and has Fp coordinates. `P` is RP57
Poseidon over Fp (proposal §3); `P_Fq` is the same construction over Fq, already pinned in
`iroha_pasta::poseidon` (`RP57_FQ`). "PIPA §" means `plonk_ipa_v1.md` and "wire §" the wire
record.

## 1. Decisions and constraints

### 1.1 Owner decisions applied

| Decision (2026-10-05) | Effect on Λ and Ω |
|---|---|
| Every protocol P-256 signature signs the 32-byte canonical encoding of the body's `P_bytes` signing message with SHA256withECDSA (proposal §3, wire §1) | Each in-circuit ECDSA needs exactly one SHA-256 compression block, in the same Q slot as the ECDSA |
| Every wallet map and the lineage-level credit-digest tree is a depth-32 Poseidon indexed Merkle tree (IMT, wire §3.2), except the B5 quota-usage array | One IMT chip; there is no sparse-Merkle-tree chip |
| **OQ-1 (B1), applied.** Every digest Λ recomputes is Poseidon: `operation_id`, the unload nullifier, the request, receipt, package, credential, certificate, ordinary Load receipt, fee-schedule and policy object digests, the certificate-set digest, and the receipt's statement digest. `H` remains only for `scheme_id`, the enrollment and renewal transcripts, `account`, the marker, the output descriptor and the artifact digests | Λ computes no SHA-256 beyond one block per signature. Identities Λ only carries (`wallet_id`, `enrollment_id`, asset scope, `relation_id`, verifying-key set) are never recomputed in-circuit (scope question, wire §7). Encodings (wire §§1, 3.2): an object digest is `P(d_obj, [m, r_lo, r_hi, s_lo, s_hi])` (3 permutations); the package digest has 3 elements (2), `operation_id` 4 or 5 (3), the nullifier 5 (3); the statement digest is the σ statement digest, 26 elements (14) |
| **OQ-2 (B2), applied.** Λ_recv and Λ_archive may fold a self-computed *corrected claim* (G*, u), with G* = ⟨s(u), g⟩ ≠ G, as the witness that an incoming accumulator (G, u) fails to decide | §2.7 burn and no-op branches |
| **OQ-3 (B3), applied.** On the burn branch with a duplicate `credit_id`, the committed consumed-credit root equals the predecessor's root or is a structurally valid IMT insert of a fresh key | §2.7 |
| **OQ-4 (B4), applied.** The QuotaShare refresh rule "keeps the end of every existing usage key" is checked only for the 64 quota-window slots | §5.1; with B5 it is part of the usage-array rebuild, whose budget §5.4 states |
| **B5.** The quota-usage map is a depth-6 fixed array aligned one to one with the 64 quota-window slots; a Send charges its window slots in place | σ_send: ≈ 45 permutations per charge, ≈ 309 for the quota part and ≈ 346 with every control [E], a single-lane k14 shape (≈ 3,424 B [C]) or k13 with shared paths, replacing the k15 IMT estimate. Λ_refresh(QuotaShare): array rebuild ≈ 954 permutations instead of ≈ 4,734; the measured recursive composition requires split root/merge owners (§§5.1, 5.4) |
| **B6.** The Request records the receiver blacklist version and root used at issuance; Receive (native and σ_recv) checks only that list | σ_recv proves the gap in the recorded root and its key is selected by the recorded version. Λ_recv looks the recorded pair up in the blacklist-history IMT of the rest (≈ 68 permutations); Refresh(Blacklist) inserts into it (≈ 264). F_payment +42 B, so R9 becomes 8,277 B (§3.5) |
| **B7.** `quota_share_expires_at_ms` is a core field; σ_send enforces `U < expires_at_ms` with the quota control | σ only; one 64-bit comparison |
| **B8.** `time_anchor_max_response_ms` < the shortest quota window, checked when a share is installed; σ_send checks `U − L ≤ time_anchor_max_response_ms` (a core field) with the quota control | Λ_refresh(QuotaShare): 64 length comparisons; σ_send: one comparison; two charge candidates per kind suffice |
| Gate degree ≤ 6; k ≤ 16; ≤ 1 GiB fold memory with one sub-proof at a time; std Rust only; identical outputs on every hardware; no new external crates | §§2, 6, 9 |

### 1.2 Binding constraints and how they are met

| Constraint | Met by | Status |
|---|---|---|
| 1–2 s to durable completion; Ω verified on the path unless pre-verified | §4: ≈ 35–140 ms of phone proof CPU when pre-verified, +0.29–0.75 s cold | met [E]; hardware signing and durable commit unmeasured |
| R9: Ω + largest σ_send ≤ 10,000 − F_payment = 8,277 B (wire §4, F_payment = 1,723† with the B6 Request fields) | §3: Ω = 4,736 B; with the largest measured revision-4 σ_send (3,456 B) the Ω budget is 4,821 B | conditional [C], margin 85 B; Ω unbuilt |
| Credited::Status ≤ 10,000 B, Ω ≤ 7,812 B (wire §4, F_status = 2,188†) | 2,188 + 4,736 = 6,924 B | met [C] |
| Fold peak RAM ≤ 1 GiB | §6: one prover at a time, ≤ 0.85 GiB per sub-proof plus ≤ 0.15 GiB wallet core | met [E]; thresholds G3.6, G3.7, G4.6, G5.3 |
| First release; formats may be redesigned | PIPA-R profile and PIPA-AS-v1 (§8); σ moves to the base-field transcript at unchanged byte length | used |
| std, deterministic, no new external crates, Pasta curves | only `iroha_pasta`, `iroha_plonk`, `iroha_plonk_gadgets` and a new workspace crate `iroha_plonk_recursion`; verifier MSMs stay `msm_complete` (PIPA S10) | met |
| `credit_id`, `proof_digest` (σ only and Ω‖σ) and the Payment digest are `P` / `P_bytes` | spec-literal `P_bytes` over the bytes, linked in-circuit (§5.2) | met |
| Wallet maps (the blacklist history included) and the credit-digest tree are depth-32 IMTs; the quota-usage map is the B5 depth-6 array | IMT chip in A; the array shares the depth-6 path layer of the quota-window tree | met |
| Receiver matched by `wallet_id` and `payment_key`; continuity proven in Λ | A equalities; the Request's receiver credential is verified in Λ_recv and deduplicated with the current credential | met |
| One Fp head commitment; one `relation_id`; σ keys selected by (tag, mask), Receive by its Request's recorded blacklist version | `relation_id` is carried in D_A, never a circuit constant; σ's key is selected in Q by one-hot digest and checked in A against the (tag, mask) table, with the Receive selector derived from the Request | met |
| Enabled controls enforced in σ_send, the receiver's Request-recorded blacklist decision in σ_recv | Λ only selects σ's key; G-Ω2 bounds σ_send at 8,277 B minus the Ω length (3,541 B) | met; σ shape threshold |
| Proposal §3.2 containment: deferred failures burn or no-op, no poison | corrected-claim witness plus total soft verifiers (§2.7) | met |
| Proposal §3.2: native and in-circuit verifiers accept exactly the same set | one table-driven predicate (PIPA S11), complete in-circuit arithmetic, total soft verifiers (§7 C7) | met deterministically |

## 2. Architecture

### 2.1 Circuit kinds

Each Λ step is a fixed DAG of k16 circuits. Every consumed proof is verified completely in
the circuit whose field is its base field, except its 2^16 generator MSM, so no deferred
scalar crosses the cycle; the generator MSMs are accumulated by separate, local,
non-hiding PIPA-AS-v1 fold proofs (§3.4).

| Kind | Circuit field / proof curve | k | Advice / fixed / equality / lookups [E] | Holds |
|---|---|---:|---|---|
| σ (exists) | Fp / Vesta | 12 | 5 / 24 / 7 / 1 [M] | step relation; payment path |
| **Q** leaf | Fq / Pallas | 16 | 22 / ~32 / 8 / 3 | P-256 (variable key V, fixed key F) with its SHA block; the single **σ-leaf Q_σ** also holds every σ verifier of the step and the fold F_V^Q |
| **A** aggregator | Fp / Vesta | 16 | 32 / ~44 / 10 / 3 | all `P` work (openings, IMT, digests, `P_bytes`, consumer checks, lineage-adjusted values, burn logic); succinct verification of Ω(pred) (hard), Ω_in or Ω(h) (soft) and every Q (hard); fold F_P |
| **Ω** wrap | Fq / Pallas | 16 | 11 / ~18 / 4 / 1 | succinct verification of A (hard); fold F_V^Ω; selection of A's key; D_A passed through |
| **W** (context wrap) | Fq / Pallas | 16 | Ω's descriptor, other context domain | intermediate wrap of the A-split (§2.8); never transported |
| F_V^Q, F_P, F_V^Ω | PIPA-AS-v1 fold proofs | K = 16 | — | local, 1,088 B body plus 32 B salt each [C] |

Field placement:

- `P` is native in Fp, so A holds all hashing.
- Pallas group operations are native in Fp, so A verifies the Pallas proofs (Ω, W, Q).
- Vesta group operations are native in Fq, so Q verifies σ and Ω verifies A.
- P-256 and SHA-256 are non-native in both fields; they sit in Fq leaves so that A, which is
  native for Pallas, verifies them cheaply.
- Each proof's transcript runs in its **base** field (PIPA-R, §8), so every verifier circuit
  runs the transcript natively. A foreign-field Poseidon would cost 20–35k cells per
  permutation [E] instead of 148 [M].

### 2.2 Per-step DAG and proving order

```text
  fold witnesses (proposal §4.1; payer data already natively verified at Receive)
        |
  Fq   Q_1 … Q_r (Pallas)    P-256 V/F + SHA slots (soft for incoming objects, hard for own)
        Q_σ (one of them)    σ verifiers (own hard; σ_send / σ_recv soft) + F_V^Q over the O_σ
        |        out: per signature (m, key, valid); per σ (d_σ, vk_index, valid, descriptor-sized byte chunks);
        |             acc_V^part; gated-slot modes
  Fp   A (Vesta)             verifies Ω(pred) [hard, witness key K], Ω_in or Ω(h) [soft, same K],
        |                    Q_1..Q_r [hard, keys fixed per A variant];
        |                    P: openings, IMT, receipt bodies, P_bytes, credit_id, consumer checks;
        |                    F_P over {acc_P(pred), O_Ω(pred), [acc_P(in), O_Ω(in)], O_Q1..O_Qr}
        |        out: D_A (binds the public fields, vkΩ_digest and acc_P); acc_V^part;
        |             acc_V(pred), acc_V(in) with its mode
  Fq   Ω (Pallas)            verifies A [hard, digest K_A belongs to T_A];
                             F_V^Ω over {acc_V^part, O_A, pred-or-TRIV, incoming-or-TRIV}
                 out: [D_A, acc_V]; transported: π_Ω ‖ acc_P ‖ acc_V
```

Proving is native and sequential; each output is durable before the next proof starts:

1. Synthesize every value natively. Decide every incoming accumulator with the prover-side
   kernel (`msm_public`, 292–297 ms at 2^16 on 1 thread [M]) to choose the branch (§2.7).
2. Prove F_V^Q (when Q_σ holds two σ), then Q_σ, then the other Q leaves.
3. Prove F_P, then A.
4. Prove F_V^Ω, then Ω.
5. Self-verify Ω with the native verifier, both decides included, and record it (proposal
   §3.1 step 5).

### 2.3 Obligation ledger (PIPA S13)

| Obligation | Curve, k | Created by | Folded in | Mode |
|---|---|---|---|---|
| O_σ(own) | Vesta, source k12/k14 | σ verifier in Q_σ | F_V^Q; with one σ it is forwarded as acc_V^part with checked prefix padding and its original source k | hard |
| O_σsend (Receive), O_σrecv (ArchiveSent (i)) | Vesta, selected source k12/k14 | soft σ verifier in Q_σ | F_V^Q | gated |
| acc_V^part | Vesta, 16 after a fold or original source k when forwarded | F_V^Q output or single O_σ, carried Q_σ → A → Ω as instances | F_V^Ω | hard |
| acc_V(pred) | Vesta, 16 | Ω(pred) instance, forwarded by A | F_V^Ω | hard |
| acc_V(in) / acc_V(h) | Vesta, 16 | Ω_in / Ω(h) instance, forwarded by A with mode and G* | F_V^Ω | gated |
| O_A | Vesta, 16 | A verifier in Ω | F_V^Ω | hard |
| O_Q (each leaf) | Pallas, 16 | Q verifier in A | F_P | hard |
| acc_P(pred), O_Ω(pred) | Pallas, 16 | Ω(pred) verifier in A (O from its suffix G'_0) | F_P | hard |
| acc_P(in), O_Ω(in) | Pallas, 16 | soft Ω_in / Ω(h) verifier in A | F_P | gated |
| acc_P (out) | Pallas, 16 | F_P output, bound in D_A | natively batch-decided with Ω's own opening; in Λ the next A's acc_P(pred) | — |
| Ω's own opening | Pallas, 16 | every native verifier; the next A | native batch decide; the next F_P | — |
| acc_V (out) | Vesta, 16 | F_V^Ω output, an Ω instance | natively decided; in Λ forwarded by the next A as acc_V(pred) | — |

Every obligation enters exactly one fold of its own curve, through a fixed slot of its
variant; *Trivial* and *Corrected* enter only through mode bits that the consuming circuit
constrains. By induction, Ω(h)'s own opening, acc_P and acc_V cover every obligation of the
lineage. Pallas and Vesta obligations cannot share an MSM (PIPA §11), so a consumer runs
exactly two 2^16 MSMs. A build-time test asserts the ledger for every variant
(`every_obligation_folded_exactly_once`).

A fold whose actual obligations all have source k < 16 includes one additional,
explicit fixed `ACC_TRIV` slot at k16 (§3.4). This public constant is not an obligation
and does not discharge another slot. Its position, count and transcript absorption
are fixed by the consuming circuit; it is never added or removed implicitly.
In particular, F_V^Q over two short σ openings has three slots including this constant.

**One Ω descriptor.** Every A variant exports one Bounded instance column of
69 fields: `D_A`; the part's source k, G coordinates in S6 and 16 normalized
challenges (21); the predecessor's G in S6 and 16 challenges (20); the incoming
G in S6, 16 challenges, three mode bits and corrected G in S6 (27). An absent
predecessor or incoming claim is the pinned full-length `ACC_TRIV`, constrained
by that A variant; absent incoming uses Trivial mode and the pinned trivial
point for its unused correction. Ω always folds four slots in the diagram's
order. Its part source k is constrained to 12, 14 or 16, with exact zero-prefix
padding and nonzero active challenges. All A variants share one descriptor
(including instance types/lengths and selector layout); their full key digests
select the operation in `T_A`. Variant-dependent Ω keys would break the single
carried `vkΩ_digest` construction and are not permitted. These explicit absent
slots discharge no obligation and cannot replace a present claim.

### 2.4 Verifying keys without a cycle (PIPA S14)

Build order: σ VKs → Q VKs → A VKs → Ω VK → `vkΩ_digest` and
`lineage_verifying_key_digest` → `relation_id` and `verifying_key_set_digest` → `scheme_id`.

| Verifier → verified | Key binding | In-circuit cost [E] |
|---|---|---|
| Q → σ | Witness VK (31 points + `transcript_repr`); its `P_Fq` digest compared one-hot with the allowlist's σ digests (constants of Q). Q exports `vk_index`; A checks it against the constant (tag, mask) → index table, with a Receive mask of 1 iff its Request records a nonzero blacklist version (B6) | ≈ 32 permutations ≈ 4.7k cells |
| A → Q | Q variants' VKs are fixed columns of each A variant | 0 |
| A → Ω(pred), Ω_in, Ω(h), W | Witness key K. A computes `P(K)` and requires it to equal the `vkΩ_digest` field of the D_A(pred) it opens, copies that field into its own D_A, and recomputes D_A(in) with the same field. Bootstrap's A takes the field as a free witness | ≈ 23 permutations ≈ 3.4k |
| Ω → A | Witness VK_A (≈ 54 points + repr); the complete `P_Fq` digest is bound by the zero product of its differences from the 1..32 distinct constant digests in T_A. A pinned-key profile selects every key component with one constrained catalog selection and retains the same membership predicate. No lookup argument is added | ≈ 56 permutations ≈ 8.3k |
| native verifiers → Ω | D_A recomputed with the artifact-set constant `vkΩ_digest` | 27 native permutations |

`relation_id` is a carried value in every circuit, σ included: σ takes it as witness limbs
bound by its statement digest (wire §3.2, `StatementV1`). It is never a circuit constant
(`relation_id_is_never_a_circuit_constant`).

The same build order requires `scheme_id` to be carried, never fixed into an A
key: it depends on the completed key inventory through `relation_id`. Bootstrap
binds its certificate and credential to the scheme limbs in its constrained
state, statement and lineage. Later steps bind their signed objects to the
scheme limbs of the authenticated current state and predecessor. The provider
identity and scheme-root public key are independently selected constants; they
remain fixed in the authorization keys. Native admission separately requires
the carried scheme and relation to equal the authenticated installation.

The former `OwnPolicy` and `BootstrapPolicy` scheme constants violated this
order. Their removal requires fresh affected A/W/Ω keys and complete catalog
qualification. Proof captures made with those constants remain evidence only
for their recorded source; they do not qualify the corrected artifacts. No
compatibility key or fallback acceptance path is retained.

**VK digest framing.** A PIPA-R verifying key has the base-field digest
`P_B(kgwvkey1; 1, curve_code, k, fixed_count, permutation_count, transcript_repr,
descriptor_digest_lo128, descriptor_digest_hi128, fixed_points[x,y]..., permutation_points[x,y]...)`.
Pallas has curve code 0 and Vesta 1; counts and commitment order match the canonical
VK encoding, coordinates and the base-field representation are canonical, and every
point is finite. The descriptor digest is split as a little-endian integer into
two 128-bit limbs. `P_B` includes the domain and arity prefix, as the native
`hash_with_domain` function does. With n commitment points this takes n + 6 RP57
permutations, replacing the preceding approximate cost estimates. The same framing
applies to σ/Q/A/Ω/W key hashes in each key's base field. Verified descriptors are
circuit-fixed, so their limbs are constants in the recursive key-hash gadget;
the gadget does not recompute BLAKE2b. It also binds the witnessed key's
`transcript_repr`; a bare representation is not the allowlist key digest.

### 2.5 Variants and the allowlist

- **One descriptor per kind.** Variants of a kind differ only in fixed columns (program,
  copies, constants).
- **σ shape classes.** A shape class is one σ descriptor (k, column counts, gate set).
  Relations of one class differ only in fixed commitments, share one Q_σ program and are
  selected by the one-hot key digest; each distinct class has its own Q_σ program. The
  allowlist (wire §3.1, at most 16 σ entries) holds every operation with mask 0, Send per
  supported mask and, when some Send mask enables the blacklist, Receive for a
  Request-recorded blacklist decision (selected by the Request's recorded version, not
  by the receiver's mask). With the B5 usage array the quota-enabled σ_send is expected
  to be a single-lane k14 class (k13 with shared window and usage paths), and the
  blacklist σ_recv to stay in the k12 class [E].
- **A variants.** One per (operation, σ shape classes it verifies): Bootstrap, Load, Send,
  Unload, Retiring, Receive and Receive (renewed receiver credential), ArchiveSent (i) and
  (ii), the five RefreshPolicy kinds and the A-split halves. T_A, the constant list in Ω, is
  sized at artifact freeze (≤ 32 expected [E]; each entry costs one comparison).

### 2.6 Base case

- Bootstrap's A has no Ω slot. It enforces the unique zero state (proposal §3.2) and writes
  free `vkΩ_digest` and `relation_id` fields, which every native verifier pins.
- Bootstrap uses the complete required Q set. The current implementation separates Q_σ from a 2V/1F signature leaf, so F_P hard-folds both k16 Q openings with no predecessor input. A genuinely combined single-Q layout may forward O_Q, but only after proving all of its obligations in that leaf; the single-Q frame fixture does not establish that workload.
- F_V^Ω folds {acc_V^part = O_σ, O_A, ACC_TRIV, ACC_TRIV}; the last two are
  the fixed absent-predecessor and absent-incoming slots of the uniform frame.
- A forwarded `acc_V^part` is an internal checked fold input, not a transported
  `AccumulatorT`. It retains the source k derived from the selected σ descriptor
  and has exactly `16-k` leading zeros. A real F_V^Q output instead has source
  k16 and no zero challenges. Both A and Ω constrain this distinction; relabeling
  a padded short claim as a k16 transported claim is rejected.
- **Trivial accumulator** `ACC_TRIV(C) = (Σ_{i<2^16} g_i, 1^16)`: s_i = 1 for every i, so it
  decides by construction. It is pinned per curve by a KAT.

### 2.7 Soft verification, burn and no-op

**Soft verifiers are total.** They run for Ω_in or Ω(h) in A; for σ_send or σ_recv, τ_send,
τ_recv or τ(h) and the Request in Q; and for the consumer checks, `credit_id`
non-membership and the Request's recorded-blacklist history lookup (B6) in A. A lookup
always opens, hard, either the recorded version's leaf or its low leaf in the
predecessor's history root; its soft bit is false only on proven absence or an
authenticated root different from the recorded one, so a bad path is unsatisfiable,
never a burn. Each outputs a verdict bit and is satisfiable for every witness
(PIPA S12, §8): every decode check yields a bit and a failing input is replaced by a fixed
default before use; denominators are guarded by is-zero bits; group arithmetic is complete.

**Gated slots.** Every incoming obligation j (acc_P(in), O_Ω(in), acc_V(in), O_σin) enters its
fold in one of three modes: **Accept** (G_j, u_j); **Trivial** ACC_TRIV; **Corrected**
(G*_j, u_j) with G*_j ≠ G_j, checked natively in the fold-owning circuit (OQ-2).

```text
soft_ok  = AND of every soft bit (Ω_in succinct incl. D_A(in) recomputation, σ_send, τ_send,
           Request incl. its recorded-blacklist lookup, consumer checks, credit_id
           non-membership)
valid    = soft_ok AND (no slot in Corrected mode)
valid = 1  ⇒ every incoming slot is Accept
valid = 0  ⇒ every incoming slot is Trivial except at most one Corrected slot, and
             (soft_ok = 0) OR (exactly one Corrected slot)
```

A constrains every mode bit; Q and Ω receive them as instances.

**Λ_recv effects.** Λ checks the consumed-credit transition from the predecessor core to the
committed successor core (opened from σ_recv's successor head):

- On accept (valid = 1): the insert of `credit_id`, whose low-leaf part is the
  non-membership soft bit; the credit-digest tree inserts `credit_id → (Payment digest, 0)`.
- On burn (valid = 0): `burned_total += amount` (checked u128) and the `credit_id` stays
  consumed. The consumed-credit root (OQ-3) equals the predecessor's root or is a
  structurally valid IMT insert of a key proved absent from the predecessor's root. The
  credit-digest tree records `credit_id → (Payment digest, 1)` unless the key is already
  present.
- One credit-digest gadget serves both branches (membership-or-insert): its single opening is
  either the key's own leaf (present: root unchanged) or its low leaf (absent: insert).
  Existing-key membership preserves the existing Payment digest and burned flag, even when
  they differ from this Receive's proposed insertion: `burned` is fixed at the first
  insertion and the tree stays insert-only. A duplicate `credit_id` carrying another Payment
  digest therefore shows the original leaf to CreditStatus; that leaf does not match the
  second Payment, so native ArchiveSent rejects it and Λ_archive takes its no-op branch.

**Λ_archive** has the same structure with `valid_evidence`. On valid_evidence = 0 it takes the
no-op branch: Λ's pending-outgoing root keeps the descriptor and nothing else changes
(proposal §3.2).

Why this meets proposal §3.2 (§7 C8):

- **Deterministic.** Accept requires every incoming claim to fold, so the final decide forces
  them true. Burn requires a false soft bit (a deterministic function of the bytes) or a folded
  corrected claim, which forces G*_j = ⟨s(u_j), g⟩ ≠ G_j, so obligation j truly fails. The
  branch equals the native verdict; the prover cannot choose it.
- **No poison.** On a completed burn, the only Payment-derived claim folded is a corrected
  claim, which decides because the honest receiver computes G*_j itself. The lineage stays
  decidable and its other value is unaffected. Algebraic correction is defined for every u_j,
  but the exceptional G*_j = O cannot use the finite-point transport and returns an encoding
  failure, not a completed burn. Liveness therefore has the IPA's computational/negligible-
  exception scope, not an unconditional claim for every possible challenge vector.
- **Kernel diversity.** The honest prover locates a failing claim with `msm_public`; the
  receiver's native check used `msm_complete`. Poisoning needs both kernels wrong on the same
  input.

### 2.8 A-split and runs

**A-split.** Used when a variant's A exceeds its capacity of 1.67M cells [E: 32 × 63k ×
0.83]:

1. Each A_i binds the complete immutable operation context
   `C = P(kgwctx_1, …)` and its current Pallas accumulator with
   `D_i = P(kgwlink1, [1, variant, i, C, encode(P_i)])`.
2. W_i (Ω's descriptor, with its own exact stage VK) wraps A_i and retains
   its Vesta part and opening obligation.
3. A_(i+1) recomputes C and D_i, hard-verifies W_i, and folds the carried P_i,
   W_i opening and every assigned new obligation. It reuses C for its output.
   The fixed key sequence supplies the recursive link; no historical digest
   trace is retained. The exact framing and induction are in
   `kagemusha_a_split_context_v1.md`.

Native verifiers recompute only `kgwomg_1`, so W can never pose as Ω. Cost: +1 A, +1 W and
+2 folds ≈ +48–65 s on 1 Mac thread [E]. At the M3 P-256 thresholds the split is needed only by
Receive (renewed) at the high end of its band (§5.4); with the B5 usage array,
Refresh(QuotaShare) no longer needs it.

**Runs.** Send, Unload and Retiring commit only from a folded head (proposal §3.1), so a run
holds at most one Send-class step, and only first. An intermediate head of a run still needs
a W (A cannot verify A), and no pair of steps fits one A (§5.4). **The artifact set ships run
length 1.**

## 3. Ω encoding and size

### 3.1 Transport layout

Wire `lineage.proof`; the 320-byte public transcript (wire §3.2) precedes it and is counted in
F_payment.

| Offset | Bytes | Field | Rule |
|---:|---:|---|---|
| 0 | 3,648 | π_Ω: PIPA-R Pallas proof, k16, Direct typed instances, `FoldedGenerator` suffix, PIPA §7 order | exact descriptor length |
| 3,648 | 32 | acc_P.G (Pallas, compressed) | canonical, ≠ O |
| 3,680 | 512 | acc_P.u[0..16) (Fq, little-endian) | canonical, ≠ 0 |
| 4,192 | 32 | acc_V.G (Vesta, compressed) | canonical, ≠ O |
| 4,224 | 512 | acc_V.u[0..16) (Fp, little-endian) | canonical, ≠ 0 |
| **4,736** | | `lineage_proof_bytes` of the allowlist | §3.5 |

The 32-byte suffix keeps Ω's own opening point in the bytes, so the soft verdict of §2.7 is a
function of the bytes alone. Dropping it (4,704 B) is held in reserve.

### 3.2 Public instances and D_A

Ω's Direct instances are 19 Fq values: `[D_A (Bounded), acc_V.G.x, acc_V.G.y (Field),
acc_V.u_0..u_15 (Bounded)]`.

```text
D_A = P(kgwomg_1;
        version, scheme_id(lo,hi), relation_id(lo,hi), head, wallet_id(lo,hi), credential_digest,
        payment_key.x(lo,hi), payment_key.y(lo,hi), lifecycle + 2^8·policy_epoch + 2^72·enabled_controls,
        burned_total, pending_outgoing_root, credit_digest_root,
        vkΩ_digest,
        acc_P.G.x, acc_P.G.y, acc_P.u_0(lo,hi) … acc_P.u_15(lo,hi))
```

52 elements, **27 permutations** [C: ⌊52/2⌋ + 1]. `credential_digest` is one element because
the credential object digest is `P` (OQ-1). acc_P is bound only through D_A: Ω passes it
through, because it cannot do Pallas arithmetic. The native verifier recomputes D_A from the
public transcript, the transported acc_P and the constant `vkΩ_digest`.

### 3.3 Accumulator semantics

- **decide:** accept iff G = ⟨s(u), g[0..2^16)⟩ with s_i = Π_j u_j^{bit_{15−j}(i)} (PIPA §9.2).
- **Fold-input padding:** an obligation of k < 16 enters as (G, 0^{16−k} ‖ u); then s_i = 0
  for i ≥ 2^k, which is the k-round decide (prefix property, PIPA §3). Zero u_j occur only as
  fold inputs, never in transported accumulators.
- **Non-hiding fold completeness:** at least one input slot has source k16. If every
  actual obligation is shorter, the caller supplies an explicit pinned `ACC_TRIV`
  slot. Otherwise the upper half of h is identically zero, forcing the first IPA L
  point to be the identity for every salt, which the point format rejects. Native
  and circuit verifiers enforce this structural requirement. Full-length inputs
  still use fallible proving for exceptional zero challenges or identity messages;
  a salt retry cannot repair the all-short structural case.

### 3.4 PIPA-AS-v1 fold proof

BCMS20 PC_DL accumulation, implemented in
`iroha_plonk_recursion::accumulation`:

- **Transcript.** A base-field sponge with tag `pipa-as1` absorbs a canonical prover salt
  (one base-field element), r, and for each slot (finite G_i as [x, y], source k_i,
  normalized 16-element u_i), then squeezes full-width α, z and ζ_ipa in that order.
  The only permitted zero entries in input u_i are the checked prefix padding of §3.3.
  For each of the 16 rounds it absorbs L_j, R_j and squeezes nonzero u'_j; it then
  reads and absorbs c and reads the unabsorbed suffix G'. Challenge conversion and
  scalar/point absorption follow PIPA-R (§8). A zero u'_j rejects the proof.
- **Prover.** h(X) = Σ α^i h_{u_i}(X), C = Σ α^i G_i, v = h(z); a **non-hiding** 16-round IPA
  opening of C at z (PIPA §9.2 without ξ·C_s and f·W): L_j, R_j, c and the suffix G'.
  Its coefficient vector is `a = h − h(z)e_0`, so its evaluation is zero and its
  initial commitment is `C − v g[0]`; ζ_ipa scales U in the IPA equation below.
- **Verifier (succinct).** Recompute C with a complete Horner chain and v = Σ α^i Π_j (1 +
  u_{i,15−j} z^{2^j}); check C − v·g[0] + Σ(u'^{-1}_j L_j + u'_j R_j) − c·G' − c·b(z)·ζ·U = O;
  output (G', u').
- **Bytes and time.** 32·(2·16 + 2) = **1,088 B** [C] for the IPA body. The canonical local
  `FoldWitness` is `salt (32 B) ‖ proof_body (1,088 B)`, **1,120 B** in total; neither is
  transported in a Payment. Time: 2.9–3.1 s on 1 Mac thread
  [E: generator fold 1.92–2.03 s [M] + L/R MSMs ≈ 0.7 s].

### 3.5 Byte budget and thresholds

With PIPA §7, d = 6, k = 16 and the suffix, π_Ω is 32·(44 + V) bytes, where
V = n_a + 8n_l + n_z + q_a + q_f + m + max(3n_z − 1, 0) + n_s. The Ω budget with the
largest measured revision-4 σ_send is 8,277 − 3,456 = 4,821 B (B6 adds 42 B to
F_payment), so 32·(44 + V) + 1,088 ≤ 4,821 requires **V ≤ 72**. The baseline Ω descriptor has V = 70 [E].

The captured degree-nine secondary-range component has V = 69 and the exact
PIPA count 32·(47 + V) = 3,712 proof bytes, hence **4,800 transported bytes** [M].
The unchanged 4,821 B cap therefore requires V ≤ 69 at degree nine; the separate
G-Ω1 bound V ≤ 72 is also retained. Actual native Bootstrap-source proofs pass
for witnessed-key and pinned-one-key layouts; the captured witnessed-key
Bootstrap/Load/Send-mask0 catalog also passes its three-terminal rebuild. These
are historical component results. The current native producer pins the complete
catalog into its source; its fresh layout, proof size and signed-source rebuilding
remain pending. Descriptor equality does not transfer source qualification.
Ordinary-finality Load, the full catalog and every operation's qualification
remain open.


| Ω descriptor [E] | Transport [C] | Margin to 4,821 B |
|---|---:|---:|
| n_a 11, n_l 1, m 4, q_a 22, q_f 18, n_s 4 (baseline) | **4,736** | 85 |
| m 5 | 4,896 | −75 (fails) |
| n_a 12, q_a 24 | 4,832 | −11 (fails) |
| m 6, n_a 12, q_a 24 | 5,024 | −203 (fails) |
| + 1 lookup argument | 5,024 | −203 (fails) |
| Pow5 round constants share fixed columns with glue coefficients (q_f 13) | 4,576 | 245 |
| no suffix (reserve) | 4,704 | 117 |

- **G-Ω1:** the measured Ω descriptor has V ≤ 72 and exactly one lookup argument.
- **G-Ω2 (R9 joint):** |Ω| + max over allowlisted σ_send of |σ_send| ≤ 8,277 B, so with
  Ω = 4,736 B every σ_send is ≤ **3,541 B** [C]. k12 with one lane (3,296 B [M]) passes; k14
  with one lane (3,456 B [M]; the B5 quota-enabled shape, 309–345 permutations,
  12,123–13,542 used rows [S]) and k15 with one lane (3,488 B [C]) pass; k16 with one lane (the measured pre-B5
  quota shape, 3,584 B [M]) and k14 with two lanes (3,840 B [C]) fail. If no single-lane shape
  fits an enabled control, proposal §8 requires a new owner decision (contingent question
  C-1, §12).
- **Credited::Status** = 2,188 + |Ω| = 6,924 B ≤ 10,000; the allowlist caps Ω at 7,812 B
  (wire §§3.1, 4), a derived envelope bound that B1–B8 leave unchanged.
- F_payment (1,723 B, computed from the B6 Request fields) and F_status are marked † in wire
  §4 until `size_tests.rs` re-measures them; the thresholds follow those constants.

The current revision-4 single-lane descriptor inventory is below. Real native proofs
for quota-only and all-controls Send verify at 3,456 B; the remaining lengths are
exact descriptor calculations checked against both curves. PIPA-R migration and
actual Ω construction must preserve or re-establish these bounds before artifact
freeze; this is not an end-to-end payment measurement.

| Relation / mask | k | Poseidon permutations | Used rows | Folded proof bytes |
|---|---:|---:|---:|---:|
| Send 0 | 12 | 69 | 2,587 | 3,296 |
| Send 1 | 12 | 106 | 4,041 | 3,296 |
| Send 2 | 14 | 309 | 12,123 | 3,456 |
| Send 3 | 14 | 345 | 13,541 | 3,456 |
| Send 4 | 12 | 69 | 2,588 | 3,296 |
| Send 5 | 12 | 106 | 4,042 | 3,296 |
| Send 6 | 14 | 309 | 12,124 | 3,456 |
| Send 7 | 14 | 345 | 13,542 | 3,456 |
| Receive 0 | 12 | 67 | 2,510 | 3,296 |
| Receive 1 (recorded blacklist) | 12 | 104 | 3,958 | 3,296 |

### 3.6 Ω contents and rows

| Item [E] | Cells |
|---|---:|
| Verify A, full-width challenges (n_a 32), complete arithmetic included | 265–337k |
| Forwarded A instances (up to 66) | included |
| F_V^Ω verify, r = 3–4 | 70–91k |
| VK_A digest and fixed product-of-differences membership | ≈ 8.3k |
| **Total** | **0.36–0.46M**, capacity 0.58M (11 × 63k × 0.83) |

Rows: ≈ 181–190 GLV terms × 130 rows over 10 columns (≈ 23–25k rows) plus ≈ 300
permutations × 37 rows (≈ 11k) ≈ 36k of 65,530 usable rows [E]. k15 (32,762 usable rows) does
not fit.

## 4. Receiver payment path

### 4.1 Setup, off the 2 s window

1. **Offer.** Verify the payer credential (issuer signature with a variable key, its certificate
   under the root) and the Offer signature: 3 P-256 verifications, 0.25–0.28 ms each [M].
2. **Lineage.** The payer always sends it right after the Offer (proposal §5.1 permits it):
   - check Ω's scheme, `wallet_id`, credential digest and `payment_key` against the Offer;
   - recompute D_A (27 permutations);
   - succinct verification of Ω: ≈ 154 base-field permutations and ≈ 450 scalar operations,
     2–6 ms on the Mac [E];
   - **two decides with `msm_complete`**: Pallas batches Ω's opening with acc_P (2^16 + ≈ 90
     bases); Vesta decides acc_V (2^16 + 1);
   - cache the verdict under `lineage_digest = P_bytes(kgwlin_1, Ω bytes)` (wire §3.2).
3. **Request.** Record the enforced blacklist version and root (or `(0, 0)`) and retain the
   payer's 580-byte gap opening (B6), sign the Request and precompute σ_recv against the
   recorded root: 0.27 s on 4 Mac threads, 0.77 s on 1 [M].

### 4.2 At Payment arrival (critical path)

| Step | Work | Mac | Phone [E] |
|---|---|---|---|
| Decode ≤ 10,000 B canonically | — | < 0.1 ms [E] | < 0.3 ms |
| Ω(pred) byte identity with the cached Lineage Ω | byte comparison (equal `lineage_digest`) | < 0.1 ms [E] | < 0.1 ms |
| Consumer checks, Request account digests; for a nonzero recorded blacklist pair, its history lookup and the retained gap opening against the recorded root (B6) | equalities, ≈ 35 + 68 permutations | < 0.5 ms [E] | < 1 ms |
| σ_send `verify_full`, key by (Send, Ω.enabled_controls) | k12; its 2^12 G'_0 MSM is 36.8 ms [M] | **39 ms 1t, 14 ms 4t** [M]; PIPA-R re-measure G4.8 | 15–32 ms (4 cores), 43–90 ms (1 core) |
| τ_send and Request P-256 | 2 verifications | 0.5–0.6 ms [M] | < 2 ms |
| `P` work: statement 14, receipt message ≈ 7, `operation_id` 3, `proof_digest` 136, `credit_id` 14, Payment digest and its object digests ≈ 14 | ≈ 188 permutations | ≈ 1–2 ms [E; native permutation timing unmeasured] | 2–5 ms |
| Consumed-credit IMT non-membership and insert in Advance | 265 permutations + store I/O | ≈ 1.5–3 ms + I/O [E] | 3–8 ms |
| σ_recv | precomputed; re-proved only if the head changed | 0 (0.27 s 4t [M]) | 0 (0.3–0.7 s) |
| τ_recv hardware signing, self-verify (0.25 ms), two durable commits | — | unmeasured | unmeasured |
| **Proof CPU, pre-verified** | | **≈ 49–58 ms on 1 thread** [E] | **≈ 35–140 ms** |
| Add if Ω was not pre-verified | §4.1 step 2 | 836–846 ms 1t [M, 2 × 418–423 ms]; 261–325 ms 4t [E] | **+0.29–0.75 s** (4 cores, optimistic); +0.48–1.50 s (pessimistic) |

Native verification is exactly PIPA-v1's predicate plus the PIPA-R transcript; parity with
the in-circuit verifiers comes from complete in-circuit arithmetic (§7 C7), not from any
native replay.

### 4.3 Against 1–2 s

The remainder of the 2 s budget is the payer's σ_send (0.27 s on 4 Mac threads [M],
≈ 0.3–0.7 s on a phone [E], provable speculatively after the Request is verified), a ≤ 10 KB
transfer, two hardware signatures and two durable commits (unmeasured). The cold path fits
2 s only if those stay under ≈ 0.5–0.9 s; pre-verification makes the receiver side
negligible.

### 4.4 Ledger and CreditStatus verifiers

Unload, fee claims and CreditStatus use the same native procedure: one Pallas and one Vesta
decide per Ω, 0.84 s on 1 Mac thread [M]. CreditStatus also recomputes Ω(h)'s
credit-digest root from the 32-sibling leaf opening (wire §3.4): 64 node permutations plus 4
for the value and the leaf.

## 5. Per-operation Λ budgets

### 5.1 Check placement

| Check | Placement |
|---|---|
| C1 predecessor | A: Ω(pred) hard with witness key K; Bootstrap uses the base variant |
| C2 own σ | Q_σ: hard σ verifier, key one-hot (Receive: by its Request's recorded blacklist version, B6). A recomputes the 26-element statement digest (14 permutations) and checks d_σ and `vk_index` |
| C3 own τ | Q: V slot under `payment_key` with 1 SHA block. A computes the signing message `m = P_bytes(kgwrcpt1, receipt body)`, `operation_id` (3), `proof_digest` = `P_bytes` over the linked bytes (55 σ-only or 136 Ω‖σ) and the receipt object digest `P(kgworcp1, [m, r_lo, r_hi, s_lo, s_hi])` (3) where a package digest needs it |
| C4 R10, spec-literal | Q: the current credential (V, issuer key from its certificate) and its certificate (F, scheme root), every step. A opens the credential body (25 + 8 permutations) and checks scope, relation, tag and provider contract |
| C5 continuity | A equalities. Λ_send checks the Request's payer account digest against the payer's own credential. Λ_recv verifies the Request's receiver credential, which binds `wallet_id`, `payment_key` and the receiver account digest; deduplicated with C4 when the digests are equal, otherwise verified (Receive (renewed): +V +F) |
| C6–C8 | A: core and rest openings, IMT operations, u128 arithmetic, lineage-adjusted values |
| C9 `relation_id` | carried in D_A |
| Incoming Payment | Ω_in soft in A; σ_send, τ_send and Request soft in Q; consumer checks and `credit_id` non-membership soft in A. No fee-schedule signature: proposal §3.2 gives fee terms to Λ_send against the payer's own policy, and the Request signature binds the fee and schedule digest |
| Receive recorded blacklist (B6) | for a nonzero recorded pair, a hard-authenticated lookup of its version in the predecessor rest's blacklist-history IMT (the leaf or its low leaf, ≈ 68 permutations), whose soft bit (present with the recorded root) joins the Request's verdict; σ_recv proves the gap in the recorded root. A recorded `(0, 0)` needs nothing |
| Credited evidence | (i) σ_recv (key by the Request's recorded blacklist version) and τ_recv soft in Q, with `proof_digest(σ_recv)` linked. (ii) Ω(h) soft in A, τ(h) soft in Q, IMT membership of `credit_id → (Payment digest, burned)` in Ω(h)'s credit-digest root (≈ 70 permutations) |
| ArchiveSent removal | two wire §3.2 removals (core root and Λ root; the Λ one skipped on the no-op branch); each relinks the predecessor and clears the slot: 4 depth-32 traversals (256 permutations), 3 leaf hashes (6) and the 7-element pending value bound to the retained Payment's descriptor (4), ≈ 266 permutations, so ≈ 2 × 266 for both, which §5.4 counts. Core and lineage removals are separate unless their roots and descriptors coincide |
| RefreshPolicy (Blacklist), B6 | insertion of `(list_version, entries_root)` into the rest's blacklist-history IMT (≈ 264 permutations) |
| RefreshPolicy (QuotaShare), OQ-4 with B5 | rebuild of the 64-slot usage array: the 64 predecessor usage leaves against the core's `quota_usage_root` (318 permutations), the 64 new window leaves against the share's signed `windows_root` (318) and the 64 successor usage leaves (318), ≈ 954 permutations, plus a constrained sorted merge of the two key-sorted arrays (the current deterministic 128-entry bitonic merge uses 448 compare/swap nodes): matching keys keep `end` and carry `used`, an absent key starts at 0 only with `start ≥` the new floor (unless no share was held), a charged key is dropped only with `end ≤` the new floor, and every window is longer than `time_anchor_max_response_ms` (B8) |

Current component evidence: the complete fixed64 quota rebuild plus both state openings and refresh effects fits k16 at 51,652 maximum assigned rows on the stand-alone sponge lane (36,008 range rows, 17,670 glue rows). The same constraints pass on A’s shared verifier duplex. Its actual Bootstrap-rooted recursive composition exceeded k16 at 91,131 rows, and the run stopped before generating an oversized proof. The replacement source assigns three exact array-root owners and one deterministic matching owner, all mandatory. Their shared internal context contains `[H_old, H_windows, H_used, issued, count]`; the three hashes use `kgwciw_1` with distinct tags7/8/9 and fixed counts256/256/64. The context object uses tag6 and count5 (160 bytes of canonical field words). Each root owner opens every array it consumes; the matching owner opens all three arrays and binds issue/count to the signed share. This preserves all578 witness words and all fixed64 semantics without duplicating every array hash in every stage. The first eight-stage recursive attempt produced four valid 7,744-byte A proofs, then failed the PreviousRoot stage at 68,931 rows. Its result is retained; no oversized proof was generated. Root-only stages now retain proposed object digest/length/tape triples under the exact complete quota task/schema plan. Mandatory Effects and authorization owners recompute every signed original, and Merge binds signed issue/count; root proposals cannot supply signed fields. The eight-stage proposal preflight reduced PreviousRoot to 65,490 rows but found WindowRoot/UsageRoot at 67,303/70,411. It generated no Refresh proof. The current seven-stage schedule places Effects+PreviousRoot with the hard predecessor at A0, WindowRoot at A1, UsageRoot at A2, Q-sigma at A3, update authorization at A4, current authorization at A5, and Merge at A6. The seven-stage unknown-witness preflight and genuine recursive closure pass at maxima53,206/60,014/63,122/62,715/61,679/62,974/61,420 under the unchanged65,529 ceiling. The representative-W preflight is only a sizing diagnostic; the actual chain derives every successive key and independently confirms those bounds. All seven A proofs are7,744 B and all six W continuations verify with every original/Q/opening obligation retained. The captured native producer/canonical checkpoint test passes1/1 in3,884.48 s with exact A/W proof-byte replay and every checkpoint restored. This uses the earlier typed-key mount; current strict original-PK intake is qualified separately. The component result establishes neither a performance gate nor terminal admission.

Signed messages are `P_bytes` over the body transcript (wire §1): A links the transcript
bytes (2–3 cells per byte, 108–476 B per body) and hashes them; Q receives m as a Bounded
instance and feeds its 32-byte canonical encoding to SHA-256.

### 5.2 Signature, SHA and proof counts (spec-literal R10)

| Operation | P-256 V / F | SHA blocks | σ verified | Ω verified in A | Bytes linked in A |
|---|---|---:|---:|---:|---|
| Bootstrap | 2 / 1 (τ, credential; certificate) | 3 | 1 | 0 | σ (3.3 KB) |
| Load | 2 / 1 (own receipt, credential; Enrollment certificate) | 3 | 1 | 1 | σ; exact receipt and native-authorized Advance signature |
| Send, Unload, Retiring | 2 / 1 | 3 | 1 | 1 | Ω(pred) ‖ σ (8.4 KB) |
| Receive | 4 / 1 (τ_recv, credential, τ_send, Request; certificate) | 5 | 2 | 2 | σ_recv; Ω_in ‖ σ_send |
| Receive (renewed receiver credential) | 5 / 2 | 7 | 2 | 2 | as Receive |
| ArchiveSent (i) | 3 / 1 (+ τ_recv) | 4 | 2 | 1 | σ, σ_recv; opaque Payment `proof_digest` (283 chunks) |
| ArchiveSent (ii) | 3 / 1 (+ τ(h)) | 4 | 1 | 2 | σ; opaque Payment `proof_digest` |
| RefreshPolicy (every kind) | 3 / 2 | 5 | 1 | 1 | σ |

**σ byte crossing.** σ is verified in Q (Fq) but its `P_bytes` digest is computed in A (Fp).
Q decomposes the length-prefixed σ bytes into 31-byte chunks (2–3 cells per byte)
and exports them as Bounded instances (each < 2^248 < p). The fixed descriptor
selects the export length: `ceil((4 + |σ|) / 31)`, 107 chunks for the measured
3,296-byte k12 class and 112 for the measured 3,456-byte k14 class. A checks the
same class and length, including the final zero padding. Its estimated Lagrange
evaluation cost is ≈ 0.43k cells per chunk [E], about 46k–48k cells per σ.

### 5.3 Shapes and unit costs

| Circuit | k | Advice | Local proof bytes [C] | Capacity (cells, 0.83 packing) [E] | Prove, Mac 1t [E] |
|---|---:|---:|---:|---:|---:|
| σ | 12 | 5 | 3,296 [M] | — | 0.77–0.78 s [M] |
| Q | 16 | 22 | 6,016 | 1.15M | 21–30 s |
| A | 16 | 32 | 7,424 | 1.67M | 26–36 s |
| Ω / W | 16 | 11 | 3,648 (+1,088) | 0.58M | 15–21 s |
| PIPA-AS fold | K16 | — | 1,088 | — | 2.9–3.1 s |

Historical prove-time calibration [E]: a 25-column k16 circuit took 43.5 s with the
vendored prover on one thread [M]; the measured native/vendored ratio of 0.43–0.60
gave an estimate of 18.7–26 s. Current native k16 synthetic and real-chip measurements
are recorded in the [evidence checklist](kagemusha_evidence_gate.md); that campaign
still has hard failures, borderline margins and incomplete configurations. These
historical estimates cannot establish the current G3.6 result.

| Unit | Cells |
|---|---:|
| Pow5 permutation | 148 [M] |
| Tree node `P(d, [l, r])` | 2 permutations = 296 [M] |
| P-256 variable key (complete, low-S, SEC1, soft) | 0.2–0.4M [E]; **threshold 0.30M**; historical retired-engine measurement: 1,466,624 [M, checklist §8] |
| P-256 fixed key (scheme root) | 0.06–0.15M [E]; **threshold 0.12M** |
| SHA-256 block, degree 6 | 37–50k [E] (Table8 source estimate 2,304 rows, unmeasured) |
| FF-CRT multiplication (Fq-in-Fp, Fp-in-Fq, P-256 p and n) | 80–100 [E] |
| GLV variable-base multiplication, full width | 1.2–1.5k + complete tail [E] |
| Complete-arithmetic surcharge per verified proof | 10–15k [E] |
| Verify σ / Q (24 instances) / A / Ω, complete arithmetic included | 149–191k / 236–297k / 265–337k / 167–212k [E] |
| Each further Direct instance of a verified proof | ≈ 0.43k [E] |
| PIPA-AS verify, r = 2 / 4 / 7 | 65–79k / 75–91k / 91–109k [E] |
| IMT insert or removal / non-membership / membership (depth 32; no map updates a value in place after B5) | 39.7k (265–267 permutations) / 10.0k / 9.9k [E] |
| Quota-usage array charge (depth 6, B5): window opening 15 + usage old and new 30 permutations | 6.7k [E] |
| Quota-usage array rebuild (three 64-leaf depth-6 trees, B5) | 141k (954 permutations) + merge [E] |
| Byte linking | 2–3 per byte; opaque 31-byte chunk ≈ 20 [E] |

### 5.4 Per-operation budget at the M3 P-256 thresholds (V 0.30M, F 0.12M) [E]

| Operation | Q leaves (cells) | A cells (cap 1.67M) | Ω cells | Folds | Proofs (Q + A + Ω) | Mac 1t | Phone 4 cores, optimistic / pessimistic |
|---|---|---:|---:|---:|---:|---:|---:|
| Bootstrap (original combined-leaf estimate; current implementation uses at least 2 Q leaves) | 1 (1.00–1.09M) [E] | 0.31–0.40M | 0.34–0.43M | 1 | 3 | 67–94 s | 23–87 / 39–166 s |
| Load (current native-BLS schedule) | 3; current cells pending measurement | 4 A stages; current cells pending measurement | Current cells pending measurement | 3 W stages | 8 (+ 3 W) | Unqualified | Unqualified |
| **Send** | 1 (1.00–1.09M) | 0.67–0.81M | 0.36–0.45M | 2 | 3 | **70–97 s** | **24–89 / 41–172 s** |
| **Receive** | 2 (1.02–1.07 + 0.83–1.05M) | **1.18–1.45M** (B6 history lookup included) | 0.37–0.46M | 3 | 4 | **96–132 s** | **33–122 / 55–234 s** |
| Receive (renewed) | 3 | 1.43–1.76M; A-split at the high end | 0.37–0.46M | 3 (+2) | 5 (+2) | 118–163 s (+48–65 s split) | 40–150 / 68–289 s (+ split) |
| ArchiveSent (i) | 2 | 0.98–1.20M | 0.36–0.45M | 3 | 4 | 95–132 s | 33–121 / 55–233 s |
| ArchiveSent (ii) | 2 | 1.11–1.37M | 0.37–0.46M | 2 | 4 | 93–129 s | 32–119 / 54–228 s |
| Unload | 1 | 0.62–0.77M | 0.36–0.45M | 2 | 3 | 70–97 s | 24–89 / 41–172 s |
| Retiring | 1 | 0.58–0.73M | 0.36–0.45M | 2 | 3 | 70–97 s | 24–89 / 41–172 s |
| RefreshPolicy (Credential, worst other kind) | 2 | 0.81–1.02M | 0.36–0.45M | 2 | 4 | 92–128 s | 32–118 / 53–227 s |
| RefreshPolicy (Blacklist, B6 history insertion) | 2 | 0.85–1.06M | 0.36–0.45M | 2 | 4 | 92–128 s | 32–118 / 53–227 s |
| RefreshPolicy (QuotaShare, OQ-4 with the B5 array rebuild) | 2 | 0.97–1.18M; no A-split | 0.36–0.45M | 2 | 4 | 92–128 s | 32–118 / 53–227 s |

Load verifies ordinary BLS finality natively before Advance signing; it has no
recursive BLS-finality stage. Its compiled schedule is three Q, four A, three W
and one Ω proof (`a_relation/schedule/compiled.rs`). The table's other historical
estimates and the model below do not measure this schedule. Current Load timing,
memory and full-catalog artifact qualification remain separate gates; retaining
Pasta payment proofs does not restore independent in-proof funding verification.

Historical time model [E]:

- Mac = n_Q·T_Q + T_A + T_Ω + folds·T_fold + proofs × (0.5–1.0 s, proving key from VK) +
  self-verify 0.86–0.90 s + 0.3 s per incoming-claim decide.
- Phone = Mac × 1.1–2.3 per core ÷ 2.5–3.2 for 4 cores (optimistic: 2.9× measured for σ k12,
  3.2× for narrow k14) or ÷ 1.3–1.9 (pessimistic: vendored wide-k16 scaling [M]).
- Time is set by the number of k16 proofs, not by cells.

### 5.5 Sensitivity

- **P-256 in its 0.2–0.4M estimate band.** Send-class steps take 1–2 Q leaves (70–128 s on 1
  Mac thread). At the high end Receive needs 3 Q leaves and A reaches 1.75M, so it takes the
  A-split: ≈ 229 s on 1 Mac thread, 210 s (optimistic) to 404 s (pessimistic) on 4 phone
  cores [E].
- **OQ-1 (B1, applied)** removes the SHA-256 work an `H`-digest wire record would add: about
  10–16 blocks per ordinary step, 41 on Receive and about 150 on ArchiveSent (ii) [E].
- **Available levers, none needed for a binding requirement:**

| Lever | Effect [E] |
|---|---|
| Inductive R10 (verify the credential only at Bootstrap and refresh) | Load, RefreshPolicy and ArchiveSent drop to 1 Q leaf (−22–31 s) |
| `proof_digest` over binding digests | −55–135k cells in A per step |
| Inline own σ instead of verifying it | −150–190k cells in Q |
| Precommitted own-key table | own τ 0.04–0.08M instead of 0.3M |
| 128-bit fold challenges | Ω −512 B |
| Audited fixed-base batch-affine decide (PIPA S10 amendment) | cold receiver ≈ −45% |
| 1-permutation tree nodes (hash-format change) | IMT costs −50% |

### 5.6 Scheduling, checkpoints, preemption

- **Checkpoints.** Sub-proofs run strictly in order and each output is persisted with
  the exact stage type and byte bound from the frozen proof descriptors. The earlier
  approximately 7.4 KB estimate was based on the estimated A layout (7,424 bytes),
  not an independent 7,400-byte wire limit. Current local workload proofs are larger;
  their measured bounds must replace estimates before the wallet schedule is frozen. A
  crash loses at most one sub-proof (15–36 s on 1 Mac thread).
- **Preemption.** Any payment interaction (Offer, Request, Payment) aborts the running
  sub-proof through a cooperative cancellation token checked at Rayon task boundaries, which
  frees its memory; the fold resumes from the last checkpoint. The payment path then has the
  device to itself (σ_recv proving peaks at 45–49 MiB, decides at 16.4 MiB [M]).
- **Order.** Folding runs in step order whenever the app runs or the phone charges. Receive
  needs no fold to complete; only the next Send, Unload or device move waits for the backlog.

## 6. RAM plan (≤ 1 GiB)

The peak falls in the quotient phase [E]:

- vectors = PK[2(F + m) + 6] + witness[c·n_a + 8n_l + 2n_z] + coset[n_a + F + m + n_z + 3n_l +
  4] + 2(d − 1);
- × 2 MiB at k16 × 1.15, + 8 MiB params + 64 MiB MSM scratch cap + 50 MiB core baseline.

The original borrowed-witness estimate used c = 3; the implemented consuming-witness
path uses c = 2 in that estimate. Advice values move into coefficient buffers after
the permutation and lookup products are built
[S `crates/iroha_plonk/src/prover/advice.rs`]. The table below retains design estimates;
current peak RSS qualification must use the measured owned-witness path and complete
process lifetime. Streaming fixed/permutation columns remains a separate memory choice.

| Circuit | Borrowed estimate (c = 3) | Owned estimate (c = 2) | Streamed estimate |
|---|---:|---:|---:|
| A (32 / 44 / 10 / 3) | 0.91 GiB | **0.84 GiB** | 0.64 GiB |
| Q (22 / 32 / 8 / 3) | 0.72 GiB | 0.67 GiB | 0.53 GiB |
| Ω / W (11 / 18 / 4 / 1) | 0.44 GiB | 0.42 GiB | 0.34 GiB |
| PIPA-AS fold prover | ≈ 0.03 GiB | | |

Rules:

1. One prover at a time; Q leaves never run in parallel.
2. OnDemand coset policy [S `keys/pk.rs`]; Eager adds (d − 1)(F + m) vectors (≈ +0.6 GiB for A).
3. No cached proving keys: `keygen_pk_from_vk` rebuilds fixed and permutation values and
   coefficients from synthesis without commitment MSMs (0.5–1.0 s on 1 Mac thread [E]).
4. The owned-witness API (M4) is mandatory; streaming is the margin lever.
5. A process-wide MSM scratch budget of 64 MiB shared by concurrent kernels (the per-kernel
   `MemoryBudget` default is 256 MiB [S `crates/iroha_pasta/src/msm/budget.rs`] and advice
   commitments run in parallel).
6. No commitment tables while folding (+84 MiB per curve for a 4–6% gain [M]).
7. Envelope: measured prover peak ≤ 0.85 GiB plus ≤ 0.15 GiB for the rest of the wallet core.
   A circuit whose measured peak exceeds 0.85 GiB is split: A by the A-split, Q by moving a
   slot to another leaf.
8. Preemption frees memory (§5.6).

## 7. Soundness argument

Each claim rests on published constructions except where marked **novel**.

**C1. Single proofs (PIPA-v1 and PIPA-R).** PLONKish arithmetization with the GWC19
permutation, halo2 permuted lookups and the BGH19 IPA with succinct check and amortized
generator. Fiat–Shamir uses RP57 Poseidon as a random oracle; multi-round soundness follows from
state-restoration / round-by-round soundness. PIPA-R changes only absorption encodings, which
stay injective, and the challenge map: points as native [x, y]; a Vesta proof's Fp scalar as one
Fq element; a Pallas proof's Fq scalar as S6 limbs (lo < 2^128, hi < 2^127, lo + 2^128·hi <
q); challenges map Fq → Fp by w mod p and Fp → Fq by identity, at distance ≤ (q − p)/q =
2^−167.84 [C] from uniform. The [implementation argument](kagemusha_recursion_soundness_v1.md) records the
framing and challenge-map derivation; its remaining composition and simulator
review obligations must be closed before freezing (G4.1).

**C2. Accumulation (PIPA-AS-v1).** BCMS20 PC_DL accumulation (ePrint 2020/499 §7 and Appendix A) on BGH19 §3.
If (G', u') decides then, except with probability about (r + 2^16)/|F| per hash query, the
opened C = Commit(h) and every input decides, except with the computational soundness
error: α is squeezed after every input is absorbed (cancelling inputs is a degree-r event)
and z after those bound inputs and α determine C (a degree-2^16 event). C is not absorbed
again. These are computational claims under Fiat–Shamir, not a literal equivalence for
every possible challenge output. The format has no
hiding term, so "G is the commitment" is enforced by the decide itself.

**C3. PCD composition.** Each step is a constant-depth DAG (Q → A → Ω, or Q → A_1 → W → A_2 →
Ω), composed into PCD by BCMS20 PCD-from-accumulation and BCLMS21 (ePrint 2020/1618). The
theorems give constant depth; **unbounded lineage depth is heuristic**, as for Halo 2, Pickles
and Nova, and PIPA §11's TODO remains.

**C4. Full succinct verification in the base field.** Transcript and group operations of each
consumed proof are native in its verifier circuit. Scalar arithmetic is CRT foreign-field
arithmetic: the native residue plus 3-limb arithmetic modulo 2^258–2^264; an integer identity
holds when both residues agree and every limb and carry is range-bounded (halo2-ecc /
halo2wrong practice; 3 × 86-bit limbs fail the 512-bit product bound, 3 × 87 hold). **A written
carry-bound proof per modulus (P-256 p and n, Fq-in-Fp, Fp-in-Fq) is an M3 exit item (G3.4).**
Only accumulators and typed instances cross the cycle, each checked by equality.

**C5. Composition inside a step.** A's statement is the conjunction of its inner
verifications, equality of every Q instance with A's own values (`m`, keys, d_σ, `vk_index`, σ
byte chunks, accumulators, modes) and its own `P` relations. Hard slots force `valid = 1`.
Soundness follows by conjunction and C2.

**C6. Verifying-key continuity (§2.4).** Basis: the Pickles wrap-key treatment
(`dlog_plonk_index`). Induction on lineage depth: the native check pins the final D_A's
`vkΩ_digest` to the constant; A_h enforces `P(K_h)` equal to that field and to D_A(pred)'s
field, so K_h is genuine and Ω(h − 1) was verified under the genuine key; knowledge extraction
of Ω(h − 1) yields A_{h−1}'s witness, whose own equality continues the induction. It relies on
collision resistance of `P`. A payer Ω under a foreign key soft-fails, because D_A(in) is
recomputed with the receiver's field.

**C7. Complete in-circuit arithmetic and exact native parity.**

- *GLV iterations.* With acc initialized to [2]·T_top and joint signed digits {±1}, the
  accumulated scalar pair (a, b) has odd components with |a| ≥ 3 after the first iteration.
  The incomplete addition at iteration i is exceptional only if a nonzero vector of sup-norm ≤
  2^{i+2} + 1 lies in the GLV lattice {(x, y) : x + λy ≡ 0 mod r}. Its sup-norm minimum is
  **2^126.21 for both Pasta scalar fields** [C, Gauss reduction], so iterations i ≤ 124 are
  exception-free for every base P ≠ O and every scalar (Orchard's incomplete-addition argument
  lifted to GLV). Circuits use incomplete addition for i ≤ 122.
- *Remaining operations.* Iterations i ≥ 123, every Horner join and the IPA and fold sums use
  complete addition; bases that can be O are guarded by selection; [u_j^{-1}]L_j is a witness
  Q_j with [u_j]Q_j = L_j.
- *Consequence.* In-circuit group arithmetic is complete for every decodable input. With PIPA
  S11 (one table-driven predicate) and soft totality, the in-circuit verdict equals the native
  verdict exactly. Native verifiers stay `msm_complete` (S10).

**C8. Containment (§2.7). Novel selection rule.** Accept is sound by C2 on every gated slot.
Burn is sound because either a soft bit is false (by C7 the native verifier also rejects) or a
corrected claim is folded, so by C2 G* = ⟨s(u_j), g⟩ ≠ G_j and the native decide of that
obligation rejects. A representable corrected claim decides; exceptional identity corrections
fail encoding as described in §2.7. For completed proofs, (accept ⇔ native accept)
∧ (burn ⇔ native reject), so the branch is unique. A burn moves value only out of the
receiver's spendable balance; it cannot create value. The OQ-3 root rule keeps the
consumed-credit IMT invariant (C10) on the burn branch, so no later non-membership becomes
false. The B6 history lookup keeps the branch unique: its opening is hard, and its soft bit
is a function of the authenticated leaf or low leaf, so the prover cannot select burn with a
bad path. The [containment argument](kagemusha_recursion_soundness_v1.md#branch-uniqueness-and-containment)
reduces the selection rule to C2, C7 and C10; complete operation binding and
independent review remain G4.1 work.

**C9. Hard-verifier completeness and retries.** C7 gives native/circuit verdict agreement;
it does not exclude zero challenges, identity messages or exceptional denominators for an
honest witness. The native Q/A/Ω owners perform one proving attempt and propagate proof,
self-verification, entropy, resource and cancellation failures. A failure does not establish
payment completion or authorize a burn. PIPA-AS does not silently retry its salt,
and a salt retry cannot repair an all-short input set (§3.3).

A retry of unpublished proof work is a new attempt; all hash queries and any fresh blinds
or fold salts actually drawn enter the bounded experiment, including failed attempts.
Q's capsule-derived public local-fold nonce is reused and is not fresh private entropy.
Retained checkpoints and completed Ω records are restored from their exact bytes;
payment retries return the retained Payment and never repeat irreversible Send. The
[conditional failure bounds](kagemusha_recursion_soundness_v1.md#conditional-honest-fold-abort-bound)
retain their independent-challenge premise and separate operational failures. Hiding and
verdict parity alone establish no unconditional liveness or zero failure probability.

**C10. Maps.** Every wallet map except the quota-usage array (below) and the credit-digest tree
is the wire §3.2 depth-32 indexed Merkle tree (the Aztec construction): leaves `(key, value, next_key)` sorted and linked from a
zero sentinel; membership opens the key's leaf; non-membership opens the low leaf with
full-field comparisons through S6 limbs; insert relinks the low leaf and writes into a slot
opened as empty in the intermediate root; removal relinks the predecessor and clears the slot.
The invariant (unique keys, one sorted list, every present key reachable) holds by induction,
because every insert proves absence through the low leaf and writes only an empty slot. Slot
positions carry no meaning, so the next free index stays a native rule that no root commits
(wire §3.2) without affecting soundness: allocation position and lifetime exhaustion are
native-store policy, not proved map semantics. A prover slot that differs from the native
store only breaks its own successor commitment, and CreditStatus relies on Ω's certified
root through membership alone. Slot `2^32 − 1` is a valid slot and only `f = 2^32` is
rejected (G1); any IMT reference kept for Λ follows that rule. Removal never reuses a slot:
unlinking without clearing would leave an orphan whose membership still opens. The
quota-usage map is not an IMT (B5): it is a depth-6 array whose slot `i` is bound to window
slot `i` by equal index, kind, start and end, so a Send's in-place charges at distinct slots
commute and leave every other slot unchanged. An empty slot (element 0) never opens as a leaf: that
would be a `P` preimage of 0. Leaf and node domains are separated (`kgwimlf1`, `kgwimnd1`);
binding is collision resistance of `P`.

**C11. Hash-then-sign.** ECDSA(SHA-256(enc(P_bytes(d, body)))) reduces to collision resistance
of `P` and of SHA-256 on 32-byte inputs, plus P-256 EUF-CMA (owner protocol choice). The
in-circuit P-256 is complete for natively accepted inputs: complete Renes–Costello–Batina
formulas, low-S, x(R) mod n.

**C12. Zero knowledge.** Ω uses the hiding proof construction in PIPA §13. For a deciding
accumulator, G = ⟨s(u), g⟩ is determined by u and the pinned generators. D_A hashes the
18 public lineage fields and acc_P's coordinates and challenge limbs (52 field words),
so it adds no information beyond that public tuple. Q, A and the local fold proofs are
not transported; `wallet_id` and `payment_key` are already public.

A receipt's public `capsule_commitment` binds its frozen private recovery body
through the selected private opening described in proposal §4.1. For any fixed
body and auxiliary information fixed before independent uniform r is drawn,
`m0 g[0] + m1 g[1] + r w` is uniform in Vesta. Its deterministic `kgwcapc1` hash
therefore has the same distribution for every body, including the explicit
zero-hash refusal branch. This does not assert a uniform digest or a 1/p zero
probability. The private wrapper hash and r never appear in that receipt.
Binding uses SHA/Poseidon collision resistance and the admitted IPA tuple's
existing generator-relation premise. A/Q continue to authenticate the opaque
receipt field and payment-key signature; the trusted native provider verifies
the full wrapper and opening before signing.

These local facts do not prove privacy of the joint public transcript. The two exposed
challenge vectors come from non-hiding folds and can share inputs correlated with
public σ proofs and earlier accumulators. A simulator must handle both vectors and Ω
under one random oracle, including adaptive queries, retained checkpoint reuse, retries
and exceptional aborts. Independently sampling two vectors does not by itself produce
an Ω witness or establish that distribution. Fresh private salts support a possible
hidden-prefix argument, but that argument and the composed simulator remain M4 work
([recursive soundness memo](kagemusha_recursion_soundness_v1.md), PIPA §13 TODO).
No stronger privacy or linkability conclusion is established by this paragraph.

## 8. PIPA-v1 extensions (applied to `plonk_ipa_v1.md` in M4)

- **PIPA-R profile.** A descriptor whose `transcript` is `KagemushaPoseidonRp57Base` is a PIPA-R
  proof: its transcript runs over the proof curve's base field B, it uses Direct instances with
  declared types and it carries the `FoldedGenerator` suffix. Every proof a KAGEMUSHA circuit
  verifies in-circuit (σ, Q, A, Ω, W) is PIPA-R. Message order, the §7 length formula and the
  §8–9 verifier equations are unchanged.
- **`CircuitDescriptorV2`** (`iroha.plonk.pipa.circuit_descriptor.v2`) = V1 plus the
  `KagemushaPoseidonRp57Base` transcript and `instance_types` (`Field`, `Bounded` (< p),
  `Bits(b)`, b ≤ 253) per instance column. PIPA-R requires `Direct` instances and the suffix;
  `descriptor_digest` and `transcript_repr` move to v2 domains, with `transcript_repr` a B
  element. Protocol version remains 1; the canonical descriptor schema uses the explicit
  v2 domain `PIPA-v2-CircDesc` and key domain `Iroha-PlonkVK-v2`. No decoder guesses a
  descriptor version or retries another profile. Type codes are Field = 0, Bounded = 1
  and Bits(b) = 2 + b for 0 ≤ b ≤ 253. Each instance column has one homogeneous type;
  mixed public statements use multiple columns (Ω lengths 1, 2 and 16).
- **§6.2b base-field transcript.** `iroha_pasta::poseidon::Sponge` over B, first element
  `B::from(u64::from_le_bytes(*b"pipa-rb1"))`; points as canonical [x, y] (O rejected);
  scalars as one element when |F| < |B| and as S6 limbs when |F| > |B|; challenges c = w − p
  if w ≥ p else w (Vesta proofs) and c = w (Pallas proofs); `common_base(transcript_repr)`
  absorbed first. §6.3 absorbs one type code per instance column, and a value outside its type
  is rejected (`InstanceType`). The precise prelude is the key representation, the
  `pipainst` tag, column count, all column lengths, all column type codes and finally
  the column-major values. The tag, count, lengths and type codes are native base-field
  metadata elements, not proof-scalar messages. Field
  requires a canonical proof-scalar value, Bounded additionally requires `< p`, and
  Bits(b) additionally requires `< 2^b` (Bits(0) admits only zero). Generic proof scalars
  use the curve's scalar-absorption rule regardless of the declared instance type;
  Pallas scalar absorption therefore always uses S6 limbs.
- **§9.3 in-circuit verifiers.** Horner chains with complete joins; variable-base `[c]P` by GLV
  (`c = k1 + λk2`, |k1|, |k2| < 2^128, one foreign-field multiplication), acc = [2]T_top,
  incomplete addition for i ≤ 122 and complete after; identity-guarded bases;
  `u_j^{-1}L_j` as witnessed Q_j with [u_j]Q_j = L_j; fixed bases (`g[0]`, `U`, `W`,
  `ACC_TRIV.G`) by 3-bit windows with a complete final window; soft mode as in §2.7. Foreign
  arithmetic is CRT with a written carry bound per modulus.
- **§11.1 `AccumulatorT`** = `G ‖ u_0..u_{K−1}` (32 + 32K bytes), canonical G ≠ O and nonzero
  canonical u_j. **§11.2 PIPA-AS-v1** as §3.4, with slot modes Accept, Trivial and Corrected
  (G* ≠ G, same u), and acceptance of a lineage proof = the decide of each exposed accumulator
  plus its own opening, batched per curve.
- **§12 invariants.** S6 and S11 extended to cross-cycle typed instances and the σ, Q, A, Ω, W
  and PIPA-AS verifiers; new **S12** complete in-circuit verification (§7 C7), **S13**
  obligation ledger (§2.3), **S14** key binding (§2.4). **§14** registers DEV-12 (base-field
  transcript) and DEV-13 (typed instances).
- **§15 open items, blocking the KAGEMUSHA artifact freeze:** the Fiat–Shamir memo for 6.2b and
  PIPA-AS-v1, the CRT carry-bound proofs, the GLV lattice KAT, the PCD statement and a Python
  reference verifier for 6.2b, PIPA-AS-v1 and `decide`.

## 9. Gadget list

Chips go in `iroha_plonk_gadgets` (M3); recursion components in the new workspace crate
`iroha_plonk_recursion` (M4). Every chip has degree ≤ 6, deterministic witness generation and
native/in-circuit equality tests against native references (`iroha_pasta`; test-only `p256`
0.13, `sha2` 0.10 and `num-bigint` 0.4, already in `Cargo.lock`). Vendored halo2 is only a test
oracle; the `iroha_core_zk` gadgets below are references, never dependencies.

| Gadget (crate::module) | Fields | Cost [E] | Port or learn from | Notes |
|---|---|---|---|---|
| FF-CRT chip `iroha_plonk_gadgets::ff` | Fq-in-Fp, Fp-in-Fq, P-256 p and n | 80–100 cells per multiplication; add ≈ 5; inverse = witness + 1 multiplication | `kagemusha_p256_curve_gadget.rs` (3 × 87-bit bound) | 15-bit range table; carry-bound memo |
| Pasta ECC chip `::ecc` | Pallas-in-Fp (A), Vesta-in-Fq (Q, Ω) | GLV variable base 1.2–1.5k + complete tail; complete add ≈ 12; fixed base 0.5–1.0k; on-curve 3 | M8 double-and-add in `g3_proof_scaling_measurement_tests.rs`; `pasta_dense_msm.rs`; Orchard complete addition | §8 §9.3 rules; lattice KAT |
| P-256 ECDSA chip `::p256` | Fq (Q) | V ≤ 0.30M, F ≤ 0.12M; soft and hard | `kagemusha_p256_curve_gadget.rs` (joint 2-bit Shamir, low-S, x(R) mod n); RCB complete formulas | per-proof `lookup_any` window table; e = SHA-256 output as a big-endian integer mod n |
| SHA-256 compression `::sha256` | Fq | ≤ 2,800 rows, ≤ 50k cells per block | `pasta_sha256_table8.rs` (degree 9 → 6) | exactly one block: the 32-byte canonical (little-endian, wire §3.2) encoding of m, loaded as eight big-endian words, then the fixed padding; codec m → bytes with the `< p` canonicity check (≈ 0.1k) |
| Pow5 Fq lane | Fq | 148 per permutation | existing generic `poseidon::pow5` | parity vectors against `RP57_FQ` |
| IMT chip `::imt` (depth 32) | Fp | insert 39.7k; removal ≈ 39.7k; non-membership 10.0k; membership 9.9k; membership-or-insert ≈ insert | wire §3.2; `iroha_data_model` native trees | shares its path layer with the blacklist gap, quota-window and quota-usage array path chips; written slot must be empty; next free index is native (slot `2^32 − 1` valid) |
| Byte linking `::bytes` | Fp, Fq | 2–3 cells per byte; opaque chunk ≈ 20 | `statement.rs` codecs | `P_bytes` chunks; signed-message transcripts; compressed point ↔ (x, y parity); descriptor-fixed 107/112-chunk σ export |
| u128, glue, statement | Fp | existing | `iroha_plonk_gadgets` | — |
| PIPA-R transcript `iroha_plonk_recursion::transcript` | Fp, Fq | 148 per permutation; ≈ 30 per S6 limb pair; challenge map ≈ 10 | native `kagemusha_poseidon.rs` | 6.2b |
| Succinct verifier interpreter `::verifier` | Pallas-in-Fp, Vesta-in-Fq | §5.3 | S11 `constraint_terms`, `transcript_schedule` | hard and soft modes; typed instances; one-hot key or carried digest |
| PIPA-AS verifier `::accumulation` | both | 65–109k for r = 2–7 | snark-verifier `IpaAs`; `iroha_core_zk` `accumulation.rs` | slot modes; Corrected G* ≠ G |
| Key binding `::vk` | both | ≈ 23–56 permutations + one-hot | Pickles step-key selection | S14 |

Native side (`iroha_plonk`, M4): the PIPA-R transcript, typed instances,
`CircuitDescriptorV2`, the PIPA-AS prover and verifier, `create_proof` returning (G'_0, u),
`keygen_pk_from_vk`, the owned-witness and streaming prover API, the global MSM scratch budget,
a cooperative cancellation token and the `ACC_TRIV` constants.

## 10. Milestones, named tests and thresholds

Measurement thresholds are measured natively at k16 on the shared Mac under the
loaded-host procedure below. One-worker budgets use process CPU time; four-worker
budgets use observed elapsed time. This replaces the earlier `load1 < 4` condition;
a CPU result does not establish idle elapsed time. Each threshold names its fallback.

### M3: gadgets (`iroha_plonk_gadgets`)

Named tests:

- `ff_mul_matches_bigint_{fq_in_fp,fp_in_fq,p256_p,p256_n}`
- `ff_carry_bound_overflow_is_unsatisfiable`
- `ff_noncanonical_limbs_rejected`
- `ff_canonical_compare_at_m_minus_1_m_m_plus_1`
- `glv_lattice_sup_norm_minimum_pallas_vesta` (2^126.21)
- `glv_mul_matches_native_{pallas,vesta}`
- `glv_split_rejects_halves_ge_2_128`
- `glv_incomplete_iterations_never_exceptional_on_adversarial_bases`
- `complete_add_handles_identity_equal_opposite`
- `identity_guarded_horner_matches_native_msm`
- `fixed_base_mul_matches_native`
- `p256_soft_bit_equals_native_on_wycheproof_prehashed`
- `p256_rejects_high_s_r_ge_n_zero`
- `p256_complete_for_native_accepted_edge_keys`
- `sha256_one_block_fips180_vectors`
- `sha256_gate_degree_at_most_six`
- `sha256_of_poseidon_digest_matches_native`
- `imt_insert_matches_native_and_rejects_wrong_low_leaf`
- `imt_nonmembership_rejects_present_key`
- `imt_insert_rejects_occupied_slot`
- `imt_remove_matches_native_and_rejects_wrong_predecessor`
- `imt_membership_or_insert_matches_native_credit_digest_tree`
- `quota_usage_array_charge_matches_native_and_rejects_misaligned_or_repeated_slot`
- `p_bytes_link_matches_native_at_chunk_boundaries` (0, 30, 31, 32, 62)
- `point_bytes_link_rejects_wrong_parity`
- `pow5_fq_lane_matches_rp57_fq_vectors`

Every chip also has adversarial tests: each meaningful advice cell of a valid witness is
tampered and the circuit must become unsatisfiable.

| Threshold | Value | If missed |
|---|---|---|
| G3.1 P-256 variable key | ≤ 0.30M cells and ≤ 14k rows at ≤ 22 advice | 0.30–0.40M: Receive uses the A-split (§5.5); > 0.40M: redesign before M4 (`lookup_any` window tables, precommitted own key) |
| G3.2 P-256 fixed key | ≤ 0.12M cells | as G3.1 |
| G3.3 SHA-256 block | ≤ 2,800 rows, ≤ 50k cells, degree ≤ 6 | Q packing is recomputed |
| G3.4 FF multiplication | ≤ 100 cells; carry-bound memo written | blocks M4 |
| G3.5 GLV multiplication | ≤ 1.6k cells with the complete tail | verifier budgets are recomputed |
| G3.6 synthetic Q-shaped proof (22 / 32 / 8 / 3) | ≤ 30 s Mac 1t; ≤ 10 s 4t; peak RSS ≤ 0.75 GiB | time model recalibrated; the leaf is narrowed |
| G3.7 synthetic A-shaped proof (32 / 44 / 10 / 3) | ≤ 36 s Mac 1t; peak RSS ≤ 0.85 GiB with the owned-witness API | A is split by default |

### M3 qualification on a shared machine

`m3_gates` measures synthesis through consuming-witness proving and cleanup;
parameter setup, key generation and verification are reported separately. Every
measured proof is verified. A one- or four-worker Rayon pool is constructed and
its actual worker count checked. Missing CPU/RSS probes invalidate a run. Memory
is the kernel lifetime high-water RSS of a fresh process, including setup; it is
never a subtraction of phase peaks or the maximum of periodic RSS samples.
The current driver keeps one explicit caller-owned quotient workspace across
both proofs, with a 256 MiB field-buffer ceiling. Its allocation is included in
kernel RSS; it does not replace or relax the independent process-wide 64 MiB MSM
scratch limit. The first proof starts with empty workspace storage and the second
reuses the same column allocations. Reports bind the ceiling and both before/after byte
counts; missing or inconsistent reuse evidence invalidates the attempt. Every
lease zeroizes retained rows before return, including errors and unwinding.

Run `scripts/kagemusha_qualify.py prepare --output <untracked-directory>` to build
and freeze a candidate, then its `run` subcommand. Preserve source and binary
hashes, compiler/profile/features, descriptor, machine/OS, power and thermal
state, cache policy, witness API, process scratch cap, seeds and all raw results.
The exact synthetic Q/A shapes and real chip-filled Q/A workloads are separate
configurations and cannot stand in for each other.
For a component qualification during unrelated protocol work, `prepare
--component` derives its source scope from Cargo's actual compiled package
artifacts, including local build/dev dependencies, cross-crate Rust inputs,
workspace build configuration and the measurement harness. It records every
selected file and both whole-checkout hashes. Changes anywhere in a selected
crate invalidate that component; edits outside the recorded scope do not.
A component verdict qualifies only those measured workloads and cannot establish
a frozen whole-release candidate. Registry versions remain bound by Cargo.lock.

For each configuration collect three separated blocks of three fresh processes,
balancing configuration order with a recorded shuffle seed. Retain the first two
proofs of each process and use the slower one for its timing sample. Bracket each
process with a fixed k16 proof calibration of its family; both CPU and elapsed
calibration samples must agree within 5%. Require nominal thermal/power state,
normal memory pressure and no new compression, pageout or swapout episode from
before process creation through exit. A fresh process starts without compressed
pages; unchanged global compression counters also exclude compression of that
process. Existing compressed pages of other processes do not invalidate a run.
Swap-in increases are retained as diagnostics, not an additional veto: the
three required unchanged counters above define this memory-activity rule.
A decreasing counter or failed/missing probe invalidates the evidence. The
prepared candidate binds this exact policy; a changed policy requires a fresh
candidate and schedule, and never upgrades a retained invalid attempt.
Keep failed attempts/reasons; at most 18 attempts per configuration may be used
to collect nine valid samples, otherwise the result is inconclusive.
An optional stop after a valid hard-limit breach retains the failing partial
schedule. It can establish a failure, never a qualification pass.
The retained ledger includes each measured process and both calibrations, with
their exit status, raw output and environmental probes, plus source/binary hashes
before and after the attempt. Recomputing a verdict rechecks those records and
the declared execution order; cached validity flags or report-only records cannot
establish a pass. Probe or process-launch failures remain invalid attempts.

| Metric | Each block median | Every valid sample |
|---|---:|---:|
| Q, one worker, process CPU | ≤ 27 s | ≤ 30 s |
| A, one worker, process CPU | ≤ 32.4 s | ≤ 36 s |
| Q, four workers, observed elapsed | ≤ 9 s | ≤ 10 s |

For each worker count, every block's median kernel peak RSS must be ≤ 0.7125 GiB
for Q and ≤ 0.8075 GiB for A for a qualification pass. Every valid process must
meet the unchanged hard caps of 0.75 and 0.85 GiB respectively; report its peak
and the maximum as well as the block medians. A4 supplies memory and diagnostic timing evidence. Values
within hard limits but missing headroom are borderline; hard-limit violations
fail. Invalid environmental evidence is inconclusive, never a pass. Normalized
estimates cannot turn an observed four-worker failure into a pass. Load is logged,
not used to cherry-pick low-load runs. These margins are engineering headroom,
not statistical confidence intervals.

The [FF carry memo](kagemusha_ff_carry_v1.md) pins the arithmetic and the M3b
range/shared-table proof obligations. Carry review, completed adversarial tests
and final-layout shape counts precede performance qualification.

### M4: recursion and accumulation (`iroha_plonk`, `iroha_plonk_recursion`)

Named tests:

- `pipa_r_transcript_kats_{pallas,vesta}`
- `fq_to_fp_challenge_map_kat`
- `pipa_r_instance_type_out_of_range_rejected`
- `descriptor_v2_requires_direct_and_suffix`
- `in_circuit_verdict_parity_{sigma,q,a,omega,pipa_as}_tamper_corpus`
- `soft_verifier_never_unsatisfiable_on_any_witness`
- `soft_verifier_bit_zero_on_off_curve_or_noncanonical_input`
- `pipa_as_accepts_iff_all_inputs_decide`
- `pipa_as_solved_g_input_rejected_by_decide`
- `pipa_as_cancelling_inputs_rejected`
- `pipa_as_swapped_input_order_rejected`
- `pipa_as_k12_padding_equals_k12_decide`
- `pipa_as_has_no_hiding_term`
- `acc_triv_decides_and_matches_pin`
- `corrected_slot_requires_g_star_ne_g`
- `trivial_slot_only_through_mode_bit`
- `vk_continuity_foreign_omega_key_rejected`
- `omega_vk_digest_mismatch_rejected_natively`
- `a_variant_outside_t_a_rejected_by_omega`
- `relation_id_is_never_a_circuit_constant`
- `every_obligation_folded_exactly_once` (all variants)
- `keygen_pk_from_vk_matches_keygen_pk`
- `owned_witness_prover_bytes_identical`
- `global_msm_scratch_cap_respected_under_parallel_commits`
- `prover_cancellation_resumes_identically`
- `cycle_chain_depth_16_decides_once_per_curve`
- `cycle_chain_tampered_middle_proof_fails_final_decide`
- `cycle_chain_dropped_accumulator_fails`

Mutation rows (PIPA §15): MV9 skip absorbing a PIPA-AS input; MV10 drop a fold slot; MV11
reuse α across folds; MV12 incomplete addition in a Horner join; MV13 accept `valid = 0` on a
hard slot; MV14 skip the VK-digest equality in A; MV15 allow a Corrected slot with G* = G.

| Threshold | Value |
|---|---|
| G4.1 | Fiat–Shamir, CRT and PCD/containment memos written; PIPA-R and PIPA-AS text merged into `plonk_ipa_v1.md` with KATs |
| G4.2 | In-circuit verify cells ≤ σ 191k; Q 297k + 0.45k per instance; A 337k; Ω 212k; PIPA-AS (r = 4) 91k |
| G4.3 | Ω descriptor V ≤ 72 with exactly one lookup; transport ≤ 4,821 B with the measured largest σ_send of 3,456 B. The captured degree-nine Bootstrap component produces 3,712 B proof / 4,800 B transport; current pinned-catalog source measurement, full catalog, root continuity and qualification remain open |
| G4.4 | PIPA-AS prover ≤ 3.5 s Mac 1t, ≤ 1.2 s 4t |
| G4.5 | `msm_complete` at 2^16 measured on 4 threads; two decides ≤ 0.35 s Mac 4t |
| G4.6 | Measured peak RSS ≤ 0.85 GiB for the A shape under the owned-witness API |
| G4.7 | Cycle demo prove time within ±30% of §5.3 per proof kind |
| G4.8 | σ under PIPA-R: 3,296 B unchanged; prove ≤ 0.85 CPU-s 1t; verify ≤ 45 ms 1t |

### M5: Λ and Ω relations (`iroha_kagemusha_proof` and the canonical wallet state integration)

Named tests:

- `omega_transport_length_equals_allowlist`
- `payment_with_largest_sigma_send_fits_10000`
- `credit_status_with_32_sibling_opening_fits_10000`
- `lineage_reuse_by_whole_omega_byte_identity_skips_decide`
- `receiver_decides_omega_with_one_msm_per_curve`
- `lambda_bootstrap_zero_state_unique`
- `lambda_send_then_send_chain_folds`
- `lambda_recv_accepts_honest_payment`
- `lambda_recv_burn_on_forged_sigma_send_excludes_its_accumulators`
- `lambda_recv_burn_on_invalid_tau_send`
- `lambda_recv_burn_on_undecidable_acc_p_in_via_corrected_claim`
- `lambda_recv_burn_on_undecidable_acc_v_in_via_corrected_claim`
- `lambda_recv_cannot_burn_valid_payment` (no witness exists)
- `lambda_recv_cannot_accept_undecidable_payment` (the final decide fails)
- `lambda_recv_branch_is_unique_per_payment`
- `lambda_recv_duplicate_credit_id_root_rule`
- `lambda_recv_duplicate_credit_id_keeps_first_credit_digest_leaf` (same and other Payment digest)
- `lambda_archive_duplicate_credit_id_other_payment_digest_takes_noop`
- `lambda_recv_recorded_blacklist_lookup_matches_native` (present, absent, other root; a bad path is unsatisfiable, never a burn)
- `sigma_recv_key_selected_by_request_recorded_version`
- `lambda_recv_renewed_receiver_credential_verified`
- `lambda_recv_receiver_credential_with_other_payment_key_rejected`
- `lambda_archive_noop_branch_keeps_descriptor_then_rearchive`
- `lambda_archive_credit_status_imt_membership`
- `lambda_refresh_quota_share_rebuilds_usage_array`
- `lambda_refresh_quota_share_rejects_changed_end_dropped_live_charge_or_started_new_key`
- `lambda_refresh_quota_share_rejects_window_not_longer_than_response_bound`
- `lambda_refresh_blacklist_inserts_history`
- `a_split_context_wrap_never_accepted_as_omega`
- `run_with_two_send_class_steps_rejected`
- `sigma_vk_index_must_match_tag_and_mask`
- `stale_burned_total_or_pending_input_rejected_natively_and_in_lambda`
- `request_payer_differs_from_omega_wallet_rejected`
- `relay_rewritten_payment_key_or_credential_rejected`
- `quota_sigma_send_shape_within_joint_budget`
- `fold_peak_rss_under_0_85_gib_{q,a,omega}`
- `crash_between_sub_proofs_resumes`
- `payment_preempts_fold_and_frees_memory`

| Threshold | Value |
|---|---|
| G5.1 | A cells per variant ≤ 1.67M, else the variant ships as the A-split |
| G5.2 | Measured Ω = allowlist length; Payment worst case ≤ 10,000 B with the largest σ_send; Credited::Status worst case ≤ 10,000 B |
| G5.3 | On at least two phone classes, per-sub-proof peak RSS ≤ 0.85 GiB and the fold engine ≤ 1 GiB in total |
| G5.4 | On the slower phone class, receiver proof CPU on the pre-verified path ≤ 150 ms; cold two decides ≤ 0.8 s on 4 cores |
| G5.5 | Fold time and energy recorded per operation and measured phone as evidence; nothing gates a device class or model. The proposal §5.3 runtime capacity check uses per-relation bounds computed from the installed relation descriptors and refuses before commit with `NotEnoughStorage` or `NotEnoughMemory` |
| G5.6 | Measured phone 4-core speedup on the Q and A shapes ≥ 2.0×, else fold-time estimates (this section's tables) use the pessimistic band |

## 11. Risks

| # | Risk | Effect | Mitigation |
|---|---|---|---|
| R1 | P-256 cost: estimated 0.2–0.4M cells, measured today at 1.47M | above 0.30M Receive needs the A-split (+48–65 s Mac); above 0.40M every operation gains a Q leaf | G3.1 first; window tables; precommitted own key |
| R2 | The captured compact Bootstrap component produces 4,800 B, leaving 21 B under the 4,821 B cap; current pinned-catalog capacity and qualification remain open | any descriptor growth beyond 21 B breaks the current Payment bound | G4.3; preserve exactly one lookup and establish the full admitted catalog/root before artifact freeze |
| R3 | σ_send with enabled controls grows; largest measured revision-4 proof is 3,456 B | with a 4,800 B Ω, σ_send above 3,477 B breaks R9; the threshold is always 8,277 − actual Ω bytes | B5 fixed64 usage array and measured k14 controls; remeasure every allowlisted mask and apply G-Ω2 at artifact freeze |
| R4 | No native measurement wider than k14; quotient cost of the wide gate sets | fold times 1.5–2× the model | G3.6, G3.7, G4.7 |
| R5 | RAM: A at 0.84 GiB under the owned-witness API, close to 0.85 | over the cap | streaming (0.64 GiB); A-split; global scratch cap |
| R6 | Phone performance: per-core ratio 1.1–2.3, 4-core wide-circuit speedup unmeasured, thermals | Receive up to ≈ 4 min on a slow phone | G5.6; fold while charging or in the foreground; preemption |
| R7 | Merchant backlog: 30 receives an hour ≈ 17–61 min (optimistic) to 28–117 min (pessimistic) of 4-core folding per hour [E] | a busy merchant catches up only while charging | Receive needs no fold; only onward spending waits; no batching gain in this topology |
| R8 | Novel compositions: containment rule, PIPA-R Fiat–Shamir, CRT bounds, unbounded depth (heuristic) | late audit findings | the memos of G3.4 and G4.1 |
| R9 | Scope: about 12 gadget families, one interpreter, PIPA-AS, 3 circuit kinds with up to T_A variants | schedule | one interpreter driven by the S11 tables; variants as fixed programs |
| R10 | Durable commit and hardware signing latency unmeasured | the 2 s p95 target | G4/G5 device runs; pre-verification removes the decides from the path |

## 12. Text changes elsewhere and contingent questions

These changes keep the proposal, the wire record and PIPA-v1 consistent with §1.1. All but the
last were applied to the proposal and the wire record with the third set of owner answers
(2026-10-05, B1–B8); the implementation follows in G1 (wire §7, TODO(G1, third set)) and M4
(PIPA-v1):

- **Applied. Proposal §3 notation:** to decide an Ω is to run `decide` on each accumulator Ω
  carries (the Pallas accumulator bound in its public digest, batched with Ω's own opening,
  and the Vesta accumulator); these are Ω's deferred values. **§3.2:** Ω's public digest binds
  the lineage verifying-key digest, which every native verifier recomputes with the
  artifact-set constant.
- **Applied. Proposal §3.2 burn bullet (OQ-2, B2):** no accumulator or deferred value of the
  burned Payment enters Ω, except a corrected claim (G*, u) with G* = ⟨s(u), g⟩ ≠ G that
  Λ_recv computes itself to show that the Payment's accumulator (G, u) fails to decide; such
  a claim decides by construction. The same holds for Λ_archive.
- **Applied. Proposal §3.2 duplicate rule (OQ-3, B3):** on a duplicate, the committed
  consumed-credit root equals the predecessor's root or is a structurally valid indexed-tree
  insert of a fresh key. The credit-digest leaf of the first insertion stays (wire §3.2).
- **Applied. Proposal §3 hash families and wire §1 (OQ-1, B1):** the object digests of the
  request, receipt, credential, certificate, ordinary Load receipt, fee schedule and policy objects, the
  certificate-set and package digests, `operation_id`, the unload nullifier and the
  receipt's statement digest left the SHA-256 role table (34 → 18 roles) and are `P` values
  with the encodings of §1.1. The statement digest is the σ statement digest, now 26 elements
  (14 permutations), and `credit_id` has 26 elements (14) with the B6 fields. The wire §7 note
  that these "stay `H` although Λ recomputes them" is resolved.
- **Applied. Wire §3.3 RefreshPolicy (OQ-4, B4 with B5):** the end check is bounded to the 64
  quota-window slots and is part of the usage-array rebuild (§5.1).
- **Applied with B5–B8.** Wire §§3.2–3.4 and proposal §§3, 3.2, 5.1, 5.2 and 7: the fixed
  quota-usage array and its in-place charges, the Request-recorded receiver blacklist with
  its history and Request-derived Receive selector, the core quota share expiry and maximum
  anchor response time, and the Send time span.
- **Pending (G4.3). Wire §3.2:** `lineage.proof = π_Ω (3,648) ‖ acc_P (544) ‖ acc_V (544)`,
  4,736 bytes, once the Ω descriptor is measured.

Contingent owner questions, asked only if a threshold fails:

- **C-1.** A σ_send shape for an enabled control exceeds 8,277 − |Ω| (3,477 B with the
  current 4,800 B compact component), so Payment breaks R9 (proposal §8 requires a new
  owner decision). The largest measured revision-4 σ_send is 3,456 B; the joint bound
  must be rechecked against actual frozen Ω bytes (§3.5).
- **C-2.** The Ω descriptor exceeds V = 72 after q_f sharing and dropping the suffix: approve
  128-bit fold challenges (Ω −512 B, about 120-bit per-query Fiat–Shamir security for those
  challenges)?
