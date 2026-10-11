# Parliament ballot proof profile: evaluation record

Status: evaluation of 2026-10-11 against
[parliament_private_ballot_design.md](parliament_private_ballot_design.md)
(the "ballot design") at source baseline `45f112b1cc` plus the uncommitted
working-tree revision of the ballot design, which touches its sections 9, 12
and 13; sections 1, 3, 4 and 5 are as committed. **No profile is
selected. Nothing is qualified.** Nothing has been implemented or measured for
the ballot relation: every size and time below is a calculation or an estimate
and is labelled as such. Binding Parliament governance, and every capability
that depends on it, stays no-go. Schemas and integration (ballot design
section 12.2, steps 3 and 4) do not start until section 5 is discharged and a
profile is selected (ballot design section 12.2, step 2).

This record discharges none of the section 5 gate. It compares the candidate
families, states the leading experimental candidate exactly, and lists what is
missing, which decisions belong to the owner and what evidence a selection
needs. The owner decisions in ballot design section 1 are taken as fixed.

Every statement of fact carries one of these labels:

| Label | Meaning |
| --- | --- |
| **[P]** | Verified by this evaluation in a primary source, which is cited. Section 13 states how much of each source was read. |
| **[C]** | Read in repository source at the baseline. |
| **[R]** | Reported by the second-opinion review (section 3). Not independently verified. |
| **[D]** | Derived by calculation in this record. The formula and inputs are given. |
| **[E]** | Estimate or judgement. Not a measurement. |
| **[U]** | Published claim seen only in an abstract, a landing page or a secondary citation, or collected by the research pass without verification. |

## 1. Terms

`P`, `profile_id`, `sk`, `C`, `R`, `S`, `scope`, `nf`, `m`, `m_reg`, `pi_reg`
and `pi_vote` are as in ballot design section 3.1. Further terms:

| Term | Meaning |
| --- | --- |
| VOLE-in-the-head | The proof family of the FAEST signature: a GGM-tree vector commitment, small-field VOLE correlations, a QuickSilver constraint check and Fiat–Shamir |
| `lambda`, `tau`, `w_grind`, `T_open`, `d_zk` | FAEST security parameter, number of small-VOLE instances, grinding bits, GGM opening threshold, maximal constraint degree |
| `l` | Number of committed witness bits of a relation |
| QROM | Quantum random-oracle model |
| Public-list membership | The verifier holds the `S` sealed real leaves and the proof selects one of them, instead of proving a Merkle path inside the relation |
| BHT, CNS | The Brassard–Høyer–Tapp and Chailloux–Naya-Plasencia–Schrottenloher quantum collision algorithms |

## 2. What a profile must provide

A profile `P` fixes every hash, PRF, field, in-relation encoding, tree and
proof parameter and instantiates the abstract functions of ballot design
section 3.1:

```text
C       = CredentialCommit_P(PARLIAMENT_CREDENTIAL_V1, body_context, sk)
nf      = NullifierPRF_P(sk, scope)
R       = CredentialRoot_P(sorted real leaves, S, profile_id)
pi_reg  = Possession_P(sk; C, m_reg)
pi_vote = Ballot_P(sk, i, path; m)
```

with `m_reg = (network_id, authority, assignment_id, election_attempt_id,
body_role, C)` (section 3.2) and `m = (scope, R, S, nf, vote, policy_hash,
profile_id)` (section 3.5). `sk` is one high-entropy secret; every derived
secret is a constrained derivation of it; `pi_reg` and `pi_vote` use distinct
transcript domain tags (section 3.1). The tree has 1,024 positions with real
leaves at `[0, S)` and domain-tagged empty leaves elsewhere (section 3.3).

`P` must establish the eight properties of ballot design section 5. They are
restated here in that section's own words:

1. **Authorization.** Knowledge of a registered credential, real-leaf
   membership with `i < S`, a correct nullifier, a valid choice, and binding of
   the complete message `m`.
2. **Unforgeability.** Quantum chosen-message security despite observed honest
   ballots and adversarial credential registrations.
3. **Nullifier uniqueness.** For a fixed scope and sealed root, let the
   adversary control `k` sealed credentials and obtain honest ballots whose
   nullifiers form the set `H`. Except with negligible probability it cannot
   produce valid ballots with more than `k` distinct nullifiers outside `H`.
   Exclusion is by nullifier, not proof encoding: same-message replay and
   rerandomization are permitted, while authorizing a different message under
   an honest nullifier remains forbidden by item 2. Separately, the nullifier is
   deterministic for a credential and scope, independent of the vote.
4. **Cross-scope unlinkability and non-frameability.** Observing other scopes
   cannot identify or impersonate an honest credential holder.
5. **Full quantum zero knowledge and anonymity.** A multi-theorem definition
   covering the complete transcripts of `pi_reg` and `pi_vote` under the same
   `sk`, adaptive queries, public registrations and corrupt credentials. It
   states exactly which later credential disclosures are excluded.
6. **Concrete security.** At least 128-bit effective post-quantum security,
   including Fiat–Shamir losses, grinding, hash attacks and lifetime
   multi-target use. Statistical soundness error and its accumulation are
   quantified separately. Hash output lengths follow the actual reduction;
   256-bit outputs are not assumed adequate for every role.
7. **Deterministic bounded verification.** Fixed encodings, maximum
   allocations, bounded hash and field work, defined malformed-proof behaviour
   and identical results across hardware.
8. **Registration.** `pi_reg` is a simulation-extractable signature of
   knowledge of `sk` for `C` under `m_reg`, and is zero knowledge jointly with
   every ballot proof.

The engineering targets of section 5 are proposals: complete ballot proof
≤ 256 KiB (262,144 bytes); uncached verification on the pinned minimum
validator CPU ≤ 250 ms; verifier workspace ≤ 64 MiB; phone proving p95 ≤ 10 s;
phone peak prover memory ≤ 256 MiB; both proofs measured at `S = 3`, 500 and
1,000.

## 3. Method and sources

Three inputs were used. Section 13 lists every source with its reading status.

**Repository components, read as code.** PQ-MASP, ZK-ACE, FASTPQ and the
shared transparent STARK driver were read in source and in their specifications
at the baseline. No build, test or benchmark was run for this record.

**Literature, read by this evaluation's own pipeline.** The limits are exact:

- *FAEST specification v2.0* (111 pages): pages 2–82, 93–97 and 101–111 were
  read. Pages 83–92 and 98–100 (part of the EUF-KO proof and Lemmas 9.38 and
  9.39) were not.
- *FAEST specification v3.0* (about 150 pages): read were sections 1 and 1.1,
  3.1 with Tables 3.1–3.3 (pages 13–18), the hash definitions of 3.3, 4.2,
  Table 5.1, the first page of 6.1, pages 64–70 (key generation, signing,
  verification, Tables 9.1–9.3), 10.1.2–10.1.4, 10.3.2–10.3.4, 10.7 and 10.8
  (pages 99–104), pages 115–116 (Theorem 10.42), all of 10.11 (pages 122–139)
  and section 11. Not read: sections 2, 5.2–5.5, 6.2–6.3, 7 (the degree-7
  constraints), 10.4–10.6 and the proofs of 10.9–10.10. Both specifications
  were also converted to text for exact-string search.
- *Chiang, Damgård, Duro, Engan, Kolby, Scholl* (ePrint 2025/113, CCS 2025):
  **the paper could not be read.** The ePrint and ACM copies refused automated
  access. Only its abstract was seen. Its reference implementation was read
  instead: the README, configuration and header files in full, `owf_proof.c`
  and `quicksilver.c` retrieved in full and read closely in the ring and tag
  builders, `faest.c` in part. `faest_cbc_tagged_ring_verify` was not
  retrieved, and only branch `master` was read. Everything this record says
  about that paper's theorems, tables or security model is therefore **[R]** or
  absent.
- QROM Fiat–Shamir literature: four arXiv papers were read in part (the cited
  theorems and their surroundings). Chiesa–Manohar–Spooner, Chiesa–Fenzi,
  Chiesa–Di–Hu–Zheng, Unruh (2014/587 and 2017/398), Liu–Zhandry,
  Kosuge–Xagawa and the FAEST QROM paper (ePrint 2026/164) were read **as
  abstracts only**. Bernstein's collision-cost analysis could not be read.
- STARK, classical MPC-in-the-head, lattice and ring-signature literature was
  collected by a research pass mostly from abstracts and secondary citations.
  It is labelled **[U]**.

**Second-opinion review.** An owner-authorized review by another model answered
seven questions on the same material. It reports reading primary
specifications and, through a mirror copy, the full Chiang et al. paper that
this evaluation's pipeline could not read. It describes itself as a second
opinion, not a completed independent proof review. Its statements are
attributed with **[R]** and are not independently verified. Where it conflicts
with the research pass, it is followed; where primary-source verification
conflicts with either, the primary source is followed.

## 4. Candidates compared

No row below is a qualified profile. "Evidence" gives the best available size
and cost information with its label. Verdicts are **[E]**.

| Family | Construction | Assumptions | Evidence of size and cost | Verdict |
| --- | --- | --- | --- | --- |
| In-repo PQ-MASP | Goldilocks FRI STARK, SHA-256 depth-32 membership, stable nullifier, outer ML-DSA-65 authorization (`crates/iroha_core_privacy/src/privacy_engines/pq_masp/`) | SHA-256 and SHA3-384 as random oracles; FRI soundness; ML-DSA | **[C]** descriptor fixes trace 2^14, 556 base columns, maximum inner proof 9,431,915 B. **[E]** about 2.3–2.6 MB calculated from the geometry by the research pass. No measured size or time in the repository | Cannot be the profile (section 5) |
| In-repo ZK-ACE | Dedicated STARK: Poseidon-x7 identity commitment and replay nullifier, no membership | Non-standard six-lane Poseidon; its descriptor states QROM qualification is unavailable **[C]** | **[C]** canonical proof exactly 2,131,222 B | Not a candidate: no membership; **[E]** the research pass reports three independent witness secrets |
| In-repo FASTPQ | Masked DEEP/FRI engine, one fixed geometry | Honest-verifier answer-view hiding argument only (ballot design section 5) | **[C]** canonical child frame 500,084 B (`fastpq_production_readiness.md`) | Not a candidate at its geometry |
| STARK, SHA-2/SHA-3 in the relation | DEEP-ALI + FRI compiled with BCS; Merkle path, commitment and nullifier hashed inside the relation | Standard hashes as random oracles; FRI soundness in the proven (Johnson) regime | **[E]** 250–600 KiB (research pass; depends on undecided digest length and soundness floor) | Closest to the literal relation and most conservative primitives. Size near or above the target (250–600 KiB **[E]**, unmeasured); **[R]** no demonstrated impossibility of meeting 256 KiB has been established. Gates 2, 5, 8 unproven in the QROM |
| STARK, arithmetisation-oriented hash | Same proof system; Poseidon2 or Rescue-Prime in the relation | As above, plus collision and PRF security of a non-standardised hash under active cryptanalysis **[U]** | **[E]** 150–300 KiB with 48-byte digests, 100–200 KiB with 32-byte digests (research pass) | Fits only under a lenient security metric; a further assumption and parameter review **[R]** |
| STARK with STIR or WHIR | FRI replaced by a newer proximity test | As above; the up-to-capacity conjectures are refuted **[U]** (Crites–Stewart, ePrint 2025/2046) | **[U]** published figures are for large instances; **[E]** modest gain at this relation size | Dominated at this statement size |
| Ligero / Aurora | Linear-code IOPs with zero knowledge designed in | Standard hashes | **[U]** neighbouring published proofs 0.2–1.9 MB; an Aurora credential prototype verifies in 1.37 s | Dominated: size and linear verification |
| VOLE-in-the-head, AES-only published shape | One AES key; AES commitment; AES CBC-chain tag as nullifier; one-out-of-N selector over the public list (Chiang et al.) | AES pseudorandomness and key binding; SHAKE as (Q)RO; **[R]** the paper's theorem is in a classical model | **[D]** from the reference code's size macros at N = 2^10: 9,962 / 27,516 / 51,848 B at 128/192/256-bit. **[R]** paper: 51.98 KB and at most 103 ms sign or verify at ring 1,024, AES-256. **[D]** 31,938–43,824 B on a FAEST v3 backend at `lambda` = 256 (section 9, V1) | Smallest; 128-bit tag; commitment not statistically injective (expected 1/2 colliding key pair in the random-map model, section 8.4); reference code unusable (section 6.5) |
| VOLE-in-the-head, hybrid with SHAKE256 nullifier | Six-block AES-256 commitment, SHAKE256 nullifier inside the relation, public-list selector (section 6) | AES key binding in a stated multi-key form; keyed SHAKE256 pseudorandom given the AES commitment; SHAKE as QRO | **[D]** `pi_vote` 62,562–188,760 B at `lambda` = 256 (section 9, V2) | Leading experimental candidate; not qualified |
| VOLE-in-the-head, two-SHAKE public list | Commitment and nullifier both SHAKE256 inside the relation; no AES in the relation | SHAKE256 only in the relation; the proof system still uses AES-based PRGs **[R]** | **[D]** `pi_vote` 81,834–316,668 B at `lambda` = 256 (section 9, V3). **[R]** about 224 KB at slow `lambda` = 256 before selector and framing. **[U]** a SHA-3 component inside VOLE-in-the-head is reported implemented (ePrint 2026/109) | Comparison candidate; largest witness; registration proof much heavier |
| VOLE-in-the-head, Merkle path inside the proof | Depth-10 path with a Rijndael-256 compression function, or with SHA-3 | Rijndael-256 in a hash mode analysed only in the ideal-cipher model **[E]**; or SHA-3 | **[D]** Rijndael: 134,304–217,998 B at `lambda` = 256 from the v3 size formula with the research pass's unverified 45,000–50,000-bit witness. **[D]** SHA-3: at least 13 Keccak permutations. At grouping (c) of section 9.2 (12,800 bits per permutation): 13 × 12,800 = 166,400 bits, 10,554 + 22 × 166,400 / 8 = 468,154 B at 256s. At grouping (d) (8,000 bits, `d_zk = 14`, the least reliable figures): 13 × 8,000 = 104,000 bits, 10,554 + 833 + 22 × 104,000 / 8 = 297,387 B at 256s | Keeps root-only verification. Rijndael's 256-bit digest gives about 2^85 quantum collision queries; SHA-3 misses the size target at `lambda` = 256 |
| Classical MPC-in-the-head rings | ZKB++ / KKW ring signatures over LowMC | LowMC; classical ROM | **[U]** 388 KB (Katz et al.) and 56 KB (Goel et al.) at ring 2^10; seconds on small machines | Dominated; none is linkable as published |
| Power-residue and algebraic-OWF rings | PegaRing, DualRing-PRF; Rain, AIM, MQ one-way functions | Legendre / power-residue PRFs or young algebraic designs; **[U]** AIM broken, Rain margins shrinking | **[U]** PegaRing about 28 KB at ring 1,024 with a claimed QROM proof; linkability not stated in its abstract | Not conservative enough for a governance ballot |
| Lattice compositions | MLWE commitment, log-size set membership, weak-PRF nullifier on a hashed scope | MLWE / MSIS; classical ROM | **[E]** tens of KB to about 220 KB; no published scheme, parameter set or QROM proof for this relation | Compared; not implementable as a first profile |
| Published post-quantum linkable ring signatures | Falafl, Calamari, SMILE, MatRiCT, Raptor and others | MLWE / MSIS, isogenies; classical ROM | **[U]** sizes from about 10 KB to above 1 MB at ring 1,024 | **[U]** The research pass describes the tags of these schemes as key-only. **[R]** The review found that description wrong as a general statement (Chiang et al. support instance-dependent tags, section 6.5). **[R]** No verified theorem was found covering the scoped nullifier, registration and adaptive quantum anonymity together |

**The comparison ballot design section 5 asks for.** A hash-based
Merkle-membership signature of knowledge matches the literal relation of
section 3.5 and keeps verification against the root alone. With standardised
hashes its projected size is near or above the 256 KiB target in the STARK
form (250–600 KiB **[E]**, unmeasured) and above it in the VOLE-in-the-head
form at `lambda` = 256 **[D]**. **[R]** No demonstrated impossibility of
meeting 256 KiB has been established. No proof of gates 2, 5 or 8 was found
for any concrete instance. A post-quantum
linkable ring signature gives a far smaller private relation, but no published
scheme was found whose theorems cover a scope-dependent nullifier, the
registration proof and joint quantum anonymity **[R][U]**; ring verification
needs the verifier to hold the member list, which the ballot design does not
currently require (section 6.4). The leading experimental candidate is a
hybrid: a ring-style public-list selector proved in a symmetric-primitive
proof system, with the Merkle root computed outside the proof. "Evaluate
first" in section 5 requires a substantive evaluation of the hash-based Merkle
construction; it does not mandate selecting that family after comparison
**[R]**. Neither side of the comparison is qualified.

## 5. Why the in-repo PQ-MASP cannot be the profile

- **It publishes a key.** The STARK is wrapped in an ML-DSA-65 authorization
  whose public key and signature travel with the proof **[C]** (profile
  descriptor in `pq_masp/stark.rs`). A ballot carrying it identifies the
  voter.
- **It has a second secret.** The nullifier is derived from a separate
  nullifier key and a per-note value **[C]** (`pq_masp/relation.rs`). Ballot
  design section 3.1 forbids an unconstrained second secret.
- **The relation is a different one.** Depth 32, a note transfer with value
  conservation, no index bound `i < S`, no scope **[C]**.
- **Size.** The descriptor bounds the inner proof at 9,431,915 B **[C]**,
  about 36 times the target. The research pass calculates 2.3–2.6 MB from the
  geometry and a shared-driver minimum trace of 2^13 rows **[E]**. Nothing is
  measured.
- **Hash width.** The in-relation SHA-256 output is 256 bits, about 2^85
  quantum collision queries under BHT **[D]** (section 8.3).
- **No reduction.** The source excludes hash collisions and the
  Fiat–Shamir/QROM reduction from its certified soundness **[C]**. There is no
  simulator and no multi-theorem statement.

Removing the wrapper, merging the secrets and changing the geometry and the
relation creates a new profile with its own analysis and measurements **[R]**.

Reusable as code, for a STARK-route candidate only **[E]**: the Goldilocks and
quartic-extension arithmetic, SHA3-384 framing and Merkle multiproofs, the
transcript, deterministic query sampling, the fixed-length codec, the masking
machinery, the exact-integer FRI certificate checker and the fail-closed
randomness wrapper. None of it applies to a VOLE-in-the-head engine, and the
repository contains no VOLE-in-the-head or MPC-in-the-head code **[E]**
(research pass).

## 6. Leading experimental candidate

This is an experiment. It is not the normative `P`. Its `profile_id` is not
allocated: `P16` below is an experimental 16-byte domain identifier. The
relations are those proposed by the second-opinion review **[R]**; they are a
proposal to implement and measure outside the node, not a claim that the proof
system is qualified.

### 6.1 Framing and context

```text
Frame(tag; fields) =
    u16_le(tag_length) || ASCII(tag) ||
    u16_le(field_count) ||
    concatenation(u32_le(field_length) || field_bytes)
```

Record schemas fix field types and order. Integers have fixed-width
little-endian encodings. Votes are exactly `0 = Aye`, `1 = Nay`,
`2 = Abstain`. Identifiers and the canonical domainless `AccountId` use their
pinned canonical Norito encoding. Alternative encodings, trailing bytes and
excess lengths are rejected. The bijection between these relation bytes and
the stored and wire Norito forms is documented with the schemas.

The body context is hashed once, so that no security-critical AES input is a
truncation of it:

```text
B = SHA3-512(Frame("PARL/BODY/v1"; P16, Enc(body_context)))
```

### 6.2 Commitment, nullifier, tree and messages

```text
p_j = ASCII("PARL-COMMIT-V1") || u16be(j)          0 <= j < 6
U   = AES256_sk(p_0) || ... || AES256_sk(p_5)       768 bits
D   = SHAKE256(Frame("PARLIAMENT_CREDENTIAL_V1"; P16, B), 96 bytes)
C   = U xor D

nf  = SHAKE256("PN1\0" || P16 || sk[32] || scope[32], 64 bytes)

real_value(C)  = 0x00 || C[96]
empty_value(j) = 0x01 || u16_le(j)
leaf_j = SHA3-512(Frame("PARL/LEAF/v1"; P16, value_j))
node   = SHA3-512(Frame("PARL/NODE/v1"; P16, level_u8, left[64], right[64]))
R      = SHA3-512(Frame("PARL/ROOT/v1"; P16, S_u16, top[64]))

m_reg = Enc(network_id, authority, assignment_id,
            election_attempt_id, body_role, C)
m     = Enc(scope, R, S, nf, vote, policy_hash, profile_id)
```

- `sk` is 256 uniformly random bits. `"PARL-COMMIT-V1"` is 14 bytes, so each
  `p_j` is exactly one AES block.
- The mask `D` is public. It makes `C` depend on the body context without
  secret nonlinear work. It gives no multi-target improvement: anyone can
  remove it **[R]**.
- The nullifier uses the full scope, is independent of the vote and fits one
  SHAKE256 absorption block (84 input bytes against a 136-byte rate, 64 output
  bytes: one Keccak-f[1600] permutation **[D]**). All of it is constrained
  inside `pi_vote`.
- Real values are sorted bytewise, duplicates are rejected, they occupy
  `[0, S)`, and deterministic empty values fill the tree to position 1,023.
  Ten levels are fixed.
- An AES-only full-scope nullifier was rejected: `AES_sk(H128(scope))` has a
  short-input collision problem, and adding ciphertext blocks or hashing the
  output does not automatically repair it **[R]**.

Points this evaluation's own primary reading adds; the proposed relations do
not yet resolve them:

- All seats share the plaintexts `p_j`. The FAEST specification's argument
  against multi-target key recovery relies on an independently sampled
  plaintext per public key **[P]** (FAEST v3 section 10.1.4), so that argument
  does not transfer. A per-seat public tweak can help under an appropriate
  model but changes the commitment inputs and the hidden-selection relation
  **[R]**.
- FAEST's QROM proof restricts the key space (`k[0]·k[1] = 0`, enforced in key
  generation and inside the relation) so that a random public key has no
  preimage with probability at least 1/4 **[P]** (FAEST v3 section 10.7,
  Lemma 10.50). A ballot proof that reuses that argument must keep an
  equivalent restriction or find another source of lossiness.
- In FAEST the statement and the message enter the challenge chain only
  through the digest `mu` **[P]** (FAEST v3 Figure 8.2). The ballot statement,
  the relation identifier and the message must enter there.

### 6.3 Transcripts, relations and selector

Both transcripts absorb the relation identifier, `B`, the complete public
statement and the canonical message. `REG` and `VOTE` use separate namespaces
for randomness derivation, commitments and challenges. Core-derived context is
checked against authenticated state and is never accepted from the caller.
Domain separation is necessary; it is not itself a joint-security proof **[R]**.

| Proof | Witness | Required checks |
| --- | --- | --- |
| `pi_reg` | `sk`; fully constrained AES intermediate states | Recompute `C`; bind all of `m_reg` and the body context. Core separately checks account authorization, assignment eligibility and duplicate registration |
| `pi_vote` | `sk`; hidden selector; AES and SHAKE intermediate states | Select exactly one real entry with `i < S`; recompute its `C`; recompute `nf`; require a valid choice; bind the complete `m` and the context |

**Selector.** The tree has 1,024 = 32 × 32 positions. The selector is two
32-entry vectors `a` and `b`; position `i = 32u + v` is selected when
`a_u = b_v = 1`. The selected commitment is the sum over `i < S` of
`a_u · b_v · C_i`, and is constrained to equal the AES output XOR `D`. The
constraints on each vector are, all three required:

1. every entry is Boolean;
2. pairwise exclusivity: `x_u · x_v = 0` for every `u < v` (496 products per
   vector **[D]**);
3. the entries sum to one.

A further constraint forbids the selected pair from indexing a position at or
beyond `S`.

**The characteristic-two pitfall.** Boolean entries plus "sum equals one"
alone are wrong over a field of characteristic two: they enforce odd parity,
not one-hotness **[R]**. Three active entries pass. With a multiplexer, a
selector with three active entries in one vector selects the XOR of three
registered commitments, which is not a registered leaf **[D]**. The published
reference implementation derives the last entry of each vector by parity and
adds a "single active bit" constraint that is identically zero in
characteristic two **[D]** (algebra on `quicksilver.c`). That design tolerates
it, because it gates a complete per-member constraint set with the selector
instead of multiplexing public values, so extra active entries only force more
branches to hold **[D]**. The multiplexer form above does not tolerate it.

### 6.4 Public-list verification contract

The proof does not hash a Merkle path. Membership under `R` holds by a
witness-preserving equivalence **[R]**:

1. obtain exactly the canonical sorted list of the `S` real leaves;
2. rebuild the specified 1,024-position tree, including padding;
3. check its root against the authenticated `(R, S, profile_id)`;
4. a witness selecting position `i < S` then determines the Merkle path
   publicly.

Consequences:

- **Who must do it.** Every verifier of a ballot, not only Core at seal. A
  verifier must either perform steps 1–3 or hold an equivalently authenticated
  immutable verification context. Putting `R` in the signed message does not
  connect an arbitrary supplied list to `R` **[R]**.
- **Full nodes** already hold the registration state but must construct
  precisely the sealed subset **[R]**.
- **Independent full verification** acquires a list requirement **[R]**.
  Ballot design section 3.9 already lists the "authenticated finalized seal
  and attempt context" as its first input, beside the closure record and
  every block from the `s0` height to the closure height **[C]**. Today that
  context need only authenticate `(R, S, profile_id)`. Under the public list
  it must also supply, durably, the `S` sorted real-leaf values. They
  originate in registration blocks before the `s0` height, so the block
  interval of section 3.9 does not contain them **[R]**.
- **A possible carrier.** Ballot design section 3.8 already binds "a
  registration root over the sealed `(assignment_id, C)` pairs" into every
  closure record **[C]**. It is the existing authenticated handle closest to
  the list. Whether it can carry the list is not decided here: its encoding is
  not fixed by a profile, and it is written at closure, after the ballots it
  would serve **[E]**. `R` itself authenticates a supplied list once the tree
  is rebuilt from it (steps 1–3), so the open question is availability of the
  list bytes, not their authentication **[D]**.
- **Authenticated summary** (the other mode of section 3.9) verifies no
  ballot proof and is unaffected **[C]**. The review also names light clients
  **[R]**; the ballot design defines no light-client mode that verifies ballot
  proofs.
- **Owner decision preserved.** "Outcomes are provable from block data ...
  without any secret" (ballot design section 1) still holds: the list is
  public registration data recorded on chain **[D]**. What changes is which
  blocks or authenticated context a verifier must hold.
- **Cost at `S = 1,000`.** The list is 96,000 bytes with six-block
  commitments (64,000 with four blocks), before framing **[D][R]**. Root
  construction is 1,024 leaf hashes and 1,023 node hashes plus the root
  framing, once per immutable body context **[R]**. Each ballot verification
  processes about `O(S)` public data, so a complete body can involve `O(S^2)`
  selection work if the list is processed per ballot **[R]**.
- **Gain and loss.** The private relation is much cheaper. Root-only
  verification without the auxiliary list is lost. No additional trusted party
  is needed **[R]**.

This changes the ballot design in five places **[C]**:

| Clause | Text today | Under the public list |
| --- | --- | --- |
| 3.1 | `pi_vote = Ballot_P(sk, i, path; m)` | No path witness; the witness is `sk` and a hidden selector |
| 3.3 | "The ballot relation proves `i < S` and a correct real-leaf encoding" | The relation proves `i < S`; the real-leaf encoding and all tree hashing are checked publicly, outside the relation |
| 3.5 | Index and path under `R` are proved in the relation | Membership under `R` holds through the public rebuild of steps 1–3 |
| 3.9 | Full verification needs the seal and attempt context, the closure record and the `s0`-to-closure blocks | The context must also supply the `S` real-leaf values |
| 12.2 step 3 | "`P` defines the in-relation leaf, node and padding encodings" | The candidate has no in-relation leaf, node or padding encoding; these encodings are public |

It is an owner decision (section 10), not an instantiation detail.

### 6.5 The published reference implementation is not a reference

Verified in the authors' repository, branch `master` **[P]**, unless marked:

- The linkable builder constrains only the first block of the first
  public-key function per member. The second public-key function is committed,
  counted in the signature size and left unconstrained (its loop is commented
  out). At 192 and 256 bits the second block is skipped by a condition that is
  never true (`if (OWF_BLOCK_SIZE == 2)` while the constant is 16). A run of
  this branch omits work a correct relation needs. Whether the paper's
  published timings were produced from this code is not known: only `master`
  was read and the paper was not read by us **[E]**.
- Only the first public-key outputs are hashed into the challenge chain. The
  ring size, the selector dimension and any profile or domain identifier are
  absent from it.
- The one-hot constraint is vacuous (section 6.3) **[D]**.
- The ring size is a compile-time power of two. Nothing makes padding members
  unselectable.
- The tag is one 128-bit block at every security level. **[R]** The paper
  reports a four-block commitment and a 127-bit CBC-MAC-derived tag for
  AES-256, and its theorem assumes a suitable weakly simulation-extractable
  proof system in a classical model.
- The tag is a function of the key and a caller-supplied public input, not of
  the key alone, so a scope-dependent tag needs no circuit change. The
  research pass's description of published tags as key-only was wrong: the
  paper supports instance-dependent tags **[R]**. No verified quantum proof
  covers that composition.
- The code is a FAEST version 1 style witness layout with later tree options.
  It is not the version 2 or version 3 specification code, so size anchors do
  not transfer directly.
- It requires AVX2. The README makes no constant-time claim. It has a `printf`
  in the verification failure path, deprecated code paths, and a test
  generator seeded with a constant.

The code-derived 51,848 B and the paper's reported 51.98 KB differ by 132 B if
a KB is 1,000 B; the difference is unexplained **[D][R]**.

## 7. Gate-by-gate status

Status classes: **(a)** an applicable theorem as is; **(b)** a short new
argument; **(c)** substantial new proof work; **(d)** an assumption about a
concrete primitive. No gate of either route has an unconditional (a).

### 7.1 Leading candidate

The route and class columns are the second-opinion review's assessment **[R]**.
"Missing" adds what primary-source reading established.

| Gate | Argument route | Class | Missing |
| --- | --- | --- | --- |
| 1 Authorization | Quantum knowledge authorization for the actual registration, list and nullifier relation | (c) | Ordinary soundness proves a statement true, not that its producer knows the credential. FAEST's QROM proof reduces to soundness and deliberately avoids extraction **[P]** (v3 section 10.7). Its soundness lemma is stated for static adversaries **[P]** (Lemma 10.49) |
| 2 Unforgeability | Adaptive chosen-message security with malicious registrations, corrupt members and both honest proof types | (c) | FAEST's theorem is for one honestly generated key **[P]** (Theorem 10.53). In a ring relation the statement stays true through the adversary's own leaves, so the lossy-key step does not apply directly **[D]** |
| 3 Nullifier uniqueness | Associate every newly authorized nullifier with a controlled credential; then commitment binding and deterministic nullification | (b), conditional on gates 1, 2 and binding; otherwise (c) | Binding of the AES commitment (section 8.4). Computational binding needs extraction or an equivalent proved argument |
| 4 Unlinkability, non-frameability | PRF-given-commitment and simulation hybrids | (b) once the premises hold | The premises: gate 5 for the actual composition, gate 2 for non-frameability, and the keyed-SHAKE assumption (d) |
| 5 Joint quantum ZK and anonymity | One adaptive multi-theorem simulator for both relations, public registrations, adversarial credentials, the same secret and oracles | (c) | The simulator and its quantitative reprogramming bounds. Distinct transcript tags do not establish it. The claim must exclude later disclosure of a challenge credential, which recomputes its nullifier by design |
| 6 Concrete security | Arithmetic over the bounds of gates 1, 2 and 5 | (b) after applicable bounds exist; idealising AES and SHAKE is (d) | The bounds do not exist for this relation (section 8) |
| 7 Bounded deterministic verification | Canonical decoding, allocation and work bounds, malformed-input behaviour, hardware parity | (b) plus implementation evidence | Nothing is implemented |
| 8 Registration | Simulation-extractable signature of knowledge, as written | (c) | No QROM simulation-extractability theorem covering VOLE-in-the-head was found in the sources read (section 13 lists their coverage). **[P]** The QROM extraction results read concern sigma-protocols and commit-and-open protocols; Don–Fehr–Majenz 2020 Theorem 23 is a proof sketch whose preconditions (constant rounds, an interactive quantum proof of knowledge, a rewinding loss) were not shown to hold here |

### 7.2 Two unsafe shortcuts

Both appeared in the research pass and are rejected **[R]**; primary reading
reaches the same conclusion on the first **[D]**.

- **Soundness plus injectivity does not give the `k`-credential bound.** It
  bounds the whole root to at most `S` credential handles. It does not prevent
  a proof for a true statement about an uncorrupted credential whose ballot
  has never been requested. That needs authorization, unforgeability or
  knowledge (gates 1 and 2).
- **Soundness plus duplicate-commitment rejection does not stop a copied
  registration.** Before the honest registration lands, an attacker can race
  it under another account and assignment. The copied commitment has an
  opening, so the attacker's statement is true; soundness says nothing about
  whether the attacker knows the opening. **What does stop it:** new-message
  unforgeability under the honest commitment, provided it stays secure after
  the adversary has observed both registration and ballot proofs. `m_reg`
  binds the account and assignment, so the copied proof is a forgery on a new
  message. Duplicate rejection then handles later reuse. This is a plausible
  alternative to full simulation-extractability; it is not proved by the
  duplicate check.

### 7.3 A tension inside ballot design section 5

Gate 8 as written requires that `pi_reg` "is a simulation-extractable
signature of knowledge". The paragraph that follows calls multi-theorem QROM
simulation-extractability "one sufficient route to properties 1 and 8". The
two cannot both be the requirement. Ballot design section 3.2 ("Possession
proof") states the same requirement a second time in normative text: `pi_reg`
"is a post-quantum, simulation-extractable, zero-knowledge signature of
knowledge of `sk` opening `C`" **[C]**. A weaker theorem, such as the anti-copy
formulation of section 7.2, is not compliance with gate 8 or with section 3.2
until the owner resolves the wording (section 10). A ruling that permits an
equivalent must amend both places.

### 7.4 STARK route

This table is this evaluation's own judgement **[E]** from sources read mostly
as abstracts.

| Gate | Route and class | Missing |
| --- | --- | --- |
| 1 | Adaptive straight-line quantum extraction for hash-based reductions (Chiesa–Di–Hu–Zheng **[U]**), plus a proof of round-by-round knowledge soundness of the exact masked protocol: (c) | Theorem statements not read; nothing is stated for a masked DEEP-ALI protocol with this relation |
| 2 | Simulation-soundness under reprogramming for multi-round BCS in the QROM: (c) | No published theorem found |
| 3 | Extraction plus ordinary collision resistance of the commitment and tree hash: (b) | Gate 1; digest length per section 8.3 |
| 4 | PRF from the in-relation hash, given gate 5: (b) | Gate 5 |
| 5 | Multi-theorem adaptive QROM simulator covering salted Merkle openings and both relations: (c) | No published theorem found; the in-repo substrate has unsalted leaves **[E]** |
| 6 | Parameter calculation after 1, 2, 5 | The form `t^2·eps + t^3/2^lambda` of the Chiesa–Manohar–Spooner bound was seen only in search excerpts **[U]** |
| 7 | By design: fixed query count, integer arithmetic: (b) | Nothing is implemented for the ballot relation |
| 8 | Classical ROM only (Chiesa–Fenzi **[U]**, preconditions not read); QROM: (c) | No published theorem found |

The STARK route has extraction available in the QROM at abstract level, which
the VOLE-in-the-head route lacks. It has more unproven zero-knowledge theory
and a size near or above the target (250–600 KiB **[E]**, unmeasured).
**[R]** No demonstrated impossibility of meeting 256 KiB has been established.

## 8. Concrete security

### 8.1 What the published FAEST v3 QROM bound gives

**[P]** FAEST v3 Theorem 10.53 and Corollary 10.54, for an adversary making
`Q_sig ≤ 2^64` signing queries, bound the forgery advantage by twice the
key-only advantage plus terms multiplied by `Q_sig`. The key-only advantage is

```text
AdvEUFKO <= (1 - dom(OWF)/cod(OWF))^-1 *
            ( 10*(tau+1)*Q^3 * 2^(-2*lambda)
            + 10*Q^2*(tau + d_zk) * 2^(-lambda)
            + AdvPRG^OWF )
Q = (sum of oracle queries) + (tau+4)*Q_sig + 3*tau + d_zk + 19
```

with the prefactor at most 4 (Lemma 10.50) and `d_zk = 7`. The underlying
tools are Theorem 10.46 (round-by-round soundness implies Fiat–Shamir
soundness in the QROM) and Lemmas 10.48 and 10.49.

**[D]** The quadratic term, with the prefactor 4, reaches 1 at
`Q = 2^(lambda/2 - log2(40*(tau+7))/2)`; the cubic term at
`Q = 2^((2*lambda - log2(40*(tau+1)))/3)`:

| Row | `tau` | Quadratic term reaches 1 at | Cubic term reaches 1 at | Quadratic term at `Q = 2^64` |
| --- | ---: | ---: | ---: | ---: |
| 128s | 11 | 2^59.3 | 2^82.4 | above 1 |
| 128f | 17 | 2^59.0 | 2^82.2 | above 1 |
| 256s | 22 | 2^122.9 | 2^167.4 | 2^-117.8 |
| 256f | 33 | 2^122.7 | 2^167.2 | 2^-117.4 |

Without the prefactor the 256s figure is 2^123.9, the number the second-opinion
review gives **[R]**. The bound therefore does not certify 128 query bits at
`lambda` = 256, and certifies about 59 at `lambda` = 128. It does not prove an
attack at that cost.

**[D]** In the chosen-message bound the reprogramming term
`2·Q_sig·3·sqrt(3·sqrt(Q_1)·2^-lambda)` is about
`2^3.4 · Q_sig · Q_1^(1/4) · 2^(-lambda/2)`. For `Q_sig = 2^20` and
`Q_1 = 2^64` it is about 2^-24.6 at `lambda` = 128 and 2^-88.6 at
`lambda` = 256. A further term is `Q_sig` times the square root of the
AES-CTR PRG advantage. This arithmetic has not been rechecked by a second
reader. The specification's own summary calls the proofs "almost tight, except
for a multiplicative loss in the number of signing queries" **[P]** (section
11.1).

### 8.2 What it does not cover

- **Adversarially registered leaves.** The theorems are single-user games with
  the key produced by the challenger; the proof replaces that honest key by a
  random one **[P]** (v3 section 10.7). Nothing covers adversarially chosen or
  multiple public keys.
- **The ring relation.** The lossy step makes FAEST's single statement false.
  A ballot statement stays true through the adversary's own leaves **[D]**.
- **Grinding and signer randomness.** The QROM proof is for a variant in which
  the signer's randomness is sampled instead of derived, only one grinding
  counter is attempted, and one hash is replaced by a fixed function **[P]**
  (v3 section 10.11.6). The round-by-round errors contain no grinding term.
  Grinding gets no security credit beyond its actual quantum analysis **[R]**.
- **The detail the proof does not model.** The specification says the QROM
  proof "gives up on faithfully modeling one detail of FAEST" and does not
  name it **[P]** (v3 section 1). That it is the grinding retry loop is an
  inference **[E]**.
- **Larger witnesses.** Theorem 10.30 assumes `l + d_zk − 1 ≤ 2^12`,
  `C + 1 ≤ 2^13` and `d_zk ∈ {7, 14}` **[P]**; Lemmas 4.6 and 4.7 state the
  universal-hash errors under those limits. Every leading-candidate proof
  exceeds them (section 9). **[D]** From the proofs' own expressions the
  VOLE-hash error grows by a factor of about 2^7.0 at `l` = 18,912, 2^8.7 at
  23,712 and 2^12.9 at 42,912; the constraint-hash term is unaffected in
  practice. How the larger error propagates into the soundness bound was not
  derived.
- **Adaptive statements.** Theorem 10.46 and Lemma 10.49 are stated for static
  adversaries **[P]**. The ballot needs adaptive soundness over the list,
  scope and nullifier.
- **Strong unforgeability** is conjectured, not proved **[P]** (v3 section
  1.1). Deduplication must not rely on proof bytes being unique; ballot design
  section 3.6 already excludes by nullifier.

### 8.3 Quantum collision, multi-target and digest lengths

Two readings of "128-bit" exist and give different answers **[P][D]**. NIST's
categories price attacks in gates with a depth limit: category 1 is key search
on AES-128, and a 256-bit collision-resistant digest is category 2 **[P]**
(NIST evaluation criteria). The QROM bounds read here count queries, with
terms of the form `q^3/2^n`, so a collision-type term reaches 1 at
`q = 2^(n/3)` **[D]**. Gate 6 says hash lengths "follow the actual reduction",
which points to the query-count reading. The second-opinion review defends
that reading: effective security after the actual reduction and lifetime
accounting, not category 1 relabelled as 128 quantum bits **[R]**.

**[D]** Generic quantum collision cost by digest length (BHT queries
`2^(n/3)`; CNS time `2^(2n/5)`; from the abstracts of those papers):

| Digest | BHT queries | CNS time | Classical |
| ---: | ---: | ---: | ---: |
| 256 bits | 2^85.3 | 2^102.4 | 2^128 |
| 384 bits | 2^128 | 2^153.6 | 2^192 |
| 512 bits | 2^170.7 | 2^204.8 | 2^256 |

**[R]** Same-function key search against `S` targets costs about
`2^(256/2)/sqrt(S)` oracle evaluations: about 2^123 at `S = 1,000` **[D]**.
Wider commitments do not increase key entropy. Translating evaluations into
quantum gates needs an explicit calculation.

Digest lengths per role in the leading candidate:

| Role | Length | Basis |
| --- | --- | --- |
| `sk` | 256 bits | Key search as above |
| `C` | 768 bits | Injectivity arithmetic of section 8.4, not collision resistance |
| `nf` | 512 bits | Collision of nullifiers across credentials: 2^170.7 BHT queries **[D]** |
| Leaf, node, `R`, `B` | 512 bits (SHA3-512) | As `nf` |
| `scope`, `policy_hash` | 256 bits, fixed by the ballot design | Not analysed. Increasing `R` alone does not resolve a collision-critical 256-bit bottleneck elsewhere **[R]** |
| Proof-system internals at `lambda` = 256 | Seeds 256; leaf commitments 768; tree commitments and message digest 512; challenges 2,112 / 832 / 256; IV 128 | The reference's role-specific lengths, kept unchanged **[R]**; consistent with the specification's `3·lambda`, `2·lambda`, `8·lambda + 64`, `3·lambda + 64` and `lambda` **[P]** |

### 8.4 Commitment injectivity

Without an extractor, soundness gives only the existence of a witness. The
number of distinct accepted nullifiers is then bounded by the number of pairs
(leaf, key) that open a registered leaf. That equals `S` only if no registered
commitment has two preimages. Computational collision resistance is not
enough, because the reduction cannot output the two preimages **[D]**. FAEST
states exactly this stronger notion for its Even–Mansour variant and calls it
an assumption that cannot be efficiently verified **[P]** (v3 Definition
10.13).

**[D]** For an ideal random map from `k` key bits to `n` output bits the
expected number of distinct colliding key pairs is about `2^(2k − n − 1)`:

| Key | Output | Expected colliding pairs |
| --- | --- | ---: |
| 128 bits | two blocks, 256 bits | 1/2 |
| 256 bits | four blocks, 512 bits | 1/2 |
| 256 bits | five blocks, 640 bits | 2^-129 |
| 256 bits | six blocks, 768 bits | 2^-257 |

Six blocks avoid relying on near-certain injectivity of a four-block
commitment, which the arithmetic does not support. The figure holds in the
ideal-cipher model only. Actual AES does not inherit a global multi-key
injectivity theorem from ordinary PRP security; the required multi-key binding
assumption must be stated explicitly **[R]**.

### 8.5 Why no parameter tuple can be certified today

- No theorem covers the ring relation, adversarial registrations, the joint
  simulator or the registration proof (section 7).
- The one published QROM bound, applied to plain FAEST, reaches about 2^123
  queries at `lambda` = 256, below a 2^128-query reading (section 8.1).
- Multi-target key search at `S = 1,000` is about 2^123 evaluations
  (section 8.3).
- Every candidate witness is outside the stated hypotheses of the
  universal-hash lemmas (section 8.2).
- The security metric, the success probability that defines a break and the
  lifetime numbers of registrations, proofs, scopes and queries are not fixed
  (section 10).

The second-opinion review states that there is no final parameter tuple it can
honestly certify **[R]**. This record agrees.

### 8.6 Measurement baseline

Proposed **[R]** for a first measurement only. It is not a security claim and
not a selection.

| Role | Experimental choice |
| --- | --- |
| Credential master secret | 256 uniformly random bits |
| VOLE field and security parameter | `lambda` = 256 |
| Performance baseline | FAEST v3 fast row: `tau` = 33, `w_grind` = 8, `T_open` = 229 |
| Credential commitment `C` | Six AES blocks, 768 bits |
| Nullifier `nf` | SHAKE256, 512 output bits |
| Credential root `R` | SHA3-512, 512 bits |
| Public context digest | SHA3-512 |
| Proof-system internals | The exact reference's role-specific lengths |

The custom relation's degree, masks and checks must be recalculated. The
reference tuple is not a transferable theorem.

### 8.7 Anonymity is computational

**[D]** `C` and `nf` are deterministic functions of `sk` (ballot design
section 3.1), `C` is public at registration and `nf` is public in the ballot.
An unbounded adversary can search for the `sk` that opens each registered `C`
and recompute its nullifier in every scope. No profile that instantiates
section 3.1 can therefore give statistical anonymity; this is a property of
the ballot design, not of the leading candidate. Ballot design section 4
already scopes ballot anonymity as resting on "the post-quantum primitives of
`P`" **[C]**.

For the leading candidate those primitives are: AES-256 one-wayness and
pseudorandomness with plaintexts shared across seats, keyed SHAKE256
pseudorandomness given the AES commitment, and zero knowledge of the proof
system in the QROM (gate 5, not proved). Ballots and registrations stay on
chain permanently, so a later break of any of these identifies past voters
retrospectively **[E]**. The lifetime envelope of section 10 item 1 must
cover that horizon.

## 9. Resource projections

Analytical projection only. Nothing has been built or measured.

### 9.1 Formula

**[P]** FAEST v3 section 3.1 with Tables 3.1–3.3 and 5.1:

```text
size_bits = tau*l + n_mask*nbar_mult + 4*lambda + (d_zk-1)*lambda
          + T_open*lambda + n_leafcom*lambda*tau + lambda + 128 + 32
n_mask = d_zk + 3      nbar_mult = 8*ceil(n_mult/8)      n_leafcom = 3
```

Only `tau*l` depends on the witness length. The number of constraints has no
size term. The constraint degree enters through `d_zk`; any relation of degree
at most 7 uses the published `d_zk = 7`. `n_mult` depends on
`(lambda, tau, w_grind)`, not on the proven circuit **[P]** (Table 3.2
caption), so the table value is reused for a different relation on the same
row.

**[D]** Working form for `d_zk = 7`: `size_bytes = F_row + tau*l/8`, where
`F_row` is the published size minus `tau*l_plain/8`. `F_row` and the
"largest `l`" column below hold for `d_zk = 7` only. For `d_zk = 14` the full
formula applies with `n_mask = 17`, and the fixed part is larger than `F_row`
by `7*(nbar_mult + lambda)/8` bytes: 385 B on the 128 rows, 609 B on the 192
rows, 833 B at 256s and 840 B at 256f. `n_mult` for `d_zk = 14` is assumed
equal to the `d_zk = 7` table value; the specification's treatment of
`d_zk = 14` was not read:

| Row | `tau` | `w_grind` | `T_open` | Published size (B) | `F_row` (B) | Bytes per witness bit | Largest `l` under 262,144 B |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 128s | 11 | 7 | 102 | 4,066 | 2,746 | 1.375 | 188,653 |
| 128f | 17 | 8 | 108 | 5,170 | 3,130 | 2.125 | 121,888 |
| 192s | 16 | 12 | 162 | 9,410 | 5,954 | 2.0 | 128,095 |
| 192f | 24 | 8 | 163 | 11,738 | 6,554 | 3.0 | 85,196 |
| 256s | 22 | 6 | 225 | 16,626 | 10,554 | 2.75 | 91,487 |
| 256f | 33 | 8 | 229 | 20,856 | 11,748 | 4.125 | 60,702 |

The formula counts the proof object only. Statement fields, the message and
wire framing are extra and were not projected.

### 9.2 Assumptions

- The backend is FAEST v3 exactly as specified on the chosen row.
- AES witness accounting **[P]** (v3 Table 3.3): key schedule 448 / 448 / 672
  bits for AES-128/192/256; one encryption with public input and output costs
  512 / 640 / 768 bits. **[D]** An encryption whose output is not a public
  constant needs 128 more committed bits: 640 / 768 / 896.
- Keccak **[D]**: one Keccak-f[1600] permutation has 24 rounds of 1,600 AND
  gates, 38,400 in all. The nullifier needs exactly one permutation.
  Committed-state options: (a) degree 2, every round, 36,800 bits; (b)
  forward-only, a state every second round, degree 4, 17,600 bits; (c)
  forward-two and inverse-backward-one matching, a state every third round,
  12,800 bits; (d) `d_zk = 14`, 8,000 bits. Option (c) relies on the inverse of
  the Keccak nonlinear step having degree 3, which is recalled from the
  literature and not taken from the material read. Option (d) is the least
  reliable: what the specification prescribes for `d_zk = 14` was not read.
- The selector is two 32-entry vectors, 64 committed bits, at every `S`.
- V2 proves AES-256 and SHAKE256 at every `lambda`, so its witness length does
  not change with the row. V3 assumes a 96-byte commitment computed by one
  SHAKE256 call over 116 input bytes (one permutation); a wider input or
  output adds permutations.
- The selected 768-bit commitment is committed as witness and bound by a
  degree-2 multiplexer over the public list.

### 9.3 Variants

| Variant | Relation |
| --- | --- |
| V1 | AES-only published shape transplanted onto a v3 backend: commitment of 2 / 4 / 4 blocks, CBC-chain tag of 2 / 3 / 4 encryptions with a 128-bit output, per-member gated last-round constraints |
| V2 | The leading candidate of section 6 |
| V3 | Two-SHAKE public list: commitment and nullifier both SHAKE256 in the relation |
| V4 | AES-only with a statistically injective commitment (3 / 4 / 5 blocks) and a 256-bit tag. The tag construction is an assumption of this projection with no security analysis |

No one has specified or implemented V1 or V4 on a v3 backend.

### 9.4 Projected proof sizes

All figures **[D]**, in bytes, proof object only: `F_row + tau*l/8`, except
rows V2 (d) and V3 (d), which use the full section 9.1 formula with
`d_zk = 14` (fixed part `F_row` plus the increment given there). The
`lambda` = 128 and 192 columns of V2 and V3 are for comparison; they would mix
a 256-bit credential with a weaker proof. Worked example, V2 (b) at 256f:
11,748 + 33 × 23,712 / 8 = 109,560. V2 (d) at 256f: 11,748 + 840 +
33 × 14,112 / 8 = 70,800.

`pi_vote`:

| Variant | `l` (bits) | 128s | 128f | 192s | 192f | 256s | 256f |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| V1 | 2,944 / 5,760 / 7,776 | 6,794 | 9,386 | 17,474 | 23,834 | 31,938 | 43,824 |
| V4 | 4,096 / 6,400 / 9,440 | 8,378 | 11,834 | 18,754 | 25,754 | 36,514 | 50,688 |
| V2 (a) | 42,912 | 61,750 | 94,318 | 91,778 | 135,290 | 128,562 | 188,760 |
| V2 (b) | 23,712 | 35,350 | 53,518 | 53,378 | 77,690 | 75,762 | 109,560 |
| V2 (c) | 18,912 | 28,750 | 43,318 | 43,778 | 63,290 | 62,562 | 89,760 |
| V2 (d) | 14,112 | 22,535 | 33,503 | 34,787 | 49,499 | 50,195 | 70,800 |
| V3 (a) | 73,920 | 104,386 | 160,210 | 153,794 | 228,314 | 213,834 | 316,668 |
| V3 (b) | 35,520 | 51,586 | 78,610 | 76,994 | 113,114 | 108,234 | 158,268 |
| V3 (c) | 25,920 | 38,386 | 58,210 | 57,794 | 84,314 | 81,834 | 118,668 |
| V3 (d) | 16,320 | 25,571 | 38,195 | 39,203 | 56,123 | 56,267 | 79,908 |

`pi_reg`:

| Variant | `l` (bits) | 128s | 128f | 192s | 192f | 256s | 256f |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| V1 | 1,472 / 3,008 / 3,744 | 4,770 | 6,258 | 11,970 | 15,578 | 20,850 | 27,192 |
| V4 | 1,984 / 3,008 / 4,512 | 5,474 | 7,346 | 11,970 | 15,578 | 22,962 | 30,360 |
| V2 | 5,280 | 10,006 | 14,350 | 16,514 | 22,394 | 25,074 | 33,528 |
| V3 (a) | 37,056 | 53,698 | 81,874 | 80,066 | 117,722 | 112,458 | 164,604 |
| V3 (b) | 17,856 | 27,298 | 41,074 | 41,666 | 60,122 | 59,658 | 85,404 |
| V3 (c) | 13,056 | 20,698 | 30,874 | 32,066 | 45,722 | 46,458 | 65,604 |

Against the 256 KiB target: every V2 figure is under it, including the
unoptimised degree-2 form at the measurement-baseline row (188,760 B, 72%).
Only V3 (a) at 256f exceeds it (316,668 B, 121%). These sizes do not establish
security. The witness-length hypothesis of Theorem 10.30 is
`l + d_zk − 1 ≤ 2^12`, that is `l ≤ 4,090` at `d_zk = 7` **[P]**. For
`pi_vote`, only V1 at `lambda` = 128 lies inside it, and V4 at `lambda` = 128
misses it by 6 bits. For `pi_reg`, V1 at all three levels (1,472 / 3,008 /
3,744) and V4 at `lambda` = 128 and 192 (1,984 / 3,008) are inside it; V4 at
`lambda` = 256 (4,512), V2 (5,280) and every V3 form are outside **[D]**.

Proof size does not depend on `S` in any variant. Verifier public data does
**[D]**:

| Variant | Bytes per leaf | `S = 3` | `S = 500` | `S = 1,000` |
| --- | ---: | ---: | ---: | ---: |
| V1 (128 / 192 / 256) | 32 / 64 / 64 | 96 / 192 / 192 | 16,000 / 32,000 / 32,000 | 32,000 / 64,000 / 64,000 |
| V2, V3 | 96 | 288 | 48,000 | 96,000 |
| V4 (128 / 192 / 256) | 48 / 64 / 80 | 144 / 192 / 240 | 24,000 / 32,000 / 40,000 | 48,000 / 64,000 / 80,000 |

Work depends on `S` in every variant. For V2 and V3, selection is `O(S)`
cheap linear work over public data per ballot (section 6.4), with no
per-member AES constraints; how it compares with the Keccak constraint phase
is not measured **[E]**. For V1 and V4 each member needs its own gated
last-round constraints **[D]**: `S × blocks × 16 S-boxes × 2 constraints`, at
`S = 1,000` and `lambda` = 256 that is 1,000 × 4 × 32 = 128,000 (V1) and
1,000 × 5 × 32 = 160,000 (V4) gated constraint evaluations.

### 9.5 Time illustrations

All **[E]**. They scale published plain-FAEST v3 timings **[P]** (Tables 9.1
and 9.2, single core) by the ratio of VOLE lengths. The published times cannot
be split into witness-proportional and fixed parts from the material read, so
the true ratio may differ by about a factor of two either way. For V1 and V4
the figures are lower bounds at large `S`, because the per-member constraint
phase is extra.

| Variant, row | VOLE-length ratio to plain FAEST | Verify, Intel Core Ultra 9 285H (AVX2) | Verify, Pixel 6a | Verify, reference C on the Intel machine |
| --- | ---: | ---: | ---: | ---: |
| Plain FAEST 256f (published) | 1 | 1.603 ms | 5.531 ms | 72.850 ms |
| V1, 256f | 3.4 | 5.5 ms | 19 ms | 250 ms |
| V4, 256f | 4.2 | 6.7 ms | 23 ms | 0.3 s |
| V2 (c), 256f | 8.3 | 13 ms | 46 ms | 0.6 s |
| V2 (c), 256s | 8.2 | 100 ms | 380 ms | 1.5 s |
| V3 (c), 256f | 11.4 | 18 ms | 63 ms | 0.83 s |

Phone proving for V2 (c) at 256f scales to about 56 ms on the Pixel 6a anchor
**[E]**. Peak prover memory and verifier workspace were not projected. A
published "reference implementation" time is not necessarily a scalar time:
the official reference can select hardware or platform cryptography at build
**[R]**.

### 9.6 Cross-checks

- **[D]** The v3 formula reproduces all twelve published FAEST v3 and FAEST-EM
  signature sizes exactly.
- **[D]** The reference-code size formula, with its witness lengths of 5,248 /
  10,624 / 14,432 bits, reproduces the code-derived linkable sizes 9,962 /
  27,516 / 51,848 B at N = 2^10.
- **[D]** The gap between those and the V1 projection is witness length: the
  version 1 style code commits every AES round state, the v3 matching commits
  every second one. At 128s, (5,248 − 2,944) × 11 / 8 = 3,168 B =
  9,962 − 6,794.
- **[R][D]** The review's estimate for two SHAKE evaluations, about 76,800 AND
  gates and about 224 KB at slow `lambda` = 256, agrees with V3 (a): 213,834 B
  with the last-round saving, 222,634 B without.

### 9.7 Against the section 5 targets

| Target | Status |
| --- | --- |
| Proof ≤ 256 KiB | Projected to hold for V2 with margin **[D]**. Not measured |
| Verification ≤ 250 ms on the pinned minimum validator CPU | Cannot be judged. The CPU is not defined. Illustrations for V2 (c): about 13 ms (256f) to 100 ms (256s) on the architecture-specific implementation, and about 0.6 s (256f) to 1.5 s (256s) scaled from the published reference-implementation times, which are not established to be scalar or portable **[E]** |
| Verifier workspace ≤ 64 MiB | Not projected |
| Phone proving p95 ≤ 10 s | Cannot be judged. The devices are not defined. Scaled anchors suggest a wide margin **[E]** |
| Phone prover memory ≤ 256 MiB | Not projected |

Neither hardware baseline is defined anywhere in the repository **[C]**: the
phrases "pinned minimum validator CPU" and "supported baseline Android and iOS
devices" occur only in the ballot design itself.

## 10. Decisions that are the owner's

Engineering cannot make these implicitly. Each item names the consequence of
either answer and the section that supports it.

1. **Security metric and lifetime envelope.** The resource metric for gate 6
   (quantum queries through the actual reduction, or a gate-and-depth cost
   model), the success probability that defines a break, and the lifetime
   numbers of registrations, proofs, scopes and adversarial queries, over the
   horizon of section 8.7.
   *If queries through the reduction:* no FAEST row is certified by the
   published bound even at `lambda` = 256 (about 2^123, section 8.1), and
   256-bit digests are insufficient in collision roles (section 8.3).
   *If a gate-and-depth model:* the cost model and its depth limit must be
   written down before any ledger can be computed; gate 6's "follow the
   actual reduction" then needs a stated reading.
2. **Public-list verifier and evidence contract.** Whether `pi_vote` may prove
   selection from the sealed list with the root rebuilt outside the proof.
   This changes ballot design sections 3.1 (`Ballot_P(sk, i, path; m)`), 3.3
   (the relation proves the real-leaf encoding), 3.5 (index and path under
   `R`), 3.9 (full-verification inputs) and 12.2 step 3 (in-relation leaf,
   node and padding encodings), as tabulated in section 6.4.
   "Instantiation-neutral" is not clear authorization to leave the change
   implicit **[R]**.
   *If yes:* those clauses are amended and the carrier of the `S` real-leaf
   values is specified (section 6.4).
   *If no:* the leading candidate is out. What remains is a Merkle path
   inside the proof, projected at 134,304–468,154 B at `lambda` = 256, or the
   STARK route (section 4).
3. **Gate 8 wording.** Simulation-extractability as written, or a permitted
   equivalent such as the anti-copy formulation with its own cross-message,
   cross-relation argument (section 7.3). Ballot design section 3.2
   ("Possession proof") states simulation-extractability a second time and
   must be amended together with gate 8 if an equivalent is permitted.
   *If as written:* gate 8 needs a QROM simulation-extractability proof that
   was not found for either route (sections 7.1 and 7.4).
   *If an equivalent is permitted:* gate 8 reduces to the unforgeability
   argument of gate 2 plus joint zero knowledge, which are still class (c).
4. **AES binding assumption.** Whether multi-key key binding and injectivity
   of the six-block AES-256 commitment may be an explicit assumption
   (section 8.4).
   *If yes:* it is stated and reviewed as class (d).
   *If no:* gate 3 needs extraction (gates 1 and 2) or a commitment with a
   proved binding argument, which changes the relation.
5. **Keyed-SHAKE assumption.** Whether pseudorandomness of SHAKE256 keyed by
   `sk`, given the AES commitment of the same `sk`, may be an explicit
   assumption (sections 6.2 and 7.1, gate 4).
   *If yes:* it is stated and reviewed as class (d).
   *If no:* the nullifier needs another construction; the AES-only form was
   rejected (section 6.2).
6. **Arithmetisation-oriented hash.** Whether the STARK row of section 4 that
   uses Poseidon2 or Rescue-Prime in the relation is admissible, with its
   further assumption on a non-standardised hash.
   *If yes:* that row becomes a comparison candidate with its own parameter
   review.
   *If no:* the STARK route is limited to SHA-2/SHA-3 in the relation
   (250–600 KiB **[E]**).
7. **Hardware baselines.** The minimum validator CPU, including whether AES
   and carry-less-multiply acceleration is guaranteed, the supported phones,
   and whether the mandatory portable fallback must itself meet 250 ms.
   *Until answered:* the 250 ms and phone targets cannot be judged or
   falsified (sections 9.7 and 11.4).
   *If the portable path must meet 250 ms:* the scaled reference-code
   illustrations (0.6–1.5 s **[E]**, section 9.5) suggest it may not.
8. **Proof work.** Gates 1, 2, 5 and 8 need new written QROM arguments that no
   published theorem supplies (section 7.1). Decide whether that work is
   commissioned, who owns it and who reviews it, or whether the profile waits
   for published results.
   *If commissioned:* it is new cryptographic research with no assured
   outcome.
   *If not:* measurement can only falsify the engineering targets; it cannot
   move the candidate toward selection.
9. **What "discharge section 5" requires at ballot design 12.2 step 2.**
   Whether phone proving and memory measurements and independent proof review
   must be complete before `P` is selected and schemas start, or may remain
   as listed obligations until step 5 (section 11.1).
   *If complete before selection:* selection waits for the full measurement
   campaign and for review.
   *If deferred:* the ballot design text should say so, because step 2 as
   written does not.
10. **A standalone measurement harness.** Whether an isolated implementation
    and measurement of the candidate is authorized before items 1–9 are
    settled. Section 11.2 records a recommendation for an in-tree
    implementation **[R]**; an in-tree harness makes item 11 a precondition,
    an out-of-tree one does not.
    *If authorized:* the work of section 11.2 can start, and its runs are
    exploratory (section 11.3).
    *If the owner intends that nothing be built until a profile can be
    selected:* this record is a stop report, and engineering does not read it
    as permission to advance stages **[R]**.
11. **Placement and dependencies.** Where a VOLE-in-the-head engine lives
    under the shared-backend rule of [zk_delivery_plan.md](zk_delivery_plan.md)
    ("Shared proof backend and complete IVM proof"). That rule names one
    shared FASTPQ owner and lists the distinct families that keep their
    roles; it does not list VOLE-in-the-head **[C]**. The review reads the
    rule as one shared STARK owner, not a prohibition of a distinct family
    **[R]**. New crates and third-party dependencies need explicit approval.
    *If a distinct family is admitted:* the rule's list is extended in that
    specification.
    *If not:* no VOLE-in-the-head candidate can be built in tree.

Whether computational anonymity is acceptable is not a separate decision:
section 8.7 shows it follows from ballot design section 3.1 for every profile.

Any change to the qualification-before-integration order of ballot design
section 12.2, and the eventual record of activation qualification, are also
the owner's.

## 11. Evidence required and order of work

### 11.1 Minimum evidence before selection can be considered

Ballot design section 12.2 step 2 reads "Discharge section 5 and select `P`"
**[C]**. Read literally, section 5 includes the phone targets and the full
measurement inventory (cold runs, late-failing invalid proofs, thermal effects
and cancellation). Step 5 separately places "complete proof review" later
**[C]**. The review lists the six items below as what it would require before
integration **[R]**. Its item 6 lets phone qualification and independent
review remain outstanding at that point. That is the review's reading, not
the design's text; this record does not adopt it as the selection bar. Which
reading governs is section 10 item 9. The list is a minimum under either
reading:

1. Exact relations, encodings, domains and immutable parameters, including the
   approved list-verification contract.
2. Complete written arguments for every gate under explicit assumptions, not
   "should extend from FAEST".
3. A concrete lifetime security ledger, including statistical error and every
   relevant reduction loss.
4. A functioning deterministic implementation, reference and component
   vectors, and adversarial relation tests.
5. Measured proof sizes and bounded verifier costs at `S = 3`, 500 and 1,000,
   with a credible resource envelope.
6. A precise list of the remaining independent-review and phone-qualification
   obligations, with activation still disabled.

A complete exact-protocol argument awaiting independent review can be
compatible with review remaining a launch gate. A missing foundational
argument that needs new research is not a completed qualification step.
Independent review can find errors in a written argument; it cannot review an
argument that has not been written **[R]**.

### 11.2 Recommended order

**[R]** A small, state-free in-tree implementation directed by a pinned
specification, reusing established primitive implementations and keeping
external implementations as differential references. The available Rust
`faest` crate states compatibility with specification version 2 and no
security audit, and exposes whole signatures only **[P]** (crate manifest,
README and `src/lib.rs`, read through summaries); the official reference
implements version 3 **[P]**. Their known-answer tests are not
interchangeable.

1. Resolve the construction: games, assumptions, relation, specification
   version, hardware baselines and the owner of proof work. Produce exact
   circuit counts.
2. **Reproduce plain FAEST first.** Match same-version full-signature
   known-answer tests with fixed key, message and random tape, and
   cross-verify with the reference.
3. Match intermediate vectors: AES key expansion and round states; field
   basis, endianness and reduction; PRGs; GGM commit, open and reconstruct;
   VOLE consistency; universal hashes; transcript challenges and grinding.
4. Implement an independent native relation evaluator, then the proof
   constraints. Test wrong commitments and nullifiers, unconstrained states,
   invalid selectors, padding, `i ≥ S`, reordered lists, altered contexts and
   messages, and registration-copy attempts.
5. Bound the verifier: canonical parser, checked lengths, allocation
   accounting, late-failure tests, mutations and fuzzing.
6. Measure the portable implementation, then add feature-gated accelerated
   paths. Require identical fixed-randomness proof bytes and identical
   verification results, charges and error behaviour.
7. Measure the complete candidate at `S = 3`, 500 and 1,000.

Component known-answer tests establish conformance, not ballot security.
"Deterministic prover" means deterministic given an explicit random tape, never
fixed or reused production randomness. The phone prover needs constant-time
secret arithmetic, no secret-indexed tables, branches or roster accesses,
reviewed randomness handling and clearing of keys, round states, seeds and
masks on success, error and cancellation **[R]**.

### 11.3 Measurement record

Each run records, following ballot design section 5 and the repository's
evidence conventions (`zk_delivery_plan.md` H.1–H.3, `iroha_measurement`):

- full source commit and tree state; artifact, build profile and
  configuration identity; the pinned specification version;
- a named hardware record with observed host facts, and for phones the device,
  OS and thermal state;
- the exact inventory: `pi_reg` and `pi_vote`, prove and verify, at `S = 3`,
  500 and 1,000, on the portable path and each accelerated path;
- exact proof bytes; verification time cold and warm; verification time for
  late-failing invalid proofs and malformed encodings;
- verifier peak memory against the 64 MiB target; prover wall time with a
  stated sample count for p95, after sustained load, and with cancellation;
  prover peak memory; the grinding-retry distribution;
- logical work counters (hash calls, field multiplications, AES blocks) from
  which `B_work` and `B_bytes` are derived;
- byte-identical accept and reject results across paths;
- measured values kept separate from targets and projections; raw failures
  retained; a statement of what was not run; no private witness or key in the
  record.

Exploratory runs before the profile is frozen never count as qualification.

### 11.4 What would falsify the leading candidate

Thresholds, hardware records and the designated verification path are fixed
and recorded before a qualifying run (section 11.3, section 10 item 7). Until
they are, the measurement criteria below cannot be evaluated. The stop
conditions follow the second-opinion review **[R]**; the observable form given
to each is this record's **[E]**.

- **Proof.** No complete written argument for gates 1, 2, 5 and 8 exists when
  the measured candidate is otherwise ready for selection, or review concludes
  the ring relation cannot be proved.
- **Security floor.** The ledger of section 11.1 item 3 cannot reach the floor
  fixed under section 10 item 1.
- **Owner decisions.** The public-list contract, the AES binding assumption or
  the keyed-SHAKE assumption is not accepted (section 10 items 2, 4 and 5).
- **Targets.** For `pi_reg` or `pi_vote` at `S = 3`, 500 or 1,000, on the
  designated path, including late-failing invalid proofs, any of these is
  measured and no explicit profile and resource review approves a relaxation:
  - proof above 262,144 B;
  - worst-case uncached verification above 250 ms on the pinned minimum
    validator CPU;
  - verifier workspace above 64 MiB;
  - phone proving p95 above 10 s on a supported baseline device;
  - phone peak prover memory above 256 MiB.

  The two memory targets were not projected (section 9.7).
- **Capacity.** The worst-case per-ballot verification charge, including
  public-list processing (section 6.4), does not permit the capacity rule of
  ballot design section 3.6 at `S = 1,000`: 1,000 ballots for each of `K`
  concurrent attempts within the per-block budget at the minimum block
  cadence.
- **Parity.** Any accept, reject, charge or error difference between
  accelerated and portable paths.

## 12. What independent review must cover

- The exact relations, encodings and domain separation of section 6,
  including the selector and the `i < S` constraint.
- A written argument for each of the eight gates, with the game definitions,
  for both proofs under one `sk`.
- Applicability of the QROM Fiat–Shamir analysis to the actual protocol:
  adaptive statements, adversarially registered leaves, grinding and the
  retry loop, the unmodelled detail, and the re-derived universal-hash errors
  for witnesses beyond the published limits.
- The concrete security ledger: every reduction loss, statistical error and
  its accumulation, multi-target use, and the digest length of every role,
  including the 256-bit `scope` and `policy_hash`.
- The primitive assumptions: multi-key binding and injectivity of the AES
  commitment; AES pseudorandomness with plaintexts shared across seats; keyed
  SHAKE256 pseudorandomness given the commitment.
- The public-list contract, the carrier of the list and its effect on
  independent full verification (section 6.4).
- The arithmetic of this record that has had one reader only: section 8.1's
  chosen-message terms, the Keccak grouping of section 9.2 and every
  `d_zk = 14` figure.
- The implementation: conformance to the pinned specification, bounded and
  deterministic verification, identical results across hardware,
  malformed-input behaviour, constant-time and randomness handling in the
  prover. Source inspection alone does not establish resistance to physical
  side channels **[R]**.

## 13. References

Reading status: **full**, **part**, **abstract**, **code** (source files
read), **research pass** (collected mostly from abstracts or secondary
citations; unverified), **not read by us** (reported by the second-opinion
review).

Venue and year metadata for the arXiv QROM entries, for Unruh 2014/587 and
Liu–Zhandry 2019/262, the Bernstein title, and the author line of the FAEST
specifications were supplied from memory and not checked against the sources
**[E]**. The URLs are the identifiers.

**Specifications and code**

| Source | Status |
| --- | --- |
| FAEST team (Baum et al.), *FAEST Algorithm Specifications*, version 2.0. <https://faest.info/faest-spec-v2.0.pdf> | Part: pp. 2–82, 93–97, 101–111 |
| FAEST team (Baum et al.), *FAEST v3 Algorithm Specifications*, version 3.0. <https://faest.info/faest-spec-v3.0.pdf> | Part: sections listed in section 3 |
| FAEST reference implementation. <https://github.com/faest-sign/faest-ref> | Part: listings, README, changelog, test manifest; v2.0.5 sources through tool summaries |
| `faest` Rust crate (ait-crypto). <https://github.com/ait-crypto/faest-rs> | Part: manifest, README, changelog, `src/lib.rs`, `src/faest.rs`, `tests/nist.rs`, through tool summaries |
| FAEST project site. <https://faest.info/> | Front page; resources page not read by us |
| Chiang et al., reference implementation. <https://github.com/jachiang/PQ-Threshold-Ring-Sigs-from-VOLEitH> | Code: branch `master`; files listed in section 3 |
| NIST, *Post-Quantum Cryptography: Security (Evaluation Criteria)*. <https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-(evaluation-criteria)> | Full, through a tool summary |
| *Zcash Protocol Specification*. <https://zips.z.cash/protocol/protocol.pdf> | Part: sections 4.16 and 8.4 |
| Semaphore v4 circuit. <https://github.com/semaphore-protocol/semaphore> | Code: `semaphore.circom`, through a tool summary |

**VOLE-in-the-head and ring signatures**

| Source | Status |
| --- | --- |
| Chiang, Damgård, Duro, Engan, Kolby, Scholl, *Post-Quantum Threshold Ring Signature Applications from VOLE-in-the-Head*, ACM CCS 2025, ePrint 2025/113. <https://eprint.iacr.org/2025/113> | Abstract only. Paper not read by us; read by the second-opinion review through a mirror at moneroresearch.info |
| Baum, Beullens, Braun, Delpech de Saint Guilhem, Klooß, Majenz, Mukherjee, Orsini, Ramacher, Rechberger, Roy, Scholl, *Shorter, Tighter, FAESTer: Optimizations and Improved (QROM) Analysis for VOLE-in-the-Head Signatures*, CRYPTO 2025, ePrint 2026/164. <https://eprint.iacr.org/2026/164> | Abstract; its analysis was read as FAEST v3 section 10.11 |
| Baum, Beckmann, Beullens, Mukherjee, Rechberger, *Concretely Efficient Blind Signatures Based on VOLE-in-the-Head Proofs and the MAYO Trapdoor*, ePrint 2026/109. <https://eprint.iacr.org/2026/109> | Abstract |
| Baum, Beullens, Mukherjee, Orsini, Ramacher, Rechberger, Roy, Scholl, *One Tree to Rule Them All*, ASIACRYPT 2024, ePrint 2024/490. <https://eprint.iacr.org/2024/490> | Research pass |
| Zhang, Li, Steinfeld, Zhao, Liu, Yuen, *Fast Post-Quantum Ring Signature from Power Residue PRFs with QROM Security* (PegaRing), ePrint 2025/1841. <https://eprint.iacr.org/2025/1841> | Abstract |
| Jeon, Abou Haidar, Tibouchi, *LastRings*, ISC 2025, ePrint 2025/1633. <https://eprint.iacr.org/2025/1633> | Abstract |
| Zhang, Steinfeld, Liu, Esgin, Liu, Ruj, *DualRing-PRF*, ACISP 2024, ePrint 2024/985. <https://eprint.iacr.org/2024/985> | Research pass |
| Katz, Kolesnikov, Wang, *Improved Non-Interactive Zero Knowledge with Applications to Post-Quantum Signatures*, ACM CCS 2018, ePrint 2018/475. <https://eprint.iacr.org/2018/475> | Research pass |
| Derler, Ramacher, Slamanig, *Post-Quantum Zero-Knowledge Proofs for Accumulators with Applications to Ring Signatures from Symmetric-Key Primitives*, PQCrypto 2018, ePrint 2017/1154. <https://eprint.iacr.org/2017/1154> | Research pass |
| Goel, Green, Hall-Andersen, Kaptchuk, *Efficient Set Membership Proofs using MPC-in-the-Head*, PoPETs 2022(2), ePrint 2021/1656. <https://eprint.iacr.org/2021/1656> | Research pass (Tables 1 and 2) |
| Liu, Mahzoun, Øygarden, Meier, *Algebraic Attacks on RAIN and AIM Using Equivalent Representations*, ToSC 2024, ePrint 2023/1133. <https://eprint.iacr.org/2023/1133> | Research pass |
| Yang, Zheng, Yang, *Algebraic Cryptanalysis of AO Primitives Based on Polynomial Decomposition*, ASIACRYPT 2025, ePrint 2025/981. <https://eprint.iacr.org/2025/981> | Research pass |
| Beullens, Katsumata, Pintore, *Calamari and Falafl*, ASIACRYPT 2020, ePrint 2020/646. <https://eprint.iacr.org/2020/646> | Research pass |
| Lyubashevsky, Nguyen, Seiler, *SMILE*, CRYPTO 2021, ePrint 2021/564. <https://eprint.iacr.org/2021/564> | Research pass |
| Esgin, Zhao, Steinfeld, Liu, Liu, *MatRiCT*, ACM CCS 2019, ePrint 2019/1287; Esgin, Steinfeld, Zhao, *MatRiCT+*, IEEE S&P 2022, ePrint 2021/545. <https://eprint.iacr.org/2019/1287>, <https://eprint.iacr.org/2021/545> | Research pass |
| Lu, Au, Zhang, *Raptor*, AsiaCCS 2019, ePrint 2018/857. <https://eprint.iacr.org/2018/857> | Research pass |
| Gajland, Janneck, Kiltz, *Ring Signatures for Deniable AKEM: Gandalf's Fellowship*, CRYPTO 2024, ePrint 2024/890. <https://eprint.iacr.org/2024/890> | Research pass |
| Yuen, Esgin, Liu, Au, Ding, *DualRing*, CRYPTO 2021, ePrint 2021/1213. <https://eprint.iacr.org/2021/1213> | Research pass |
| Borin, Lai, Leroux, *Erebor and Durian*, IACR Communications in Cryptology 1(4), 2024. <https://cic.iacr.org/p/1/4/4> | Research pass |
| Xue, Lu, Au, Zhang, *Efficient Linkable Ring Signatures: New Framework and Post-Quantum Instantiations*, ESORICS 2024, ePrint 2024/553. <https://eprint.iacr.org/2024/553> | Research pass |
| Lyubashevsky, Nguyen, Plançon, *Lattice-Based Zero-Knowledge Proofs and Applications*, CRYPTO 2022, ePrint 2022/284. <https://eprint.iacr.org/2022/284> | Research pass |
| Kemmoe, Lysyanskaya, Nguyen, *Lattice-Based Rate-Limited Tokens in the Random Oracle Model*, ePrint 2026/1649. <https://eprint.iacr.org/2026/1649> | Research pass |
| Pareek, Kar Gangopadhyay, Gangopadhyay, *Lattice-Based Linkable Ring Signatures for Anonymous and Accountable Whistleblowing*, ePrint 2025/2170. <https://eprint.iacr.org/2025/2170> | Research pass |
| Katsumata, *A New Simple Technique to Bootstrap Various Lattice Zero-Knowledge Proofs to QROM Secure NIZKs*, CRYPTO 2021, ePrint 2021/927. <https://eprint.iacr.org/2021/927> | Research pass |

**QROM Fiat–Shamir and quantum cost**

| Source | Status |
| --- | --- |
| Don, Fehr, Majenz, Schaffner, *Security of the Fiat-Shamir Transformation in the Quantum Random-Oracle Model*, CRYPTO 2019. <https://arxiv.org/abs/1902.07556> | Part |
| Don, Fehr, Majenz, *The Measure-and-Reprogram Technique 2.0: Multi-Round Fiat-Shamir and More*, CRYPTO 2020. <https://arxiv.org/abs/2003.05207> | Part |
| Don, Fehr, Majenz, Schaffner, *Online-Extractability in the Quantum Random-Oracle Model*, EUROCRYPT 2022. <https://arxiv.org/abs/2103.03085> | Abstract and theorem index |
| Don, Fehr, Majenz, Schaffner, *Efficient NIZKs and Signatures from Commit-and-Open Protocols in the QROM*, CRYPTO 2022. <https://arxiv.org/abs/2202.13730> | Part |
| Grilo, Hövelmanns, Hülsing, Majenz, *Tight Adaptive Reprogramming in the QROM*, ASIACRYPT 2021. <https://arxiv.org/abs/2010.15103> | Part |
| Chiesa, Manohar, Spooner, *Succinct Arguments in the Quantum Random Oracle Model*, TCC 2019, ePrint 2019/834. <https://eprint.iacr.org/2019/834> | Abstract |
| Chiesa, Fenzi, *zkSNARKs in the ROM with Unconditional UC-Security*, TCC 2024, ePrint 2024/724. <https://eprint.iacr.org/2024/724> | Abstract |
| Chiesa, Di, Hu, Zheng, *How to Prove Post-Quantum Security for Succinct Non-Interactive Reductions*, EUROCRYPT 2026, ePrint 2025/2166. <https://eprint.iacr.org/2025/2166> | Abstract |
| Unruh, *Non-Interactive Zero-Knowledge Proofs in the Quantum Random Oracle Model*, EUROCRYPT 2015, ePrint 2014/587. <https://eprint.iacr.org/2014/587> | Abstract |
| Unruh, *Post-Quantum Security of Fiat-Shamir*, ASIACRYPT 2017, ePrint 2017/398. <https://eprint.iacr.org/2017/398> | Abstract |
| Liu, Zhandry, *Revisiting Post-Quantum Fiat-Shamir*, CRYPTO 2019, ePrint 2019/262. <https://eprint.iacr.org/2019/262> | Abstract |
| Kosuge, Xagawa, *New Security Proofs of MPC-in-the-Head Signatures in the QROM*, ePrint 2025/1999. <https://eprint.iacr.org/2025/1999> | Abstract |
| Brassard, Høyer, Tapp, *Quantum Algorithm for the Collision Problem*. <https://arxiv.org/abs/quant-ph/9705002> | Abstract |
| Chailloux, Naya-Plasencia, Schrottenloher, *An Efficient Quantum Collision Search Algorithm and Implications on Symmetric Cryptography*, ASIACRYPT 2017, ePrint 2017/847. <https://eprint.iacr.org/2017/847> | Abstract |
| Bernstein, *Cost analysis of hash collisions: Will quantum computers make SHARCS obsolete?*, 2009. <https://cr.yp.to/hash/collisioncost-20090823.pdf> | Not read: could not be retrieved |

**Hash-based proof systems (STARK family)**

| Source | Status |
| --- | --- |
| Ben-Sasson, Carmon, Ishai, Kopparty, Saraf, *Proximity Gaps for Reed-Solomon Codes*, FOCS 2020, ePrint 2020/654. <https://eprint.iacr.org/2020/654> | Research pass |
| Ben-Sasson, Carmon, Haböck, Kopparty, Saraf, *On Proximity Gaps for Reed-Solomon Codes*, ePrint 2025/2055. <https://eprint.iacr.org/2025/2055> | Research pass |
| Crites, Stewart, *On Reed-Solomon Proximity Gaps Conjectures*, ePrint 2025/2046. <https://eprint.iacr.org/2025/2046> | Research pass |
| Block, Garreta, Katz, Thaler, Tiwari, Zając, *Fiat-Shamir Security of FRI and Related SNARKs*, ASIACRYPT 2023, ePrint 2023/1071. <https://eprint.iacr.org/2023/1071> | Research pass |
| Haböck, Al Kindi, *A note on adding zero-knowledge to STARKs*, ePrint 2024/1037. <https://eprint.iacr.org/2024/1037> | Research pass |
| Grassi, Khovratovich, Schofnegger, *Poseidon2*, AFRICACRYPT 2023, ePrint 2023/323. <https://eprint.iacr.org/2023/323> | Research pass |
| Arnon, Chiesa, Fenzi, Yogev, *STIR*, CRYPTO 2024, ePrint 2024/390; *WHIR*, ePrint 2024/1586. <https://eprint.iacr.org/2024/390>, <https://eprint.iacr.org/2024/1586> | Research pass |
| Ames, Hazay, Ishai, Venkitasubramaniam, *Ligero*, ACM CCS 2017, ePrint 2022/1608. <https://eprint.iacr.org/2022/1608> | Research pass |
| Ben-Sasson, Chiesa, Riabzev, Spooner, Virza, Ward, *Aurora*, EUROCRYPT 2019, ePrint 2018/828. <https://eprint.iacr.org/2018/828> | Research pass |
| Manulis, Pulval-Dady, Slamanig, Wittig, *Context-Blind Device-Bound Anonymous Credentials from Signatures and Proofs*, ePrint 2026/2295. <https://eprint.iacr.org/2026/2295> | Research pass |
