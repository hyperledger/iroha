# Parliament ballot proof profile: evaluation record

Status: evaluation of 2026-10-12 against
[parliament_private_ballot_design.md](parliament_private_ballot_design.md)
(the "ballot design") at source baseline `485d392e62` plus the working-tree
revision of the ballot design. It incorporates the five texts that the
second-opinion review delivered on 2026-10-12 (section 3). **No profile is
selected. Nothing is qualified.**

The construction to develop is decided (section 6): a two-SHAKE proof over the
public sealed list, with a registration authorization value and a fresh
256-bit pad in the witness, in a VOLE-in-the-head backend derived from FAEST
v3.0. Its relations, witness layout, ordered constraints, parameter row,
proving tape and retry rule are frozen by decision. For the standalone
construction its byte-level protocol is frozen by decision as well: the
descriptor and its digest, the role prefix of every backend hash call, the
preimage of `mu`, the bounded opaque public inputs and the naked proof layout
(sections 6.1, 6.3, 6.6 and 6.7). The production Norito mappings, the
production envelopes and authenticated integration are later obligations and
are not written (section 11.1). The written arguments for the eight gates are consolidated in
[parliament_ballot_proof_arguments.md](parliament_ballot_proof_arguments.md)
(the "arguments file"). None of gates 1, 2, 5 and 8 has a complete argument,
gates 3, 4 and 7 are conditional, and gate 6 is not met (section 7.1).

What exists: stage 1 of the backend in `crates/iroha_zkp_vole` (parameters,
binary fields, the PRG, the `H0` to `H5` oracles, VOLEHash, ZKHash and
LeafHash), with conformance tests against the official FAEST v3.0.2 component
vectors `prg_tvs`, `universal_hashing_tvs` and `field_tvs` **[C]**. The
implementation work reports that every entry of those vectors is reproduced,
with and without the `accel` feature, and that a scratch prototype outside the
repository reproduces the reference CRT table construction (section 11.2).
This record ran no build and did not repeat those runs; the two reports are
statements of the implementation work, not verified by this record, and carry
none of the labels below. The later stages are in progress: the vector
commitment is unfinished work in the working tree, and the Rust port of the
CRT tables, the VOLE layer, the constraint check, plain-FAEST signatures and
the ballot relations are not implemented. `crates/iroha_parliament_ballot_proof`
is a skeleton **[C]**. Nothing is wired into anything. **No measurement
exists**: every size and time below is a
calculation or an estimate and is labelled as such.

Binding Parliament governance, and every capability that depends on it, stays
no-go. Of the selection rule of ballot design section 12.2 step 2
(section 11.1), condition 1 holds for the standalone construction by the
review's decision **[R]** (the construction, the row and the byte-level
protocol over bounded opaque byte strings are frozen; that does not cover the
production Norito mappings, the production envelopes or authenticated
integration), conditions 2 and 3 fail,
condition 4 is in progress, condition 5 is not met (no envelope schema and no
measurement), condition 6 is in progress and condition 7 holds. Schemas and
Core integration
(steps 3 and 4) therefore stay blocked, and the permitted work is standalone
implementation, measurement and proof work only (section 11.1).
`parliament_binding_ballot_available()` stays false until the owner records
qualification.

This record discharges none of the section 5 gate. It compares the candidate
families, states the decided construction exactly, records the decisions taken
and their source, and lists what is missing and what evidence a selection
needs. The owner decisions in ballot design section 1 are taken as fixed.

Every statement of fact carries one of these labels:

| Label | Meaning |
| --- | --- |
| **[P]** | Verified by this evaluation in a primary source, which is cited. Section 13 states how much of each source was read. |
| **[C]** | Read in repository source at the baseline. |
| **[R]** | Reported or decided by the second-opinion review (section 3). Not independently verified. A decision so labelled is a design decision, not a security proof. |
| **[D]** | Derived by calculation in this record. The formula and inputs are given. |
| **[E]** | Estimate or judgement. Not a measurement. |
| **[U]** | Published claim seen only in an abstract, a landing page or a secondary citation, or collected by the research pass without verification. |

## 1. Terms

`P`, `profile_id`, `sk`, `C`, `auth`, `L`, `R`, `B`, `S`, `scope`, `nf`, `m`,
`m_reg`, `pi_reg` and `pi_vote` are as in ballot design section 3.1. Further terms:

| Term | Meaning |
| --- | --- |
| VOLE-in-the-head | The proof family of the FAEST signature: a GGM-tree vector commitment, small-field VOLE correlations, a QuickSilver constraint check and Fiat–Shamir |
| `lambda`, `tau`, `w_grind`, `T_open`, `d_zk` | FAEST security parameter, number of small-VOLE instances, grinding bits, GGM opening threshold, maximal constraint degree |
| `l` | Number of committed witness bits of a relation |
| `N_c` | Number of constraints of a relation, Booleanity included. The FAEST specification and the review write `C`; this record keeps `C` for the credential commitment |
| `D_reg` | The 512-bit digest of the complete registration statement other than `auth` (section 6.2) |
| Pad | 256 fresh prover-random bits at witness positions `[0, 256)`. Proof coins, not a credential secret (section 6.3) |
| `mu` | The backend's message digest, into which the complete statement and message are bound (section 6.3) |
| Proving tape | The 80 fresh random bytes of one proof invocation (section 6.7) |
| QROM | Quantum random-oracle model |
| Public-list membership | The verifier holds the validated list of the `S` sealed commitments and the proof selects one of them, instead of proving a Merkle path inside the relation |
| `P16` | The 16-byte domain identifier of the experimental construction (section 6.1) |
| Fast row, small row | The sole integration candidate row and its measurement comparator (section 8.6) |
| BHT, CNS | The Brassard–Høyer–Tapp and Chailloux–Naya-Plasencia–Schrottenloher quantum collision algorithms |

## 2. What a profile must provide

A profile `P` fixes every hash, PRF, field, domain tag, canonical list and
preimage encoding, digest length and proof parameter and instantiates the
abstract functions of ballot design section 3.1:

```text
B       = BodyContextDigest_P(body_context)
C       = CredentialCommit_P(body_context, sk)
auth    = RegistrationAuth_P(sk, D_reg)
nf      = NullifierPRF_P(sk, scope)
R       = SealedListDigest_P(B, S, L)
pi_reg  = Registration_P(sk; C, m_reg)
pi_vote = Ballot_P(sk, selector; B, L, m)
```

with `m_reg = (network_id, authority, assignment_id, governance_attempt_id,
election_attempt_id, body_role, B, C, auth, profile_id)` (section 3.2) and
`m = (scope, R, S, nf, vote, policy_hash, profile_id)` (section 3.5). `sk` is
one high-entropy secret; every derived secret is a constrained derivation of
it. Fresh proof coins that a profile carries inside its witness are not
credential secrets: no commitment, authorization value or nullifier depends on
them. `D_reg` is the profile's digest of the registration statement. `pi_reg`
and `pi_vote` use distinct transcript domain tags (section 3.1). `L` is the
`S` sealed commitments in strictly increasing bytewise order, without padding.
The finalized block data of the seal carries its bytes. A verifier of
`pi_vote` holds a validated list or an immutable verification context
authenticated to that seal (sections 3.3 and 3.5) **[C]**.

`P` must establish the eight properties of ballot design section 5. They are
restated here in that section's own words:

1. **Authorization.** Knowledge of a registered credential, selection of
   exactly one entry of the validated sealed list at a position below `S`, a
   correct nullifier, a valid choice, and binding of the complete message `m`.
2. **Unforgeability.** Quantum chosen-message security despite observed honest
   ballots and adversarial credential registrations.
3. **Nullifier uniqueness.** For a fixed scope and sealed list, let the
   adversary control `k` sealed credentials and obtain honest ballots whose
   nullifiers form the set `H`. Except with negligible probability it cannot
   produce valid ballots with more than `k` distinct nullifiers outside `H`.
   Exclusion is by nullifier, not proof encoding: same-message replay and
   rerandomization are permitted, while authorizing a different message under
   an honest nullifier remains forbidden by item 2. Separately, the nullifier is
   deterministic for a credential and scope, independent of the vote.
4. **Cross-scope unlinkability and non-frameability.** Observing other scopes
   cannot identify or impersonate an honest credential holder.
5. **Full quantum zero knowledge and anonymity.** Two requirements, each
   with its own game.
   - *Joint zero knowledge.* An adaptive multi-theorem definition covering the
     complete transcripts of `pi_reg` and `pi_vote` under the same `sk`,
     adaptive queries, public registrations with their authorization values,
     and corrupt credentials. It holds for arbitrary application witnesses
     (`sk` for `pi_reg`; `sk` and the selected position for `pi_vote`) and
     arbitrary auxiliary information about them, the witness itself included.
     It is not restricted to honestly generated, undisclosed credentials. The
     honest prover samples the proof's own coins fresh for every proof. Those
     coins are excluded from disclosure, and a prover that accepts
     adversarially fixed or disclosed coins is outside the claim.
   - *Anonymity.* A separate left-or-right game. The two challenge credentials
     are honest and uncorrupted and sit in the same sealed list and body.
     Identified vote or nullifier queries for either candidate at the
     challenge scope are forbidden, earlier ones included. Later disclosure
     of either candidate is excluded. Several challenges must show the same
     nullifier-equality pattern in both worlds. The definition states exactly
     these exclusions; zero knowledge alone does not give anonymity, because
     the public commitments, authorization values and nullifiers under one
     `sk` must also be shown unlinkable.
6. **Concrete security.** A complete proven deployment-wide bound and an
   independently assessed attack cost, as read in section 8.8, including
   Fiat–Shamir losses, grinding, hash attacks and lifetime multi-target use.
   Statistical soundness error and its accumulation are quantified separately.
   Hash output lengths follow the actual reduction; 256-bit outputs are not
   assumed adequate for every role.
7. **Deterministic bounded verification.** Fixed encodings, maximum
   allocations, bounded hash and field work, defined malformed-proof behaviour
   and identical results across hardware.
8. **Registration authorization.** Establish adaptive multi-user
   credential-origin unforgeability in the QROM against malicious registrations
   and corrupt credentials, with access to both honest proof types. An
   adversary cannot authorize an uncorrupted honest credential under a fresh
   registration message, including recontextualization into another body. The
   registration message is the complete `m_reg`, the authorization value
   included. Joint zero knowledge is required. Simulation-extractability is
   sufficient but is not required by this item.

Section 7.3 gives the item 8 game. Section 8.8 gives the stated reading of
item 6. Item 8 does not discharge the knowledge requirement of item 1.

The engineering limits of section 5 apply to both proofs at `S = 3`, 500 and
1,000: complete canonical proof envelope ≤ 256 KiB (262,144 bytes); uncached
verification on the minimum validator baseline ≤ 250 ms; verifier workspace
≤ 64 MiB; phone proving p95 ≤ 10 s; phone peak prover memory ≤ 256 MiB. The
list-context object is capped separately at 160 KiB. The hardware baselines
are named in ballot design section 5 **[C]** and in section 11.4 of this
record.

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

The decisions of section 10.1 were taken by the same reviewer in two passes
that the owner delegated. The pass of 2026-10-11 reports reading the requested
records and the relevant implementation paths, consulting a further model and
checking primary sources **[R]**.

The pass of 2026-10-12 delivered five texts **[R]**:

- part 1: the exact relations, witness layout, constraint order and
  homogenisation, the re-derived universal-hash bounds, response-graph
  soundness for false instances and the proof of the encoding equivalence;
- part 2: gates 3, 4 and 7 as conditional arguments, the audit of imported
  results and a numeric ledger;
- part 3: a common oracle environment, the games and proof skeletons for
  gates 1, 2, 5 and 8 with their missing steps, candidate construction changes
  and the prioritised remaining proof tasks;
- the reconciling decisions, which supersede parts 1 to 3 wherever they
  differ. This record follows that precedence;
- a fifth text: the gate 5 game for the decided target with the carry-over of
  the simulator steps (section 7.1), the gate 8 event split with its premises
  (section 7.3), the corrected query offset of the static comparison
  (section 8.1), and the byte-level decisions for the standalone construction
  (sections 6.1 to 6.3, 6.6 and 6.7). It replaces or corrects the earlier
  texts on the points it names, and this record follows it there. For it the
  review reports reading the requested records and the reconciling text,
  checking the relevant backend code and primary FAEST sources, and
  independently recomputing the CRT digests.

That pass reports reading the working-tree records and the implementer's
notes and checking the relevant FAEST v3.0 material directly. It reports that
the PDF of ePrint 2026/164 was inaccessible to it and that it relies on no
theorem that appears only there **[R]**. Where it cites a FAEST v3 lemma,
figure or proof step outside the pages listed above, or a paper this
evaluation did not read (section 13), the statement is **[R]**. It describes
its arguments as written arguments awaiting independent review, not a
qualification. Their consolidated text is the arguments file.

Neither pass edited a file or ran a build **[R]**. The decisions are design
decisions. They are not security proofs, they are not an independent review of
this record, and they select and qualify nothing.

## 4. Candidates compared

No row below is a qualified profile. "Evidence" gives the best available size
and cost information with its label. Verdicts are **[E]**.

| Family | Construction | Assumptions | Evidence of size and cost | Verdict |
| --- | --- | --- | --- | --- |
| In-repo PQ-MASP | Goldilocks FRI STARK, SHA-256 depth-32 membership, stable nullifier, outer ML-DSA-65 authorization (`crates/iroha_core_privacy/src/privacy_engines/pq_masp/`) | SHA-256 and SHA3-384 as random oracles; FRI soundness; ML-DSA | **[C]** descriptor fixes trace 2^14, 556 base columns, maximum inner proof 9,431,915 B. **[E]** about 2.3–2.6 MB calculated from the geometry by the research pass. No measured size or time in the repository | Cannot be the profile (section 5) |
| In-repo ZK-ACE | Dedicated STARK: Poseidon-x7 identity commitment and replay nullifier, no membership | Non-standard six-lane Poseidon; its descriptor states QROM qualification is unavailable **[C]** | **[C]** canonical proof exactly 2,131,222 B | Not a candidate: no membership; **[E]** the research pass reports three independent witness secrets |
| In-repo FASTPQ | Masked DEEP/FRI engine, one fixed geometry | Honest-verifier answer-view hiding argument only (ballot design section 5) | **[C]** canonical child frame 500,084 B (`fastpq_production_readiness.md`) | Not a candidate at its geometry |
| STARK, SHA-2/SHA-3 in the relation | DEEP-ALI + FRI compiled with BCS; Merkle path, commitment and nullifier hashed inside the relation | Standard hashes as random oracles; FRI soundness in the proven (Johnson) regime | **[E]** 250–600 KiB (research pass; depends on undecided digest length and soundness floor) | Most conservative primitives; proves a Merkle path, which the sealed-list contract of the ballot design no longer uses. Size near or above the target (250–600 KiB **[E]**, unmeasured); **[R]** no demonstrated impossibility of meeting 256 KiB has been established. Gates 2, 5, 8 unproven in the QROM. A narrow form is the fallback research candidate if the construction to develop fails **[R]** (section 11.5) |
| STARK, arithmetisation-oriented hash | Same proof system; Poseidon2 or Rescue-Prime in the relation | As above, plus collision and PRF security of a non-standardised hash under active cryptanalysis **[U]** | **[E]** 150–300 KiB with 48-byte digests, 100–200 KiB with 32-byte digests (research pass) | Not admissible in this profile **[R]** (section 10.1). It fits the size limit only under a lenient security metric, with a further assumption and parameter review |
| STARK with STIR or WHIR | FRI replaced by a newer proximity test | As above; the up-to-capacity conjectures are refuted **[U]** (Crites–Stewart, ePrint 2025/2046) | **[U]** published figures are for large instances; **[E]** modest gain at this relation size | Dominated at this statement size |
| Ligero / Aurora | Linear-code IOPs with zero knowledge designed in | Standard hashes | **[U]** neighbouring published proofs 0.2–1.9 MB; an Aurora credential prototype verifies in 1.37 s | Dominated: size and linear verification |
| VOLE-in-the-head, AES-only published shape | One AES key; AES commitment; AES CBC-chain tag as nullifier; one-out-of-N selector over the public list (Chiang et al.) | AES pseudorandomness and key binding; SHAKE as (Q)RO; **[R]** the paper's theorem is in a classical model | **[D]** from the reference code's size macros at N = 2^10: 9,962 / 27,516 / 51,848 B at 128/192/256-bit. **[R]** paper: 51.98 KB and at most 103 ms sign or verify at ring 1,024, AES-256. **[D]** 31,938–43,824 B on a FAEST v3 backend at `lambda` = 256 (section 9, V1) | Compared alternative; not the preferred design **[R]**. Smallest; 128-bit tag; commitment not statistically injective (expected 1/2 colliding key pair in the random-map model, section 8.4); reference code unusable (section 6.5) |
| VOLE-in-the-head, hybrid with SHAKE256 nullifier | Six-block AES-256 commitment `C = (AES256_sk(p_0) \|\| ... \|\| AES256_sk(p_5)) xor D` with a public SHAKE256 mask `D` of the body context, a SHAKE256 nullifier inside the relation, a 256-bit `sk` and the public-list selector | AES key binding in a stated multi-key form; keyed SHAKE256 pseudorandom given the AES commitment; SHAKE as QRO | **[D]** `pi_vote` 62,562–188,760 B at `lambda` = 256 (section 9, V2) | Compared alternative; not chosen **[R]**. It needs two additional credential assumptions, multi-key injectivity of the AES commitment and keyed-SHAKE security given that commitment, and the public mask does not remove them. Avoiding them is judged worth the larger proof (section 10.1). If the two-SHAKE construction passes, it is retained even if the hybrid benchmarks faster (section 11.5) |
| VOLE-in-the-head, two-SHAKE public list | Commitment and nullifier both SHAKE256 inside the relation, and a SHAKE256 registration authorization value inside the registration relation; 384-bit `sk`; no AES in the relation; flat digest of the public sealed list (section 6) | SHAKE256 as the modelled oracles in its three uses; the backend's PRG and commitment assumptions, with AES-based PRGs in the initial implementation **[R]** | **[R][D]** Fast row: `pi_vote` 159,852 B and `pi_reg` 159,588 B. Small row: 109,290 B and 109,114 B (section 9.7). **[D]** The V3 projection shape (256-bit `sk`, 96-byte commitment, no pad, no authorization value): `pi_vote` 81,834–316,668 B at `lambda` = 256 (section 9, V3). **[U]** a SHA-3 component inside VOLE-in-the-head is reported implemented (ePrint 2026/109) | The construction to develop (section 6). Not selected and not qualified. Largest witness of the three public-list variants; no additional credential assumption |
| VOLE-in-the-head, Merkle path inside the proof | Depth-10 path with a Rijndael-256 compression function, or with SHA-3 | Rijndael-256 in a hash mode analysed only in the ideal-cipher model **[E]**; or SHA-3 | **[D]** Rijndael: 134,304–217,998 B at `lambda` = 256 from the v3 size formula with the research pass's unverified 45,000–50,000-bit witness. **[D]** SHA-3: at least 13 Keccak permutations. At grouping (c) of section 9.2 (12,800 bits per permutation): 13 × 12,800 = 166,400 bits, 10,554 + 22 × 166,400 / 8 = 468,154 B at 256s. At grouping (d) (8,000 bits, `d_zk = 14`, the least reliable figures): 13 × 8,000 = 104,000 bits, 10,554 + 833 + 22 × 104,000 / 8 = 297,387 B at 256s | Keeps root-only verification. Rijndael's 256-bit digest gives about 2^85 quantum collision queries; SHA-3 misses the size target at `lambda` = 256 |
| Classical MPC-in-the-head rings | ZKB++ / KKW ring signatures over LowMC | LowMC; classical ROM | **[U]** 388 KB (Katz et al.) and 56 KB (Goel et al.) at ring 2^10; seconds on small machines | Dominated; none is linkable as published |
| Power-residue and algebraic-OWF rings | PegaRing, DualRing-PRF; Rain, AIM, MQ one-way functions | Legendre / power-residue PRFs or young algebraic designs; **[U]** AIM broken, Rain margins shrinking | **[U]** PegaRing about 28 KB at ring 1,024 with a claimed QROM proof; linkability not stated in its abstract | Not conservative enough for a governance ballot |
| Lattice compositions | MLWE commitment, log-size set membership, weak-PRF nullifier on a hashed scope | MLWE / MSIS; classical ROM | **[E]** tens of KB to about 220 KB; no published scheme, parameter set or QROM proof for this relation | Compared; not implementable as a first profile |
| Published post-quantum linkable ring signatures | Falafl, Calamari, SMILE, MatRiCT, Raptor and others | MLWE / MSIS, isogenies; classical ROM | **[U]** sizes from about 10 KB to above 1 MB at ring 1,024 | **[U]** The research pass describes the tags of these schemes as key-only. **[R]** The review found that description wrong as a general statement (Chiang et al. support instance-dependent tags, section 6.5). **[R]** No verified theorem was found covering the scoped nullifier, registration and adaptive quantum anonymity together |

**The comparison.** A hash-based Merkle-membership signature of knowledge
keeps verification against a root alone. With standardised hashes its
projected size is near or above the 256 KiB limit in the STARK form
(250–600 KiB **[E]**, unmeasured) and above it in the VOLE-in-the-head form at
`lambda` = 256 **[D]**. **[R]** No demonstrated impossibility of meeting
256 KiB has been established. No proof of gates 2, 5 or 8 was found for any
concrete instance. A post-quantum linkable ring signature gives a far smaller
private relation, but no published scheme was found whose theorems cover a
scope-dependent nullifier, the registration proof and joint quantum anonymity
**[R][U]**, and ring verification needs the verifier to hold the member list.
The construction to develop takes the ring-style public-list selector, proves
it in a symmetric-primitive proof system and commits to the list by a flat
digest outside the proof. The ballot design requires the validated list of
every verifier (section 6.4) **[C]**. Among the three public-list variants,
the hybrid and the AES-only shape are smaller, but they rest on additional
credential assumptions or a 128-bit tag. They stay in the table as compared
alternatives only **[R]**. No row is qualified.

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
randomness wrapper. None of it applies to a VOLE-in-the-head engine **[E]**
(research pass). That backend is the separate experimental crate of
section 11.2.

## 6. Construction to develop

This is the single construction to develop **[R]**. It is not the normative
`P`: no profile is selected. Its `profile_id` is not allocated. `P16` below
identifies this experimental construction. The ballot proof is FAEST-derived.
It is not a standard FAEST signature, and fixing the relation does not claim
that the custom proof inherits FAEST's signature theorem **[R]**.
Sections 6.1 to 6.4, 6.6 and 6.7 state the construction as decided by the
second-opinion review (section 10.1); every definition in them is **[R]**
unless marked otherwise. The review describes the result as a construction
frozen for investigation, not a selected or qualified one **[R]**.

Frozen by decision: the relations, the witness layout, the ordered constraint
stream and its homogenisation (section 6.3), the parameter row, the leaf
commitments and the CRT tables (section 6.6), and the proving tape and retry
rule (section 6.7).

Frozen by decision for the standalone construction as well **[R]**:

- the descriptor `DESC`, its 64-byte digest `D` and the CRT table digest
  `T_crt`, with their values for both rows, and the public inputs as bounded
  opaque byte strings with their bounds and boundary rules (section 6.1);
- the 64 bytes that `D_reg` takes for the descriptor (section 6.2);
- the role namespaces, the 77-byte prefix of every backend hash call and the
  exact preimage of `mu` (section 6.3);
- the naked proof layout for both rows and relations, and a test-only
  statement codec (section 6.6);
- the allocation and uses of the tape and the erasure rule (section 6.7).

The review states that the public-input language of the standalone
construction is now explicitly bounded byte strings and that no relation or
transcript choice remains open for it **[R]**. Later obligations, not
written: the production Norito mappings of the typed node values onto those
byte strings, the production envelopes, and authenticated integration. The
standalone verifier does not validate node-level canonicality, and the
absence of those mappings must not be hidden by claiming that it does
**[R]**. The comparator row has a transcript identity distinct from the
candidate row **[R]**: its descriptor digest `D`, and with it both role
prefixes, differ (sections 6.1 and 6.3).

### 6.1 Framing and context

```text
P16 = 5041524c2d5348414b452d5631000000      // 16-byte construction domain

Frame(tag; fields...) =
    u16_le(len(tag)) || ASCII(tag) ||
    u16_le(number_of_fields) ||
    concat(u32_le(len(field)) || field)

B = SHA3-512(Frame("PARL/BODY/v1"; P16, Enc(body_context)))
```

- `P16` is the ASCII string `PARL-SHAKE-V1` followed by three zero bytes
  **[D]**. It is a 128-bit literal identifier, not a collision-security claim.
- All ASCII literals exclude a terminating NUL byte. The three zero bytes of
  `P16` are its explicitly defined padding.
- In the standalone construction every `Enc(x)` is a bounded opaque byte
  string supplied by the caller ("Opaque public inputs" below). The
  construction neither imports node types nor parses their encodings. In
  production `Enc(x)` is the pinned canonical Norito encoding of the specified
  typed value, which Core must supply and validate; that mapping is a later
  obligation (section 11.1). Stored and wire records use header-framed Norito.
  `Frame` is a cryptographic preimage definition, not an alternative wire
  codec.
- Field order and the length bounds below are fixed. No conversion,
  normalization, delimiter insertion or terminator is applied to any opaque
  input. Rejecting alternative encodings and non-canonical values of a typed
  node value is Core's obligation on its pinned Norito representations: the
  proof crate does not detect two encodings of one node-level value, and Core
  must not rely on it to do so.
- Fixed integers are little-endian. Votes are exactly `0 = Aye`, `1 = Nay`,
  `2 = Abstain`.
- Keccak lane and bit conventions follow FIPS 202. Backend field conventions
  follow the pinned backend specification.
- **Role audit of 32-byte values.** An opaque, authenticated state identifier
  need not become wider merely because it has 32 bytes. A collision-sensitive
  content fingerprint must become 64 bytes or be replaced in the binding by
  its canonical preimage. Hashing an ambiguous 32-byte fingerprint again does
  not repair it. The audit has not been carried out.

**Descriptor.** `lambda`, `tau`, `w_grind`, `T_open`, `d_zk` and `n_mult` are
the row of section 6.6; `l_reg`, `M_reg`, `l_vote` and `M_vote` are the
witness lengths and constraint counts (`N_c`) of section 6.3.

```text
SUITE = ASCII(
  "KECCAK-F1600/2R-FWD/SEL-32X32-PREFIX/PAD-256/TAPE-80/CTR-U32/NS-PREFIX77"
)

DESC = Frame("PARL/DESC/v1";
    P16,
    ASCII("FAEST-3.0"),
    u16_le(lambda) || u16_le(tau) || u16_le(w_grind) ||
    u16_le(T_open) || u16_le(d_zk) || u16_le(n_mult),
    T_crt,
    u32_le(l_reg) || u32_le(M_reg) ||
    u32_le(l_vote) || u32_le(M_vote),
    SUITE)

D = SHA3-512(DESC)
```

| Row | Parameter tuple `(lambda, tau, w_grind, T_open, d_zk, n_mult)` | Relation dimensions `(l_reg, M_reg, l_vote, M_vote)` |
| --- | --- | --- |
| Fast | `(256, 33, 8, 229, 7, 704)` | `(35840, 72576, 35904, 72707)` |
| Comparator (small) | `(256, 22, 6, 225, 7, 696)` | The same |

- `SUITE` is 72 bytes **[D]**. It immutably names the relation, the
  constraint ordering, the encodings, the transcript and the randomness rules
  frozen in this section. It is not an extensible options string.
- The verifier selects a compiled, fixed descriptor. It does not accept an
  arbitrary caller-defined descriptor.
- `DESC` is 229 bytes on both rows **[R]**, recomputed here **[D]**:
  `2 + 12 + 2` for the tag and the field count, plus six length prefixes of
  4 bytes and fields of 16, 9, 12, 64, 16 and 72 bytes.

**CRT table digest.** `T_crt` binds the official CRT tables of section 6.6.
`CRT_BYTES` is defined as the byte serialisation of the canonical word codec
of the working-tree backend, `crates/iroha_zkp_vole/src/crt/codec.rs`:

```text
CRT_BYTES =
    ASCII("FAESTCRT")
    || u64_le(lambda) || u64_le(tau)
    || u64_le(w_grind) || u64_le(n_mult)
    || concat(u64_le(tree_modulus_i))       // increasing i
    || words_le64(M_TREE)
    || words_le64(F)
    || words_le64(G)
    || words_le64(W_TREE)
    || words_le64(W_GATE)
    || words_le64(W_CRT)

T_crt = SHAKE256(CRT_BYTES, 64 bytes)

n_delta = lambda - w_grind
M_TREE: n_delta + 1 bits
F:      n_mult × lambda
G:      n_mult × n_delta
W_TREE: lambda × n_delta
W_GATE: lambda × n_mult
W_CRT:  lambda × n_delta
```

Matrices are row-major. Each row occupies `ceil(width/64)` words; column `c`
is bit `c % 64` of word `c / 64`; unused high bits are zero. **[C]**
`encode_words` in the codec file emits the word `FAESTCRT` (little-endian
bytes), `lambda`, `tau`, `w_grind`, `n_mult`, the tree moduli as `u64` words
in table order, then `M_TREE`, `F`, `G`, `W_TREE`, `W_GATE` and `W_CRT`, in
that order. `CRT_BYTES` is 84,304 bytes on the fast row and 83,704 bytes on
the small row **[D]** (`8 ×` the word count: 5 header words, `tau` modulus
words, 4 words of `M_TREE`, and the five matrices).

**Fixed digest values [R].** Each is 64 bytes, written as 128 hexadecimal
digits.

```text
T_crt (fast row) =
a9c572a7c8f2cc735218123c6456e1e016e78b06aa2d03192ef801bf7fdb93ae014a9e16555e6bad81382c630467e45e76c9b1c3948f9dfea41a7a1435bcffea

T_crt (small row) =
792f81bf102cac84b7c559595342b6b23ad27dab9065651feb928dd0a649a3f4bd1da3d350fbd4c62f1707d441d46ef084430b5f00b53a1af7088281d6a7386e

D (fast row) =
44028deb664beb1a06a336cd6f622c223a5c15741dfafa72b55e19cbb42f287ba48979a0d6a8342c80034cc88b87fcb055f0db686fe97beffb2197bc7f85e910

D (small row) =
1f59fe5ae24c0d5dfb86611f1ed4439edd7995d6cbbf308f2954b4bb2c3fece8fe4c080dcef118bb4100d6cf5c4de012318e3a1227b78299e24d5a113cb31273
```

The review reports that it recomputed the two `T_crt` values independently
**[R]**. **[D]** Both `T_crt` values were recomputed here as
`SHAKE256(CRT_BYTES, 64 bytes)` in two ways, and both agree with the printed
values on both rows: from the word arrays in the generated table sources
`crates/iroha_zkp_vole/src/crt/generated/faest_256f_tables.rs` and
`faest_256s_tables.rs`, read as text and serialised in the order above; and
from tables produced by a separate Python port of the FAEST v3.0.2 reference
table generator. **[D]** Both `D` values were recomputed here as
`SHA3-512(DESC)` from the definition above, and agree. No build was run:
that the compiled backend emits these bytes through `encode_words`, and that
the generated tables equal the official reference tables other than through
the Python port, are not checked.

**Opaque public inputs.** The public inputs of the standalone construction
are bounded byte strings.

| Input | Permitted byte length |
| --- | ---: |
| `Enc(body_context)` | 0 to 4,096 |
| Each of `Enc(network_id)`, `Enc(authority)`, `Enc(assignment_id)`, `Enc(governance_attempt_id)`, `Enc(election_attempt_id)`, `Enc(body_role)` | 0 to 256 |
| `B`, `scope`, `R`, `auth`, `nf`, `policy_hash`, `proposal_digest`, `D` | Exactly 64 |
| `C` and each list entry | Exactly 128 |

- Empty opaque strings are structurally permitted by the standalone protocol.
  Application validity belongs to the caller's typed encoding and
  authentication rules.
- `body_context` and `authoritative_body_context` (section 6.2) are the same
  byte string.
- Registration verification recomputes `B` and `D_reg`. It does not trust
  caller-supplied derived digests.
- Vote validation enforces `3 ≤ S ≤ 1000`, exactly `S` entries, strict
  unsigned bytewise ordering, no duplicates, the recomputed `R` and
  `vote ∈ {0, 1, 2}`. The caller authenticates the expected body and the
  sealed list.
- The digest helpers for the section 6.2 frames are optional. In them
  `Enc(body_instance_id)` has length 0 to 256, and the network and
  governance-attempt inputs use the bounds above. The policy and proposal
  preimages may have any length from 0 to `0xffff_ffff`, the field-length
  limit of `Frame`; the helpers stream them with checked lengths. They are
  not additional proof fields. The section 6.2 frames are preserved exactly,
  including where each places or omits `P16`.

### 6.2 Commitment, authorization value, nullifier, list and messages

```text
sk = 48 uniformly random bytes, fresh for each body

C  = SHAKE256("PCR1" || P16 || sk[48] || B[64],     128 bytes)
nf = SHAKE256("PNF1" || P16 || sk[48] || scope[64],  64 bytes)

D_reg = SHA3-512(Frame("PARL/REG-AUTH/v1";
                      P16,
                      ASCII("REG"),
                      D,
                      Enc(body_context),
                      Enc(network_id),
                      Enc(authority),
                      Enc(assignment_id),
                      Enc(governance_attempt_id),
                      Enc(election_attempt_id),
                      Enc(body_role),
                      B,
                      C))

auth = SHAKE256("PAU1" || P16 || sk[48] || D_reg[64], 64 bytes)

policy_hash = SHA3-512(Frame("PARL/POLICY/v1";
                            P16, Enc(complete_frozen_policy)))

proposal_digest = SHA3-512(Frame("PARL/PROPOSAL/v1";
                                Enc(canonical_proposal_content)))

scope = SHA3-512(Frame("PARL/SCOPE/v1";
                      P16, Enc(network_id), proposal_digest,
                      Enc(governance_attempt_id),
                      Enc(body_instance_id)))

L = (C_0, ..., C_(S-1))    // strictly increasing bytewise; no duplicates

R = SHA3-512(Frame("PARL/LIST/v1";
                  P16, B, u16_le(S), concat(L)))

m_reg = (
    network_id, authority, assignment_id,
    governance_attempt_id, election_attempt_id, body_role,
    B, C, auth, P16
)

m = (scope, R, S, nf, vote, policy_hash, P16)
```

- `sk` is 384 bits, `C` is 1,024 bits, and `auth`, `D_reg`, `nf`, `R`, `B`,
  `scope`, `policy_hash` and `proposal_digest` are 512 bits.
- The three SHAKE256 inputs are exactly 132 bytes each: 4 + 16 + 48 + 64
  **[D]**. Each output fits the 136-byte SHAKE256 rate, so each evaluation
  needs one Keccak-f[1600] permutation and no second squeezing permutation.
  Standard SHAKE padding and bit ordering apply (FIPS 202).
- The commitment depends on the body context through `B`. The nullifier
  depends on the full scope and is independent of the vote. The authorization
  value depends on the complete registration statement through `D_reg`. All
  three are constrained inside a relation under the same `sk`. There is no AES
  in the relation.
- **Authorization value.** `auth` is a public value of the registration
  statement. `D_reg` covers the profile descriptor, the authoritative body
  context, every field of `m_reg` other than `auth`, and the role string
  `REG`. It excludes `auth`, `mu`, the proof bytes and the prover's
  randomness. The descriptor field is exactly the 64 bytes `D` of
  section 6.1: not `DESC`, and not a Norito wrapper around `D`. `D` commits to
  the parameter row and, through `SUITE`, to all fixed protocol choices. The
  body-context field is the byte string `Enc(body_context)` that `B` hashes;
  `body_context` and `authoritative_body_context` name the same byte string.
  Every field of `m_reg` other than `P16`, with the body context, enters `mu`
  through `F_REG`; `P16` is not a field of `F_REG` or `F_VOTE` and enters only
  through `DESC`, hence `D`, in `NS_R` **[D]** (read from the definitions of
  section 6.3; the review does not state it). So `auth` is bound through `mu` into the IV and
  the challenge chain, and it is also constrained inside the registration
  relation (section 6.3). `auth` is neither a signature nor a Core check; what it
  supports and what it does not establish is in section 7.3.
- **The vote relation has no authorization value.** An analogous value would
  not establish uniqueness of the secret underlying a target nullifier: the
  512-bit nullifier is not globally injective on the 384-bit secret space, so
  a statement about a target nullifier still needs an argument that excludes
  alternative witnesses (section 7.1, gate 2).
- `L` has exactly `S` entries. There are no padded credential leaves, no leaf
  or node hashing and no tree.
- In the experimental construction `P16` stands where the ballot design's
  messages carry `profile_id`.

### 6.3 Relations, witness layout, constraints and transcript

**Relations.** After the public validation below:

```text
R_reg(x; sk)      <=>  C = SHAKE256("PCR1" || P16 || sk || B, 1024 bits)
                       and auth = SHAKE256("PAU1" || P16 || sk || D_reg, 512 bits)

R_vote(x; sk, i)  <=>  0 <= i < S
                       and C_i = SHAKE256("PCR1" || P16 || sk || B, 1024 bits)
                       and nf  = SHAKE256("PNF1" || P16 || sk || scope, 512 bits)
```

| Proof | Public input | Semantic witness | Extended witness |
| --- | --- | --- | --- |
| `pi_reg` | Complete `m_reg`, authoritative body context and the profile descriptor | `sk` | Pad, `sk`, the committed Keccak states of the commitment and authorization permutations |
| `pi_vote` | `B`, validated `L`, complete `m`, the profile descriptor | `sk` and the position `i` | Pad, `sk`, the committed Keccak states of the commitment and nullifier permutations, two selector vectors |

- **Public validation** contributes no witness constraint. In the standalone
  construction it covers the length bounds of section 6.1, the compiled fixed
  descriptor and the recomputed body-context digest `B`, and for registration
  the recomputed `D_reg`; canonicality of the typed values behind the opaque
  inputs is validated by Core, not by it. For voting it also covers `3 ≤ S ≤ 1,000`, exactly `S`
  strictly ordered distinct commitments, the correct authenticated list digest
  `R`, and a vote byte in `{0, 1, 2}`.
- Core separately checks registration authority, invitation and assignment
  eligibility, freshness, uniqueness and the sealed subset. Those checks are
  not facts proved by `pi_reg`.
- **Uniformity of `sk` is a generation requirement, not an algebraic
  predicate.** The relation accepts every secret that satisfies its equations,
  including an adversarially chosen one.
- **No key-validity constraint.** The relation has no analogue of FAEST's
  `k[0]·k[1] = 0`; adding one would exclude a quarter of the uniformly sampled
  secrets.

**Field and embedding.** `K = F_2[α]/(α^256 + α^10 + α^5 + α^2 + 1)`, the FAEST
polynomial-basis representation of `F_(2^256)`. Boolean values are `0, 1 ∈ K`.
Every sum below is a field sum, so addition and subtraction coincide.

**Witness layout.** Half-open bit intervals; `g = 1, ..., 11`.
`A_D^(r)` is the complete 1,600-bit state of permutation `D` after `r`
completed Keccak rounds, each round's iota step included. `D` is `C`
(commitment), `A` (authorization) or `N` (nullifier). States are committed
after 2, 4, ..., 22 rounds.

| Component | Registration | Vote |
| --- | --- | --- |
| Fresh pad | `[0, 256)` | `[0, 256)` |
| Credential secret `sk` | `[256, 640)` | `[256, 640)` |
| Commitment state `A_C^(2g)` | `[640 + 1600(g−1), 640 + 1600g)` | Same |
| Authorization state `A_A^(2g)` | `[18240 + 1600(g−1), 18240 + 1600g)` | None |
| Nullifier state `A_N^(2g)` | None | `[18240 + 1600(g−1), 18240 + 1600g)` |
| Selector `a_0, ..., a_31` | None | `[35840, 35872)` |
| Selector `b_0, ..., b_31` | None | `[35872, 35904)` |
| **Total `l`** | **35,840** | **35,904** |

**[D]** `l_reg = 256 + 384 + 2 × 11 × 1,600 = 35,840` and
`l_vote = 256 + 384 + 2 × 11 × 1,600 + 64 = 35,904`. There is no witness block
for the absorbed initial states, the odd-round states, the final states, the
selected commitment or the SHAKE padding.

- **The pad is prover randomness, not a second credential secret.** It
  appears in exactly its 256 Booleanity constraints and in no other
  application constraint. Its coordinates take part in the backend's
  commitment, correction and consistency machinery like any witness
  coordinate. No commitment, authorization value or nullifier depends on it.
  Extraction of the application witness projects it away.
- **Why the pad is first.** The CRT gates use labels with
  `L_e^1 = L_e^0 xor u[0, 256)`, and the proof publishes `d = w xor u`. A
  party that knows `w[0, 256)` therefore learns the label offset and, from the
  one reconstructed label, both labels; their two `H5` outputs then expose the
  mask information behind the gate correction **[R]** (FAEST v3 section 6,
  Figure 6.2, cited by the review; not read by us). With fresh pad bits in
  those positions the label mechanism no longer depends on the credential
  prefix. This supports the zero-knowledge target of gate 5; it does not
  establish it (section 7.1).

**Keccak conventions.** State coordinates are flattened as
`t = 64·(x + 5y) + z` with `0 ≤ x, y < 5` and `0 ≤ z < 64`. Bit `j` of a
serialized byte is its bit of value `2^j`, so state bytes and lanes are
little-endian under this convention (FIPS 202 sections 3.1, 3.3, 5, 6 and
Appendix B, cited by the review; not read by us). Each unpadded SHAKE message
is 132 bytes:

| Byte interval | Commitment | Authorization | Nullifier |
| --- | --- | --- | --- |
| `[0, 4)` | ASCII `PCR1` | ASCII `PAU1` | ASCII `PNF1` |
| `[4, 20)` | `P16` | `P16` | `P16` |
| `[20, 68)` | `sk` | the same `sk` | the same `sk` |
| `[68, 132)` | `B` | `D_reg` | `scope` |

The four bytes `1f 00 00 80` are appended to give the 136-byte rate block, and
64 zero capacity bytes follow to form `A_D^(0)`. Bit `j` of `sk`, which is
witness coordinate `256 + j`, occupies initial-state bit `160 + j`. After the
permutation the commitment is state bits `[0, 1024)`, and the authorization
value and the nullifier are state bits `[0, 512)` of their permutations,
packed with the same convention.

**Constraint polynomials.** XOR is field addition and AND is multiplication.

```text
R_r = iota_r ∘ chi ∘ pi ∘ rho ∘ theta          // FIPS 202 round r, 0 <= r <= 23
chi(A)[x, y, z] = A[x, y, z] + (1 + A[x+1, y, z]) * A[x+2, y, z]     // x mod 5
G_g = R_(2g-1) ∘ R_(2g-2)                      // forward two-round group, 1 <= g <= 12
O_D = G_12(A_D^(22))                           // last two rounds, as expressions

(B)   w_i * (w_i + 1) = 0                                  every witness coordinate
(T)   A_D^(2g)[t] + G_g(A_D^(2g-2))[t] = 0                 1 <= g <= 11, 0 <= t < 1600
(RC)  O_C[t] + C[t] = 0                                    0 <= t < 1024   registration
(RA)  O_A[t] + auth[t] = 0                                 0 <= t < 512    registration
(SP)  a_j * (sum_{k<j} a_k) = 0,  b_j * (sum_{k<j} b_k) = 0      0 <= j < 32
(SS)  1 + sum_j a_j = 0,  1 + sum_j b_j = 0
(SR)  1 + sum_{i<S} p_i = 0,   p_i = a_floor(i/32) * b_(i mod 32)
(VC)  O_C[t] + sum_{i<S} p_i * C_i[t] = 0                  0 <= t < 1024   vote
(VN)  O_N[t] + nf[t] = 0                                   0 <= t < 512    vote
```

- Every coordinate of `G_g` has polynomial degree at most four. The other
  Keccak mappings are affine or linear. No inverse-round computation is used.
- The multiplexer in (VC) has degree two, because each `C_i[t]` is a public
  scalar; its equality with the computed output has degree at most four.
- The maximum native relation degree is four.
- **The prefix form is one-hot in characteristic two.** Boolean entries plus
  "sum equals one" alone enforce odd parity, not one-hotness: three active
  entries pass, and a multiplexer would then select the XOR of three
  registered commitments, which is not a registered entry **[D]**. In the
  prefix form the second active entry of a vector sees a prefix sum of exactly
  one, so its constraint fails; no second active entry can exist **[D]**. The
  form needs no extra prefix witnesses.
- **No selection beyond `S`.** The sum over `i < S` in (SR) equals one only if
  the selected pair indexes a position below `S`. Every unused selector
  position is excluded.
- **No selected-commitment witness.** The commitment-output polynomials are
  equated directly to the degree-two selector expression.

**Ordered constraint stream.** Within each transition block the order is by
`g`, then by state coordinate `t`. Outputs are ordered by `t`, selector
prefixes by `j`. Booleanity is emitted once, in increasing witness index,
selector Booleanity included; no second selector-Booleanity block exists. The
two identically zero prefix constraints at `j = 0` are retained, because
removing them would change every later ZKHash position. Reordering the stream
changes ZKHash and therefore the protocol.

| Registration block | Constraint indices |
| --- | --- |
| Booleanity (B) | `[0, 35840)` |
| Commitment transitions (T) | `[35840, 53440)` |
| Commitment output (RC) | `[53440, 54464)` |
| Authorization transitions (T) | `[54464, 72064)` |
| Authorization output (RA) | `[72064, 72576)` |
| **Total `N_c`** | **72,576** |

| Vote block | Constraint indices |
| --- | --- |
| Booleanity (B) | `[0, 35904)` |
| `a`-prefix constraints (SP) | `[35904, 35936)` |
| `a`-sum (SS) | `35936` |
| `b`-prefix constraints (SP) | `[35937, 35969)` |
| `b`-sum (SS) | `35969` |
| Range constraint (SR) | `35970` |
| Commitment transitions (T) | `[35971, 53571)` |
| Commitment output (VC) | `[53571, 54595)` |
| Nullifier transitions (T) | `[54595, 72195)` |
| Nullifier output (VN) | `[72195, 72707)` |
| **Total `N_c`** | **72,707** |

Count ledger **[R][D]**. The degrees are assigned bounds, not claims that
every specialised coordinate polynomial has exactly that degree.

| Constraint kind | Assigned degree bound | Registration | Vote |
| --- | ---: | ---: | ---: |
| Witness Booleanity | 2 | 35,840 | 35,904 |
| Prefix constraints | 2 | 0 | 64 |
| Selector sums | 1 | 0 | 2 |
| Range constraint | 2 | 0 | 1 |
| Commitment transitions | 4 | 17,600 | 17,600 |
| Commitment output | 4 | 1,024 | 1,024 |
| Authorization transitions | 4 | 17,600 | 0 |
| Authorization output | 4 | 512 | 0 |
| Nullifier transitions | 4 | 0 | 17,600 |
| Nullifier output | 4 | 0 | 512 |
| **Relation constraints, excluding Booleanity** | | **36,736** | **36,803** |
| **Total `N_c`** | | **72,576** | **72,707** |

**Homogenisation to degree seven.** For a constraint polynomial `f` of
assigned degree `e` and the formal witness commitments
`rho_i(X) = V_i + w_i·X`:

```text
f_hat(X) = X^(7-e) * Hom_e(f)(rho(X), X) = X^7 * f(rho(X) / X)
```

The expression is a polynomial because `deg f ≤ e ≤ 7`, and its coefficient
of `X^7` is exactly `f(w)`. Operationally, terms are aligned in degree before
they are added (the degree-two multiplexer is aligned to degree four before it
is added to the degree-four Keccak expression), and the result is lifted to
seven. Every constraint handed to ZKHash has nominal degree seven. The backend
keeps `d_zk = 7`; the native degree of four does not replace seven in the
final root-count bound, because the checked polynomial has degree seven.

**Encoding equivalence.** For every publicly valid instance, the ordered
constraint system vanishes on an extended witness in `K^l` if and only if that
witness consists of Boolean coordinates that encode a valid relation witness
with its specified intermediate states. The statement is deterministic and
needs no collision-resistance, random-oracle, PRF or secret-entropy
assumption. Its proof is in the arguments file and awaits independent review
(section 7.1).

**Transcript binding.** `R` below is the role, `REG` or `VOTE`. Every ballot
backend hash call carries a role prefix.

```text
NS_REG  = SHA3-512(Frame("PARL/NS/v1"; D, ASCII("REG")))
NS_VOTE = SHA3-512(Frame("PARL/NS/v1"; D, ASCII("VOTE")))

PREFIX_R = ASCII("PARL/FAEST/v1") || NS_R     // exactly 77 bytes

F_REG = Frame("PARL/MU/REG/v1";
    Enc(body_context), Enc(network_id), Enc(authority), Enc(assignment_id),
    Enc(governance_attempt_id), Enc(election_attempt_id), Enc(body_role),
    B, C, auth)

F_VOTE = Frame("PARL/MU/VOTE/v1";
    B, scope, R, u16_le(S), concat(L), nf, u8(vote), policy_hash)

mu_R = SHAKE256(PREFIX_R || F_R || hex("08"), 64 bytes)
```

- `PREFIX_R` is 13 bytes of ASCII followed by the 64 bytes of `NS_R`
  **[D]**. There is no second `NS_R` between `PREFIX_R` and `F_R`.
- In `F_VOTE`, `R` is the list digest of section 6.2, not the role.
- The descriptor, and with it the construction identifier `P16`, the
  parameter row, the CRT tables, the relation dimensions and `SUITE`, is
  bound through `D` in `NS_R`. The role is bound through `NS_R`. The complete
  public statement is bound through `F_R`: for registration every field of
  `m_reg` other than `P16`, `auth` included, with the body context; for
  voting the canonical list bytes `concat(L)`, although their digest `R` is
  also a field, with `B` and every field of `m` other than `P16`. Every field
  of the public statement that verification reads therefore enters `mu_R`
  through `F_R` or through `PREFIX_R` **[D]** (read from the definitions; the
  review does not state it).
- In FAEST the statement and the message enter the challenge chain only
  through `mu` **[P]** (FAEST v3 Figure 8.2).

Every remaining ballot hash call is SHAKE256 over `PREFIX_R`, then the body
below, then the single suffix byte shown:

| Call | Body between prefix and suffix | Suffix | Output |
| --- | --- | ---: | ---: |
| `H4` | `iv_pre[16] \|\| mu[64]` | `04` | 16 bytes |
| `H0` | `iv[16]` | `00` | 96 bytes |
| Inner `H1`, vector `i` | Its leaf commitments in increasing leaf order | `01` | 64 bytes |
| Outer `H1` | The vector digests in increasing vector order | `01` | 64 bytes |
| Challenge 1 | `mu \|\| com \|\| c_1 \|\| … \|\| c_(tau−1) \|\| c_mult \|\| iv_pre` | `09` | 264 bytes |
| Challenge 2 | `chall_1 \|\| ToBits(u_tilde[4]) \|\| ToBits(V_tilde[4]) \|\| d` | `0a` | 104 bytes |
| Challenge 3 | `chall_2 \|\| ToBits(a_0, …, a_6) \|\| u32_le(ctr)` | `0b` | 32 bytes |
| `H5`, gate `e` | `iv \|\| u32_le(e) \|\| label[32]` | `05` | Low 10 bits of the first two output bytes |

- `com` is the 64-byte aggregate BAVC commitment. Arrays use increasing
  indices. `iv = H4(iv_pre || mu)`, so the v3 challenge chain is preserved
  inside the prefix.
- For challenge 2, verification reconstructs `V_tilde = Q_tilde + Δ·u_tilde`.
- There is no additional `H1` consistency digest. The review states that
  these placements follow the official v3.0.2 transcript implementation
  (`faest_impl.c` at tag `v3.0.2` of `faest-sign/faest-ref`) **[R]**; this
  record did not read that file.
- For `H5`, two bytes are squeezed, interpreted little-endian and masked with
  `0x03ff`.
- Ballot proving makes no `H3` call.
- Proof randomness is the fresh proving tape of section 6.7. Deterministic
  testing means deterministic given an explicit tape.

**Why a literal prefix [R].** Dependence on `mu` is not literal namespace
separation. In the unchanged backend `H0` receives only the 128-bit IV and
`H1` receives commitment material without a namespace, so different roles can
reach identical oracle inputs; `H5` includes the IV and inherits the same
limitation. The review cites `crates/iroha_zkp_vole/src/hash.rs` and
`crates/iroha_zkp_vole/src/bavc.rs` for these facts. Its dependency audit of
ordinary FAEST:

| Component | Dependency in ordinary FAEST |
| --- | --- |
| `H4` | Directly reads `mu` |
| `H0` | Reads the IV derived from `mu` |
| `H1` | Reads descendants of IV-dependent expansion and leaf commitments |
| Challenge 1 | Directly reads `mu` |
| Challenges 2 and 3 | Read the preceding challenge chain |
| `H5` | Directly reads the derived IV |
| PRG | Uses the derived IV with the official tweaks |

All of them depend causally on `mu`. That is insufficient for the
disjoint-domain statement adopted here, which is why every call carries the
prefix.

**The PRG is unchanged [R].** The AES PRG keeps the derived `iv`, the existing
counter-word arithmetic and the official tweaks. With `N` total leaves and
vector index `i`:

```text
tree-node tweak:       node heap index
leaf-expansion tweak:  N - 1 + i
high-mask tweak:       2^31 - 1
small-VOLE tweak:      2^31 + i
```

The PRG is not converted into an independently namespaced random oracle. Its
IV and cross-instance security remain proof obligations.

**Reference mode [R].** The prefix adds a namespace parameter to the ballot
hash invocations. The primitive algorithms, the suffixes, the field
representation, the PRG, the CRT tables and the leaf-commitment formula are
retained. An empty prefix reproduces the original hash inputs in reference
mode. Genuine signature reference mode must also retain the official OWF and
the `H3` derivation. Empty-prefix mode is not an accepted ballot mode.

Domain separation is necessary; it is not itself a joint-security proof
**[R]**. The algebraic equations alone do not establish the transcript
binding **[R]**.

A point from this evaluation's own primary reading: FAEST's QROM proof
restricts the key space (`k[0]·k[1] = 0`, enforced in key generation and
inside the relation) so that a random public key has no preimage with
probability at least 1/4 **[P]** (FAEST v3 section 10.7, Lemma 10.50). The
construction has no AES key and no equivalent restriction, so an argument that
reuses the lossy-key step needs another source of lossiness **[D]**. The
review finds that the missing restriction leaves no gap in the false-instance
soundness argument, and that for registration a source exists in principle:
for every fixed `B`, even for concrete SHAKE, the image of the commitment
function has at most `2^384` elements, so a uniform 1,024-bit string lies in
it with probability at most `2^-640`, by counting alone. The computational
transition that makes this counting useful is not proved, and no replacement
exists for voting **[R]** (section 7.1, gates 2 and 8).

### 6.4 Public-list verification contract

The proof hashes no Merkle path. `R` is the flat digest of section 6.2. There
is no membership tree, leaf hashing, internal-node hashing, padding or path
witness **[R]**.

- **At seal.** Core constructs and persists a canonical
  `SealedCredentialListV1` containing at least `profile_id`,
  `body_context_digest`, `S` and `commitments[S]`. The seal's finalized block
  data carries these bytes durably, not a pointer to a mutable service. The
  object is bound through `R` into the roster root, the body identity and the
  sealed state **[R]**.
- **Every verifier.** Either decode the list, check its length, ordering and
  uniqueness, recompute `R` and match the authenticated seal; or use an
  immutable verification context constructed by those checks and authenticated
  to that same seal. An unvalidated caller-supplied list is never sufficient.
  Restore validation performs the same checks **[R]**.
- **Closure evidence** references the seal and list commitment. It does not
  duplicate the list in every ballot **[R]**.
- **Registration mapping.** The separate binding over the sealed
  `(assignment_id, C)` pairs is a precisely encoded, domain-separated 512-bit
  digest. It authenticates the assignment mapping; `R` authenticates the
  anonymous membership list **[R]**.
- **Independent full verification** needs the authenticated seal and its list
  bytes, in addition to the complete ballot-bearing block interval. It keeps
  its existing trust boundary on registration eligibility unless the verifier
  also replays registration and sortition history **[R]**.
- **Authenticated summary** verifies no ballot proof and is unaffected
  **[C]**.
- **Owner decision preserved.** "Outcomes are provable from block data ...
  without any secret" (ballot design section 1) holds: the list is public data
  in finalized block data **[D]**.
- **Cost.** 128 bytes per credential: 384 B at `S = 3`, 64,000 B at
  `S = 500` and 128,000 B at `S = 1,000`, before framing **[R][D]**. Public-list
  work is linear in `S` per ballot. Root-only proof verification is
  deliberately not provided **[R]**. No additional trusted party is needed.

The ballot design states this contract in sections 3.1, 3.3, 3.5, 3.8, 3.9 and
12.2 **[C]**.

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
- The one-hot constraint is vacuous **[D]** (algebra on `quicksilver.c`). The
  last entry of each selector vector is derived by parity, and the "single
  active bit" constraint is identically zero in characteristic two. That
  design tolerates it, because it gates a complete per-member constraint set
  with the selector instead of multiplexing public values, so extra active
  entries only force more branches to hold. A multiplexer over public values,
  as in section 6.3, does not tolerate it.
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

### 6.6 Backend row, leaf commitments and CRT tables

- **Row.** The fast row `(lambda, tau, w_grind, T_open, d_zk) =
  (256, 33, 8, 229, 7)` is the sole integration candidate. The small row
  `(256, 22, 6, 225, 7)` is a measurement comparator only (section 8.6).
  Neither is selected or qualified.
- **Leaf commitments are FAEST v3's, unchanged.** The official leaf expansion,
  field representation, universal-hash construction, tweaks, tree layout and
  commitment lengths are preserved. Direct hash commitments to the leaf seeds
  were considered as a way to make efficient seed recovery more plausible, and
  were not adopted: they are not an established solution to the extraction
  problem of gate 1 **[R]**.
- **CRT tables are the official ones**, with the official gate order:
  `n_mult = 704` on the fast row and 696 on the small row. A table generator
  that yields a different gate count cannot replace them under the same
  descriptor and size ledger.
- **Fast-row geometry.** 17 eight-bit and 16 seven-bit small-VOLE challenges:
  248 challenge bits, `17 × 256 + 16 × 128 = 6,400` leaves, 12,799 GGM nodes
  and ten masks **[R][D]**. The elementary parameter conditions `tau > 1`,
  `3 × 128 > 2` and `(tau + 1) × 2^8 = 8,704 < 2^31` hold **[R][D]**; they do
  not certify an implementation of the maps.
- **Challenge lengths** stay `8·lambda + 64 = 2,112` and
  `3·lambda + 64 = 832` bits, with the existing 64-bit short evaluation
  points. Widening those points is unnecessary at these dimensions and would
  be a distinct protocol variant (section 8.2).
- **Conformance.** The official component vectors and plain-FAEST signature
  vectors remain conformance targets for the unchanged reference-mode backend,
  which is the backend with an empty prefix, the official OWF and the `H3`
  derivation (section 6.3). The ballot prefixes, the padded witnesses and the
  custom relations need their own vectors. Passing the official signature
  vectors does not validate their composition.

**Naked proof layout [R].** The proof contains these fields, in this order,
and no header. Byte counts, recomputed here **[D]** from `l`, `tau`, `n_mult`
and `T_open`:

| Field | Fast `pi_reg` | Fast `pi_vote` | Small `pi_reg` | Small `pi_vote` |
| --- | ---: | ---: | ---: | ---: |
| `c_1, …, c_(tau−1)` | 143,360 | 143,616 | 94,080 | 94,248 |
| `c_mult` | 880 | 880 | 870 | 870 |
| `u_tilde` | 128 | 128 | 128 | 128 |
| `d` | 4,480 | 4,488 | 4,480 | 4,488 |
| `a_1, …, a_6` | 192 | 192 | 192 | 192 |
| Opening | 10,496 | 10,496 | 9,312 | 9,312 |
| `chall_3` | 32 | 32 | 32 | 32 |
| `iv_pre` | 16 | 16 | 16 | 16 |
| `u32_le(ctr)` | 4 | 4 | 4 | 4 |
| **Total bytes** | **159,588** | **159,852** | **109,114** | **109,290** |

- `a_0` is hashed (challenge 3, section 6.3) and is not serialised.
- `c_mult` is mask-row-major, with increasing gate index within each row.
- Bits are low-bit first within bytes. Field elements use the existing
  polynomial-basis `ToBits`.
- **Opening**, in order: the `tau` hidden-leaf commitments, 96 bytes each, in
  increasing vector index; then the revealed sibling seeds, 32 bytes each,
  found by scanning parent heap indices from `N − 2` down to zero and, where
  exactly one child belongs to the union of the hidden paths, emitting the
  other child's seed; then zero bytes that fill the seed area to exactly
  `T_open · 32` bytes.
- The verifier derives the seed count from `chall_3`. It rejects an excessive
  count and any nonzero unused padding.
- Every proof length other than the fixed length for the externally selected
  row and relation is rejected. The verifier does not autodetect a row and
  accepts no trailing bytes.

**[D]** The opening is `tau · 96 + T_open · 32` bytes:
`33 × 96 + 229 × 32 = 10,496` on the fast row and
`22 × 96 + 225 × 32 = 9,312` on the small row. The corrections are
`(tau − 1) · l/8` bytes, `c_mult` is `10 · n_mult / 8`, and `d` is `l/8`.

**Test-only statement codec [R].** The plain statement structs contain the
fields of `F_REG` and of `F_VOTE` (section 6.3). For tests only:

```text
TEST_STATEMENT_REG =
    Frame("PARL/TEST/REG/v1"; D, fields of F_REG in their stated order)

TEST_STATEMENT_VOTE =
    Frame("PARL/TEST/VOTE/v1"; D, fields of F_VOTE in their stated order)

TEST_RECORD =
    u32_le(len(TEST_STATEMENT)) || TEST_STATEMENT ||
    u32_le(len(proof)) || proof
```

The test decoder checks the tag, the exact field count, the expected `D`, all
bounds and the absence of trailing bytes. This codec is not a production
schema and introduces none, and it puts no prefix inside the naked proof. The
production envelope is a later obligation (section 11.1).

### 6.7 Proving tape and retry rule

Each proof invocation obtains exactly 80 fresh bytes from the caller's
fallible cryptographic random-number generator:

```text
r      = tape[0..32]      // backend root seed
iv_pre = tape[32..48]
pad    = tape[48..80]     // witness positions [0, 256)
```

- **Model.** The 80 bytes are independent uniform coins, independent of the
  application witness, the public message and every earlier tape.
- **No fallback.** An entropy failure returns an error and produces no proof.
  There is no secret-derived, deterministic or zero-filled production
  fallback. Fixed tapes are permitted for reproducible tests only.
- **Uses of `r`.** `r` feeds the ordinary backend root expansion and the
  existing high-mask expansion
  `PRG(r, iv, 2^31 - 1; n_mask * w_grind bits)`. The second use is already
  part of the backend's VOLECommit (the review cites
  `crates/iroha_zkp_vole/src/vole.rs`); it is not an additional tape
  derivation.
- **Uses of the pad.** The raw pad is supplied only as witness bits
  `[0, 256)`. It then necessarily affects `d`, the pad Booleanity
  constraints, the masked response calculations and the downstream challenge
  hashes; "only as witness bits" does not exclude those derived effects.
- **What is hashed.** `iv_pre` is transmitted and is hashed directly in both
  `H4` and challenge 1 (section 6.3). There is no separate hash of the tape,
  of raw `r` or of the raw pad.
- **No `H3` call.** Ballot proving derives nothing from the secret and the
  message through `H3`. `iv = H4(iv_pre || mu)` is retained, inside the role
  prefix.
- **Erasure.** The prover erases its owned tape buffers, `r`, the pad and the
  transient secret witness, VOLE, tree and hash material on success, on error
  and on exhaustion. That includes temporary copies of the credential secret;
  it does not include the wallet's retained credential. The public `iv_pre`
  need not be erased from the returned proof; its copy inside the tape buffer
  is erased with the buffer.
- **Retry loop.** The commitment, the corrections, the first two challenges
  and the response coefficients are computed once. The prover then tries every
  counter in order from `0` through `0xffff_ffff` inclusive:

  ```text
  chall_3 = H2^3(chall_2 || ToBits(a~_0, ..., a~_6) || LE32(ctr), 256 bits)
  ```

  which as a ballot call is challenge 3 of section 6.3: SHAKE256 over
  `PREFIX_R`, that body and the suffix byte `0b`. An
  attempt is rejected unless its grinding suffix is zero and its canonical
  BAVC opening fits the row's threshold: eight grinding bits and
  `T_open = 229` on the fast row, six and 225 on the comparator. The first
  success is returned.
- **Exhaustion.** If no counter succeeds the prover returns
  `GrindingExhausted`. The counter never wraps. Any later invocation needs an
  entirely fresh 80-byte tape.
- **Verification** checks the supplied counter and opening once. It hashes
  the counter once, never repeats grinding, never loops a number of times
  given by the counter and does not establish that the counter is minimal.
- **A prover that accepts an adversarially fixed or disclosed pad is outside
  the zero-knowledge claim.** The auxiliary information of the gate 5 game may
  include the semantic witness; it does not include the proving tape.
- **What the arguments must analyse.** Exactly this fresh-randomness,
  incrementing-counter prover. A verifier-only false-statement analysis can
  use the unchanged acceptance predicate. The joint zero-knowledge and
  authorization proofs must reproduce the honest transcript and its stopping
  distribution (section 8.2).

## 7. Gate-by-gate status

Status classes: **(a)** an applicable theorem as is; **(b)** a short new
argument; **(c)** substantial new proof work; **(d)** an assumption about a
concrete primitive. No gate of either route has an unconditional (a).

### 7.1 Construction to develop

The arguments are written out in the
[arguments file](parliament_ballot_proof_arguments.md). Every statement in this
subsection about what is written or missing is the second-opinion review's
**[R]** unless marked. Status words: **complete** means a full written
argument under the standard of section 11.1; **conditional** means a written
reduction or design argument whose premises are other gates, unproved
assumptions or unfinished implementation; **incomplete** means that a
foundational step is missing. No gate is complete. Nothing in the table has
had independent review.

| Gate | Status | Written | Missing |
| --- | --- | --- | --- |
| 1 Authorization | Incomplete | The game: fresh-authorization knowledge extraction in the common oracle environment, with both honest proof types available and exact-input replay and rerandomization exempt. The algebraic step from an effective committed witness to the secret, the selected position and the correct nullifier (encoding equivalence, below) | The efficient extractor that recovers an effective committed witness, with bounds on its time, queries and disturbance of the adversary. The published soundness route may inspect a whole response graph or invert commitment generation without a polynomial-time guarantee: enough for a false statement, not an extractor. A preimage of the aggregate commitment hash can reveal leaf commitment values without the PRG seeds needed to rebuild the witness. The lossy-key step and adaptive reprogramming recover no witness. FAEST's QROM proof reduces to soundness and avoids extraction **[P]** (v3 section 10.7). Class (c) |
| 2 Unforgeability | Incomplete | The target-origin game: a win is a valid vote under an uncorrupted honest credential's nullifier whose exact public input that credential never authorized; a mixed-list ballot under another nullifier is not a forgery. An extraction-based reduction skeleton | Providing both honest proof types without the target secret, extracting from a fresh forgery, and the composition of the two (a joint extraction and simulation lemma). The primitive game with public-commitment leakage, other-scope outputs, many users and adaptive contexts. A false-instance route would have to eliminate every alternative list witness, for which computational collision resistance is not enough. FAEST's theorem is for one honestly generated key **[P]** (Theorem 10.53). Class (c) |
| 3 Nullifier uniqueness | Conditional | `Pr[Win_3] ≤ ε_K + ε_C + ε_2`, or with a single-output gate 2 game `ε_K + ε_C + 1000·ε_2,single`. The determinism of the nullifier for a credential and scope is unconditional | The premises: the joint adaptive extractor of gate 1 (`ε_K`), gate 2 (`ε_2`), adaptive-context collision resistance of the commitment (`ε_C`), and the validated-list contract with relation correctness and message binding. None of the three terms has a numerical value. If account registration is read as establishing honest credential origin, the gate 8 term `ε_8` is added |
| 4 Unlinkability, non-frameability | Conditional | `Δ_link ≤ 2·ε_Z + 2·ε_SP` by a hybrid sequence. `Pr[Frame_vote] ≤ ε_2` and `Pr[Frame_reg] ≤ ε_8`, where framing means fresh authorization, since published proofs can be copied | `ε_Z`: joint zero knowledge (gate 5) with a simulator that is total on syntactically valid inputs and programs only backend namespaces. `ε_SP`: secret-prefix pseudorandomness of the nullifier function given the public commitment and simulation access, a primitive assumption that ordinary collision, preimage or PRF security of SHAKE does not imply (section 8.7). Gates 2 and 8. Neither term is quantified. An alternative route that keeps every statement true needs a quantum hidden-point programming theorem, which is missing. Class (d) for concrete SHAKE |
| 5 Joint quantum zero knowledge and anonymity | Incomplete | The target (section 10.1): adaptive joint zero knowledge for arbitrary application witnesses and arbitrary auxiliary information about them, with the pad as fresh proof coins; and a separate left-or-right anonymity game. The game for that target, written by the review: one stateful simulator for the whole execution, adaptive proof requests on adversary-chosen application witnesses, no tape-selection or coin-disclosure interface (below). The carry-over of the candidate simulator's nine steps to that game, and the target stopping law of the retry loop in the ideal fresh-query experiment (below). The decomposition `Adv_anon ≤ 2·ε_JZK + ε_hidden-input + ε_accidental-equality` | The proof for the padded backend: the pad supports the unrestricted target and does not establish it. First, the padded CRT hidden-label simulation lemma: that the real correlated material and the simulator's ideal material, any `H5` programming included, are indistinguishable given arbitrary application-witness auxiliary information and all subsequent quantum oracle access. Then the programming-location bounds; the coupling of retries and exhaustion to the oracle state, including locations the adversary has already queried or queries later; the joint distribution of the sampled corrections, CRT corrections and `d` with a known application witness; the justification for programming challenges 1 and 2 despite complete application-witness knowledge; the mask distribution that the consistency-mask calculation requires; and the hidden-input term of the anonymity game, an adaptive multi-user quantum proof of its own. No argument for the decided target is complete. Class (c) |
| 6 Concrete security | Incomplete: not met | The re-derived universal-hash bounds and the interactive component sums at the final dimensions. Comparison arithmetic against the published single-key formula (section 8.5) | A complete deployment-wide ledger. No bound exists for gates 1, 2, 5 and 8, and the primitive terms have no justified values. Compliance with either part of the contract of section 8.8 is unestablished |
| 7 Bounded deterministic verification | Conditional | A design argument: verification as a total deterministic function of the canonical proof bytes and the authenticated public context, with finite work and allocation bounds and prescribed malformed-input behaviour. It needs no cryptographic assumption | The production envelope and Norito mappings, which are not written (the standalone descriptor, the proof layout and the length rules are frozen: sections 6.1 and 6.6); the parser and verifier, which are not implemented; a complete arena and work inventory (the arguments file section 6.7 holds the implementers' recalculation **[D]** of the fast-row work bounds for both relations and of the principal vote buffers, from formulas fitted to the review's figures and unconfirmed against an implementation; it has no registration buffer table and no small-row figures and is not a complete allocation certificate); conformance, parity and malformed-input evidence; measurements. The 250 ms limit is a separate measurement |
| 8 Registration authorization | Incomplete | The registration-origin game with per-handle logs (section 7.3). The unconditional counting bound `2^-640` on a uniform string lying in the commitment image. The event split of the opening-uniqueness route, written by the review in full: `Win_8 ⊆ FalseAccepted ∪ BadOpen ∪ FrameCollision ∪ FreshAuthCorrect`, its premise table and the conditional bound `ε_8 ≤ ε_snd,mix + δ_open + ε_CR,REG + ε_JZK + ε_pred` (section 7.3). An alternative extraction route | Every cryptographic premise of the split is unproved: adaptive target-opening uniqueness, which is existential almost-injectivity and cannot simply be replaced by a collision-finding assumption without extraction; adaptive registration soundness with both honest proof interfaces; quantum collision resistance of SHA3-512 on legal registration frames, a premise new relative to the review's part 3; joint simulation (gate 5); adaptive multi-user authorization prediction. The work and the oracle queries of every reduction are still to be charged. No term has a numerical value. No QROM simulation-extractability theorem covering VOLE-in-the-head was found in the sources read **[P]** (section 13). Class (c) |

**The gate 5 game for the decided target [R].** This is the review's
experiment; the full text is in the arguments file, section 5.2. The
descriptor, both semantic relations, the
public-validation rules and the oracle interfaces of section 6 are fixed.

1. One global bit `b` is chosen and the public quantum-accessible oracle
   environment is initialised. In the simulated world **one stateful
   simulator is initialised for the entire execution**, covering both roles
   and every credential.
2. The adversary receives arbitrary quantum auxiliary information about
   application witnesses and statements. It may contain complete secrets,
   membership indices and deterministic application traces. Initial advice is
   independent of the freshly sampled oracles and proving coins;
   oracle-dependent preprocessing counts against the query budget.
3. The adversary makes adaptive **classical** requests
   `Prove(role, x, w_app)`, with `w_app = sk` for registration and
   `w_app = (sk, i)` for voting. It may choose the witnesses, repeat
   statements, reuse witnesses and alternate roles.
4. In both worlds the same public validation is applied and
   `R_role(x; w_app)` is checked. An invalid request returns the same
   prescribed error without invoking the simulator. The adversary supplies
   the complete statement; the challenger checks it and does not silently
   repair its `auth`, nullifier or other fields.
5. For a valid request:
   - **real:** the challenger obtains an independent uniform 80-byte tape,
     constructs the padded extended witness and runs the exact prover,
     including the incrementing counter and the exhaustion outcome;
   - **simulated:** the challenger invokes `Sim(role, x)` and returns its
     proof or exhaustion outcome. The simulator receives neither the
     application witness, the selected index, the trace, the pad nor the
     adversary's private auxiliary state.
6. The simulator may program only the designated backend oracle domains. It
   cannot alter credential functions, public statements, the authoritative
   context or application authentication decisions.
7. The adversary may interleave requests with quantum oracle queries,
   verification, malicious registrations and other application operations.
   It may retain, disclose and use application witnesses at any time. There
   is **no tape-selection or secret-coins-disclosure interface**. The
   transmitted `iv_pre` is public and is expressly permitted.
8. After the final proof request the adversary keeps quantum oracle access
   until it outputs a bit, and

   ```text
   Adv_JZK = | Pr[A → 1 | b = 0] − Pr[A → 1 | b = 1] |
   ```

   Preprocessing, interleaved and subsequent queries are all counted. The
   recorded lifetime ceilings apply, repeated proof generation included.

- "Identical public-input rules" does not mean that the adaptive executions
  remain identical after different replies.
- The game imposes no hidden-honest-key requirement. The separate anonymity
  game retains its challenge-secret disclosure exclusions.
- Simulator totality on syntactically valid **false** statements remains an
  additional interface requirement for gate 4. The game invokes simulation
  only for valid witnessed statements.

The steps of the candidate simulator (arguments file section 6.5) carry over
as follows **[R]**:

| Existing step | Decision |
| --- | --- |
| 1: compute `mu`, sample root and `iv_pre`, construct BAVC | Retained, using the frozen namespaces and independent coins; no `H3` |
| 2: choose challenge and opening | Replaced: the isolated-success description gives way to the complete bounded retry distribution |
| 3: sample corrections, CRT corrections and `d` | Retained as candidate operations at the final lengths. Their joint distribution still needs proof |
| 4: reconstruct `Q`, mask keys | Retained |
| 5 and 7: program challenges 1 and 2 | Retained as candidate operations; programming must be justified despite complete application-witness knowledge |
| 6: consistency-mask calculation | The algebra is retained, once its required mask distribution is justified |
| 8: sample coefficients and reconstruct `a_0` | Retained, including the pad's Booleanity constraints |
| 9: program challenge 3 and serialise | Must account for every attempted counter, earlier failures, opening-limit rejection and exhaustion, not merely the successful query |

**Retry step [R].** Let `G` be the set of 256-bit challenges whose grinding
suffix is zero and whose canonical opening fits the row, and
`p = |G| / 2^256`. In the ideal fresh-query experiment the target stopping
law is

```text
Pr[C = c] = (1 − p)^c · p      (0 ≤ c < 2^32)
Pr[exhaustion] = (1 − p)^(2^32)
```

Conditioned on `C = c`, the preceding challenge values lie uniformly outside
`G` and the final value lies uniformly inside `G`. The simulator must realise
the corresponding oracle interactions at the exact counter inputs. This
distributional description does not establish that the required QROM
programming is valid when the adversary has already queried, or later
queries, those locations.

**Pad argument [R].**

```text
W = (P, W_app),   U = (U_P, U_app),   d = (P ⊕ U_P, W_app ⊕ U_app)
```

Knowing the application witness reveals `W_app`, its trace included, and
therefore reveals `U_app` from `d`. The argument must tolerate this. The CRT
label offset is `U_P`, and the first part of `d` masks it with the fresh
proof coins `P`. In an ideal uniform-mask hybrid one can sample `d_P` and
define `P = d_P ⊕ U_P`, which preserves that elementary distribution. It does
**not** prove conditional hiding after the complete proof is exposed.
Accordingly:

- the PRG idealisation framework, the commitment plumbing and the four
  consistency plus six QuickSilver mask degrees of freedom remain the
  intended proof structure;
- replacing `d` by uniform must preserve the joint distribution with known
  `W_app`, exposed `U_app`, the corrections, the responses and the oracle
  state;
- the hidden-label transition must use the pad argument and cannot rely on
  secrecy or entropy of the application witness;
- every continuation guarantee must survive later application-witness
  disclosure and quantum queries.

**The first missing bridge is the padded CRT hidden-label simulation lemma
[R]:** that the real correlated material and the simulator's ideal material,
including any `H5` programming, are indistinguishable given arbitrary
application-witness auxiliary information and all subsequent quantum oracle
access. Pad independence at sampling and witness-independent proof-byte
marginals do not establish it. Programming-location bounds and the coupling
of retries and exhaustion remain further obligations. The lemma is not
written.

Three supporting arguments are written in full and await independent review.
They are not gates:

| Argument | Statement | Limits |
| --- | --- | --- |
| Encoding equivalence | The ordered constraint system vanishes exactly on Boolean encodings of valid witnesses (section 6.3). It replaces the AES-specific relation step of the FAEST argument and needs no key-validity restriction | The review's proof text is for the commitment and nullifier blocks and the selector. It states that extending the witness by Boolean pad coordinates and projecting them away preserves the implication; the authorization block repeats the commitment block's induction. The constraint implementation does not exist |
| Universal-hash bounds | `ε_v ≤ 2^(−4·lambda)·(1 + (l+5)^5 / 2^64)` and `ε_zk ≤ 2^(−lambda)·(1 + (N_c − 1)^2 / 2^64)`, for an input fixed before the seed is sampled (section 8.2) | New derivations by root counting. They extend the proofs of FAEST Lemmas 4.6 and 4.7 and are not applications of those lemmas, whose length hypotheses fail |
| Response-graph soundness for false instances | For a publicly valid false instance and an unbounded prover in the interactive protocol, the three core bad events are bounded by `ε_v·binom(2^248, 3)`, `ε_zk` and `7·2^-256`, so the core round error stays at most `7·2^-256` (section 8.2) | Static false instances only. The extraction map may need exhaustive access to the response graph: it is not an efficient knowledge extractor. It is not the Fiat–Shamir proof-of-knowledge game |

Imported FAEST results are used only as follows **[R]**: Lemmas 4.6 and 4.7
are re-derived; Lemma 7.3 is the polynomial-root step; Lemma 10.26 and
Corollary 10.27 give the affine consistency argument with the revised hash
error; Lemma 10.40 is re-established, not applied; Theorem 10.30 and
Corollary 10.41 are whole-scheme theorems that do not transfer; Theorem 10.46
and Lemmas 10.48 and 10.49 give a conditional route to static false-statement
soundness and establish neither adaptive knowledge nor the multi-user games;
Lemma 10.50 needs a new instance-distribution argument; Lemmas 10.24, 10.51
and 10.52 are hiding and unpredictability components whose lengths, tables and
randomness must be checked; Theorem 10.53 and Corollary 10.54 are single-key
chosen-message results.

The published FAEST work supplies important ingredients, not these complete
custom-scheme arguments **[R]**. No gate is known to be impossible in
principle; the review rates the missing proofs for gates 1, 2, 5 and 8 as hard
but plausible research and cannot promise that they can be established
**[R]**. Its order for the remaining proof work **[R]**, after the freezing
of the protocol and games, which section 6 completes by decision for the
standalone construction (the production encodings and envelopes are later
obligations, section 11.1):

1. complete the algebraic foundation: the exact grouped-Keccak compiler, the
   selector and homogenisation implication, and reviewed versions of the
   universal-hash bounds with their propagation;
2. resolve whether efficient extraction is feasible: a polynomial-time
   reconstruction theorem for the underlying interactive VOLE protocol, before
   a full QROM knowledge reduction;
3. prove joint simulation for both roles, with shared secrets, complete future
   quantum oracle access, adaptive public inputs and the stated exclusions;
   the padded CRT hidden-label simulation lemma is the first missing
   zero-knowledge obligation;
4. analyse the actual retry algorithm: the stopping-time and oracle-state
   hybrids, with the complete retry and future-oracle-state analysis;
5. prove the adaptive authorization reductions, registration origin first,
   then the mixed-list, target-nullifier voting case;
6. build the deployment-wide ledger with every primitive term, extractor
   overhead, simulation loss, target selection, transcript count and
   statistical event, and revisit the parameter row if the bound stays
   inadequate.

### 7.2 Two unsafe shortcuts

Both appeared in the research pass and are rejected **[R]**; primary reading
reaches the same conclusion on the first **[D]**.

- **Soundness plus injectivity does not give the `k`-credential bound.** It
  bounds the whole list to at most `S` credential handles. It does not prevent
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
  message. Duplicate rejection then handles later reuse. This is the
  requirement gate 8 now states (section 7.3). It is not proved by the
  duplicate check, and it is not proved for this construction.

### 7.3 The gate 8 game

Gate 8 requires adaptive cross-relation registration unforgeability in place
of simulation-extractability **[R]**; ballot design sections 3.2 and 5 state
it **[C]**. The game must **[R]**:

1. publish honest commitments before registration, so front-running is
   covered;
2. permit adaptive registration-proof and ballot-proof queries, malicious
   credentials, corruption and quantum oracle access;
3. record the exact messages authorized by honest provers;
4. declare a win on a valid fresh registration message using an uncorrupted
   honest credential, including a commitment `Commit(B*, sk_j)`
   recontextualized from that credential;
5. exclude exact-message replay and rerandomization from the winning
   condition;
6. keep the target secret uncorrupted through the forgery.

In the review's formulation the adversary outputs `(j, x_reg*, pi_reg*)` and
wins exactly when the proof verifies, `j` stays uncorrupted through the
output, `C* = Commit(B*, sk_j)` and `(j, x_reg*)` is not in the log of honest
registration proofs. The challenger knows `sk_j`, so the third condition is
efficiently decidable even for a new body `B*` **[R]**. The registration
message is the complete `m_reg`, `auth` included.

**Logs [R].** For each honest handle `j` the challenger maintains
`RegLog[j]`, the complete statements authorized by permitted
registration-proof requests, and `AuthLog[j]`, their authorization digests.
An authorization is recorded **before `auth` is exposed**, also when the
subsequent proof generation fails: an aborted request must not expose an
unlogged authorization value. Exact logging is a necessary clarification of
the game.

**The event split [R].** The review takes the opening-uniqueness route.
Write

```text
Y(x) = Frame("PARL/REG-AUTH/v1"; ...)      // every registration field except auth
d(x) = SHA3-512(Y(x))                      // the D_reg of section 6.2
```

and let `s_j` be the secret of handle `j`, `Com_B(s)` the commitment function
and `Auth_d(s)` the authorization function of section 6.2. For a winning
output `(j, x*, pi*)`:

1. If `x*` is false, it belongs to the adaptive false-statement soundness
   event.
2. Otherwise a witness `s'` satisfies its commitment and authorization
   equations.
3. Outside the target-opening ambiguity event
   `∃ s' ≠ s_j : Com_B*(s') = Com_B*(s_j)`, that witness must be `s_j`, so
   `auth* = Auth_d*(s_j)`.
4. Suppose `d* ∈ AuthLog[j]`, associated with a logged `x_0`.
   - If `Y(x*) ≠ Y(x_0)`, these are two distinct SHA3-512 preimages with the
     same digest.
   - If the frames agree, injective framing gives equality of every statement
     field except possibly `auth`.
   - If `auth` agrees too, this is exact-statement replay and cannot win.
   - If `auth` differs, honest-log correctness and opening uniqueness make
     `x*` false: the unique opening forces the logged authorization value.
5. So a true fresh win outside these bad events yields a correct
   authorization value on a fresh **pair `(j, d*)`**. The digest need not be
   globally fresh across other handles.

The resulting inclusion in the real game:

```text
Win_8 ⊆ FalseAccepted ∪ BadOpen ∪ FrameCollision ∪ FreshAuthCorrect
```

Its complete premises **[R]**:

| Premise | Originating experiment or rule |
| --- | --- |
| Public validation, encoding equivalence, injective framing, the fixed descriptor, honest log correctness and the disclosure restrictions | The deterministic construction and the rules of the gate 8 game |
| Adaptive target-opening uniqueness | The same common environment; the adversary selects an uncorrupted `j` and `B*`; the bad event is the existence of another opening of the target commitment |
| Adaptive registration soundness with both honest proof interfaces | A win on an accepted registration statement outside the language |
| Quantum collision resistance of SHA3-512 on legal registration frames | Output of distinct `Y`, `Y'` with equal SHA3-512 digests |
| Joint simulation | The arbitrary-application-witness game of section 7.1 |
| Adaptive multi-user authorization prediction | Public commitments, authorization values, nullifiers, permitted corruptions and quantum queries remain available; proof replies use the joint simulator; the output is an uncorrupted `j`, `d` and `a` with `d ∉ AuthLog[j]` and `a = Auth_d(s_j)` |

The conditional bound, with the work and the oracle queries of every
reduction charged:

```text
ε_8 ≤ ε_snd,mix + δ_open + ε_CR,REG + ε_JZK + ε_pred
```

- The uniqueness premise is **existential almost-injectivity**, not ordinary
  computational collision resistance. Without extraction, a collision-finding
  assumption cannot simply replace it.
- Joint simulation is applied to the efficiently checkable
  `FreshAuthCorrect` prediction event, whose challenger knows the honest
  keys. It is not applied to deciding whether an arbitrary statement is false
  or has another opening.
- **The registration-frame SHA3-512 collision premise is new** relative to
  the review's part 3. The other cryptographic premises were already named
  and remain unproved.
- This route does not require a uniform-commitment replacement or the
  programming of credential functions.

The bound is conditional on premises that are not proved; no term has a
value, and gate 8 is not established (section 7.1). The split does not remove
gate 1's knowledge obligation, and it does not carry over to voting
(section 6.2).

Duplicate rejection prevents reuse after registration; the game protects the
period before the honest registration lands. The amendment does not discharge
gate 1's knowledge requirement. An anti-copy theorem alone is not a proof of
knowledge or the `k`-credential nullifier bound **[R]**.

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
| 8 | Simulation-extractability, a sufficient route, in the classical ROM only (Chiesa–Fenzi **[U]**, preconditions not read); credential-origin unforgeability in the QROM: (c) | No published theorem found |

The STARK route has extraction available in the QROM at abstract level, which
the VOLE-in-the-head route lacks. It has more unproven zero-knowledge theory
and a size near or above the target (250–600 KiB **[E]**, unmeasured).
**[R]** No demonstrated impossibility of meeting 256 KiB has been established.
A narrow standard-hash STARK remains the fallback research candidate **[R]**
(section 11.5).

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

**[R][D]** Three quadratic coefficients must be kept apart on the fast row,
where `tau + d_zk = 40`. Each multiplies `Q^2 / 2^256`; the boundaries are
recomputed here as `log2 Q = (256 + log2 p − log2 c) / 2`:

| Bound | Coefficient `c` | `log2 Q` where the term reaches 2^-64 | `log2 Q` where it reaches 1/2 | Value at `Q = 2^128` |
| --- | ---: | ---: | ---: | ---: |
| Static published shape, `10·(tau + d_zk)`, without the lossy-key factor | 400 | 91.678 | 123.178 | 400 |
| Static shape with the worst-case factor four of Lemma 10.50 | 1,600 | 90.678 | 122.178 | 1,600 |
| Full chosen-message comparison, `8·10·(tau + d_zk)` (Corollary 10.54 with its outer factor two and the factor four) | 3,200 | 90.178 | 121.678 | 3,200 |

The published bound is therefore vacuous at 2^128 queries in every form. This
is a limitation of the bound, not evidence of an attack, and none of the three
is a bound proved for the ballot construction **[R]**.

**Query offset of the static comparison [R].** The static comparison for the
compact proof on the fast row uses `Q = Q~ + 125`, with the coefficients 340
and 400 kept, where `340 = 10·(tau + 1)` and `400 = 10·(tau + d_zk)`
**[D]**. Lemma 10.49 states

```text
Q = Q~ + 2·tau + d_zk + 12 = Q~ + 85
```

for its explicit-leaf intermediate experiment, and 85 applies only there. Its
accounting is `40 + 38 + 7`: `tau + 7` challenge-recomputation queries,
`tau + 5` of local-witness overhead and the statement's retained `d_zk`
slack. The last two are not additional protocol hash calls. The conversion
from the compact proof to explicit leaves adds another `tau + 7 = 40`:

| Oracle | Additional calls |
| --- | ---: |
| `H0` | 1 |
| `H1` | `tau + 1 = 34` |
| `H2mu`, `H2^1`, `H2^2`, `H2^3` | 1 each |
| `H4` | 1 |

There are also `n_mult` calls to `H5`, outside this particular sum. Hence

```text
Q_compact    = Q~ + 125
Q_comparison = q + 37·T + 125
```

which reconciles Lemmas 10.49 and 10.50 with Corollary 10.54 (FAEST v3
specification, PDF page 130, cited by the review). **[D]** The arithmetic
agrees: `2·33 + 7 + 12 = 85`, `1 + 34 + 4 + 1 = 40`, `85 + 40 = 125`, and the
constant of the offset in the formula above is
`3·tau + d_zk + 19 = 99 + 7 + 19 = 125`, with `tau + 4 = 37`. The comparison
of section 8.5 uses this `Q_comparison`. It remains a conditional comparison,
not an established adaptive bound for the ballot.

**[D]** In the chosen-message bound the reprogramming term
`2·Q_sig·3·sqrt(3·sqrt(Q_1)·2^-lambda)` is about
`2^3.4 · Q_sig · Q_1^(1/4) · 2^(-lambda/2)`. For `Q_sig = 2^20` and
`Q_1 = 2^64` it is about 2^-24.6 at `lambda` = 128 and 2^-88.6 at
`lambda` = 256. A further term is `Q_sig` times the square root of the
AES-CTR PRG advantage. **[R][D]** With the whole transcript ceiling of
section 8.8 as the signing budget, `6·sqrt(3)·2^44·Q_1^(1/4)·2^-128` is about
2^-64.6 at `Q_1 = 2^64` and 2^-48.6 at `Q_1 = 2^128`; it reaches 2^-64 near
`Q_1 = 2^66.5`. These are component substitutions into a single-key formula,
not a forgery or privacy bound for the ballot. The specification's own summary calls the proofs "almost tight, except
for a multiplicative loss in the number of signing queries" **[P]** (section
11.1).

### 8.2 What it does not cover

- **Adversarially registered entries.** The theorems are single-user games with
  the key produced by the challenger; the proof replaces that honest key by a
  random one **[P]** (v3 section 10.7). Nothing covers adversarially chosen or
  multiple public keys. A reduction that guesses one target among the honest
  registrations may lose a factor up to 2^34, which a multi-user proof must
  avoid or charge **[R]**.
- **The list relation.** The lossy step makes FAEST's single statement false.
  Replacing one honest commitment does not make a list statement false: the
  adversary can choose a nullifier supported by its own entry **[D][R]**. For
  a fixed honest nullifier an adversarial entry does not keep the statement
  true automatically, since its opening must also produce that nullifier; but
  nothing shows that every alternative list witness has disappeared **[R]**.
- **Retries and prover randomness.** The published analysis does treat the
  retry loop: games G5 and G6 of Theorem 10.42 handle the iterations and the
  successful opening, and the QROM Theorem 10.53 follows that game sequence
  **[R]**. Section 10.11.6 formulates a variant with sampled randomness, a
  single counter attempt and one hash replaced by a fixed function **[P]**;
  that single-attempt variant serves the soundness argument, since its
  verifier is unchanged **[R]**. It does not justify replacing the honest
  retrying prover's transcript distribution in a chosen-message or joint
  zero-knowledge proof. What remains is to establish the applicable extensions
  for this padded, joint-relation protocol with the tape and counter rule of
  section 6.7 **[R]**. The round-by-round errors contain no grinding term, and
  grinding gets no security credit beyond its actual quantum analysis **[R]**.
- **The detail the proof does not model.** The specification says the QROM
  proof "gives up on faithfully modeling one detail of FAEST" and does not
  name it **[P]** (v3 section 1). Which detail is meant is not established
  here.
- **Larger witnesses.** Theorem 10.30 assumes `l + d_zk − 1 ≤ 2^12`,
  `N_c + 1 ≤ 2^13` and `d_zk ∈ {7, 14}` **[P]**; Lemmas 4.6 and 4.7 state the
  universal-hash errors under those limits. Both relations exceed them:
  `l` = 35,840 and 35,904, `N_c` = 72,576 and 72,707. The bounds are therefore
  re-derived, not imported (section 7.1). At the final dimensions **[R]**,
  recomputed here **[D]**:

  | Quantity | Registration | Vote |
  | --- | ---: | ---: |
  | `l + 6` (VOLEHash polynomial length) | 35,846 | 35,910 |
  | `l + 5` (degree bound) | 35,845 | 35,909 |
  | `N_c + 1` | 72,577 | 72,708 |
  | VOLEHash inflation factor `1 + (l+5)^5 / 2^64` | 3,208.92 | 3,237.66 |
  | `log2` of the `ε_v` bound | −1,012.352 | −1,012.339 |
  | ZKHash increment `(N_c − 1)^2 / 2^64` | 2.855 × 10^-10 | 2.866 × 10^-10 |
  | Fast row, `log2` of the first core bad event `ε_v·binom(2^248, 3)` | −270.937 | −270.924 |
  | Fast row, sum of the seven interactive challenge errors, in units of 2^-256 | 41.0000319 | 41.0000322 |
  | Small row, the same sum | 30.0020402 | 30.0020584 |

  The sums are `41 + (1 + (l+5)^5 / 2^64) / (6·2^24) + (N_c − 1)^2 / 2^64` on
  the fast row; the small row replaces 41 by 30 and `2^24` by `2^18`. The 41
  is `33 + 1 + 7`: the leaf-hash injectivity round `tau·2^-lambda`, the
  ZKHash round and the final root count. The core round error stays at most
  `7·2^-256`, so the larger witnesses do not by themselves raise the
  degree-seven round error, and neither 64-bit evaluation point needs
  widening. Over 2^44 independently challenged interactive executions the
  fast-row union bound is about 2^-206.64, below 2^-128. **That figure is an
  interactive component calculation, not the deployment's Fiat–Shamir
  ledger**: the transcript ceiling bounds honest transcripts, not adversarial
  oracle queries or retries, and no argument converts those queries into at
  most 2^44 fresh-challenge opportunities **[R]**.
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
`q = 2^(n/3)` **[D]**. Gate 6 says hash lengths "follow the actual reduction".
The contract of section 8.8 uses both readings for different purposes: the
proven bound counts queries through the actual reduction, and the separate
attack-cost requirement counts gates **[R]**. Neither is category 1 relabelled
as 128 quantum bits.

**[D]** Generic quantum collision cost by digest length (BHT queries
`2^(n/3)`; CNS time `2^(2n/5)`; from the abstracts of those papers):

| Digest | BHT queries | CNS time | Classical |
| ---: | ---: | ---: | ---: |
| 256 bits | 2^85.3 | 2^102.4 | 2^128 |
| 384 bits | 2^128 | 2^153.6 | 2^192 |
| 512 bits | 2^170.7 | 2^204.8 | 2^256 |

**[R]** Same-function key search against `S` targets costs about
`2^(k/2)/sqrt(S)` oracle evaluations for a `k`-bit secret. For a 256-bit
secret that is about 2^123 at `S = 1,000` **[D]**. For the construction's
384-bit secret it is about 2^187 **[D]**, and about 2^175 across the 2^34
registrations of the lifetime envelope **[R][D]**.
The 384-bit credential removes the immediate multi-target sizing problem of a
256-bit secret **[R]**. Wider commitments do not increase key entropy.
Translating evaluations into quantum gates needs an explicit calculation.

**[R]** Nominal generic attack scales for the construction: about 2^128
queries for search of a 256-bit seed or challenge, about 2^175 for ideal
shared-function search across 2^34 secrets of 384 bits, and about 2^170.67
for ideal 512-bit collision search. They are starting points for the attack
report of section 8.8, not an exhaustive lower bound. Neither a 2^106
multi-transcript seed attack nor its absence follows from counting
transcripts alone: the IV-dependent predicates and their implementation
costs matter.

Lengths per role in the construction **[R]**:

| Role | Length |
| --- | ---: |
| Credential secret | 384 bits |
| Pad (proof coins, not a credential secret) | 256 bits |
| Credential commitment `C` | 1,024 bits |
| `auth`, `D_reg`, `nf`, `R`, `B`, scope, policy digest, proposal-content digest | 512 bits |
| Construction identifier | 128-bit literal identifier; not a collision-security claim |
| Transcript message digest at the fast row | 512 bits |
| Backend GGM seeds | 256 bits |
| Backend leaf commitments | 768 bits |
| Backend aggregate commitments | 512 bits |
| Backend challenges | 2,112 / 832 / 256 bits |
| Backend IV / grinding counter | 128 / 32 bits |

There are no membership-tree leaf or node digests. The backend lengths are
consistent with the specification's `3·lambda`, `2·lambda`, `8·lambda + 64`,
`3·lambda + 64` and `lambda` at `lambda` = 256 **[P]**. A 512-bit digest gives
about 2^170.7 BHT collision queries **[D]**. The ballot design fixes no
256-bit length for `scope` or `policy_hash`; their lengths follow its
section 5 item 6 **[C]**.

### 8.4 Commitment injectivity

Without an extractor, soundness gives only the existence of a witness. The
number of distinct accepted nullifiers is then bounded by the number of pairs
(entry, key) that open a registered commitment. That equals `S` only if no registered
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
| 384 bits | SHAKE256, 1,024 bits | 2^-257 |

The AES rows are the arithmetic behind the compared alternatives. Actual AES
does not inherit a global multi-key injectivity theorem from ordinary PRP
security, which is one reason the hybrid was not chosen **[R]** (section 10.1).
For the construction, an ideal random map from 384 bits to 1,024 bits in one
fixed context has `binom(2^384, 2)·2^-1024 = 2^-257 − 2^-641` expected
colliding key pairs, and fewer than 2^-233 over 2^24 fixed, independently
selected contexts **[R][D]**. Three limits apply **[R]**:

- The figure cannot be multiplied by a number of adversarially selected
  contexts without analysing that selection. It does not cover adaptive
  quantum context selection.
- Requesting 1,024 output bits from SHAKE256 does not by itself establish an
  ideal 1,024-bit random-map claim for the concrete sponge. Ideal-map
  injectivity calculations stay distinct from concrete SHAKE guarantees.
- The 512-bit nullifier and authorization outputs are not injective on the
  384-bit secret space: the same ideal-map arithmetic gives about 2^255
  expected colliding pairs **[D]**. The nullifier-uniqueness argument does
  not need injectivity of the nullifier; the unforgeability argument for a
  target nullifier needs an alternative-witness argument instead
  (section 7.1).

A different counting fact holds without any model: the image of the
commitment function in one context has at most 2^384 elements, so a uniform
1,024-bit string lies in it with probability at most 2^-640 **[R]**
(section 6.3). Neither the key-search calculation of section 8.3 nor the
calculations here prove the concrete scheme secure.

### 8.5 Why no parameter tuple can be certified today

- No theorem covers the list relation, adversarial registrations, the joint
  simulator or the registration proof. Gates 1, 2, 5 and 8 have no bound at
  all, so no deployment-wide total exists (section 7.1).
- The one published QROM bound is for plain FAEST with one honest key. It does
  not transfer to this construction, to both proof types or to its retry
  behaviour **[R]** (section 8.2).
- **Comparison arithmetic only [R].** Substituting the whole transcript
  ceiling `T = 2^44` as a signing budget into Corollary 10.54, with
  `n_mult = 704` and `Q = q + 37·T + 125`, gives a numerical subtotal that
  crosses 2^-64 near `q = 2^66.49` (the reprogramming term) and 1/2 near
  `q = 2^121.68` (the quadratic term with coefficient 3,200). At `q = 2^64`
  it is about 2^-64.62. This subtotal sets every primitive advantage to zero
  and treats a single-key formula as if it were a multi-user one. It is not a
  bound for the ballot. The term-by-term table is in the arguments file.
- **Primitive terms have no assigned values [R].** The comparison still
  carries `8·δ_OWF`, `2·T·δ_H3`,
  `2·T·(δ_root + 33·(12·δ_tree + δ_leaf))` and
  `6·T·sqrt(13·δ_tree + δ_leafcommit)`, the quantum PRF and PRP advantages of
  the actual reduction adversaries. None has a justified value merely because
  its implementation uses AES-256. For the total to stay below 2^-64 they
  would need `δ_OWF < 2^-67`, `δ_H3 < 2^-109`, the root-tree-leaf bracket
  below 2^-109 and the last bracket below 2^-221.17; for 1/2, below 2^-4,
  2^-46, 2^-46 and 2^-95.17. For illustration only, modelling
  `δ_tree = δ_leafcommit = q^2 / 2^256` makes the last term about 2^-15.5 at
  `q = 2^64`, so the numerical subtotal cannot justify a complete 2^-64
  guarantee there.
- **What changes for the ballot [R].** The proving tape of section 6.7
  removes the `H3` derivation term. The plain-FAEST one-way-function term does
  not transfer; its replacement credential-security terms must be proved.
  Neither change licenses deleting another unresolved term. The PRP switching
  factor of the comparison is multiplicative and stays below 2 at the final
  witness lengths.
- Both witnesses are outside the stated hypotheses of the universal-hash
  lemmas. The re-derived bounds are written and await review (section 8.2).
- The quantitative, domain-separated QROM analysis of the commitment,
  authorization and nullifier uses of SHAKE256 is not written. Adaptive
  context selection and SHAKE's concrete sponge construction must be addressed
  in it **[R]** (section 8.4). Adaptive commitment binding for concrete SHAKE,
  secret-prefix pseudorandomness given the public commitment, joint label
  hiding and the transfer of the actual retry distribution are all unknown
  **[R]**.
- The contract and lifetime envelope are fixed (section 8.8). No ledger
  computed against them exists.

The second-opinion review states that the complete proven floor and the
complete attack-cost assessment are both unestablished for the fast row, and
that the only presently justified universal numerical upper bound on the
construction's total is 1, which is not evidence of an attack succeeding
**[R]**. This record agrees. Routine retuning within the published
`lambda ≤ 256` rows does not repair the published quadratic term: grinding
gets no divisor in it and `T_open` does not remove it **[R]**. A wider-field,
wider-seed, SHAKE-PRG backend is new protocol and proof work, not a change of
`lambda` to 384, and the review does not recommend building a speculative
`lambda = 384` backend merely to compensate for the comparison bound **[R]**.
Gate 6 stays closed until an actual construction and ledger meet it.

### 8.6 Candidate row and comparator

Decided **[R]**. Neither row is a security claim, a selection or a
qualification. The released protocol eventually accepts exactly one qualified
row.

| Row | Role | `lambda` | `tau` | `w_grind` | `T_open` | `d_zk` | `n_mult` |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fast | Sole integration candidate | 256 | 33 | 8 | 229 | 7 | 704 |
| Small | Measurement comparator only | 256 | 22 | 6 | 225 | 7 | 696 |

| Role | Experimental choice |
| --- | --- |
| Credential master secret | 384 uniformly random bits |
| Pad | 256 fresh uniform bits per proof, from the proving tape |
| Credential commitment `C` | SHAKE256, 1,024 output bits |
| Registration authorization value `auth` | SHAKE256, 512 output bits |
| Nullifier `nf` | SHAKE256, 512 output bits |
| `D_reg`, sealed-list digest `R`, body-context digest `B` | SHA3-512 |
| Keccak witness | States committed after rounds 2, 4, ..., 22; rounds 23 and 24 evaluated forward with the exposed output bits constrained |
| Leaf commitments and CRT tables | FAEST v3, unchanged (section 6.6) |
| Not used | Inverse-chi grouping; degree-14 masking; widened evaluation points; hash commitments to leaf seeds; `H3` randomness derivation |
| Proof-system internals | The role-specific lengths of section 8.3 |

The reference tuple is not a transferable theorem: the custom relation's
degree, masks and checks are those of section 6.3, and their error terms are
re-derived (section 8.2). The small row is measured for comparison and is not
an integration candidate **[R]**.

### 8.7 Anonymity is computational

**[D]** `C`, `auth` and `nf` are deterministic functions of `sk` and public
values (ballot design section 3.1). `C` and `auth` are public at registration
and `nf` is public in the ballot.
An unbounded adversary can search for the `sk` that opens each registered `C`
and recompute its nullifier in every scope. No profile that instantiates
section 3.1 can therefore give statistical anonymity; this is a property of
the ballot design, not of the construction. Ballot design section 4 already
scopes ballot anonymity as resting on "the post-quantum primitives of `P`"
**[C]**.

For the construction those primitives are: SHAKE256 behaving sufficiently like
the modelled oracles in its commitment, authorization and nullifier uses,
which remains an explicit primitive assumption, and in particular
secret-prefix pseudorandomness of the nullifier function given the public
commitment of the same secret, which ordinary collision resistance, preimage
resistance or PRF security without that auxiliary commitment do not imply; the backend's PRG and commitment assumptions,
with AES in the initial measurement implementation; and zero knowledge of the
proof system in the QROM (gate 5, not proved) **[R]**. Ballots and
registrations stay on chain permanently, so a later break of any of these
identifies past voters retrospectively **[E]**. The archive horizon of
section 8.8 covers that exposure. Changing profiles does not erase it **[R]**.

### 8.8 Security contract and lifetime envelope

The stated reading of gate 6 is the contract that the second-opinion review
recommended on 2026-10-12 **[R]**. Ballot design section 5 carries it **[C]**.

**This contract weakens the earlier one.** The earlier contract required at
least 2^128 total quantum queries to modelled primitives and oracles for a
break, counted through the actual reduction. That floor is replaced by a
complete proven bound at 2^64 queries plus an independently assessed attack
cost of 2^128 gates. The split is the review's recommended policy. It is not a
theorem, and it is not an equivalent restatement of the earlier contract
**[R]**. The owner's qualification record must restate it explicitly
(section 10.2). The unconditional statistical budget and the lifetime ceilings
are unchanged.

| Quantity | Requirement |
| --- | --- |
| Computational break | Forgery success ≥ 1/2, or anonymity distinguishing gap ≥ 1/2 |
| Proven-bound requirement | Every required computational game has a complete, applicable deployment-wide bound below 1/2 at an adversary budget of 2^64 quantum queries |
| Scope of the proven bound | Both relations, all lifetime ceilings, concrete primitive terms, and the actual simulator and extractor query and time overhead |
| Recorded thresholds | The largest budgets that the complete ledger justifies at advantage 2^-64 and at advantage 1/2 |
| Attack-cost requirement | Independent cryptanalysis finds no attack that achieves forgery success or an anonymity distinguishing gap of at least 1/2 below 2^128 total elementary gates |
| Accounting | Deployment-wide, including reduction overhead and all targets |
| Archive horizon | 100 years per network and profile instance |
| Body scopes | At most 2^24 |
| Sealed seats per body | At most 1,000 |
| Registrations, including alternates | At most 2^34 |
| Honest prover transcripts per credential | At most 2^10, counting fresh proof generations |
| Total registration plus ballot transcripts | At most 2^44 |
| Accepted ballots | One per credential and body |
| Unconditional statistical bad-event budget | At most 2^-128 over the lifetime |

- **What the attack-cost assessment must count [R].** Classical and quantum
  work, preprocessing, coherent lookup, QRAM construction and use, and all
  parallel processors. Primitive evaluations are expanded into circuits.
  Queries, depth and memory are reported separately. The assessment is
  independent cryptanalysis of the complete deployment, not the arithmetic of
  this record; the nominal scales of section 8.3 are its starting points.
- **What does not satisfy either requirement [R].** Comparison formulas,
  omitted terms, incomplete reductions and nominal primitive security levels.
  The attack-cost requirement is additional to the proven bound and never
  replaces it.
- Repeated transmission of identical proof bytes is not a new prover
  transcript.
- The ceilings are analysis ceilings, not new consensus lifetime counters.
  Exceeding one requires reassessment. They overlap and are not multiplied
  together: `1,000 × 2^24 = 16,777,216,000 < 2^34` **[R][D]**. The 100-year
  horizon adds no factor once the event counts are bounded **[R]**.
- **Context of the recalibration [R].** The review's stated rationale is that
  the split preserves a separate 128-bit attack-cost objective while demanding
  a substantial complete proof guarantee. The published-shape bound is
  vacuous at 2^128 queries (section 8.1), for plain FAEST-256 as for this
  construction. With its coefficient held fixed, the quadratic term alone
  would need `lambda ≥ 269` to fall below 1/2 there, which is an arithmetic
  threshold and not an available parameter set **[R][D]**. NIST's category 5
  compares attack resources with those against AES-256 and asserts no literal
  query theorem of that size **[R]**. To the question whether any published
  QROM bound of a post-quantum Fiat–Shamir scheme is non-vacuous at 2^128
  queries under a 2^44-transcript lifetime, the review names one conditional
  result: Kiltz, Lyubashevsky and Schaffner, Theorem 3.1 with its
  deterministic extension and section 4.4, give for the paper's
  "Dilithium-QROM" `Adv_UF-CMA < Adv_MLWE + q_H^2·2^-261 + Adv_PR`, whose
  Fiat–Shamir term is 2^-5 at `q_H = 2^128` and whose signing-count term
  vanishes by perfect honest-verifier zero knowledge. It is a single-key
  theorem for that paper's scheme, not for ML-DSA and not for a multi-user
  contract, and it is conditional on the primitive advantages (cited by the
  second-opinion review; not read by us).
- **Current compliance is unestablished for both requirements.** No complete
  proven bound and no complete attack-cost assessment exists for the fast row
  or any other row (section 8.5). The review's recommendation does not
  establish that the row meets the contract **[R]**. **No parameter tuple is
  certified.** The fast row is the sole integration candidate, not a certified
  row.

## 9. Resource projections

Analytical projection only. No measurement is recorded. Sections 9.2 to 9.6
are the projections made while comparing candidates. Section 9.7 gives the
counts for the construction to develop.

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
  output adds permutations. The construction of section 6 has 132-byte inputs
  and outputs of at most 128 bytes, so one permutation per evaluation, and two
  evaluations in each relation **[D]**.
- The selected 768-bit commitment is committed as witness and bound by a
  degree-2 multiplexer over the public list.

### 9.3 Variants

| Variant | Relation |
| --- | --- |
| V1 | AES-only published shape transplanted onto a v3 backend: commitment of 2 / 4 / 4 blocks, CBC-chain tag of 2 / 3 / 4 encryptions with a 128-bit output, per-member gated last-round constraints |
| V2 | The hybrid: six-block AES-256 commitment with a public SHAKE256 mask, and a SHAKE256 nullifier in the relation (compared alternative, section 4) |
| V3 | Two-SHAKE public list in the shape projected for the candidate comparison: 256-bit `sk` and a 96-byte commitment. The construction of section 6 differs (384-bit `sk`, 128-byte commitment, a 256-bit pad, and a second permutation in the registration relation for `auth`); its counts are in section 9.7 |
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
unoptimised degree-2 form on the 256f row (188,760 B, 72%).
Only V3 (a) at 256f exceeds it (316,668 B, 121%). These sizes do not establish
security. The witness-length hypothesis of Theorem 10.30 is
`l + d_zk − 1 ≤ 2^12`, that is `l ≤ 4,090` at `d_zk = 7` **[P]**. For
`pi_vote`, only V1 at `lambda` = 128 lies inside it, and V4 at `lambda` = 128
misses it by 6 bits. For `pi_reg`, V1 at all three levels (1,472 / 3,008 /
3,744) and V4 at `lambda` = 128 and 192 (1,984 / 3,008) are inside it; V4 at
`lambda` = 256 (4,512), V2 (5,280) and every V3 form are outside **[D]**.

Proof size does not depend on `S` in any variant. Verifier public data does
**[D]**:

| Variant | Bytes per entry | `S = 3` | `S = 500` | `S = 1,000` |
| --- | ---: | ---: | ---: | ---: |
| V1 (128 / 192 / 256) | 32 / 64 / 64 | 96 / 192 / 192 | 16,000 / 32,000 / 32,000 | 32,000 / 64,000 / 64,000 |
| V2, V3 | 96 | 288 | 48,000 | 96,000 |
| Construction of section 6 | 128 | 384 | 64,000 | 128,000 |
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
| Construction `pi_vote` (section 9.7), 256f | 15.7 | 25 ms | 87 ms | 1.1 s |
| Construction `pi_vote` (section 9.7), 256s | 15.5 | about 190 ms | about 0.7 s | about 2.8 s |

The two construction rows use the same scaling, with a VOLE length of the
witness length plus 80 bits (256f) or 120 bits (256s) **[D]**:
(35,904 + 80) / (2,208 + 80) = 15.7 and (35,904 + 120) / (2,208 + 120) = 15.5.
Their 256s figures are back-derived from this table's rounded V2 (c) entry.
`pi_reg` is 64 witness bits shorter and scales to the same figures within the
rounding shown. None of these
machines is a baseline of section 11.4.

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

### 9.7 Analytical counts for the candidate row and the comparator

Derived, not measured. The witness lengths, constraint counts and sizes are
those of the second-opinion review **[R]** and are recomputed here **[D]**.
They assume the layout of section 6.3: a 256-bit pad, the 384-bit secret, and
11 committed states of 1,600 bits (17,600 bits) for each of the two
permutations of a relation.

| Proof | Witness bits `l` | Constraints `N_c` | Fast row, proof bytes | Small row, proof bytes |
| --- | ---: | ---: | ---: | ---: |
| `pi_reg` | 256 + 384 + 35,200 = 35,840 | 72,576 | 159,588 | 109,114 |
| `pi_vote` | 256 + 384 + 35,200 + 64 = 35,904 | 72,707 | 159,852 | 109,290 |

**[D]** Working form of section 9.1 with the official `n_mult` (704 and 696):
`11,748 + 33·l/8` on the fast row and `10,554 + 22·l/8` on the small row. For
example `pi_vote` on the fast row is 11,748 + 33 × 35,904 / 8 = 159,852, and
`pi_reg` is 11,748 + 33 × 35,840 / 8 = 159,588. The constraint count has no
size term. The pad costs 33 × 256 / 8 = 1,056 bytes on the fast row and 704 on
the small row; the authorization permutation costs 33 × 17,600 / 8 = 72,600
and 48,400 bytes.

Raw proof layout on the fast row, in order **[R][D]**. The field list is the
review's; the byte counts are recomputed here for the final witness lengths:

| Field | `pi_reg` bytes | `pi_vote` bytes |
| --- | ---: | ---: |
| Corrections `c_1, ..., c_32`, each `l/8` bytes | 143,360 | 143,616 |
| `c_mult`, ten masks of 704 bits | 880 | 880 |
| `u~`, four field elements | 128 | 128 |
| `d`, `l/8` bytes | 4,480 | 4,488 |
| `a~_1, ..., a~_6` | 192 | 192 |
| Opening: 33 leaf commitments of 96 bytes and at most 229 seeds of 32 bytes, in the prescribed order with canonical unused padding | 10,496 | 10,496 |
| Third challenge | 32 | 32 |
| `iv_pre` | 16 | 16 |
| Counter | 4 | 4 |
| **Total** | **159,588** | **159,852** |

These are raw proof sizes. The public `auth` adds 64 bytes to a registration.
Statement fields, the message and envelope framing are additional, and
compliance of the complete envelope needs measurement against the exact
schema, which is not written **[R]**. Every count is regenerated from the
actual constraint implementation when it exists.

Verification work and workspace. The review's design argument for gate 7
gives work formulas, a hash-input table and a buffer inventory **[R]**. The
arguments file section 6.7 holds the implementers' recalculation **[D]** at
the final dimensions: the fast-row work bounds for both relations from the
review's formulas, and the hash-input sizes and the principal vote buffers
(subtotal 8,829,935 B) from formulas inferred by fitting figures the review
gave for other dimensions, with one buffer row (114,752 B) carried as the
review gave it **[R]**. That recalculation is not a complete allocation
certificate, has no registration buffer table and no small-row figures, and
awaits confirmation against the implementation. No measurement exists. Three
of the work formulas **[D]**:

| Fast-row verification work, upper bound | Formula | `pi_reg` | `pi_vote` |
| --- | --- | ---: | ---: |
| AES block encryptions | `4·6,399 + 6,367·(8 + ceil((l + 80) / 128))` | 1,865,659 | 1,872,026 |
| VOLEHash field products | `5·(l + 6) + 4` | 179,234 | 179,554 |
| ZKHash field products | `2·N_c + 2` | 145,154 | 145,416 |

Each relation also evaluates two Keccak-f[1600] permutations in the
constraint check, 24 rounds of 1,600 nonlinear products each, and a vote adds
at most `S` selector products and `1,024·S` public-bit selections. The list
frame at `S = 1,000` is 128,114 bytes and takes 1,780 SHA3-512 permutations
**[R]**. The inventory of hash calls, buffers and the arena design is in the
arguments file section 6.7.

Thresholds **[R]**. The same hard limits apply at every roster size and to
both proofs:

| `S` | Complete canonical proof envelope | Uncached validator verification | Verifier workspace | Phone proving | Phone peak prover memory |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 3 | ≤ 262,144 B | ≤ 250 ms | ≤ 64 MiB | p95 ≤ 10 s | ≤ 256 MiB |
| 500 | ≤ 262,144 B | ≤ 250 ms | ≤ 64 MiB | p95 ≤ 10 s | ≤ 256 MiB |
| 1,000 | ≤ 262,144 B | ≤ 250 ms | ≤ 64 MiB | p95 ≤ 10 s | ≤ 256 MiB |

- The ballot envelope size includes its proof, public fields, stamp and
  framing. Shared seal and list evidence is separate, capped at 160 KiB
  (163,840 B **[D]**) for the list-context object. The two caps together allow
  at most 262,144 + 163,840 = 425,984 bytes of combined bounded input
  **[R][D]**.
- Verification measurements include fresh list decoding and digest
  validation, transcript preparation and late-invalid proofs. They exclude
  network and disk retrieval. Memory includes list and transcript buffers.
- **Cold-input total at `S = 1,000`.** The fast `pi_vote` proof plus the raw
  list alone is 159,852 + 128,000 = 287,852 bytes, before other framing
  **[D]**. The 256 KiB envelope limit is not a claim that all cold
  verification inputs fit inside 256 KiB. On the small row the same sum is
  109,290 + 128,000 = 237,290 bytes **[D]**.

### 9.8 Against the section 5 limits

| Limit | Status |
| --- | --- |
| Proof envelope ≤ 256 KiB | The fast-row proof objects are projected at 159,852 B (`pi_vote`) and 159,588 B plus the 64-byte `auth` (`pi_reg`), each about 61% of the limit, before public fields, stamp and framing **[D]**. The registration proof is as large as the ballot proof. Not measured; the envelope schema is not written |
| Verification ≤ 250 ms on the minimum validator baseline | Cannot be judged. The baseline is named (section 11.4) but no run on it exists, and the verifier is not implemented. The illustrations of section 9.5 are for other machines **[E]** |
| Verifier workspace ≤ 64 MiB | Not measured. The review's design argument reserves a 64 MiB arena and lists the principal buffers **[R]**. The implementers' recalculation of the principal vote buffers on the fast row is 8,829,935 B, 13.2% of 67,108,864 B **[D]** (arguments file section 6.7; fitted formulas, one row carried **[R]**). It is not a complete allocation certificate: decoder metadata, alignment, provider scratch space, stack and the public-input schema are not inventoried, and there is no registration or small-row table |
| Phone proving p95 ≤ 10 s | Cannot be judged without runs on the baseline phones. Scaled anchors suggest a wide margin **[E]** |
| Phone prover memory ≤ 256 MiB | Not projected |

## 10. Decisions

### 10.1 Decisions taken

On 2026-10-11 the owner delegated the open decisions of this record to the
second-opinion review, under the instruction that this is the first release,
backward compatibility is not needed and the best design is chosen. The review
decided in two passes, on 2026-10-11 and 2026-10-12 (section 3). Each row is
a design decision of that review **[R]**. None is a security proof, a profile
selection or a qualification.

| Item | Decision | Stated in |
| --- | --- | --- |
| Construction | Two-SHAKE public-list construction with a flat commitment to the sealed ordered list, a registration authorization value and a fresh pad, as the single construction to develop. The hybrid is not chosen: avoiding its extra credential assumptions is worth the projected increase in proof size. The construction is frozen for investigation; no security-qualified normative profile is selected | Section 6 |
| Contract recalibration | Two requirements replace the literal 2^128-query floor: a complete proven deployment-wide bound below 1/2 at 2^64 quantum queries, and an independently assessed attack cost of at least 2^128 elementary gates. The statistical budget, the lifetime ceilings and the 100-year archive horizon are unchanged. **This expressly weakens the earlier contract.** It is the review's recommended policy, not a theorem. Current compliance is unestablished and no parameter tuple is certified | Section 8.8; ballot design section 5 |
| Public-list verifier and evidence contract | Flat digest of the ordered list; the list bytes are published in finalized block data at seal; every verifier holds a validated list or an immutable context authenticated to the seal | Section 6.4; ballot design sections 3.1, 3.3, 3.5, 3.8, 3.9 and 12.2 |
| Gate 8 wording | Adaptive cross-relation registration unforgeability replaces simulation-extractability. Gate 1's knowledge requirement stays a separate obligation | Section 7.3; ballot design sections 3.2 and 5 |
| Pad | 256 fresh prover-random bits before the secret, at witness positions `[0, 256)`, constrained only by Booleanity. It removes the dependence of the CRT labels on the credential prefix. Cost: 1,056 proof bytes on the fast row and 256 constraints | Section 6.3 |
| Gate 5 target | Standard adaptive joint zero knowledge for arbitrary application witnesses and arbitrary auxiliary information about them, not the honest-key-only simulation game. The proving tape is excluded from the auxiliary information, and a prover that accepts a fixed or disclosed pad is outside the claim. The separate anonymity game keeps hidden honest challenge credentials and its disclosure exclusions. The pad supports this target; it does not establish it | Sections 6.7 and 7.1; ballot design section 5 |
| Registration authorization value | `auth = SHAKE256("PAU1" \|\| P16 \|\| sk \|\| D_reg)`, 64 bytes, public in `m_reg`, bound through `mu` and constrained in the registration relation. Final dimensions: registration 35,840 witness bits and 72,576 constraints; vote 35,904 and 72,707. No analogous value in the vote relation | Sections 6.2, 6.3 and 7.3; ballot design section 3.2 |
| Witness layout and constraint order | Frozen: the layout, the ordered constraint stream with Booleanity emitted once and selector constraints before the Keccak blocks, the retained zero prefix constraints, and homogenisation to nominal degree seven | Section 6.3 |
| Leaf commitments and CRT tables | FAEST v3 leaf commitments kept unchanged; official CRT tables and gate order, 704 gates on the fast row. Direct hash commitments to leaf seeds are not adopted | Section 6.6 |
| Row choice | Fast row `(256, 33, 8, 229, 7)` as the sole integration candidate; small row as a measurement comparator. No `lambda = 384` backend is built to compensate for the comparison bound | Sections 6.6, 8.5 and 8.6 |
| Randomness and retries | An independent fresh 80-byte proving tape per invocation; no `H3` derivation; counters `0..=u32::MAX` in order; `GrindingExhausted` on exhaustion, never a wrap; verification checks the supplied counter once | Section 6.7 |
| Tape uses and erasure | The allocation `r`, `iv_pre`, pad is retained. `r` feeds the backend root expansion and the existing high-mask expansion; the raw pad is supplied only as witness bits `[0, 256)`; `iv_pre` is hashed in `H4` and challenge 1, and nothing else of the tape is hashed separately. Owned tape buffers, `r`, the pad and transient secret material are erased on success, error and exhaustion | Section 6.7 |
| Descriptor and digests | `DESC`, with the `SUITE` string, the parameter tuple, the CRT table digest `T_crt` and the relation dimensions; `D = SHA3-512(DESC)`; the CRT serialisation `CRT_BYTES`; fixed values of `T_crt` and `D` for both rows. `D_reg` takes exactly the 64 bytes `D`. The verifier selects a compiled fixed descriptor | Sections 6.1 and 6.2 |
| Opaque public inputs | The standalone construction takes bounded opaque byte strings, with fixed bounds and boundary rules, and neither imports node types nor parses their encodings. Canonical Norito validation is the caller's: Core supplies and validates the pinned representations | Section 6.1 |
| Hash prefixes | Every ballot backend hash call carries the 77-byte role prefix `PREFIX_R = ASCII("PARL/FAEST/v1") \|\| NS_R`; `mu_R` is defined with suffix `08`; no `H3` and no additional `H1` consistency digest. The primitive internals, the suffixes and the PRG with its tweaks are unchanged; an empty prefix reproduces the reference inputs and is not an accepted ballot mode. Causal dependence on `mu` was judged insufficient for the disjoint-domain statement | Section 6.3 |
| Proof layout and test codec | A fixed naked proof layout per row and relation, without header; `a_0` hashed and not serialised; canonical opening padding, nonzero padding rejected; fixed length, no row autodetection, no trailing bytes. A test-only statement codec that is not a production schema | Section 6.6 |
| Gate 5 game | The arbitrary-witness, shared-simulator experiment: application-witness disclosure permitted, secret-tape disclosure excluded. The padded CRT hidden-label simulation lemma is the first missing zero-knowledge obligation, with the complete retry and future-oracle-state analysis | Section 7.1 |
| Gate 8 route | The opening-uniqueness split, per-handle authorization logs and an explicit registration-frame SHA3-512 collision term | Section 7.3 |
| Query offset | `Q = Q~ + 125` for compact-proof static comparisons; 85 only for the explicit-leaf intermediate of Lemma 10.49 | Section 8.1 |
| Construction freeze | Selection-rule condition 1 is complete for standalone work. Selection and activation stay blocked on the remaining proof, ledger, implementation and qualification requirements. The feature remains disabled | Section 11.1 |
| AES binding assumption | Not made a dependency. Multi-key injectivity of `k -> AES_k(p_0) \|\| ... \|\| AES_k(p_5)` does not follow from single-key PRP security. It leaves the normative candidate with the hybrid | Section 4 |
| Keyed-SHAKE assumption given the AES commitment | Not made a dependency; it leaves with the hybrid. The two-SHAKE construction instead needs a quantitative, domain-separated QROM analysis of its commitment, authorization and nullifier uses, with concrete SHAKE as an explicit primitive assumption | Sections 4 and 8.7 |
| Arithmetisation-oriented hash | Not admissible in this profile, in its commitments or its transcript. Algebraic universal hashes inside the proof protocol are a different category, subject to their proved error bounds | Ballot design section 5 |
| Hardware baselines | Intel Xeon Silver 4310 (one physical core, base frequency), Pixel 6a and iPhone SE third generation. The portable scalar path must be correct and bounded; it need not meet 250 ms | Section 11.4; ballot design section 5 |
| Proof work | The written-argument standard of section 11.1. Complete reductions may await independent review; missing reductions may not. The review states that it can write and check the arguments in a follow-up, with no assured outcome | Sections 7.1 and 11.1 |
| What selection requires | Profile selection is distinguished from activation qualification. Selection needs the complete dossier of section 11.1; independent review and the validator and phone launch measurements may remain enumerated obligations | Section 11.1; ballot design section 12.2 step 2 |
| Selection rule amendment | Only the contract condition (condition 3) is amended, to the recalibrated contract. The proof-completeness and sequencing requirements and the stop conditions are unchanged | Sections 11.1 and 11.5; ballot design section 12.2 step 2 |
| Boundary of permitted work | Standalone implementation, measurement and proof work only. No production schemas, no Core verifier bridge, no signerless envelope integration, no sealed-list or nullifier state transitions, no Torii or SDK paths, and no retirement of the old ballot or its threshold-encryption code before selection | Section 11.1; ballot design section 12.2 |
| Qualification | Accepting and recording activation qualification is the owner's alone. Implementers and reviewers may produce evidence and record a profile selection; they may not claim qualification or make `parliament_binding_ballot_available()` true | Section 10.2 |
| Standalone implementation | An in-tree, standalone experimental implementation, following FAEST specification v3.0. The owner authorised it, the download of the official test vectors and the patching of dependencies | Sections 11.2 and 11.3 |
| Placement and dependencies | VOLE-in-the-head is a distinct mathematical family with exactly one reusable owner crate, `crates/iroha_zkp_vole`. The pinned `aes` 0.8.4 dependency is minimally patched to expose portable types and to put hardware dispatch behind a positive feature | Section 11.2; [zk_delivery_plan.md](zk_delivery_plan.md), "Shared proof backend and complete IVM proof" |
| Draw seed | Attempt identity stays out of the ranking seed | Ballot design section 9 |
| Idle-chain latency and casting clock | Bounded native-slot progress, casting-clock due work and late processing as requirements on the SCCP-owned governance clock; `parliament_sccp_attempt_latency_ms()` is `None` until a qualified bound exists | Ballot design sections 9 and 11; wording owned by [sccp.md](sccp.md) |

Whether computational anonymity is acceptable is not a separate decision:
section 8.7 shows it follows from ballot design section 3.1 for every profile.

### 10.2 Still requiring the owner

The owner has authorised downloading the official test vectors and patching
dependencies. Three items remain:

1. **Access to the named hardware.** Any access or expenditure needed for the
   validator and phone measurements on the baselines of section 11.4. Until
   then those launch measurements remain open.
2. **The contract change, restated.** The contract of section 8.8 weakens the
   earlier floor of 2^128 quantum queries through the actual reduction. The
   split is the second-opinion review's policy recommendation, made under the
   owner's delegation; it is not a theorem. The owner's qualification record
   must restate the change explicitly and contain the actual complete
   thresholds of the ledger and the independently reviewed attack-cost
   assessment **[R]**.
3. **The qualification record.** The eventual record of activation
   qualification. Until the owner supplies it,
   `parliament_binding_ballot_available()` remains false.

## 11. Evidence required and order of work

### 11.1 Selection rule

Ballot design section 12.2 step 2 distinguishes profile selection from
activation qualification **[C]**. Selection, and steps 3 to 5, may proceed only
when all of these are true **[R]**:

1. One exact construction and parameter row are frozen; no unresolved relation
   or transcript choice remains.
2. Every gate has a complete written argument under the standard below.
3. The complete deployment-wide ledger satisfies the explicitly recorded
   contract of section 8.8: each required computational game has advantage
   below 1/2 at 2^64 adversarial quantum queries, with every primitive and
   reduction cost included; the independent attack assessment meets the
   2^128-gate requirement; and the unconditional statistical budget remains at
   most 2^-128. The complete ledger's thresholds at advantages 2^-64 and 1/2
   are recorded. Comparison formulas, omitted terms, incomplete reductions and
   nominal primitive security levels do not satisfy this condition.
4. The standalone prover and verifier implement that exact protocol and pass
   meaningful adversarial and component checks.
5. Complete envelope sizes, deterministic work and allocation bounds and
   measurements at all three roster sizes are recorded.
6. All remaining independent review, external conformance, hardware, phone,
   lifecycle and network qualification obligations are enumerated.
7. `parliament_binding_ballot_available()` remains false.

Condition 3 is the review's amended text; only the contract condition of the
rule changed **[R]**.

**Where the record stands.**

| Condition | State |
| --- | --- |
| 1 | **Holds for the standalone construction**, by the review's decision **[R]**; it is a design decision, not a selection. It covers: the construction, the relations, the witness layout, the ordered constraint stream and homogenisation, the row `(256, 33, 8, 229, 7)`, the unchanged leaf commitments and official CRT tables, the proving tape and the retry rule; the descriptor `DESC` and its digest `D`; the public inputs as bounded opaque byte strings; the role prefixes of every backend hash call and the preimage of `mu`; the naked proof layout; and the uses of the tape (section 6). The review states that no relation or transcript choice remains open for it, and that this replaces the earlier requirement that the standalone crate define node-type encodings. It does not cover the production Norito mappings, the production envelopes or authenticated integration, which remain later obligations and are not written; the standalone verifier does not validate node-level canonicality |
| 2 | **Fails.** Gates 1, 2, 5 and 8 are incomplete; gates 3, 4 and 7 are conditional; gate 6 is not met (section 7.1) |
| 3 | **Fails.** No complete ledger and no attack-cost assessment exists; compliance with either part of the contract is unestablished (sections 8.5 and 8.8) |
| 4 | In progress. Stage 1 of the backend exists; no prover or verifier exists (section 11.2) **[C]** |
| 5 | Not met. No envelope schema and no measurement exist. The fast-row work bounds and the principal vote buffers are recalculated **[D]** in the arguments file section 6.7; that is not a complete allocation certificate (section 9.7) |
| 6 | In progress. Sections 10.2, 11.4 and 12 enumerate the known obligations **[E]** |
| 7 | Holds **[C]** |

**Conditions 2 and 3 fail, so production schemas and Core integration do not
start.** Implementation, resource measurements and qualification are
unfinished, and the feature remains disabled **[R]**. A false launch gate does not remove the selection precondition
**[R]**.

**Boundary of permitted work [R].** Standalone step-2 work only:

- complete the backend, its conformance with the official plain-FAEST
  vectors, and the exact experimental ballot prover and verifier;
- implement the profile-local relation encodings and codecs needed to specify
  and test that standalone protocol;
- carry out adversarial tests, independent relation checks, deterministic
  parity checks, resource accounting and measurements at `S = 3`, 500 and
  1,000;
- write and review the missing cryptographic arguments.

Not permitted before selection: production schemas, a Core verifier trait
bridge, signerless envelope integration, sealed-list or nullifier state
transitions, Torii or SDK paths, and retirement of the old ballot or its
threshold-encryption implementation. That retirement belongs to step 4, with
the replacement **[R]**.

**Dossier that selection requires [R].** Selection for integration, with the
launch gate false, needs:

- **the exact protocol:** one row, descriptor, byte encodings, namespaces,
  relations, ordered constraints, randomness and retries, with no unresolved
  choice;
- **complete arguments for all eight gates:** in particular efficient
  extraction for gate 1, adaptive mixed-list authorization for gate 2, joint
  simulation and anonymity for gate 5 and registration origin for gate 8,
  each with its game, assumptions, simulator or extractor, transitions,
  theorem hypotheses and quantitative losses;
- **a complete calibrated security ledger and attack assessment:** both proof
  roles, users, contexts, lifetime use, primitive terms and reduction
  overhead;
- **an exact standalone implementation without placeholders:** official
  baseline conformance, ballot-specific independent checks, constraint
  mutations, malformed-proof tests and determinism evidence;
- **resource evidence:** complete envelope sizes, deterministic work and
  allocation bounds, and measurements at all three roster sizes against the
  hard limits;
- **enumerated qualification obligations:** completion of independent review,
  the named validator and phone baselines, lifecycle, SDK parity, real-peer
  restart and rollback, network and release evidence.

Missing foundational proofs continue to prevent selection **[R]**.

**Written-argument standard [R].** An argument counts as complete, awaiting
independent review, only when it contains:

- the exact protocol, relations, encodings and randomness behaviour;
- the security game, corruption model, oracle access and winning condition;
- explicit primitive assumptions, distinct from properties being proved;
- every simulator or extractor and every game transition;
- precise citations and verification of every imported theorem hypothesis;
- quantitative loss terms, including lifetime, multi-user, grinding,
  reprogramming, witness-length and constraint-count effects;
- the numerical substitution into the contract of section 8.8;
- an explicit list of exclusions and remaining implementation and review
  obligations.

A lemma that assumes "this ballot proof is quantum unforgeable" does not count
as a proof of ballot unforgeability. An unresolved theorem is a gap, even if
its expected result sounds plausible. Independent proof review may remain
pending; missing foundational arguments may not **[R]**.

Measurements on the implementer's machine can support construction feasibility
and selection. They do not satisfy the named validator or phone launch
measurements **[R]**.

### 11.2 Implementation route

**[R]** unless marked. The backend follows FAEST specification v3.0, which the
review dates 1 September 2026 and the official site identifies as the current
submission. It is implemented in tree from that specification.

| Crate | Role |
| --- | --- |
| `crates/iroha_zkp_vole` | Reusable, state-free VOLE-in-the-head backend. The one owner of that family under the shared-backend rule. Experimental and unqualified |
| `crates/iroha_parliament_ballot_proof` | Fixed experimental profile, context and list validation, and the ballot relations. Standalone; nothing in Core depends on it |

The review placed the ballot relations under
`crates/iroha_core_privacy/src/parliament_ballot/` **[R]**. The standalone
experiment keeps them in a separate leaf crate so that nothing is wired into
Core before selection; their placement at integration is settled with ballot
design section 12.2 step 4. Governance state transitions stay in Core.

State of the modules **[C]**, at the baseline:

| Crate | Modules | State |
| --- | --- | --- |
| Backend, stage 1 | `params`, `field`, `prg`, `hash` (`H0` to `H5`), `universal_hash` (VOLEHash, ZKHash, LeafHash) | Implemented, with conformance tests against the official component vectors (section 11.3) |
| Backend | `bavc` | Unfinished work in the working tree; no result is recorded here |
| Backend | `vole`, `crt`, `quicksilver`, `transcript`, `codec`, `randomness`, `faest` (the plain-FAEST instantiation used for conformance) | Placeholders |
| Ballot | `profile`, `framing`, `credential`, `sealed_list`, `selector`, `keccak_relation`, `registration`, `vote` | Placeholders; the crate is a skeleton |

- **CRT tables.** A scratch prototype outside the repository is reported by
  the implementation work to reproduce the reference CRT table construction:
  gate counts 312, 312, 504, 504, 696, 704, 504 and 504 for the eight
  parameter sets that have official `crt_vole_commit` vectors, `W_CRT` equal
  to those vectors, and `M_TREE` and the first tree modulus equal to the
  official field vectors. It has not been byte-compared with upstream's
  generated table headers, and it is not ported to Rust. This is a report of
  the implementation work: it is not verified by this record and carries none
  of the record's labels. The official tables are the pinned ones (section 6.6).
- **Reuse.** The pinned `sha3`, Norito, `zeroize` and the existing randomness
  interfaces. `aes` 0.8.4 supplies the full-block backend PRGs, without a
  dependency on `iroha_sccp_rpc` to reach it.
- **No new AES.** No new production AES implementation with exposed round
  states is written. The relation has no AES witness.
- **AES dependency patch.** The workspace's `aes` is the vendored 0.8.4 under
  `vendor/aes`, patched so that hardware modules and dispatch sit behind a
  positive `hardware` Cargo feature and the constant-time software
  implementation is a public `soft` module **[C]**. The backend depends on it
  with default features off and selects the hardware provider only through
  its own `accel` feature **[C]**. AES arithmetic and key expansion are not
  changed, and no runtime environment toggle is substituted **[R]**.
- **No second driver.** The backend is not another FASTPQ or STARK driver.

The available Rust `faest` crate states compatibility with specification
version 2 and no security audit, and exposes whole signatures only **[P]**
(crate manifest, README and `src/lib.rs`, read through summaries). It is not
the backend. Known-answer tests of different specification versions are not
interchangeable.

### 11.3 Test strategy

Confidence is built in layers **[R]**:

- independently structured native Boolean evaluators against the polynomial
  constraints;
- exhaustive reduced selector and gadget tests, and deliberate constraint
  mutations;
- independent field-arithmetic and CRT oracles;
- BAVC and VOLE identities, opening and reconstruction, and transcript tests;
- wrong contexts, changed messages, malformed selectors and incorrect outputs;
- bounded-parser fuzzing, truncation, trailing bytes and late failures;
- cancellation, randomness-failure and zeroization checks;
- byte parity between the portable and accelerated paths under fixed
  randomness;
- locally generated regression fixtures, labelled self-generated.

Self-generated fixtures do not establish independent conformance **[R]**.

The official FAEST v3.0.2 test vectors are in the repository as fixtures
converted from the reference implementation's test headers at tag `v3.0.2`
(commit `4fb6b71143`), under the MIT licence, with the upstream SHA-256 of
every header (`crates/iroha_zkp_vole/tests/fixtures/faest_v3_0_2/README.md`)
**[C]**. Their use so far:

| Official vectors | State |
| --- | --- |
| `prg_tvs`, `universal_hashing_tvs`, `field_tvs` | Every entry is reported reproduced by stage 1, with and without the `accel` feature. The conformance tests are in the repository **[C]**; this record did not run them |
| `crt_vole_commit_tvs` | Reported by the implementation work as reproduced by the scratch prototype only (section 11.2); not verified by this record and carrying none of its labels. The fixture README notes that upstream ships no generator for this header, so the meaning of its entries is inferred from their names **[C]** |
| `bavc_tvs`, `vole_tvs`, `owf_tvs`, `faest_tvs` (full signatures) | Not reproduced: the layers they test are unfinished or not implemented |

Bidirectional cross-verification with a pinned official implementation remains
to be added **[R]**. The ballot namespaces, the padded witnesses and the custom
relations need their own vectors; none exists **[R]**.

Conformance of the backend to FAEST vectors establishes that the backend
computes FAEST. It does not establish ballot security: the ballot relation has
no official vectors. "Deterministic prover" means deterministic given an
explicit random tape, never fixed or reused production randomness. The phone
prover needs constant-time secret arithmetic, no secret-indexed tables,
branches or list accesses, reviewed randomness handling and clearing of keys,
round states, seeds and masks on success, error and cancellation **[R]**.

### 11.4 Measurement record

Minimum measurement baselines **[R]**:

| Role | Baseline |
| --- | --- |
| Validator | One physical core of an Intel Xeon Silver 4310 at its 2.10 GHz base frequency, turbo disabled, idle SMT sibling, Linux x86-64; AES-NI, PCLMUL and AVX2 allowed; no AVX-512 requirement |
| Android | Pixel 6a, Tensor, 6 GB RAM |
| iOS | iPhone SE, third generation, A15 |

The portable scalar path must preserve results, proof bytes under fixed
randomness, work charges and memory limits. It need not meet 250 ms. That
limit belongs to the accelerated build of the minimum validator baseline.
Slower hardware receives no claim that it supports the qualified validator
throughput **[R]**. The implementer's Mac can establish only timing and memory
on that exact machine and build, genuine scalar measurements with acceleration
disabled, ARM accelerated measurements and local deterministic parity. It
cannot qualify the Intel baseline, either phone, x86 parity or phone thermal
behaviour **[R]**.

Each run records, following ballot design section 5 and the repository's
evidence conventions (`zk_delivery_plan.md` H.1–H.3, `iroha_measurement`):

- full source commit and tree state; artifact, build profile and
  configuration identity; the pinned specification version; the parameter row;
- a named hardware record with observed host facts, the OS, compiler and build
  flags, and for phones the device, OS, battery operation and thermal state;
- the exact inventory: `pi_reg` and `pi_vote`, prove and verify, at `S = 3`,
  500 and 1,000, on the portable path and each accelerated path;
- exact proof and envelope bytes, and the total cold input including the list;
- verification time cold and warm, including fresh list decoding and digest
  validation and transcript preparation, and excluding network and disk
  retrieval; verification time for late-failing invalid proofs and malformed
  encodings; distributions and the maximum observed valid and late-invalid
  times, not only averages;
- verifier peak memory against the 64 MiB limit, including list and
  transcript buffers; prover wall time with a stated sample count for p95,
  after sustained load, and with cancellation; prover peak memory; the
  grinding-retry distribution, that is the accepted counter values and any
  `GrindingExhausted` result;
- logical work counters (hash calls, field multiplications, AES blocks) from
  which `B_work` and `B_bytes` are derived;
- byte-identical accept and reject results across paths;
- measured values kept separate from limits and projections; raw failures
  retained; a statement of what was not run; no private witness or key in the
  record.

Exploratory runs before the profile is frozen never count as qualification.

### 11.5 What stops selection or switches the construction

Selection and integration stop again if any of these occurs **[R]**:

- a foundational game, simulator, extractor or reduction is missing or fails;
- the ledger fails the contract of section 8.8;
- the implementation needs an unproved protocol deviation;
- adversarial tests expose an unconstrained witness, transcript substitution
  or determinism defect;
- the final secure parameters exceed a hard resource limit;
- a primitive assumption is stronger than the recorded approved design.

A performance experiment may continue to investigate such a blocker, clearly
labelled experimental **[R]**. The recalibration of section 8.8 leaves these
stop conditions unchanged **[R]**. The first two apply today: foundational
steps are missing for gates 1, 2, 5 and 8, and no ledger exists
(section 11.1).

The construction is switched when the final security argument fails, or when
the secure implementation exceeds a hard limit after straightforward grouping
and streaming work. A narrow standard-hash STARK is then evaluated under the
same requirements. Digests are not shortened, the security metric is not
weakened and limits are not raised silently; the one change of the metric,
in section 8.8, is explicit and recorded as a weakening. If the two-SHAKE construction
passes, it is retained even if the hybrid benchmarks faster **[R]**.

Observable forms of the resource conditions, this record's **[E]**:

- **Limits.** For `pi_reg` or `pi_vote` at `S = 3`, 500 or 1,000, including
  late-failing invalid proofs: an envelope above 262,144 B; worst-case
  uncached verification above 250 ms on the accelerated build of the minimum
  validator baseline; verifier workspace above 64 MiB; phone proving p95 above
  10 s on a baseline phone; phone peak prover memory above 256 MiB; a
  list-context object above 160 KiB. The two memory limits were not projected
  (section 9.8).
- **Capacity.** The worst-case per-ballot verification charge, including
  public-list processing (section 6.4), does not permit the capacity rule of
  ballot design section 3.6 at `S = 1,000`: 1,000 ballots for each of `K`
  concurrent attempts within the per-block budget at the minimum block
  cadence.
- **Parity.** Any accept, reject, proof-byte, charge or error difference
  between accelerated and portable paths under fixed randomness.

## 12. What independent review must cover

- The exact relations, encodings and domain separation of section 6:
  the pad and its Booleanity-only role, the authorization value and the
  preimage of `D_reg`, the witness layout, the ordered constraint stream and
  its homogenisation, the prefix-form selector, the exclusion of positions at
  or beyond `S`, the descriptor and its digests, the bounded opaque inputs,
  the role prefix on every backend hash call, the naked proof layout, and the
  transcript binding of the statement, `auth` and the list bytes through
  `mu`. The `T_crt` values are the review's and are reproduced here from the
  generated table sources without a build (section 6.1); the compiled
  backend's serialisation is unchecked.
- The [arguments file](parliament_ballot_proof_arguments.md) in full, against
  the standard of section 11.1, for both proofs under one `sk`. Its written
  parts: the encoding equivalence at the final layout, the re-derived
  universal-hash bounds, response-graph soundness for false instances, the
  conditional theorems for gates 3 and 4, and the design argument for gate 7.
- **Its incomplete parts, which review cannot close by reading:** the
  efficient extractor of gate 1; the joint extraction and simulation lemma and
  the mixed-list reduction of gate 2; for gate 5 the proof for the padded
  backend, beginning with the padded CRT hidden-label simulation lemma, the
  reprogramming location bounds, the stopping-time and oracle-state analysis
  of the retry loop and the hidden-input term; for gate 8 every unproved
  premise of the event split of section 7.3 (target-opening uniqueness,
  adaptive registration soundness, the registration-frame collision
  resistance, joint simulation and authorization prediction); the IV and
  cross-instance security of the unchanged PRG (section 6.3); and the deployment-wide ledger of gate 6.
- Applicability of the QROM Fiat–Shamir analysis to the actual protocol:
  adaptive statements, adversarially registered entries, the fresh proving
  tape and the incrementing-counter retry loop of section 6.7, the review's
  reading that Theorem 10.42 and Theorem 10.53 treat the published retry loop,
  the unmodelled detail, and every imported lemma that this evaluation did not
  read (section 3).
- The contract of section 8.8: that it weakens the earlier one, whether the
  recalibration is acceptable, the concrete security ledger against it (every
  reduction loss, primitive term, statistical error and its accumulation,
  multi-target use, and the length of every role in section 8.3), and the
  independent attack-cost assessment with the accounting that section 8.8
  requires.
- The role audit of existing 32-byte values (section 6.1).
- The primitive assumptions: SHAKE256 as the modelled oracles in its
  commitment, authorization and nullifier uses, including adaptive context
  selection, the concrete sponge and secret-prefix pseudorandomness given the
  public commitment; the backend's PRG and commitment assumptions.
- The public-list contract, the publication of the list at seal and its effect
  on independent full verification (section 6.4).
- The arithmetic of this record that has had one reader, or one reader besides
  the review: section 8.1's coefficients and chosen-message terms, the bounds
  of section 8.2, the comparison figures of section 8.5, the Keccak grouping
  of sections 8.6 and 9.2, the counts, layout and work figures of section 9.7
  and every `d_zk = 14` figure.
- The implementation: conformance to the pinned specification, the port of
  the official CRT tables and its comparison with upstream's generated
  headers, bounded and deterministic verification, identical results across
  hardware, malformed-input behaviour, constant-time and randomness handling
  in the prover including the tape and the exhaustion path, and the patch to
  the pinned `aes` dependency. Source inspection alone does not establish
  resistance to physical side channels **[R]**.

## 13. References

Reading status: **full**, **part**, **abstract**, **code** (source files
read), **research pass** (collected mostly from abstracts or secondary
citations; unverified), **not read by us** (reported by the second-opinion
review).

Venue and year metadata for the arXiv QROM entries, for Unruh 2014/587 and
Liu–Zhandry 2019/262, the Bernstein title, the title and venue of the
Kiltz–Lyubashevsky–Schaffner entry, and the author line of the FAEST
specifications were supplied from memory and not checked against the sources
**[E]**. The URLs are the identifiers.

**Specifications and code**

| Source | Status |
| --- | --- |
| FAEST team (Baum et al.), *FAEST Algorithm Specifications*, version 2.0. <https://faest.info/faest-spec-v2.0.pdf> | Part: pp. 2–82, 93–97, 101–111 |
| FAEST team (Baum et al.), *FAEST v3 Algorithm Specifications*, version 3.0. <https://faest.info/faest-spec-v3.0.pdf> | Part: sections listed in section 3. The second-opinion review also cites section 6 with Figure 6.2 (CRT gates), Lemma 7.3, Lemmas 10.24, 10.26, 10.40, 10.51 and 10.52, Corollaries 10.27 and 10.41, and games G5 and G6 of Theorem 10.42; statements resting on parts outside the pages we read are **[R]** |
| FAEST reference implementation. <https://github.com/faest-sign/faest-ref> | Part: listings, README, changelog, test manifest; v2.0.5 sources through tool summaries. The implementation work read the test headers and generator sources at tag `v3.0.2`, commit `4fb6b71143` (fixture README, section 11.3) |
| `faest` Rust crate (ait-crypto). <https://github.com/ait-crypto/faest-rs> | Part: manifest, README, changelog, `src/lib.rs`, `src/faest.rs`, `tests/nist.rs`, through tool summaries |
| FAEST project site. <https://faest.info/> | Front page; resources page not read by us |
| Chiang et al., reference implementation. <https://github.com/jachiang/PQ-Threshold-Ring-Sigs-from-VOLEitH> | Code: branch `master`; files listed in section 3 |
| NIST, *Post-Quantum Cryptography: Security (Evaluation Criteria)*. <https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-(evaluation-criteria)> | Full, through a tool summary |
| *Zcash Protocol Specification*. <https://zips.z.cash/protocol/protocol.pdf> | Part: sections 4.16 and 8.4 |
| Semaphore v4 circuit. <https://github.com/semaphore-protocol/semaphore> | Code: `semaphore.circom`, through a tool summary |
| NIST, *FIPS 202: SHA-3 Standard*. <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf> | Not read by us; cited by the second-opinion review (sections 3.1, 3.3, 5, 6 and Appendix B for the conventions of section 6.3) |
| FAEST official specifications and resources. <https://faest.info/resources.html> | Not read by us; cited by the second-opinion review |
| FAEST official test vectors, version 3.0.2, MIT licence. `crates/iroha_zkp_vole/tests/fixtures/faest_v3_0_2/` | Code: converted fixtures and their provenance README in the repository; reproduction status in section 11.3 |
| Intel, Xeon Silver 4310 specifications. <https://www.intel.com/content/www/us/en/products/sku/215277/intel-xeon-silver-4310-processor-18m-cache-2-10-ghz/specifications.html> | Not read by us; cited by the second-opinion review |
| Google, Pixel phone hardware specifications. <https://support.google.com/pixelphone/answer/7158570> | Not read by us; cited by the second-opinion review |
| Apple, iPhone SE (3rd generation) technical specifications. <https://support.apple.com/en-ie/111866> | Not read by us; cited by the second-opinion review |

**VOLE-in-the-head and ring signatures**

| Source | Status |
| --- | --- |
| Chiang, Damgård, Duro, Engan, Kolby, Scholl, *Post-Quantum Threshold Ring Signature Applications from VOLE-in-the-Head*, ACM CCS 2025, ePrint 2025/113. <https://eprint.iacr.org/2025/113> | Abstract only. Paper not read by us; read by the second-opinion review through a mirror at moneroresearch.info |
| Baum, Beullens, Braun, Delpech de Saint Guilhem, Klooß, Majenz, Mukherjee, Orsini, Ramacher, Rechberger, Roy, Scholl, *Shorter, Tighter, FAESTer: Optimizations and Improved (QROM) Analysis for VOLE-in-the-Head Signatures*, CRYPTO 2025, ePrint 2026/164. <https://eprint.iacr.org/2026/164> | Abstract; its analysis was read as FAEST v3 section 10.11. The second-opinion review reports that the PDF was inaccessible to it as well and relies on no theorem that appears only there |
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
| Don, Fehr, Majenz, Schaffner, *Efficient NIZKs and Signatures from Commit-and-Open Protocols in the QROM*, CRYPTO 2022. <https://arxiv.org/abs/2202.13730> | Part. The second-opinion review cites its Definition 3.4 and the hypotheses of Theorems 4.2 and 5.2 for the limits of online extractability (section 7.1) **[R]** |
| Grilo, Hövelmanns, Hülsing, Majenz, *Tight Adaptive Reprogramming in the QROM*, ASIACRYPT 2021. <https://arxiv.org/abs/2010.15103> | Part. The second-opinion review cites its Theorem 1 for the form of the reprogramming bound and its need for location bounds (section 7.1) **[R]** |
| Chiesa, Manohar, Spooner, *Succinct Arguments in the Quantum Random Oracle Model*, TCC 2019, ePrint 2019/834. <https://eprint.iacr.org/2019/834> | Abstract |
| Chiesa, Fenzi, *zkSNARKs in the ROM with Unconditional UC-Security*, TCC 2024, ePrint 2024/724. <https://eprint.iacr.org/2024/724> | Abstract |
| Chiesa, Di, Hu, Zheng, *How to Prove Post-Quantum Security for Succinct Non-Interactive Reductions*, EUROCRYPT 2026, ePrint 2025/2166. <https://eprint.iacr.org/2025/2166> | Abstract |
| Unruh, *Non-Interactive Zero-Knowledge Proofs in the Quantum Random Oracle Model*, EUROCRYPT 2015, ePrint 2014/587. <https://eprint.iacr.org/2014/587> | Abstract |
| Unruh, *Post-Quantum Security of Fiat-Shamir*, ASIACRYPT 2017, ePrint 2017/398. <https://eprint.iacr.org/2017/398> | Abstract |
| Liu, Zhandry, *Revisiting Post-Quantum Fiat-Shamir*, CRYPTO 2019, ePrint 2019/262. <https://eprint.iacr.org/2019/262> | Abstract |
| Kosuge, Xagawa, *New Security Proofs of MPC-in-the-Head Signatures in the QROM*, ePrint 2025/1999. <https://eprint.iacr.org/2025/1999> | Abstract |
| Kiltz, Lyubashevsky, Schaffner, *A Concrete Treatment of Fiat-Shamir Signatures in the Quantum Random-Oracle Model*, EUROCRYPT 2018. <https://www.iacr.org/archive/eurocrypt2018/10822196/10822196.pdf> | Not read by us; cited by the second-opinion review (Theorem 3.1, its deterministic extension and section 4.4; section 8.8) |
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
