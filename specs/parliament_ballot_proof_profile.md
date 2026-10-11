# Parliament ballot proof profile: evaluation record

Status: evaluation of 2026-10-11 against
[parliament_private_ballot_design.md](parliament_private_ballot_design.md)
(the "ballot design") at source baseline `fd8d296670` plus the working-tree
revision of the ballot design that states the sealed-list contract. **No
profile is selected. Nothing is qualified.** The construction to develop is
decided (section 6): a two-SHAKE proof over the public sealed list, in a
VOLE-in-the-head backend derived from FAEST v3.0. A standalone experimental
implementation is in progress in `crates/iroha_zkp_vole` (the backend) and
`crates/iroha_parliament_ballot_proof` (the ballot relations). It is wired into
nothing, and this record contains no measurement of it: every size and time
below is a calculation or an estimate and is labelled as such. Binding
Parliament governance, and every capability that depends on it, stays no-go.
Schemas and Core integration (ballot design section 12.2, steps 3 and 4) remain
blocked by the selection rule of step 2 (section 11.1), whose conditions 2 and
3 do not hold. `parliament_binding_ballot_available()` stays false until the
owner records qualification.

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

`P`, `profile_id`, `sk`, `C`, `L`, `R`, `B`, `S`, `scope`, `nf`, `m`, `m_reg`,
`pi_reg` and `pi_vote` are as in ballot design section 3.1. Further terms:

| Term | Meaning |
| --- | --- |
| VOLE-in-the-head | The proof family of the FAEST signature: a GGM-tree vector commitment, small-field VOLE correlations, a QuickSilver constraint check and Fiat–Shamir |
| `lambda`, `tau`, `w_grind`, `T_open`, `d_zk` | FAEST security parameter, number of small-VOLE instances, grinding bits, GGM opening threshold, maximal constraint degree |
| `l` | Number of committed witness bits of a relation |
| QROM | Quantum random-oracle model |
| Public-list membership | The verifier holds the validated list of the `S` sealed commitments and the proof selects one of them, instead of proving a Merkle path inside the relation |
| `P16` | The 16-byte domain identifier of the experimental construction (section 6.1) |
| Fast row, small row | The two measurement parameter rows of section 8.6 |
| BHT, CNS | The Brassard–Høyer–Tapp and Chailloux–Naya-Plasencia–Schrottenloher quantum collision algorithms |

## 2. What a profile must provide

A profile `P` fixes every hash, PRF, field, domain tag, canonical list and
preimage encoding, digest length and proof parameter and instantiates the
abstract functions of ballot design section 3.1:

```text
B       = BodyContextDigest_P(body_context)
C       = CredentialCommit_P(body_context, sk)
nf      = NullifierPRF_P(sk, scope)
R       = SealedListDigest_P(B, S, L)
pi_reg  = Registration_P(sk; C, m_reg)
pi_vote = Ballot_P(sk, selector; B, L, m)
```

with `m_reg = (network_id, authority, assignment_id, governance_attempt_id,
election_attempt_id, body_role, B, C, profile_id)` (section 3.2) and
`m = (scope, R, S, nf, vote, policy_hash, profile_id)` (section 3.5). `sk` is
one high-entropy secret; every derived secret is a constrained derivation of
it; `pi_reg` and `pi_vote` use distinct transcript domain tags (section 3.1).
`L` is the `S` sealed commitments in strictly increasing bytewise order,
without padding. The finalized block data of the seal carries its bytes. A
verifier of `pi_vote` holds a validated list or an immutable verification
context authenticated to that seal (sections 3.3 and 3.5) **[C]**.

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
8. **Registration authorization.** Establish adaptive multi-user
   credential-origin unforgeability in the QROM against malicious registrations
   and corrupt credentials, with access to both honest proof types. An
   adversary cannot authorize an uncorrupted honest credential under a fresh
   registration message, including recontextualization into another body. Joint
   zero knowledge is required. Simulation-extractability is sufficient but is
   not required by this item.

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

The decisions of section 10.1 were taken by the same reviewer, in a second
pass that the owner delegated on 2026-10-11. That pass reports reading the
requested records and the relevant implementation paths, consulting a further
model and checking primary sources; it edited no file and ran no build
**[R]**. Its decisions are design decisions. They are not security proofs,
they are not an independent review of this record, and they select and qualify
nothing.

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
| VOLE-in-the-head, two-SHAKE public list | Commitment and nullifier both SHAKE256 inside the relation; 384-bit `sk`; no AES in the relation; flat digest of the public sealed list (section 6) | SHAKE256 as the modelled oracles in its two uses; the backend's PRG and commitment assumptions, with AES-based PRGs in the initial implementation **[R]** | **[R][D]** `pi_vote` 108,586 B (small row) and 158,796 B (fast row); `pi_reg` 60,010 B and 85,932 B (section 9.7). **[D]** The earlier 96-byte-commitment shape: `pi_vote` 81,834–316,668 B at `lambda` = 256 (section 9, V3). **[U]** a SHA-3 component inside VOLE-in-the-head is reported implemented (ePrint 2026/109) | The construction to develop (section 6). Not selected and not qualified. Largest witness of the three public-list variants; no additional credential assumption |
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
identifies this experimental construction; the eventual normative profile
descriptor must also fix the complete backend parameter tuple, and benchmark
parameter rows have distinct transcript identities **[R]**. The ballot proof is
FAEST-derived. It is not a standard FAEST signature, and fixing the relation
does not claim that the custom proof inherits FAEST's signature theorem
**[R]**. Sections 6.1 to 6.4 state the construction as decided by the
second-opinion review (section 10.1); every definition in them is **[R]**
unless marked otherwise.

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
- `Enc` is the pinned canonical Norito encoding of the specified typed value.
  Stored and wire records use header-framed Norito. `Frame` is a cryptographic
  preimage definition, not an alternative wire codec.
- Layout flags, field order and length bounds are fixed. Alternative
  encodings, trailing bytes and non-canonical values are rejected.
- Fixed integers are little-endian. Votes are exactly `0 = Aye`, `1 = Nay`,
  `2 = Abstain`.
- Keccak lane and bit conventions follow FIPS 202. Backend field conventions
  follow the pinned backend specification.
- **Role audit of 32-byte values.** An opaque, authenticated state identifier
  need not become wider merely because it has 32 bytes. A collision-sensitive
  content fingerprint must become 64 bytes or be replaced in the binding by
  its canonical preimage. Hashing an ambiguous 32-byte fingerprint again does
  not repair it. The audit has not been carried out.

### 6.2 Commitment, nullifier, list and messages

```text
sk = 48 uniformly random bytes, fresh for each body

C  = SHAKE256("PCR1" || P16 || sk[48] || B[64],     128 bytes)
nf = SHAKE256("PNF1" || P16 || sk[48] || scope[64],  64 bytes)

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
    B, C, P16
)

m = (scope, R, S, nf, vote, policy_hash, P16)
```

- `sk` is 384 bits, `C` is 1,024 bits, and `nf`, `R`, `B`, `scope`,
  `policy_hash` and `proposal_digest` are 512 bits.
- Both SHAKE256 inputs are exactly 132 bytes: 4 + 16 + 48 + 64 **[D]**. Each
  output fits the 136-byte SHAKE256 rate, so each evaluation needs one
  Keccak-f[1600] permutation. Standard SHAKE padding and bit ordering apply
  (FIPS 202).
- The commitment depends on the body context through `B`; the nullifier
  depends on the full scope and is independent of the vote. Both are
  constrained inside the relation. There is no AES in the relation.
- `L` has exactly `S` entries. There are no padded credential leaves, no leaf
  or node hashing and no tree.
- In the experimental construction `P16` stands where the ballot design's
  messages carry `profile_id`.

### 6.3 Relations, selector and transcript

| Proof | Public input | Witness and conditions |
| --- | --- | --- |
| `pi_reg` | Complete `m_reg`, authoritative body context and fixed profile parameters | `sk`; constrained Keccak states; recompute `C` exactly |
| `pi_vote` | `B`, validated `L`, complete `m`, fixed profile parameters | `sk`, two selector vectors, constrained Keccak states; select one real commitment, recompute that commitment and `nf`, require a valid public vote |

Core separately checks registration authority, invitation and assignment
eligibility, freshness, uniqueness and the sealed subset. Those checks are not
facts proved by `pi_reg`.

**Selector.** Two 32-entry vectors `a` and `b`. For each vector `x`:

```text
x_j * (x_j - 1) = 0                    for every j
x_j * (sum_{k<j} x_k) = 0              for every j
sum_j x_j = 1
```

Then:

```text
sum_{i<S} a_floor(i/32) * b_(i mod 32) = 1

Commit(sk, B)[t] =
    sum_{i<S} a_floor(i/32) * b_(i mod 32) * C_i[t]
                                                for every commitment bit t
Nullifier(sk, scope) = nf
```

- **The prefix form is one-hot in characteristic two.** Boolean entries plus
  "sum equals one" alone enforce odd parity, not one-hotness: three active
  entries pass, and a multiplexer would then select the XOR of three
  registered commitments, which is not a registered entry **[D]**. In the
  prefix form the second active entry of a vector sees a prefix sum of exactly
  one, so its constraint fails; no second active entry can exist **[D]**. The
  first active entry prevents every later one. The form needs no extra prefix
  witnesses.
- **No selection beyond `S`.** The sum over `i < S` equals one only if the
  selected pair indexes a position below `S`. Every unused selector position is
  excluded.
- **No selected-commitment witness.** The final commitment-output polynomials
  are equated directly to the degree-two selector expression.
- **Keccak grouping.** Forward-only two-round groups. The maximum relation
  degree is four. The first implementation keeps the backend's degree-seven
  masking configuration.

**Transcript binding:**

- `REG` and `VOTE` have separate hash and randomness namespaces.
- The construction identifier, the complete parameter descriptor, the relation
  identifier, `B`, the complete public statement and the complete message are
  bound into `mu`. In FAEST the statement and the message enter the challenge
  chain only through `mu` **[P]** (FAEST v3 Figure 8.2).
- For voting, the statement includes the canonical list bytes, although their
  digest is also in `m`.
- The v3 challenge chain is preserved, including `iv = H4(ivpre || mu)`.
- Every backend hash is domain-separated by construction, parameter row,
  relation and hash role.
- Proof randomness is fresh. Deterministic testing means deterministic given an
  explicit random tape.

Domain separation is necessary; it is not itself a joint-security proof
**[R]**.

A point from this evaluation's own primary reading that the construction does
not resolve: FAEST's QROM proof restricts the key space (`k[0]·k[1] = 0`,
enforced in key generation and inside the relation) so that a random public
key has no preimage with probability at least 1/4 **[P]** (FAEST v3
section 10.7, Lemma 10.50). The construction has no AES key and no equivalent
restriction. An argument that reuses the lossy-key step needs another source
of lossiness **[D]**.

### 6.4 Public-list verification contract

The proof hashes no Merkle path. `R` is the flat digest of section 6.2. The
1,024-position tree, leaf hashing, internal-node hashing, padding and path
witnesses of the earlier design are deleted **[R]**.

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

## 7. Gate-by-gate status

Status classes: **(a)** an applicable theorem as is; **(b)** a short new
argument; **(c)** substantial new proof work; **(d)** an assumption about a
concrete primitive. No gate of either route has an unconditional (a).

### 7.1 Construction to develop

"Completable now" is the second-opinion review's assessment of what a written
argument can establish today **[R]**. "Remains" adds what primary-source
reading established. An argument counts only under the standard of
section 11.1.

| Gate | Argument route | Completable now | Remains |
| --- | --- | --- | --- |
| 1 Authorization | Quantum knowledge authorization for the actual registration, list and nullifier relation | Relation and selector correctness | Research, class (c). Ordinary soundness proves a statement true, not that its producer knows the credential. FAEST's QROM proof reduces to soundness and deliberately avoids extraction **[P]** (v3 section 10.7). Its soundness lemma is stated for static adversaries **[P]** (Lemma 10.49) |
| 2 Unforgeability | Adaptive chosen-message security with malicious registrations, corrupt members and both honest proof types | The exact game | Research, class (c): the custom adaptive unforgeability reduction. FAEST's theorem is for one honestly generated key **[P]** (Theorem 10.53). In a list relation the statement stays true through the adversary's own entries, so the lossy-key step does not apply directly **[D]** |
| 3 Nullifier uniqueness | Associate every newly authorized nullifier with a controlled credential; then commitment binding and deterministic nullification | The deterministic-nullifier lemma and a conditional `k`-credential argument | Completion depends on the authorization and binding premises: gates 1 and 2, and binding of the SHAKE commitment (section 8.4) |
| 4 Unlinkability, non-frameability | Simulation hybrids over the commitment and nullifier oracles | Conditional unlinkability and non-frameability hybrids | Completion depends on gates 2 and 5 and on the primitive analysis of the two SHAKE uses, class (d) for concrete SHAKE |
| 5 Joint quantum ZK and anonymity | One adaptive multi-theorem simulator for both relations, public registrations, adversarial credentials, the same secret and oracles | The exact joint privacy game | Research, class (c): the adaptive joint simulator and its quantitative reprogramming bound. Distinct transcript tags do not establish it. The claim must exclude later disclosure of a challenge credential, which recomputes its nullifier by design |
| 6 Concrete security | Arithmetic over the bounds of gates 1, 2, 5 and 8 against the contract of section 8.8 | The target and the arithmetic framework | No successful full ledger today (section 8.5) |
| 7 Bounded deterministic verification | Canonical decoding, allocation and work bounds, malformed-input behaviour, hardware parity | A complete design argument is feasible now | Implementation evidence. The experimental implementation is in progress and none of its results is recorded here |
| 8 Registration authorization | Adaptive cross-relation credential-origin unforgeability (section 7.3) | The exact replacement game | Research, class (c): the cross-relation unforgeability reduction. Simulation-extractability would suffice, and no QROM simulation-extractability theorem covering VOLE-in-the-head was found in the sources read **[P]** (section 13 lists their coverage) |

The published FAEST work supplies important ingredients, not these complete
custom-scheme arguments **[R]**. No gate is known to be impossible in
principle; several cannot honestly be marked complete with present knowledge
**[R]**. The review states that it can write and check the arguments in a
follow-up against the exact protocol, and that it cannot promise the missing
theorems can be established **[R]**.

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

**[R][D]** Worked at the floor of section 8.8. On the fast row
`tau + d_zk = 40`, so the quadratic term with its maximum prefactor is
`40 · (tau + d_zk) · Q^2 / 2^lambda = 40 · 40 = 1,600` at `Q = 2^128`. The
published bound is vacuous there. This is not evidence of an attack.

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

- **Adversarially registered entries.** The theorems are single-user games with
  the key produced by the challenger; the proof replaces that honest key by a
  random one **[P]** (v3 section 10.7). Nothing covers adversarially chosen or
  multiple public keys.
- **The ring relation.** The lossy step makes FAEST's single statement false.
  A ballot statement stays true through the adversary's own entries **[D]**.
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
  universal-hash errors under those limits. Both proofs of the construction
  exceed them: `l` = 17,984 and 35,648 (section 9.7). **[D]** From the proofs'
  own expressions the VOLE-hash error grows by a factor of about 2^7.0 at
  `l` = 18,912, 2^8.7 at 23,712 and 2^12.9 at 42,912; the constraint-hash term
  is unaffected in practice. The factors at the construction's two witness
  lengths, and their propagation into the soundness bound, have not been
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
`2^(k/2)/sqrt(S)` oracle evaluations for a `k`-bit secret. For a 256-bit
secret that is about 2^123 at `S = 1,000` **[D]**, below the floor of
section 8.8. For the construction's 384-bit secret it is about 2^187 **[D]**.
The 384-bit credential removes the immediate multi-target sizing problem of a
256-bit secret **[R]**. Wider commitments do not increase key entropy.
Translating evaluations into quantum gates needs an explicit calculation.

Lengths per role in the construction **[R]**:

| Role | Length |
| --- | ---: |
| Credential secret | 384 bits |
| Credential commitment `C` | 1,024 bits |
| `nf`, `R`, `B`, scope, policy digest, proposal-content digest | 512 bits |
| Construction identifier | 128-bit literal identifier; not a collision-security claim |
| Transcript message digest at the measurement row | 512 bits |
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
For the construction, an ideal random map from 384 bits to 1,024 bits in a
fixed context has about 2^-257 expected colliding key pairs **[R][D]**. Neither
the key-search calculation of section 8.3 nor this one proves the concrete
scheme secure: adaptive context selection and SHAKE's concrete sponge
construction must be addressed **[R]**.

### 8.5 Why no parameter tuple can be certified today

- No theorem covers the list relation, adversarial registrations, the joint
  simulator or the registration proof (section 7).
- The one published QROM bound, applied to plain FAEST, is vacuous at the
  contract's floor of 2^128 queries on the fast row and reaches about 2^123
  queries at `lambda` = 256 (section 8.1). Chosen-message losses make the
  lifetime calculation more demanding still **[R]**.
- That theorem does not directly cover this relation, its enlarged witness or
  the complete implemented grinding behaviour **[R]** (section 8.2).
- Both witnesses are outside the stated hypotheses of the universal-hash
  lemmas (section 8.2).
- The quantitative, domain-separated QROM analysis of the commitment and
  nullifier uses of SHAKE256 is not written. Adaptive context selection and
  SHAKE's concrete sponge construction must be addressed in it **[R]**
  (section 8.4).
- The metric and lifetime envelope are fixed (section 8.8). No ledger computed
  against them exists.

The second-opinion review states that there is no presently justified tuple it
can designate as satisfying the contract **[R]**. This record agrees. The
approximate 123-bit key-only calculation is not a lifetime security
certificate. A hypothetical wider-field, wider-seed, SHAKE-PRG backend is new
protocol research, not a change of `lambda` to 384 **[R]**. Gate 6 stays closed
until an actual construction and ledger meet it.

### 8.6 Measurement rows

Decided **[R]** for measurement only. Neither row is a security claim or a
selection. They are harness alternatives; the released protocol eventually
accepts exactly one qualified row.

| Row | `lambda` | `tau` | `w_grind` | `T_open` | `d_zk` |
| --- | ---: | ---: | ---: | ---: | ---: |
| First: fast | 256 | 33 | 8 | 229 | 7 |
| Comparison: small | 256 | 22 | 6 | 225 | 7 |

| Role | Experimental choice |
| --- | --- |
| Credential master secret | 384 uniformly random bits |
| Credential commitment `C` | SHAKE256, 1,024 output bits |
| Nullifier `nf` | SHAKE256, 512 output bits |
| Sealed-list digest `R`, body-context digest `B` | SHA3-512 |
| Keccak witness | States committed after rounds 2, 4, ..., 22; rounds 23 and 24 evaluated forward with the exposed output bits constrained |
| Not used at first | Inverse-chi grouping; degree-14 masking |
| Proof-system internals | The role-specific lengths of section 8.3 |

The custom relation's degree, masks and checks are recalculated for the actual
constraint implementation. The reference tuple is not a transferable theorem.
The small row is chosen only if it supplies a useful resource trade-off and
then meets the same security gate **[R]**.

### 8.7 Anonymity is computational

**[D]** `C` and `nf` are deterministic functions of `sk` (ballot design
section 3.1), `C` is public at registration and `nf` is public in the ballot.
An unbounded adversary can search for the `sk` that opens each registered `C`
and recompute its nullifier in every scope. No profile that instantiates
section 3.1 can therefore give statistical anonymity; this is a property of
the ballot design, not of the construction. Ballot design section 4 already
scopes ballot anonymity as resting on "the post-quantum primitives of `P`"
**[C]**.

For the construction those primitives are: SHAKE256 behaving sufficiently like
the modelled oracles in its commitment and nullifier uses, which remains an
explicit primitive assumption; the backend's PRG and commitment assumptions,
with AES in the initial measurement implementation; and zero knowledge of the
proof system in the QROM (gate 5, not proved) **[R]**. Ballots and
registrations stay on chain permanently, so a later break of any of these
identifies past voters retrospectively **[E]**. The archive horizon of
section 8.8 covers that exposure. Changing profiles does not erase it **[R]**.

### 8.8 Security contract and lifetime envelope

The stated reading of gate 6 **[R]**; ballot design section 5 carries it
**[C]**. The literal query-security floor is retained.

| Quantity | Requirement |
| --- | ---: |
| Computational break | Forgery success ≥ 1/2, or anonymity distinguishing gap ≥ 1/2 |
| Required work for a break | At least 2^128 total quantum queries to modeled primitives and oracles |
| Accounting | Deployment-wide, including reduction overhead and all targets |
| Archive horizon | 100 years per network and profile instance |
| Body scopes | At most 2^24 |
| Sealed seats per body | At most 1,000 |
| Registrations, including alternates | At most 2^34 |
| Honest prover transcripts per credential | At most 2^10, counting fresh proof generations |
| Total registration plus ballot transcripts | At most 2^44 |
| Accepted ballots | One per credential and body |
| Unconditional statistical bad-event budget | At most 2^-128 over the lifetime |

- Repeated transmission of identical proof bytes is not a new prover
  transcript.
- The ceilings are analysis ceilings, not new consensus lifetime counters.
  Exceeding one requires reassessment.
- A gate-depth metric is not substituted to rescue a row without the
  corresponding reversible-circuit, parallelism, depth and reduction analysis.
- **No parameter tuple is certified under this contract** (section 8.5). The
  fast row of section 8.6 is implemented as the first measurement row only.

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
  output adds permutations. The construction of section 6 has a 132-byte input
  and a 128-byte output, still one permutation per evaluation **[D]**.
- The selected 768-bit commitment is committed as witness and bound by a
  degree-2 multiplexer over the public list.

### 9.3 Variants

| Variant | Relation |
| --- | --- |
| V1 | AES-only published shape transplanted onto a v3 backend: commitment of 2 / 4 / 4 blocks, CBC-chain tag of 2 / 3 / 4 encryptions with a 128-bit output, per-member gated last-round constraints |
| V2 | The hybrid: six-block AES-256 commitment with a public SHAKE256 mask, and a SHAKE256 nullifier in the relation (compared alternative, section 4) |
| V3 | Two-SHAKE public list in the earlier projection shape: 256-bit `sk` and a 96-byte commitment. The construction of section 6 differs (384-bit `sk`, 128-byte commitment); its counts are in section 9.7 |
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
| Construction `pi_vote` (section 9.7), 256f | 15.6 | 25 ms | 86 ms | 1.1 s |
| Construction `pi_vote` (section 9.7), 256s | 15.4 | about 190 ms | about 0.7 s | about 2.8 s |

The two construction rows use the same scaling, with a VOLE length of the
witness length plus 80 bits (256f) or 120 bits (256s) **[D]**. Their 256s
figures are back-derived from this table's rounded V2 (c) entry. None of these
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

### 9.7 Analytical counts for the two measurement rows

Derived, not measured. The witness lengths and sizes are reported by the
second-opinion review **[R]** and reproduce under the working form of
section 9.1 **[D]**: for example `pi_vote` on the fast row is
11,748 + 33 × 35,648 / 8 = 158,796. They assume the Keccak grouping of
section 8.6: 11 committed states of 1,600 bits, 17,600 bits per permutation.

| Proof | Witness bits | Fast row, proof bytes | Small row, proof bytes |
| --- | ---: | ---: | ---: |
| `pi_reg` | 384 + 17,600 = 17,984 | 85,932 | 60,010 |
| `pi_vote` | 384 + 35,200 + 64 = 35,648 | 158,796 | 108,586 |

These exclude statement and envelope framing. They are regenerated from the
actual constraint implementation, and the universal-hash bounds are re-derived
for the larger witness and constraint count **[R]**.

Thresholds **[R]**. The same hard limits apply at every roster size and to
both proofs:

| `S` | Complete canonical proof envelope | Uncached validator verification | Verifier workspace | Phone proving | Phone peak prover memory |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 3 | ≤ 262,144 B | ≤ 250 ms | ≤ 64 MiB | p95 ≤ 10 s | ≤ 256 MiB |
| 500 | ≤ 262,144 B | ≤ 250 ms | ≤ 64 MiB | p95 ≤ 10 s | ≤ 256 MiB |
| 1,000 | ≤ 262,144 B | ≤ 250 ms | ≤ 64 MiB | p95 ≤ 10 s | ≤ 256 MiB |

- The ballot envelope size includes its proof, public fields, stamp and
  framing. Shared seal and list evidence is separate, capped at 160 KiB
  (163,840 B **[D]**) for the list-context object.
- Verification measurements include fresh list decoding and digest
  validation, transcript preparation and late-invalid proofs. They exclude
  network and disk retrieval. Memory includes list and transcript buffers.
- **Cold-input total at `S = 1,000`.** The fast `pi_vote` proof plus the raw
  list alone is 158,796 + 128,000 = 286,796 bytes, before other framing
  **[R][D]**. The 256 KiB envelope limit is not a claim that all cold
  verification inputs fit inside 256 KiB. On the small row the same sum is
  108,586 + 128,000 = 236,586 bytes **[D]**.

### 9.8 Against the section 5 limits

| Limit | Status |
| --- | --- |
| Proof envelope ≤ 256 KiB | The fast `pi_vote` proof object is projected at 158,796 B, 61% of the limit, before public fields, stamp and framing **[D]**. Not measured |
| Verification ≤ 250 ms on the minimum validator baseline | Cannot be judged. The baseline is named (section 11.4) but no run on it exists. The illustrations of section 9.5 are for other machines **[E]** |
| Verifier workspace ≤ 64 MiB | Not projected |
| Phone proving p95 ≤ 10 s | Cannot be judged without runs on the baseline phones. Scaled anchors suggest a wide margin **[E]** |
| Phone prover memory ≤ 256 MiB | Not projected |

## 10. Decisions

### 10.1 Decisions taken

On 2026-10-11 the owner delegated the open decisions of this record to the
second-opinion review, under the instruction that this is the first release,
backward compatibility is not needed and the best design is chosen. Each row is
a design decision of that review **[R]**. None is a security proof, a profile
selection or a qualification.

| Item | Decision | Stated in |
| --- | --- | --- |
| Construction | Two-SHAKE public-list construction with a flat commitment to the sealed ordered list, as the single construction to develop. The earlier hybrid recommendation is changed: avoiding its extra credential assumptions is worth the projected increase in proof size. No security-qualified normative profile is selected | Section 6 |
| Security metric and lifetime envelope | The literal 2^128 quantum-query floor through the actual reduction, with deployment-wide accounting and a 100-year archive horizon. No parameter tuple is certified | Section 8.8; ballot design section 5 |
| Public-list verifier and evidence contract | Flat digest of the ordered list; the list bytes are published in finalized block data at seal; every verifier holds a validated list or an immutable context authenticated to the seal | Section 6.4; ballot design sections 3.1, 3.3, 3.5, 3.8, 3.9 and 12.2 |
| Gate 8 wording | Adaptive cross-relation registration unforgeability replaces simulation-extractability. Gate 1's knowledge requirement stays a separate obligation | Section 7.3; ballot design sections 3.2 and 5 |
| AES binding assumption | Not made a dependency. Multi-key injectivity of `k -> AES_k(p_0) \|\| ... \|\| AES_k(p_5)` does not follow from single-key PRP security. It leaves the normative candidate with the hybrid | Section 4 |
| Keyed-SHAKE assumption given the AES commitment | Not made a dependency; it leaves with the hybrid. The two-SHAKE construction instead needs a quantitative, domain-separated QROM analysis of its commitment and nullifier uses, with concrete SHAKE as an explicit primitive assumption | Sections 4 and 8.7 |
| Arithmetisation-oriented hash | Not admissible in this profile, in its commitments or its transcript. Algebraic universal hashes inside the proof protocol are a different category, subject to their proved error bounds | Ballot design section 5 |
| Hardware baselines | Intel Xeon Silver 4310 (one physical core, base frequency), Pixel 6a and iPhone SE third generation. The portable scalar path must be correct and bounded; it need not meet 250 ms | Section 11.4; ballot design section 5 |
| Proof work | The written-argument standard of section 11.1. Complete reductions may await independent review; missing reductions may not. The review states that it can write and check the arguments in a follow-up, with no assured outcome | Sections 7.1 and 11.1 |
| What selection requires | Profile selection is distinguished from activation qualification. Selection needs complete internal evidence; independent review and the validator and phone launch measurements may remain enumerated obligations | Section 11.1; ballot design section 12.2 step 2 |
| Standalone implementation | An in-tree, standalone experimental implementation, following FAEST specification v3.0. The owner authorised it, the download of the official test vectors and the patching of dependencies | Sections 11.2 and 11.3 |
| Placement and dependencies | VOLE-in-the-head is a distinct mathematical family with exactly one reusable owner crate, `crates/iroha_zkp_vole`. The pinned `aes` 0.8.4 dependency is minimally patched to expose portable types and to put hardware dispatch behind a positive feature | Section 11.2; [zk_delivery_plan.md](zk_delivery_plan.md), "Shared proof backend and complete IVM proof" |
| Draw seed | Attempt identity stays out of the ranking seed | Ballot design section 9 |
| Idle-chain latency and casting clock | Bounded native-slot progress, casting-clock due work and late processing as requirements on the SCCP-owned governance clock; `parliament_sccp_attempt_latency_ms()` is `None` until a qualified bound exists | Ballot design sections 9 and 11; wording owned by [sccp.md](sccp.md) |

Whether computational anonymity is acceptable is not a separate decision:
section 8.7 shows it follows from ballot design section 3.1 for every profile.

### 10.2 Still requiring the owner

The owner has authorised downloading the official test vectors and patching
dependencies. Two items remain:

1. **Access to the named hardware.** Any access or expenditure needed for the
   validator and phone measurements on the baselines of section 11.4. Until
   then those launch measurements remain open.
2. **The qualification record.** The eventual record of activation
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
3. The actual lifetime ledger meets the contract of section 8.8.
4. The standalone prover and verifier implement that exact protocol and pass
   meaningful adversarial and component checks.
5. Complete envelope sizes, deterministic work and allocation bounds and
   measurements at all three roster sizes are recorded.
6. All remaining independent review, external conformance, hardware, phone,
   lifecycle and network qualification obligations are enumerated.
7. `parliament_binding_ballot_available()` remains false.

**The present record fails conditions 2 and 3, so production schemas and Core
integration do not start.** Condition 1 does not hold either: the relation is
chosen but no parameter row is frozen. Conditions 4 and 5 are in progress
**[E]**.

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

| Area | Modules |
| --- | --- |
| Backend | `params`, `field`, `prg`, `bavc`, `vole`, `crt`, `universal_hash`, `quicksilver`, `transcript`, `codec`, `randomness`, `allocation`, `arch` |
| Ballot | `profile`, `context`, `credential`, `sealed_list`, `selector`, `registration_relation`, `vote_relation` |

- **Reuse.** The pinned `sha3`, Norito, `zeroize` and the existing randomness
  interfaces. `aes` 0.8.4 supplies the full-block backend PRGs, without a
  dependency on `iroha_sccp_rpc` to reach it.
- **No new AES.** No new production AES implementation with exposed round
  states is written. The relation has no AES witness.
- **AES dependency patch.** Unmodified `aes` 0.8.4 uses x86 hardware
  autodetection and does not expose the feature-controlled portable API needed
  here. The pinned dependency receives a minimal, provenance-preserving patch:
  explicit portable AES types; hardware modules and dispatch behind a positive
  Cargo feature; the constant-time software fallback kept; the backend's
  acceleration feature selects the accelerated provider; without it the
  portable types are selected explicitly, despite Cargo feature unification.
  AES arithmetic and key expansion are not changed. No runtime environment
  toggle is substituted.
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

Self-generated fixtures do not establish independent conformance **[R]**. The
official FAEST v3.0.2 test vectors are available under the MIT licence and are
used for component and full-signature conformance of the backend **[U]**
(reported by the implementation work; not verified by this record).
Bidirectional cross-verification with a pinned official implementation remains
to be added **[R]**.

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
  grinding-retry distribution;
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
labelled experimental **[R]**.

The construction is switched when the final security argument fails, or when
the secure implementation exceeds a hard limit after straightforward grouping
and streaming work. A narrow standard-hash STARK is then evaluated under the
same requirements. Digests are not shortened, the security metric is not
weakened and limits are not raised silently. If the two-SHAKE construction
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

- The exact relations, encodings and domain separation of section 6,
  including the prefix-form selector, the exclusion of positions at or beyond
  `S`, and the transcript binding of the list bytes.
- A written argument for each of the eight gates under the standard of
  section 11.1, with the game definitions, for both proofs under one `sk`.
- Applicability of the QROM Fiat–Shamir analysis to the actual protocol:
  adaptive statements, adversarially registered entries, grinding and the
  retry loop, the unmodelled detail, and the re-derived universal-hash errors
  for witnesses beyond the published limits.
- The concrete security ledger against the contract of section 8.8: every
  reduction loss, statistical error and its accumulation, multi-target use,
  and the length of every role in section 8.3.
- The role audit of existing 32-byte values (section 6.1).
- The primitive assumptions: SHAKE256 as the modelled oracles in its
  commitment and nullifier uses, including adaptive context selection and the
  concrete sponge; the backend's PRG and commitment assumptions.
- The public-list contract, the publication of the list at seal and its effect
  on independent full verification (section 6.4).
- The arithmetic of this record that has had one reader only: section 8.1's
  chosen-message terms, the Keccak grouping of sections 8.6 and 9.2, the
  counts of section 9.7 and every `d_zk = 14` figure.
- The implementation: conformance to the pinned specification, bounded and
  deterministic verification, identical results across hardware,
  malformed-input behaviour, constant-time and randomness handling in the
  prover, and the patch to the pinned `aes` dependency. Source inspection alone
  does not establish resistance to physical side channels **[R]**.

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
| NIST, *FIPS 202: SHA-3 Standard*. <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf> | Not read by us; cited by the second-opinion review |
| FAEST official specifications and resources. <https://faest.info/resources.html> | Not read by us; cited by the second-opinion review |
| FAEST official test vectors, version 3.0.2, MIT licence | Not read by this record; used by the implementation work (section 11.3) |
| Intel, Xeon Silver 4310 specifications. <https://www.intel.com/content/www/us/en/products/sku/215277/intel-xeon-silver-4310-processor-18m-cache-2-10-ghz/specifications.html> | Not read by us; cited by the second-opinion review |
| Google, Pixel phone hardware specifications. <https://support.google.com/pixelphone/answer/7158570> | Not read by us; cited by the second-opinion review |
| Apple, iPhone SE (3rd generation) technical specifications. <https://support.apple.com/en-ie/111866> | Not read by us; cited by the second-opinion review |

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
