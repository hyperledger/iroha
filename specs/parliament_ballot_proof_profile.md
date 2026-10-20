# Parliament ballot proof profile: evaluation record

Status: evaluation as of 2026-10-13 against
[parliament_private_ballot_design.md](parliament_private_ballot_design.md)
(the "ballot design") at source baseline `485d392e62` plus the working tree.
It incorporates the thirteen texts of the second-opinion review (section 3).
**No profile is selected. Nothing is qualified.**

**Current engineering order:** the owner's 2026-10-18 authorization in ballot
design section 12.2 supersedes this evaluation's earlier preselection sequencing.
Real-candidate schemas, integration and development tests may proceed alongside
B6. The selection dossier and production activation requirements remain unmet;
historical review decisions and evidence below retain their original scope.

The construction to develop is decided (section 6). This record calls it the
frozen construction: a proof over the public sealed list in a
VOLE-in-the-head backend derived from FAEST v3.0, with a fresh 256-bit pad in
the witness. The registration relation has two SHAKE256 evaluations under the
credential secret: the commitment and the registration authorization value.
The vote relation `R_vote+` has three: the commitment, a 1,024-bit nullifier
and a vote authorization value. The backend carries a role prefix on every
hash call and four extensions decided by the review **[R]**: a fresh 256-bit
public salt in every proof, the salt in every `H5` input, a counter range of
`2^20`, and a 112-byte leaf commitment with an affine checksum (sections 6.3,
6.6 and 6.7). The relations, witness layout, ordered constraints, parameter
row, descriptor, hash inputs, naked proof layout, proving tape and retry rule
are frozen by decision. The digest `D` of the descriptor is computed in this
record and independently recomputed **[D]** (section 6.1). Reference-mode FAEST,
the construction of the official test vectors, is a separate and unchanged
construction that serves conformance of the backend; nothing official covers
the extensions. The production Norito mappings, the production envelopes and
authenticated integration are later obligations and are not written
(section 11.1).

**Two weakenings stand [R].** Gate 1 is adaptive relation soundness and no
longer knowledge extraction: a genuine weakening, not an equivalent
reformulation (sections 2, 7.6 and 10.1). The security contract replaces the
earlier floor of 2^128 queries by a proven bound at 2^64 queries plus an
assessed attack cost (section 8.8). Authorization rests on gates 2, 3 and 8,
through reductions that use no extractor and that need two explicit
assumptions about the concrete SHAKE256 credential functions: pseudorandomness
with public leakage (P) and existential uniqueness (U) (section 8.4).

The written arguments are consolidated in
[parliament_ballot_proof_arguments.md](parliament_ballot_proof_arguments.md)
(the "arguments file"). Every one awaits independent review. Gates 1 to 5, 7
and 8 are conditional; gate 6 is not met (section 7.1). The written bounds
that contain the joint zero-knowledge term cannot certify an advantage of
2^-64 even with every unknown primitive term set to zero; that is a
limitation of the bounds, not an attack (section 8.5).

The [B6 arithmetic and source-hypothesis
review](parliament_ballot_b6_security_review.md) adds an executable exact/high
precision ledger and records the primary statements inspected on 2026-10-13.
It identifies unresolved generator-query, resource and model obligations.
It is not an independent human cryptographic review, primitive qualification
or owner acceptance; gate 6 and selection conditions 2 and 3 remain open.
Historical source-reading statements in this record describe the earlier
consolidation pass; the B6 document states the scope of the later check.

What exists **[C]**. The standalone implementation now follows the frozen
construction in section 6:

- `crates/iroha_zkp_vole` implements the extended backend beside reference
  mode: the salt in challenge 1 and `H5`, bounded counter, and affine-checked
  leaf. Reference mode continues to reproduce all twelve official FAEST
  v3.0.2 signatures. The extended mode has independent project-generated
  leaf and transcript vectors; these are not official FAEST vectors.
- `crates/iroha_parliament_ballot_proof` implements registration and
  `R_vote+`, including the 128-byte nullifier, `D_v`, `auth_v`, third
  permutation, final descriptor and 112-byte tape. Both roles select the
  extended backend explicitly; retired descriptors are rejected.
- The independent Python reference is retained under the ballot crate's
  `tests/reference/`, with deterministic vector-generation commands.
  Implementation checks and local measurements are tracked by the
  [completion goals](parliament_ballot_implementation_goals.md). They do not
  establish the conditional security arguments or qualify a platform.

Neither experimental crate is a dependency of Core or a node crate. No
ballot produced by these crates has governance effect.

Binding Parliament governance, and every capability that depends on it, stays
no-go. Of the selection rule of ballot design section 12.2 step 2
(section 11.1), condition 1 holds for the frozen standalone construction by
the review's decision **[R]** (that does not cover the production Norito
mappings, the production envelopes or authenticated integration), conditions
2 and 3 are not met, condition 4 has standalone implementation and component
evidence, condition 5 is not met (complete envelope, allocation and
qualification-baseline evidence remains open), condition 6's obligations
are enumerated and condition 7 holds. Schemas and Core integration (steps 3
and 4) are authorized alongside qualification under ballot design section
12.2; missing qualification evidence alone does not block development tests.
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
| `D_v` | The 512-bit digest of the complete vote statement other than `auth_v` (section 6.2) |
| `auth`, `auth_v` | The registration authorization value and the vote authorization value, each 64 bytes (section 6.2) |
| `R_vote+` | The vote relation of the frozen construction: commitment, nullifier and vote authorization value under one secret (section 6.3) |
| Pad | 256 fresh prover-random bits at witness positions `[0, 256)`. Proof coins, not a credential secret (section 6.3) |
| `mu` | The backend's message digest, into which the complete statement and message are bound (section 6.3) |
| Proving tape | The 112 fresh random bytes of one proof invocation (section 6.7) |
| Salt | 32 fresh public bytes of the proving tape, hashed into challenge 1 and every `H5` input and carried in the proof (sections 6.3 and 6.7) |
| Reference mode, ballot mode | The unchanged FAEST v3.0 backend of the official vectors, and the backend of the frozen construction (section 6) |
| P, U | The two credential-side assumptions: selective-entry pseudorandomness with public leakage, and selected-context existential uniqueness (section 8.4) |
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
auth_v  = VoteAuth_P(sk, D_v)
R       = SealedListDigest_P(B, S, L)
pi_reg  = Registration_P(sk; C, m_reg)
pi_vote = Ballot_P(sk, selector; B, L, m)
```

with `m_reg = (network_id, authority, assignment_id, governance_attempt_id,
election_attempt_id, body_role, B, C, auth, profile_id)` (section 3.2) and
`m = (scope, R, S, nf, auth_v, vote, policy_hash, profile_id)` (section 3.5).
The vote authorization value `auth_v`, its digest `D_v` and its place in `m`
are the review's decision **[R]** (section 6.2). `VoteAuth_P` is this
record's name for the abstract function; the ballot design's own text
governs the naming. `sk` is
one high-entropy secret; every derived secret is a constrained derivation of
it. Fresh proof coins that a profile carries inside its witness are not
credential secrets: no commitment, authorization value or nullifier depends on
them. `D_reg` and `D_v` are the profile's digests of the registration
statement and of the vote statement. `pi_reg`
and `pi_vote` use distinct transcript domain tags (section 3.1). `L` is the
`S` sealed commitments in strictly increasing bytewise order, without padding.
The finalized block data of the seal carries its bytes. A verifier of
`pi_vote` holds a validated list or an immutable verification context
authenticated to that seal (sections 3.3 and 3.5) **[C]**.

`P` must establish the eight properties of ballot design section 5. Item 1
below is the review's replacement text, verbatim **[R]**. Items 2 to 8 are
the design's items with the wording changes that the decision requires
applied **[R]** (table below). The ballot design's section 5 is the
normative text; where it differs from this restatement, the design governs.

1. **Adaptive relation soundness.** In the common adaptive quantum-oracle
   environment, with authenticated public contexts, malicious registrations,
   permitted corruptions and both honest proof interfaces available, every
   accepted fresh registration or ballot statement belongs to its specified
   language, except with the deployment-wide error bounded under item 6. A
   registration has a secret that opens its commitment and produces its
   registration authorization value. A ballot has a secret and exactly one
   selector position below `S` such that the selected entry of the
   authenticated sealed list is that secret's commitment, and the stated
   nullifier and vote authorization value are the specified functions of
   that same secret. Public validation enforces the permitted choice and
   complete statement encoding and binding. This is an existence
   requirement: it requires neither efficient witness extraction nor
   knowledge of the secret by the submitter. Exact-statement relaying,
   replay and proof rerandomization remain permitted, subject to admission
   and duplicate checks.
2. **Unforgeability.** Quantum chosen-message security despite observed honest
   ballots and adversarial credential registrations. The complete authorized
   statement includes the vote authorization value `auth_v`.
3. **Nullifier uniqueness.** For a fixed scope and sealed list, let `k` be
   the number of adversarially registered or corrupted sealed entries,
   including entries whose registrant knows no opening, and let the
   adversary obtain honest ballots whose nullifiers form the set `H`. Except
   with negligible probability it cannot produce valid ballots with more
   than `k` distinct nullifiers outside `H`.
   Exclusion is by nullifier, not proof encoding: same-message replay and
   rerandomization are permitted, while authorizing a different message under
   an honest nullifier remains forbidden by item 2. Separately, the nullifier is
   deterministic for a credential and scope, independent of the vote.
4. **Cross-scope unlinkability and non-frameability.** Observing other scopes
   cannot identify or impersonate an honest credential holder. The public
   auxiliary information includes the vote authorization values.
5. **Full quantum zero knowledge and anonymity.** Two requirements, each
   with its own game.
   - *Joint zero knowledge.* An adaptive multi-theorem definition covering the
     complete transcripts of `pi_reg` and `pi_vote` under the same `sk`,
     adaptive queries, public registrations and ballots with their
     authorization values, and corrupt credentials. It holds for arbitrary
     application witnesses
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
     the public commitments, both families of authorization values and the
     nullifiers under one `sk` must also be shown unlinkable.
6. **Concrete security.** A complete proven deployment-wide bound and an
   independently assessed attack cost, as read in section 8.8, including
   Fiat–Shamir losses, grinding, hash attacks and lifetime multi-target use.
   All actual proving, simulation, verification and reduction overhead is
   accounted for; an extractor, no longer required, is not.
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

The wording changes that the decision requires **[R]**:

| Item | Required change |
| --- | --- |
| 1 | Replaced by the text above |
| 2 | Chosen-message unforgeability is kept; `auth_v` is explicitly included in the complete authorized statement |
| 3 | `k` is the number of adversarially registered or corrupted sealed entries, including entries whose registrant knows no opening. The extraction-based argument is replaced by the counting argument of section 7.5 |
| 4 | Both endpoints are kept. The public auxiliary information and the unlinkability argument include `auth_v` |
| 5 | The full arbitrary-witness joint zero-knowledge requirement is preserved. Both authorization families are included in the correlated-output privacy games |
| 6 | The requirement to account for an extractor is removed, since none is required. All actual proving, simulation, verification and reduction overhead is accounted for. The numerical contract is unchanged |
| 7 | No change of the security property; dimensions and resource accounting are updated |
| 8 | The endpoint and the existing event-split argument are kept. Statements that item 1 retains a separate knowledge obligation are removed |

Claims that a proof "proves knowledge" are replaced in the design, in this
record, in the arguments file and in the implementation documentation, and
the privacy functionality must simulate `auth_v` consistently with
complete-statement and nullifier equality **[R]**.

**Item 1 is weakened [R].** It required knowledge of a registered
credential; it now requires adaptive relation soundness. The review states
that this is a genuine weakening of property 1 and not an equivalent
reformulation of knowledge soundness, and that properties 2, 3 and 8 must
carry the authorization guarantees independently, under the additional
assumptions of section 8.4. The formal game bounds
`Pr[V_R(x, π) = 1 ∧ x ∉ L_R] ≤ ε_snd`, with the role and the statement
chosen adaptively (section 7.1 bounds `ε_snd` by `s`); no freshness condition is needed, because honestly issued
statements are true. The launch gate remains false.

**What the owner gives up [R].** The system no longer promises an efficient
procedure that recovers a credential from an adversary producing a fresh
valid proof. The definition therefore permits:

- a party to produce a proof of a true statement without knowing its
  witness;
- an adversarial registrant to establish a credential whose opening exists
  but which it cannot subsequently use;
- proof transformations that preserve an already authorized complete
  statement;
- future protocols to fail if they silently treat a ballot or registration
  proof as a proof of possession, as extractable knowledge or as a
  simulation-extractable credential.

The last point is the material composability limitation: a later protocol
that requires knowledge must prove its own theorem or change the
construction. These permissions do not authorize a fresh honest vote if
property 2 holds, do not increase the coalition's seat allowance if
property 3 holds, and do not permit registration recontextualization if
property 8 holds. They provide no general non-malleability or
universal-composability claim. Anyone may still relay an already authorized
ballot, including delivering it before its creator does, which the
signerless design already permitted; property 2 means no unauthorized fresh
message, not exclusive control over delivery. Censorship, credential
disclosure and knowingly authorizing conflicting choices keep their existing
limitations **[R]**.

Section 7.3 gives the item 8 game. Section 8.8 gives the stated reading of
item 6. Item 1 imposes no knowledge requirement; what is known about
extraction is in section 7.6.

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
at the baseline. The two proof crates, `crates/iroha_zkp_vole` and
`crates/iroha_parliament_ballot_proof`, were read in the working tree: their
module lists, crate and test documentation and the constants of the ballot
profile module (sections 11.2 and 11.3). No build, test or benchmark was run
for this record.

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

The pass of 2026-10-12 delivered five texts **[R]**: three parts with the
exact relations, witness layout and constraint order, the re-derived
universal-hash bounds, response-graph soundness for false instances, the
encoding equivalence, the games, the audit of imported results and a first
ledger; the reconciling decisions; and a fifth text with the gate 5 game,
the gate 8 event split, the query offset of the static comparison
(section 8.1) and the byte-level decisions for the standalone construction.
For the fifth the review reports checking the relevant backend code and
primary FAEST sources and independently recomputing the CRT digests. The
pass reports reading the working-tree records and the implementer's notes
and checking the relevant FAEST v3.0 material directly, and that the PDF of
ePrint 2026/164 was inaccessible to it, so that it relies on no theorem that
appears only there **[R]**. Where the review cites a FAEST v3 lemma, figure
or proof step outside the pages listed above, or a paper this evaluation did
not read (section 13), the statement is **[R]**. The consolidated text of
its arguments is the arguments file.

The review then delivered eight further texts **[R]**, which this record
names by content:

- **five earlier texts:** the confirmations of the pad bit order and of the
  rejection of an inconsistent `B`, with the CRT-layer simulation argument;
  the outer composition for gate 5 with one simulator for both roles; the
  analysis of extraction (section 7.6); the association-hiding lemma; and
  the decision that makes gate 1 adaptive relation soundness and strengthens
  the vote relation, with the extractor-free reductions for gates 2, 3 and 8
  (sections 2, 6 and 7);
- **the soundness text:** the adaptive soundness argument written out. It
  finds that the transitions of the passive prefix, a late `H4` or `H0`
  answer completing an already queried chain, are not covered by FAEST
  Lemma 10.48, and gives a theorem that conditions on global induced-seed
  uniqueness and fixes the auxiliary functions instead (section 7.1);
- **the credential text:** the common credential experiment; assumptions P
  and U; the vote test and the privacy composition restated with `auth_v`;
  the two authorization-prediction games and their reduction to P; an
  ideal-table lemma; an assessment of the sponge literature; a direct batch
  reduction for gate 3; and a first consolidated ledger (sections 7.1, 7.5,
  8.4 and 8.5);
- **the extension text:** the latest decision. It adds the salt, the salted
  `H5`, the counter range `2^20` and the affine-checked leaf commitment;
  gives the byte-level delta with the final `SUITE`, the hash-call table and
  the proof layout; and revises the consolidated ledger with an explicit
  nominal resource normalisation (sections 6, 8.5 and 9.7).

Where these texts differ, the latest governs: the extension text over the
soundness and credential texts, and those over everything before them. This
record states the result and does not keep the superseded statements. The
analysis of extraction is retained as analysis of a requirement that is not
imposed (section 7.6). No text gives a value of the descriptor digest `D`;
the values in section 6.1 are computed in this record **[D]**.

Each of the eight reports editing no file and running no build **[R]**. The
review treats the implementation results supplied to it as supplied
evidence, not as independently repeated measurements, and as evidence for
the earlier relation only **[R]**. The eight texts cite sources and passages
this evaluation did not read (section 13); statements resting on them are
**[R]**. The review describes all of its arguments as written arguments
awaiting independent review, not a qualification certificate.

Neither of the two earlier passes edited a file or ran a build **[R]**. The
decisions are design decisions. They are not security proofs, they are not an
independent review of this record, and they select and qualify nothing.

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
| VOLE-in-the-head, SHAKE256 public list | Commitment and nullifier both SHAKE256 inside the relation, with a SHAKE256 authorization value inside each relation: two permutations in registration, three in the vote; 384-bit `sk`; no AES in the relation; flat digest of the public sealed list (section 6) | Concrete-function assumptions about SHAKE256 in its commitment, nullifier and authorization uses under one secret: assumptions P and U (sections 8.4 and 8.7); SHAKE256 as the modelled backend oracles; the backend's PRG and commitment assumptions, with AES-based PRGs in the initial implementation **[R]** | **[R][D]** Fast row: `pi_vote` 233,012 B and `pi_reg` 160,148 B. Small row: 158,074 B and 109,498 B (section 9.7). **[D]** The V3 projection shape (256-bit `sk`, 96-byte commitment, no pad, no authorization value): `pi_vote` 81,834–316,668 B at `lambda` = 256 (section 9, V3). **[U]** a SHA-3 component inside VOLE-in-the-head is reported implemented (ePrint 2026/109) | The construction to develop (section 6). Not selected and not qualified. Largest witness of the three public-list variants. It avoids the hybrid's AES credential assumptions and carries assumptions P and U of section 8.4 |
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

This is the single construction to develop **[R]**, the frozen construction.
It is not the normative `P`: no profile is selected. Its `profile_id` is not
allocated. `P16` below identifies this experimental construction. The ballot
proof is FAEST-derived. It is not a standard FAEST signature, and fixing the
relation does not claim that the custom proof inherits FAEST's signature
theorem **[R]**. Sections 6.1 to 6.4, 6.6 and 6.7 state the construction as
decided by the second-opinion review (section 10.1); every definition in them
is **[R]** unless marked otherwise. The review describes the result as a
construction frozen for investigation, not a selected or qualified one
**[R]**.

Frozen by decision **[R]**:

- the relations `R_reg` and `R_vote+`, the witness layout, the ordered
  constraint stream and its homogenisation (section 6.3);
- the descriptor `DESC` with its `SUITE` and dimensions, the definition of
  its 64-byte digest `D`, the CRT table digest `T_crt` with its values for
  both rows, and the public inputs as bounded opaque byte strings
  (section 6.1). The values of `D` are computed in this record **[D]**;
- the 64 bytes that `D_reg` and `D_v` take for the descriptor (section 6.2);
- the role namespaces, the 77-byte prefix of every backend hash call, the
  exact preimage of `mu` and the body of every hash call (section 6.3);
- the parameter row, the leaf commitment, the CRT tables, the naked proof
  layout for both rows and relations, and a test-only statement codec
  (section 6.6);
- the proving tape, its uses, the counter rule and the erasure rule
  (section 6.7).

**Two constructions, kept apart [R].**

- *Reference mode* is FAEST v3.0 as specified: an empty prefix, the official
  OWF, the `H3` derivation, the 96-byte leaf commitment, no salt and the
  32-bit counter. The official component and signature vectors test it, and
  it is unchanged. It is not an accepted ballot mode.
- *Ballot mode* is the backend of the frozen construction. It differs from
  reference mode in exactly these points: the role prefix on every hash
  call; a fresh proving tape in place of the `H3` derivation; the salt in
  challenge 1, in `H5` and in the proof; the counter range `2^20`; and the
  112-byte leaf commitment with its 128-byte `H0` output and 144-byte leaf
  expansion. The field representation, the universal hashes, the PRG with
  its tweaks, the tree layout, the CRT tables, the challenge lengths and the
  sibling ordering are those of reference mode.

**No official vector covers ballot mode.** Its hash inputs, leaf commitments
and proof bytes differ from reference mode, so it needs its own vectors
(section 11.3). The comparator row has a transcript identity distinct from
the candidate row: its descriptor digest `D`, and with it both role prefixes,
differ (sections 6.1 and 6.3).

The review states that the public-input language of the standalone
construction is explicitly bounded byte strings and that no relation or
transcript choice remains open for it **[R]**. Later obligations, not
written: the production Norito mappings of the typed node values onto those
byte strings, the production envelopes, and authenticated integration. The
standalone verifier does not validate node-level canonicality, and the
absence of those mappings must not be hidden by claiming that it does
**[R]**.

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
  "KECCAK-F1600/2R-FWD/SEL-32X32-PREFIX/PAD-256/TAPE-112/CTR-U20-LE32/NS-PREFIX77/NF-1024/VAUTH-512/SALT-256/H5-SALT/LEAF-AFFINE-896"
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
| Fast | `(256, 33, 8, 229, 7, 704)` | `(35840, 72576, 53504, 108931)` |
| Comparator (small) | `(256, 22, 6, 225, 7, 696)` | The same |

- `SUITE` is 129 ASCII bytes without a terminator **[R]**, counted here
  **[D]**. Its twelve `/`-separated tokens, in order: `KECCAK-F1600`,
  `2R-FWD`, `SEL-32X32-PREFIX`, `PAD-256`, `TAPE-112`, `CTR-U20-LE32`,
  `NS-PREFIX77`, `NF-1024`, `VAUTH-512`, `SALT-256`, `H5-SALT` and
  `LEAF-AFFINE-896`.
  Its bytes in hexadecimal **[D]**:

  ```text
  4b454343414b2d46313630302f32522d4657442f53454c2d33325833322d5052
  454649582f5041442d3235362f544150452d3131322f4354522d5532302d4c45
  33322f4e532d50524546495837372f4e462d313032342f56415554482d353132
  2f53414c542d3235362f48352d53414c542f4c4541462d414646494e452d3839
  36
  ```

  It immutably names the relation, the constraint ordering, the encodings,
  the transcript, the randomness rules and the backend extensions frozen in
  this section. It is not an extensible options string.
- The verifier selects a compiled, fixed descriptor. It does not accept an
  arbitrary caller-defined descriptor.
- `DESC` is 286 bytes on both rows **[R]**, recomputed here **[D]**:
  `2 + 12 + 2` for the tag and the field count, plus six length prefixes of
  4 bytes and fields of 16, 9, 12, 64, 16 and 129 bytes.
- **Every retired descriptor is rejected. No compatibility path exists
  [R].** A verifier of the frozen construction accepts neither a proof nor a
  statement made under a descriptor with another `SUITE` or other
  dimensions.
- The descriptor digest is shared by both roles. Both role namespaces, every
  registration authorization value and every vote authorization value
  depend on it (sections 6.2 and 6.3) **[R]**.

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

**Fixed digest values.** Each is 64 bytes, written as 128 hexadecimal
digits. The two `T_crt` values are the review's **[R]** and do not depend on
the relations:

```text
T_crt (fast row) =
a9c572a7c8f2cc735218123c6456e1e016e78b06aa2d03192ef801bf7fdb93ae014a9e16555e6bad81382c630467e45e76c9b1c3948f9dfea41a7a1435bcffea

T_crt (small row) =
792f81bf102cac84b7c559595342b6b23ad27dab9065651feb928dd0a649a3f4bd1da3d350fbd4c62f1707d441d46ef084430b5f00b53a1af7088281d6a7386e
```

The review reports that it recomputed the two `T_crt` values independently
**[R]**. **[D]** Both were recomputed here as
`SHAKE256(CRT_BYTES, 64 bytes)` in two ways, and both agree with the printed
values on both rows: from the word arrays in the generated table sources
`crates/iroha_zkp_vole/src/crt/generated/faest_256f_tables.rs` and
`faest_256s_tables.rs`, read as text and serialised in the order above; and
from tables produced by a separate Python port of the FAEST v3.0.2 reference
table generator. Those arithmetic checks did not use a build. The final
compiled profile and vector tests also check these digests through the
backend's `encode_words` **[C]**. The later
[direct upstream comparison](../crates/iroha_zkp_vole/tests/fixtures/faest_v3_0_2/upstream_crt_comparison.txt)
checks every table word in all eight profiles against unmodified pinned C++,
separately from the Python port and official component vectors **[C]**.

No text of the review gives a value of `D`; it directs that `D`, both role
namespaces and the descriptor-dependent authorization values be recomputed
**[R]**. The two values below are computed in this record **[D]** as
`SHA3-512(DESC)`:

```text
D (fast row) =
01ed9f564981a07ab383d513c4e816f5a76542c7220eaaa36742f8eb0c51341da089e154a815f92fcd18353077cde18f435dfaa0834b65fdf3a658b0accdda28

D (small row) =
4c38e45d70b5aa1295c107fe9035e82b179d8ec10ab7acf59b6955e0b22f9fdb09976788745a0fbb4ee1cabd840a12d9e746bf76b3998ab72c06e019bb889412
```

**[D]** The exact serialisation hashed, 286 bytes, with every integer
little-endian and the bytes written in hexadecimal:

```text
DESC =
    0c00     || ASCII("PARL/DESC/v1")                    // tag length 12, tag
 || 0600                                                 // six fields
 || 10000000 || 5041524c2d5348414b452d5631000000         // P16
 || 09000000 || ASCII("FAEST-3.0")
 || 0c000000 || 0001 2100 0800 e500 0700 c002            // fast row tuple
 || 40000000 || T_crt of the row                         // 64 bytes
 || 10000000 || 008c0000 801b0100 00d10000 83a90100      // 35840, 72576, 53504, 108931
 || 81000000 || SUITE                                    // 129 ASCII bytes
```

The small row differs in two fields: its tuple is
`0001 1600 0600 e100 0700 b802` and its `T_crt` is the small-row value. The
length prefix `81 00 00 00` of the suite field is the review's **[R]**.

**[D]** A separately
written Python `struct`/`hashlib` calculation independently rebuilt the
129-byte suite and both 286-byte descriptors from the definitions above and
reproduced both printed values of `D`. The same transcription and arithmetic
check reproduced the four proof-size totals and the revised candidate
ledger's `Q`, soundness, batch soundness, challenge-1, `K`, `D_sw` and nominal
`Z` values. This checks transcription and arithmetic only, not the security
arguments or imported theorem hypotheses. The final independent Python
reference and Rust vector tests also reproduce both descriptor digests and
all four proof lengths **[C]** (section 11.3).

**Opaque public inputs.** The public inputs of the standalone construction
are bounded byte strings.

| Input | Permitted byte length |
| --- | ---: |
| `Enc(body_context)` | 0 to 4,096 |
| Each of `Enc(network_id)`, `Enc(authority)`, `Enc(assignment_id)`, `Enc(governance_attempt_id)`, `Enc(election_attempt_id)`, `Enc(body_role)` | 0 to 256 |
| `B`, `scope`, `R`, `auth`, `auth_v`, `policy_hash`, `proposal_digest`, `D` | Exactly 64 |
| `C`, `nf` and each list entry | Exactly 128 |

- Empty opaque strings are structurally permitted by the standalone protocol.
  Application validity belongs to the caller's typed encoding and
  authentication rules.
- `body_context` and `authoritative_body_context` (section 6.2) are the same
  byte string.
- Registration verification recomputes `B` and `D_reg`. It does not trust
  caller-supplied derived digests. A statement that carries a `B` different
  from the digest recomputed from the exact encoded body context is rejected
  before any backend proof work, and an inconsistent statement is never
  silently repaired **[R]** (confirmed by the review).
- Vote validation enforces `3 ≤ S ≤ 1000`, exactly `S` entries, strict
  unsigned bytewise ordering, no duplicates, the recomputed `R` for the
  validated list, the exact lengths of `nf` and `auth_v`, the recomputed
  `D_v` and `vote ∈ {0, 1, 2}`. The caller authenticates the expected body
  and the sealed list.
- The digest helpers for the section 6.2 frames are optional. In them
  `Enc(body_instance_id)` has length 0 to 256, and the network and
  governance-attempt inputs use the bounds above. The policy and proposal
  preimages may have any length from 0 to `0xffff_ffff`, the field-length
  limit of `Frame`; the helpers stream them with checked lengths. They are
  not additional proof fields. The section 6.2 frames are preserved exactly,
  including where each places or omits `P16`.

### 6.2 Commitment, authorization values, nullifier, list and messages

```text
sk = 48 uniformly random bytes, fresh for each body

C  = SHAKE256("PCR1" || P16 || sk[48] || B[64],     128 bytes)
nf = SHAKE256("PNF1" || P16 || sk[48] || scope[64], 128 bytes)

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

D_v = SHA3-512(Frame("PARL/VOTE-AUTH/v1";
                    P16,
                    ASCII("VOTE"),
                    D,
                    B,
                    scope,
                    R,
                    u16_le(S),
                    concat(L),
                    nf,
                    u8(vote),
                    policy_hash))

auth_v = SHAKE256("PAV1" || P16 || sk[48] || D_v[64], 64 bytes)

m_reg = (
    network_id, authority, assignment_id,
    governance_attempt_id, election_attempt_id, body_role,
    B, C, auth, P16
)

m = (scope, R, S, nf, auth_v, vote, policy_hash, P16)
```

- `sk` is 384 bits, `C` and `nf` are 1,024 bits, and `auth`, `auth_v`,
  `D_reg`, `D_v`, `R`, `B`, `scope`, `policy_hash` and `proposal_digest` are
  512 bits.
- The four SHAKE256 inputs are exactly 132 bytes each: 4 + 16 + 48 + 64
  **[D]**. Each output, 128 bytes at most, fits the 136-byte SHAKE256 rate,
  so each evaluation needs one Keccak-f[1600] permutation and no second
  squeezing permutation (FIPS 202 sections 5 and 6, cited by the review; not
  read by us). Widening the nullifier to 128 bytes therefore adds no
  permutation and no committed trace state; the vote authorization value
  adds one permutation. Standard SHAKE padding and bit ordering apply.
- The commitment depends on the body context through `B`. The nullifier
  depends on the full scope and is independent of the vote. Each
  authorization value depends on the complete statement of its role, through
  `D_reg` or `D_v`. All of them are constrained inside a relation under the
  same `sk`. There is no AES in the relation.
- **Registration authorization value.** `auth` is a public value of the
  registration statement. `D_reg` covers the profile descriptor, the
  authoritative body context, every field of `m_reg` other than `auth`, and
  the role string `REG`. It excludes `auth`, `mu`, the proof bytes and the
  prover's randomness. The descriptor field is exactly the 64 bytes `D` of
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
  supports and what it does not establish is in section 7.3. Because `D_reg`
  covers `D`, every registration authorization value of the frozen
  construction differs from the value under any other descriptor **[R]**.
- **Vote authorization value.** `auth_v` is a public value of the vote
  statement and a field of `m`. `D_v` covers every vote statement field other
  than `auth_v`, the actual list bytes `concat(L)` included, with the
  descriptor digest `D` (exactly its 64 bytes) and the role string `VOTE`.
  It excludes `auth_v`, `mu`, the proof bytes and the proving randomness. It
  is recomputed, not trusted as a supplied digest. Including `concat(L)`
  makes the authorization-frame argument independent of a separate
  list-digest collision reduction. No account, authority or selected
  position enters this frame. The frame is `128·S + 536` bytes. `auth_v` is
  bound through `mu` by `F_VOTE` and constrained inside the vote relation
  (section 6.3). It exists so that gate 2 can be argued without an extractor:
  with a target nullifier that has no second secret, a fresh ballot under an
  honest nullifier has to predict a fresh authorization value
  (section 7.5). Like `auth`, it is neither a signature nor a Core check.
- **Nullifier length.** The nullifier is 128 bytes because the argument for
  gate 2 needs an existential uniqueness premise for the target nullifier,
  which a 512-bit output cannot support at the lifetime ceilings
  (sections 8.3 and 8.4).
- `L` has exactly `S` entries. There are no padded credential leaves, no leaf
  or node hashing and no tree.
- In the experimental construction `P16` stands where the ballot design's
  messages carry `profile_id`.

### 6.3 Relations, witness layout, constraints and transcript

**Relations.** After the public validation below:

```text
R_reg(x; sk)       <=>  C = SHAKE256("PCR1" || P16 || sk || B, 128 bytes)
                        and auth = SHAKE256("PAU1" || P16 || sk || D_reg, 64 bytes)

R_vote+(x; sk, i)  <=>  0 <= i < S
                        and C_i    = SHAKE256("PCR1" || P16 || sk || B,     128 bytes)
                        and nf     = SHAKE256("PNF1" || P16 || sk || scope, 128 bytes)
                        and auth_v = SHAKE256("PAV1" || P16 || sk || D_v,    64 bytes)
```

All equations of a relation use the same 384-bit secret.

| Proof | Public input | Semantic witness | Extended witness |
| --- | --- | --- | --- |
| `pi_reg` | Complete `m_reg`, authoritative body context and the profile descriptor | `sk` | Pad, `sk`, the committed Keccak states of the commitment and registration-authorization permutations |
| `pi_vote` | `B`, validated `L`, complete `m`, the profile descriptor | `sk` and the position `i` | Pad, `sk`, the committed Keccak states of the commitment, nullifier and vote-authorization permutations, two selector vectors |

- **Public validation** contributes no witness constraint. In the standalone
  construction it covers the length bounds of section 6.1, the compiled fixed
  descriptor and the recomputed body-context digest `B`, and for registration
  the recomputed `D_reg`; canonicality of the typed values behind the opaque
  inputs is validated by Core, not by it. For voting it also covers `3 ≤ S ≤ 1,000`, exactly `S`
  strictly ordered distinct commitments, the correct authenticated list digest
  `R`, a vote byte in `{0, 1, 2}`, the exact field lengths of `nf` (128 bytes)
  and `auth_v` (64 bytes), and the recomputed `D_v`.
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
(commitment), `A` (registration authorization), `N` (nullifier) or `V` (vote
authorization; `A` is reserved for registration). States are committed
after 2, 4, ..., 22 rounds.

| Component | Registration | Vote |
| --- | --- | --- |
| Fresh pad | `[0, 256)` | `[0, 256)` |
| Credential secret `sk` | `[256, 640)` | `[256, 640)` |
| Commitment state `A_C^(2g)` | `[640 + 1600(g−1), 640 + 1600g)` | Same |
| Registration-authorization state `A_A^(2g)` | `[18240 + 1600(g−1), 18240 + 1600g)` | None |
| Nullifier state `A_N^(2g)` | None | `[18240 + 1600(g−1), 18240 + 1600g)` |
| Vote-authorization state `A_V^(2g)` | None | `[35840 + 1600(g−1), 35840 + 1600g)` |
| Selector `a_0, ..., a_31` | None | `[53440, 53472)` |
| Selector `b_0, ..., b_31` | None | `[53472, 53504)` |
| **Total `l`** | **35,840** | **53,504** |

**[D]** `l_reg = 256 + 384 + 2 × 11 × 1,600 = 35,840` and
`l_vote = 256 + 384 + 3 × 11 × 1,600 + 64 = 53,504`. There is no witness block
for the absorbed initial states, the odd-round states, the final states, the
selected commitment or the SHAKE padding.

- **The pad is prover randomness, not a second credential secret.** It
  appears in exactly its 256 Booleanity constraints and in no other
  application constraint. Its coordinates take part in the backend's
  commitment, correction and consistency machinery like any witness
  coordinate. No commitment, authorization value or nullifier depends on it.
  The application witness is the extended witness with the pad projected
  away.
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

| Byte interval | Commitment | Registration authorization | Nullifier | Vote authorization |
| --- | --- | --- | --- | --- |
| `[0, 4)` | ASCII `PCR1` | ASCII `PAU1` | ASCII `PNF1` | ASCII `PAV1` |
| `[4, 20)` | `P16` | `P16` | `P16` | `P16` |
| `[20, 68)` | `sk` | the same `sk` | the same `sk` | the same `sk` |
| `[68, 132)` | `B` | `D_reg` | `scope` | `D_v` |

The four bytes `1f 00 00 80` are appended to give the 136-byte rate block, and
64 zero capacity bytes follow to form `A_D^(0)`. Bit `j` of `sk`, which is
witness coordinate `256 + j`, occupies initial-state bit `160 + j`. After the
permutation the commitment and the nullifier are state bits `[0, 1024)` of
their permutations, and the two authorization values are state bits
`[0, 512)` of theirs, packed with the same convention.

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
(VN)  O_N[t] + nf[t] = 0                                   0 <= t < 1024   vote
(VA)  O_V[t] + auth_v[t] = 0                               0 <= t < 512    vote
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
| Booleanity (B) | `[0, 53504)` |
| `a`-prefix constraints (SP) | `[53504, 53536)` |
| `a`-sum (SS) | `53536` |
| `b`-prefix constraints (SP) | `[53537, 53569)` |
| `b`-sum (SS) | `53569` |
| Range constraint (SR) | `53570` |
| Commitment transitions (T) | `[53571, 71171)` |
| Commitment output (VC) | `[71171, 72195)` |
| Nullifier transitions (T) | `[72195, 89795)` |
| Nullifier output (VN) | `[89795, 90819)` |
| Vote-authorization transitions (T) | `[90819, 108419)` |
| Vote-authorization output (VA) | `[108419, 108931)` |
| **Total `N_c`** | **108,931** |

Count ledger **[R][D]**. The degrees are assigned bounds, not claims that
every specialised coordinate polynomial has exactly that degree.

| Constraint kind | Assigned degree bound | Registration | Vote |
| --- | ---: | ---: | ---: |
| Witness Booleanity | 2 | 35,840 | 53,504 |
| Prefix constraints | 2 | 0 | 64 |
| Selector sums | 1 | 0 | 2 |
| Range constraint | 2 | 0 | 1 |
| Commitment transitions | 4 | 17,600 | 17,600 |
| Commitment output | 4 | 1,024 | 1,024 |
| Registration-authorization transitions | 4 | 17,600 | 0 |
| Registration-authorization output | 4 | 512 | 0 |
| Nullifier transitions | 4 | 0 | 17,600 |
| Nullifier output | 4 | 0 | 1,024 |
| Vote-authorization transitions | 4 | 0 | 17,600 |
| Vote-authorization output | 4 | 0 | 512 |
| **Relation constraints, excluding Booleanity** | | **36,736** | **55,427** |
| **Total `N_c`** | | **72,576** | **108,931** |

**[D]** The vote indices and totals were recomputed here by laying the
blocks end to end after the 53,504 Booleanity constraints:
`64 + 2 + 1 + 3 × 17,600 + 1,024 + 1,024 + 512 = 55,427` and
`53,504 + 55,427 = 108,931`.

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

**The three lowest unmasked coefficients are zero, and nothing changes
[R].** Every homogenised constraint is divisible by `X^3`, so the unmasked
coefficients satisfy `A_0 = A_1 = A_2 = 0` and the masked responses
`a~_0`, `a~_1`, `a~_2` consist of mask fields only. The degree-seven error
polynomial and the `7·2^-256` root bound are kept, because dishonest claimed
coefficients and the mask polynomial need not be divisible by `X^3`. Six
sampled transmitted coefficients and the reconstructed `a~_0` are kept, and
the map from masks to responses stays invertible. Seven is the frozen
backend degree, not the minimum native degree of these circuits; reducing it
would be a different, unvalidated protocol. All ten masks and all six
transmitted coefficients stay as they are, with their hashing and
serialisation.

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
    B, scope, R, u16_le(S), concat(L),
    nf, auth_v, u8(vote), policy_hash)

mu_R = SHAKE256(PREFIX_R || F_R || hex("08"), 64 bytes)
```

- `PREFIX_R` is 13 bytes of ASCII followed by the 64 bytes of `NS_R`
  **[D]**. There is no second `NS_R` between `PREFIX_R` and `F_R`.
- `NS_R` and `PREFIX_R` are fixed by these definitions. Their values follow
  from `D` and change with it: both namespaces of the frozen
  construction differ from those of any other descriptor **[R]**. This
  record prints no namespace value.
- In `F_VOTE`, `R` is the list digest of section 6.2, not the role. `nf` is
  128 bytes and `auth_v` is 64 bytes. `F_VOTE` is `128·S + 506` bytes
  **[R]**.
- The descriptor, and with it the construction identifier `P16`, the
  parameter row, the CRT tables, the relation dimensions and `SUITE`, is
  bound through `D` in `NS_R`. The role is bound through `NS_R`. The complete
  public statement is bound through `F_R`: for registration every field of
  `m_reg` other than `P16`, `auth` included, with the body context; for
  voting the canonical list bytes `concat(L)`, although their digest `R` is
  also a field, with `B` and every field of `m` other than `P16`, `nf` and
  `auth_v` included. Every field
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
| `H0` | `iv[16]` | `00` | 128 bytes: `h0[96] \|\| h1[32]` |
| Inner `H1`, vector `i` | Its 112-byte leaf commitments in increasing leaf order | `01` | 64 bytes |
| Outer `H1` | The vector digests in increasing vector order | `01` | 64 bytes |
| Challenge 1 | `mu \|\| com \|\| c_1 \|\| … \|\| c_(tau−1) \|\| c_mult \|\| iv_pre \|\| salt` | `09` | 264 bytes |
| Challenge 2 | `chall_1 \|\| ToBits(u_tilde[4]) \|\| ToBits(V_tilde[4]) \|\| d` | `0a` | 104 bytes |
| Challenge 3 | `chall_2 \|\| ToBits(a_tilde_0, …, a_tilde_6) \|\| u32_le(ctr)` | `0b` | 32 bytes |
| `H5`, gate `e` | `iv[16] \|\| salt[32] \|\| u32_le(e) \|\| label[32]` | `05` | Low 10 bits of the first two output bytes |

- `com` is the 64-byte aggregate BAVC commitment. Arrays use increasing
  indices. `iv = H4(iv_pre || mu)`, so the v3 challenge chain is preserved
  inside the prefix.
- **The salt** is the 32 bytes `tape[80..112]` of section 6.7. It is the last
  field of the challenge-1 body and the second field of every `H5` body, and
  it is serialised in the proof (section 6.6). It does not enter `H4`, `H0`,
  the AES PRG or the leaf commitment (section 6.6.1).
- For challenge 2, verification reconstructs `V_tilde = Q_tilde + Δ·u_tilde`;
  for challenge 3 it reconstructs `a_tilde_0`. The reconstructed values
  belong to the challenge inputs, on both rows.
- The full `H5` input is `77 + 16 + 32 + 4 + 32 + 1 = 162` bytes, more than
  the 136-byte SHAKE256 rate, so each `H5` evaluation absorbs with two
  Keccak permutations **[R]**, recomputed here **[D]**. The full challenge-3
  input is `77 + 104 + 224 + 4 + 1 = 410` bytes, four permutations
  **[R][D]**.
- There is no additional `H1` consistency digest. The review states that
  these placements, apart from the salt, follow the official v3.0.2
  transcript implementation (`faest_impl.c` at tag `v3.0.2` of
  `faest-sign/faest-ref`) **[R]**; this record did not read that file.
- For `H5`, two bytes are squeezed, interpreted little-endian and masked with
  `0x03ff`.
- Ballot proving makes no `H3` call.
- Proof randomness is the fresh proving tape of section 6.7. Deterministic
  testing means deterministic given an explicit tape.

**Why a literal prefix [R].** Dependence on `mu` is not literal namespace
separation. Without a prefix `H0` receives only the 128-bit IV and
`H1` receives commitment material without a namespace, so different roles can
reach identical oracle inputs; `H5` includes the IV and inherits the same
limitation. The review cites `crates/iroha_zkp_vole/src/hash.rs` and
`crates/iroha_zkp_vole/src/bavc.rs` for these facts. In ordinary FAEST `H4`
and challenge 1 read `mu` directly, `H0`, `H5` and the PRG use the IV derived
from it, `H1` reads descendants of the IV-dependent expansion, and
challenges 2 and 3 read the preceding challenge chain. All of them depend
causally on `mu`. That is insufficient for the disjoint-domain statement
adopted here, which is why every call carries the prefix.

**The PRG keeps its IV and tweaks [R].** The AES PRG keeps the derived `iv`,
the existing counter-word arithmetic and the official tweaks. With `N` total
leaves and vector index `i`:

```text
tree-node tweak:       node heap index
leaf-expansion tweak:  N - 1 + i
high-mask tweak:       2^31 - 1
small-VOLE tweak:      2^31 + i
```

The one change is the length of the leaf expansion: 144 bytes, nine AES
blocks, in place of 128 (section 6.6.1). The PRG is not converted into an
independently namespaced random oracle, and neither the salt, `iv_pre` nor
`mu` enters it. Its IV and cross-instance security remain proof obligations.

Reference mode has an empty prefix, a 96-byte `H0` output and a 128-byte
leaf expansion; ballot mode is not obtained from it by the prefix alone
(section 6).

Domain separation is necessary; it is not itself a joint-security proof
**[R]**. The algebraic equations alone do not establish the transcript
binding **[R]**.

FAEST's QROM proof restricts the key space (`k[0]·k[1] = 0`) so that a
random public key has no preimage with probability at least 1/4 **[P]**
(FAEST v3 section 10.7, Lemma 10.50). The construction has no AES key and no
equivalent restriction, and it needs none: the soundness theorem's winning
condition already names a false statement, so the key-distribution step is
omitted, and gates 2 and 8 take event splits that keep every statement true
**[R]** (sections 7.1, 7.3 and 7.5). For every fixed `B`, even for concrete
SHAKE, the image of the commitment function has at most `2^384` elements, so
a uniform 1,024-bit string lies in it with probability at most `2^-640`; no
argument uses that counting **[R]**.

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
- **Leaf commitments** are the 112-byte commitments of section 6.6.1 on both
  rows. The field representation, the universal-hash construction, the
  tweaks and the tree layout are FAEST v3's. No root tag and no extraction
  commitment is added: gate 1 does not require extraction (section 7.6).
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
- **Conformance.** The official vectors are conformance targets for
  reference mode only; passing them does not validate ballot mode
  (sections 6 and 11.3).

#### 6.6.1 Leaf commitment

Decided by the review for both rows **[R]**:

```text
H0 input  = PREFIX_R || iv[16] || hex("00")
H0 output = h0[96] || h1[32]                         // 128 bytes

LeafPRG(node_key, iv, leaf-expansion tweak; 144 bytes)
          = sd[32] || b0[96] || b1[16]

c0 = ToBits768(iota(sd) * h0 + b0)                   // in F_(2^768)
c1 = ToBits256(sd * h1)[0..16]  xor  b1              // product in F_(2^256)

leaf_commitment = c0[96] || c1[16]                   // 112 bytes
```

- `c0` is the existing FAEST v3 leaf hash, unchanged: `iota` injects the
  32-byte seed into the 768-bit field as the encoding `sd[32] || zero[64]`.
- `c1` multiplies `sd` and `h1`, each read as an element of
  `F_(2^256) = F_2[X]/(X^256 + X^10 + X^5 + X^2 + 1)`, the field `K` of
  section 6.3. No new field is introduced.
- **Bit convention.** In every encoding, bit `j` of byte `i` is the
  coefficient of `X^(8i + j)`. `[0..16]` therefore selects the 128 low
  polynomial coordinates of the product.
- The leaf expansion is nine AES blocks, with the existing IV and
  leaf-expansion tweak (section 6.3).
- A hidden leaf's commitment in the opening contains both `c0` and `c1`. The
  verifier recomputes both for every reconstructed visible leaf. The inner
  `H1` call of a vector hashes its 112-byte commitments in increasing leaf
  order.
- The review states that these operations match the existing field
  definitions and affine leaf hash of
  `crates/iroha_zkp_vole/src/field.rs` and
  `crates/iroha_zkp_vole/src/universal_hash.rs` **[R]**; this record did not
  compare them.

**What it is for [R].** For any fixed IV and tweak, take two root seeds that
induce distinct seeds `sd ≠ sd'`. Equality of `c0` fixes at most one value
of the independent 768-bit `h0`. Multiplication by `sd − sd' ≠ 0` permutes
`F_(2^256)`, so the 128 low coordinates of `(sd − sd')·h1` are uniform and
equality of `c1` has probability `2^-128`, independently of the first
equality. The pair-ambiguity probability is therefore at most `2^-896` for
any deterministic leaf PRG; no AES assumption enters. The global union this
feeds is `δ_leaf,all` of section 7.1. The hiding side is explicit as well:
replacing the 144-byte expansion by uniform bytes makes `sd`, `c0` and `c1`
mutually independent and uniform, conditional on the public hash key.

**What does not enter `H0` and the leaf PRG, and why [R].** Neither the
salt, `iv_pre` nor `mu` is added to the `H0` input or to the leaf PRG. The
ambiguity bound is a union over every context in which a leaf commitment is
computed: two role namespaces, `2^128` IVs and the vector tweaks. Adding any
of those values would enlarge that universe and with it the bound.
Requesting more `H0` output without using it in the commitment would not
improve the bound either. `c1` is not an extraction commitment and the
soundness theorem that uses it gives no extraction (section 7.1).

#### 6.6.2 Naked proof layout

The proof contains these fields, in this order, and no header **[R]**. Byte
counts, recomputed here **[D]** from `l`, `tau`, `n_mult` and `T_open`:

| Field | Fast `pi_reg` | Fast `pi_vote` | Small `pi_reg` | Small `pi_vote` |
| --- | ---: | ---: | ---: | ---: |
| `c_1, …, c_(tau−1)` | 143,360 | 214,016 | 94,080 | 140,448 |
| `c_mult` | 880 | 880 | 870 | 870 |
| `u_tilde` | 128 | 128 | 128 | 128 |
| `d` | 4,480 | 6,688 | 4,480 | 6,688 |
| `a_tilde_1, …, a_tilde_6` | 192 | 192 | 192 | 192 |
| Opening | 11,024 | 11,024 | 9,664 | 9,664 |
| `chall_3` | 32 | 32 | 32 | 32 |
| `iv_pre` | 16 | 16 | 16 | 16 |
| `salt` | 32 | 32 | 32 | 32 |
| `u32_le(ctr)` | 4 | 4 | 4 | 4 |
| **Total bytes** | **160,148** | **233,012** | **109,498** | **158,074** |

- `a_tilde_0` is hashed (challenge 3, section 6.3) and is not serialised.
- `c_mult` is mask-row-major, with increasing gate index within each row.
- Bits are low-bit first within bytes. Field elements use the existing
  polynomial-basis `ToBits`.
- **Opening**, in order: the `tau` hidden-leaf commitments, 112 bytes each,
  in increasing vector index; then the revealed sibling seeds, 32 bytes each,
  found by scanning parent heap indices from `N − 2` down to zero and, where
  exactly one child belongs to the union of the hidden paths, emitting the
  other child's seed; then zero bytes that fill the seed area to exactly
  `T_open · 32` bytes.
- The verifier derives the seed count from `chall_3`. It rejects an excessive
  count and any nonzero unused padding.
- The counter field is four bytes although the permitted range is `2^20`
  (section 6.7).
- Every proof length other than the fixed length for the externally selected
  row and relation is rejected. The verifier does not autodetect a row and
  accepts no trailing bytes.

**[D]** The opening is `tau · 112 + T_open · 32` bytes:
`33 × 112 + 229 × 32 = 11,024` on the fast row and
`22 × 112 + 225 × 32 = 9,664` on the small row. The corrections are
`(tau − 1) · l/8` bytes, `c_mult` is `10 · n_mult / 8`, and `d` is `l/8`:
for the vote, `32 × 6,688 = 214,016` and `21 × 6,688 = 140,448` correction
bytes. The review's field-by-field table gives the same forty values and
four totals **[R]**.

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

Each proof invocation obtains exactly 112 fresh bytes from the caller's
fallible cryptographic random-number generator:

```text
r      = tape[0..32]      // backend root seed
iv_pre = tape[32..48]
pad    = tape[48..80]     // witness positions [0, 256)
salt   = tape[80..112]    // public; transmitted in the proof
```

- **Model.** The 112 bytes are independent uniform coins, independent of the
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
- **Uses of `iv_pre`.** It is transmitted and is hashed directly in `H4` and
  in challenge 1 (section 6.3). It stays 16 bytes.
- **Uses of the pad.** The raw pad is supplied only as witness bits
  `[0, 256)`. It then necessarily affects `d`, the pad Booleanity
  constraints, the masked response calculations and the downstream challenge
  hashes; "only as witness bits" does not exclude those derived effects.
- **Pad bit order [R].** Witness coordinate `j`, for `0 ≤ j < 256`, is

  ```text
  P_j = (tape[48 + floor(j / 8)] >> (j mod 8)) & 1
  ```

  that is bit `j mod 8` of `tape[48 + j div 8]`, with the bit of value `2^0`
  as bit 0. This is the backend's ordinary witness bit convention. It
  affects `d` and every later proof byte.
- **Uses of the salt.** It is appended to the challenge-1 body, it is the
  second field of every `H5` body of the proof, and it is serialised
  immediately after `iv_pre` and before the counter (sections 6.3 and
  6.6.2). It enters neither `H4`, `H0`, the AES PRG nor the leaf
  commitment. Its purpose is in the arguments: every challenge-1 input and
  every `H5` input of a proof then contains 256 bits that the prover sampled
  privately for that request (section 7.1).
- **What is hashed.** There is no separate hash of the tape, of raw `r` or
  of the raw pad.
- **No `H3` call.** Ballot proving derives nothing from the secret and the
  message through `H3`. `iv = H4(iv_pre || mu)` is retained, inside the role
  prefix.
- **Erasure.** The prover erases its owned tape buffers, `r`, the pad and the
  transient secret witness, VOLE, tree and hash material on success, on error
  and on exhaustion. That includes temporary copies of the credential secret;
  it does not include the wallet's retained credential. The public `iv_pre`
  and salt need not be erased from the returned proof; their copies inside
  the tape buffer are erased with the buffer.

**Counter rule [R]**, the same on both rows:

```text
M_ctr            = 1 << 20
allowed counters = 0x00000000 through 0x000fffff, inclusive
encoding         = four-byte little-endian u32
```

- **Retry loop.** The commitment, the corrections, the first two challenges
  and the response coefficients are computed once. The prover then tries the
  allowed counters in increasing order:

  ```text
  chall_3 = H2^3(chall_2 || ToBits(a~_0, ..., a~_6) || LE32(ctr), 256 bits)
  ```

  which as a ballot call is challenge 3 of section 6.3: SHAKE256 over
  `PREFIX_R`, that body and the suffix byte `0b`. An attempt is rejected
  unless its grinding suffix is zero and its canonical BAVC opening fits the
  row's threshold: eight grinding bits and `T_open = 229` on the fast row,
  six and 225 on the comparator. The first success is returned.
- **Exhaustion.** If all `2^20` attempts fail the prover returns the typed
  result `GrindingExhausted { last: 0x000fffff }`. The counter never wraps.
  Any later invocation needs an entirely fresh 112-byte tape.
- **Verification** rejects a proof whose counter exceeds `0x000fffff`
  before any expensive reconstruction. Otherwise it checks the supplied
  counter and opening once: it hashes the counter once, never repeats
  grinding, never loops a number of times given by the counter and does not
  establish that the counter is minimal.
- **What the bound on exhaustion covers.** The lower bound `p > 1/7360` on
  the acceptance probability of one attempt is a candidate-row result
  (section 7.1). The comparator's different opening geometry does not
  inherit it; its counter rule is the same bounded, total rule.
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
[arguments file](parliament_ballot_proof_arguments.md), under "Arguments by
property", "Oracle environment and games" and "Numeric ledger". This
subsection summarises them; every statement in it about what is written or
missing is the second-opinion review's **[R]** unless marked. Status words:
**complete** means a full written argument under the standard of
section 11.1, its numerical substitution into the contract included;
**conditional** means a written reduction or design argument whose premises
are other gates, unproved assumptions, an idealised model or unfinished
implementation; **incomplete** means that a foundational step is missing.
No gate is complete. Nothing in the table has had independent review, and
the review describes its texts as written arguments awaiting it.

| Gate | Status | Written | Open |
| --- | --- | --- | --- |
| 1 Adaptive relation soundness | Conditional | An adaptive theorem in the backend QROM against both real honest proof interfaces: `s ≤ δ_leaf,all + 340·Q^3·2^-512 + 70·Q^2·2^-256`, and for at most 1,001 outputs `s_batch ≤ δ_leaf,all + 1001·(340·Q^3·2^-512 + 70·Q^2·2^-256)`, with `δ_leaf,all ≤ 33·(1 − 2^-256)·2^-256` (below) | Independent review, first of the auxiliary-function conditioning and the local-witness predicate. The premises: the deterministic implementation obligations and the random-oracle idealisation of the backend hash domains, which is not proved for concrete SHAKE256. The direct local argument for late `H4` and `H0` completions is missing; the theorem avoids it and does not supply it. Class (c) |
| 2 Unforgeability | Conditional | The target-origin game, the event inclusion and `ε_2^app ≤ s + u_N + F_V + Z + α_P + ρ + g_V` (section 7.5) | Values of `u_N`, `F_V`, `α_P` and of the generator terms inside `Z` at the complete resource vector. FAEST's theorem is for one honestly generated key **[P]** (Theorem 10.53). Classes (c) and (d) |
| 3 Nullifier uniqueness | Conditional | The direct batch counting reduction `ε_3^app ≤ s_batch + u_C,seal + F_V,batch + Z + α_P + ρ + g_batch`, with no extractor and no nullifier-uniqueness premise (section 7.5). The determinism of the nullifier for a credential and scope is unconditional | Values of `u_C,seal`, `F_V,batch`, `α_P` and of the terms inside `Z`; the validated-list contract with relation correctness and message binding |
| 4 Unlinkability, non-frameability | Conditional | Unlinkability by the privacy composition with `auth_v` among the challenge outputs: `ε_priv ≤ 2·Z + 2·α_P + 2·ρ` (below). Non-frameability: the union of the two endpoints is at most `ε_2^app + ε_8^app`, identity reductions in which framing means fresh authorization, since published proofs can be copied | `α_P` and the terms inside `Z`. The stated disclosure exclusions are part of the claim. Class (d) for concrete SHAKE |
| 5 Joint quantum zero knowledge and anonymity | Conditional | The game (below). One total witness-free simulator for both roles; the outer composition with challenge 1 programmed at its salted input; the CRT-layer argument with the singleton-record deletion lemma; `ε_JZK ≤ Z ≤ ε_1 + T·e + K + σ` (section 8.5). Anonymity: `ε_priv` as for gate 4 | The four generator advantages inside `e` have no values, and the random-oracle model of the backend domains is an idealisation. The written bound on `Z` exceeds 2^-64 at the ceilings whatever those values are (section 8.5). Class (c) |
| 6 Concrete security | Not met | The consolidated ledger with its component table, the six game inequalities, the crossing conditions and a nominal substitution that is hypothetical (section 8.5) | Justified values of `e`, `α_P`, `u_C`, `u_N` and `F` at the complete resource vectors; the concrete justification of the backend oracle model; the independent attack assessment. Compliance with either part of the contract of section 8.8 is unestablished |
| 7 Bounded deterministic verification | Conditional | A design argument: verification as a total deterministic function of the canonical proof bytes and the authenticated public context, with finite work and allocation bounds and prescribed malformed-input behaviour, the early rejection of an out-of-range counter included. It has no cryptographic hardness premise | The production envelope and Norito mappings, which are not written; a complete arena and work inventory at the final layout (section 9.7; no allocation certificate exists); bounded-parser fuzzing, cross-architecture parity and qualification measurements. The standalone parser/verifier and component/malformed-input tests are implemented (section 11.2). The 250 ms limit is a separate measurement |
| 8 Registration authorization | Conditional | The registration-origin game with per-handle logs, the event inclusion and `ε_8^app ≤ s + u_C,target + F_R + Z + α_P + ρ + g_R` (section 7.3). It needs no extractor | Values of `u_C,target`, `F_R`, `α_P` and of the terms inside `Z`. Class (c) |

**Dependencies [R].** Authenticated state, canonical framing and constraint
correctness are common deterministic prerequisites of every gate.

| Item | Premises | Result or status |
| --- | --- | --- |
| Canonical relation correctness | Frozen encodings, authenticated state, correct constraint evaluation | Deterministic obligation; the strengthened relation must be checked |
| Adaptive relation soundness, `s` and `s_batch` | Backend model, algebraic bounds, induced-seed uniqueness, the resource inventory | Written theorem awaiting review |
| Total padded joint simulator, `Z` | CRT mask argument, generator assumptions, programming, retries, totality | Conditional argument |
| P | The concrete four-tag SHAKE256 family in the test experiment (section 8.4) | Explicit unproved primitive assumption |
| U | The concrete existential experiment (section 8.4) | Explicit unproved structural assumption |
| Registration and vote authorization prediction | P | Proved reduction: `ε_pred,t ≤ ρ + α_P + q_guess·2^-512` (section 8.4) |
| Pair decorrelation | P | Direct restriction: `α_dec(ℛ) ≤ α_P(ℛ')` |
| Association hiding | Pair decorrelation, the equality restrictions | Conditional coupling |
| Gate 1 | `s` | Conditional |
| Gate 2 | `s`, `u_N` (from U), `F_V`, `Z`, P | Conditional |
| Gate 3 | `s_batch`, `u_C,seal` (from U), `F_V,batch`, `Z`, P | Conditional; direct batch reduction |
| Gate 4, unlinkability | `Z`, P, the disclosure exclusions | Conditional |
| Gate 4, non-frameability | Gates 2 and 8 | Endpoint identity reductions; the union is bounded by `ε_2^app + ε_8^app` |
| Gate 5, joint zero knowledge | The backend simulator premises | `ε_JZK ≤ Z` |
| Gate 5, anonymity | Joint zero knowledge and association hiding | Conditional |
| Gate 6 | All bounds at the actual resources and the statistical ledger | Not qualified |
| Gate 7 | Implementation, deterministic bounds, envelopes and measurements | Separate engineering qualification |
| Gate 8 | `s`, `u_C,target` (from U), `F_R`, `Z`, P | Conditional |

`F_R`, `F_V` and `F_V,batch` bound finding distinct legal authorization
frames with equal SHA3-512 digests; they may be restrictions of one global
legal-frame collision game `F`. If an application claim identifies scopes or
policies by their structured meaning and not by exact digest bytes, the
corresponding context-frame collisions belong in `F` as well. The
superscript `app` marks a bound of an application game, to keep it apart
from the programming losses `ε_1`, `ε_2`, `ε_3` below. `ρ` is the coupling
between independent and distinct honest secrets,
`ρ = binom(U, 2)·2^-384 < 2^-317` for `U ≤ 2^34` credentials. Vote
authorization prediction and pair decorrelation are not separate
assumptions: both are consequences or restrictions of P.

**The adaptive soundness theorem [R].** Full text: arguments file,
"Property 1: adaptive relation soundness".

- **Game.** The challenger generates all honest credential secrets and
  keeps the authenticated public state. The adversary has both real honest
  proof interfaces, malicious registration, the permitted corruptions and
  adaptive public submissions, and wins with an accepted `(role, x, π)`
  whose `x` is outside the role's language; with at most 1,001 outputs, if
  one of them is. No freshness condition is needed. Oracle-dependent
  preprocessing is charged; initial advice is independent of the backend
  oracles and of the honest randomness.
- **Model and premises.** The designated backend hash domains are
  independent quantum-accessible random oracles: an idealisation, not proved
  for concrete SHAKE256. Deterministic premises: parsing and public
  validation implement the complete statements; the ordered constraint
  systems are equivalent to their relations over Boolean witnesses; the
  field operations, CRT maps, reconstruction and compact-opening
  verification implement the frozen backend; the raw admissible challenge
  map is injective; the two 77-byte role prefixes are distinct. No
  credential pseudorandomness, uniqueness, one-wayness or zero-knowledge
  assumption is used.
- **Statement.** Let `J` be the event that, in both role namespaces, for
  every 128-bit IV and each of the 33 vector tweaks, every leaf commitment
  has at most one induced seed. For any deterministic leaf PRG, with the
  leaf commitment of section 6.6.1:

  ```text
  δ_leaf,all := Pr[not J] ≤ 2·2^128·33·binom(2^256, 2)·2^-896 = 33·(1 − 2^-256)·2^-256 < 2^-250.9556

  s       ≤ δ_leaf,all + 340·Q^3·2^-512 + 70·Q^2·2^-256
  s_batch ≤ δ_leaf,all + 1001·(340·Q^3·2^-512 + 70·Q^2·2^-256)

  Q ≤ q_pub + 1447·T + 2^20·T + 1024
  ```

- **Method.** Conditional on `J`, the complete functions `H0`, `H4` and
  `H5` are fixed (analytical conditioning, not an executable table); the
  domains of `mu`, `H1` and the three challenges stay random oracles. A
  challenge-1 input then fixes the IV, the leaf-hash key and one response
  graph. The database predicate covers every false complete statement of
  both roles through its first bad round, with collisions in `mu`, `H1` and
  the first two challenges; outside them a prefix has one predecessor chain,
  so there is no union over statements, credentials, registrations or
  scopes. Its local witnesses have 38 cells (one `mu`, 33 inner `H1`, one
  outer `H1`, three challenges). The transition table, late completion of an
  old chain by a new `mu` or `H1` answer included, gives
  `δ(k) ≤ 34·k·2^-512 + 7·2^-256`, with the round bounds of section 8.2
  re-derived at the strengthened dimensions and the root bound taken over
  the raw final challenges. The batch reduction pads to 1,001 outputs and
  selects one; the global event is charged once.
- **Imports.** FAEST v3 Lemma 10.44 (compressed-oracle search for a
  predicate with local witnesses), and Lemma 10.50 only for the
  acceptance-preserving conversion of a compact proof to its explicit
  transcript. Not used: the passive-prefix and isolation conclusion of
  Lemma 10.48, Lemma 10.49 as an adaptive theorem, and the
  one-way-function and key-distribution step.
- **Query ledger.** `q_pub` includes the adversary's backend queries and
  every backend call induced by its public verification, registration and
  submission requests. Honest calls can create the predicate and are
  counted: 1,447 fixed backend calls per candidate-row proof (1,408 `H5`,
  34 `H1`, five others) and every attempted counter, `2^20·T` under the
  deterministic limit. The constant 1,024 covers one selected final
  verification (at most 744 backend calls, stored and reused) and the 38
  certificate cells. At `q_pub = 2^64`, `T = 2^44`:
  `Q = 36,918,944,040,625,374,208`, `log2 Q = 65.0009950923`,
  `s < 2^-119.8687268`, `s_batch < 2^-109.9015005` **[R]**, recomputed here
  **[D]**. Non-oracle proving and verification work stays in the operation
  ledger; credential evaluations idealised as oracles in another game need
  their own accounting.
- **Open.** Independent review. The direct local argument, a predicate that
  handles a late `H4` or `H0` answer completing an existing chain, is
  missing: a missing proof step, not an exhibited forgery, which the theorem
  avoids at the cost of `δ_leaf,all`. The constants are written for the
  candidate row; for the comparator the review gives only the coefficient 22
  in `δ_leaf,all` (55 for both rows together).
- **Not given.** No extraction, no possession guarantee, no restriction on
  proofs of true statements; nothing about authorization prediction,
  uniqueness, anonymity, joint zero knowledge, concrete-SHAKE security or
  deployment readiness. The query-dependent part is not a statistical
  bound; only `δ_leaf,all` is (section 8.8).

**The gate 5 game [R].** Full text: arguments file, "Games". One global bit
and one stateful simulator for the entire execution, both roles and every
credential. The adversary holds arbitrary quantum auxiliary information
about application witnesses, complete secrets included, and makes adaptive
classical, atomic requests `Prove(role, x, w_app)` with witnesses of its
choice. Both worlds apply the same public validation and check
`R_role(x; w_app)`; an invalid request returns the same error without the
simulator, and no statement is silently repaired. A valid request is
answered by the exact prover with an independent uniform 112-byte tape,
counter loop and exhaustion outcome included, or by `Sim(role, x)`, which
receives neither the application witness, the selected index, the trace nor
the pad and programs only the designated backend oracle domains. Requests
interleave with quantum oracle queries, verification, malicious
registrations and other operations; oracle access continues after the last
request; all queries are counted and the lifetime ceilings apply. There is
**no tape-selection or secret-coins-disclosure interface**; the transmitted
`iv_pre` and salt are public. The game imposes no hidden-honest-key
requirement. It invokes simulation only for valid witnessed statements; the
privacy hybrids additionally need the simulator to run on every
syntactically valid statement, false intermediate ones included, which is
algorithmic totality and not a zero-knowledge claim for false statements.

**The joint simulation argument [R].** Full text: arguments file,
"Property 5: zero knowledge and anonymity". `T ≤ 2^44` counts all valid
proving invocations of both roles, exhaustion included; `q` is the
adversarial oracle budget, `2^64` at the ceilings; `M = 2^20`;
`g = n_mult = 704`. The games: the actual prover; challenge 1 programmed at
its exact salted input (`ε_1`); challenge 2 programmed (`ε_2`); an
independent uniform value installed at every attempted counter, stopping at
the first admissible one or at exhaustion (`ε_3`); the stopping schedule
sampled first and coupled to the selective-opening challenge (0); the
CRT-layer argument (`ε_CRT`).

```text
ε_1 ≤ T·( sqrt((q + T)·2^-256) + (q + T)·2^-256 / 2 )  ≤  (3/2)·T·sqrt((q + T)·2^-256)
ε_2 ≤ (3/2)·T·sqrt((q + T)·2^-2112)
ε_3 ≤ (3/2)·T·M·sqrt((q + T)·2^-832)

ε_CRT     ≤ T·e + ε_initial + δ_MH + δ_sep + 2·ε_delete
e         = ε_root + 396·ε_tree + 33·(ε_leaf + ε_expand)
ε_initial ≤ (3/2)·T·sqrt(256·g·(q + 1408·T)·2^-384)
δ_MH      ≤ 2·2^-256 + T·2^-256 + 2·g·T^2·256·2^-384
δ_sep     ≤ (T + 2·g·T^2)·2^-256
ε_delete  ≤ 2·q_eff·2^-128 + δ_salt,      q_eff ≤ q + 704·T,
δ_salt    ≤ binom(T, 2)·2^-256 < 2^-169
σ         ≤ T·e^(−2·M/7360) = 2^-367.0802704
```

- **Challenge 1.** With the other oracle functions fixed, every complete
  challenge-1 location contains the request's privately sampled salt and has
  point probability at most `2^-256`, also when `c_mult` depends on salted
  `H5` evaluations. This is a marginal location-probability argument, not a
  conditional-entropy assertion after intermediate disclosure, which atomic
  requests prevent. It is the fresh-location form of adaptive reprogramming
  (Grilo, Hövelmanns, Hülsing and Majenz, Theorem 1). Commitment
  unpredictability is not needed, and the outer composition has no
  primitive term.
- **Challenge 3 and the stopping law.** The oracle is partitioned by the
  four-byte counter and the counter domains are replaced in order, each with
  location bound `2^-832`; all `T·M = 2^64` attempted points are charged.
  With `p` the fraction of admissible 256-bit challenges, the programmed
  game has `Pr[C = c] = (1 − p)^c·p` for `0 ≤ c < 2^20` and
  `Pr[exhaustion] = (1 − p)^M`. The selective-opening coupling costs
  nothing under its hypotheses: admissibility depends only on the challenge,
  the commitment coins do not depend on the selected opening, no witness
  data enters acceptance, and exhaustion is retained with its oracle
  effects.
- **Acceptance and exhaustion, candidate row.** The expected number of
  sibling seeds in the canonical opening is below 222 for the frozen heap
  and leaf mapping; rejection needs at least 230; Markov's inequality and the
  eight grinding bits give `p > (4/115) / 256 = 1/7360`. **[D]** Those two
  steps were recomputed here; the expectation was not. In the programmed
  game: fewer than 7,360 expected attempts per invocation; one exhaustion
  with probability at most `e^(−2^20/7360) = 2^-205.5401352`; any exhaustion
  at most `2^-161.5401352`; `Pr[G > 14720·T] ≤ e^(−T/4)` for the total
  number `G` of attempts. **In the real game the exponential bound is not a
  theorem by itself**; the transfer is
  `Pr_real[any exhaustion] ≤ T·e^(−M/7360) + ε_1 + ε_2 + ε_3`, with no CRT
  primitive loss. Genuine exhaustion adds nothing to `Z`, because the
  simulator reproduces it. The comparator does not inherit the bound on
  `p`. An opening-abort fraction of 0.14 reported by the implementation
  work would mean about 298 attempts per proof; it is a measurement, not a
  certified bound.
- **CRT layer.** The four generator games of `e` replace the joint root
  expansion with its two tweaks, the hidden GGM-path expansions, the
  nine-block leaf expansion and the hidden expanded VOLE rows by uniform
  output (block counts 5, 4, 9 and 419). They are quantum pseudorandomness
  assumptions about the actual generators at the actual IVs and tweaks,
  shared-IV and cross-role correlations retained; the conformance vectors
  do not establish them. FAEST's multi-hiding lemmas (10.24 and 10.51) apply
  in their selective-opening experiment. The ten masks are solved jointly:
  the six QuickSilver masks first, the four consistency masks compensating.
  The pad makes the label offset independent of the application witness,
  also when that witness is known; that identity does not cover responses
  computed from the pad.
- **Deletion of the hidden labels.** The `T` salts are presampled, unused
  slots included. Outside a salt collision a query's salt identifies at
  most one proof record and its gate index one hidden label, and matching
  that label fixes one value of its independent 256-bit pad. The collision
  term is additive, not under a square root, and conditioning on salt
  uniqueness does not condition on the pads. `q_eff` assumes cached
  reconstruction and counts every later `H5` evaluation; the auxiliary
  information may contain the application witness but no fresh pad (the
  one-way-to-hiding step is Jaeger, Theorem 2.1; not read by us). `δ_MH`
  and `δ_sep` are the conservative bounds and count some events twice. The
  review also derived a bound for an unsalted `H5` from the multiplicity of
  IVs across contexts, `2·q_eff·sqrt(3·2^-256) + δ_mult ≈ 2^-62.2066` with
  `δ_mult < 2^-304.664752 + 2^-190.619178`, and did not adopt it.
- **The simulator `Sim+`.** It samples a fresh root, `iv_pre` and salt,
  builds the commitment with the 112-byte leaves, uses the salt in every
  `H5` evaluation of the proof, samples the public response fields and
  derives `V~` and `a~_0` from the public equations, programs challenge 1 at
  the salted location, challenge 2, and challenge 3 at **every** attempted
  counter, and returns the proof or the exhaustion result. One persistent
  oracle state serves all requests; nothing is reset or rolled back. On
  exhaustion it tries at most `M` further independent challenges for its
  unused admissible opening and then falls back to the admissible `0^256`;
  those trials need randomness and admissibility checks, not programming.
  Their bounded-total-simulator correction is `σ`; the up-to-`M` random
  samples and admissibility checks are included in the resource vector.
- **Resources.** At most 2,764,797 AES blocks per candidate-row commitment
  and 2,750,672 per heavy public verification, with at least 740 charged
  backend calls (section 9.7); at most `4·M·T = 2^66` counter-related Keccak
  permutations; at most `q + T` queries per programmed domain. **The
  primitive terms are evaluated at the adversary's resources plus these
  costs**, not at the query budget (section 8.5).
- **Status.** Assumed: the four generator games and the random-oracle model
  of the backend domains. Not established: any value of `e`, hence of `Z`.

**Anonymity and unlinkability [R].** Full text: arguments file, "Anonymity:
association hiding after joint simulation". Joint zero knowledge does not
give association hiding of the public values; the composition uses the
common credential experiment and assumption P of section 8.4.

- **The vote test.** A challenge ballot of handle `j` at scope `σ` with the
  other public fields `z` is tested in sequence: the nullifier entry
  `(j, PNF1, σ)`, giving `n`; the digest `d = D_v(z, n)`; the authorization
  entry `(j, PAV1, d)`. The random branch returns
  `(F_j,PNF1(σ), F_j,PAV1(D_v(z, F_j,PNF1(σ))))`. Nullifier entries are
  indexed by credential and scope, authorization entries by credential and
  complete-statement digest. Accidentally equal outputs of different
  entries are not rejected.
- **Admissibility of `LR(j_0, j_1, z)`,** with one persistent hidden bit.
  (1) Both handles are honest, uncorrupted, in their original common body
  and in the same authenticated sealed list. (2) Neither candidate
  credential and scope pair has had an identified nullifier exposure.
  (3) Both handles become protected against corruption and both pairs
  blocked against identified disclosure. (4) Across challenge requests the
  equality partitions of the candidate and scope pairs agree on both sides.
  (5) With the tentative returned nullifier and its **actual** public
  digest `d_t`, neither candidate authorization entry `(j_0, PAV1, d_t)`,
  `(j_1, PAV1, d_t)` has been exposed concretely; two counterfactual digests
  are not computed. (6) The equality partitions of the authorization
  entries agree on both sides, and both candidate entries are then blocked.
  (7) Every other observable field, policy outcome, quota and error is
  symmetric: both possible branch counters are maintained, a request is
  rejected if either would exceed its allowance, and no identity-labelled
  issuance log is revealed. A late rejection keeps the protection, the
  blocking and the oracle effects and exposes neither tentative value.
- **Hybrids and bounds.** Real proofs to the one shared simulator (`Z`);
  independent honest secrets to distinct ones (`ρ`); concrete challenge
  pairs to random pairs (`α_dec`); the challenge bit switched at zero cost,
  by coupling nullifiers along the classes of rule 4 and authorizations
  along those of rule 6; and the three restorations.

  ```text
  ε_association ≤ 2·α_dec + 2·ρ,      α_dec(ℛ) ≤ α_P(ℛ')
  ε_anonymity, ε_unlinkability ≤ 2·Z + 2·α_P + 2·ρ
  ```

  These are deployment-wide terms, not per-proof bounds to multiply by `T`.
  `ℛ'` adds the digest computation, two test calls and the simulator work.
- **Available and excluded.** Registration authorizations, other-scope vote
  authorizations and identified authorizations at other digests stay
  available. An identified authorization for the exact candidate digest is
  excluded by rule 5. Equal nullifiers link ballots at a scope, ballots with
  different votes included, and `auth_v` does not conceal that intentional
  link. A previously identified nullifier excludes anonymity at that
  credential and scope. The claim is cross-scope privacy under these
  exclusions, without retrospective protection after disclosure of a
  challenge secret, and without covering identity-bearing transport
  information or distinctive public voting behaviour.
- **Blanket replacement is invalid.** Replacing every honest credential's
  outputs and later revealing a concrete secret is distinguishable at once:
  handles are protected online, commitments are never randomised and
  untested outputs stay concrete.

Three supporting arguments are written in full and await independent review.
They are not gates:

| Argument | Statement | Limits |
| --- | --- | --- |
| Encoding equivalence | The ordered constraint system vanishes exactly on Boolean encodings of valid witnesses (section 6.3). It replaces the AES-specific relation step of the FAEST argument and needs no key-validity restriction | A premise of the soundness theorem. The review asks that the strengthened constraint equivalence, with the 1,024-bit nullifier output and the vote-authorization block, be checked in the independent review. No constraint implementation of `R_vote+` was read in the repository **[C]** |
| Universal-hash bounds | `ε_v ≤ 2^(−4·lambda)·(1 + (l+5)^5 / 2^64)` and `ε_zk ≤ 2^(−lambda)·(1 + (N_c − 1)^2 / 2^64)`, for an input fixed before the seed is sampled (section 8.2) | New derivations by root counting, at the strengthened dimensions. They extend the proofs of FAEST Lemmas 4.6 and 4.7 and are not applications of those lemmas, whose length hypotheses fail |
| Response-graph soundness for false instances | For a publicly valid false instance and an unbounded prover in the interactive protocol, the three core bad events are bounded by `ε_v·binom(2^248, 3)`, `ε_zk` and `7·2^-256` (section 8.2) | Static false instances only; the response reconstruction is mathematical. The adaptive theorem uses these as pointwise round bounds |

The published FAEST work supplies ingredients, not these custom-scheme
arguments **[R]**: its hash lemmas are re-derived; its whole-scheme and
single-key theorems (Theorems 10.30 and 10.53, Corollaries 10.41 and 10.54)
do not transfer; the audit of every import is in the arguments file, "Audit
of imported results". No gate is known to be impossible in principle, and
the review cannot promise that the open items can be closed **[R]**.

What remains **[R]**: independent review of every argument, primitive
qualification (sections 8.4 and 8.5), the closed resource and statistical
ledgers, the attack-cost assessment, the production envelopes and the
implementation qualification (section 12). The launch gate stays false
until those obligations and independent review are completed.

### 7.2 Two unsafe shortcuts

Both appeared in the research pass and are rejected **[R]**; primary reading
reaches the same conclusion on the first **[D]**.

- **Soundness plus injectivity does not give the `k`-credential bound.** It
  bounds the whole list to at most `S` credential handles. It does not prevent
  a proof for a true statement about an uncorrupted credential whose ballot
  has never been requested. That needs an unforgeability argument, which the
  direct batch reduction of gate 3 supplies through its fresh-authorization
  event (section 7.5).
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
reduction charged to the resource vector:

```text
ε_8^app ≤ s + u_C,target + F_R + Z + α_P + ρ + g_R,      g_R = q_guess,R·2^-512
```

`s` is the soundness bound of section 7.1, `u_C,target` the restriction of
assumption U to registration-origin targets, `F_R` the registration-frame
collision term, `Z` the joint zero-knowledge bound and `α_P` the advantage
of assumption P, through which the prediction premise is discharged
(section 8.4).

- The uniqueness premise is **existential almost-injectivity**, not ordinary
  computational collision resistance. Without extraction, a collision-finding
  assumption cannot simply replace it. For this gate assumption U must cover
  the adversarially selected target context `B*`, including a
  recontextualization that has never been sealed (section 8.4).
- Joint simulation is applied to the efficiently checkable
  `FreshAuthCorrect` prediction event, whose challenger knows the honest
  keys. It is not applied to deciding whether an arbitrary statement is false
  or has another opening.
- This route does not require a uniform-commitment replacement or the
  programming of credential functions. It needs no extractor.
- The registration authorization values depend on the descriptor digest
  `D`, which `D_reg` covers (section 6.2).

The bound is conditional: `u_C,target`, `F_R`, `α_P` and the generator terms
inside `Z` have no justified values, and gate 8 is not established
(sections 7.1 and 8.5). The same form of split carries gate 2
(section 7.5).

Duplicate rejection prevents reuse after registration; the game protects the
period before the honest registration lands. An anti-copy theorem alone is
not the `k`-credential nullifier bound of gate 3 **[R]**.

### 7.4 STARK route

This table is this evaluation's own judgement **[E]** from sources read mostly
as abstracts.

| Gate | Route and class | Missing |
| --- | --- | --- |
| 1 | Adaptive relation soundness of the exact masked protocol in the QROM, by a proof of its round-by-round soundness: (c). Adaptive straight-line quantum extraction for hash-based reductions (Chiesa–Di–Hu–Zheng **[U]**) would give more than gate 1 requires | Theorem statements not read; nothing is stated for a masked DEEP-ALI protocol with this relation |
| 2 | Simulation-soundness under reprogramming for multi-round BCS in the QROM: (c) | No published theorem found |
| 3 | Extraction plus ordinary collision resistance of the commitment and tree hash: (b) | An extraction theorem, which gate 1 no longer supplies; digest length per section 8.3 |
| 4 | PRF from the in-relation hash, given gate 5: (b) | Gate 5 |
| 5 | Multi-theorem adaptive QROM simulator covering salted Merkle openings and both relations: (c) | No published theorem found; the in-repo substrate has unsalted leaves **[E]** |
| 6 | Parameter calculation after 1, 2, 5 | The form `t^2·eps + t^3/2^lambda` of the Chiesa–Manohar–Spooner bound was seen only in search excerpts **[U]** |
| 7 | By design: fixed query count, integer arithmetic: (b) | Nothing is implemented for the ballot relation |
| 8 | Simulation-extractability, a sufficient route, in the classical ROM only (Chiesa–Fenzi **[U]**, preconditions not read); credential-origin unforgeability in the QROM: (c) | No published theorem found |

The STARK route has extraction available in the QROM at abstract level, which
the VOLE-in-the-head route lacks; gate 1 no longer requires it
(section 7.6). It has more unproven zero-knowledge theory
and a size near or above the target (250–600 KiB **[E]**, unmeasured).
**[R]** No demonstrated impossibility of meeting 256 KiB has been established.
A narrow standard-hash STARK remains the fallback research candidate **[R]**
(section 11.5).

### 7.5 The gate 2 event split and the gate 3 batch reduction

Both are the review's **[R]**. Neither uses an extractor, and neither bound
has a value.

**Gate 2.** Write

```text
Y_v(x) = Frame("PARL/VOTE-AUTH/v1"; ...)   // every vote statement field except auth_v
d_v(x) = SHA3-512(Y_v(x))                  // the D_v of section 6.2
```

and let `Tag^1024_scope(s)` be the nullifier function and `Auth^v_d(s)` the
vote authorization function of section 6.2.

**Logs.** For each honest handle `j` the challenger maintains `VoteLog[j]`,
the complete authorized statements, and `VoteAuthLog[j]`, their
authorization digests. An authorization is recorded **before `auth_v` is
exposed**, also when proving fails or exhausts its counter.

**The event split.** For a winning output that targets the uncorrupted
secret `s_j`:

1. If its statement is false, it is charged to adaptive vote soundness.
2. Otherwise an existential witness `s'` satisfies all three equations of
   `R_vote+`.
3. Outside the event
   `BadTagOpen = {∃ s' ≠ s_j : Tag^1024_scope*(s') = Tag^1024_scope*(s_j)}`,
   that witness must be `s_j`, so `auth_v* = Auth^v_{d_v(x*)}(s_j)`.
4. If this digest occurs in `VoteAuthLog[j]`, take its logged statement
   `x_0`. Distinct frames with equal digests give a SHA3-512 collision.
5. Equal frames identify every statement field except `auth_v`; truth and
   the unique target secret identify `auth_v` too. So `x* = x_0`, which
   contradicts freshness.
6. Every remaining win therefore correctly predicts the authorization value
   for a fresh pair `(j, d_v(x*))`.

The resulting inclusion:

```text
Win_2 ⊆ FalseAccepted_vote ∪ BadTagOpen ∪ FrameCollision_v ∪ FreshVoteAuthCorrect
```

Its complete premises:

| Premise | Required experiment or fact |
| --- | --- |
| Deterministic construction | Correct public validation, encoding equivalence, complete injective frames, the fixed descriptor, honest logs and the corruption exclusions |
| Adaptive vote soundness | A false accepted statement, with both **real** honest proof interfaces available |
| Adaptive nullifier-opening uniqueness | The existential target event `BadTagOpen`, including adaptively selected targets and scopes (section 8.4) |
| Vote-frame collision resistance | Quantum collision resistance of SHA3-512 on distinct legal `Y_v` frames |
| Joint zero knowledge | Both revised relations, arbitrary application-witness auxiliary information and the shared stateful simulator |
| Vote-authorization prediction | Both authorization families, commitments, nullifiers, malicious registrations, permitted corruptions, simulated proof interfaces and quantum queries remain available; the output is correct for an uncorrupted target and a fresh **per-handle** digest |
| Resource accounting | All exploration, preprocessing, public verification, honest proving and reduction overhead is charged |

The conditional bound:

```text
ε_2^app ≤ s + u_N + F_V + Z + α_P + ρ + g_V,      g_V = q_guess,V·2^-512
```

- Joint zero knowledge is applied only to `FreshVoteAuthCorrect`, which the
  challenger can test efficiently with its honest secrets. Computational
  indistinguishability is **not** applied to deciding whether an arbitrary
  statement is false or whether an opening is existentially ambiguous.
- The prediction event is then bounded through assumption P
  (section 8.4); `u_N` is the restriction of assumption U to the designated
  scopes, which implies the target-opening condition used here.
- A statement honestly issued for another handle (the event `CrossIssued_2`)
  is covered by the other-handle interfaces of the prediction game. It is
  not discarded.
- Repeated honest secrets are charged by `ρ`. Nullifier injectivity does not
  eliminate two handles with the same secret.
- Including `concat(L)` in `Y_v` makes the authorization-frame argument
  independent of a separate list-digest collision reduction (section 6.2).
- Anyone may still relay an already authorized ballot, including delivering
  it before its creator does. Gate 2 therefore means **no unauthorized fresh
  message**, not exclusive control over delivery.

**Gate 3: the direct batch reduction.** `k` is the number of adversarially
registered or corrupted sealed entries, including entries whose registrant
knows no opening. Retain at most 1,001 output ballots with distinct
nullifiers outside the honest-issued set `H` (`k = S = 1,000` is allowed).

1. A false retained statement is charged to batch soundness, `s_batch`.
2. Outside the event that some sealed entry has two openings, which is
   charged to `u_C,seal`, each of the `k` controlled entries explains at most
   one nullifier. More than `k` distinct nullifiers outside `H` therefore
   include a ballot with a witness for an honest entry, and commitment
   uniqueness forces that witness to be that entry's honest secret.
3. So the following event occurs, and it is efficiently testable: some
   retained ballot carries a fresh correct authorization value for some
   uncorrupted honest handle of the sealed list. The challenger tests it by
   enumerating at most `1,001 × 1,000` ballot and handle pairs.
4. Joint zero knowledge is applied once, to that event. After a frame
   collision is excluded (`F_V,batch`), all eligible fresh authorization
   guesses are output in one prediction game, which reduces to P.

```text
ε_3^app ≤ s_batch + u_C,seal + F_V,batch + Z + α_P + ρ + g_batch
g_batch ≤ 1,001,000·2^-512 < 2^-492.0669
```

- No witness is extracted or selected: the argument is exact existential
  counting.
- `Z` and `α_P` are charged once. The reduction does not go through gate 2
  with a selection factor, and it does not need nullifier-opening
  uniqueness: commitment uniqueness identifies the honest witness.
- `s_batch` carries the factor 1,001 on its query-dependent part and charges
  the global leaf event once (section 7.1).
- **`H` must include the nullifiers whose authorizations were disclosed on
  failed or exhausted proving requests.** Otherwise "outside the
  honest-issued set" does not have the required freshness implication.
- The argument uses existential opening uniqueness in place of computational
  collision resistance, a stronger and different premise (section 8.4).

Both bounds are conditional: none of `u_N`, `u_C,seal`, the frame terms,
`α_P` or the generator terms inside `Z` has a justified value
(section 8.5). The review judges the routes completable under their
premises; that is a judgement, not a proof of the premises.

### 7.6 Why knowledge extraction is not required

Efficient extraction is a means of establishing authorization, not one of
the ballot system's application goals; requiring it once authorization can
be established another way would make release depend on a stronger theorem
than the application needs **[R]**. Gates 2, 3 and 8 must carry the
authorization guarantees independently **[R]**, through the event splits and
the batch reduction of sections 7.3 and 7.5, which use soundness,
existential uniqueness and authorization prediction and no extractor. Those
reductions are conditional and none is established (section 7.1). This is a weakening of gate 1 and is recorded as one
(sections 2 and 10.2).

What is known about extraction for this backend **[R]**: reading oracle
queries directly fails, because the QROM has no classical query log and even
a classical record exposes leaf commitment values, not the seeds; two
openings with different final challenges recover one complete vector, yet
special soundness from two to seven accepting transcripts is false (an
algebraic counterexample, not an efficient forgery); eight branches with
distinct final points allow an efficient reconstruction under stated binding
and hash conditions, but nothing shows how to obtain those branches; and the
generic multi-round measure-and-reprogram bound loses about 2^387.4 at 2^64
queries, so it is vacuous at the row. A root tag bound into challenge 1 does
not establish seed consistency, and checked per-leaf tags as an extraction
mechanism are an unproved variant that is not adopted. The affine checksum
of the leaf commitment (section 6.6.1) is not such a mechanism: it serves
the induced-seed uniqueness count of the soundness theorem, which gives no
extraction. Efficient adaptive extraction remains an open
research problem that this application no longer requires. The analysis is
kept in the [arguments file](parliament_ballot_proof_arguments.md) as
analysis of a requirement that is no longer imposed.

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

**[R][D]** Three quadratic coefficients of `Q^2 / 2^256` must be kept apart
on the fast row, where `tau + d_zk = 40`: 400 for the static published
shape `10·(tau + d_zk)`, 1,600 with the worst-case factor four of
Lemma 10.50, and 3,200 for the full chosen-message comparison of
Corollary 10.54. Their terms reach 2^-64 at `log2 Q` = 91.678, 90.678 and
90.178 and 1/2 at 123.178, 122.178 and 121.678, recomputed here as
`log2 Q = (256 + log2 p − log2 c) / 2`; at `Q = 2^128` each equals its
coefficient. The published bound is therefore vacuous at 2^128 queries in
every form. This is a limitation of the bound, not evidence of an attack,
and none of the three is a bound proved for the ballot construction
**[R]**.

**Query offset of the static comparison [R].** A static comparison for the
compact proof on the fast row uses `Q = Q~ + 125`, hence
`Q_comparison = q + 37·T + 125`: Lemma 10.49's `Q~ + 2·tau + d_zk + 12 =
Q~ + 85` holds for its explicit-leaf intermediate experiment only, and the
conversion from the compact proof adds `tau + 7 = 40` calls (one `H0`,
34 `H1`, the four `H2` calls and one `H4`), besides the `n_mult` calls to
`H5`. **[D]** The arithmetic agrees: `2·33 + 7 + 12 = 85`,
`1 + 34 + 4 + 1 = 40`, and the constant of the formula above is
`3·tau + d_zk + 19 = 125`, with `tau + 4 = 37`. This offset belongs to the
comparison with the published single-key formula (arguments file,
"Comparison with the published formula"). The ballot's own soundness
theorem has its own query ledger (section 7.1).

**[D]** In the chosen-message bound the reprogramming term
`2·Q_sig·3·sqrt(3·sqrt(Q_1)·2^-lambda)` is about
`2^3.4 · Q_sig · Q_1^(1/4) · 2^(-lambda/2)`: about 2^-88.6 at `lambda` = 256
for `Q_sig = 2^20` and `Q_1 = 2^64`, and, with the whole transcript ceiling
of section 8.8 as the signing budget, about 2^-64.6 at `Q_1 = 2^64`
**[R][D]**. A further term is `Q_sig` times the square root of the AES-CTR
PRG advantage. These are substitutions into a single-key formula, not a
bound for the ballot, whose own programming terms are in section 7.1. The
specification's summary calls the proofs "almost tight, except for a
multiplicative loss in the number of signing queries" **[P]**
(section 11.1).

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
  true automatically, but nothing shows that every alternative list witness
  has disappeared **[R]**. The adopted argument for gate 2 does not take a
  false-instance route (section 7.5).
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
  `l` = 35,840 and 53,504, `N_c` = 72,576 and 108,931. The bounds are therefore
  re-derived, not imported (section 7.1). At the final dimensions, recomputed
  here **[D]**; the review gives the vote column's core bad event and ZKHash
  increment **[R]**, and they agree:

  | Quantity | Registration | Vote |
  | --- | ---: | ---: |
  | `l + 6` (VOLEHash polynomial length) | 35,846 | 53,510 |
  | `l + 5` (degree bound) | 35,845 | 53,509 |
  | `N_c + 1` | 72,577 | 108,932 |
  | VOLEHash inflation factor `1 + (l+5)^5 / 2^64` | 3,208.92 | 23,781.14 |
  | `log2` of the `ε_v` bound | −1,012.352 | −1,009.462 |
  | ZKHash increment `(N_c − 1)^2 / 2^64` | 2.855 × 10^-10 | 6.432 × 10^-10 |
  | Fast row, `log2` of the first core bad event `ε_v·binom(2^248, 3)` | −270.937 | −268.047 |
  | Small row, `log2` of the first core bad event `ε_v·binom(2^250, 3)` | −264.937 | −262.047 |
  | Fast row, sum of the interactive challenge errors, in units of 2^-256 | 8.0000319 | 8.0002362 |
  | Small row, the same sum | 8.0020402 | 8.0151196 |

  The sums are `8 + (1 + (l+5)^5 / 2^64) / (6·2^24) + (N_c − 1)^2 / 2^64` on
  the fast row, with `2^18` in place of `2^24` on the small row, plus a leaf
  round that is negligible at this precision. The 8 is `1 + 7`: the ZKHash
  round and the final root count. With the leaf commitment of section 6.6.1
  the leaf-hash round contributes `(33/2)·(1 − 2^-256)·2^-384` per
  opportunity on the fast row **[R]**. The core round error stays at most
  `7·2^-256`, so the larger witnesses do not by themselves raise the
  degree-seven round error, and neither 64-bit evaluation point needs
  widening. Over 2^44 independently challenged interactive executions the
  fast-row union bound is about 2^-208.99996 **[R]**, recomputed here
  **[D]**. **That figure is an interactive component calculation, not the
  deployment's Fiat–Shamir ledger**, and it is not added again to the
  adaptive theorem, which has its own bound (section 7.1).
- **Adaptive statements.** Theorem 10.46 and Lemma 10.49 are stated for static
  adversaries **[P]**. Gate 1 needs adaptive soundness over both roles and
  all false complete statements, with both real honest proof interfaces
  available. The published static theorem is not cited as an adaptive ballot
  theorem. The review's adaptive theorem is a separate written argument that
  imports the compressed-oracle lemma and re-derives the round bounds; the
  passive-prefix conclusion of Lemma 10.48 does not cover the late `H4` and
  `H0` transitions and is not used **[R]** (section 7.1).
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
| Nullifier `nf` | 1,024 bits |
| `auth`, `auth_v`, `D_reg`, `D_v`, `R`, `B`, scope, policy digest, proposal-content digest | 512 bits |
| Construction identifier | 128-bit literal identifier; not a collision-security claim |
| Transcript message digest at the fast row | 512 bits |
| Backend GGM seeds | 256 bits |
| Backend leaf commitments | 896 bits: the 768-bit leaf hash and a 128-bit affine checksum |
| Backend aggregate commitments | 512 bits |
| Backend challenges | 2,112 / 832 / 256 bits |
| Backend IV / salt | 128 / 256 bits |
| Counter | Range `2^20`, encoded in 32 bits |

There are no membership-tree leaf or node digests. The leaf hash, the
aggregate commitment, the challenges and the seeds have the specification's
lengths `3·lambda`, `2·lambda`, `8·lambda + 64`, `3·lambda + 64` and
`lambda` at `lambda` = 256 **[P]**; the checksum, the salt and the counter
range are the extensions of section 6 **[R]**. A 512-bit digest gives
about 2^170.7 BHT collision queries **[D]**. The ballot design fixes no
256-bit length for `scope` or `policy_hash`; their lengths follow its
section 5 item 6 **[C]**.

**Why the nullifier has 1,024 bits [R].** The length is set by the
existential uniqueness argument of section 8.4, not by collision search. The
argument has to exclude alternative secrets for a target nullifier, including
ones nobody can efficiently find. For an ideal random map from 384 bits to
512 bits the expected number of colliding secret pairs in one whole map is
about 2^255, another secret matches one fixed honest tag with probability
about 2^-128, and the union over 2^44 fixed target and scope pairs is only
about 2^-84. At 1,024 bits the same union is below 2^-596. A 128-byte output
still fits the 136-byte SHAKE256 rate, so the wider nullifier adds no
permutation and no committed trace state. The lengthening supplies no general
claim of "1,024-bit SHAKE security" **[R]**.

### 8.4 Credential-side assumptions: P and U

Without an extractor, soundness gives only the existence of a witness. The
extractor-free reductions of sections 7.3 and 7.5 need that witness to be the
intended one, and they need a fresh authorization value to be unpredictable.
Computational collision resistance is not enough for the first, because the
reduction cannot output the two preimages **[D]**. FAEST states exactly this
stronger notion for its Even–Mansour variant and calls it an assumption that
cannot be efficiently verified **[P]** (v3 Definition 10.13).

The review states the credential side as two independent assumptions about
the concrete four-tag SHAKE256 family of section 6.2 **[R]**:

```text
f_t(s, x) = SHAKE256(t || P16 || s || x),    s ∈ {0,1}^384,  x exactly 64 bytes
t = PCR1 (commitment, 1,024 bits),  PNF1 (nullifier, 1,024 bits),
    PAU1 (registration authorization, 512 bits),  PAV1 (vote authorization, 512 bits)
```

They may share one name; they keep separate bounds. Neither has a proof or a
justified value. SHA3-512 frame collision resistance and the backend
assumptions are further premises of the system. No argument substitutes an
abstract random function inside the concrete Keccak constraint circuit.

**The common credential experiment [R].** Distinguishing advantages are
output-probability gaps: a gap `ε` corresponds to an optimal guessing
probability `1/2 + ε/2`. Authorization and soundness bounds are winning
probabilities.

- A resource vector `ℛ` records adversarial computation, preprocessing,
  primitive evaluations, application requests, proof simulation,
  verification, final comparisons, memory and gate costs. Public computation
  of SHAKE256, SHA3-512, Keccak-f and its inverse is permitted, coherently
  as well. Application requests are classical and atomic. Backend oracle
  access follows the QROM model of section 7.1.
- `U` distinct uniform secrets are presampled, so that no hidden row is
  programmed into an already queried ideal oracle later; handles may be
  revealed adaptively. Deployment samples independently, and the coupling
  costs `ρ = binom(U, 2)·2^-384 < 2^-317`.
- The experiment maintains authenticated application state. Its interfaces:

  | Interface | Information or action |
  | --- | --- |
  | `NewHonest(B)` | Reveals a new handle and its **concrete** commitment |
  | Registration authorization and proof requests | Reveal concrete registration authorization values, complete public statements and simulator responses |
  | Identified nullifier and vote requests | Reveal concrete nullifiers and concrete vote authorization values, at other scopes and other statements included |
  | Raw authorization queries | May additionally expose either authorization family on arbitrary 64-byte digests, within an explicit resource budget; they strengthen the assumption beyond application-only access |
  | Malicious registration, sealing and submission | Execute the actual public validation, verification and admission rules. No malicious opening is assumed known |
  | `Corrupt(j)` | Reveals the secret of handle `j`, unless the handle is protected |
  | Public computation | All permitted concrete quantum computation and backend oracle access |

- Every indirect disclosure counts as exposure of the corresponding function
  entry.
- Both honest proof interfaces use the one persistent, witness-free, total
  simulator `Sim+` of section 7.1, with shared backend-oracle state. Its
  runtime, programming, exhaustion behaviour and later oracle effects belong
  to `ℛ`.
- The experiment keeps a set of protected handles and sets of exposed and of
  tested entries `(j, t, x)`. `Reserve(j)` requires an honest uncorrupted
  handle and permanently prevents its corruption.

**Assumption P [R].** For `t ∈ {PNF1, PAU1, PAV1}`:

```text
Test_b(j, t, x) = f_t(s_j, x)       if b = 0
                  F_j,t(x)          if b = 1
```

where the `F_j,t` are independent random functions with the output lengths
of their tags. A first test reserves the handle and requires that exact
entry never to have been exposed concretely. Repeated tests return the same
value. Later concrete disclosure of a tested entry is forbidden. Other
entries stay concrete. **Commitments are never randomised.**

> **P: selective-entry pseudorandomness with public leakage.** For the
> specified concrete four-tag SHAKE family, the test experiment, including
> real commitments, both authorization families, adaptive corruption of
> unprotected handles, the common simulator and all public quantum
> computation, has advantage at most the recorded `α_P(ℛ)`, where
> `α_P(ℛ) = sup_A | Pr[A^(P_0) = 1] − Pr[A^(P_1) = 1] |`.

- P is stronger and more specific than ordinary single-key PRF security. It
  is an explicit assumption, not a consequence established anywhere of
  generic "SHAKE256 security".
- Protecting handles online is essential: the construction neither predicts
  future corruptions nor replaces commitments (section 7.1).
- **What P gives.** Pair decorrelation for the privacy composition, by
  restriction (section 7.1). Both authorization-prediction premises, by the
  reduction below.

**The two prediction games and their reduction to P [R].** `Pred_R` is the
game for `t = PAU1`, `Pred_V` for `t = PAV1`. There is no test interface
while the predictor runs. All disclosed credential outputs are concrete and
both proof interfaces use `Sim+`. The adversary sees every public commitment
and authenticated list, both authorization families on permitted other
inputs, identified nullifiers and complete identified ballots, the secrets
of adaptively corrupted other handles, malicious registrations and all
public verification results, the shared simulated transcript and backend
oracle environment, and public coherent computation of the concrete
functions. An authorization entry is recorded **before disclosure**, also
when proving then fails or exhausts its counter. The adversary outputs at
most `q_guess` triples `(j, d, a)`; a triple wins exactly when `j` is honest
and uncorrupted, `d` is a 512-bit string, `(j, t, d)` has never been exposed
by any interface and `a = f_t(s_j, d)`. Freshness is per handle and per
family: the other family at the same digest, and another handle's
authorization at that digest, are allowed. The single-output games have
`q_guess = 1`; a final list serves the batch reduction of section 7.5; no
unbounded free guessing interface is implied.

The reduction runs the predictor once. After it has committed its output
list, it reserves the eligible target handles, tests their fresh entries and
outputs whether any guess matches. In the random branch every fresh
authorization is an independent 512-bit entry, and a union bound applies
also with duplicate guesses:

```text
ε_pred,t ≤ ρ + α_P(ℛ_t') + q_guess·2^-512          for both families
```

There is no target-handle guessing factor `U`. The final tests and
comparisons are charged in `ℛ_t'`.

**An ideal-table lemma, kept apart [R].** It concerns a random function
indexed by hidden secret rows, not the concrete sponge and not a publicly
accessible random permutation. With `N = 2^384`, `μ = U / (N − U)` and
`g = q_guess·2^-512`, a time-dependent reference oracle that answers from an
independent base table on undisclosed rows differs from the real ideal
oracle only there, where the expected query mass is at most `μ`
(a use of the hybrid method of Bennett, Bernstein, Brassard and Vazirani;
not read by us):

```text
p_pred^ideal ≤ (sqrt(g) + 2·q·sqrt(μ))^2
             ≤ q_guess·2^-512 + (2·q + 1)^2·U / (2^384 − U)        when g ≤ μ
α_P^ideal    ≤ 4·q·sqrt(U / (2^384 − U))  ≈  2^-109 at q = 2^64, U = 2^34
```

At `q = 2^64` and `U = 2^34` the search term of the prediction bound is
`(2^-220 + 2^-284 + 2^-350) / (1 − 2^-350)`; one blind guess contributes
`2^-512` and `2^44` guesses `2^-468`. The prediction benchmark has a
search-order term and the distinguishing benchmark a square-root loss; they
must not be interchanged. Neither supplies public inverse-permutation access
or a bridge to concrete Keccak-f. They are diagnostics for a different,
ideal model, and neither is a value of `α_P`.

**Assumption U [R].** In the common environment with **real** proofs, the
adversary designates a legal collection
`𝒦 ⊆ {PCR1, PNF1} × {0,1}^512`, with separate bounds `m_C` and `m_N` on its
commitment contexts and nullifier scopes. It wins if

```text
∃ (t, x) ∈ 𝒦,  ∃ s ≠ s' ∈ {0,1}^384 :  f_t(s, x) = f_t(s', x)
```

The adversary need not output, know or efficiently find the two secrets.

> **U: selected-context existential uniqueness.** The probability of that
> event, with all adaptive exploration and preprocessing charged, is at most
> `δ_U(ℛ, m_C, m_N)`.

Its restrictions are the uniqueness terms of the reductions:

| Term | Restriction | Used by |
| --- | --- | --- |
| `u_C,seal` | Commitment uniqueness at authenticated seals | Gate 3 |
| `u_C,target` | Commitment uniqueness at registration-origin targets, **unsealed recontextualizations included** | Gate 8 |
| `u_N` | Nullifier uniqueness at designated scopes; it implies the target-opening condition | Gate 2 |

- Computational joint zero knowledge is not applied to the existential
  predicate: it is not an efficiently decidable distinguishing event.
- **P does not imply U.** Modify an otherwise secure family at two fixed
  secret keys so that their long outputs coincide for every context:
  random-key pseudorandomness changes only when one of those keys is
  sampled, with probability about `2·U / 2^384`, while every context map is
  non-injective.
- Computational collision resistance does not imply U either: inability to
  produce two colliding openings does not exclude their existence.
- **Concrete SHAKE is fixed.** There is no probability over "a random SHAKE
  implementation": the event at a deterministic context is a structural
  fact, and uncharged primitive-dependent advice containing a bad legal
  context would defeat a selected-context claim. The qualification must
  keep a costed preprocessing model and state exactly which deployment
  randomness and which context-selection process its probability concerns.
  Computationally bounded selection alone is not a proof of existential
  uniqueness.
- The record must not claim injectivity simultaneously for every possible
  context; over the entire space of 512-bit contexts the ideal-map
  expectation of same-context colliding pairs is about 2^255.

**Ideal-map diagnostics for U [R].** For an ideal random map and contexts
fixed independently of it. For a random permutation followed by truncation
to 1,024 bits the pair-collision probability is
`(2^576 − 1) / (2^1600 − 1) < 2^-1024`, so the same upper bounds apply:

| Event | Ideal bound |
| --- | ---: |
| One whole map from 384 to 1,024 bits is non-injective | `2^-257 − 2^-641` |
| The same over 2^24 fixed contexts | < 2^-233 |
| Another opening of one fixed honest output | < 2^-640 |
| The same over 2^34 fixed target and context pairs | < 2^-606 |
| The same over 2^44 fixed target and scope pairs | < 2^-596 |

**[D]** The exponents were recomputed here:
`binom(2^384, 2)·2^-1024 = 2^-257 − 2^-641`, `−257 + 24 = −233`,
`384 − 1,024 = −640`, `−640 + 34 = −606` and `−640 + 44 = −596`. They do not
prove the adaptively selected-context bounds, and the review does not accept
them as a concrete-SHAKE proof **[R]**. The 512-bit arithmetic that set the
nullifier length is in section 8.3.

**The review's reading of the literature [R].** None of these papers was
read by this evaluation; every entry is the review's statement, with its
numbers, and the last column is its conclusion:

| Source | Result as the review reads it | What it does not give |
| --- | --- | --- |
| Bertoni, Daemen, Peeters, Van Assche, 2008, Theorem 2 | Classical sponge indifferentiability, inverse permutation queries included. With `N` primitive calls, rate 1,088 and capacity 512: `ε ≤ N·(N+1) / (2^513·(1 − (N−1)·2^-1600))`, about 2^-385 at `N = 2^64`. All keys share one query inventory, so no factor `U` | Not a quantum theorem |
| Alagic, Carolan, Majenz, Tokat, 2025, Theorem 7.22 | Quantum indifferentiability of the full permutation-based sponge, with quantum permutation and inverse access: `O(l^2·sqrt(q^9·2^-min(r,c)) + l^3·(q^5·2^-min(r,c))^(1/4))` | At `l = 1`, `q = 2^64`, `c = 512` the terms are `O(2^32 + 2^-48)`: vacuous. It does not qualify this deployment |
| Carolan, Poremba, Zhandry, Theorem 8.1 | A one-round result with `O(2^(-r/2))` under `r ≤ c` and a reset and shared-randomness model | SHAKE256 has `r = 1088 > c = 512`; substitution is invalid, and one-block use does not remove the hypothesis |
| Gaži, Pietrzak, Tessaro, 2015, Theorems 2 and 3 | Classical keyed-sponge PRF bounds, for a construction that absorbs key and message in separate blocks | The tag, secret and context here share one block, an extension the paper discusses and does not give. No directly applicable quantum bound for P |
| Hosoyamada, 2025 (ePrint 2025/1059) | The abstract reports quantum results for keyed sponges and KMAC, with a KMAC regime about `min(2^(c/3), 2^(r/2), 2^((κ−r)/2))` | The review did not verify the full theorem and does not import it. Inserting `c = 512`, `r = 1088`, `κ = 384` naively gives a vacuous term; that is not an attack, since the encoding and hypotheses differ |
| Carolan, Majenz, September 2026, Theorem 5.5 | Explicit quantum **search** bounds for an ideal invertible permutation, digest length `d ≤ r`, `Q' = q + 2·L`: `p_pre ≤ 64·Q'^2·2^-d + 128·Q'^3·2^-c + 32768·Q'^2·2^-1600` and `p_col ≤ 32·Q'^3·2^-d + 128·Q'^3·2^-c + 32768·Q'^2·2^-1600`. At `Q' ≈ 2^64`, `c = 512`: collision terms `2^-315 + 2^-313 + 2^-1457` for `d = 512` and `2^-827 + 2^-313 + 2^-1457` for `d = 1024`; preimage terms `2^-378 + 2^-313 + 2^-1457` and `2^-890 + 2^-313 + 2^-1457` | Neither P nor U. The preimage target must be independent of the permutation, which commitment-derived targets do not automatically satisfy; a 2^34-target union would add 34 to the exponents. Its query convention and output-evaluation overhead must be preserved |

**What stays heuristic [R].** Replacing an ideal sampled permutation or
random table by the fixed public Keccak-f[1600] in these leakage, corruption
and selected-context games. Keccak-f is not a secret-key PRP instance.
Output length, standardised padding, conformance vectors and classical
indifferentiability do not discharge that replacement.

**Other maps [D].** For an ideal random map from `k` key bits to `n` output
bits the expected number of distinct colliding key pairs is about
`2^(2k − n − 1)`: 1/2 for a 128-bit key and two AES blocks or a 256-bit key
and four blocks, 2^-129 and 2^-257 for a 256-bit key and five or six blocks,
2^255 for the 384-bit secret and 512 output bits, and 2^-257 for 1,024. The
AES figures are the arithmetic behind the compared alternatives; actual AES
does not inherit a global multi-key injectivity theorem from ordinary PRP
security, which is one reason the hybrid was not chosen **[R]**
(section 10.1). The two 512-bit authorization values are not injective on
the secret space, and the reductions do not ask that of them: they use
authorization prediction, through P. Neither the key-search calculation of
section 8.3 nor the calculations here prove the concrete scheme secure.

### 8.5 The consolidated ledger, and why no parameter tuple can be certified

- Every gate's bound rests on premises without justified values: the four
  generator advantages in `e`, the credential terms `α_P`, `u_C` and `u_N`,
  the frame terms `F`, each to be evaluated at the complete resource
  vector, and the concrete justification of the backend oracle model
  (section 7.1). No deployment-wide total exists.
- The one published QROM bound is for plain FAEST with one honest key. It
  does not transfer to this construction, to both proof types or to its
  retry behaviour **[R]** (section 8.2). Substituting the transcript ceiling
  into it is comparison arithmetic only; the term-by-term table is in the
  arguments file, "Comparison with the published formula".
- The contract and lifetime envelope are fixed (section 8.8). The ledger
  below is the review's consolidated ledger against them **[R]**. All its
  entries are upper bounds, not measured attack advantages, and it awaits
  independent review.

**The joint zero-knowledge term [R].** With the notation of section 7.1,

```text
Z ≤ ε_1 + T·e + K + σ

e = ε_root + 396·ε_tree + 33·(ε_leaf + ε_expand)
K = ε_2 + ε_3 + ε_initial + δ_MH + δ_sep + 2·ε_delete
```

`K` excludes challenge 1. `e` uses the nine-block leaf experiment. At
`q = 2^64` and `T = 2^44`, recomputed here **[D]** from the formulas of
section 7.1:

| Component | Bound at the ceilings |
| --- | ---: |
| Challenge 1, `ε_1` | `3.3306706621 × 10^-16 = 2^-51.41503681` |
| Challenge 2, `ε_2` | `2^-979.41503681` |
| Challenge 3, `ε_3` | `2^-319.41503681` |
| Initial `H5` programming, `ε_initial` | `7.6702489205 × 10^-33` |
| Multi-hiding exceptions, `δ_MH` | about `2^-212` |
| Assignment collisions, `δ_sep` | `2^-157.54056838` |
| Hidden-label deletion, twice: `2·ε_delete` | about `2^-61.99903172` |
| `K` | `2.16986018285 × 10^-19` |
| Total-simulator correction, `σ` | `2^-367.08027043` |
| Generator term, `T·e` | Unknown |
| For comparison, global leaf ambiguity `δ_leaf,all` (in `s`, not in `Z`) | `2^-250.95560588` |

- **The recorded switching subtotal (applicability unresolved).** Counting
  generator terms directly against uniform strings requires appropriate
  permutation-switching distances. The review's expression uses block counts
  5, 4, 9 and 419:

  ```text
  D_sw = T·[10 + 396·6 + 33·(36 + binom(419, 2))] / 2^128 = 1.49586152902 × 10^-19
  ```

  **[R]**, recomputed here **[D]**: the bracket is 2,893,417. The
  [B6 source-hypothesis check](parliament_ballot_b6_security_review.md) found
  that the published leaf game has `N_0` queries, whereas this subtotal
  charges one nine-block call. Accepting that smaller charge requires a
  precise correlated-game interface and a justified single-query reduction.
  The alternative classical `binom(9·N_0, 2)` charge gives a separate
  diagnostic subtotal of `4.67579748963 × 10^-18`; it does not establish the
  quantum correlated experiment. The recorded arithmetic subtotal, with
  (unqualified) switching and before any computational generator
  advantage, is `ε_1 + K + D_sw + σ ≈ 3.3343363838 × 10^-16`. `D_sw` is a
  statistical distance and is not relabelled as a computational assumption.
  The alternative, still conditional PRP-native accounting carries the
  multiplicative factor `exp(1.2650301513 × 10^-17)` instead **[R]**,
  recomputed by the B6 ledger **[D]**. The two formulations are not mixed;
  reproducing arithmetic does not verify either reduction's hypotheses.
  The [B6 generator-interface analysis](parliament_ballot_b6_generator_interface.md)
  records the implemented call matrix and reference multiquery games, with
  the missing embedding and IV/tweak alias handling explicit. It supplies
  no primitive bound and does not select the smaller switching charge.
- The interactive lifetime subtotal of section 8.2 is not an entry of this
  ledger.

**The six game inequalities [R].** Deployment-wide; `ρ < 2^-317` and
`g_batch ≤ 1,001,000·2^-512`:

| Game | Bound |
| --- | --- |
| Gate 1 | `ε_snd ≤ s` |
| Gate 2 | `ε_2^app ≤ s + u_N + F_V + Z + α_P + ρ + g_V` |
| Gate 3 | `ε_3^app ≤ s_batch + u_C,seal + F_V,batch + Z + α_P + ρ + g_batch` |
| Gate 8 | `ε_8^app ≤ s + u_C,target + F_R + Z + α_P + ρ + g_R` |
| Joint zero knowledge | `ε_JZK ≤ Z` |
| Anonymity and unlinkability | `ε_priv ≤ 2·Z + 2·α_P + 2·ρ` |

Combined non-frameability is bounded by the sum of the gate 2 and gate 8
rows. P and U keep their definitions, with their environments taken for the
prover and simulator of the frozen construction.

**Resources, and the nominal normalisation [R].** A backend-query ceiling
alone cannot determine a primitive or gate budget: direct AES computation
and validation-only requests need their own accounting. The review's
inventory per unit of work:

- one full candidate-row commitment: at most 2,764,797 AES blocks;
- one heavy public verification: at most 2,750,672 AES blocks, with at least
  740 charged backend calls;
- a reserve of `2^16` non-counter Keccak permutations per honest invocation
  or heavy verification;
- retry permutations: at most `4·M·T = 2^66`.

For a fully explicit nominal normalisation it takes `q_pub ≤ 2^64`, direct
primitive evaluations `≤ 2^64` and public requests `≤ 2^64`. The
[checked candidate request allowance](parliament_ballot_b6_request_accounting.md)
is `w_request <= 2^12 + ((2,750,672 + 2^16)/740) q_request`, counting
`H_mu` among induced backend calls. Its `2^12` term is an intercept, not a
standalone preparation ceiling. The recorded pooled subtotal of logical AES
input blocks and Keccak permutations is

```text
W_known = 2^64 + ((2,750,672 + 2^16) / 740)·2^64 + 2^12·2^64
          + 2·2,764,797·T + 4·M·T + 2^16·T
        = 27000944741207686661537792 / 185 < 2^77
```

with `log2 W_known = 76.9498307985590493` **[D]**. The review uses
**`Q* = 2^77`** as a nominal substitution. The remaining headroom is
`955464837380613003542528 / 185 ≈ 2^72.1291675`. The final-comparison
allowance and every omitted primitive cost need a justified bound below that
headroom before asserting the complete `W < 2^77`; they are not zero.
The [B6 inventory](parliament_ballot_b6_security_review.md) keeps non-oracle
relation/transcript/context work, sampler costs, memory/coherent access,
preprocessing/advice and elementary-gate conversion unquantified. Including
the additional exhaustion sampler, `Sim+` can perform at most `2^65`
256-bit draws/admissibility checks, using `2^73` random bits for those draws;
the extra trials do not program extra challenge-oracle entries.

- **What `Q*` is.** A declared nominal resource condition for checking
  arithmetic: a defensible explicit substitution. Dropping to `2^68`
  would omit adversarially induced verification work.
- **What it is not.** It is not an additional deployment rule, not a
  measured resource count and not an unconditional all-cost certificate
  derived from `q_pub`. A completed inventory and a primitive assessment
  must establish the bounds at the actual `ℛ`; oracle calls, AES
  evaluations, Keccak permutations and elementary gates are not
  interchangeable.

**The nominal table is a hypothetical substitution [R].** It replaces every
unknown by a generic shape evaluated at `Q*`. None of these shapes is a
justified value for the concrete primitives:

```text
each of the four generator terms:   Q*^2·2^-256 = 2^-102, plus the switching distances D_sw
α_P = 4·Q*·sqrt(2^34 / (2^384 − 2^34)) ≈ 2^-96           // the ideal-table shape of section 8.4
u_C, u_N < 2^-233                                        // assumed, not derived adaptive SHAKE bounds
F ≤ 64·Q*^3·2^-512 = 2^-275                              // hypothetical, not a theorem-derived constant

T·e_comp = 463·2^44·2^-102 = 1.6063539388 × 10^-15
Z ≈ 1.9397875771 × 10^-15
```

The [B6 review](parliament_ballot_b6_security_review.md) preserves the cited
collision theorem's query units and output costs: one ordinary XOR query
costs two swap queries, and the two maximum standalone output frames require
their padded blocks. That produces a separate ideal-permutation diagnostic
approximately `2^-273` at `Q* = 2^77`, not the nominal `2^-275` above.
Neither is a concrete SHA3-512 bound or a justification of `P` or `U`.

| Game | Hypothetical nominal bound | Below 1/2? | Below 2^-64? |
| --- | ---: | :---: | :---: |
| Gate 1 | `8.23982 × 10^-37` | Yes | Yes |
| Gate 2 | about `1.93979 × 10^-15` | Yes | No |
| Gate 3 | about `1.93979 × 10^-15` | Yes | No |
| Gate 8 | about `1.93979 × 10^-15` | Yes | No |
| Joint zero knowledge | about `1.93979 × 10^-15` | Yes | No |
| Anonymity and unlinkability | about `3.87958 × 10^-15` | Yes | No |
| Combined non-frameability | about `3.87958 × 10^-15` | Yes | No |

**[D]** Recomputed here from the stated shapes: `463 = 1 + 396 + 33 + 33`;
`Z` is the sum of `ε_1`, `T·e_comp`, `K`, `D_sw` and `σ`; the gate 1 entry
is `s` at the query ledger of section 7.1 and contains no hypothetical
primitive value, only the random-oracle model. **This table certifies
nothing.** It shows that the arithmetic of the ledger is below 1/2 under one
explicit set of hypothetical values, and it shows where the written bounds
sit relative to 2^-64.

**What remains unknown [R].** `e`, `α_P`, `u_C`, `u_N` and `F`, evaluated at
the complete resource vectors, and the concrete justification of the backend
oracle model. The B6 checker retains four separate generator entries, all
three restrictions of `U`, the concrete frame entries, complete resource
vectors and reviewed protocol embeddings as missing; its qualification mode
fails closed. Nominal values cannot fill them. With `C = ε_1 + K + σ`, so
that `Z ≤ C + T·e`, each written
upper bound reaches 1/2 exactly when its unknown and guessing terms sum to
the residual: `T·e + α_P + u + F + g + ρ = 1/2 − s − C` for gates 2 and 8
with their own `u`, `F` and `g`, the same with `s_batch` for gate 3,
`T·e = 1/2 − C` for joint zero knowledge, `T·e + α_P + ρ = 1/4 − C` for
anonymity and unlinkability, and `s = 1/2` for gate 1. With every other
unknown at zero, the aggregate `e` may be at most about
2^-45 where `Z` is charged once and 2^-46 for privacy; an individual
generator term has that ceiling divided by its weight, 396 or 33. A singly
charged `α_P`, uniqueness term or frame term has a residual of about 1/2,
and privacy's `α_P` about 1/4. These are individual ceilings, not
simultaneous allocations.

**The written bounds cannot certify 2^-64 [R].** Every bound that contains
`Z` stays above 2^-64 at the ceilings even with every unknown computational
term set to zero: the challenge-1 programming term alone, about
`2^-51.4`, exceeds it. More strongly, holding `T = 2^44` fixed, **[D]**
`ε_1(0) = (3/2)·2^44·sqrt(2^44/2^256) = 3·2^-63 = 6·2^-64` even at zero
external queries. Since it increases with `q`, there is no nonnegative query
cutoff at this target for the written `Z` bound. This is a limitation of the
upper bound, not an attack or evidence that the true advantage exceeds
2^-64. The B6 report gives exact crossings of the conditional soundness
polynomial only; complete-construction `1/2` thresholds remain unknown until
the primitive terms are bounded at the complete resources.

Routine retuning within the published `lambda ≤ 256` rows does not repair
the quadratic term of the published comparison bound: grinding gets no
divisor in it and `T_open` does not remove it. A wider-field, wider-seed,
SHAKE-PRG backend is new protocol and proof work, not a change of `lambda`
to 384, and the review does not recommend building one to compensate
**[R]**. Gate 6 stays closed
until primitive qualification, the resource ledger at the actual `ℛ`, the
attack assessment and independent review exist.

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
| Nullifier `nf` | SHAKE256, 1,024 output bits |
| Vote authorization value `auth_v` | SHAKE256, 512 output bits |
| `D_reg`, `D_v`, sealed-list digest `R`, body-context digest `B` | SHA3-512 |
| Keccak witness | States committed after rounds 2, 4, ..., 22; rounds 23 and 24 evaluated forward with the exposed output bits constrained |
| Leaf commitments | 112 bytes: the FAEST v3 leaf hash and a 16-byte affine checksum (section 6.6.1) |
| CRT tables | The official FAEST v3 tables, unchanged (section 6.6) |
| Salt | 256 fresh uniform public bits per proof, from the proving tape; in challenge 1, in every `H5` input and in the proof |
| Counter | `0` through `0x000fffff`, little-endian in four bytes; larger counters rejected before reconstruction |
| Not used | Inverse-chi grouping; degree-14 masking; widened evaluation points; hash commitments to leaf seeds; root tags or other extraction commitments; `H3` randomness derivation; the salt, `iv_pre` or `mu` in `H0` or the leaf PRG |
| Proof-system internals | The role-specific lengths of section 8.3 |

The reference tuple is not a transferable theorem: the custom relation's
degree, masks and checks are those of section 6.3, and their error terms are
re-derived (section 8.2). The small row is measured for comparison and is not
an integration candidate **[R]**.

### 8.7 Anonymity is computational

**[D]** `C`, `auth`, `nf` and `auth_v` are deterministic functions of `sk`
and public values (section 6.2). `C` and `auth` are public at registration,
and `nf` and `auth_v` are public in the ballot.
An unbounded adversary can search for the `sk` that opens each registered `C`
and recompute its nullifier in every scope. No profile that instantiates
section 3.1 can therefore give statistical anonymity; this is a property of
the ballot design, not of the construction. Ballot design section 4 already
scopes ballot anonymity as resting on "the post-quantum primitives of `P`"
**[C]**.

For the construction those primitives are **[R]**:

- **The credential uses of concrete SHAKE256 under one secret.** The review
  takes a concrete-function assumption for them, not an abstract
  programmable oracle, because the relation contains the specified Keccak
  round polynomials. Honest values drawn from an abstract oracle would
  generally cease to have their claimed witnesses; and an abstract oracle
  kept accessible beside the concrete evaluation is distinguished from it at
  any known chosen secret. The overall privacy theorem is therefore a
  mixed-model conditional theorem: concrete credential SHAKE, backend
  oracles in the QROM.
- **Assumption P** (section 8.4). The privacy premise concerns the joint
  outputs under the shared secret: the challenge nullifier and the challenge
  vote authorization value are tested together, while commitments,
  registration authorization values and all other entries stay concrete
  (section 7.1). It is not an established consequence of ordinary preimage
  resistance, collision resistance or PRF security without the public
  commitment and authorization leakage, and it has no justified value.
- The backend's generator assumptions, with AES-based PRGs in the initial
  implementation, and zero knowledge of the proof system in the QROM
  (gate 5, conditional).

Ballots and registrations stay on chain permanently, so a later break of any
of these identifies past voters retrospectively **[E]**. The archive horizon
of section 8.8 covers that exposure. Changing profiles does not erase it
**[R]**.

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

**Neither the decision on gate 1 nor the extensions of the backend change
this contract [R].** Both weakenings stand: this contract weakens the
earlier one, and gate 1 is weakened from knowledge extraction to adaptive
relation soundness (section 2). The second changes the property that is
required, not the metric; its one effect on the reading of gate 6 is that an
extractor, no longer required, is no longer accounted for, while all actual
proving, simulation, verification and reduction overhead is. The numerical
contract is not weakened further.

| Quantity | Requirement |
| --- | --- |
| Computational break | Forgery success ≥ 1/2, or anonymity distinguishing gap ≥ 1/2 |
| Proven-bound requirement | Every required computational game has a complete, applicable deployment-wide bound below 1/2 at an adversary budget of 2^64 quantum queries |
| Scope of the proven bound | Both relations, all lifetime ceilings, concrete primitive terms, and all actual proving, simulation, verification and reduction overhead in queries and time |
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
  query theorem of that size **[R]**. The one published QROM bound the
  review names as non-vacuous at 2^128 queries under a 2^44-transcript
  lifetime is conditional and single-key: Kiltz, Lyubashevsky and Schaffner,
  Theorem 3.1 with section 4.4, for that paper's "Dilithium-QROM", with a
  Fiat–Shamir term `q_H^2·2^-261`; it is not a theorem for ML-DSA or for a
  multi-user contract (cited by the second-opinion review; not read by
  us).
- **The statistical budget, as the ledger stands [R].** Inside it: the
  structural term of the soundness theorem,
  `δ_leaf,all ≤ 33·(1 − 2^-256)·2^-256 < 2^-250.96` on the candidate row
  (coefficient 22 on the comparator, 55 for both rows together), and the
  other explicit unconditional events of the written arguments: salt
  collisions `δ_salt < 2^-169`, assignment collisions `δ_sep < 2^-157.5`,
  the multi-hiding exceptions at about `2^-212`, the simulator correction
  `σ < 2^-367`, repeated honest secrets `ρ < 2^-317` and the programmed-game
  exhaustion probability `2^-161.54`. **[D]** Their sum is below 2^-157.
- **Outside any statistical claim [R].** The query-dependent losses are not
  unconditional statistical bad-event probabilities: the soundness bound
  `340·Q^3·2^-512 + 70·Q^2·2^-256`, the programming terms `ε_1`, `ε_2`,
  `ε_3` and `ε_initial`, and the deletion term `ε_delete`. Closing the
  structural gap does not claim that the query-dependent soundness bound is
  below 2^-128, and the privacy losses must not be advertised as a 2^-128
  statistical zero-knowledge guarantee. The switching subtotal
  `D_sw ≈ 1.496 × 10^-19 ≈ 2^-62.54` (section 8.5) is an
  information-theoretic hybrid distance: if the budget is read to include
  every such distance, `D_sw` already fails it. It stays visible in the
  ledger; the PRP-native formulation needs its own stated justification and
  does not relabel a statistical distance as computational.
- **Current compliance is unestablished for both requirements.** No complete
  proven bound and no complete attack-cost assessment exists for the fast row
  or any other row (section 8.5). Neither the review's recommendation nor
  the hypothetical nominal table of section 8.5 establishes that the row
  meets the contract **[R]**. **No parameter tuple is
  certified.** The fast row is the sole integration candidate, not a certified
  row.

## 9. Resource projections and first measurements

Sections 9.1 to 9.8 are analytical. Sections 9.2 to 9.6 are the projections
made while comparing candidates, and section 9.7 gives the counts for the
frozen construction. Section 9.9 records source-bound local measurements of
that construction; they are not qualification-baseline results.

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
  and outputs of at most 128 bytes, so one permutation per evaluation: two
  evaluations in the registration relation and three in the vote relation
  **[D]**.
- The selected 768-bit commitment is committed as witness and bound by a
  degree-2 multiplexer over the public list.

### 9.3 Variants

| Variant | Relation |
| --- | --- |
| V1 | AES-only published shape transplanted onto a v3 backend: commitment of 2 / 4 / 4 blocks, CBC-chain tag of 2 / 3 / 4 encryptions with a 128-bit output, per-member gated last-round constraints |
| V2 | The hybrid: six-block AES-256 commitment with a public SHAKE256 mask, and a SHAKE256 nullifier in the relation (compared alternative, section 4) |
| V3 | Two-SHAKE public list in the shape projected for the candidate comparison: 256-bit `sk` and a 96-byte commitment. The construction of section 6 differs (384-bit `sk`, 128-byte commitment, 128-byte nullifier, a 256-bit pad, a second permutation in the registration relation for `auth` and a third permutation in the vote relation for `auth_v`); its counts are in section 9.7 |
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
| Construction `pi_reg` (section 9.7), 256f | 15.7 | 25 ms | 87 ms | 1.1 s |
| Construction `pi_vote` (section 9.7), 256f | 23.4 | 38 ms | 130 ms | 1.7 s |
| Construction `pi_reg` (section 9.7), 256s | 15.4 | about 190 ms | about 0.7 s | about 2.8 s |
| Construction `pi_vote` (section 9.7), 256s | 23.0 | about 280 ms | about 1.1 s | about 4.2 s |

The four construction rows use the same scaling, with a VOLE length of the
witness length plus 80 bits (256f) or 120 bits (256s) **[D]**:
(35,840 + 80) / (2,208 + 80) = 15.7 and (53,504 + 80) / (2,208 + 80) = 23.4
on 256f; (35,840 + 120) / (2,208 + 120) = 15.4 and
(53,504 + 120) / (2,208 + 120) = 23.0 on 256s. Their 256s figures are
back-derived from this table's rounded V2 (c) entry. The scaling ignores the
backend extensions (nine-block leaf expansion, two absorption permutations
per `H5`). None of these machines is a baseline of section 11.4.

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
They assume the layout of section 6.3: a 256-bit pad, the 384-bit secret, 11
committed states of 1,600 bits (17,600 bits) for each permutation of a
relation, two permutations in registration and three in the vote, and 64
selector bits in the vote; and the proof layout of section 6.6.2.

| Proof | Witness bits `l` | Constraints `N_c` | Fast row, proof bytes | Small row, proof bytes |
| --- | ---: | ---: | ---: | ---: |
| `pi_reg` | 256 + 384 + 35,200 = 35,840 | 72,576 | 160,148 | 109,498 |
| `pi_vote` | 256 + 384 + 52,800 + 64 = 53,504 | 108,931 | 233,012 | 158,074 |

**[D]** Working form: the `F_row` of section 9.1 plus `16·tau` bytes for the
wider leaf commitments of the opening and 32 bytes of salt, plus `tau·l/8`.
That is `12,308 + 33·l/8` on the fast row (`11,748 + 528 + 32`) and
`10,938 + 22·l/8` on the small row (`10,554 + 352 + 32`). For example
`pi_vote` on the fast row is 12,308 + 33 × 53,504 / 8 = 233,012 and `pi_reg`
is 12,308 + 33 × 35,840 / 8 = 160,148; on the small row `pi_vote` is
10,938 + 22 × 53,504 / 8 = 158,074. The constraint count has no size term.
The pad costs 33 × 256 / 8 = 1,056 bytes on the fast row and 704 on the small
row. The opening is 11,024 bytes on the fast row and 9,664 on the small row.
The field-by-field layout is the table of section 6.6.2.

**Per ballot [R][D].** Each committed permutation is 17,600 witness bits:
72,600 proof bytes on the fast row and 48,400 on the small row; the vote
relation has three. The public nullifier and vote authorization value are
`128 + 64 = 192` bytes; `D_v` is derived and not carried. The list remains
shared seal data, `128·S` raw bytes once per body **[R]**.

**Envelope [D].** These are raw proof sizes. The fast-row vote proof leaves
262,144 − 233,012 = 29,132 bytes under the envelope cap. Carrying all the
fixed cryptographic fields `B`, `scope`, `R`, `S`, `nf`, `auth_v`, `vote`,
`policy_hash` and `P16` adds 467 bytes (`64 + 64 + 64 + 2 + 128 + 64 + 1 +
64 + 16`), which leaves 28,665 bytes for the other envelope fields, the
stamp and the framing. The construction is size-compatible with the existing
cap. **Complete-envelope compliance is unqualified, because the production
schema is not frozen**, and no exact framed size is reported before that
schema exists **[R]**. The public `auth` adds 64 bytes to a registration.
Every count is regenerated from the actual implementation of the frozen
construction when it exists.

Work counts on the fast row. Upper bounds from engineering formulas
**[R]**, recomputed here **[D]** where a formula is given:

| Component | Formula | `pi_reg` | `pi_vote` |
| --- | --- | ---: | ---: |
| AES blocks, one full commitment (proving or simulating) | `6,399·4 + 6,400·9 + 6,400·ceil((l + 80) / 128) + 1` | 1,881,597 | 2,764,797 |
| AES blocks, one verification | `4·6,399 + 6,367·(9 + ceil((l + 80) / 128))` | 1,872,026 | 2,750,672 |
| VOLEHash field products | `5·(l + 6) + 4` | 179,234 | 267,554 |
| ZKHash field products | `2·N_c + 2` | 145,154 | 217,864 |
| Relation permutations | One per SHAKE evaluation | 2 | 3 |
| Relation nonlinear products | `24 × 1,600` per permutation | 76,800 | 115,200 |
| Leaf-commitment products in verification | One in `F_(2^768)` and one in `F_(2^256)` per reconstructed leaf | At most 6,367 of each | At most 6,367 of each |
| Backend SHAKE calls in verification | 704 `H5`, 34 `H1`, `H0`, `H4`, `mu` and the three challenges | 744 | 744 |
| Fixed CRT gates (`H5` gates) | `n_mult` | 704 | 704 |
| `H5` absorption permutations in verification | Two per 162-byte input | 1,408 | 1,408 |
| Inner `H1` absorption permutations | 212 for a 256-leaf vector and 106 for a 128-leaf vector | 5,300 | 5,300 |
| Public `D_v` hashing at `S = 1,000` | SHA3-512 over a frame of `128·S + 536` bytes | None | 1,786 permutations |

- The two vote-column AES counts and the 744 are the review's **[R]**; the
  registration-column AES counts, the leaf-product row and the two
  absorption rows are computed here **[D]**. `ceil((l + 80) / 128)` is 281
  for registration and 419 for the vote. The leaf expansion is nine blocks.
  6,367 is the 6,400 leaves less the 33 hidden ones.
- **[D]** An inner `H1` input is `77 + 112·N_i + 1` bytes: 28,750 bytes for
  `N_i = 256` and 14,414 for `N_i = 128`, hence
  `floor(28,750 / 136) + 1 = 212` and `floor(14,414 / 136) + 1 = 106`
  absorption permutations, and `17 × 212 + 16 × 106 = 5,300` in all.
- A prover makes 1,408 `H5` evaluations **[R]**, hence 2,816 absorption
  permutations, and four permutations per attempted counter **[D]**.
- A vote also adds at most `S` selector products and `1,024·S` public-bit
  selections. The extra application permutation adds no `H5` gate **[R]**.
- The `D_v` frame is `128·S + 536` bytes and `F_VOTE` is `128·S + 506` bytes
  **[R]**, recomputed here from the frames of sections 6.2 and 6.3 **[D]**:
  a 17-byte tag, eleven fields and 471 fixed field bytes for `D_v`; a 15-byte
  tag, nine fields and 451 fixed field bytes for `F_VOTE`. At `S = 1,000`
  the `D_v` frame is 128,536 bytes: `floor(128,536 / 72) + 1 = 1,786`
  SHA3-512 permutations **[D]**.
- The list frame at `S = 1,000` is 128,114 bytes and takes 1,780 SHA3-512
  permutations **[R]**.
- These are analytical counts, not timing or allocation certificates. The
  250 ms, 64 MiB, phone-time and phone-memory limits are unchanged **[R]**.

Workspace. The review's work formulas, hash-input table and buffer
inventory for gate 7 **[R]** are in the arguments file, "Property 7:
deterministic bounded verification". No buffer inventory at the final layout
is recalculated here; an allocation certificate needs the implementation.

Thresholds **[R]**. The hard limits of section 2 apply unchanged at
`S = 3`, 500 and 1,000 and to both proofs.

- The ballot envelope size includes its proof, public fields, stamp and
  framing. Shared seal and list evidence is separate, capped at 160 KiB
  (163,840 B **[D]**) for the list-context object. The two caps together allow
  at most 262,144 + 163,840 = 425,984 bytes of combined bounded input
  **[R][D]**.
- Verification measurements include fresh list decoding and digest
  validation, transcript preparation and late-invalid proofs. They exclude
  network and disk retrieval. Memory includes list and transcript buffers.
- **Cold-input total at `S = 1,000`.** The fast `pi_vote` proof plus the raw
  list alone is 233,012 + 128,000 = 361,012 bytes, before other framing
  **[D]**. The 256 KiB envelope limit is not a claim that all cold
  verification inputs fit inside 256 KiB. On the small row the same sum is
  158,074 + 128,000 = 286,074 bytes **[D]**.

### 9.8 Against the section 5 limits

| Limit | Status |
| --- | --- |
| Proof envelope ≤ 256 KiB | The fast-row proof objects are 233,012 B (`pi_vote`, 88.9% of the limit) and 160,148 B plus the 64-byte `auth` (`pi_reg`, 61.1%), before public fields, stamp and framing **[D]**. The vote proof leaves 29,132 B, or 28,665 B after the 467 bytes of fixed cryptographic fields **[D]**. Size-compatible with the cap; complete-envelope compliance is unqualified because the envelope schema is not written |
| Verification ≤ 250 ms on the minimum validator baseline | Cannot be judged. The final standalone verifier is implemented and measured on a development machine (section 9.9), but no run on the named baseline of section 11.4 exists. The illustrations of section 9.5 are scaled estimates **[E]** |
| Verifier workspace ≤ 64 MiB | Not qualified. The later [standalone resource contract](parliament_ballot_resource_contract.md) implements bounded copy-in, a reclaiming arena, metadata and a supplied native stack; 120 source-bound calls pass within its 41.09375 MiB mapping on the Mac. Complete runtime/System/TLS coverage, all-valid-input sufficiency, target qualification and the production input schema remain open. Earlier requested-heap and sampled-process measures are separate historical evidence |
| Phone proving p95 ≤ 10 s | Cannot be judged without runs on the baseline phones |
| Phone prover memory ≤ 256 MiB | Supplementary iPhone 17 Pro Max and Samsung SM-S942B observations exist in the B6 record, with requested Rust heap and sampled process memory reported separately. The named baseline phones, battery/sustained-thermal conditions and complete memory qualification remain open |

The [B6 interface note](parliament_ballot_b6_generator_interface.md) records
the earlier envelope-ordering ambiguity. Ballot design section 12.2 now
authorizes schema engineering alongside qualification. Actual canonical
envelope sizes and complete accounting remain required; the standalone size
inventory supplies neither selection approval nor production qualification.

### 9.9 Measurements of the frozen standalone construction

**[C]** The [standalone validation record](../docs/validation/parliament_ballot_standalone.md)
retains the source manifest, reproduction commands and raw measurements of
the final registration and three-permutation vote relations with the salted,
affine-checked backend. Both rows were measured at 3, 500 and 1,000 seats in
release builds, with seven samples per case and one thread, using portable
and accelerated AES on an Apple M2 Ultra development machine.

Candidate-row accelerated median prove/verify times were 226.7/110.4 ms for
registration and 330.1/158.5, 345.7/164.1 and 357.8/168.7 ms for votes at the
three roster sizes. Portable medians were 482.1/337.1 ms for registration
and 585.6/408.3, 592.5/409.8 and 606.8/415.1 ms for those votes. These are
local observations, not estimates or results on a named qualification baseline.

The B5 incremental requested-heap peaks were 2.95/2.21 MiB for
candidate registration and at most 4.22/3.41 MiB for candidate proving and
verification. They exclude existing statements, lists and proofs, stack,
allocator overhead and RSS. Verification starts with decoded statements;
cold decoding and late-invalid proofs were not measured in that campaign.
Seven samples are not a phone p95 qualification. The complete envelope, full allocation/work
bound and named Intel validator and phone results remain open. No security
assumption or section 5 limit is discharged by these measurements.

The later [B6 record](../docs/validation/parliament_ballot_b6.md) adds 31
candidate and three comparator samples per case per feature mode on Mac,
iPhone 17 Pro Max and Samsung SM-S942B, with fresh test-record decoding,
late-invalid verification, retry/digest parity and requested live heap.
The phone records separately report sampled process memory and device
conditions; the Samsung run is a native shell executable. These are
supplementary observations, not the Xeon, Pixel 6a or iPhone SE third-generation
baseline qualification. They do not replace deterministic resource bounds.

## 10. Decisions

### 10.1 Decisions taken

On 2026-10-11 the owner delegated the open decisions of this record to the
second-opinion review, under the instruction that this is the first release,
backward compatibility is not needed and the best design is chosen. The review
decided in the passes of 2026-10-11 and 2026-10-12 and in the eight further
texts (section 3); where they differ, the latest governs. Each row is a design decision
of that review **[R]**. None is a security proof, a profile selection or a
qualification.

| Item | Decision | Stated in |
| --- | --- | --- |
| Construction | SHAKE256 public-list construction with a flat commitment to the sealed ordered list, an authorization value in each relation and a fresh pad, as the single construction to develop. The hybrid is not chosen: avoiding its extra credential assumptions is worth the projected increase in proof size. The construction is frozen for investigation; no security-qualified normative profile is selected | Section 6 |
| Gate 1 weakened to soundness | Gate 1 is adaptive relation soundness: every accepted fresh registration or ballot statement belongs to its specified language. It requires neither efficient witness extraction nor knowledge of the secret by the submitter. **This is a genuine weakening of gate 1, not an equivalent reformulation of knowledge soundness.** Efficient extraction is a means of establishing authorization, not one of this ballot system's application goals; gates 2, 3 and 8 must carry the authorization guarantees independently, under explicit additional assumptions. Knowledge claims are removed from the design, this record, the arguments file and the implementation documentation. The launch gate remains false | Sections 2 and 7.6; ballot design section 5 |
| Strengthened vote relation | `R_vote+`: the commitment, a 128-byte nullifier and a 64-byte vote authorization value `auth_v = SHAKE256("PAV1" \|\| P16 \|\| sk \|\| D_v)`, all under the same 384-bit secret, with the exact frames, witness intervals and constraint order of section 6. Final dimensions: registration 35,840 witness bits and 72,576 constraints; vote 53,504 and 108,931. The unchanged-relation false-instance hybrid for gate 2 is not selected | Sections 6.2 and 6.3 |
| Nullifier length | 1,024 bits, not 512. The existential uniqueness argument must exclude alternative secrets, including ones nobody can efficiently find; the 512-bit ideal-map arithmetic does not support that at the lifetime ceilings and the 1,024-bit arithmetic does. The lengthening supplies no general claim of "1,024-bit SHAKE security" | Sections 8.3 and 8.4 |
| Salt | A separate fresh 256-bit public salt per proof: tape bytes `[80, 112)`, appended to the challenge-1 body and serialised after `iv_pre`. `iv_pre` stays 16 bytes and `H4` is unchanged. Challenge 1 is then programmed at a location of point probability `2^-256`, and the commitment-unpredictability term of the outer composition with its primitive reductions is deleted | Sections 6.3, 6.7 and 7.1 |
| Salted `H5` | `H5` body `iv \|\| salt \|\| LE32(e) \|\| label`, with the singleton-record deletion bound and its additive salt-collision term. The bound the review derived for an unsalted `H5` from IV multiplicity is not adopted | Sections 6.3 and 7.1 |
| Counter limit | Counters `0..=0x000fffff` in LE32 encoding on both rows; the verifier rejects a larger counter before expensive reconstruction; typed exhaustion, never a wrap. The exhaustion bound in the real game needs the stated transfer | Sections 6.7 and 7.1 |
| Leaf commitment | 128-byte `H0` output, 144-byte leaf expansion, and a 16-byte affine checksum appended to the existing 96-byte leaf hash: 112-byte commitments on both rows. Neither the salt, `iv_pre` nor `mu` enters `H0` or the leaf PRG. It brings the global leaf-ambiguity term to `33·(1 − 2^-256)·2^-256`. No root tag and no extraction commitment is added | Sections 6.6.1 and 7.1 |
| Adaptive soundness argument | The theorem that conditions on global induced-seed uniqueness and fixes `H0`, `H4` and `H5`, recorded as a written argument awaiting review, with its explicit leaf-ambiguity term, both real honest interfaces charged and the selection factor 1,001 for batches. The direct local argument for late `H4` and `H0` completions stays open | Section 7.1 |
| Extractor-free reductions | The event split for gate 2, the event split for gate 8 and, for gate 3, the direct batch reduction: joint zero knowledge and P are charged once, no selection factor is applied to them, and no nullifier-uniqueness premise is needed. The honest-issued set includes nullifiers disclosed on failed or exhausted proving requests | Sections 7.3 and 7.5 |
| Credential assumptions P and U | Two independent assumptions with separate bounds. P, selective-entry pseudorandomness with public leakage, gives both authorization-prediction premises and the privacy premise. U, selected-context existential uniqueness, covers sealed contexts, unsealed registration targets and designated scopes, and is not replaced by collision-finding resistance. P does not imply U. The ideal-table lemma and the ideal-map diagnostics are kept distinct from the concrete assumptions | Section 8.4 |
| Logging rule | Authorization is logged before it is disclosed. Per-handle logs of complete statements and of authorization digests, for both roles, failed proving requests included | Sections 7.3 and 7.5 |
| Privacy claims | Arbitrary-witness joint zero knowledge is preserved. The vote functionality has two entries: nullifiers indexed by credential and scope, authorizations by credential and `D_v`, with `D_v` computed from the returned nullifier and the complete statement. Privacy admissibility tracks both equality partitions, blocks both candidates' exact authorization entries, keeps quotas symmetric and prohibits corruption of protected handles. Equal nullifiers link conflicting ballots by design, and anonymity excludes previously identified candidate and scope pairs | Sections 7.1 and 8.7 |
| Deployment limits | Every existing deployment limit is kept. The new proof is size-compatible with the envelope cap; the exact framed size, the verification cost and the memory still require qualification | Sections 9.7 and 9.8 |
| Confirmations | Pad packing is least-significant-bit first, as implemented. A supplied `B` that differs from the recomputed digest is rejected before proof work, and `D_reg` and `R` are recomputed. `d_zk = 7`, all ten masks, all six transmitted coefficients and the existing bytes are kept; the three zero unmasked coefficients do not justify reducing the degree-seven soundness bound | Sections 6.1, 6.3 and 6.7 |
| Ledger and nominal normalisation | The six-game ledger with `Z ≤ ε_1 + T·e + K + σ`, and the explicit nominal resource normalisation `Q* = 2^77`, with all actual primitive and gate costs kept in the resource vector. Recorded outcome: the structural soundness gap is closed; every listed game is below 1/2 under the stated hypothetical nominal values; the written bounds that contain `Z` stay above 2^-64. No claim is made of primitive advantages equal to zero, of a direct transfer of FAEST's signature theorem or of a completed gate. Primitive qualification and independent review remain required before binding production activation | Sections 7.1 and 8.5 |
| Contract recalibration | Two requirements replace the literal 2^128-query floor: a complete proven deployment-wide bound below 1/2 at 2^64 quantum queries, and an independently assessed attack cost of at least 2^128 elementary gates. The statistical budget, the lifetime ceilings and the 100-year archive horizon are unchanged. **This expressly weakens the earlier contract.** It is the review's recommended policy, not a theorem. Current compliance is unestablished and no parameter tuple is certified | Section 8.8; ballot design section 5 |
| Public-list verifier and evidence contract | Flat digest of the ordered list; the list bytes are published in finalized block data at seal; every verifier holds a validated list or an immutable context authenticated to the seal | Section 6.4; ballot design sections 3.1, 3.3, 3.5, 3.8, 3.9 and 12.2 |
| Gate 8 | Adaptive cross-relation registration unforgeability replaces simulation-extractability; no statement remains that gate 1 retains a separate knowledge obligation. Route: the opening-uniqueness split, per-handle authorization logs and an explicit registration-frame SHA3-512 collision term. It needs no extractor | Section 7.3; ballot design sections 3.2 and 5 |
| Pad | 256 fresh prover-random bits before the secret, at witness positions `[0, 256)`, constrained only by Booleanity. It removes the dependence of the CRT labels on the credential prefix. Cost: 1,056 proof bytes on the fast row and 256 constraints | Section 6.3 |
| Gate 5 target and game | Standard adaptive joint zero knowledge for arbitrary application witnesses and arbitrary auxiliary information about them, not the honest-key-only simulation game, in the shared-simulator experiment: application-witness disclosure permitted, secret-tape disclosure excluded, and a prover that accepts a fixed or disclosed pad outside the claim. The retry and future-oracle-state analysis accounts for every attempted counter. The separate anonymity game keeps hidden honest challenge credentials and its disclosure exclusions. The pad supports this target; it does not establish it | Sections 6.7 and 7.1; ballot design section 5 |
| Registration authorization value | `auth = SHAKE256("PAU1" \|\| P16 \|\| sk \|\| D_reg)`, 64 bytes, public in `m_reg`, bound through `mu` and constrained in the registration relation. Its values change with the descriptor digest `D`, which `D_reg` covers | Sections 6.2, 6.3 and 7.3; ballot design section 3.2 |
| Witness layout and constraint order | Frozen: the layout, the ordered constraint stream with Booleanity emitted once and selector constraints before the Keccak blocks, the retained zero prefix constraints, and homogenisation to nominal degree seven | Section 6.3 |
| CRT tables | Official CRT tables and gate order, 704 gates on the fast row. Direct hash commitments to leaf seeds and root tags are not adopted | Sections 6.6 and 7.6 |
| Row choice | Fast row `(256, 33, 8, 229, 7)` as the sole integration candidate; small row as a measurement comparator. No `lambda = 384` backend is built to compensate for the comparison bound | Sections 6.6, 8.5 and 8.6 |
| Randomness and retries | An independent fresh 112-byte proving tape per invocation; no `H3` derivation; the allowed counters in increasing order; `GrindingExhausted { last: 0x000fffff }` on exhaustion, never a wrap; verification checks the supplied counter once | Section 6.7 |
| Tape uses and erasure | The allocation root, `iv_pre`, pad, salt, in that order. `r` feeds the backend root expansion and the existing high-mask expansion; the raw pad is supplied only as witness bits `[0, 256)`; `iv_pre` is hashed in `H4` and challenge 1; the salt is hashed in challenge 1 and `H5`; nothing else of the tape is hashed separately. Owned tape buffers, `r`, the pad and transient secret material are erased on success, error and exhaustion | Section 6.7 |
| Descriptor and digests | `DESC` with the 129-byte `SUITE` ending in `/SALT-256/H5-SALT/LEAF-AFFINE-896`, the parameter tuple, the CRT table digest `T_crt` and the relation dimensions `(35840, 72576, 53504, 108931)`: 286 bytes on both rows. `D = SHA3-512(DESC)`; the CRT serialisation `CRT_BYTES`; fixed values of `T_crt` for both rows. `D_reg` and `D_v` take exactly the 64 bytes `D`. The verifier selects a compiled fixed descriptor; every retired ballot descriptor is rejected, with no compatibility handling. `D`, both namespaces and the descriptor-dependent authorization values are regenerated; the values of `D` are computed in this record **[D]**, not given by the review | Sections 6.1 and 6.2 |
| Opaque public inputs | The standalone construction takes bounded opaque byte strings, with fixed bounds and boundary rules, and neither imports node types nor parses their encodings. Canonical Norito validation is the caller's: Core supplies and validates the pinned representations | Section 6.1 |
| Hash prefixes | Every ballot backend hash call carries the 77-byte role prefix `PREFIX_R = ASCII("PARL/FAEST/v1") \|\| NS_R`; `mu_R` is defined with suffix `08`; no `H3` and no additional `H1` consistency digest. The suffixes and the PRG's IV and tweaks are unchanged. Reference mode, with the empty prefix, is a separate unchanged construction and is not an accepted ballot mode. Causal dependence on `mu` was judged insufficient for the disjoint-domain statement | Section 6.3 |
| Proof layout and test codec | A fixed naked proof layout per row and relation, without header, with the salt after `iv_pre`; `a_0` hashed and not serialised; canonical opening padding, nonzero padding rejected; fixed length, no row autodetection, no trailing bytes. A test-only statement codec that is not a production schema | Section 6.6 |
| Query offset | `Q = Q~ + 125` for compact-proof static comparisons; 85 only for the explicit-leaf intermediate of Lemma 10.49 | Section 8.1 |
| Construction freeze | Selection-rule condition 1 is complete for standalone work. Selection and activation stay blocked on the remaining proof, ledger, implementation and qualification requirements. Binding production use remains disabled; development testing is authorized | Section 11.1; ballot design section 12.2 |
| AES binding assumption | Not made a dependency. Multi-key injectivity of `k -> AES_k(p_0) \|\| ... \|\| AES_k(p_5)` does not follow from single-key PRP security. It leaves the normative candidate with the hybrid | Section 4 |
| Keyed-SHAKE assumption given the AES commitment | Not made a dependency; it leaves with the hybrid. The SHAKE256 public-list construction instead needs assumptions P and U, quantified, for the commitment, nullifier and authorization uses of SHAKE256 under one secret | Sections 4, 8.4 and 8.7 |
| Arithmetisation-oriented hash | Not admissible in this profile, in its commitments or its transcript. Algebraic universal hashes inside the proof protocol are a different category, subject to their proved error bounds | Ballot design section 5 |
| Hardware baselines | Intel Xeon Silver 4310 (one physical core, base frequency), Pixel 6a and iPhone SE third generation. The portable scalar path must be correct and bounded; it need not meet 250 ms | Section 11.4; ballot design section 5 |
| Proof work | The written-argument standard of section 11.1. Complete reductions may await independent review; missing reductions may not. The review states that it can write and check the arguments in a follow-up, with no assured outcome | Sections 7.1 and 11.1 |
| What selection requires | Profile selection is distinguished from activation qualification. Selection needs the complete dossier of section 11.1; independent review and the validator and phone launch measurements may remain enumerated obligations | Section 11.1; ballot design section 12.2 step 2 |
| Selection rule amendment | The review amended only condition 3 to the recalibrated contract. Its sequencing restrictions were subsequently superseded by the owner's engineering authorization; selection and activation evidence remain required | Sections 11.1 and 11.5; ballot design section 12.2 step 2 |
| Boundary of permitted work | Real-candidate schemas, Core verification, signerless envelopes, sealed-list/nullifier state, Torii/CLI/SDK paths, coordinated retirement and development testing are authorized alongside B6; no placeholder relations or protocol bypasses | Ballot design section 12.2 |
| Qualification | Accepting and recording activation qualification is the owner's alone. Implementers and reviewers may produce evidence and record a profile selection; they may not claim qualification or make `parliament_binding_ballot_available()` true | Section 10.2 |
| Standalone implementation | An in-tree, standalone experimental implementation, following FAEST specification v3.0. The owner authorised it, the download of the official test vectors and the patching of dependencies | Sections 11.2 and 11.3 |
| Placement and dependencies | VOLE-in-the-head is a distinct mathematical family with exactly one reusable owner crate, `crates/iroha_zkp_vole`. The pinned `aes` 0.8.4 dependency is minimally patched to expose portable types and to put hardware dispatch behind a positive feature | Section 11.2; [zk_delivery_plan.md](zk_delivery_plan.md), "Shared proof backend and complete IVM proof" |
| Draw seed | Attempt identity stays out of the ranking seed | Ballot design section 9 |
| Idle-chain latency and casting clock | Bounded native-slot progress, casting-clock due work and late processing as requirements on the SCCP-owned governance clock; `parliament_sccp_attempt_latency_ms()` is `None` until a qualified bound exists | Ballot design sections 9 and 11; wording owned by [sccp.md](sccp.md) |

Whether computational anonymity is acceptable is not a separate decision:
section 8.7 shows it follows from ballot design section 3.1 for every profile.

### 10.2 Still requiring the owner

The owner has authorised downloading the official test vectors and patching
dependencies. Four items remain:

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
3. **The weakening of gate 1, restated.** In the review's words **[R]**, the
   qualification record must expressly say that knowledge extraction has been
   removed, that authorization is instead established by the separate
   origin-security reductions, and that existential selected-context
   uniqueness is an additional assumption. The record restates both
   credential assumptions, U and the pseudorandomness assumption P, each
   with its own bound (section 8.4). It must preserve the existing
   security ceilings, statistical budget and engineering limits. None of the
   missing terms receives a numerical value merely from this design decision
   **[R]**. What the owner gives up is listed in section 2.
4. **The qualification record.** The eventual record of activation
   qualification, with the completed proofs, the assumptions, the concrete
   ledger, the independent review and the implementation evidence **[R]**.
   Until the owner supplies it, `parliament_binding_ballot_available()`
   remains false.

## 11. Evidence required and order of work

### 11.1 Selection rule

Ballot design section 12.2 step 2 distinguishes profile selection from
activation qualification **[C]**. Selection requires all of the following
**[R]**. The earlier restriction on engineering steps 3–5 is superseded by
the owner's authorization in that section; these evidence requirements remain.

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

Condition 3 is the review's amended text; only the contract condition changed
in that review **[R]**. The later engineering authorization is separate.

**Where the record stands.**

| Condition | State |
| --- | --- |
| 1 | **Holds for the frozen standalone construction**, by the review's decision **[R]**; it is a design decision, not a selection. It covers everything listed at the head of section 6, for the row `(256, 33, 8, 229, 7)`. The values of `D` printed in section 6.1 are computed in this record and independently recomputed **[D]**; that check covers transcription and arithmetic only. The freeze does not cover the production Norito mappings, the production envelopes or authenticated integration, which remain later obligations and are not written; the standalone verifier does not validate node-level canonicality |
| 2 | **Not met.** Gates 1 to 5, 7 and 8 have written conditional arguments, all awaiting independent review; gate 6 is not met (section 7.1). The standard below requires the numerical substitution into the contract, and the only substitution that exists is hypothetical: the generator, credential and frame terms have no justified values (section 8.5). This record does not claim that any written argument meets the standard |
| 3 | **Not met.** The consolidated ledger exists as a written ledger with unknown primitive terms; its nominal table is a hypothetical substitution and satisfies nothing. No attack-cost assessment exists. The recorded thresholds do not exist; what is known is that the written bounds containing `Z` cannot certify 2^-64. Compliance with either part of the contract is unestablished (sections 8.5 and 8.8) |
| 4 | Standalone implementation and meaningful component/adversarial checks exist **[C]**: both final relations use the extended backend; official reference-mode signatures and independent project-generated ballot vectors agree (sections 11.2–11.3). B6 adds bounded parser fuzzing and supplementary ARM-platform parity. Further local checks are tracked in the requirement audit; physical x86/ARM qualification and independent cryptographic/implementation review remain open |
| 5 | Not met. Raw proof sizes, three-roster measurements, cold-input/late-invalid observations and a conditional standalone requested-allocation model exist (sections 9.7–9.9 and the B6 record). The later standalone whole-call/byte reservation and arena/native-stack proposal is implemented; complete envelope accounting, calibrated work and full allocation certificates, qualified cold-process/cache methodology and baseline records remain absent |
| 6 | Enumerated. Sections 10.2, 11.4 and 12 and the [B6 requirement audit](parliament_ballot_b6_requirement_audit.md) identify local, owner/external and postselection obligations **[E]**; enumeration does not discharge them |
| 7 | Holds **[C]** |

**Conditions 2 and 3 are not met.** Selection and activation remain unqualified;
schemas, Core integration and real-candidate testing may proceed under ballot
design section 12.2. Full resource accounting and qualification remain unfinished,
and the binding production launch gate stays false.

**Continuing standalone work [R].** This work proceeds alongside authorized
schema and integration engineering:

- complete the backend, its conformance with the official plain-FAEST
  vectors, and the exact experimental ballot prover and verifier;
- implement the profile-local relation encodings and codecs needed to specify
  and test that standalone protocol;
- carry out adversarial tests, independent relation checks, deterministic
  parity checks, resource accounting and measurements at `S = 3`, 500 and
  1,000;
- write and review the missing cryptographic arguments.

The review originally deferred production schemas, a Core verifier bridge,
signerless envelopes, state transitions, Torii/SDK paths and retirement until
selection **[R]**. That sequencing is superseded by ballot design section
12.2. Coordinated retirement still belongs with the actual replacement in
step 4; engineering completion does not authorize binding production use.

**Dossier that selection requires [R].** Selection for integration, with the
launch gate false, needs:

- **the exact protocol:** one row, descriptor, byte encodings, namespaces,
  relations, ordered constraints, randomness and retries, with no unresolved
  choice;
- **complete arguments for all eight gates:** in particular adaptive relation
  soundness for gate 1 (the decision removes efficient extraction from the
  requirement), adaptive mixed-list authorization for gate 2, joint
  simulation and anonymity for gate 5 and registration origin for gate 8,
  each with its game, assumptions, simulator, transitions, theorem
  hypotheses and quantitative losses;
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
experiment keeps them in a separate leaf crate. Integration is authorized by
ballot design section 12.2 step 4; governance state transitions stay in Core.

State of the modules **[C]**:

| Crate | Modules | State |
| --- | --- | --- |
| Backend | `params`, `field`, `prg`, `hash` (`H0` to `H5`), `universal_hash` (VOLEHash, ZKHash, LeafHash), `bavc`, `crt`, `vole`, `quicksilver`, `transcript`, `codec`, `randomness`, `proof` (generic prove and verify for any relation on a supported row), `faest` (the plain-FAEST instantiation used for conformance) | Reference and extended modes are implemented. The extended mode uses salt in challenge 1 and `H5`, a `2^20` counter limit, 128-byte `H0`, 144-byte leaf expansion and 112-byte leaf commitments. Official vectors cover reference mode; independent project-generated vectors cover the extensions (section 11.3). |
| Ballot | `profile`, `framing`, `credential`, `sealed_list`, `selector`, `keccak_relation`, `layout`, `registration`, `vote`, `proving`, `test_codec` | Registration and `R_vote+` use the final 129-byte suite, 286-byte descriptor, 128-byte nullifier, `D_v`, `auth_v`, third permutation and 112-byte tape. Tests cover exact layout, malformed statements and proof rejection, and independent fixed-tape vectors. No retired-descriptor acceptance path exists. |

- **CRT tables.** The official tables are embedded as generated sources under
  `crates/iroha_zkp_vole/src/crt/generated/`, with the generator in the
  crate. `tests/conformance_crt.rs` is written to check every entry of the
  official `crt_vole_commit_tvs` vectors and to regenerate each embedded
  table set and compare it with the embedded statics word for word, with the
  generated source on disk and with pinned SHAKE256 digests of the prototype
  tables (its module documentation) **[C]**. B6 also records a
  [direct comparison](../crates/iroha_zkp_vole/tests/fixtures/faest_v3_0_2/upstream_crt_comparison.txt)
  of every word in all eight table profiles with unmodified pinned upstream
  C++ **[C]**. The official tables are the pinned ones (section 6.6).
- **Two modes, one backend.** Reference mode stays exactly as it is, so that
  the official vectors keep testing it. Ballot mode runs beside it; a
  ballot verifier uses ballot mode only, fixed by its compiled descriptor
  (section 6.1). No official vector covers ballot mode.
- **Independent reference.** The pure-Python relation and backend are
  retained in `crates/iroha_parliament_ballot_proof/tests/reference/`.
  They implement the same final construction independently of Rust.
  `tests/fixtures/README.md` records the deterministic cases and provenance.
  Cross-implementation agreement tests fidelity to the construction; it
  does not discharge its cryptographic assumptions.
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
**[C]**. The stage tests and the scoped validation commands are recorded in
the [validation record](../docs/validation/parliament_ballot_standalone.md):

| Official vectors | Test in `crates/iroha_zkp_vole/tests/` |
| --- | --- |
| `prg_tvs`, `universal_hashing_tvs`, `field_tvs` | `conformance_prg.rs`, `conformance_universal_hash.rs`, `conformance_field.rs` |
| `bavc_tvs`, `vole_tvs`, `owf_tvs` | `conformance_bavc.rs`, `conformance_vole.rs`, `conformance_owf.rs` |
| `crt_vole_commit_tvs` | `conformance_crt.rs`. The fixture README notes that upstream ships no generator for this header, so the meaning of its entries is inferred from their names |
| `faest_tvs` (full signatures, all twelve parameter sets) | `conformance_faest.rs`: the public key, the extended witness, the exact signature bytes and acceptance of the official signature, with rejection tests; `conformance_signature_fields.rs` for the relation-independent fields |
| None (ballot namespaces and extensions) | `namespace_layout.rs`: exact namespaced hash bodies; `extended_variant.rs`: independent Python leaf/transcript vectors, salt and counter-bound tests; `proof_generic.rs`: the generic engine on a toy relation. Project-generated evidence, not official FAEST vectors |

The scoped validation reproduced every official component vector and all
twelve official signatures byte for byte in both portable and accelerated
builds **[C]**. That evidence concerns reference mode.
The separate [bidirectional cross-verification record](../crates/iroha_zkp_vole/tests/fixtures/faest_v3_0_2/cross_verification.md)
covers all twelve sets against pinned upstream C **[C]**. The original run
completed its functional cases but rejected publication after concurrent lock
drift; retained negative logs and lost raw C return values are distinguished.
A separate recovery regenerated the C proofs, retained the Rust proofs and
passed 84 positive verification calls against the frozen executables. This is
reference-mode interoperability evidence, not a current-tree qualification or
validation of the ballot extensions.

**Nothing official covers the extensions.** The salt, the salted `H5`, the
counter range, the 128-byte `H0` output, the 144-byte leaf expansion and the
112-byte leaf commitment have no upstream vector and no upstream
implementation. Their independent check is
cross-implementation: vectors produced by the archived Python reference and
the Rust backend from the definitions of section 6, under fixed tapes,
compared byte for byte, together with unit vectors for the leaf commitment
(`h0`, `h1`, the expansion, `c0`, `c1`), for each hash body and for the
descriptor digest `D`. Agreement of two implementations written from one
text is weaker evidence than an official vector, and is recorded as
self-generated (above).

The ballot crate's tests **[C]** are `relation.rs` (honest witnesses and
single-bit and semantic faults against the constraint blocks),
`evaluators.rs` (the relations on independent evaluators), `proofs.rs`
(prove, verify, determinism in the tape and rejection) and `vectors.rs`
(the independent reference's cross-implementation vectors). The tests now
exercise the frozen construction: both descriptor digests, all four proof
sizes, full proof bytes and transcript intermediates, with 3-, 500- and
1,000-seat votes on both rows **[C]**. Old descriptor, short nullifier and
unsalted encodings have no acceptance path. Rejection tests include altered
authorization and nullifier halves, message-binding faults, malformed list
lengths and counters rejected before reconstruction. Implementation agreement
establishes no quantum simulation or security theorem.

**Component evidence and remaining implementation obligations:**

1. **Final-construction component conformance is recorded [C].** Reference
   mode passes the official vectors. The independent Python reference and
   fixed-tape ballot fixtures are archived beside the Rust tests, including
   leaf commitments, transcript intermediates and the two values of `D`.
   Independent cryptographic and implementation audit remains open.
2. **Complete adversarial verification evidence.** Malformed statements and
   lengths, truncation and trailing bytes, non-canonical padding and
   openings, wrong role, descriptor, context or list, a retired descriptor,
   an altered authorization value, nullifier, salt or leaf checksum, a
   counter above `0x000fffff` (rejected before reconstruction), and
   late-failing proofs. Focused rejection tests, deterministic campaigns and
   bounded ASan parser fuzzing exist **[C]**, with retained source/corpus
   identities in [B6](../docs/validation/parliament_ballot_b6.md).
   These do not provide exhaustive coverage or a complete malformed-input
   resource certificate. [Constructive nonminimal-counter tests](../docs/validation/parliament_ballot_b6/nonminimal-counter-results.md)
   pass for both rows and roles in both feature modes (votes use `S=3`);
   they test acceptance of a later valid opening, not verifier work counts.
   [Malformed-encoding observations](../docs/validation/parliament_ballot_b6/malformed-results.md)
   cover 164 selected classes per mode, 31 repetitions each, with expected
   decode/codec refusal and input/outcome/diagnostic parity. These are
   warm-process observations, not exhaustive coverage or worst-case bounds;
   remaining work is tracked in the
   [requirement audit](parliament_ballot_b6_requirement_audit.md).
3. **Establish deterministic and randomness behaviour.** Scalar, x86 and ARM
   byte and acceptance parity; entropy failure; fresh tapes; forced retry and
   exhaustion tests with the typed result; counter-independent verifier
   work; erasure on every exit. Portable/accelerated parity, typed exhaustion
   tests and supplementary Mac/iPhone/Samsung ARM-platform agreement exist
   **[C]**. The [standalone lifecycle contract](parliament_ballot_prover_lifecycle.md)
   adds finish-and-discard cancellation with a synchronized publication boundary
   and selected-buffer cleanup observations; eight release tests pass per mode.
   It does not interrupt the synchronous prover. Physical x86/ARM parity,
   named-phone cancellation latency/memory and independent side-channel/full
   erasure review remain open.
4. **Produce resource tables and measurements.** Complete allocations and
   work counts; cold and warm verification; late-invalid cases; proving
   distributions and retry histograms; peak memory. The source revision, the
   compiler, the hardware and the measurement method are pinned. B5 supplies
   decoded-statement timing and incremental requested heap; B6 additionally
   records fresh-input decode/verification, warm and late-invalid runs,
   actual proving/retry distributions and requested live Rust heap including
   inputs **[C]**. Separate phone process samples are observations, not peak
   bounds. Complete work/allocation certificates, cold-process/cache tests,
   named-phone cancellation and the baseline qualification remain open.
5. **Close envelope accounting.** Naked proof lengths are not complete
   envelope lengths. Exact dossier-level framing and accounting remain
   required. Ballot design section 12.2 resolves the engineering sequence:
   measure the actual canonical schemas during authorized integration, with
   complete accounting still required for qualification.

Passing the implementation checks does not substitute for the complete
foundational arguments and the complete ledger that selection requires
**[R]**.

Conformance to the FAEST vectors establishes that reference mode computes
FAEST, and nothing about ballot security or ballot mode. "Deterministic
prover" means deterministic given an explicit random tape, never fixed or
reused production randomness. The phone
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

The review's following conditions still prevent selection or activation **[R]**:

- a foundational game, simulator, extractor or reduction is missing or fails;
- the ledger fails the contract of section 8.8;
- the implementation needs an unproved protocol deviation;
- adversarial tests expose an unconstrained witness, transcript substitution
  or determinism defect;
- the final secure parameters exceed a hard resource limit;
- a primitive assumption is stronger than the recorded approved design.

Engineering follows the later authorization in ballot design section 12.2:
missing qualification evidence alone does not stop development. An identified
unsound relation, invalid binding, determinism defect or exceeded hard resource
limit stops the affected implementation pending correction. Experiments remain
labelled experimental. Today no ledger satisfies the
contract, because its primitive terms have no justified values
(section 8.5); the written arguments are conditional and unreviewed; and the
direct local argument for late `H4` and `H0` completions is missing, although
the soundness theorem avoids it (section 7.1).

The construction is switched when the final security argument fails, or when
the secure implementation exceeds a hard limit after straightforward grouping
and streaming work. A narrow standard-hash STARK is then evaluated under the
same requirements. Digests are not shortened, the security metric is not
weakened and limits are not raised silently; the one change of the metric,
in section 8.8, is explicit and recorded as a weakening. If the SHAKE256 public-list
construction passes, it is retained even if the hybrid benchmarks faster **[R]**.

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
  the pad and its Booleanity-only role, both authorization values and the
  preimages of `D_reg` and `D_v`, the 1,024-bit nullifier, the witness
  layout, the ordered constraint stream and its homogenisation, the
  prefix-form selector, the exclusion of positions at or beyond `S`, the
  descriptor and its digests, the bounded opaque inputs, the role prefix and
  body of every backend hash call, the salt, the counter rule, the leaf
  commitment with its field and bit conventions, the naked proof layout, and
  the transcript binding of the statement, `auth`, `auth_v` and the list
  bytes through `mu`. The `T_crt` values are the review's and are reproduced
  here from the generated table sources, then checked against the compiled
  codec by the final profile/vector tests. The `D` values are
  independently recomputed from the definitions (section 6.1). The
  implementation vectors check the compiled descriptor and namespace bytes.
- **The two weakenings:** gate 1 from knowledge extraction to adaptive
  relation soundness, with what the owner gives up (section 2); and the
  contract of section 8.8. Whether gates 2, 3 and 8 carry the authorization
  guarantees as the extractor-free reductions claim.
- The [arguments file](parliament_ballot_proof_arguments.md) in full, against
  the standard of section 11.1, for both proofs under one `sk`. In the
  review's own order **[R]**: first the adaptive soundness theorem, its
  conditioning on fixed auxiliary functions and its local-witness predicate
  and transition table; then the strengthened constraint equivalence and the
  compact-conversion query ledger. Then the joint simulator with the salted
  challenge 1, the singleton-record deletion lemma, the stopping law and the
  real-game exhaustion transfer; the privacy composition with its
  admissibility rules; the prediction reduction; the direct batch reduction;
  the event inclusions of gates 2 and 8; the re-derived universal-hash
  bounds; the leaf-ambiguity count and the hiding statement for the 112-byte
  leaf commitment; the reconstruction lemmas and the counterexample of
  section 7.6; and the design argument for gate 7.
- **What review cannot close by reading:** assumptions P and U for the
  concrete four-tag SHAKE256 family, including adaptive quantum context
  selection, the costed preprocessing model and the structure of the actual
  sponge (section 8.4), and the bridge from the ideal models to the fixed
  public Keccak-f[1600]; frame collision resistance for both roles; the four
  generator games at the full reduction resources, with the IV and
  cross-instance security of the PRG (section 6.3); the random-oracle model
  of the backend hash domains; the direct local argument for late `H4` and
  `H0` completions; and the deployment-wide ledger of gate 6 at the actual
  resource vector.
- Applicability of the QROM analysis to the actual protocol: adaptive
  statements, adversarially registered entries, the fresh proving tape and
  the bounded incrementing-counter retry loop of section 6.7, the unmodelled
  detail of the published proof, and every imported lemma that this
  evaluation did not read (section 3).
- The consolidated ledger of section 8.5: every loss term, the switching
  subtotal and its treatment, the nominal normalisation `Q* = 2^77` and the
  claim that it bounds the pooled inventory, the crossing conditions, and
  the statement that the written bounds cannot certify 2^-64; the
  statistical budget of section 8.8 and its interpretation; the length of
  every role in section 8.3; and the independent attack-cost assessment with
  the accounting that section 8.8 requires.
- The role audit of existing 32-byte values (section 6.1).
- The public-list contract, the publication of the list at seal and its effect
  on independent full verification (section 6.4).
- The arithmetic of this record that has had one reader, or one reader besides
  the review: section 8.1's coefficients and chosen-message terms, the bounds
  of section 8.2, the recomputed entries of section 8.5, the Keccak grouping
  of sections 8.6 and 9.2, the counts, layout and work figures of
  section 9.7 and every `d_zk = 14` figure.
- The implementation: conformance of reference mode to the pinned
  specification, the port of the official CRT tables and its comparison with
  upstream's generated headers, ballot mode and its cross-implementation
  vectors, the update of the ballot crate to the frozen construction,
  bounded and deterministic verification, identical results across hardware,
  malformed-input behaviour, constant-time and randomness handling in the
  prover including the tape and the exhaustion path, and the patch to the
  pinned `aes` dependency. Source inspection alone does not establish
  resistance to physical side channels **[R]**.

The review's own list of what falls to an independent human cryptographer
and to the owner **[R]**: independent review of the games, reductions,
oracle modelling and concrete accounting; primitive qualification; an
independent attack-cost assessment against the 2^128-elementary-gate
requirement, with preprocessing, coherent lookup, memory and parallel work
counted; independent implementation review of constant-time behaviour,
randomness and erasure, and the named validator and phone qualification; the
owner's records for the explicitly weakened security contract, for the
weakened gate 1 and for eventual activation qualification; and later
production authentication, lifecycle, SDK, restart and rollback, network and
release qualification.

## 13. References

Reading status: **full**, **part**, **abstract**, **code** (source files
read), **research pass** (collected mostly from abstracts or secondary
citations; unverified), **not read by us** (reported by the second-opinion
review).

Venue and year metadata for the arXiv QROM entries, for Unruh 2014/587 and
Liu–Zhandry 2019/262, the Bernstein title, the title and venue of the
Kiltz–Lyubashevsky–Schaffner entry, the title of the
Bennett–Bernstein–Brassard–Vazirani entry, and the author line of the FAEST
specifications were supplied from memory and not checked against the sources
**[E]**. The URLs are the identifiers.

**Specifications and code**

| Source | Status |
| --- | --- |
| FAEST team (Baum et al.), *FAEST Algorithm Specifications*, version 2.0. <https://faest.info/faest-spec-v2.0.pdf> | Part: pp. 2–82, 93–97, 101–111 |
| FAEST team (Baum et al.), *FAEST v3 Algorithm Specifications*, version 3.0. <https://faest.info/faest-spec-v3.0.pdf> | Part: sections listed in section 3. The second-opinion review also cites section 6 with Figure 6.2 (CRT gates), Lemma 7.3, Figure 7.19 (`ZK.OWFVerify`), Lemmas 10.24, 10.26, 10.40, 10.44, 10.48, 10.49, 10.50, 10.51 and 10.52, Corollaries 10.27 and 10.41, games G5 and G6 of Theorem 10.42, games G4 and G5 of Theorem 10.53, and sections 10.5, 10.5.2, 10.7, 10.11.7–10.11.9 and 10.11.10. Statements resting on parts outside the pages we read are **[R]**; the passages inside those pages were not re-checked against the review's use of them and are **[R]** as well |
| FAEST reference implementation. <https://github.com/faest-sign/faest-ref> | Part: listings, README, changelog, test manifest; v2.0.5 sources through tool summaries. The implementation work read the test headers and generator sources at tag `v3.0.2`, commit `4fb6b71143` (fixture README, section 11.3) |
| `faest` Rust crate (ait-crypto). <https://github.com/ait-crypto/faest-rs> | Part: manifest, README, changelog, `src/lib.rs`, `src/faest.rs`, `tests/nist.rs`, through tool summaries |
| FAEST project site. <https://faest.info/> | Front page; resources page not read by us |
| Chiang et al., reference implementation. <https://github.com/jachiang/PQ-Threshold-Ring-Sigs-from-VOLEitH> | Code: branch `master`; files listed in section 3 |
| NIST, *Post-Quantum Cryptography: Security (Evaluation Criteria)*. <https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-(evaluation-criteria)> | Full, through a tool summary |
| *Zcash Protocol Specification*. <https://zips.z.cash/protocol/protocol.pdf> | Part: sections 4.16 and 8.4 |
| Semaphore v4 circuit. <https://github.com/semaphore-protocol/semaphore> | Code: `semaphore.circom`, through a tool summary |
| NIST, *FIPS 202: SHA-3 Standard*. <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf> | Not read by us; cited by the second-opinion review (sections 3.1, 3.3, 5, 6 and Appendix B for the conventions of section 6.3; sections 5 and 6 for the single rate block of each credential evaluation, section 6.2) |
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
| Don, Fehr, Majenz, *The Measure-and-Reprogram Technique 2.0: Multi-Round Fiat-Shamir and More*, CRYPTO 2020. <https://arxiv.org/abs/2003.05207> | Part. The second-opinion review cites its Corollaries 13 and 15 for the generic multi-round bound (section 7.6) **[R]**; not checked by us |
| Don, Fehr, Majenz, Schaffner, *Online-Extractability in the Quantum Random-Oracle Model*, EUROCRYPT 2022. <https://arxiv.org/abs/2103.03085> | Abstract and theorem index. The second-opinion review cites its Theorem 4.3 for the extractable random oracle (section 7.6) **[R]**; not read by us |
| Don, Fehr, Majenz, Schaffner, *Efficient NIZKs and Signatures from Commit-and-Open Protocols in the QROM*, CRYPTO 2022. <https://arxiv.org/abs/2202.13730> | Part. The second-opinion review cites its Definitions 3.4 and 3.5 and the hypotheses of Theorems 4.2 and 5.2 for the limits of online extractability (section 7.6) **[R]** |
| Grilo, Hövelmanns, Hülsing, Majenz, *Tight Adaptive Reprogramming in the QROM*, ASIACRYPT 2021. <https://arxiv.org/abs/2010.15103> | Part. The second-opinion review cites its Theorem 1 for the form of the reprogramming bound, its need for location bounds and its fresh-value hypothesis, and applies its fresh-location form to challenge 1 at the salted input (section 7.1) **[R]** |
| Jaeger, arXiv:2511.16009 (version 1; title not recorded in the review's citation). <https://arxiv.org/html/2511.16009v1> | Not read by us; cited by the second-opinion review (Theorem 2.1 and section 1.1, the fixed-permutation formulation of one-way-to-hiding used in the hidden-label deletion bound, section 7.1) |
| Bennett, Bernstein, Brassard, Vazirani, *Strengths and Weaknesses of Quantum Computing*. <https://arxiv.org/abs/quant-ph/9701001> | Not read by us; cited by the second-opinion review (section 3, the hybrid method behind its ideal-table lemma, section 8.4) |
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

**Sponge and keyed-sponge security**

All cited by the second-opinion review for its assessment of assumptions P
and U (section 8.4). **None was read by us**; the titles are not recorded in
the review's citations.

| Source | Status |
| --- | --- |
| Bertoni, Daemen, Peeters, Van Assche, 2008 (sponge indifferentiability). <https://keccak.team/files/SpongeIndifferentiability.pdf> | Not read by us; the review cites Theorem 2 |
| Alagic, Carolan, Majenz, Tokat, 2025, arXiv:2504.16887 (version 1). <https://arxiv.org/html/2504.16887v1> | Not read by us; the review cites Theorem 7.22 |
| Carolan, Poremba, Zhandry, arXiv:2410.16595 (version 1). <https://arxiv.org/html/2410.16595v1> | Not read by us; the review cites Theorem 8.1 |
| Gaži, Pietrzak, Tessaro, 2015 (keyed-sponge PRF bounds). <https://research-explorer.ista.ac.at/download/1671/4827/IST-2016-673-v1%2B1_053.pdf> | Not read by us; the review cites Theorems 2 and 3 |
| Hosoyamada, ePrint 2025/1059. <https://eprint.iacr.org/2025/1059> | Not read by us. The review reports the abstract only, did not verify the full theorem and does not import it |
| Carolan, Majenz, September 2026, arXiv:2609.28469 (version 1). <https://arxiv.org/html/2609.28469v1> | Not read by us; the review cites Theorem 5.5 |

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
