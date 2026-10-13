# Parliament ballot proof: written arguments awaiting independent review

Status: written arguments, consolidated on 2026-10-13, for the eight
properties of
[parliament_private_ballot_design.md](parliament_private_ballot_design.md)
section 5 (the "ballot design"), for the construction stated in section 1
here (the "frozen construction"): the strengthened relations on the backend
with the role-namespace prefix and four extensions (a per-proof public salt,
a `2^20` counter limit, a salted `H5` and an affine-checked leaf commitment).
[parliament_ballot_proof_profile.md](parliament_ballot_proof_profile.md) is
the "profile record". The arguments were written by the second-opinion review
(profile record section 3) in successive texts. Where those texts differ, the
review's latest decision governs the construction and which arguments are
adopted. The implementers consolidated them here without changing their
content: overlapping statements are merged, the final dimensions are used
throughout, and quantities that depend on the dimensions are recomputed and
marked. **Every statement is [R] unless labelled otherwise**; the labels are
those of the profile record.

Sources not read by us:

- FIPS 202.
- The FAEST v3.0 specification outside the parts listed in profile record
  section 3. Citations of its other parts are the review's and unverified;
  among them section 6 with Figure 6.2, Figure 7.19, Lemma 7.3,
  section 10.5.2, Lemmas 10.24, 10.26, 10.40, 10.44, 10.51 and 10.52,
  Corollaries 10.27 and 10.41, and games G5 and G6 of Theorem 10.42. Where
  the review uses a result from the pages we read (Theorem 10.42,
  section 10.11), the use made of it is still the review's.
- Jaeger, arXiv 2511.16009 (fixed-permutation one-way-to-hiding), and
  Bennett–Bernstein–Brassard–Vazirani, arXiv quant-ph/9701001.
- The sponge and keyed-sponge papers of the table in section 7
  (Bertoni–Daemen–Peeters–Van Assche; Alagic–Carolan–Majenz–Tokat;
  Carolan–Poremba–Zhandry; Gaži–Pietrzak–Tessaro; Hosoyamada;
  Carolan–Majenz). Every statement about them is the review's reading.
- The reading status of every other paper named below is that of profile
  record section 13.

**This file selects no profile and qualifies nothing.** No property of the
gate is established by it, and the security contract is not met.

Two requirements are weaker than the ones this construction was first
measured against, and both are stated in those words where they apply:

- **Property 1 is weakened from knowledge extraction to soundness.** The
  review's decision replaces the requirement that an efficient extractor
  recover a witness by adaptive relation soundness: existence of a witness.
  The review calls this a genuine weakening and not an equivalent
  reformulation (section 5.2). Properties 2, 3 and 8 must carry the
  authorization guarantees independently, under additional assumptions.
- **The earlier contract weakening stands** (section 8.1): the review's
  recommended contract replaces the earlier proven `2^128`-query requirement.

Each part has one of three statuses:

- **complete (awaiting review)**: every step is written; no independent review
  has taken place;
- **conditional**: a reduction to stated premises that are themselves unproven;
- **incomplete**: a named step is missing.

| Part | Status |
| --- | --- |
| 1. Protocol the arguments are about | Frozen for investigation: both relations, the witness layouts, the ordered constraints, the backend rows and CRT tables, the role prefixes, the 112-byte tape, the salt, the counter rule, the salted `H5`, the 112-byte leaf commitments, the proof layout, `SUITE` and the descriptor. The descriptor digests are computed here **[D]** and await cross-checking. No implementation of the frozen construction is reported in this file (section 9.3). Production encodings and envelopes are later obligations |
| 2. Encoding equivalence | Complete (awaiting review). The review's proof covers the commitment and nullifier permutations and the selector; its extension to the pad, the two authorization permutations and the 1,024-bit nullifier output is the implementers' **[D]**. The soundness argument uses it as a premise |
| 3. Universal-hash bounds at the final dimensions | Complete (awaiting review); values recomputed **[D]** |
| 4. Soundness for false instances, response-graph experiment | Complete (awaiting review); it is not a Fiat–Shamir theorem, not adaptive and not a knowledge theorem |
| Property 1, adaptive relation soundness | Complete (awaiting review) for the repaired theorem only, a written argument in an explicit model: the designated backend hash domains are independent quantum-accessible random oracles, and the argument conditions on global induced-seed uniqueness. Bound `δ_leaf,all + 340·Q^3·2^-512 + 70·Q^2·2^-256`, batch form with the factor 1,001. The structural statistical term `δ_leaf,all` is below `2^-128` with the 112-byte leaf commitment. Open: the original local-transition step for late `H4` and `H0` completions (a missing proof step, not needed by the written argument), and a real-game tail bound for the retry count |
| Property 2, unforgeability | Conditional on adaptive soundness, selected-context uniqueness `U`, vote-frame collision resistance, the joint zero-knowledge bound `Z` and the credential assumption `P`. Bound (43) |
| Property 3, nullifier uniqueness | Conditional on batch soundness, `U` at authenticated seals, frame collision resistance, `Z` and `P`; a direct batch reduction that charges `Z` and `P` once; no extractor. Bound (45) |
| Property 4, unlinkability | Conditional on `Z` and `P`, under the admissibility rules of section 5.2, restated by the review for the vote authorization value. Bound (88) |
| Property 4, non-frameability | Conditional: identity reductions to properties 2 and 8 |
| Property 5, joint zero knowledge | Conditional chain (CRT-layer simulation argument, then the outer composition with the salt, the `2^20` counter limit and the salted `H5`), giving `Z ≤ ε_P1 + T·e_gen + K_sim + σ`. The generator terms `e_gen` are unquantified, the chain is unreviewed, and the review has not restated the CRT-layer argument in full for the extended backend |
| Property 5, anonymity | Conditional on `Z` and `P`; the same bound (88) |
| Property 6, concrete security | Incomplete. The ledger is assembled (section 8.5) with its unknown terms symbolic. Under an explicitly hypothetical nominal substitution every game bound is below 1/2. That is not a certificate, and the written bounds that contain `Z` cannot certify `2^-64` for any values of the unknown terms |
| Property 7, deterministic bounded verification | Conditional: a design argument whose premises are a completed verifier for the frozen construction and, for production, the envelope and Norito mappings, which are not written |
| Property 8, registration authorization | Conditional on adaptive soundness, `U` at registration-origin targets, registration-frame collision resistance, `Z` and `P`. Bound (90) |
| Knowledge extraction (section 10) | Not required by the design. The review's analysis is kept as analysis; no efficient extractor is established |

What the review has and has not restated. For the strengthened relations it
restated the soundness argument, the credential-side reductions and the
privacy composition at the final dimensions. For the extended backend it
gave the changes to the outer composition, the hidden-label deletion lemma,
the leaf-ambiguity term and the ledger, and stated that the leaf generator
experiment has nine blocks. It did not restate the encoding equivalence, the
universal-hash derivations or the remaining steps of the CRT-layer argument;
sections 2 to 4 and 6.5.1 carry those at the final dimensions as the
implementers' consolidation, marked **[D]** or **[E]** where it goes beyond
the review's text.

Notation. `K = F_2[α]/(α^256 + α^10 + α^5 + α^2 + 1)` is the FAEST
polynomial-basis field `F_(2^256)`; Boolean values are embedded as `0, 1 ∈ K`;
all sums are field sums, so addition and subtraction coincide. `l` is the
witness length in bits and `M` the number of constraints of a relation (the
review's `ℓ` and `N_c`), kept distinct from the credential commitment `C`.
`sk` is the review's `s`. `lambda = 256`, `tau`, `w_grind`, `T_open` and
`d_zk = 7` are the backend parameters. Lifetime symbols: `U = 2^34`
registrations, `T = 2^44` honest proving invocations over both roles
(invocations that return exhaustion included), at most `2^10` per credential,
`J = 2^24` body scopes, `S ≤ 1,000`. `q` or `Q` is a quantum query budget, as
each section states. `M_ctr = 2^20` is the number of counter values (the
review's `M`). `Ω` is the set of admissible third challenges and
`p = |Ω| / 2^256`. `U` also names the uniqueness assumption and `P` the
credential pseudorandomness assumption (section 8.4); the context separates
them from the registration ceiling and from polynomials.

## 1. The protocol

Framing, `P16`, `Frame`, `Enc`, `B`, `scope`, `R`, `policy_hash` and the list
`L` are those of profile record sections 6.1 and 6.2 and are not repeated.
The credential functions, the two authorization digests and values, both
messages and both `mu` preimages are stated in section 1.1. The backend, its
hash calls, the tape, the counter rule and the proof layout are stated in
section 1.7.

The protocol is frozen for investigation. Two constructions are kept apart:

- **The frozen construction** (ballot mode): the relations of section 1.1 on
  the backend of section 1.7. Every ballot backend hash call carries the
  77-byte role prefix `PREFIX_R = ASCII("PARL/FAEST/v1") || NS_R`, and the
  backend has four extensions over the FAEST v3 algorithms: a fresh 256-bit
  public salt per proof, a counter limit of `2^20`, the salt in every `H5`
  input, and a 16-byte affine checksum appended to every leaf commitment.
- **Reference mode**: the unchanged FAEST v3 algorithms with an empty prefix,
  the official OWF and the `H3` derivation. It is a separate construction,
  used only to test the backend against the official vectors. It is not an
  accepted ballot mode.

Where this section and profile record section 6 differ on the backend, this
section states the frozen construction. Unchanged in definition: the
descriptor frame, the CRT serialisation `CRT_BYTES` and its digest `T_crt`,
the role namespaces `NS_REG` and `NS_VOTE` as functions of `D`, the preimages
`F_REG` and `F_VOTE` of `mu_R`, the length bounds and boundary rules of the
public inputs, and the test-only statement codec.

- The standalone construction's public inputs are bounded opaque byte strings.
  It neither imports node types nor parses their encodings, and it applies no
  conversion, normalization, delimiter or terminator to an opaque input. Core
  must supply and validate the pinned canonical Norito representations; the
  proof construction does not detect two encodings of one node-level value.
- The verifier selects a compiled, fixed descriptor. It does not accept a
  caller-defined descriptor. Every other ballot descriptor, including every
  retired one, is rejected; there is no compatibility path.
- The review's decisions freeze the relations, the witness intervals, the
  constraint order, the backend extensions, the suite string and the
  descriptor, so no relation or transcript choice remains open **for the
  standalone construction**. On that basis condition 1 of the selection rule
  (profile record section 11.1) is taken as satisfied by decision **[E]**:
  the review's finding on condition 1 is for standalone work with bounded
  opaque inputs, and its later decision texts do not restate it. Conditions 2
  and 3 still fail. Production Norito mappings, production envelopes and
  authenticated integration remain later obligations, and their absence must
  not be hidden by claiming that the standalone verifier validates node-level
  canonicality. Implementation, resource measurements and qualification
  remain unfinished, and the feature stays disabled.

**[C]** The working-tree crate `crates/iroha_parliament_ballot_proof`
compiles a 72-byte suite string that ends in `/NS-PREFIX77` and a 229-byte
descriptor (`src/profile.rs`, read on 2026-10-13; no build was run). That is
neither the suite nor the descriptor of section 1.1: the crate does not
contain the frozen construction. The implementation state is in section 9.3.
The constraint order and the byte layouts below are protocol choices, not
descriptions of implemented behaviour.

### 1.1 Functions, relations and public validation

```text
Com_B(sk)   = SHAKE256("PCR1" || P16 || sk[48] || B[64],   128 bytes)
Tag_x(sk)   = SHAKE256("PNF1" || P16 || sk[48] || x[64],   128 bytes)
Auth_d(sk)  = SHAKE256("PAU1" || P16 || sk[48] || d[64],    64 bytes)
AuthV_d(sk) = SHAKE256("PAV1" || P16 || sk[48] || d[64],    64 bytes)
```

Registration:

```text
D_reg = SHA3-512(
    Frame("PARL/REG-AUTH/v1";
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
        C
    )
)

auth = Auth_(D_reg)(sk)

m_reg = (
    network_id, authority, assignment_id,
    governance_attempt_id, election_attempt_id, body_role,
    B, C, auth, P16
)
```

Vote:

```text
nf = Tag_scope(sk)

D_v = SHA3-512(
    Frame("PARL/VOTE-AUTH/v1";
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
        policy_hash
    )
)

auth_v = AuthV_(D_v)(sk)

m = (scope, R, S, nf, auth_v, vote, policy_hash, P16)

F_VOTE = Frame("PARL/MU/VOTE/v1";
    B, scope, R, u16_le(S), concat(L),
    nf, auth_v, u8(vote), policy_hash)
```

`F_REG` is that of profile record section 6.3.

- In `Auth_d` and `AuthV_d`, `d` is any 64-byte digest argument; `auth` uses
  `d = D_reg` and `auth_v` uses `d = D_v`.
- `D` in both frames is exactly the 64 bytes `SHA3-512(DESC)`: not `DESC` and
  not a Norito wrapper around `D`. `body_context` and
  `authoritative_body_context` name the same byte string.
- `D_reg` excludes `auth`, `mu`, the proof bytes and the prover randomness.
  Its role field is the literal `REG`, not a backend seed.
- `D_v` covers every vote statement field other than `auth_v`, including the
  actual list bytes `concat(L)`. It excludes `auth_v`, `mu`, the proof bytes
  and the proving randomness. No account, authority or selected position
  enters it. Including `concat(L)` makes the authorization-frame argument of
  section 6.2 independent of a separate list-digest collision reduction.
- `D_reg` and `D_v` are recomputed by verification. A supplied derived digest
  is never trusted, and `D_v` need not be carried.
- The registration fields, including `auth`, enter `mu_REG` through `F_REG`;
  the vote fields, including `nf` and `auth_v`, enter `mu_VOTE` through
  `F_VOTE`; the descriptor digest `D` enters both through `PREFIX_R`. Both
  authorization values are therefore bound through `mu` into the IV and the
  challenge chain, and each is also constrained inside its relation.
- The nullifier is 1,024 bits, not 512. The existential uniqueness argument
  of section 6.2 must exclude alternative secrets, including ones that nobody
  can efficiently find; the 512-bit ideal-map arithmetic does not support
  that at the lifetime ceilings and the 1,024-bit arithmetic does
  (section 8.2). The lengthening supplies no general claim of "1,024-bit
  SHAKE security".
- A vote authorization value alone would not settle the mixed-list case: a
  different list secret might share the target nullifier and produce its own
  authorization value. That is why the relation carries both the
  authorization value and the widened nullifier.

After public validation the semantic relations are:

```text
R_reg(x_reg; sk)        ⇔  WellFormed_reg(x_reg)
                            ∧ C = Com_B(sk)
                            ∧ auth = Auth_(D_reg)(sk)

R_vote+(x_vote; sk, i)  ⇔  WellFormed_vote(x_vote)
                            ∧ 0 ≤ i < S
                            ∧ C_i = Com_B(sk)
                            ∧ nf = Tag_scope(sk)
                            ∧ auth_v = AuthV_(D_v)(sk)
                            ∧ vote ∈ {0, 1, 2}
```

All equations of a relation use the same 384-bit secret. `x_reg` contains the
authoritative body context, the fixed descriptor and the complete `m_reg`.
`x_vote` contains `B`, the validated ordered list `L` itself (its canonical
bytes, not merely `R`), the descriptor and the complete `m`. `L_R` is the
language of role `R`: the statements with a witness.

`WellFormed` (public validation) covers, in the standalone construction, the
length bounds of profile record section 6.1 with `nf` exactly 128 bytes and
`auth_v` exactly 64 bytes, the compiled fixed descriptor, the recomputed
body-context digest `B`, for registration the recomputed `D_reg`, and, for
voting, `3 ≤ S ≤ 1,000`, exactly `S` strictly ordered distinct commitments
(unsigned bytewise order), the recomputed list digest `R`, the recomputed
`D_v` and a vote byte in `{0, 1, 2}`. A supplied `B` that differs from the
digest recomputed from the exact encoded body context is rejected before any
backend proof work; an inconsistent statement is never silently repaired.
Canonicality of the typed values behind the opaque inputs is validated by
Core on its pinned Norito representations, not by public validation. These
checks contribute no witness constraints. Authenticity of the seal is an
external premise supplied by the finalized-board model: a caller-supplied `L`
is never sufficient. Registration eligibility, account authorization and
assignment policy remain separate Core checks.

The algebraic equations alone do not establish transcript binding: the
complete public statement and message must enter `mu` as prescribed, and all
bytes read by verification are bound into the transcript identity. `REG`,
`VOTE` and the parameter rows are separated by the explicit role prefix on
every backend hash call; each call keeps its reference suffix byte (profile
record section 6.3). Dependence of a hash input on `mu` is causal dependence
only and is not the disjoint-domain statement adopted here: without the prefix
`H0` reads only the IV and `H1` reads commitment material without a namespace,
so different roles can reach identical oracle inputs (the review cites
`crates/iroha_zkp_vole/src/hash.rs` and `bavc.rs`; not re-read by us for this
purpose). The AES PRG is unchanged and keeps its tweaks; it is not converted
into an independently namespaced random oracle, and its IV and cross-instance
security remain proof obligations. Binding the full list, statement and
descriptor in every relevant transcript domain simplifies adaptive statement
localization; it requires a new exact transcript argument (section 6.1).

Honest credential generation samples `sk` uniformly from `{0,1}^384`, fresh for
each body. **Uniformity is a generation requirement, not an algebraic
predicate**: the relations accept every secret that satisfies their equations,
including an adversarially chosen one. No AES key-validity constraint is
included; adding `sk_0·sk_1 = 0` would change the relation and exclude one
quarter of the uniformly sampled secrets.

The circuit witness additionally contains a fresh 256-bit pad, the committed
Keccak states and, for voting, two selector vectors. These are derived or
random coordinates; they introduce no second credential secret. Formally the
proof-system relation is the semantic relation extended by Boolean pad
coordinates, which are projected away when the application witness is
considered.

**Descriptor.** The suite literal is the review's, 129 ASCII bytes without a
terminator; its length prefix is `81 00 00 00`:

```text
SUITE = ASCII(
  "KECCAK-F1600/2R-FWD/SEL-32X32-PREFIX/PAD-256/TAPE-112/CTR-U20-LE32/NS-PREFIX77/NF-1024/VAUTH-512/SALT-256/H5-SALT/LEAF-AFFINE-896"
)
```

The relation dimensions are
`(l_reg, M_reg, l_vote, M_vote) = (35840, 72576, 53504, 108931)` on both rows.
The parameter tuples and `T_crt` are unchanged, and the descriptor frame
definition is unchanged apart from the suite value. `DESC` is 286 bytes on
both rows (the review's figure, recomputed **[D]**: `2 + 12 + 2` for the tag
and the field count, six length prefixes of 4 bytes, and fields of 16, 9, 12,
64, 16 and 129 bytes). Exact serialisation, in order, with `Frame` of profile
record section 6.1:

```text
DESC =
    u16_le(12) || ASCII("PARL/DESC/v1") || u16_le(6)
 || u32_le(16) || P16
 || u32_le(9)  || ASCII("FAEST-3.0")
 || u32_le(12) || u16_le(lambda) || u16_le(tau) || u16_le(w_grind)
               || u16_le(T_open) || u16_le(d_zk) || u16_le(n_mult)
 || u32_le(64) || T_crt
 || u32_le(16) || u32_le(35840) || u32_le(72576)
               || u32_le(53504) || u32_le(108931)
 || u32_le(129) || SUITE

fast row:   (lambda, tau, w_grind, T_open, d_zk, n_mult) = (256, 33, 8, 229, 7, 704)
small row:  (lambda, tau, w_grind, T_open, d_zk, n_mult) = (256, 22, 6, 225, 7, 696)
T_crt:      the two values of profile record section 6.1

D (fast row) =
01ed9f564981a07ab383d513c4e816f5a76542c7220eaaa36742f8eb0c51341da089e154a815f92fcd18353077cde18f435dfaa0834b65fdf3a658b0accdda28

D (small row) =
4c38e45d70b5aa1295c107fe9035e82b179d8ec10ab7acf59b6955e0b22f9fdb09976788745a0fbb4ee1cabd840a12d9e746bf76b3998ab72c06e019bb889412
```

**[D]** Both values are `SHA3-512(DESC)` computed here with Python `hashlib`
from the serialisation above; the review gives no digest values. The same
script, given the suite and the dimensions that the ballot crate compiles
(the 72-byte suite ending in `/NS-PREFIX77` and dimensions
`(35840, 72576, 35904, 72707)` in
`crates/iroha_parliament_ballot_proof/src/profile.rs` **[C]**), reproduces
that file's two descriptor digest constants; that checks the serialisation
and not the new values. **The new values have not been cross-checked against
a second implementation; that check is outstanding.** Because `D` changes,
both role namespaces, both `mu` values, every authorization value and every
proof byte change. All retired ballot descriptors are rejected without
compatibility handling.

### 1.2 SHAKE inputs, padding and state bits

Each unpadded SHAKE256 message is 132 bytes:

| Byte interval | Commitment `C` | Registration authorization `A` | Nullifier `N` | Vote authorization `V` |
| --- | --- | --- | --- | --- |
| `[0, 4)` | ASCII `PCR1` | ASCII `PAU1` | ASCII `PNF1` | ASCII `PAV1` |
| `[4, 20)` | `P16` | `P16` | `P16` | `P16` |
| `[20, 68)` | `sk` | the same `sk` | the same `sk` | the same `sk` |
| `[68, 132)` | `B` | `D_reg` | `scope` | `D_v` |

- Append `1f 00 00 80` to obtain the 136-byte rate block, then 64 zero capacity
  bytes, giving the initial state `A_D^(0)` for the permutation
  `D ∈ {C, A, N, V}`. Registration uses `C` and `A`; voting uses `C`, `N`
  and `V`.
- Serialized byte bit `j` is the bit of value `2^j`, `0 ≤ j < 8`; state bytes
  and lanes are little-endian under this convention. State coordinates are
  flattened by `t = 64·(x + 5y) + z`, `0 ≤ x, y < 5`, `0 ≤ z < 64`.
- Secret bit `j` occupies initial-state bit `160 + j` of every permutation of
  the relation.
- After the permutation the commitment and the nullifier are state bits
  `[0, 1024)` and each authorization value is state bits `[0, 512)`, packed
  with the same convention. A 128-byte output fits within the 136-byte rate,
  so no output needs a second squeezing permutation and widening the
  nullifier adds no permutation and no committed state. The vote
  authorization evaluation adds one permutation.
- The mappings follow FIPS 202 sections 3.1, 3.3, 5, 6 and Appendix B.

`A_D^(r)` is the complete 1,600-bit state after `r` completed Keccak-f[1600]
rounds (FIPS round indices 0 to 23, each including its iota step). With
`R_r = ι_r ∘ χ ∘ π ∘ ρ ∘ θ`, XOR replaced by field addition and AND by
multiplication,

```text
χ(A)[x, y, z] = A[x, y, z] + (1 + A[x+1, y, z])·A[x+2, y, z]     (x mod 5)
G_g = R_(2g-1) ∘ R_(2g-2),    1 ≤ g ≤ 12
```

The other step mappings are affine or linear, so each coordinate of a forward
two-round group `G_g` has degree at most four. No inverse-round computation is
used. States are committed after 2, 4, ..., 22 completed rounds. There are no
witness blocks for the absorbed initial states, odd-round states, final
states, the selected commitment or the padding.

### 1.3 Witness layout

Half-open bit intervals; `g = 1, ..., 11`.

| Component | Registration | Vote |
| --- | --- | --- |
| Fresh pad | `[0, 256)` | `[0, 256)` |
| Credential secret `sk` | `[256, 640)` | `[256, 640)` |
| Commitment state `A_C^(2g)` | `[640 + 1600(g-1), 640 + 1600g)` | the same |
| Registration authorization state `A_A^(2g)` | `[18240 + 1600(g-1), 18240 + 1600g)` | none |
| Nullifier state `A_N^(2g)` | none | `[18240 + 1600(g-1), 18240 + 1600g)` |
| Vote authorization state `A_V^(2g)` | none | `[35840 + 1600(g-1), 35840 + 1600g)` |
| Selector `a_0, ..., a_31` | none | `[53440, 53472)` |
| Selector `b_0, ..., b_31` | none | `[53472, 53504)` |
| **Total `l`** | **35,840** | **53,504** |

**[D]** `256 + 384 + 2 × 11 × 1,600 = 35,840` and
`256 + 384 + 3 × 11 × 1,600 + 64 = 53,504`, equal to the review's totals.

The pad occupies the positions whose backend masks define the CRT label
offset: the gates use labels with `L_e^1 = L_e^0 ⊕ u[0, 256)` while the proof
publishes `d = w ⊕ u`, so a party that knows `w[0, 256)` learns the offset
(FAEST v3 section 6, Figure 6.2, cited by the review; not read by us). The pad
is prover randomness sampled per proof (section 1.7). It participates in
exactly its 256 Booleanity constraints and in no other application
constraint; its coordinates take part in the backend commitment, correction
and consistency machinery like any other witness coordinate.

### 1.4 Constraints

Transitions, for every permutation `D` of the relation:

```text
A_D^(2g)[t] + G_g(A_D^(2g-2))[t] = 0,     1 ≤ g ≤ 11,  0 ≤ t < 1600      (1)
O_D = G_12(A_D^(22))                      // an expression, not a witness
```

Registration outputs:

```text
O_C[t] + C[t]    = 0,     0 ≤ t < 1024                                   (2)
O_A[t] + auth[t] = 0,     0 ≤ t < 512                                    (3)
```

Vote selector, with `p_i = a_floor(i/32) · b_(i mod 32)`:

```text
a_j · sum_{k<j} a_k = 0,    b_j · sum_{k<j} b_k = 0,     0 ≤ j < 32      (4)
1 + sum_{j<32} a_j = 0,     1 + sum_{j<32} b_j = 0                       (5)
1 + sum_{i<S} p_i = 0                                                    (6)
```

Vote outputs:

```text
O_C[t] + sum_{i<S} p_i · C_i[t] = 0,     0 ≤ t < 1024                    (7)
O_N[t] + nf[t] = 0,                      0 ≤ t < 1024                    (8)
O_V[t] + auth_v[t] = 0,                  0 ≤ t < 512                     (9)
```

Booleanity, supplied once by the generic wrapper for every witness coordinate,
selectors and pad included:

```text
w_i · (w_i + 1) = 0                                                     (10)
```

The multiplexer in (7) has degree two, because each `C_i[t]` is a public
scalar; its equality with the computed output has degree at most four. No
second selector-Booleanity block is appended. (1) for `D = V` is the review's
block `(TV)`, (8) its widened `(VN)` and (9) its `(VA)`.

### 1.5 Constraint order

| Registration block | Constraint indices |
| --- | --- |
| Booleanity (10), increasing witness index | `[0, 35840)` |
| Commitment transitions (1) | `[35840, 53440)` |
| Commitment output (2) | `[53440, 54464)` |
| Authorization transitions (1) | `[54464, 72064)` |
| Authorization output (3) | `[72064, 72576)` |
| **Total `M`** | **72,576** |

| Vote block | Constraint indices |
| --- | --- |
| Booleanity (10), increasing witness index | `[0, 53504)` |
| `a`-prefix constraints (4) | `[53504, 53536)` |
| `a`-sum (5) | `53536` |
| `b`-prefix constraints (4) | `[53537, 53569)` |
| `b`-sum (5) | `53569` |
| Range constraint (6) | `53570` |
| Commitment transitions (1) | `[53571, 71171)` |
| Commitment output (7) | `[71171, 72195)` |
| Nullifier transitions (1) | `[72195, 89795)` |
| Nullifier output (8) | `[89795, 90819)` |
| Vote-authorization transitions (1) | `[90819, 108419)` |
| Vote-authorization output (9) | `[108419, 108931)` |
| **Total `M`** | **108,931** |

Within a transition block the order is by `g`, then by state coordinate `t`.
Outputs are ordered by `t` and selector prefixes by `j`. Both identically zero
`j = 0` prefix constraints are retained: removing them would change every
later ZKHash position. Reordering any block changes ZKHash and therefore the
protocol.

Count ledger **[D]** (block lengths of the tables above, summed by kind):

| Constraint kind | Assigned degree bound | Registration | Vote |
| --- | ---: | ---: | ---: |
| Witness Booleanity | 2 | 35,840 | 53,504 |
| Prefix constraints | 2 | 0 | 64 |
| Selector sums | 1 | 0 | 2 |
| Range constraint | 2 | 0 | 1 |
| Commitment transitions | 4 | 17,600 | 17,600 |
| Commitment output | 4 | 1,024 | 1,024 |
| Registration authorization transitions | 4 | 17,600 | 0 |
| Registration authorization output | 4 | 512 | 0 |
| Nullifier transitions | 4 | 0 | 17,600 |
| Nullifier output | 4 | 0 | 1,024 |
| Vote authorization transitions | 4 | 0 | 17,600 |
| Vote authorization output | 4 | 0 | 512 |
| **Relation constraints, excluding Booleanity** | | **36,736** | **55,427** |
| **Total `M`** | | **72,576** | **108,931** |

The vote totals equal the review's (`M − l = 55,427`). These are assigned
degree bounds, not claims that every specialised coordinate polynomial has
exactly that degree; two prefix equations are zero polynomials. The maximum
native degree is four.

### 1.6 Homogenisation to nominal degree seven

For a constraint polynomial `f` of assigned degree `e` and formal witness
commitments `ρ_i(X) = V_i + w_i·X`:

```text
f^(X) = X^(7-e) · Hom_e(f)(ρ(X), X) = X^7 · f(ρ(X)/X)                   (11)
```

The expression is a polynomial because `deg f ≤ e ≤ 7`, and its coefficient of
`X^7` is exactly `f(w)`. Operationally: degree-aligned addition, then lifting
to seven. For example the degree-two multiplexer is aligned to degree four
before it is added to the degree-four Keccak expression. Every constraint
handed to ZKHash has nominal degree seven. A native degree of four is
compatible with `d_zk = 7` because (11) keeps the constraint as the top
coefficient and never exceeds degree seven; it does not justify replacing
seven by four in the root count of section 4.

### 1.7 Backend, proving tape, counter rule and proof layout

| Row | `lambda` | `tau` | `w_grind` | `T_open` | `d_zk` | CRT gates | Role |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Fast | 256 | 33 | 8 | 229 | 7 | 704 | Sole integration candidate |
| Small | 256 | 22 | 6 | 225 | 7 | 696 | Measurement comparator only |

Kept from FAEST v3 in ballot mode: the field representation, the PRG and its
tweaks, the tree layout, the universal hashes, the official CRT tables and
gate order, the suffix bytes, the challenge lengths, the sibling ordering and
challenge decoding of the opening, and the reconstruction of `Ṽ` and `ã_0`.
The third application permutation adds no `H5` gate. Official component and
plain-FAEST signature vectors are conformance targets for reference mode
only; the frozen construction needs its own vectors, and passing the official
vectors does not validate it.

**Backend hash calls.** Every call absorbs the 77-byte `PREFIX_R`, then the
body, then the suffix byte. Field values use the specified `ToBits` encoding.

| Oracle | Body | Suffix | Output |
| --- | --- | ---: | ---: |
| `H_mu` | The complete `F_R(x)` (`F_REG` or `F_VOTE`) | `08` | 64 bytes |
| `H4` | `iv_pre[16] \|\| mu[64]` | `04` | 16 bytes |
| `H0` | `iv[16]` | `00` | 128 bytes |
| Inner `H1` | The 112-byte leaf commitments of one vector, in increasing leaf order | `01` | 64 bytes |
| Outer `H1` | The vector digests, in increasing vector order | `01` | 64 bytes |
| Challenge 1 | `mu \|\| com \|\| c_1 \|\| ... \|\| c_(tau−1) \|\| c_mult \|\| iv_pre \|\| salt` | `09` | 264 bytes |
| Challenge 2 | `chall_1 \|\| ToBits(ũ[4]) \|\| ToBits(Ṽ[4]) \|\| d` | `0a` | 104 bytes |
| Challenge 3 | `chall_2 \|\| ToBits(ã_0, ..., ã_6) \|\| LE32(ctr)` | `0b` | 32 bytes |
| `H5` | `iv[16] \|\| salt[32] \|\| LE32(e) \|\| label[32]` | `05` | Low 10 bits of two bytes |

The full `H5` input is 162 bytes and takes two SHAKE256 absorption
permutations. The full challenge-3 input is 410 bytes
(`77 + 104 + 224 + 4 + 1` **[D]**). There is no `H3` call. The salt enters
challenge 1 and `H5` only: it does **not** enter `H4`, `H0`, the AES PRG or
the leaf-commitment computation, and neither `iv_pre` nor `mu` enters `H0` or
the leaf PRG. Putting any of them there would enlarge the context universe of
the global union bound of section 6.1.

**Leaf commitment.** For both rows:

```text
H0(PREFIX_R || iv[16] || 00)             = h0[96] || h1[32]
LeafPRG(node_key, iv, tweak; 144 bytes)  = sd[32] || b0[96] || b1[16]

c0 = ToBits768( ι(sd) · h0 + b0 )            in F_(2^768)
c1 = ToBits256( sd · h1 )[0..16]  XOR  b1    in F_(2^256)

leaf_commitment = c0[96] || c1[16]
```

- `c0` is the FAEST v3 leaf hash, unchanged; the injection `ι(sd)` is the
  byte string `sd[32] || zero[64]`.
- The second product is in
  `F_(2^256) = F_2[X]/(X^256 + X^10 + X^5 + X^2 + 1)`, the existing field.
  No new field is introduced.
- All encodings keep the existing convention: byte `i`, bit `j` represents
  `X^(8i + j)`. `[0..16]` therefore means the low 128 polynomial coordinates.
- The tweak is the existing one. The leaf expansion is nine AES blocks
  (144 bytes) instead of eight.
- Every hidden commitment in a proof carries both parts, and every
  reconstructed visible commitment recomputes both.

The review states that these operations match the field definitions and the
affine leaf hash of `crates/iroha_zkp_vole/src/field.rs` and
`universal_hash.rs`; not re-read by us for this purpose. Requesting more `H0`
output without using it in the commitment would not improve the bound of
section 6.1.

**Tape.** Each proof invocation obtains exactly 112 fresh bytes from the
caller's fallible cryptographic RNG:

```text
r      = tape[0..32]
iv_pre = tape[32..48]
pad    = tape[48..80]
salt   = tape[80..112]
```

- In the security model these are independent uniform coins, independent of
  the application witness, the public message and previous tapes.
- An entropy failure returns an error and produces no proof. There is no
  secret-derived, deterministic or zero-filled production fallback. Fixed tapes
  are permitted for reproducible tests.
- The raw pad is supplied only as witness bits `[0, 256)`. It then necessarily
  affects `d`, the pad Booleanity constraints, the masked response
  calculations and the downstream challenge hashes; those derived effects are
  not excluded. Pad packing is least-significant-bit first: witness
  coordinate `j` is
  `P_j = (tape[48 + floor(j/8)] >> (j mod 8)) & 1`, `0 ≤ j < 256`, as the
  review confirms.
- `r` feeds the ordinary backend root expansion and the existing high-mask
  expansion `PRG(r, iv, 2^31 − 1; n_mask · w_grind bits)`. The second use is
  already part of the backend's VOLE commitment (the review cites
  `crates/iroha_zkp_vole/src/vole.rs`), not an additional tape derivation.
- `iv = H4(iv_pre || mu)`, under the role prefix. `iv_pre` and `salt` are
  transmitted; `iv_pre` is hashed in `H4` and in the first challenge, `salt`
  in the first challenge and in every `H5` call of the proof. There is no
  separate hash of the tape, of the raw `r` or of the raw pad.
- Owned tape buffers, `r`, the pad and transient secret witness, VOLE, tree
  and hash material are erased on success, error and exhaustion, including
  temporary copies of the credential secret (not the wallet's retained
  credential). The public `iv_pre` and `salt` need not be erased from the
  returned proof; their copies inside the tape buffer are erased.

**Counter rule**, identical on both rows:

```text
M_ctr            = 1 << 20
allowed counters = 0x00000000 through 0x000fffff, inclusive
encoding         = four-byte little-endian u32
```

- The commitment, the corrections, the first two challenges and the response
  coefficients are computed once. The prover then tries the allowed counters
  in increasing order, computing the challenge-3 call of the table above for
  each. `ã_0` is hashed and is not serialised in the proof. An attempt is
  rejected unless its grinding suffix is zero and its canonical BAVC opening
  fits the row's threshold. The first success is returned.
- If all `2^20` attempts fail the prover returns
  `GrindingExhausted { last: 0x000fffff }`. It never wraps. A later
  invocation needs an entirely fresh 112-byte tape.
- The verifier rejects a proof whose counter exceeds `0x000fffff` **before
  any expensive reconstruction**. It then evaluates the supplied counter and
  opening once. It does not establish counter minimality and never replays
  earlier attempts.
- An authorization value is logged before it is exposed, also when proving
  then fails or exhausts its counter (sections 5.1, 6.2 and 6.8).

The arguments must analyse this exact fresh-randomness, incrementing-counter
prover. A verifier-only false-statement analysis may use the unchanged
acceptance predicate; the joint zero-knowledge argument must reproduce the
honest transcript and stopping distribution.

**Naked proof.** No header; exactly this field order:

| Field, in order | Fast, registration | Fast, vote | Small, registration | Small, vote |
| --- | ---: | ---: | ---: | ---: |
| `c_1, ..., c_(tau−1)` | 143,360 | 214,016 | 94,080 | 140,448 |
| `c_mult` | 880 | 880 | 870 | 870 |
| `ũ` | 128 | 128 | 128 | 128 |
| `d` | 4,480 | 6,688 | 4,480 | 6,688 |
| `ã_1, ..., ã_6` | 192 | 192 | 192 | 192 |
| Opening | 11,024 | 11,024 | 9,664 | 9,664 |
| `chall_3` | 32 | 32 | 32 | 32 |
| `iv_pre` | 16 | 16 | 16 | 16 |
| `salt` | 32 | 32 | 32 | 32 |
| `LE32(ctr)` | 4 | 4 | 4 | 4 |
| **Total bytes** | **160,148** | **233,012** | **109,498** | **158,074** |

The table is the review's; every entry and total is reproduced **[D]** from
`(tau − 1)·l/8`, `10·n_mult/8`, `4·lambda/8`, `l/8`, `6·lambda/8`,
`112·tau + 32·T_open`, 32, 16, 32 and 4 bytes, that is `12,308 + 33·l/8`
(fast) and `10,938 + 22·l/8` (small). The opening is:

```text
tau commitments of 112 bytes each, in increasing vector index
then the canonical sibling seeds, 32 bytes each
then zero padding to fill the T_open · 32-byte seed area
```

Its length is `112·tau + 32·T_open`. Nonzero padding is rejected.

| Proof | Witness bits | Constraints | Fast row, bytes | Small row, bytes |
| --- | ---: | ---: | ---: | ---: |
| Registration | 35,840 | 72,576 | 160,148 | 109,498 |
| Vote | 53,504 | 108,931 | 233,012 | 158,074 |

The fast-row vote proof leaves 29,132 bytes under the 262,144-byte envelope
cap. Carrying all fixed cryptographic fields `B`, `scope`, `R`, `S`, `nf`,
`auth_v`, `vote`, `policy_hash` and `P16` adds 467 bytes, leaving 28,665
bytes for other envelope fields, stamp and framing (both differences
recomputed **[D]**). The construction is size-compatible with the cap.
**Actual complete-envelope compliance is unqualified because the production
schema is not frozen**; no exact framed size is reported before that schema
exists. The list remains shared seal data: `128·S` raw bytes once per body,
not inside every ballot. The public `auth` adds 64 bytes to the registration
statement.

Changes considered by the review and not adopted: widening the 64-bit
evaluation points (unnecessary at these dimensions, section 3); a backend
degree below seven (section 4); direct domain-separated hash commitments to
leaf seeds, root tags or other extraction commitments (section 10); a public
salt in the credential commitment (it establishes neither knowledge nor
non-malleability, and a conventional salt would cross the 136-byte rate and
add a permutation); the salt, `iv_pre` or `mu` in `H0` or the leaf PRG; an
abort on repeated IVs and an unsalted `H5` with an IV-multiplicity analysis
(section 6.5.1); a 512-bit nullifier (section 8.2); moving or lengthening the
secret inside the credential functions (section 6.5.3); a `lambda = 384`
backend to compensate for the comparison bound of section 8.3.

## 2. Encoding equivalence

Status: complete (awaiting review). The review's proof covers the commitment
and nullifier permutations and the selector. The pad, the registration
authorization permutation, the vote authorization permutation and the
1,024-bit nullifier output are covered by the same steps; that extension is
the implementers' and is marked **[D]** at each place. No text of the
review restates the proof for the third vote permutation; its soundness
argument uses the equivalence as a premise (section 6.1).

> **Claim.** For every publicly valid instance, the ordered constraint system
> of section 1.5 vanishes on an extended witness in `K^l` if and only if that
> witness consists of Boolean coordinates that encode a valid relation witness,
> its specified intermediate states and an arbitrary Boolean pad.

The claim is deterministic. It needs no collision-resistance, random-oracle,
PRF or secret-entropy assumption.

**Forward.** Take a valid `sk`, for voting a valid position `i < S`, and any
pad in `{0,1}^256`. Compute the padded initial states and the actual Keccak
executions and insert the states after 2, 4, ..., 22 rounds. Set
`a_floor(i/32) = 1`, `b_(i mod 32) = 1` and every other selector coordinate to
zero.

1. Every coordinate is Boolean, so (10) holds, for the pad as well **[D]**.
2. (1) holds by construction, for each permutation, the vote authorization
   permutation included **[D]**.
3. Each selector vector has one active entry, so (4) and (5) hold.
4. Exactly one pair product is one and its index is below `S`, so (6) holds.
5. The multiplexer equals `C_i`; the hash equalities of the relation give (7)
   and (8), for all 1,024 output bits of (8) **[D]**, and (9) **[D]**; for
   registration they give (2) and (3), **[D]** for (3).

**Reverse.** Suppose every constraint vanishes for `w ∈ K^l`.

1. *Booleanity.* `K` is a field, so `w_i·(w_i + 1) = 0` implies
   `w_i ∈ {0, 1}`. This applies to every coordinate: pad, secret, committed
   state bits and selectors. The pad occurs in no other constraint, so it is an
   arbitrary Boolean string and is projected away **[D]**.
2. *Keccak.* `A_D^(0)` is fixed by the public bytes and the shared secret
   coordinates `[256, 640)`. Induction over `g = 1, ..., 11` in (1) forces
   every committed state to equal the actual state after `2g` rounds, so `O_D`
   is the actual final state and its leading bits are exactly the required
   SHAKE output. The same induction applies to each authorization
   permutation, whose only differences are the public bytes: `PAU1` and
   `D_reg`, or `PAV1` and `D_v` **[D]**. `D_v` is a public value recomputed
   by validation, so the initial state of `V` is fixed by public bytes and
   the secret exactly as for the other permutations **[D]**.
3. *One-hot selectors.* Let `x` be either selector vector. Its sum constraint
   excludes the all-zero vector. If it had at least two ones, let `j` be the
   position of its second one; exactly one earlier coordinate is one, so
   `x_j · sum_{k<j} x_k = 1·1 = 1`, contradicting (4). Hence `x` has exactly one
   one. The argument is valid in characteristic two: it does not infer
   one-hotness from odd parity.
4. *Range.* Let the active positions be `r` and `c`. Every product
   `a_r'·b_c'` is zero except `a_r·b_c = 1`, so `sum_{i<S} p_i` is 1 if
   `32r + c < S` and 0 otherwise. (6) forces a real list position
   `i = 32r + c < S`.
5. *Outputs.* (7) equates the commitment output to exactly `C_i`, (8) the
   1,024-bit nullifier output to `nf` and (9) the vote authorization output
   to `auth_v` **[D]** for (9) and for the upper 512 bits of (8); for
   registration (2) gives `C = Com_B(sk)` and (3) gives
   `auth = Auth_(D_reg)(sk)` **[D]** for (3).

All permutations of a relation read the same 384 secret coordinates; there is
no independently chosen nullifier or authorization secret. Through (11) this
gives the implication used in section 4:

```text
every top coefficient Z is 0  ⇒  a Boolean valid witness exists         (12)
```

The implication needs the wrapper's Booleanity constraints: effective
witnesses in the soundness analysis lie in the extension field, not
necessarily in `{0,1}^l`. The AES key-validity restriction of plain FAEST is
unnecessary for (12); its separate role in FAEST's false-key argument is a
different matter (section 7).

## 3. Universal-hash bounds for the larger relations

Status: complete (awaiting review). These are derivations by polynomial root
counting written by the review. They extend the calculations inside the proofs
of FAEST v3 Lemmas 4.6 and 4.7; they are **not** applications of those lemmas,
whose stated length hypotheses fail at these dimensions.

Both experiments let an arbitrary nonzero input vector be fixed **before** the
hash seed is sampled, with no random-oracle access: the seed components are
independently uniform field elements or uniform strings of the stated length.
The ordering is essential.

### 3.1 VOLEHash

```text
l' = l + d_zk - 1 = l + 6,        n = l' - 1 = l + 5
```

The polynomial input has `l` witness coordinates and six full-field mask
coordinates; four further field coordinates are additive masks, so the hash
receives `l + 10` field coordinates. Neither `l + 6·lambda` nor the PRG
expansion length `l^` (section 6.5.1) is the polynomial length.

Let `P ≠ 0` be the polynomial of the first `l'` coordinates, `deg P ≤ n`.
Sample independent uniform `r_0, ..., r_3, s_0, ..., s_3 ∈ K` and `s_4` uniform
in the `2^64`-element subset obtained by zero-padding a 64-bit polynomial-basis
representation. Only the subset's cardinality is used; it need not be a
subfield. Before the additive masks the outputs are

```text
h_i = r_i · P(s_0) + P(s_(i+1)),     0 ≤ i < 4
```

Fix any target `v ∈ K^4`.

- If `P(s_0) ≠ 0`, each equation `h_i = v_i` determines exactly one `r_i`: the
  conditional probability is `2^(-4·lambda)`.
- If `P(s_0) = 0`, then `P` is nonconstant (a nonzero constant cannot enter
  this case). The event has probability at most `n / 2^lambda`. Each of the
  next three full-field evaluations hits its target with probability at most
  `n / 2^lambda`, and the short evaluation with probability at most
  `n / 2^64`. Independence permits multiplication.

```text
eps_v ≤ 2^(-4·lambda) · (1 + (l' - 1)^5 / 2^64)                         (13)
```

For an input with zero polynomial part and nonzero additive part a zero hash
is impossible; otherwise the additive part only specifies a target for the
calculation above. This is almost universality. Uniform independent additive
masks also give the hash's hiding property directly.

### 3.2 ZKHash

The polynomial part has `M` coordinates, so its degree is at most `M - 1`.
For a nonzero such `P`, the two independent evaluations `P(s)`, `P(t)`, with
`s` uniform in `K` and `t` uniform in the short subset, vanish together with
probability at most `(M - 1)^2 / 2^(lambda + 64)`. Outside that event,
multiplication by the independently uniform row `(r_0, r_1)` gives a uniform
field element. Accounting for the final additive coordinate:

```text
eps_zk ≤ 2^(-lambda) · (1 + (M - 1)^2 / 2^64)                           (14)
```

The form with `M^2`, which uses the conservative degree bound `M`, is valid
but slightly loose; (14) is the form to record. The independent final
additive coordinate gives perfect hiding at any vector length. Hash hiding
alone is not protocol zero knowledge.

### 3.3 Substitutions at the final dimensions

Every value is recomputed **[D]** from (13) and (14) with the inputs shown.
The registration values equal those the review gave for that relation. For
the vote relation the review gives the two quantities of section 4 that
follow from this table (the first-round bound and the ZKHash factor); they
are reproduced there.

| Quantity | Registration | Vote |
| --- | ---: | ---: |
| `l` | 35,840 | 53,504 |
| `l' = l + 6` | 35,846 | 53,510 |
| `n = l + 5` | 35,845 | 53,509 |
| `M` | 72,576 | 108,931 |
| `1 + n^5 / 2^64` | 3208.917576670 | 23781.142421080 |
| `log2` of the bound (13) | −1012.352129 | −1009.462470 |
| `(M - 1)^2 / 2^64` | 2.8553172332 × 10^-10 | 6.4324331994 × 10^-10 |

Both hash bounds are independent of the parameter row; the row enters in
section 4 through the size of the challenge set.

**Neither 64-bit evaluation point needs widening.** The challenge lengths stay
`|chall_1| = 8·lambda + 64 = 2,112` and `|chall_2| = 3·lambda + 64 = 832` bits
with the existing short-point injection. Widening to `b` bits would replace
`2^64` by `2^b` in (13) and (14), change the challenge lengths to
`8·lambda + b` and `3·lambda + b`, and require matching changes to parsing,
zero-padding, the descriptor and the transcript definitions: a distinct
protocol variant, not a way to satisfy the old lemmas' literal hypotheses.

## 4. Soundness for false instances in the response-graph experiment

Status: complete (awaiting review), for exactly the statement below.

**Experiment.** Fix a publicly valid false instance `x ∉ L_R`. An arbitrary,
possibly computationally unbounded prover first fixes a partial response
function

```text
g : D_Δ → K^(l+10) ∪ {⊥},      |D_Δ| = 2^(lambda - w_grind)
```

(`2^248` on the fast row; `2^250` on the small row **[D]**). The verifier then
supplies the three challenges independently and in order; the prover may adapt
each intervening message to the preceding challenges. The prover wins if the
verifier accepts.

**First challenge.** Let `𝒮 = {(Δ, g(Δ)) : g(Δ) ≠ ⊥}`. For three noncollinear
points with distinct first coordinates, their images under
`(Δ, q) ↦ (Δ, H·q)` become collinear only if `H` annihilates the fixed nonzero
vector

```text
(Δ_1 - Δ_0)·(q_2 - q_0) - (Δ_2 - Δ_0)·(q_1 - q_0)
```

which (13) bounds by `eps_v`. A union over triples gives the first bad event
(the review's `eps_KOS`):

```text
eps_1 ≤ eps_v · binom(|D_Δ|, 3)                                         (15)
```

There is no pair with the same `Δ` and different responses, because `𝒮` is a
graph. Outside the bad event all responses that pass the consistency equation
`H·q = D_msg + Δ·ũ` lie on one affine line.

**Extraction map.**

- Empty passing set: choose any line.
- One point `(Δ, q)`: `u* = 0`, `v* = q`.
- At least two points: `u* = (q_1 - q_0)/(Δ_1 - Δ_0)`, `v* = q_0 - Δ_0·u*`. A
  passing third point off this line would be an excluded bad triple.

The map can require exhaustive access to the graph. **It is not an efficient
knowledge extractor**, and none is needed for a false instance.

**Effective witness.** Split the line into witness and mask coordinates. The
effective witness is `w* = d + u* ∈ K^l` with commitments
`ρ_i(X) = V_i* + w_i*·X`. Applying the ordered constraint system and (11)
gives `sum_{j=0}^{6} A_j·X^j + Z·X^7`. By (12), `Z = 0` would make `w*` a
Boolean valid witness for `x` (its pad coordinates included and then
discarded). The instance is false, so `Z ≠ 0`. This replaces the AES-specific
relation step of the original argument and needs no key-validity restriction.

**Second challenge.** `Z` is fixed before it, so
`ζ = ZKHash(chall_2, (Z, 0))` vanishes with probability at most

```text
eps_2 ≤ eps_zk                                                          (16)
```

The six QuickSilver mask correlations contribute
`M_mask(X) = sum_{j=0}^{5} (v̄_j* + ū_j*·X)·X^j = sum_{j=0}^{6} p_j·X^j` and no
degree-seven coefficient. With `a_j = ZKHash(chall_2, (A_j, p_j))`, linearity
gives, for a passing response on the extracted line,
`q̃ = sum_{j=0}^{6} a_j·Δ^j + ζ·Δ^7`.

**Third challenge.** Before it the prover fixes its claimed coefficients
`ã_0, ..., ã_6`. Outside the second bad event, acceptance requires

```text
E(Δ) = 0,     E(X) = sum_{j=0}^{6} (ã_j - a_j)·X^j - ζ·X^7              (17)
```

a nonzero polynomial of degree exactly seven. The raw third challenge is
uniform over `2^256` strings; a nonzero grinding suffix rejects, and the
remaining strings map injectively to `D_Δ`. At most seven raw strings reach
roots of (17):

```text
eps_3 ≤ 7 · 2^-256                                                      (18)
```

The fourth, dummy challenge contributes zero.

**Conclusion.** Define a flag that is set at any of the three bad events and
stays set. An accepted false-instance transcript with the flag clear would lie
on the extracted line, have `ζ ≠ 0` and satisfy (17), contradicting the
absence of the third event.

**The three lowest unmasked coefficients are identically zero.** Distinguish
the unmasked constraint coefficients `A_j` from the masked responses `ã_j`.
Every homogenised constraint is divisible by `X^3` (the assigned degrees
are at most four, so (11) multiplies by at least `X^3` **[D]**). Hence

```text
A_0 = A_1 = A_2 = 0,
ã_0 = v̄_0,     ã_1 = ū_0 + v̄_1,     ã_2 = ū_1 + v̄_2
```

for an honest prover. Nothing changes:

- *Soundness.* The degree-seven error polynomial (17) and the root bound (18)
  are kept. Dishonest claimed coefficients and the mask polynomial need not
  be divisible by `X^3`; the observation does not reduce (17) to degree four.
- *Simulator.* Six transmitted coefficients are still sampled and `ã_0` is
  still reconstructed; the mask-to-response map remains invertible
  (section 6.5.1).
- *Parameter choice.* Seven is the frozen backend degree, not the minimum
  native degree of these circuits. Reducing it changes the masks, the
  corrections, the descriptor, the transcript and the proof lengths: a
  different, unvalidated protocol. All ten masks, all six transmitted
  coefficients, their hashing and their serialisation are kept.

Round errors, all recomputed **[D]** from (13) to (18) with `|D_Δ| = 2^248`
(fast) and `2^250` (small). For the vote relation the review gives
`log2 eps_KOS = −268.047432` (fast) and `−262.047432` (small) and the ZKHash
factor `1 + 6.4324332 × 10^-10`; the table reproduces them.

| Core round | Fast, registration | Fast, vote | Small, registration | Small, vote |
| --- | ---: | ---: | ---: | ---: |
| 1: `log2` of the bound (15) | −270.937091 | −268.047432 | −264.937091 | −262.047432 |
| 2: bound ÷ `2^-256` | 1 + 2.8553 × 10^-10 | 1 + 6.4324 × 10^-10 | the same | the same |
| 3: bound | `7 · 2^-256` | `7 · 2^-256` | `7 · 2^-256` | `7 · 2^-256` |
| 4 | 0 | 0 | 0 | 0 |

Round 1 uses `eps_1 < (1 + (l + 5)^5 / 2^64) / 6 · 2^-280` on the fast row and
`· 2^-274` on the small row. On both rows the **core maximum round error** is

```text
eps_core,rbr ≤ 7 · 2^-256 = 2^-253.192645                               (19)
```

This is not conditioned on a successful grinding suffix or an admissible
opening. Conditioned on admissibility the root-count bound is only

```text
Pr[ root | chall_3 ∈ Ω ] ≤ 7 / |Ω|
```

and under the grinding condition alone it is `7 / 2^248` (fast). A reduction
cannot program an admissible challenge and keep the unconditioned denominator
without accounting for the change. For a raw uniform challenge the opening
threshold can only remove accepting strings, so it does not worsen (18).

**The leaf round and the other rounds of the expanded protocol.** The
expanded interactive representation has seven challenge rounds:

| Round | −3 | −2 | −1 | 0 | 1 | 2 | 3 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Challenge | `iv` | the leaf-hash key `(h0, h1)` | the `tau` inner `H1` digests | `com` | `chall_1` | `chall_2` | `chall_3` |

The `mu` call is an additional statement-binding node. The `tau` inner `H1`
calls constitute one vector challenge; they are not `tau` independent
algebraic rounds. Rounds −3, −1 and 0 have error zero. The leaf round has the
pointwise bound, for an IV fixed **before** the random leaf-hash key,

```text
eps_-2 ≤ tau · binom(2^256, 2) · 2^-896 = (tau/2) · (1 − 2^-256) · 2^-384   (20)
```

because two distinct induced seeds give equal 112-byte leaf commitments with
probability at most `2^-896` (section 6.1). For the fast row this is the
review's `(33/2)·(1 − 2^-256)·2^-384`; the small-row value has `tau = 22`
**[D]**. The structural assumptions are the leaf construction of
section 1.7, the specified CRT maps and their injectivity. On the fast row
there are 17 eight-bit and 16 seven-bit small-VOLE challenges, 248 bits and
6,400 leaves, and the elementary parameter conditions hold: `tau > 1`,
`3 × 128 > 2`, `(tau + 1)·2^8 = 8,704 < 2^31`. These checks certify no
implementation of those maps. With (20) far below it, (19) is the maximum
over all seven rounds **[D]**.

Sum of the seven interactive challenge errors for one execution:

```text
fast:   eps_run ≤ [8 + (1 + (l+5)^5/2^64)/(6·2^24) + (M-1)^2/2^64] · 2^-256 + eps_-2   (21)
small:  eps_run ≤ [8 + (1 + (l+5)^5/2^64)/(6·2^18) + (M-1)^2/2^64] · 2^-256 + eps_-2
```

| Coefficient of `2^-256` | Registration | Vote |
| --- | ---: | ---: |
| Fast row | 8.00003187801758 | 8.00023624506764 |
| Small row | 8.00204017513642 | 8.01511964380443 |

All four are **[D]**; `eps_-2` adds less than `2^-379` to each.

**What this is not.**

- It is not an efficient knowledge extractor. The extraction map is
  mathematical and may inspect the whole response graph.
- It is not the Fiat–Shamir game and not an adaptive statement. It is the
  response-graph experiment that underlies the algebraic argument, for one
  fixed false instance. Property 1 needs the adaptive Fiat–Shamir statement
  with both honest proof interfaces (section 6.1), where the use of (20)
  under adaptive choice of the IV is exactly the point that needs care.
- It is not a lifetime ledger. For a separately justified collection of at
  most `2^44` fresh interactive executions, even with adaptation between
  executions, the union bound from (21) for the vote relation is about
  `2^-208.99996` on the fast row (the review's value, reproduced **[D]**),
  below `2^-128`. That is an interactive component calculation: the
  honest-transcript ceiling does not bound adversarial Fiat–Shamir queries or
  retries, the calculation does not replace the adaptive Fiat–Shamir
  analysis, and it is not added to the bound of section 6.1.
- It is not an authorization argument. A list that contains adversarial
  credentials need not become a false statement when an honest entry is
  replaced; authorization is the subject of sections 6.2 and 6.8.

## 5. Oracle environment and games

### 5.1 Common environment

Distinctions that every argument below keeps:

1. **Constraint correctness** is the deterministic statement of section 2. It
   needs no assumption that credential SHAKE behaves as a random oracle.
2. **Backend QROM arguments** model the designated transcript and commitment
   hashes as quantum-accessible random oracles and require the specified
   quantum PRG and commitment assumptions.
3. **Credential hiding, decorrelation, uniqueness and authorization
   prediction** require the separate assumptions `P` and `U` about the
   concrete commitment, nullifier and authorization functions, including
   their joint use under one secret (section 8.4).
4. An argument that programs an abstract credential oracle must explain its
   consistency with the fixed Keccak circuit being proved. Changing the oracle
   does not change the circuit's accepted relation (section 6.5.3).

The adversary is a resource-bounded quantum algorithm with coherent access to
every explicitly modelled public oracle. Initial quantum advice is independent
of fresh honest secrets and of the sampled random oracles; oracle-dependent
preprocessing is charged to the query budget. Honest proof-generation,
registration, corruption and submission queries are classical and atomic:
adversarial oracle queries may occur before, between and after requests, not
during one. Superposition access to an honest prover is a stronger game and is
not claimed.

APIs, with classical requests and replies:

1. `NewHonest(B)` samples a fresh 384-bit secret, records a handle `j` and its
   original body, and publishes its commitment **before registration**.
2. `RegisterMalicious` accepts arbitrary canonical commitment and proof
   submissions and applies the actual verification and admission policy. It
   never demands disclosure of a malicious registrant's secret. Malicious
   provers and verifiers execute ordinary public algorithms; the challenger
   does not simulate their computations or presume that their witnesses
   exist.
3. `Seal` creates an admissible, authenticated, immutable list from the
   registration state.
4. `RegProof(j, request)` applies the honest authorization policy, computes
   the registration authorization value, logs the complete authorized public
   input and its authorization digest, and returns a fresh honest proof or
   exhaustion.
5. `VoteProof(j, request)` checks eligibility and list membership, computes
   the nullifier and the vote authorization value, logs the complete
   authorized statement and its authorization digest, records the identified
   exposure of the nullifier, and returns a fresh honest proof or exhaustion.
6. `Corrupt(j)` releases that credential's secret, subject to the exclusions
   of the particular game.

- **Logging rule.** For each honest handle `j` the challenger keeps
  `RegLog[j]` and `VoteLog[j]`, the complete authorized statements, and
  `AuthLog[j]` and `VoteAuthLog[j]`, their authorization digests `D_reg` and
  `D_v`. An authorization is recorded **before the authorization value is
  exposed**, including when proving fails or exhausts its counter. An aborted
  request must not expose an unlogged authorization value.
- The deployed honest policy uses a handle only in its original body. Letting
  a handle's proof oracle serve further bodies is a stronger game and must be
  stated separately.
- Logs store complete encodings, not hashes or proof bytes. Repeated proof
  generation counts toward the transcript budget; retransmission does not.
- A proof-security game does not hide a cryptographic forgery merely because
  duplicate rejection would prevent its admission afterwards.
- A stronger variant lets arbitrary canonical malicious entries enter sealed
  lists directly. Security there would cover the accepted-registration
  setting; it is not silently assumed.
- Advantages are deployment-wide unless described as single-output, and the
  reduction overhead is included in each query budget.

**The common credential experiment.** The credential-side premises
(assumption `P`, the prediction games and the privacy game) are restrictions
of one experiment, so that they do not use subtly different oracle
environments. Distinguishing advantages are output-probability gaps: a gap
`ε` corresponds to optimal challenge-bit guessing probability `1/2 + ε/2`.
Authorization and soundness bounds are winning probabilities.

- A resource vector `ℛ` records adversarial computation, preprocessing,
  primitive evaluations, application requests, proof simulation,
  verification, final comparisons, memory and gate costs. Public computation
  of SHAKE256, SHA3-512, Keccak-f and its inverse is permitted, including
  coherent computation. Application requests are classical and atomic.
  Backend oracle access follows the backend QROM model.
- The experiment initially samples `U` **distinct** uniform secrets; handles
  are revealed adaptively. Presampling avoids programming a new hidden row
  into an already queried ideal oracle later. Deployment samples
  independently; the two samplings are coupled except with probability

  ```text
  ρ_rep = binom(U, 2) · 2^-384 < 2^-317                                 (22)
  ```

  (the review's `ρ`). A repetition matters: corrupting one handle would
  disclose another handle's secret.
- Both honest proof interfaces use one persistent, witness-free, total
  simulator `Sim+` (section 6.5.2) with shared backend-oracle state. It
  receives the role and the public statement only. Its runtime, programming,
  exhaustion behaviour and subsequent oracle effects belong to `ℛ`. It must
  execute on every syntactically valid public statement of the appropriate
  dimensions, including false intermediate statements. That is algorithmic
  totality, not a claim of zero knowledge for false statements.

| Interface | Information or action |
| --- | --- |
| `NewHonest(B)` | Reveals a new handle and its **concrete** commitment `Com_B(s_j)` |
| Registration authorization and proof requests | Reveal concrete `Auth_d(s_j)`, complete public statements and simulator responses |
| Identified nullifier and vote requests | Reveal concrete nullifiers and concrete `AuthV_d(s_j)`, including authorizations at other scopes and other statements |
| Raw authorization queries | May additionally expose either authorization family on arbitrary 64-byte digests. They strengthen the assumption beyond application-only access |
| Malicious registration, sealing and submission | Execute the actual public validation, verification and admission rules. No malicious opening is assumed known |
| `Corrupt(j)` | Reveals `s_j`, unless the handle has been protected |
| Public computation | All permitted concrete quantum computation and backend oracle access |

Raw output queries have an explicit resource budget; they are not an
unlimited free interface. Every indirect disclosure counts as exposure of the
corresponding function entry.

The experiment maintains three sets:

```text
Protected ⊆ { handles },        Exposed, Tested ⊆ { (j, t, x) }
```

with `t` a function tag and `x` its 64-byte argument. `Reserve(j)` requires
an honest uncorrupted handle and permanently prevents its corruption. For
`t ∈ {PNF1, PAU1, PAV1}` and a hidden bit `b`,

```text
Test_b(j, t, x) = f_t(s_j, x)     if b = 0
                  F_j,t(x)        if b = 1                              (23)
```

where `f_PNF1 = Tag`, `f_PAU1 = Auth`, `f_PAV1 = AuthV` and the `F_j,t` are
independent random functions with the corresponding output lengths. A first
test reserves the handle and requires that exact entry never to have been
exposed concretely. Repeated tests return the same value. Later concrete
disclosure of a tested entry is forbidden. All other entries remain concrete.
**Commitments are never randomized.** Assumption `P` (section 8.4) bounds the
distinguishing gap `α_P(ℛ)` of this experiment.

### 5.2 Games

**Property 1: adaptive relation soundness.** The review's decision replaces
item 1 of the gate (ballot design section 5) by the following text. **This
weakens property 1 from knowledge extraction to soundness.** It is not an
equivalent reformulation of knowledge soundness.

> **1. Adaptive relation soundness.** In the common adaptive quantum-oracle
> environment, with authenticated public contexts, malicious registrations,
> permitted corruptions and both honest proof interfaces available, every
> accepted fresh registration or ballot statement belongs to its specified
> language, except with the deployment-wide error bounded under item 6. A
> registration has a secret that opens its commitment and produces its
> registration authorization value. A ballot has a secret and exactly one
> selector position below `S` such that the selected entry of the
> authenticated sealed list is that secret's commitment, and the stated
> nullifier and vote authorization value are the specified functions of that
> same secret. Public validation enforces the permitted choice and complete
> statement encoding and binding. This is an existence requirement: it
> requires neither efficient witness extraction nor knowledge of the secret
> by the submitter. Exact-statement relaying, replay and proof
> rerandomization remain permitted, subject to admission and duplicate
> checks.

The game runs the common environment. The adversary chooses the role and the
statement adaptively and outputs `(R, x, π)`. It must hold that

```text
Pr[ V_R(x, π) = 1  ∧  x ∉ L_R ] ≤ ε_snd,mix                             (24)
```

No freshness condition is needed: honestly issued statements are true.
Malformed or publicly invalid statements are rejected. In the batch game the
output contains at most 1,001 triples `(R_i, x_i, π_i)`, and

```text
Pr[ ∃ i :  V_(R_i)(x_i, π_i) = 1  ∧  x_i ∉ L_(R_i) ] ≤ ε_snd,batch      (25)
```

What the owner gives up. The system no longer promises an efficient procedure
that recovers a credential from an adversary producing a fresh valid proof.
The definition therefore permits:

- a party to produce a proof of a true statement without knowing its witness;
- an adversarial registrant to establish a credential whose opening exists
  but which it cannot subsequently use;
- proof transformations that preserve an already authorized complete
  statement;
- future protocols to fail if they silently treat a ballot or registration
  proof as proof of possession, extractable knowledge or a
  simulation-extractable credential. This is the material composability
  limitation: a later protocol that requires knowledge must prove its own
  theorem or change the construction.

These permissions do not authorize a fresh honest vote if property 2 holds,
do not increase the coalition's seat allowance if property 3 holds, and do
not permit registration recontextualization if property 8 holds. They provide
no general non-malleability or universal-composability claim. Anyone may
still relay an already authorized ballot, including delivering it before its
creator does; the signerless design already permitted that. Unforgeability
therefore means **no unauthorized fresh message**, not exclusive control over
delivery. Censorship, credential disclosure and knowingly authorizing
conflicting choices keep their existing limitations.

The wording changes the review requires for the other items of the gate:

| Item | Required change |
| --- | --- |
| 2 | Keep chosen-message unforgeability; explicitly include `auth_v` in the complete authorized statement |
| 3 | Define `k` as the number of adversarially registered or corrupted sealed entries, including entries whose registrant knows no opening. Replace the extraction-based argument with the counting argument of section 6.3 |
| 4 | Keep both endpoints. Update the public auxiliary information and the unlinkability argument to include `auth_v` |
| 5 | Preserve the full arbitrary-witness joint zero-knowledge requirement. Include both authorization families in the correlated-output privacy games |
| 6 | Remove the requirement to account for an extractor that is no longer required. Account for all actual proving, simulation, verification and reduction overhead. Keep the numerical contract unchanged |
| 7 | No security-property change; update dimensions and resource accounting |
| 8 | Keep the endpoint and the event-split argument. Remove statements saying that item 1 retains a separate knowledge obligation |

The privacy functionality must simulate `auth_v` consistently with
complete-statement and nullifier equality.

**Property 2: target-origin chosen-message unforgeability.** Run the common
environment with malicious registrations, mixed lists, both honest proof
oracles and adaptive corruption. The adversary outputs `(j, x*, π*)` for a
vote and wins exactly when

```text
V_vote(x*, π*) = 1,
j is uncorrupted through the final output,
Com_(B*)(sk_j) ∈ L*,
nf* = Tag_(scope*)(sk_j),
x* ∉ VoteLog[j]                                                         (26)
```

- The complete authorized statement `x*` includes `auth_v*`. Freshness is
  per target handle: a statement honestly issued for another handle is not in
  `VoteLog[j]` (the event `CrossIssued_2` of section 6.2).
- This includes changing the vote, the policy or another bound field under an
  observed honest nullifier, and excludes exact-statement replay and
  rerandomization.
- A mixed-list ballot whose nullifier belongs to no honest target is not
  automatically a forgery: it may be a legitimate adversarial member's
  ballot. Unexplained additional nullifiers are the subject of properties 1
  and 3.
- No game defines winning by the unobservable phrase "the adversary does not
  know the key".

**Property 3: nullifier uniqueness.** Fix an authenticated seal `(B, L, S)`
and its scope; the adversary has the entire preceding adaptive registration
and proof history. Partition the sealed entries into honest entries whose
secrets remain uncorrupted through the adversary's output, and the rest. `k`
is the number of **adversarially registered or corrupted sealed entries**; an
adversarial registration counts in it even if the registering party knows no
opening. `H` is the set of nullifiers returned by honest ballot-proof queries
for this seal and scope, including nullifiers whose authorizations were
disclosed by a request whose proving then failed or exhausted its counter.
The adversary wins if it supplies cryptographically
accepted ballots with more than `k` distinct nullifiers outside `H`. Exact
replay or rerandomization under an existing nullifier does not increase the
count. An adversary's retained output collection has at most `k + 1` ballots,
so at most **1,001**: `k = S = 1,000` is allowed.

**Property 4: cross-scope unlinkability.** The adversary sees the honest
commitments and the registration mapping, makes adaptive registration and
ballot-proof queries, registers malicious credentials and corrupts
non-challenge credentials. It names two eligible, uncorrupted honest
credentials `sk_0`, `sk_1` and two distinct scopes `x`, `y`. It obtains an
identified reference for `sk_0` at `x`. At `y` it receives a challenge
ballot from `sk_b` for a hidden bit `b`, and it distinguishes whether the
reference and the challenge use the same credential.

- This game is a restriction of the anonymity environment of property 5
  below; all restrictions of that environment apply at `y`. A
  deployment-wide anonymity bound therefore also bounds this game, with no
  additional lifetime multiplier.
- `Δ_link = | Pr[A outputs 1 | b = 0] − Pr[A outputs 1 | b = 1] |`.
- Excluded: identification from a distinctive vote, transport identity,
  timing, an anonymity set reduced to one by public information, or later
  secret disclosure. The construction deliberately permits retrospective
  linkage after the secret is disclosed. Those exclusions are substantive
  parts of the statement.
- The public auxiliary information includes the vote authorization values
  of identified ballots and of the challenge ballot. The admissibility rules
  of the anonymity environment cover them.

**Property 4: non-frameability.** The literal statement "nobody can produce a
valid proof under another participant's entry" is false, because published
proofs can be copied; the claim concerns fresh authorization. A *vote frame*
is an accepted ballot with `nf = Tag_scope(sk_j)` for an uncorrupted honest
credential `j` whose honest prover never authorized the complete statement.
A *registration frame* is a win in the property 8 game. Exact-statement replay
and rerandomization are excluded.

**Property 5: joint zero knowledge.** The target is standard adaptive
multi-theorem joint zero knowledge for **arbitrary application witnesses and
arbitrary auxiliary information about those witnesses**, not an
honest-key-only simulation game. It covers both relations of section 1.

Fix the descriptor, both semantic relations, the public-validation rules and
the oracle interfaces of section 1 and profile record section 6.

1. Choose one global bit `b`. Initialize the public quantum-accessible oracle
   environment. In the simulated world, initialize **one stateful simulator
   for the entire execution**, covering both roles and every credential.
2. Give the adversary arbitrary quantum auxiliary information about
   application witnesses and statements. This information may contain complete
   secrets, membership indices and deterministic application traces. Initial
   advice is independent of the freshly sampled oracles and proving coins;
   oracle-dependent preprocessing counts against the query budget.
3. Permit adaptive **classical** requests `Prove(role, x, w_app)`, with
   `w_app = sk` for registration and `w_app = (sk, i)` for voting. The
   adversary may choose the witnesses, repeat statements, reuse witnesses and
   alternate roles.
4. In both worlds, apply identical public validation and check
   `R_role(x; w_app)`. Invalid requests return the same prescribed error
   without invoking the simulator. The adversary supplies the complete
   statement; the challenger checks it rather than silently repairing its
   authorization value, nullifier or other fields.
5. For a valid request, respond as follows.
   - **Real:** obtain an independent uniform 112-byte tape, construct the
     padded extended witness and run the exact prover, including the
     incrementing counter and the exhaustion outcome.
   - **Simulated:** invoke `Sim+(role, x)` of section 6.5.2. The simulator
     receives neither the application witness, the selected index, the
     trace, the pad, nor the adversary's private auxiliary state. Return its proof or exhaustion
     outcome.
6. The simulator may program only the designated backend oracle domains. It
   cannot alter credential functions, public statements, authoritative context
   or application authentication decisions.
7. The adversary may interleave requests with quantum oracle queries,
   verification, malicious registrations and other application operations. It
   may retain, disclose and use application witnesses at any time. There is
   **no tape-selection or secret-coins-disclosure interface**. The transmitted
   `iv_pre` and `salt` are public and are expressly permitted.
8. After the final proof request, continue allowing quantum oracle access
   until the adversary outputs a bit. Define

   ```text
   Adv_JZK = | Pr[A → 1 | b = 0] − Pr[A → 1 | b = 1] |
   ```

   Count preprocessing, interleaved queries and subsequent queries. Apply the
   recorded lifetime ceilings, including repeated proof generation: at most
   `2^10` fresh transcripts per credential and `2^44` in total.

Clarifications:

- "Identical public-input rules" does not mean that the adaptive executions
  remain identical after different replies.
- `T` counts all valid proving invocations across both roles, including
  invocations that return exhaustion.
- This game imposes no hidden-honest-key requirement. The separate anonymity
  game keeps its challenge-secret disclosure exclusions. Simulator totality on
  syntactically valid **false** statements is an additional interface
  requirement of the credential-side arguments (section 6.5.2); the joint
  zero-knowledge experiment invokes simulation only for valid witnessed
  statements.

A prover that accepts an adversarially fixed or disclosed tape or pad is a
different algorithm, to which the target theorem is not claimed to apply.

**Property 5: anonymity.** A separate left/right game, because a
zero-knowledge proof can coexist with publicly identifying statement values.
The environment is the common credential experiment of section 5.1 with one
further interface, `LR(j_0, j_1, z)`, for one persistent hidden bit `b`; `z`
contains every public vote field other than the nullifier and the vote
authorization value. A scope means its exact 64-byte value, not a proposal's
informal identifier. The reply is the nullifier `n_t` of handle `j_b` at the
scope `σ_t`, the vote authorization value of `j_b` at the digest
`d_t = D_v(z_t, n_t)` and the corresponding proof.

An `LR` request `t` is admitted only if all of the following hold.

1. Both handles are honest, uncorrupted, in their original common body and
   in the same authenticated sealed list.
2. Neither candidate credential and scope pair has a previous identified
   nullifier exposure.
3. Both handles become protected; both candidate scope pairs become blocked
   against identified disclosure.
4. Across challenge requests the nullifier equality partitions agree: for
   every earlier request `r`,

   ```text
   [(j_0,r, σ_r) = (j_0,t, σ_t)]  =  [(j_1,r, σ_r) = (j_1,t, σ_t)]      (27)
   ```

5. After the tentative returned nullifier is formed, its actual public digest
   `d_t = D_v(z_t, n_t)` is computed. Neither candidate authorization entry
   `(j_0, PAV1, d_t)`, `(j_1, PAV1, d_t)` may have been exposed concretely.
6. The authorization equality partitions agree as well:

   ```text
   [(j_0,r, d_r) = (j_0,t, d_t)]  =  [(j_1,r, d_r) = (j_1,t, d_t)]      (28)
   ```

   Both candidate authorization entries are then blocked.
7. Every other observable field, policy outcome, quota and error is handled
   symmetrically. The challenger maintains both possible branch counters and
   rejects when either would exceed its allowance. It does not reveal an
   identity-labelled challenge issuance log.

- The digest used for both candidates' exclusion checks is the **actual
  returned public digest**. Two counterfactual digests computed from
  different hidden nullifiers are not used.
- If a late check rejects after tentative generation, protection, blocking
  and oracle effects are retained, and neither tentative value is exposed.
- `Corrupt` rejects protected handles. Identified nullifier or vote requests
  reject blocked pairs and blocked authorization entries. Registration
  authorizations and other-scope vote authorizations remain available. Exact
  tested authorization entries are excluded even if an interface would
  disclose them without explicitly returning a nullifier.
- An exposure is recorded when the value becomes public, including when the
  subsequent proving returns `GrindingExhausted`.

Limits: `U ≤ 2^34`, `T ≤ 2^44`, at most `2^10` invocations per credential,
at most `2^24` body scopes, `3 ≤ S ≤ 1,000`. `T` includes both proof roles,
repeated proving invocations and exhaustion. Any separate identified
nullifier service has an explicit request budget.

Two environments are defined: `RealLR_b`, in which every honest proof uses
the frozen prover and a fresh 112-byte tape, and `SimLR_b`, in which every
honest proof of both roles uses the one simulator `Sim+`. Anonymity is the
distinguishing gap between `RealLR_0` and `RealLR_1`.

What the game does not cover. A relayer that sees equal nullifiers can link
ballots at that scope, including ballots with different votes; `auth_v` does
not conceal that intentional link. If a nullifier was already identified,
anonymity at that credential and scope pair is excluded, whether or not its
authorization value was previously exposed. The claim is cross-scope privacy
under the stated exclusions, without retrospective protection after
disclosure of a challenge secret, and it excludes identity-bearing transport
information and distinctive public voting behaviour.

**Property 6: concrete security.** Not a game: the requirement that every
game of this section has a complete deployment-wide bound that satisfies the
contract of section 8.1, with all actual proving, simulation, verification
and reduction overhead accounted for. No extractor is accounted for, because
none is required.

**Property 7: deterministic bounded verification.** For a frozen descriptor,
verification is a total deterministic function of the canonical proof bytes
and the authenticated public context, with a finite prescribed bound on every
operation, and identical acceptance results on all conforming hardware.

**Property 8: registration origin.** Use the common environment; the adversary
outputs `(j, x_reg*, π_reg*)` and wins exactly when

```text
V_reg(x_reg*, π_reg*) = 1,
j remains uncorrupted through the output,
C* = Com_(B*)(sk_j),
x_reg* ∉ RegLog[j]                                                      (29)
```

The challenger knows `sk_j`, so the third condition is efficiently decidable
even for a new body `B*`. Publishing the commitment before registration covers
front-running. Freshness covers changed authorities, assignments and contexts,
including a recontextualization into a body that has never been sealed.
Exact-statement replay and rerandomization do not win. `x_reg*` contains
`auth*` through `m_reg` (section 1.1).

## 6. Arguments by property

Symbols for the deployment-wide terms, with the review's symbols in
parentheses where they differ:

| Symbol | Meaning |
| --- | --- |
| `ε_snd,mix`, `ε_snd,batch` (`s`, `s_batch`) | Adaptive relation soundness in the real joint environment, single output and batch of at most 1,001 (section 6.1) |
| `Z` | The deployment-wide joint zero-knowledge bound with the simulator `Sim+` (section 6.5.2) |
| `α_P` | Advantage in assumption `P`, selective-entry pseudorandomness with public leakage (section 8.4) |
| `δ_tag,target`, `δ_Com,seal`, `δ_Com,target` (`u_N`, `u_C,seal`, `u_C,target`) | The three restrictions of assumption `U`, selected-context existential uniqueness (section 8.4) |
| `ε_CR,REG`, `ε_CR,VOTE`, `ε_CR,VOTE,batch` (`F_R`, `F_V`, `F_V,batch`) | Finding distinct legal authorization frames with equal SHA3-512 digests; restrictions of one global legal-frame collision game `F` |
| `ρ_rep` (`ρ`) | Honest-secret repetition, (22) |
| `g_V`, `g_R`, `g_batch` | Blind authorization guessing, `q_guess · 2^-512` |

Authenticated state, canonical framing and constraint correctness are common
deterministic prerequisites.

### 6.1 Property 1: adaptive relation soundness

Status: complete (awaiting review) for the repaired theorem (37) only,
in an explicit model. The argument below is the review's written argument for
(24) and (25) in the common environment with both **real** honest
proof interfaces. It is not a qualification certificate. The local-transition
step of the original plan is **missing**, and a real-game bound on the retry
count is missing; both are stated at the end.

**Premises.**

- Canonical parsing and public validation implement the complete statements
  of section 1.1. In particular the vote frame includes the actual list, the
  1,024-bit nullifier and `auth_v`.
- The ordered constraint systems are equivalent to their relations over
  Boolean witnesses (section 2). Booleanity is enforced even when the
  algebraic reconstruction first produces extension-field coordinates.
- The field operations, CRT maps, reconstruction and compact-opening
  verification implement the frozen backend. The raw admissible challenge map
  is injective.
- **The backend QROM idealization**: the designated backend hash domains are
  independent quantum-accessible random-oracle domains, obtained by their
  exact prefixes, suffixes and encodings. The argument does not prove that
  concrete SHAKE256 satisfies it. The two 77-byte role prefixes must be
  distinct; that is a deterministic check on the frozen descriptor and
  namespace bytes, not an entropy assumption.

Credential-function evaluations inside the relation remain the specified
deterministic circuit computations. No hidden-input pseudorandomness,
credential uniqueness, OWF security or zero-knowledge assumption is used.
The challenger generates all honest credential secrets and maintains the
actual authenticated public state. The adversary has both real honest proof
interfaces, the malicious-registration interfaces, permitted corruptions and
adaptive public submissions. Every oracle-dependent preprocessing query is
charged; initial advice is independent of the sampled backend oracles and of
fresh honest randomness.

**What is published.** The published FAEST theorem is static. Its
standard-FAEST false-statement shape is

```text
10·(tau + 1)·Q^3·2^(-2·lambda) + 10·(tau + d_zk)·Q^2·2^(-lambda)        (30)
```

(FAEST v3 sections 10.11.7 to 10.11.9, as the review reads them). It allows
mathematical, inefficient response reconstruction and supplies no efficient
knowledge extraction. It cannot be cited as an adaptive ballot theorem. The
expanded representation and the compact-transcript conversion used below
follow the structure of FAEST v3 sections 10.11.6 to 10.11.9; the adaptive
theorem is proved separately.

**Oracle rounds.** The backend calls are those of section 1.7 and the seven
challenge rounds those of section 4. Verification reconstructs
`Ṽ = Q̃ + Δ·ũ` and `ã_0`; these reconstructed values belong to the
corresponding challenge inputs, and omitting them would describe a different
protocol. The tape, the pad and the salt change honest proving and the
relation dimensions but introduce no further Fiat–Shamir challenge. The
challenge-1 input literally fixes the salt, and with the auxiliary functions
fixed it still selects one `H5` response graph; the salt changes neither the
size of the local certificates nor the algebraic round bounds.

**The passive-prefix issue.** The original plan needs more than the statement
that the algebraic error bound holds uniformly for every IV. For fixed leaf
commitments, reconstruction uses functions of the form

```text
SeedPre_(iv, i, h)(com_i,j),     ConvertToVOLE(..., iv),     H5(iv, salt, e, label)
```

so the response graph depends on both `iv` and the leaf-hash key `h` (the
review cites the leaf commitment code in `crates/iroha_zkp_vole/src/bavc.rs`).
Consider a database predicate that requires every preceding oracle equation
to be present.

- A new `H4` answer can match an IV whose `H0` entry and later chain already
  exist. The elementary matching bound is `k · 2^-128`, not zero.
- A new `H0` answer can establish the response graph for an already queried
  later chain. Injectivity of the new leaf map does not by itself exclude
  this completion event.

The published passivity and isolation statements of FAEST Lemma 10.48, as
used by Lemma 10.49, do not supply the protocol-specific explanation.
Deleting the `H4` equation and existentially allowing different IVs can
introduce several response graphs for the same later chain.

> **Missing step of the original plan (open).** Establish a local predicate
> that handles these late `H4` and `H0` completions while retaining
> `δ(k) ≤ 34·k·2^-512 + 40·2^-256`. A uniform fixed-IV round bound alone is
> insufficient. This is a missing proof step, not an exhibited forgery. The
> argument below does not use it.

**The repair: global induced-seed uniqueness.** Define the event `Uniq` (the
review's `J`):

> For both role namespaces, every `iv ∈ {0,1}^128` and every one of the `tau`
> vector tweaks, each leaf commitment has at most one **induced seed**.

Unique root seeds are unnecessary. For a fixed role, IV and tweak, each of
the `2^256` root seeds produces `(sd, b0, b1)` and the commitment
`(c0, c1)` of section 1.7. Take two root seeds that induce distinct seeds
`sd ≠ sd'`.

- Equality of `c0` fixes at most one value of the independent 768-bit `h0`.
- Multiplication by `sd − sd' ≠ 0` permutes `F_(2^256)`. Its low 128
  coordinates are uniform, so equality of `c1` has probability `2^-128`,
  independently of the first equality.

The pair-ambiguity probability is therefore at most `2^-896`, for **any
deterministic leaf PRG**; no AES pseudorandomness assumption enters. A union
over the 33 tweaks, all `2^128` IVs and both roles gives

```text
Pr[¬Uniq] ≤ 2 · 2^128 · 33 · binom(2^256, 2) · 2^-896
          = 33 · (1 − 2^-256) · 2^-256  =: δ_leaf,all  <  2^-250.9556059   (31)
```

The small-row coefficient is 22, and a simultaneous union over both rows has
coefficient 55. All are below the `2^-128` structural statistical budget.
(31) is the value of the review's latest text; the checksum `c1` is
what brings the term under the budget. It closes the **structural statistical
gap** only: it is no claim that the query-dependent bound (37) is below
`2^-128`.

Condition on `Uniq` and fix the complete independent functions `H0`, `H4` and
`H5`. The remaining domains

```text
H_mu,    H1,    H_chall1,    H_chall2,    H_chall3                      (32)
```

stay independent random oracles. This is analytical conditioning, not an
executable construction of enormous tables. For each fixed choice of the
auxiliary functions the query theorem permits arbitrary computation and calls
to those functions between queries to (32); granting that access only
strengthens the adversary, and the ledger below counts the auxiliary calls
nevertheless. `H4` and `H0` now create no compressed-database transitions:
their values are mathematically fixed, also at locations not yet evaluated.
A challenge-1 input fixes `(R, mu, iv_pre, salt)`, hence `iv`, `h` and, once
the commitment preimages are present, one response graph. This avoids the
unresolved passive-prefix claim at the explicit cost (31).

**Algebraic round bounds.** They are (13) to (19) of sections 3 and 4 at the
final dimensions, with `|D_Δ| ≤ 2^248`: `log2 eps_KOS = −270.937091`
(registration) and `−268.047432` (vote), the ZKHash factors
`1 + 2.8553172332 × 10^-10` and `1 + 6.4324331994 × 10^-10`, and the final
root bound `7 · 2^-256` over the **raw** final challenges. Grinding and the
opening-size check only remove accepting raw strings; conditioning on
successful grinding would need a different denominator and is not used. For
a false statement the top coefficient of section 4 is nonzero by (12). The
dimension hypotheses of FAEST's hash and core lemmas fail at these
dimensions, so their numerical conclusions are not imported. The maximum
core round error is `7 · 2^-256`.

**Database predicate.** Work conditional on `Uniq` and the fixed auxiliary
functions. Let `DB` be a partial database for the domains (32), across
both roles. A consistent partial transcript includes the appropriate `mu`
equation, the commitment-hash predecessors and every challenge equation
through its last round. For each publicly valid false complete statement `x`
define the persistent response-graph flag: set at challenge 1 if the first
bad event of section 4 occurs, at challenge 2 if the nonzero constraint
vector hashes to zero, at challenge 3 if the raw challenge reaches a root of
(17); once set it stays set. The flag starts at zero and cannot first change
on a prover message, and an accepted false transcript must contain a first
change.

```text
Bad_false(DB)  ⇔  ∃ R, x ∉ L_R, t :  t is consistent with DB and ends at
                                      its first 0 → 1 transition
Bad_C(DB)      ⇔  a distinct-input, same-domain, same-role collision in
                  H_mu, H1, H_chall1 or H_chall2
Bad(DB)        =  Bad_false(DB) ∨ Bad_C(DB)                             (33)
```

The existential quantifier ranges over **all** false complete statements of
both roles, not only over registered credentials or submitted statements. A
final-challenge collision is unnecessary: `chall_3` has no successor and
selects no earlier transcript.

**Uniqueness of the predecessor chain.** Outside `Bad_C` a consistent
challenge prefix has at most one relevant predecessor chain:

1. Its literal namespace fixes the role.
2. Its `mu` predecessor fixes at most one complete statement, by canonical
   framing and absence of a `mu` collision.
3. The aggregate `H1` predecessor fixes the ordered vector digests.
4. Their predecessors fix the ordered leaf-commitment arrays.
5. The challenge-1 input fixes the corrections, `iv_pre` and the salt; the
   fixed auxiliary functions then fix `iv`, `h` and the response graph.
6. A challenge-2 or challenge-3 input traces backward uniquely through the
   preceding challenge outputs.

Repeated identical inputs create no alternative predecessors, and repeated
identical vector inputs are harmless because the vector position and its
tweak stay fixed. A fresh challenge is therefore tested against one statement
and one graph. **There is no union over statements, credentials,
registrations or scopes.**

The predicate has local witnesses of at most 38 cells:

```text
1 (mu) + 33 (inner H1) + 1 (outer H1) + 3 (challenge cells) = 38        (34)
```

A collision needs two cells. A complete reconstructed transcript supplies a
certificate that contains the necessary first-bad prefix; the reduction need
not compute an effective witness or decide language falsity.

**Transitions.** Fix `|DB| ≤ k` with `Bad(DB) = 0` and replace one database
cell by a uniformly sampled output. `n_mu`, `n_1`, `n_out`, `n_c1`, `n_c2`,
`n_c3` are the existing cell counts (`n_out ≤ n_1`); they include both roles,
and only compatible same-role cells can match.

| Changed domain | Ways to enter `Bad` | Bound |
| --- | --- | ---: |
| `H_mu` | A `mu` collision; or a new output that matches the `mu` field of an already queried challenge-1 input | `(n_mu + n_c1)·2^-512` |
| `H1` | A collision; matching one of the 33 vector-digest slots of an existing outer input; or matching `com` in an existing challenge-1 input | `(n_1 + 33·n_out + n_c1)·2^-512` |
| `H_chall1` | A collision; completing an existing challenge-2 input; or the pointwise first bad event for its unique prefix | `(n_c1 + n_c2)·2^-2112 + eps_KOS` |
| `H_chall2` | A collision; completing an existing challenge-3 input; or the pointwise ZKHash event | `(n_c2 + n_c3)·2^-832 + eps_zk` |
| `H_chall3` | The pointwise root event for its unique prefix | `7·2^-256` |

- The additional adaptive `mu` case, a new `mu` output completing an old
  challenge-1 chain, has probability at most `n_c1·2^-512 ≤ k·2^-512`. The
  `mu`-collision case is separate; their domain counts are disjoint, so
  together they are at most `k·2^-512`.
- The analogous commitment-completion cases are the two non-collision terms
  of the `H1` row, and `n_1 + 33·n_out + n_c1 ≤ 34·k`.
- If the changed cell completes a later transcript instead of causing a
  first-bad transition at its own round, its output must match one of the
  already embedded predecessor values of the table. Otherwise uniqueness
  fixes the applicable prefix before the new challenge is sampled, which
  permits (15), (16) or (18).
- There are no `H4` or `H0` database transitions in this argument: those
  functions were fixed. That is the explicit resolution of their completion
  cases, not an assertion that their literal full-database transition
  probability is zero.

Consequently

```text
δ(k) := max_{|DB| ≤ k, Bad(DB) = 0, z}  Pr_y[ Bad(DB[z ↦ y]) ]
      ≤ 34·k·2^-512 + 7·2^-256                                          (35)
```

The individual collision predicates have local probabilities `k·2^-b` with
`b = 512, 512, 2112, 832`; the compressed-oracle search lemma gives the
witness-finding bound `10·Q^3·2^-b` for each when its certificate overhead is
included in `Q`. These are quantum query bounds, not classical birthday
bounds. They are already inside (35) and are not added again.

**The imported lemma.** FAEST v3 Lemma 10.44 (the review's reading; not read
by us): a predicate with `m`-local witnesses and local transition bound
`δ(k)` has witness-finding probability at most

```text
( sum_{k=1}^{q+m} sqrt(10·δ(k)) )^2                                     (36)
```

Its hypotheses here: independent random-oracle domains encoded as one oracle;
an arbitrary query algorithm; the predicate (33); the local certificates
(34); the transition bound (35). The other imports are limited:

| Result | Use here |
| --- | --- |
| Lemma 10.48 | Its leaf and core decomposition is examined; its passive-prefix and isolation conclusion is **not** used to skip the unresolved transitions |
| Lemma 10.49 | Its static theorem is not invoked as an adaptive theorem; (33) to (36) replace that transfer |
| Lemma 10.50 | Only the acceptance-preserving conversion from a compact proof to its reconstructed explicit transcript |
| OWF and key-distribution argument | Omitted entirely |

In the signature proof the OWF distribution change is applied after the
compact conversion to relate ordinary generated keys to false instances,
which introduces its primitive advantage and a false-instance-density factor.
Here the winning condition already specifies a false statement, so neither is
needed. The other application-specific replacement is the implication (12),
supplied by the constraint equivalence. For a compact output the reduction runs
its verifier once and retains the reconstructed leaf commitments and
challenge inputs; acceptance gives the explicit transcript. No witness is
recovered, and no inefficient language test is required of the output
algorithm: it emits the reconstructed query certificate, and the analysis
establishes that this certificate witnesses `Bad` whenever the accepted
output is false. The response graph and its affine reconstruction occur only
in the mathematical predicate.

**Theorem (written argument).** Conditional on `Uniq`, for `Q ≥ q + 38`,
(36) and (35) give

```text
ε_snd,mix | Uniq ≤ ( sum_{k=1}^{Q} sqrt(10·(34·k·2^-512 + 7·2^-256)) )^2
                 ≤ 340·Q^3·2^-512 + 70·Q^2·2^-256  =: B(Q)
```

for every fixed good choice of the auxiliary functions, so averaging
preserves it, and

```text
ε_snd,mix ≤ δ_leaf,all + 340·Q^3·2^-512 + 70·Q^2·2^-256                 (37)
```

Since `δ_leaf,all ≤ 33·Q^2·2^-256` for every `Q ≥ 1` **[D]**, (37) is
below (30) at `tau = 33`, that is `340·Q^3·2^-512 + 400·Q^2·2^-256`. That is
a numerical corollary; it does not establish the original local argument.

**Honest interfaces.** The reduction runs the real challenger internally: it
knows the credentials it generated, answers corruptions from that state and
invokes both real provers with fresh tapes. An honest completed proof cannot
itself win, assuming deterministic correctness. An honest oracle call **can**
create the auxiliary predicate `Bad`, for example by colliding with an
adversarial commitment or completing an adversary's previously queried chain.
Such calls are covered by (35) exactly like adversarial calls; truth of
honest statements is not used to exempt their queries.

**Query ledger.** `q_pub` includes the adversarial backend-oracle queries
**and every backend call induced by adversarial public verification,
registration or submission requests**. Honest proving is additional:

```text
Q ≤ q_pub + 1447·T + G + c,      G ≤ M_ctr · T = 2^20 · T,      c = 1024   (38)
```

- `1447 = 1,408 + 34 + 5`: one honest candidate-row proof makes 1,408 `H5`
  evaluations, 34 `H1` evaluations and five other fixed backend calls.
- `G` counts all attempted counters; `T` includes valid invocations that
  exhaust the counter. `G ≤ 2^20·T = 2^64` is the deterministic ceiling.
- The selected final compact verification needs at most
  `704 + 34 + 1 + 1 + 1 + 1 + 1 + 1 = 744` backend calls (`H5`, `H1`, `H0`,
  `H4`, `H_mu` and the three challenges), whose results are stored and
  reused, and the local certificate 38 more: `c = 1024 > 782` suffices. The
  value is valid only with stored reconstruction results and the 38-cell
  certificate.
- If public verification is excluded from `q_pub`, its calls are added
  explicitly, up to 744 per candidate-row verification. An unbounded,
  uncharged verification interface invalidates the numerical conclusion.
- The fixed-table conditioning adds no executed table-generation procedure.
  Non-oracle proving and verification work stays in the deployment's
  operation ledger. If credential evaluations are idealized as separate
  oracles in another game, their calls need their own accounting; (38)
  concerns the designated backend oracles only.

**The retry tail (open).** The bound `p > 1/7360` of section 6.5.2 cannot
replace the deterministic retry ceiling in the **real** game. It applies when
the attempted challenges have the required independent uniform distribution;
there, domination by geometric variables gives
`Pr[G > 14720·T] ≤ e^(−T/4)`. Using that in the real adaptive QROM experiment
needs a proved transfer to that challenge distribution, with its error and
query costs added. An expectation alone cannot be substituted into a
quadratic and cubic bound. (38) therefore uses the ceiling.

**Batch form.** Pad the output list to 1,001 entries and select one
uniformly. The reduction need not identify the false entry; conditional on a
batch win it selects a winning entry with probability at least `1/1001`.
Applying this conditional on `Uniq` and charging `¬Uniq` once:

```text
ε_snd,batch ≤ δ_leaf,all + 1001 · ( 340·Q^3·2^-512 + 70·Q^2·2^-256 )    (39)
```

Only the selected output needs the additional verification inside `c`.

**Numbers.** At `q_pub = 2^64`, `T = 2^44`, with the `2^20` counter limit
(the review's latest values, each reproduced **[D]**):

| Quantity | Value |
| --- | ---: |
| `Q` | 36,918,944,040,625,374,208, `log2 Q = 65.0009950923` |
| `δ_leaf,all` | `< 2^-250.9556059` |
| (37), single output | `< 2^-119.8687268`, about `8.23982 × 10^-37` |
| (39), at most 1,001 outputs | `< 2^-109.9015005` |

The review states the theorem for the candidate row; for the comparator it
gives the leaf coefficient and no theorem. The query-dependent bounds are
computational bounds in the stated model, not unconditional statistical
failure probabilities. The ceilings on credentials, registrations, scopes and
`S` introduce no further selection factors: they restrict the environment,
(33) already covers every false statement, and their proof-generation and
public-interface activity is charged through (38).

**What the theorem does not give.** No extraction, no possession guarantee
and no restriction on proofs of true statements. It establishes neither
authorization prediction, uniqueness, anonymity, joint zero knowledge,
concrete-SHAKE security nor deployment readiness. It is not obtained from a
zero-knowledge replacement of honest proofs; the shortcut
`ε_snd,mix ≤ ε_snd,static + ε_JZK` is unsupported and is not the route.

**Open.**

1. The original local-transition step for late `H4` and `H0` completions. It
   needs a predicate that preserves graph uniqueness under late prefix
   completion, or a different proved bound. (37) does not depend on it.
2. A real-game tail theorem for `G`.
3. Independent review. The review asks that the auxiliary-function
   conditioning and the local-witness predicate be checked first, then the
   constraint equivalence at the final dimensions and the compact-conversion
   ledger.

### 6.2 Property 2: unforgeability

Status: conditional on adaptive vote soundness, `U` (nullifier restriction),
vote-frame collision resistance, `Z` and `P`. The event inclusion and the
reduction of authorization prediction to `P` are proved by the review; the
premises are unproved and unquantified.

**Frames and logs.** Write

```text
Y_v(x) = Frame("PARL/VOTE-AUTH/v1"; ...),     d_v(x) = SHA3-512(Y_v(x))
```

where `Y_v` is the `D_v` preimage of section 1.1; `d_v(x)` is the `D_v` of
the statement `x`. `VoteLog[j]` and `VoteAuthLog[j]` are kept per honest
handle under the logging rule of section 5.1.

**Event split.** Consider a winning output of the property 2 game that
targets the uncorrupted secret `s_j`.

1. If its statement is false, charge adaptive vote soundness.
2. Otherwise an existential witness `s'` satisfies all three equations of
   `R_vote+`.
3. Outside the event

   ```text
   BadTagOpen = { ∃ s' ≠ s_j :  Tag_(scope*)(s') = Tag_(scope*)(s_j) }
   ```

   that witness must be `s_j`. Hence `auth_v* = AuthV_(d_v(x*))(s_j)`.
4. If this digest occurs in `VoteAuthLog[j]`, choose its logged statement
   `x_0`. Distinct frames with equal digests give a SHA3-512 collision.
5. Equal frames identify every statement field except `auth_v`; truth and the
   unique target secret identify `auth_v` too. Thus `x* = x_0`, contradicting
   freshness.
6. Therefore every remaining win correctly predicts the authorization value
   for a fresh pair `(j, d_v(x*))`.

```text
Win_2 ⊆ FalseAccepted_vote ∪ BadTagOpen ∪ FrameCollision_v
        ∪ FreshVoteAuthCorrect                                          (40)
```

**The two authorization-prediction games.** `Pred_R` (for `t = PAU1`) and
`Pred_V` (for `t = PAV1`) are restrictions of the common credential
experiment of section 5.1. There is no `Test` interface during the
predictor's execution. All disclosed credential outputs are concrete, and
both proof interfaces use `Sim+`. The adversary sees:

- every public commitment and authenticated list;
- both authorization families on permitted other inputs;
- identified nullifiers and complete identified ballots;
- the secrets of adaptively corrupted other handles;
- malicious registrations and all public verification results;
- the shared simulated-proof transcript and backend-oracle environment;
- public coherent computation of the concrete functions.

An authorization entry is recorded **before disclosure**, including
disclosures followed by proving failure or counter exhaustion. The adversary
finally outputs at most `q_guess` triples `(j, d, a)`. A triple wins exactly
when

```text
j is honest and uncorrupted,
d ∈ {0,1}^512,
(j, t, d) has never been exposed by any interface,
a = f_t(s_j, d)                                                         (41)
```

Freshness is per handle and per family: the other family at the same digest,
and another handle's authorization at that digest, are allowed. The
single-output games use `q_guess = 1`; a final list supports the batch
reduction of section 6.3. No unbounded free guessing interface is implied.

**Reduction to `P`.** Run the predictor once. After it commits its output
list, reserve its eligible target handles, `Test` their fresh entries and
output whether any guess matches. In the real branch this recognizes
prediction success. In the random branch every fresh authorization is an
independent 512-bit entry, and a union bound applies even with duplicate
guesses. For both families

```text
ε_pred,t ≤ ρ_rep + α_P(ℛ_t') + q_guess · 2^-512                         (42)
```

There is no target-handle guessing factor `U`. The final tests and
comparisons are charged in `ℛ_t'`. This is the concrete-function premise that
replaces an ideal model: `P` at the reduction's actual resources. The ideal
calculation of section 8.2 is a separate diagnostic.

**Bound.** Apply joint zero knowledge only to the final, efficiently
testable event `FreshVoteAuthCorrect`, which the challenger can test using
its honest secrets, then (42). **Do not apply computational
indistinguishability to deciding arbitrary language falsity or existential
opening ambiguity.**

```text
ε_2 ≤ ε_snd,mix + δ_tag,target + ε_CR,VOTE + Z + α_P + ρ_rep + g_V      (43)
```

with `g_V = q_guess,V · 2^-512`. The terms bound, in order,
`FalseAccepted_vote`, `BadTagOpen`, `FrameCollision_v`, the joint simulation
step and the prediction game. `ε_snd,mix` is (37), `Z` is (84);
`δ_tag,target`, `ε_CR,VOTE` and `α_P` have no established value.

**Premises**, complete for this route:

| Premise | Required experiment or fact |
| --- | --- |
| Deterministic construction | Correct public validation, encoding equivalence, complete injective frames, fixed descriptor, honest logs and corruption exclusions |
| Adaptive vote soundness | A false accepted statement with both **real** honest proof interfaces available (section 6.1) |
| Nullifier-opening uniqueness | The existential target event `BadTagOpen`, including adaptively selected targets and scopes: the restriction `δ_tag,target` of `U` |
| Vote-frame collision resistance | Quantum collision resistance of SHA3-512 on distinct legal `Y_v` frames |
| Joint zero knowledge | Both relations of section 1, arbitrary application-witness auxiliary information, the shared simulator (section 6.5) |
| `P` | Section 8.4, at the resources `ℛ_V'` of the prediction reduction |
| Resource accounting | All exploration, preprocessing, public verification, honest proving and reduction overhead is charged |

**`CrossIssued_2`.** Freshness in (26) is per target handle, whereas honestly
issued statements exist for every handle. The event

```text
CrossIssued_2 = { Win_2  ∧  x* was honestly issued for a handle h ≠ j }
```

entails a same-scope equality of honest nullifiers, possibly caused by
repeated secrets. It is covered by the prediction game's other-handle
interfaces, not discarded; honest-secret repetition is the term `ρ_rep`.
Nullifier injectivity does not eliminate two handles with the same secret.

**Routes not adopted.**

- The unchanged-relation false-instance hybrid: changing an observed honest
  ballot's vote leaves a true statement, because the honest credential
  remains a witness, so plain soundness of the statement is insufficient and
  perfect injectivity does not change that. The hybrid would have to jointly
  simulate the target's proof history, replace its relevant commitments by
  values with no opening, preserve the public-output distribution, eliminate
  every alternative mixed-list witness, prove freshness localization despite
  prior oracle programming, and invoke soundness in the resulting
  environment. None of these transitions follows from the sparse-image
  counting fact (section 6.8).
- Dropping the AES key-validity restriction does not preserve the plain-FAEST
  unforgeability proof: that restriction is used in the signature
  reduction's false-key transition, and the list relation has no lossy-key
  step.
- An extraction-based reduction is analysed in section 10; it is not
  required.

### 6.3 Property 3: nullifier uniqueness

Status: conditional on batch soundness, `U` (commitment restriction at
authenticated seals), vote-frame collision resistance, `Z` and `P`. A direct
batch counting reduction; no extractor.

Define, for the fixed authenticated seal `(B, L, S)`,

```text
BadOpenSeal = { ∃ C ∈ L, s ≠ s' :  Com_B(s) = Com_B(s') = C }           (44)
```

This includes malicious registrations whose registrants know no opening.

**Argument.** Retain at most 1,001 relevant output ballots. Outside false
acceptance and (44), every retained statement has a witness, and each of the
`k` controlled sealed entries explains at most one nullifier. More than `k`
distinct nullifiers outside the honest-issued set therefore include a ballot
with an honest-entry witness, and commitment uniqueness forces that witness
to be the entry's honest secret. Define the efficiently testable event:

> Some retained ballot has a fresh correct authorization for some uncorrupted
> honest handle in the sealed list.

The challenger tests it by enumerating at most `1001 · 1000` ballot and
handle pairs. Apply joint zero knowledge **once** to this event. After
excluding a frame collision, output all eligible fresh authorization guesses
in one prediction game (41). No witness is extracted or selected.

```text
ε_3 ≤ ε_snd,batch + δ_Com,seal + ε_CR,VOTE,batch
      + Z + α_P + ρ_rep + g_batch                                       (45)

g_batch ≤ 1,001,000 · 2^-512 < 2^-492.0669
```

- `ε_snd,batch` is (39), in which the global leaf event is charged
  once. The review's first statement of this reduction used `1001` times a
  single-output soundness bound; its consolidated ledger uses the batch
  theorem.
- `Z` and `α_P` are charged once: the reduction avoids multiplying the
  zero-knowledge and prediction losses by 1,000.
- The reduction does **not** need nullifier-opening uniqueness: commitment
  uniqueness identifies the honest witness.
- The honest-issued set must include nullifiers whose authorizations were
  disclosed on failed or exhausted proving requests. Otherwise "outside the
  honest-issued set" does not have the required freshness implication.
- `δ_Com,seal` is **existential opening uniqueness**, a stronger and
  different premise than computational collision resistance, which does not
  establish it when no reduction obtains the purported openings.
- Determinism is unconditional: equal `sk` and equal scope give equal
  nullifiers, independently of the vote and the proof randomness.
- Property 8 is not required for (45) under this partition, whose `k`
  counts every adversarially registered entry whether or not an opening is
  known. It is required for an interpretation in which account registration
  establishes honest credential origin despite front-running and
  recontextualization; then `ε_8` is added.

`δ_Com,seal`, `ε_CR,VOTE,batch` and `α_P` have no established value.

### 6.4 Property 4: unlinkability and non-frameability

**Unlinkability.** Status: conditional on `Z` and `P` under the
admissibility rules of section 5.2. The game is a restriction of the
anonymity environment, so section 6.5.3 gives

```text
Δ_link ≤ 2·Z + 2·α_P + 2·ρ_rep                                          (46)
```

a deployment-wide bound with no lifetime multiplier. The premises, hybrids,
resource costs and exclusions are those of section 6.5.3.

**Non-frameability.** Status: conditional. Identity reductions to
properties 2 and 8.

- Property 2 uses the nullifier-based winning condition (26), so the
  reduction is the identity: forward the environment and return the framed
  ballot.

  ```text
  Pr[Frame_vote] ≤ ε_2                                                  (47)
  ```

  An accepted proof hides its selected index, so "under an entry" must not
  stay undefined; (26) defines it by the target's nullifier.
- Registration framing, including a fresh registration statement or a
  recontextualization under an uncorrupted honest credential, is property 8:

  ```text
  Pr[Frame_reg] ≤ ε_8                                                   (48)
  ```

The union of the two endpoints is bounded by `ε_2 + ε_8`. Cross-scope
observations give no additional framing capability **conditional on the
joint oracle-access games of properties 2 and 8**, which already permit
observations of both proof types. Neither `ε_2` nor `ε_8` is established.

### 6.5 Property 5: zero knowledge and anonymity

Status: conditional, for both halves. Neither half is an accepted result.

- **Joint zero knowledge** is a written chain of two arguments: the CRT-layer
  simulation argument (section 6.5.1) and the outer composition that reaches
  it from the actual prover (section 6.5.2). Together they give the
  deployment-wide bound `Z` of (84). The chain is conditional on the CRT
  generator games, whose advantages are **unquantified**, on the backend QROM
  model and on independent review, which has not taken place.
- **Anonymity** is the composition of `Z` with assumption `P`
  (section 6.5.3), with the bound (88).

**Scope of the two joint zero-knowledge arguments.** The review wrote the
CRT-layer argument for the padded prefix-only backend and the outer
composition after it; its latest decision revises the outer composition, the
hidden-label deletion lemma and the ledger for the salt, the counter limit,
the salted `H5` and the nine-block leaf expansion, and requires joint zero
knowledge for both relations of section 1. It has not restated the remaining
steps of the CRT-layer argument for the extended backend or at the final
vote dimensions. Those steps treat the application witness as an arbitrary
known string of the relation's length, use the relation only through its
public constraint evaluation, and state that arbitrary expanded witness
length is permitted; on that basis they are recorded here for the frozen
construction **[E]**. Quantities that depend on the vote dimensions or on
the leaf expansion are recomputed and marked **[D]** where the review gives
no value.

**Why the pad.** If the first 256 witness bits are known, then
`u[0, 256) = d[0, 256) ⊕ w[0, 256)` is known and, under the free-XOR-label
analysis, the intended CRT-mask hiding is defeated. A layout whose first 256
bits are credential bits cannot give unrestricted all-witness zero knowledge:
uniform sampling of a secret is not conditional entropy once its commitment,
which may determine it, is public. With the pad those positions hold fresh
proof coins independent of the application witness. **Adding the pad supports
the target; it does not by itself establish it.**

#### 6.5.1 The CRT-layer simulation argument

Status: conditional; the review's own classification is "conditional
CRT-layer simulation argument complete, awaiting independent review". The
review wrote it for the padded prefix-only backend. The deletion lemma below
is its revised form for the salted `H5`; the other steps are recorded for the
extended backend on the basis stated in section 6.5 **[E]**.

The distinction that resolves the main confusion: FAEST's multi-hiding lemma
supplies ideal VOLE material **while retaining consistent `H5` programming**.
The pad argument permits removing that programming when its values depend on
the application witness. Uniform witness-prefix bits are **not** a hypothesis
of FAEST Lemma 10.51: its underlying experiment actually releases `u` and the
field-mask values, so the lemma cannot by itself establish everlasting
secrecy of the opposite labels. The relevant imports are Lemmas 10.24 and
10.51 (FAEST v3 sections 10.5.2 and 10.11.10); the additional argument below
addresses their witness-dependent programmed oracle state.

**Variables and visibility.** `t` is a proof invocation, `e` a CRT gate,
`m ∈ {0, ..., 9}` a field mask. `W_app,t` is the entire deterministic
application part of the extended witness, including the trace and the
selectors.

| Material | Definition | Visibility |
| --- | --- | --- |
| Pad | `P_t ← {0,1}^256` | Secret proof coins |
| Witness mask | `U_t = (U_P,t, U_app,t)` | Not directly transmitted |
| Witness correction | `d_t = (P_t ⊕ U_P,t, W_app,t ⊕ U_app,t)` | Transmitted |
| VOLE corrections | `c_t,1, ..., c_t,tau−1` | Transmitted |
| Field correlations | `q̄_t,m = v̄_t,m + Δ_t·ū_t,m` | `q̄` reconstructed; `ū`, `v̄` private |
| Gate labels | `L^1_t,e = L^0_t,e ⊕ U_P,t` | One label per gate reconstructible |
| Gate correction | (49) below | All ten bits per gate transmitted |
| Opening positions | `I_t = DecodeAllChall3(chall_3,t)` | Public |
| Label selector | `γ_t,e = G[e]·Δ'_t` | Public |

The opening reveals sibling seeds and hidden-leaf commitments. Together with
the corrections and the challenge it reconstructs the observable label
`L^obs_t,e = L^(γ_t,e)_t,e`. The opposite label is
`L^hid_t,e = L^obs_t,e ⊕ U_P,t`.

The exact `H5` input encoding is

```text
I_t(e, L) = PREFIX_(R_t) || iv_t || salt_t || LE32(e) || L || hex("05")
```

and `H5_t,e(L) ∈ {0,1}^10` is the low ten output bits of the frozen
interface. Then

```text
c_mult,t[m, e] = H5_t,e(L^0_t,e)[m] ⊕ H5_t,e(L^1_t,e)[m] ⊕ f_e(ū_t,m)   (49)
```

These corrections are the relevant gate ciphertexts; there is no additional
independent ciphertext object.

**The distinguisher** receives complete proof bytes and public statements,
may know every application witness and trace, and retains arbitrary quantum
auxiliary information about them. It has quantum access to all modelled
public oracles before, between and after proof requests. It does not receive
the pad, the root seed or the proving tape.

**The public simulator** samples:

1. the root seed, `iv_pre`, the salt, the commitment and opening material,
   and the
   challenge schedule of the surrounding simulation game;
2. uniform canonical `c_i`, `c_mult`, `d`;
3. the reconstructed `Q`, `q̄`, `Δ`, using the observable `H5` labels;
4. four uniform consistency-response fields;
5. six uniform transmitted QuickSilver coefficients, then the
   verifier-determined `ã_0`.

It needs no application witness and no pad.

**Private bookkeeping, for the proof only.** Augment this simulator: sample
an unused uniform `P_t`, set

```text
U_P,t = P_t ⊕ d_P,t,        U_app,t = W_app,t ⊕ d_app,t                 (50)
```

solve for the private field masks, and record the hidden-point assignments

```text
H5_t,e(L^hid_t,e) := c_mult,t[·, e] ⊕ H5_t,e(L^obs_t,e)
                     ⊕ (f_e(ū_t,m))_(m<10)                              (51)
```

One experiment installs these assignments; the other keeps the private
records but answers `H5` from its unmodified oracle. Once
indistinguishability is established, the unused bookkeeping can be deleted.

**Exact scope of the component lemma.** The proof operates after the
surrounding game has legitimately sampled and programmed the challenges and
made the opening selective, with the correct counter schedule. Establishing
that transition from the actual prover is not a primitive assumption and is
not silently granted: it is the outer composition of section 6.5.2. Within
that interface the component lemma covers adaptive requests to both roles,
arbitrary application witnesses and auxiliary information, and complete
subsequent oracle access.

**The statistical argument.** First, an unconditional identity that needs no
PRG assumption. Let `Z` contain any material computed independently of `P`,
including arbitrary functions of `U_P`, CRT labels, corrections and oracle
evaluations. If `P` is uniform and independent of `(U_P, Z)`, then

```text
Pr[ d_P = a, Z = z ] = 2^-256 · Pr[ Z = z ]                             (52)
```

Thus `(P ⊕ U_P, Z)` has exactly the distribution of an independent uniform
`d_P` together with `Z`. Equivalently, sample `d_P` uniformly and define
`P = d_P ⊕ U_P`. This remains true with quantum auxiliary registers: the
classical register `d_P` is uniformly mixed and independent of the remaining
registers. **The identity applies even if `U_P` is not uniform.** It does not
yet cover responses computed using `P`; those need the following argument in
the ideal-mask experiment.

Let `h_j = ZKHash(chall_2, (A_j || 0))`. For fixed reconstructed `q̄_j`, fixed
challenges and a valid padded witness, the six private QuickSilver masks are
uniquely recovered from six freely chosen transmitted responses:

```text
ū_5     = ã_6 + h_6
ū_(j-1) = ã_j + h_j + q̄_j + Δ·ū_j,        j = 5, ..., 1                (53)
```

This is a triangular bijection with unit diagonal. It works even when
`Δ = 0`. Next, the remaining four masks are uniquely determined by the chosen
consistency response:

```text
(ū_6, ..., ū_9) = ũ − VOLEHash_without-tail(U, ū_0, ..., ū_5)           (54)
```

The last four inputs enter this hash additively with coefficient one.

(53) and (54) give a **joint bijection between ten uniform field masks and
ten freely sampled public response fields**. Solve the six QuickSilver masks
first and compensate in the four consistency masks. Changing the two groups
independently would not be justified.

For a valid witness the remaining coefficient is forced:

```text
ã_0 = VerifyRelation(x, d, Q, q̄, Δ, chall_2, ã_1, ..., ã_6)            (55)
```

The right side uses public reconstructed values, not `P` or `W_app`.

Therefore, after this change of variables, the **public simulator's execution
is independent of every pad**. Its private `H5` assignment values may still
depend on the pad and the application witness; that dependence is removed
next. The change of variables must preserve the oracle jointly: defer the
current invocation's hidden-point assignments until its visible-label
evaluations and the mask-coordinate change are complete. This is a
reparameterization of one experiment, not permission to change masks after
adversarial access without charging a transition.

**The seed and initial CRT hybrids.** The statistical argument starts from
ideal masks. The route there:

1. Replace the joint root expansion and high-mask expansion by uniform output.
2. Replace the hidden GGM-path expansions.
3. Replace the hidden leaf-commitment outputs. Replacing the 144-byte leaf
   expansion by uniform bytes makes `sd`, `c0` and `c1` mutually independent
   and uniform, conditional on the public hash key.
4. Replace the hidden expanded VOLE rows. The resulting `U`, `c_i`, `ū_m` are
   jointly uniform: the relevant coordinates are disjoint and the CRT mask
   decomposition is bijective.
5. Replace `c_mult` by uniform strings and install (51), charging quantum
   reprogramming and exceptional collisions.
6. Apply (50), (53) and (54), preserving the private `H5` assignments.
7. Remove those assignments using the quantum argument below.

Steps 1 to 5 are the relevant multi-hiding construction. Its hypotheses, as
checked by the review against the frozen backend:

- Fresh independent root and `iv_pre`: satisfied by the tape rule.
- Adaptively chosen 512-bit `mu`: permitted.
- Selective opening: satisfied **in the entered simulation game**, not
  assumed of the original Fiat–Shamir transcript.
- Arbitrary expanded witness length: permitted.
- Required tweak separation: `34 · 256 < 2^31` for the fast row and
  `23 · 4,096 < 2^31` for the comparator.
- The leaf construction of section 1.7 and unchanged CRT maps: required,
  and frozen here. The review states the hiding step for the 112-byte
  commitment (step 3) and that the leaf generator experiment has nine
  blocks.
- Quantum pseudorandomness of the actual generators: an explicit assumption,
  not established by conformance vectors.

Expanded lengths `l^`. The review gives the registration values; the vote
values are `l` plus the same offsets, 80 and 120 bits **[D]**:

| Row | Registration `l^` | Vote `l^` |
| --- | ---: | ---: |
| Fast | 35,920 bits | 53,584 bits |
| Comparator | 35,960 bits | 53,624 bits |

The small-length restrictions used for particular universal-hash **soundness
constants** do not restrict the additive-mask bijections above.

For quantitative accounting let `T` be the total number of invocations,
`g = n_mult`, `K_λ = 256` and `h = ceil(log2 N − 1)` for `N` leaves (12 on
the fast row **[D]**). Expressing the primitive assumptions directly as
quantum generator-to-uniform distinguishing advantages gives

```text
ε_seed ≤ T·ε_root + T·tau·h·ε_tree + T·tau·(ε_leaf + ε_expand)          (56)
```

The root term covers its **joint two-tweak use**. The leaf and expansion
terms must use the actual query counts and lengths, not nominal "AES-256
security". The initial `H5` transition has the published quantum programming
term

```text
ε_initial ≤ (3/2) · T · sqrt( K_λ · g · Q_5^pre · 2^-384 )              (57)
```

and exceptional terms bounded conservatively by

```text
δ_MH ≤ b·2^-256 + T·2^-256 + 2·g·T^2·K_λ·2^-384                         (58)
```

where `b` counts the separate role and row `H4` domains being analysed; for
the deployed fast-row pair `b = 2`. Counts include the reduction's applicable
internal queries.

(56) to (58) express the underlying hybrids using direct generator
advantages. If the specification's PRP-native accounting is used instead, its
multiplicative factor must be kept:

```text
ρ_PRP = exp( T · [ β_root^2 + 4·tau·h·β^2 + tau·a_leaf^2 ] / 2^128 )    (59)
β = 2,    β_root = 5,    a_leaf = 9·N_0 + ceil(l^ / 128)
```

The factor must not be omitted, and the two forms of primitive accounting
must not be equated without the corresponding switching argument. The leaf
coefficient 9 is the nine-block expansion. At the final dimensions `a_leaf`
is `2,304 + 281 = 2,585` (registration) and `2,304 + 419 = 2,723` (vote) on
the fast row, and the exponent of (59) at `T = 2^44` is
`1.1400605729 × 10^-17` **[D]** and `1.2650301513 × 10^-17` (the review's
value, which the formula with the coefficient 9 reproduces **[D]**), so
`ρ_PRP < 2`.

No numerical value is supplied for the primitive advantages. Consequently
none of these formulas is a completed concrete-security certificate.

**Hidden labels and all subsequent quantum queries.** The label input has
**256 bits**. It does not have `256 − w_grind` bits, and the ten-bit output
does not shorten its input entropy.

Consider the unpatched public-simulator experiment. Its `H5` oracle, public
execution and query registers are independent of the unused pads. A hidden
point has label

```text
L^obs_t,e ⊕ d_P,t ⊕ P_t                                                 (60)
```

Presample the `T` independent salts, including those of unused invocation
slots. Their collision probability is

```text
δ_salt ≤ binom(T, 2) · 2^-256 < 2^-169                                  (61)
```

Outside this event the salt in a query identifies at most **one** proof
record, and its gate index then identifies one hidden label of that record.
In the unpatched baseline, matching that label fixes one value of the
record's independent 256-bit pad:

```text
p_query ≤ 2^-256                                                        (62)
```

There is no factor `T` and no factor `g`: the query specifies the salt and
`e`. The labels across gates are correlated through the same offset; that
does not change the calculation. (62) is a baseline query-mass bound. It is
**not** a claim that the actual patched oracle leaves 256 bits of
information-theoretic conditional entropy after arbitrary quantum search;
giving the entire oracle table would invalidate such a claim.

To handle adaptive locations, define two fixed reversible lookup operations
whose input includes the base oracle table and the current private assignment
table:

- one XORs the base `H5` answer into the response register;
- the other XORs the active assigned value when the input matches an
  installed point, and otherwise the base answer.

The tables are inputs to fixed permutations; their contents may evolve
adaptively. Classical requests and measurements can be included in a dilated
execution. This is the fixed-permutation formulation of one-way-to-hiding,
not an unjustified application of a fixed-hidden-point theorem (Jaeger,
arXiv 2511.16009, Theorem 2.1 and section 1.1, cited by the review; not read
by us). Splitting both experiments on the common salt-collision event gives,
for `q_eff` total evaluations of these lookups, the **singleton-record
deletion lemma**

```text
ε_delete ≤ 2 · q_eff · 2^-128 + δ_salt                                  (63)
```

The failure term is additive; it is not placed under the square root.
Conditioning on salt uniqueness does not condition on the private pads. The
constant: if `Π_t` projects onto query inputs where the two lookups differ,
one query changes the state norm by at most `2·‖Π_t |ψ_t⟩‖`; telescope the
query operations, apply the triangle inequality and Jensen's inequality, and
use `E ‖Π_t |ψ_t⟩‖^2 ≤ 2^-256` in the unpatched execution. Subsequent
computation and tracing out private registers cannot increase
distinguishability.

The essential hypotheses:

- the baseline public and query state ignores the pads;
- the two lookup operations differ only at the recorded hidden points;
- auxiliary information may contain `W_app`, but not fresh pads;
- every later `H5` evaluation is counted;
- no independence between different gates' hidden labels is assumed;
- no independence between successive adversarial requests is assumed.

With cached reconstruction, one visible `H5` evaluation per gate per proof
suffices. Counting later verification inside the adversarial budget,
`q_eff ≤ Q_5 + 704·T`. At `Q_5 = 2^64`, `T = 2^44`,

```text
ε_delete ≤ 1.0849300914 × 10^-19 + δ_salt ≈ 2^-62.99903172              (64)
```

(reproduced **[D]**). This is a conservative distinguishing upper bound. It
is neither an attack nor a claim of a `2^-128` distinguishing advantage.

**Derived and not adopted: an IV-multiplicity lemma for an unsalted `H5`.**
Fix both complete `H4` tables. For each role and each `mu`, `H4` is a random
map from `2^128` values of `iv_pre` to `2^128` IVs, and there are `2^641`
role, context and output fibres, so some fibre has size at least 160 with
probability at most `2^641 / 160! < 2^-304.664752`. Outside that event a
fresh uniform `iv_pre` reaches any specified IV with probability at most
`160 · 2^-128`, whatever adaptively chosen `mu` precedes it and with prior
quantum queries. A union over four invocation indices gives

```text
δ_mult := Pr[ some IV occurs more than 3 times ]
        ≤ 2^641 / 160! + binom(T, 4) · (160 · 2^-128)^3
        < 2^-304.664752 + 2^-190.619178
```

and an unsalted-`H5` analysis could use
`ε_delete ≤ 2·q_eff·sqrt(3 · 2^-256) + δ_mult ≈ 2^-62.20655047`. The review
adopts the salted construction instead, as the simpler one. Numbers
reproduced **[D]**.

For actual post-query prediction, a safe transfer is the corresponding
baseline prediction probability **plus the applicable hybrid distinguishing
losses**. It would be incorrect to report `2^-256` as the actual prediction
probability after `q` quantum queries.

**Collision and abort accounting.** An own-label equality `U_P = 0`, or a
conflicting cross-proof assignment, must not be hidden inside a claim of
exact equality. Nor should the public baseline be conditioned on a
pad-dependent "no collision" event. A conservative unpatched-baseline bound,
deliberately ignoring IV separation, is

```text
δ_sep ≤ (T + 2·g·T^2) · 2^-256                                          (65)
```

The first term covers own-label equality. The second overcounts conflicting
hidden/visible and hidden/hidden pairs with matching gate indices. At the
lifetime ceiling and `g = 704` it is below `2^-157` (`2^-157.541` **[D]**).

For an explicit conservative composition, totalize the assignment experiment
with a fixed overwrite rule and keep a private bad-event flag. (63) applies
both to ordinary distinguishers and to a final test of that flag. Hence an
aborting-versus-totalized endpoint costs at most `δ_sep + ε_delete`. Allowing
this extra charge avoids relying on delicate conditioning. With `ε_MH` the
seed and initial-programming hybrid loss, including its specified failures,
the conditional bridge has the conservative bound

```text
ε_CRT ≤ ε_MH + δ_sep + 2·ε_delete                                       (66)
```

Some exceptional events are counted twice; that is intentional. It is a safe
bound, not an optimized ledger. Its oracle-removal contribution is about
`2^-62` at the stated ceiling. The primitive terms remain additional.

**What imports, and what does not.**

- **Yes:** the FAEST multi-hiding hybrids apply to the unchanged backend at
  these lengths, in their specified selective-opening experiment.
- **No:** "the first `lambda` witness bits are uniform, therefore FAEST's
  complete zero-knowledge argument applies as stated" is not a correct
  theorem citation.
- **The pad's precise contribution:** after the mask bijection it supplies
  independent latent variables for the full-oracle deletion argument (60) to
  (63), even when the application witness is known.

| Difference from plain FAEST | Treatment |
| --- | --- |
| Larger witness lengths | Use actual expansion lengths and primitive costs; the statistical mask bijections remain valid |
| Explicit namespaces | Separate oracle domains; sum domain-specific failures and query counts |
| Two relations sharing one secret | Permit arbitrary correlated application witnesses; independent fresh pads are sufficient for this component |
| Different constraints | Require encoding correctness and the valid-witness polynomial identity, including pad Booleanity |
| No `H3` derivation | Fresh independent coins replace that derivation; no `H3`-PRF hop is needed |
| Full later oracle access | Supplied by the deletion argument, not by a bound concerning only verification of one forgery |
| Salt in `H5`, 16-byte leaf checksum, nine-block leaf expansion | The salt makes the hidden-label records singletons in the deletion lemma; the leaf hiding step uses the 144-byte expansion; the review has not restated the remaining steps |

The `2^10`-per-credential and `2^44`-total ceilings are not multiplied
together. The conservative multi-hiding and assignment-collision bounds (58)
and (65) are retained without sharpening.

Not claimed: post-query 256-bit conditional entropy; direct transfer of
FAEST's signature theorem; completed property 5.

#### 6.5.2 The outer composition

Status: conditional; the review states it as a conditional theorem for
independent review.

The composition reaches the challenge-programmed selective-opening experiment
of section 6.5.1 from the actual joint Fiat–Shamir proving experiment. In
this subsection `Q ≤ 2^64` is the adversary's oracle-query budget (the
review's `q`), `T ≤ 2^44` counts **all valid proving invocations across both
roles**, including invocations returning exhaustion, and `M_ctr = 2^20`. The
game is exactly the arbitrary-application-witness game of section 5.2: the
adversary may know and disclose every application witness; fresh proving
tapes remain undisclosed; invalid requests receive the same prescribed error
in every game; the winning event is the adversary's final output bit.

For role `R`, the exact challenge inputs are (fast row; `c_1, ..., c_32` are
the `tau − 1` corrections)

```text
X_1   = PREFIX_R || mu || com || c_1 || ... || c_32 || c_mult || iv_pre || salt || hex("09")
X_2   = PREFIX_R || chall_1 || ToBits(ũ, Ṽ) || d || hex("0a")
X_3,c = PREFIX_R || chall_2 || ToBits(ã_0, ..., ã_6) || LE32(c) || hex("0b")
```

All games keep one global oracle state. The programming losses are written
`ε_P1`, `ε_P2`, `ε_P3` (the review's `ε_1`, `ε_2`, `ε_3`), to keep them apart
from the round errors of section 4 and the property advantages.

| Game | Exact change from the preceding game | Bound |
| --- | --- | ---: |
| `G_0` | Actual joint prover, fresh 112-byte tapes, actual oracle challenges, first-success counter loop and typed exhaustion | — |
| `G_1` | Expose the tape sampling as independent `r`, `iv_pre`, `P`, `salt`. Keep the actual `mu_R(x)` and `iv = H4(iv_pre \|\| mu)` | 0 |
| `G_2` | Sample challenge 1 independently and uniformly; overwrite its oracle value at `X_1`. Continue using that sampled value. No membership measurement or abort | `ε_P1` |
| `G_3` | Sample challenge 2 independently and uniformly; overwrite its oracle value at `X_2` | `ε_P2` |
| `G_4` | At every attempted counter, use an independently sampled uniform 256-bit value and install it at `X_3,c`. Stop at the first admissible value, or return exhaustion after all `M_ctr` attempts | `ε_P3` |
| `G_5` | Sample the complete stopping schedule before constructing the transcript; couple its accepted challenge to the selective-opening challenge. On exhaustion, use an independent unused admissible challenge for the selective experiment | 0 |
| `G_6` | Apply the conditional CRT argument of section 6.5.1, including its joint mask bijection and the removal of hidden `H5` assignments | `ε_CRT` |
| `G_7` | Replace the exact exhaustion-path sampling by the bounded sampling of `Sim+` | `σ` |

There is **no `mu`-replacement loss**: the simulator knows the complete
public statement and computes its real digest. Nor is there an `H3`-PRF loss:
the frozen fresh-tape prover already has the independent-root distribution
that ordinary FAEST reaches through its `H3` hybrid. Independently replacing
the derived IV would be an unnecessary, unproved change. The imported
ingredients are FAEST's selective-opening experiment (FAEST v3 Theorems 10.42
to 10.53, as the review reads them) and adaptive reprogramming. Their
component statements are used, not the FAEST signature-security theorem as a
theorem about this application. **FAEST's commitment-list unpredictability
(Lemma 10.52) is not used**: the outer composition contains no
commitment-unpredictability reduction and no primitive advantage of its own.

**Challenge 1: `G_1 → G_2`.** Fix the independent oracle functions other than
challenge 1. The current request samples its salt privately, and every
complete challenge-1 location specifies that salt. Its maximum point
probability is therefore at most `2^-256`, also when `c_mult` depends on
salted `H5` evaluations. This is a **marginal location-probability
argument**, not an assertion of conditional entropy after intermediate
fields are revealed; atomic requests prevent such intermediate disclosure.
With `F(q, p) = sqrt(q·p) + (1/2)·q·p`, the fresh-location application of
adaptive reprogramming (Grilo–Hövelmanns–Hülsing–Majenz, Theorem 1) gives

```text
ε_P1 ≤ T · F(Q + T, 2^-256) ≤ (3/2) · T · sqrt( (Q + T) · 2^-256 )      (67)
```

All subsequent computation and oracle access is included. No artificial
simulator failure remains.

**Challenge 2: `G_2 → G_3`.** Challenge 1 is now an independently sampled
2,112-bit string. Before the current atomic request releases anything,
projection of `X_2` onto that component gives

```text
p_max,2 ≤ 2^-2112                                                       (68)
```

The remainder of `X_2` may depend on challenge 1. That cannot increase the
probability of a complete location beyond the probability of its challenge-1
component. For a formal reprogramming embedding, defer the current
challenge-1 oracle write until after sampling and programming the challenge-2
location, using the sampled challenge locally. The domains differ and there
is no intervening adversarial query, so this scheduling change is exact. The
same theorem yields

```text
ε_P2 ≤ T · F(Q + T, 2^-2112) ≤ (3/2) · T · sqrt( (Q + T) · 2^-2112 )    (69)
```

This uses fresh-value reprogramming, including arbitrary later quantum
access. The theorem's fresh-value programming hypothesis must be kept apart
from the witness-dependent assignments removed in section 6.5.1.

**Challenge 3: `G_3 → G_4`.** Define the admissible set

```text
Ω = { y :  y_grind = 0^8,  N_seed(DecodeAllChall3(y)) ≤ 229 },   p = |Ω| / 2^256   (70)
```

where `N_seed(I)` is the number of sibling seeds in the canonical opening
(the review's `S(I)`; its set is written `G` there).

A direct application of a fresh-location theorem to consecutive attempts is
insufficient: they reuse challenge 2. The following counterwise hybrid avoids
that problem. Partition the challenge-3 oracle by its fixed four-byte
counter. The partition is syntactically unambiguous: every challenge-3 input
is exactly 410 bytes, with the counter immediately before the suffix `0b`
(`77 + 104 + 224 + 4 + 1` **[D]**; independent of the relation).

Process the counter domains in order `0, ..., M_ctr − 1`. For each fixed `c`,
replace the reached `c`-th evaluation across all proofs. Earlier counter
domains have already been replaced. For a target request, commute its
other-domain writes past the target-`c` programming operation. Sample earlier
attempted values privately. Whether counter `c` is reached depends only on
these independent sampled values, not on challenge 2. Therefore, even
conditional on reaching `c`,

```text
p_max,3,c ≤ 2^-832                                                      (71)
```

The coefficients can depend on challenge 2; the projection argument still
applies. Previous requests and both roles are already in the conditioning.
At most `T` previous honest calls affect this particular counter domain. A
quantum query spanning several counters may count against every
single-counter reduction, so the conservative bound `Q + T` is used for
**each** domain. Hence

```text
ε_P3 ≤ T · M_ctr · F(Q + T, 2^-832)
     ≤ (3/2) · T · M_ctr · sqrt( (Q + T) · 2^-832 )                     (72)
```

This explicitly charges the worst-case `T · M_ctr` attempted points. It does
not rely on interpreting the displayed G5 charge of Theorem 10.53 as an
already-proved batch bound for this construction.

**Selective opening: `G_4 → G_5`.** In `G_4` the attempted values are
independent uniform samples. Consequently, for the stopping counter `C`,

```text
Pr[C = c] = (1 − p)^c · p    (0 ≤ c < M_ctr),
Pr[GrindingExhausted] = (1 − p)^M_ctr                                   (73)
```

Conditional on `C = c`, the preceding values are independently uniform
outside `Ω` and the accepted value is uniform in `Ω`. Conditional on
exhaustion, all `M_ctr` values are independently uniform outside `Ω`. These
are exact statements about the **programmed game**; their use for the actual
adaptive QROM execution is paid for by (72). The verifier's refusal to check
counter minimality does not remove this simulator obligation.

The selective-opening coupling requires:

| Hypothesis | Check for this protocol |
| --- | --- |
| Admissibility depends only on the challenge | Grinding examines its suffix; opening size is determined by the decoded indices and the fixed tree |
| The selective challenge is uniform conditional on admissibility | Use the uniform distribution on `Ω`, exactly the challenge distribution required by the hiding experiment |
| Commitment coins do not depend on the selected opening | Fresh root and `iv_pre`; opening admissibility is seed-independent |
| Adaptive labels are supported | Supply the actual current `mu_R(x)` |
| No witness-dependent challenge acceptance | Neither relation evaluation nor witness data appears in `Ω` |
| Exhaustion is retained | Discard the selective opening on exhaustion, while retaining the experiment's oracle effects |
| Invocation count is bounded | One selective-hiding invocation per proof request, including exhaustion: at most `T` |

Thus the accepted sample can be replaced by the selective experiment's
independent uniform challenge in `Ω` at zero distributional cost. On
exhaustion, independently sample an unused uniform element of `Ω` to define
the selective experiment and discard its opening.

**CRT hand-over: `G_5 → G_6`.** The hand-over supplies exactly the interface
that section 6.5.1 presupposes: selective opening, independently sampled
challenges, and the complete correctly distributed retry schedule. The order
matters:

1. Enter the ideal correlated-material experiment with its `H5` assignments
   retained.
2. Reparameterize the witness correction using uniform `d`.
3. Solve the six QuickSilver masks from the six sampled transmitted
   coefficients.
4. Compensate the other four masks to obtain the sampled consistency fields.
5. Derive `ã_0` from the verification equation.
6. Retain the resulting hidden `H5` assignments while applying the pad-based
   deletion argument.
7. Delete the unused witness and pad bookkeeping.

Steps 2 to 5 are one joint coordinate change, not independent changes to two
mask groups. They occur inside the current atomic invocation. Each challenge
is programmed at the location computed from that game's final material. No
previously exposed transcript field is subsequently edited. Changes to
previously queryable oracle state are charged by the outer reprogramming
transitions or by the CRT argument; atomicity alone does not make them free.

**Programming counts and numerical bounds.**

| Operation | Location bound used | Number of points |
| --- | ---: | ---: |
| Challenge 1 | `2^-256`, from the salt | `T` |
| Challenge 2 | `2^-2112` | `T` |
| Challenge 3, fixed-counter hybrid | `2^-832` | At most `T · M_ctr = 2^64` |
| Selective-opening coupling | Exact distributional identity | At most `T` invocations |

At `T = 2^44`, `Q = 2^64` (the review's values, reproduced **[D]** from (67),
(69) and (72)):

```text
ε_P1 ≤ 3.3306706621 × 10^-16 = 2^-51.41503681
ε_P2 ≤ 2^-979.41503681
ε_P3 ≤ 2^-319.41503681                                                  (74)
```

All three use the `3/2`-square-root upper bounds. `ε_P1` is the largest known
term of the whole ledger.

**Attempts per proof.** With `K_att` the number of attempts,

```text
E[K_att] = (1 − (1 − p)^M_ctr) / p,        K_att ≤ M_ctr                (75)
```

The reported opening-abort fraction 0.14 gives the estimate
`p ≈ 0.86 / 256 = 0.003359375`, hence

```text
E[K_att] ≈ 297.6744186,        T · E[K_att] ≈ 2^52.2175914              (76)
```

The measurement is not a certified probability lower bound.

A deterministic bound is available without it. For each tree node `v`, let
`n_i(v)` count the vector-`i` leaves below it, with seventeen `N_i = 256` and
sixteen `N_i = 128`, and define `A(v) = prod_i (1 − n_i(v)/N_i)`. Independent
selection of one hidden leaf per vector gives, for the number `N_seed` of
revealed seeds,

```text
E[N_seed] = sum_{v internal} ( A(v_L) + A(v_R) − 2·A(v) )               (77)
```

Evaluating this finite expression for the frozen heap and leaf mapping gives

```text
E[N_seed] =
  100394214806767952210445323089436363695775791427601419753509949431295431340384 / 2^248
  ≈ 221.9574684231 < 222
```

The review reports checking this with exact integer arithmetic. **[D]**
Recomputed here with exact integers from the leaf-position rule of
`crates/iroha_zkp_vole/src/bavc.rs` (`Shape::position`, read as text; fast
row, 6,400 leaves, `tau = 33`); the numerator agrees digit for digit. Opening
rejection requires `N_seed ≥ 230`, so Markov's inequality yields

```text
Pr[N_seed ≤ 229] > 4/115,        p > 1/7360                             (78)
```

(`1 − 222/230 = 4/115`, and the grinding suffix contributes the factor
`2^-8`: `4/(115 · 256) = 1/7360` **[D]**). Consequently
`E[K_att] < 7360`, `T · E[K_att] < 2^56.8454901`, and

```text
Pr[ one programmed-game exhaustion ] ≤ e^(−M_ctr/7360)     = 2^-205.5401352
Pr[ any programmed-game exhaustion ] ≤ T · e^(−M_ctr/7360) = 2^-161.5401352   (79)
```

Exhaustion contributes **zero distinguishing loss**, because the simulator
reproduces it; genuine exhaustion adds no separate term to `Z`. (79) is a
performance and correctness bound of the **programmed** game. Alone it is
not a real-game theorem. The available transfer is

```text
Pr_real[ any exhaustion ] ≤ T · e^(−M_ctr/7360) + ε_P1 + ε_P2 + ε_P3    (80)
```

which needs no CRT primitive loss. (78), (79) and (80) are
candidate-row results: the comparator's different opening geometry does not
inherit the `1/7360` certificate, although its counter rule is the same
bounded, total rule.

Retry ledger with the `2^20` limit (the review's lines; arithmetic
reproduced **[D]**):

| Quantity | Bound |
| --- | ---: |
| Total honest counter attempts `G` | `G ≤ 2^20·T = 2^64` |
| Counter-related Keccak permutations | `4·G ≤ 2^66` |
| Challenge-3 programming `ε_P3` | `(3/2)·T·2^20·sqrt((Q + T)·2^-832) = 2^-319.4150368` |
| Programmed expected attempts per invocation | `(1 − (1 − p)^M_ctr)/p < 7360` |
| Programmed aggregate tail | `Pr[G > 14720·T] ≤ e^(−T/4)` |
| Extra exhaustion-path simulator trials | At most `M_ctr = 2^20` per invocation |
| Bounded-total-simulator correction `σ` | `σ ≤ T·e^(−2·M_ctr/7360) = 2^-367.0802704` |

**One simulator for both roles: `Sim+`.** The final witness-free simulator,
after the CRT transition. It is total and bounded, and it uses one
persistent programmable backend oracle across every request.

```text
Sim+(role, x):

  Compute the frozen role namespace, mu(role, x), and relation dimensions.

  Sample a fresh root r, iv_pre and a 256-bit salt.
  An additional fresh 256-bit pad may be sampled and discarded.
  Compute iv = H4(iv_pre || mu) using the actual namespaced oracle.
  Construct the BAVC commitment from r and iv, with the 128-byte H0 output
  and the 112-byte leaf commitments.

  Sample independent uniform 256-bit values Y_c for c = 0, 1, ... in order.
  Stop at the first Y_c in Ω, or after all 2^20 values.

  On success:
      y_star = the first admissible Y_c.
  On exhaustion:
      try at most 2^20 further independent uniform values and let y_star be
      the first one in Ω; if all fail, y_star = 0^256.
      The opening for y_star will not be returned.

  Obtain the BAVC opening for y_star.
  Sample uniform canonical c_1, ..., c_(tau-1), c_mult, and d.
  Reconstruct Q, q̄, and Δ using this opening and ordinary H5 evaluated
  with the sampled salt.

  Sample uniform chall_1.
  Sample four uniform consistency fields ũ.
  Compute Ṽ from the reconstructed consistency equation.

  Sample uniform chall_2.
  Sample uniform ã_1, ..., ã_6.
  Derive ã_0 from the frozen public verification equation.

  Program challenge 1 at the exact salted X_1.
  Program challenge 2 at the exact X_2.
  Program challenge 3 at EVERY attempted X_3,c with its sampled Y_c.

  On success:
      serialize the exact naked proof with the first successful counter.
  On exhaustion:
      return GrindingExhausted { last: 0x000fffff }.

  Erase private transient material; retain the global oracle state.
```

- The sampled coefficients and reconstructed equations use the selected
  role's actual constraint system, including pad Booleanity. The simulator
  receives no application witness, selected index or application trace.
- The simulator's `H5` oracle has **no hidden-label patches**: their removal
  is the charged CRT transition. Observable-label evaluations remain ordinary
  oracle evaluations. Every `H5` evaluation of the current proof uses its
  sampled salt.
- Programming uses a single consistent overwrite semantics. A repeated
  programmed location is not silently exempted, and the oracle is never reset
  between proofs or roles. The bounds already account for prior queries and
  repeated locations. Exhaustion retains all attempted challenge entries and
  all earlier oracle effects; it does not roll back the request. Simulating
  only the accepted challenge is incorrect.
- **The bounded exhaustion path.** Sampling exactly uniformly from `Ω` has no
  strict worst-case time bound, so on exhaustion `Sim+` makes at most `M_ctr`
  further independent trials and then uses the fallback `0^256`. The fallback
  is admissible: zero indices select leaves `6399, ..., 6431`, whose opening
  reveals 11 seeds, below 229 (the review cites the mapping, the opening
  count and the decoder in `bavc.rs`; the leaf positions and the count of 11
  are reproduced **[D]** from `Shape::position` and the marking rule). The
  extra trials need randomness and admissibility checks, not additional
  challenge-oracle programming. The difference from the exact sampler is

  ```text
  σ ≤ T · (1 − p)^(2·M_ctr) ≤ T · e^(−2·M_ctr/7360) = 2^-367.0802704    (81)
  ```

- **Totality on false statements.** After public syntactic and context
  validation, `Sim+` executes on every public statement of the prescribed
  dimensions, without testing whether an application witness exists: BAVC
  construction, opening and reconstruction use the fixed row and generated
  material; the consistency equations use public reconstructed field values;
  the constraint evaluator is a straight-line polynomial computation defined
  on arbitrary field inputs; the final response is reconstructed as
  `ã_0 = q̃ + sum_{j=1}^{6} ã_j·Δ^j`, with no division by `Δ`; arbitrary
  correctly sized commitment, authorization and nullifier bits introduce no
  undefined arithmetic. The final reconstruction is the verifier operation of
  FAEST's `ZK.OWFVerify` (FAEST v3 Figure 7.19, cited by the review; not read
  by us). This is **algorithmic totality**. The joint zero-knowledge theorem
  concerns valid witnessed statements only; no false-statement
  zero-knowledge claim is needed or made. The credential-side arguments of
  sections 6.2, 6.3, 6.5.3 and 6.8 use the totality.
- The game's identical validation and witness check remain outside this
  algorithm.

**Bound.** With the CRT contribution in the direct generator-to-uniform
formulation of section 6.5.1,

```text
ε_CRT ≤ ε_seed + ε_initial + δ_MH + δ_sep + 2·ε_delete                  (82)

ε_seed ≤ T · e_gen,     e_gen = ε_root + 396·ε_tree + 33·(ε_leaf + ε_expand)   (83)
```

(`396 = 33 · 12` **[D]**; `e_gen` is the review's `e`; `ε_leaf` is the
nine-block leaf experiment.) These CRT assumptions concern, respectively,
the joint two-tweak root output, the hidden-path expansions, the correlated
leaf material and the hidden expanded VOLE rows of the actual lengths. They
retain shared-IV and cross-role PRG correlations. Collecting the known terms
other than challenge 1 in

```text
K_sim = ε_P2 + ε_P3 + ε_initial + δ_MH + δ_sep + 2·ε_delete
```

(the review's `K`), the deployment-wide joint zero-knowledge bound is

```text
Adv_JZK ≤ Z,        Z ≤ ε_P1 + T·e_gen + K_sim + σ                      (84)
```

The component values at the ceilings, the switching subtotal and the nominal
substitution are in section 8.5. **(84) is not an established numerical
value for the complete advantage**: `e_gen` is unquantified, and the
below-1/2 requirement follows only when its value at the resources below
makes (84) below 1/2. Because `ε_P1 > 2^-64`, (84) cannot certify
`2^-64` for any value of `e_gen`.

**Resource accounting.** The query and runtime costs are material:

- Challenge 1, challenge 2 and each fixed-counter challenge-3 reduction: at
  most `Q + T` queries to its target domain.
- Across **all** counter domains: at most `2^64` honest challenge-3
  evaluations. Each challenge-3 input is 410 bytes and requires four
  SHAKE256 permutation calls, at most `2^66` in total.
- One full candidate-row commitment for the vote role uses at most
  `4·6,399 + 9·6,400 + 419·6,400 + 1 = 2,764,797` known-key AES block
  evaluations (the review's figure; the formula is reproduced **[D]** at
  `l^ = 53,584`). Across `T` commitments this is `2^65.3987` AES evaluations
  **[D]**, before adversary work; allowing a commitment and a reconstruction
  per request doubles it. Heavy public verification costs at most 2,750,672
  AES blocks.
- The reduction additionally performs the actual role-specific relation
  computation and transcript processing once per simulated request, and the
  extra exhaustion-path trials of `Sim+`.

The generator terms must therefore be evaluated for the adversary's
resources **plus those costs**; they are not primitive advantages evaluated
merely at the original `2^64`-query adversary budget.

Classification, as the review states it:

- **Proved in its text:** the protocol-specific embeddings, the
  fresh-location challenge-1 comparison, the counterwise reduction, the exact
  stopping and selective-opening coupling, the attempt bound and the
  composition.
- **Imported with checked hypotheses:** adaptive reprogramming and the
  selective-opening distribution.
- **Retained conditional result:** the CRT-layer argument, awaiting
  independent review.
- **Primitive assumptions:** the CRT generator games.
- **Model assumption:** the specified backend oracle domains are
  quantum-accessible random oracles.

The query-dependent QROM privacy losses in (84) are not unconditional
statistical bad-event probabilities. They must not be advertised as a
`2^-128` statistical zero-knowledge guarantee. Exact exhaustion introduces no
bad-event loss; the listed unconditional collision terms (`δ_MH`, `δ_sep`,
`δ_salt`, `σ`) are below the separate `2^-128` lifetime budget. If that
budget were intended to cap every query-dependent privacy hybrid, or every
information-theoretic hybrid distance including the switching subtotal of
section 8.5, this bound would not meet that stronger interpretation.

No IV-collision abort is introduced: the unchanged PRG assumptions must
accommodate repeated IVs, and aborting whenever 128-bit IVs repeat would
introduce an unnecessary lifetime loss. The remaining quantitative primitive
assessment might reject the row; nothing in the outer argument establishes
such a rejection.

#### 6.5.3 Anonymity: association hiding after joint simulation

Status: conditional on `Z` and on assumption `P`. The composition is the
review's restatement for the strengthened vote relation: the challenge
outputs are the 1,024-bit nullifier **and** the vote authorization value.

The environment, its admissibility rules and its exclusions are those of
section 5.2. Each honest handle `j` has one independent uniform 384-bit
secret `s_j`, used only in its original body; all credential functions use
that same secret.

**Model: a concrete-function assumption.** The review chooses a
concrete-function assumption for credential SHAKE and keeps the backend QROM
assumptions. The overall theorem is therefore a mixed-model conditional
theorem. No argument substitutes an abstract random function inside the
concrete Keccak constraint circuit.

Each credential input occupies one padded SHAKE256 rate block (section 1.2),
and both output lengths fit in the first squeezing block. That establishes
the one-permutation implementation shape, not a security bound (FIPS 202
sections 5 and 6, cited by the review; not read by us).

Why an abstract credential oracle is inconsistent. If the credential inputs
were declared to belong to an independent programmable random oracle, there
are two incompatible possibilities:

1. Honest values come from the abstract oracle while the relation still
   enforces concrete Keccak. Honest statements generally cease to have their
   claimed witnesses.
2. The abstract oracle and the concrete evaluation remain separately
   accessible as implementations of the same advertised function. At a known
   chosen secret, an adversary compares their outputs and distinguishes them.

Simulator totality solves an **algorithmic interface problem**, not this
model-consistency problem. A consistent oracle-relative relation and a proof
connecting it to this circuit would be an additional theorem.

**Blanket replacement of honest outputs is invalid under adaptive
corruption.** Take an honest handle that never becomes a challenge candidate:
obtain its commitment, corrupt it, recompute its concrete commitment from the
disclosed secret and test equality. Equality holds with probability one in
the real experiment and with probability `2^-1024` if the commitment was
replaced independently:

```text
Δ_blanket-replacement ≥ 1 − 2^-1024                                     (85)
```

Revealing some different secret cannot generally repair this: the image of a
function with a 384-bit domain contains at most `2^384` commitments, so an
independent 1,024-bit commitment has any opening with probability at most
`2^-640`. "Leave eventually corrupted credentials real" is not an online
algorithm, and predesignating a never-corrupted pool changes the adaptive
game unless a reduction and its costs are supplied. This is why the
experiment of section 5.1 **protects handles online**, tests only fresh
entries of protected handles, never randomizes commitments and neither
predicts future corruptions nor permits later disclosure of a tested key.

**The strengthened vote test.** A sequential operation on handle `j`, scope
`σ` and the other public vote fields `z`:

```text
n ← Test(j, PNF1, σ)
d ← D_v(z, n)
a ← Test(j, PAV1, d)                                                    (86)
```

Its random branch returns

```text
( F_j,PNF1(σ),   F_j,PAV1( D_v(z, F_j,PNF1(σ)) ) )                      (87)
```

- The nullifier entry is indexed by **credential and scope**.
- The authorization entry is indexed by **credential and complete-statement
  digest**.
- Repeating a credential and scope pair repeats its nullifier.
- Different digests select independent authorization entries. They can
  accidentally have equal 512-bit outputs; the game must not reject that
  equality.
- Different votes give different frames. They give different digests only
  outside a SHA3-512 frame collision.

The pair replacement is the restriction of `P` to tests of the form
(86). It is not a separate premise: its advantage is at most
`α_P(ℛ')`, where `ℛ'` includes the digest computation, the two test calls
and the prescribed simulator work.

**Hybrids.** The complete sequence, for the left/right game of section 5.2:

| Transition | Charge |
| --- | ---: |
| Real proofs, challenge bit 0 → the one shared simulator `Sim+` | `Z` |
| Independent honest secrets → distinct honest secrets | `ρ_rep` |
| Concrete challenge pairs → pairs from (87) | `α_P` |
| Switch the challenge bit 0 → 1 | 0 |
| Restore concrete challenge pairs | `α_P` |
| Restore independent secret sampling | `ρ_rep` |
| Restore real proofs | `Z` |

Each proof replacement is **one deployment-wide joint zero-knowledge
application** covering both roles and all requests. On an `LR` request the
reduction reserves both candidates, blocks both candidate scope pairs and
both candidate authorization entries, tests the selected handle by
(86) and invokes the common simulator on the resulting public
statement. It is an online reduction; it guesses neither a challenge handle
nor a future corruption set.

**The zero-cost switch.** Couple the nullifiers by the equality classes of
(27); the resulting public nullifiers and digests coincide. Couple the
authorizations by the classes of (28). The simulator receives
identical public statements, so its state and randomness can be coupled, and
the late-rejection decisions of rule 5 are identical in both worlds.
Induction over the adaptive continuation completes the argument. Accidental
equal outputs require no additional failure event: their distributions are
already identical. The coupling uses exact bytes and needs no collision
exclusion.

**Bound.**

```text
ε_association ≤ 2·α_P + 2·ρ_rep
ε_anonymity, ε_unlinkability ≤ 2·Z + 2·α_P + 2·ρ_rep                    (88)
```

These are deployment-wide terms, not per-proof bounds to multiply by `T`.
`Z` is (84); `α_P` has no established value. **(88) is not a
below-1/2 certificate** until the values of `e_gen` and `α_P` at the full
reduction resources satisfy that inequality.

**The linkage surface added by `auth_v`.** The authorization value is a
comparison surface that a nullifier-only game does not cover: an identified
authorization for the exact candidate digest could identify the challenge.
Rule 5 excludes that attack; identified authorizations at other digests
remain part of the assumption. Equal nullifiers already link ballots at a
scope, including ballots with different votes, and `auth_v` does not conceal
that intentional link.

**Resources.** The reduction runs one complete adversarial execution and the
actual joint simulator; there is no target-guessing factor. `ℛ'` includes
concrete credential generation and the permitted value computations, the
public-context hashing and malicious-submission verification, the simulator
accounting of section 6.5.2, constraint evaluation, framing, table
maintenance, randomness and memory. `α_P` and the backend generator terms
are not advantages evaluated only at the original adversary's `2^64`
queries. `ρ_rep` and `σ` are unconditional statistical losses below
`2^-128`; the query-dependent QROM terms and `α_P` are computational or
model-dependent losses.

What this argument does and does not do:

- It makes the shared-secret public commitment and authorization leakage
  explicit and supplies an online, corruption-compatible real/random game
  sufficient for both privacy properties.
- It proves the composition and the exact ideal challenge-bit switch.
- It **does not discharge `P` as a quantified primitive fact**.

No change to the credential functions follows: the 384-bit secret, the
four-byte tags, the secret-before-public-data layout and the single-block
encoding are kept. Moving or lengthening the secret would not fix the
corruption inconsistency or convert a search theorem into a distinguishing
theorem.

### 6.6 Property 6: concrete security

Status: incomplete. The ledger is assembled in section 8.5: one inequality
per game, the component values at the ceilings, and the terms that remain
unknown (`e_gen`, `α_P`, the three restrictions of `U`, the frame collision
terms, and the concrete justification of the backend oracle model). Under an
explicitly hypothetical nominal substitution for the unknown terms, at a
declared nominal resource normalisation, every game bound is below 1/2. That
substitution is an arithmetic check, not a certificate: no unknown term has
an established value at the actual resource vector. Independently of those
values, the written bounds that contain `Z` cannot certify `2^-64`, because
the challenge-1 programming term alone exceeds it.

### 6.7 Property 7: deterministic bounded verification

Status: conditional (a design argument; not an implementation certificate).
No cryptographic hardness premise is involved; qualification remains
necessary. The standalone descriptor, the proof layout and the length rules
are frozen (section 1 and profile record section 6.1); the
production envelope and the production Norito mappings are not written.

The property is algorithmic. Its proof needs no SHAKE collision resistance,
AES pseudorandomness, soundness or zero knowledge. It needs exact functional
specifications and a bounded implementation.

**Argument.** For a frozen descriptor, define verification as a total
deterministic function of the canonical proof bytes and the authenticated
public context. Each parser operation, hash, AES evaluation, field operation,
index calculation, constraint evaluation and comparison has prescribed
semantics and a finite bound. Induction over that operation sequence proves
identical acceptance results on all conforming hardware.

Premises not yet met: a completed verifier for the frozen construction. The
working-tree crate does not compile the descriptor of section 1.1 **[C]**
(section 1).

**Descriptor contents.** The descriptor is `DESC` of section 1.1, with digest
`D`. It carries:

- `P16`, `ASCII("FAEST-3.0")` and the parameter tuple
  `(lambda, tau, w_grind, T_open, d_zk, n_mult)` of the one accepted row;
- `T_crt`, the digest of the exact CRT tables. The official 704-gate fast-row
  tables are pinned; tables from another generator with a different gate
  count cannot replace them under the same descriptor and size ledger;
- the relation dimensions `(l_reg, M_reg, l_vote, M_vote)`;
- `SUITE`, which immutably names the relations, the constraint ordering, the
  encodings, the transcript and the randomness rules. Those rules are the
  witness order, the Keccak bit order and the complete ordered constraint
  sequence (sections 1.2 to 1.5), including the tautological constraints and
  the homogenisation; every backend hash input and length, the exact proof
  lengths, the padding and the opening order, the sampling of `r`, `iv_pre`,
  the pad and the salt, the counter rule and the aborts (section 1.7).

The preimage of `mu_R` is `PREFIX_R || F_R || hex("08")`, with `F_REG` of
profile record section 6.3 and `F_VOTE` of section 1.1; `F_VOTE` contains the
list bytes `concat(L)`. The public inputs are bounded opaque byte strings.
Norito layouts, flags, field order and nesting are not descriptor content of
the standalone construction: they and the envelope are production obligations
of Core and are not written.

Field encodings are little-endian polynomial coefficients:
`F_(2^256): X^256 + X^10 + X^5 + X^2 + 1` and
`F_(2^768): X^768 + X^19 + X^17 + X^4 + 1` **[R][C]**. Every correctly sized
byte string represents a field element; there is no "scalar below a modulus"
check.

**Malformed-input rules.**

1. Reject oversized input before allocation or expensive decoding.
2. Use checked length arithmetic; never allocate from an unchecked encoded
   count.
3. Require the compiled fixed descriptor, the exact fixed proof length for
   the externally selected row and relation, no row autodetection and no
   trailing bytes. The production envelope and its canonical form are a later
   obligation and are not written.
4. Validate `3 ≤ S ≤ 1,000`, the exact list length, strict ordering,
   uniqueness and authentication to the seal.
5. Reject invalid vote values, an inconsistent public context (a supplied `B`
   that differs from the recomputed one, before proof work), a nullifier or
   authorization value of the wrong length, malformed or insufficient
   openings, nonzero unused padding, a counter above `0x000fffff` (before any
   expensive reconstruction), a third challenge that fails the grinding
   check, and a final challenge mismatch.
6. Charge the fixed worst-case verification work even for late-invalid
   proofs.

No wall-clock timeout, CPU-feature choice, iteration over unordered
containers, floating-point result, randomness, environment variable or
fallback decoding path may determine validity. Accelerated implementations
compute the same functions, and the same operation order wherever order
affects transcript bytes. **Verification hashes the supplied counter once; it
never repeats grinding or loops a number of times given by the counter.**
Resource exhaustion before the arena is available is an operational failure,
not a hardware-dependent decision that a ballot is invalid.

**Fast-row geometry.** `n_Δ = 248`, `N = 17 × 256 + 16 × 128 = 6,400` leaves,
12,799 GGM nodes, ten masks, `n_mult = 704`. The third application
permutation adds no `H5` gate.

**Raw proof layout.** The field table and the totals are in section 1.7. The
fast-row opening holds 33 hidden leaf commitments of 112 bytes and at most
229 seeds in the prescribed reconstruction order, with canonical unused
padding.

**Input caps.** The complete envelope cap is 262,144 bytes and the separate
list-context cap 163,840 bytes; at `S = 1,000` the raw list is 128,000 bytes.
The caps allow at most 425,984 bytes of combined bounded input, not 262,144
**[R][D]**. Public hashing at `S = 1,000`, each reproduced **[D]** from the
`Frame` definition and the 72-byte SHA3-512 rate:

| Frame | Bytes | SHA3-512 permutations |
| --- | ---: | ---: |
| List frame for `R` | 128,114 | 1,780 |
| `Y_v`, the `D_v` preimage, `128·S + 536` | 128,536 | 1,786 |

`F_VOTE` is `128·S + 506` bytes and is absorbed by SHAKE256 inside `mu_VOTE`.

**Work bounds, fast row.** With `l^ = l + 80`: 35,920 (registration) and
53,584 (vote) **[D]**.

| Quantity | Formula | Registration | Vote |
| --- | --- | ---: | ---: |
| AES block encryptions, conservative | `4 × 6,399 + 6,367 × (9 + ceil(l^/128))` | 1,872,026 | 2,750,672 |
| VOLEHash field products | `5·(l + 6) + 4` | 179,234 | 267,554 |
| ZKHash field products | `2·M + 2` | 145,154 | 217,864 |
| Leaf-hash products in `F_(2^768)`, and as many checksum products in `F_(2^256)` | at most 6,367 each | 6,367 | 6,367 |
| Relation permutations | 24 rounds × 1,600 nonlinear products each | 2 (76,800 products) | 3 (115,200 products) |
| Backend SHAKE calls | 1 `H0` + 34 `H1` + 4 transcript-role + 1 `H4` + 704 `H5` | 744 | 744 |
| Additional public `D_v` hashing at `S = 1,000` | SHA3-512 permutations | none | 1,786 |

All values are **[D]** from the review's formulas at the final dimensions,
with nine leaf blocks. The vote AES count equals the review's figure for
heavy public verification; the registration AES count and the checksum
products are ours. The other vote figures equal those the review gave for
the strengthened relation. These are analytical counts, not timing or allocation
certificates; the 250 ms, 64 MiB, phone-time and phone-memory limits are
unchanged. There is no prover-randomness `H3` call. Selector work is bounded
by `S` selector products and `1,024·S` public-bit selections and additions.
Booleanity, equality and degree-lifting work is linear in the frozen witness
and constraint counts; powers of `Δ` through degree seven can be precomputed.
A frozen straight-line constraint schedule supplies the remaining exact
operation tally.

Backend hash inputs, fast row, without the 77-byte role prefix `PREFIX_R`
and with the one suffix byte:

| Hash input | Maximum bytes |
| --- | ---: |
| `H0` | 17 |
| All `H1` inputs combined | 718,946 |
| `H4` | 81 |
| First challenge, registration / vote | 144,417 / 215,073 |
| Second challenge, registration / vote | 5,001 / 7,209 |
| Third challenge | 333 |
| Each `H5` | 85 |
| `mu_R`, registration / vote at `S = 1,000` | 5,947 / 128,507 |

Every row is **[D]** from the bodies and suffix bytes of section 1.7 and
`F_REG`, `F_VOTE`, at `l = 35,840` (registration) and
`l = 53,504` (vote):

- `H0`: `17 = 16 + 1` (`iv`, suffix).
- All `H1` inputs: `718,946 = 6,400 × 112 + 33 × 64 + 34` (the leaf
  commitments over the 33 inner calls, the 33 vector digests of the outer
  call, and one suffix byte for each of the 34 calls).
- `H4`: `81 = 16 + 64 + 1` (`iv_pre`, `mu`, suffix).
- First challenge:
  `64 + 64 + (tau − 1)·l/8 + 880 + 16 + 32 + 1 = 32·l/8 + 1,057` (`mu`,
  `com`, the corrections, `c_mult`, `iv_pre`, `salt`, suffix).
- Second challenge: `264 + 128 + 128 + l/8 + 1 = l/8 + 521` (`chall_1`,
  `ũ`, `Ṽ`, `d`, suffix).
- Third challenge: `333 = 104 + 7 × 32 + 4 + 1` (`chall_2`, `ã_0` to `ã_6`,
  the counter, suffix).
- Each `H5`: `85 = 16 + 32 + 4 + 32 + 1` (`iv`, `salt`, `u32_le(e)`, the
  label, suffix).
- `mu_R`: the maximum of `F_REG` is
  `2 + 14 + 2 + 10 × 4 + 4,096 + 6 × 256 + 64 + 128 + 64 = 5,946` bytes and
  that of `F_VOTE` at `S = 1,000` is
  `2 + 15 + 2 + 9 × 4 + 64 + 64 + 64 + 2 + 128,000 + 128 + 64 + 1 + 64 = 128,506`
  bytes, from the `Frame` definition and the bounds of profile record
  section 6.1 with the 128-byte `nf` and the 64-byte `auth_v`; each takes one
  suffix byte.

With the prefix, the `H5` input is the review's 162 bytes and the
third-challenge input its 410 bytes; the `H0` output is 128 bytes. A SHAKE256
invocation with `m` input bytes, a fixed prefix of `h` bytes and `o > 0`
output bytes uses at most
`floor((m + h)/136) + ceil(o/136)` permutations; here `h = 77`.

**Memory.** A bounded implementation processes one small-VOLE instance at a
time, streams transcripts into hashes and streams constraints into ZKHash.
Principal vote buffers, fast row:

| Buffer | Formula | Bytes |
| --- | --- | ---: |
| Maximum envelope plus list object | `262,144 + 163,840` | 425,984 |
| GGM node seeds, leaf seeds, leaf commitments and marks | `12,799 × 32 + 6,400 × 32 + 6,400 × 112 + 12,799` | 1,343,967 |
| Two maximum-size small-VOLE conversion buffers | `2 × 256 × l^/8` | 3,429,376 |
| Raw small-VOLE columns | `248 × l^/8` | 1,661,104 |
| Full-field witness keys | `32·l` | 1,712,128 |
| Optional materialized constraint vector | `32·M` | 3,485,792 |
| Three Keccak field-state buffers | `3 × 1,600 × 32` | 153,600 |
| Selector products and five packed CRT matrices | not reconstructed | 114,752 |
| **Subtotal** | | **12,326,703** |

The review gave buffer totals without formulas and gave none for the
strengthened relation. The formulas shown are ours **[D]**: each was fitted
to a figure the review gave for other dimensions, is unconfirmed against an
implementation, and is evaluated here at `l = 53,504`, `M = 108,931`. The
Keccak-buffer row is carried unchanged on the judgement that the permutations
are evaluated one after another and need no further state buffer **[E]**. The
last row could not be reconstructed; it is the review's figure **[R]**,
carried on the judgement that selector products and CRT matrices do not
depend on `l` or `M` **[E]**. The optional constraint vector is eliminated by
streaming. One architecture reserves a 64 MiB arena before verification with
fixed regions for bounded inputs, BAVC, VOLE conversion, field and relation
work, tables and auxiliary storage; no per-gate heap allocation or recursive
tree traversal is needed. The subtotal is not a complete allocation
certificate: decoder metadata, alignment, provider scratch space, stack and
the exact public-input schema are not inventoried.

**Omitted pending measurement or implementation.**

- The small-VOLE conversion byte-XOR count. The review states a figure with
  no operation model; the fit `2 × 6,367 × l^/8` would give 57,175,660
  (registration) and 85,292,332 (vote) **[D]**, not recorded as a bound.
- A registration buffer table, small-row work, hash-input and buffer figures,
  and every time figure. None was given by the review at the final
  dimensions.

Remaining evidence: the production envelope and Norito mappings; the
implemented frozen construction; a completed parser and verifier; complete
arena and work accounting; independent field and CRT checks and backend
conformance vectors; scalar, x86 and ARM parity; malformed-input and
late-failure tests; cold-context measurements at `S = 3`, 500 and 1,000. The
250 ms requirement is a separate measurement on the validator baseline;
boundedness alone does not establish it.

### 6.8 Property 8: registration authorization

Status: conditional on adaptive registration soundness, `U` (commitment
restriction at registration-origin targets), registration-frame collision
resistance, `Z` and `P`. The route is the opening-uniqueness route. It
requires no extractor, no uniform-commitment replacement and no programming
of the credential functions.

**Frames and logs.** Write

```text
Y(x) = Frame("PARL/REG-AUTH/v1"; ...),    d(x) = SHA3-512(Y(x))
```

where `Y` contains every registration field except `auth`, exactly as in the
`D_reg` preimage of section 1.1; `d(x)` is the `D_reg` of the statement `x`.
`RegLog[j]` and `AuthLog[j]` are kept per honest handle under the logging
rule of section 5.1.

**Event split.** Consider a winning output `(j, x*, π*)` of the property 8
game, with `d* = d(x*)`.

1. If `x*` is false, it belongs to the adaptive false-statement soundness
   event.
2. Otherwise a witness `s'` satisfies its commitment and authorization
   equations.
3. Outside the target-opening ambiguity event

   ```text
   BadOpen = { ∃ s' ≠ s_j :  Com_(B*)(s') = Com_(B*)(s_j) }
   ```

   that witness must be `s_j`. Therefore `auth* = Auth_(d*)(s_j)`.
4. Suppose `d* ∈ AuthLog[j]`, associated with a logged statement `x_0`.
   - If `Y(x*) ≠ Y(x_0)`, these are two distinct SHA3-512 preimages with the
     same digest.
   - If the frames agree, injective framing gives equality of every statement
     field except possibly `auth`.
   - If `auth` agrees too, this is exact-statement replay and cannot win.
   - If `auth` differs, honest-log correctness and opening uniqueness make
     `x*` false: the unique opening forces the logged authorization value.
5. Thus a true fresh win outside these bad events yields a correct
   authorization value on a fresh **pair `(j, d*)`**. The digest need not be
   globally fresh across other handles.

The resulting inclusion in the real game:

```text
Win_8 ⊆ FalseAccepted_reg ∪ BadOpen ∪ FrameCollision ∪ FreshAuthCorrect   (89)
```

**Premises**, complete for this route:

| Premise | Originating experiment or rule |
| --- | --- |
| Public validation, encoding equivalence, injective framing, fixed descriptor, honest log correctness and disclosure restrictions | The deterministic construction and the rules of the property 8 game |
| Target-opening uniqueness | The restriction `δ_Com,target` of `U` for the adversarially selected target context `B*`, **including a recontextualization that has never been sealed** |
| Adaptive registration soundness with both honest proof interfaces | A win on an accepted registration statement outside the language (section 6.1) |
| Quantum collision resistance of SHA3-512 on legal registration frames | Output of distinct `Y`, `Y'` with equal SHA3-512 digests |
| Joint simulation | The arbitrary-application-witness game of section 5.2 |
| `P` | Section 8.4, at the resources `ℛ_R'` of the prediction reduction `Pred_R` of section 6.2 |

- The uniqueness premise is **existential almost-injectivity**, not ordinary
  computational collision resistance. Without extraction a collision-finding
  assumption cannot replace it. A bound for sealed contexts alone is
  insufficient for this property.
- The soundness premise is the Fiat–Shamir, adaptive statement with both
  honest proof oracles; section 4 is the interactive response-graph statement
  only.
- The prediction game covers adversarial exploration of contexts; a union
  bound over only the contexts eventually published does not justify that
  exploration.

**Bound.** Apply joint zero knowledge to the efficiently checkable
`FreshAuthCorrect` event, whose challenger knows the honest keys, then
(42). Do not apply it to deciding whether an arbitrary statement is
false or has another opening.

```text
ε_8 ≤ ε_snd,mix + δ_Com,target + ε_CR,REG + Z + α_P + ρ_rep + g_R       (90)
```

with `g_R = q_guess,R · 2^-512` and the work and oracle queries of every
reduction charged. The terms bound, in order, `FalseAccepted_reg`, `BadOpen`,
`FrameCollision`, the joint simulation step and the prediction game.
`δ_Com,target`, `ε_CR,REG` and `α_P` have no established value.

**The counting fact, and the route it does not open.** For every fixed `B`,
even for concrete SHAKE, `|im Com_B| ≤ 2^384`, hence

```text
Pr_{Y ← {0,1}^1024}[ Y ∈ im Com_B ] ≤ 2^-640                            (91)
```

This is unconditional counting, so the absence of the AES restriction is not
intrinsically fatal to a false-instance argument for registration. The review
also sketched such a route: simulate the target's proofs, replace its
commitment by a uniform value with dependent lists, digests and messages
updated, show that a fresh forgery cannot exploit earlier programmed
transcript locations, apply soundness outside (91), and account for adaptive
target selection and corruption. **It is not the adopted route and is
unproven.** The replacement needs a correlated-output pseudorandomness
argument whose auxiliary information includes nullifiers, authorization
values and both proof types, and it meets the objection of section 6.5.3 to
replacing an honest commitment that may later be opened. The localization
step is a freshness argument under oracle programming, which ordinary
soundness does not imply.

## 7. Audit of imported results

References are to the FAEST v3.0 specification unless another source is
named. "May be used" is conditional on checking the stated local hypotheses
for the actual lengths, tables and randomness. Every reading of a lemma or
theorem below is the review's.

| Result | What is used | What is not used |
| --- | --- | --- |
| Lemmas 4.6, 4.7 (VOLEHash, ZKHash) | The proof technique, re-derived as (13) and (14) | The lemmas as stated: their dimension hypotheses fail |
| Lemma 7.3 (polynomial roots) | The root step for a fixed nonzero polynomial of degree ≤ 7 and the independently sampled raw challenge, after the degree and challenge checks | — |
| Figure 7.19 (`ZK.OWFVerify`) | The verifier's reconstruction of `ã_0`, which is defined on arbitrary field inputs with no division by `Δ` (simulator totality, section 6.5.2) | — |
| BAVC structural conditions | The row satisfies `tau > 1`, `3·N_i > 2`, `(tau + 1)·2^8 < 2^31` | As a certificate of the implemented CRT maps or their primitive bounds |
| Lemma 10.26, Corollary 10.27 | The affine-line argument with the revised hash error; (15) and the extraction map give the required extension | — |
| Lemma 10.40 | `d_zk = 7` satisfies its degree choice; the response-graph proof of section 4 re-establishes it, with section 2 replacing the relation step | The lemma as stated: its relation and dimension hypotheses fail |
| Theorem 10.30, Corollary 10.41 | — | Their signature-security conclusions are not imported |
| Lemma 10.44 (compressed-oracle witness search) | The bound (36) for a predicate with `m`-local witnesses and local transition bound `δ(k)`, applied to the predicate (33) with the 38-cell certificates and (35), over independent random-oracle domains encoded as one oracle (section 6.1) | — |
| Lemma 10.48 (leaf and core decomposition) | The decomposition is examined | Its passive-prefix and isolation conclusion is **not** used to skip the late `H4` and `H0` transitions; the argument conditions on global induced-seed uniqueness instead |
| Lemma 10.49, sections 10.11.7 to 10.11.9, Theorem 10.46 (static false-statement soundness) | The static shape (30) as a comparison. The query count `Q = Q~ + 85` of Lemma 10.49 is that of its explicit-leaf intermediate experiment; the compact proof uses `Q~ + 125` (section 8.3) | As an adaptive ballot theorem, as a multi-user game or as knowledge extraction; the offset 85 as the compact-proof offset |
| Lemma 10.50 | Only the acceptance-preserving conversion from a compact proof to its reconstructed explicit transcript | Its OWF and key-distribution argument, with its primitive advantage and false-instance-density factor: the winning condition here already specifies a false statement. The relations have no key restriction and the list relation has no lossy-key step (section 6.2) |
| Lemmas 10.24, 10.51 (multi-hiding; sections 10.5.2 and 10.11.10) | Steps 1 to 5 of the seed and initial CRT hybrids (section 6.5.1): ideal VOLE material with consistent `H5` programming, in the specified selective-opening experiment, at the actual lengths; the published quantum programming term (57) and the exceptional terms (58), as the review reports them for that construction (the review names no theorem for (57)). Arbitrary expanded witness length is permitted in that formulation | As joint quantum zero knowledge; as a consequence of "the first `lambda` witness bits are uniform", which is not a hypothesis of Lemma 10.51; as everlasting secrecy of the opposite labels. The review has not restated these steps for the salted `H5` and the nine-block leaf expansion |
| Lemma 10.52 (commitment-list unpredictability) | — | Not used: the salt gives the challenge-1 location bound directly (section 6.5.2) |
| Theorem 10.42 (games G5, G6) | The retry and opening coupling, structurally: admissibility depends only on the challenge, so the selective hiding challenge can occupy the first successful counter (`G_4 → G_5`, section 6.5.2) | As a theorem about this joint application-witness game |
| Theorem 10.53, Corollary 10.54 (QROM, chosen message) | The game sequence as a template. (72) charges every attempted counter explicitly and does not rely on the displayed G5 charge as a batch bound. The formula of Corollary 10.54 as a numerical comparison only (section 8.3) | No direct transfer to this construction, to two proof types under one secret or to its multi-user games: they are single-key results for plain FAEST |
| Section 10.11.6 (single-attempt formulation, random `r` and `iv_pre`, fixed `H5`) | The verifier's acceptance predicate is unaffected by the honest retry behaviour | As a description of the honest transcript distribution in zero-knowledge reductions |
| Jaeger, arXiv 2511.16009, Theorem 2.1 and section 1.1 (fixed-permutation one-way-to-hiding); not read by us | The deletion bound (63): two fixed reversible lookups whose table inputs evolve adaptively, differing only at the recorded hidden points | A fixed-hidden-point theorem; any claim of post-query conditional entropy |
| Grilo–Hövelmanns–Hülsing–Majenz, Theorem 1 (adaptive reprogramming); read by us in part | The loss form `sum_r ( sqrt(q^_r · p_max,r) + (1/2)·q^_r · p_max,r )` for fresh-value programming, with the location bounds `2^-256` (salt), (68) and (71) supplied separately | The location-distribution bounds themselves, which the theorem does not supply; programming of witness-dependent values, which is the deletion argument's subject |
| Bennett–Bernstein–Brassard–Vazirani, section 3 (hybrid argument); not read by us | The quantum query hybrid method with time-dependent modified answers, for the ideal-table lemma of section 8.2 | As a bound for the concrete credential functions; as an equation of prediction with key recovery |
| Don–Fehr–Majenz, Corollaries 13 and 15 (multi-round measure-and-reprogram); read by us in part | Only in section 10, where the resulting bound is shown to be vacuous at this row | As a qualification route |
| Don–Fehr–Majenz–Schaffner, online extractability (Theorem 4.3) and commit-and-open (Definition 3.5, Theorems 4.2 and 5.2); profile record section 13 for the reading status | Only in section 10, as the published primitives an extraction variant would need | Not used by any adopted argument |

**Retry loop.** FAEST's published analysis addresses the retry loop
(Theorems 10.42 and 10.53). Its final signature theorems are not direct
theorems about this joint application-witness zero-knowledge game; the
extension to this protocol is the outer composition of section 6.5.2, which
awaits review.

**Literature on the credential functions.** The review's assessment of what
published sponge results give for assumptions `P` and `U`. **None of these
papers was read by us**; every entry, including each number, is the review's
reading. None is imported as a premise of an argument in this file.

| Source, as cited by the review | Result and numerical consequence, as the review reads it | Applicability |
| --- | --- | --- |
| Bertoni–Daemen–Peeters–Van Assche, 2008, Theorem 2 | Classical sponge indifferentiability, including inverse permutation queries. With `N` total primitive calls, `r = 1088`, `c = 512`: `ε ≤ N·(N + 1) / (2^513 · (1 − (N − 1)·2^-1600))`, about `2^-385` at `N = 2^64`. All keys share one global query inventory; no additional `U` multiplier | Not a quantum theorem |
| Alagic–Carolan–Majenz–Tokat, 2025, Theorem 7.22 | Full permutation-based sponge with quantum permutation **and inverse-permutation** access; bound `O( ℓ^2·sqrt(q^9·2^-min(r,c)) + ℓ^3·(q^5·2^-min(r,c))^(1/4) )`. At `ℓ = 1`, `q = 2^64`, `c = 512` the displayed terms are `O(2^32 + 2^-48)` | Vacuous here. Full quantum sponge indifferentiability is therefore not an open existence question, but this bound does not qualify the deployment |
| Carolan–Poremba–Zhandry, Theorem 8.1 | A special one-round result, `O(2^(-r/2))`, under its `r ≤ c` hypothesis and its reset and shared-randomness model | SHAKE256 has `1088 > 512`; direct substitution is invalid, and one-block use does not remove the hypothesis |
| Gaži–Pietrzak–Tessaro, 2015, Theorems 2 and 3 | Classical keyed-sponge PRF bounds for a construction that absorbs key and message in separate blocks; the paper discusses extending to mixed blocks without giving the extension | The tag, secret and context here share one block. No directly applicable quantum numerical bound for `P` |
| Hosoyamada, 2025 (ePrint 2025/1059); the review read the abstract only | Quantum results for keyed sponges and KMAC, with a KMAC regime of about `min(2^(c/3), 2^(r/2), 2^((κ−r)/2))`. Naively inserting `c = 512`, `r = 1088`, `κ = 384` gives a vacuous `2^-352` term | Not an attack on this construction: the encoding and hypotheses differ. The review did not verify the full theorem and does not import it **[U]** |
| Carolan–Majenz, September 2026 (arXiv 2609.28469), Theorem 5.5 | Explicit **search** bounds for an ideal invertible permutation, digest length `d ≤ r`, `Q' = q + 2L`: preimage `64·Q'^2·2^-d + 128·Q'^3·2^-c + 32768·Q'^2·2^-1600`; collision `32·Q'^3·2^-d + 128·Q'^3·2^-c + 32768·Q'^2·2^-1600`. At `Q' ≈ 2^64`, `c = 512`: preimage terms `2^-378 + 2^-313 + 2^-1457` (`d = 512`) and `2^-890 + 2^-313 + 2^-1457` (`d = 1024`); collision terms `2^-315 + 2^-313 + 2^-1457` and `2^-827 + 2^-313 + 2^-1457` | Neither `P` nor `U`. The preimage target must be independent of the permutation; a `2^34`-target union would add 34 to the exponents, but commitment-derived targets do not automatically meet that premise. Global collision search needs no `U` factor. The query convention and the output-evaluation overhead must be preserved. Supports the ideal-sponge shape of the frame-collision substitution of section 8.5 (for SHA3-512: capacity 1,024, rate 576) |

The remaining heuristic is specific: replacing an ideal sampled permutation
or random table by the fixed public Keccak-f[1600] construction in the
leakage, corruption and selected-context games of `P` and `U`. Keccak-f is
not a secret-key PRP instance. Output length, standardized padding,
conformance vectors and classical indifferentiability do not discharge that
replacement.

Not relied upon: Baum et al., ePrint 2026/164. The review reached the landing
page only; no theorem that appears only in that paper is used.

## 8. Numeric ledger

**The complete ledger is unestablished.** The fast row meets neither the
earlier contract nor the recalibrated contract today. Every required game now
has a written deployment-wide inequality (section 8.5), but each contains
terms without an established value at the actual resources, each rests on
arguments that no one has independently reviewed, and the attack-cost
assessment does not exist. This is not evidence of an attack. **No term
below gives a completed certificate.**

### 8.1 Contract and lifetime ceilings

The earlier contract (profile record section 8.8) required at least `2^128`
total quantum queries for any break with success or distinguishing gap at
least 1/2. The review's reconciling decisions recommend replacing it by two
requirements. **This expressly weakens the earlier proven `2^128`-query
requirement, and that weakening stands.** The 64/128 split is the review's
recommended policy; it is not a theorem and not an equivalent restatement of
the earlier contract. The review's later decision keeps the numerical
contract unchanged.

- **Proven-bound requirement.** Every required computational game has a
  complete, applicable deployment-wide bound below 1/2 at an adversary budget
  of `2^64` quantum queries, including both relations, all lifetime ceilings,
  concrete primitive terms and all actual proving, simulation, verification
  and reduction query and time overhead. No extractor is accounted for,
  because none is required. The largest budgets justified at advantage
  `2^-64` and at advantage 1/2 are recorded.
- **Attack-cost requirement.** Independent cryptanalysis finds no attack with
  forgery success or anonymity distinguishing gap at least 1/2 below `2^128`
  total elementary gates, counting classical and quantum work, preprocessing,
  coherent lookup, QRAM construction and use, and all parallel processors.
  Primitive evaluations are expanded into circuits; queries, depth and memory
  are reported separately.

Unchanged:

| Quantity | Ceiling |
| --- | ---: |
| Unconditional statistical bad-event budget | ≤ `2^-128` over the lifetime |
| Archive horizon | 100 years per network and profile instance |
| Body scopes `J` | ≤ `2^24` |
| Sealed seats per body `S` | ≤ 1,000 |
| Registrations, including alternates `U` | ≤ `2^34` |
| Honest prover transcripts per credential | ≤ `2^10` |
| Total registration plus ballot transcripts `T` | ≤ `2^44` |

`1,000 × 2^24 = 16,777,216,000 < 2^34`. The ceilings overlap and are not
multiplied together; the horizon adds no factor once event counts are bounded.

Context for the recalibration, cited by the second-opinion review and not read
by us: Kiltz–Lyubashevsky–Schaffner, Theorem 3.1 and section 4.4, give for the
paper's Dilithium-QROM a conditional single-key bound whose Fiat–Shamir term
is `q_H^2 · 2^-261`, that is `2^-5` at `q_H = 2^128`. Non-vacuity of that
bound remains conditional on the primitive advantages (MLWE and the sampler
PRF); the result is not about current ML-DSA and not about the ballot's
multi-user contract. NIST category 5 concerns comparison with AES-256 attack
resources and asserts no literal query theorem.

Current compliance: the complete proven floor and the complete deployment
attack-cost assessment are **both unestablished**. Neither may be replaced by
the comparison arithmetic of section 8.3 or by the nominal substitution of
section 8.5.

### 8.2 Statistical and ideal-model entries

| Quantity | Value and qualification |
| --- | --- |
| Unconditional terms of the ledger: `ρ_rep` (22), `δ_leaf,all` (31), `δ_salt` (61), `σ` (81), `δ_MH` (58), `δ_sep` (65) | Values in section 8.5; each is below `2^-128`. `δ_leaf,all` holds for any deterministic leaf PRG; `σ` is a candidate-row bound |
| Any programmed-game exhaustion | `≤ 2^-161.5401352`; a performance bound of the programmed game, not a hybrid loss and not a real-game theorem (79) |
| Generic 512-bit quantum-collision scaling `q^3 / 2^512` | `2^-128` at `q = 2^128` **[R]**, `2^-320` at `q = 2^64` **[D]**; before theorem constants and overhead; not a concrete-SHA3 certificate. Relevant to the frame collision assumptions |
| Direct generator-to-uniform switching subtotal `D_sw` | `1.49586152902 × 10^-19`; an information-theoretic hybrid distance, above `2^-128` (96) |

`D_sw` is not below the `2^-128` statistical budget: if the budget is read
as covering **every information-theoretic hybrid distance**, the direct
switching subtotal fails it. That distance stays visible; the PRP-native
formulation needs its own stated justification and does not turn a
statistical distance into a computational one.

**The ideal-table lemma.** A separately justified ideal-model calculation
about a random function indexed by hidden secret rows. It is **not** about
the concrete sponge or a publicly accessible random permutation, it supplies
no public inverse-permutation access and no bridge to concrete Keccak-f, and
it is a diagnostic for an explicitly different model. Let

```text
N = 2^384,        μ = U / (N − U),        g = q_guess · 2^-512
```

Presample distinct secret locations `s_j`, independent per-handle tables
`F_j(t, x)` and a base oracle `H_0(s, t, x)`. The real ideal oracle equals
`F_j` on row `s_j` and `H_0` elsewhere. The proof uses a time-dependent
reference oracle that answers from `H_0` on undisclosed rows and from `F_j`
on disclosed rows; at a corruption it starts using the disclosed row's
table. The reference invariant: conditional on the revealed locations, the
remaining secret locations are uniform over the unused positions and
independent of the reference quantum state, the public table entries and the
simulator state. Public table disclosures do not depend on locations, and an
adaptive corruption reveals one location and preserves the invariant for the
others. The real and reference query operators differ only on undisclosed
rows, whose expected query mass is at most `μ`; telescoping gives
`‖Ψ_real − Ψ_ref‖_2 ≤ 2·q·sqrt(μ)`. In the reference experiment fresh
authorization guesses succeed with probability at most `g`. The success
projector and the triangle inequality give the **prediction benchmark**

```text
p_pred^ideal ≤ ( sqrt(g) + 2·q·sqrt(μ) )^2                              (92)
```

and, when `g ≤ μ` as at the ceilings,

```text
p_pred^ideal ≤ q_guess · 2^-512 + (2·q + 1)^2 · U / (2^384 − U)         (93)
```

At `q = 2^64`, `U = 2^34` the search term is
`(2^-220 + 2^-284 + 2^-350) / (1 − 2^-350)`; a single blind guess adds
`2^-512`, and `2^44` guesses add `2^-468`. This is a derived application of
the quantum query hybrid method, which permits time-dependent modified
answers (Bennett–Bernstein–Brassard–Vazirani, section 3, cited by the
review; not read by us). It does not equate prediction with key recovery.

Two reference hybrids similarly give the conservative **distinguishing
benchmark**

```text
α_P^ideal ≤ 4·q·sqrt( U / (2^384 − U) ) ≈ 2^-109      (q = 2^64)        (94)
```

The prediction benchmark has a search-order term; the distinguishing
benchmark has a square-root loss. **They must not be interchanged**, and
neither is a bound for the concrete functions or a substitute for `α_P`.

**Ideal-map diagnostics for the uniqueness assumption `U`.** For a
fixed-context ideal random map `{0,1}^384 → {0,1}^1024`, which is the shape
of both `Com_B` and `Tag_scope`, with the contexts fixed independently. Each
bound is reproduced **[D]**.

| Event | Ideal-map bound |
| --- | ---: |
| One whole secret-domain map is noninjective | `≤ 2^-257 − 2^-641` |
| The same over `2^24` fixed contexts | `< 2^-233` |
| Another opening of one fixed honest output | `< 2^-640` |
| The same over `2^34` fixed target and context pairs | `< 2^-606` |
| The same over `2^44` fixed target and scope pairs | `< 2^-596` |

For `m` fixed contexts the bound is `m · binom(2^384, 2) · 2^-1024`. For a
random permutation followed by 1,024-bit truncation the pair-collision
probability is `(2^576 − 1)/(2^1600 − 1) < 2^-1024`, so the same upper
bounds apply. **These do not prove the adaptively selected-context bounds**:
adaptive quantum selection and the structure of the actual sponge must be
addressed, the bounds cannot be multiplied by the number of adversarially
selected contexts without analysing that selection, and requesting 1,024
output bits from SHAKE256 does not by itself establish an ideal 1,024-bit
random-map claim for the concrete sponge.

Why 1,024 bits for the nullifier. At 512 bits the expected number of
colliding secret pairs in one whole map is about `2^255`; a fixed honest
target's alternative-opening probability is about `2^-128`; and the union
bound over `2^44` fixed pairs is only about `2^-84`, which fails the
statistical budget. Nor should commitment injectivity be assumed
simultaneously for **every** 512-bit context: the ideal-map expectation of
same-context colliding pairs across the entire context space is about
`2^255`.

**The interactive component sum is not lifetime soundness.** The union bound
of section 4 over at most `T` independently challenged executions, about
`2^-208.99996` for the fast-row vote relation, counts honest prover
transcripts, not adversarial attempts. Fiat–Shamir challenges are searchable
oracle outputs; the query-dependent analysis of section 6.1 cannot be
replaced by multiplying an interactive error by `T`. Likewise the birthday
probability for 128-bit IVs is not automatically a failure term; the
arguments of section 6.5 introduce no IV-collision abort.

### 8.3 Comparison with the published formula

A numerical diagnostic only. It substitutes the lifetime transcript ceiling
into FAEST v3 Corollary 10.54 as if all `T` transcripts were one key's signing
queries. That is a comparison with a published single-user formula, not a
proved multi-user reduction, and the corollary is not established for the
ballot relations. None of its terms depends on the relation dimensions except
the multiplier `ρ_PRP`.

Quadratic coefficients, which must not be confused:

| Bound | Quadratic coefficient | Origin |
| --- | ---: | --- |
| Static false-statement shape, no lossy factor | 400 | `10·(tau + d_zk) = 10 × 40` |
| Static shape with FAEST's worst-case factor four | 1,600 | `4 × 400` |
| Full chosen-message comparison | 3,200 | `8 × 10 × (33 + 7)` |

The conditional static bound of the published shape is
`eps_static(Q) ≤ 340·Q^3·2^-512 + 400·Q^2·2^-256`, where `Q~` is the
adversary's oracle-query count and the offset between `Q` and `Q~` depends on
the experiment:

| Experiment | Offset | Use |
| --- | --- | --- |
| Explicit-leaf intermediate of Lemma 10.49 | `Q = Q~ + 2·tau + d_zk + 12 = Q~ + 85` | Only where that intermediate experiment is explicitly identified |
| Compact proof | `Q_compact = Q~ + 125` | The static comparison for the compact proof of this record |
| Chosen-message comparison below | `Q_comparison = q + 37·T + 125` | The table of this section |
| Adaptive soundness argument | (38) | Section 6.1 |

Accounting of the 85 of Lemma 10.49: `40 + 38 + 7`, that is `tau + 7`
challenge-recomputation queries, `tau + 5` local-witness overhead and the
`d_zk` slack retained by the lemma's statement. The latter two are not
additional protocol hash calls. Conversion from the compact proof to explicit
leaves adds another `tau + 7 = 40` calls:

| Oracle | Additional calls |
| --- | ---: |
| `H0` | 1 |
| `H1` | `tau + 1 = 34` |
| `H2^mu`, `H2^1`, `H2^2`, `H2^3` | 1 each |
| `H4` | 1 |

There are also `n_mult` calls to `H5`, outside this particular sum for `Q`.
The review states that this reconciles Lemmas 10.49 and 10.50 with
Corollary 10.54 (FAEST v3.0 specification, around page 130); the lemma
statements are the review's reading, not verified by us. The arithmetic
recomputes **[D]** at `tau = 33`, `d_zk = 7`: `2·33 + 7 + 12 = 85`,
`40 + 38 + 7 = 85`, `1 + 34 + 4 + 1 = 40` and `85 + 40 = 125`, which equals
the constant `3·tau + d_zk + 19` of the published query offset. The
coefficients 340 and 400 recompute **[D]** from the published key-only
formula quoted in profile record section 8.1: `340 = 10·(tau + 1)`,
`400 = 10·(tau + d_zk)` and, below, `2720 = 8 × 340`. **This remains a
conditional comparison, not an established adaptive ballot bound.**

Inputs: `T = 2^44`, `n = 704`, `h = 37·T + 125 ≈ 2^49.21`, `Q = q + h`, where
`q` is the external adversary budget. The offset `h` is the published query
offset `(tau + 4)·Q_sig + 3·tau + d_zk + 19` of profile record section 8.1 at
`Q_sig = T` **[D]**; its constant 125 is the compact-proof offset above.
Individual oracle counts are bounded by `q`, and `Q_2,0 + Q_2,1 ≤ q`; the two
square-root rows marked † separate one published term using
`sqrt(x + y) ≤ sqrt(x) + sqrt(y)`. Boundary columns give `log2 q` at which the
term alone equals the threshold **[R]**, reproduced **[D]**; the value columns
are **[D]** (the `2^128` column also **[R]**). The boundaries are rounded
logarithms; the exact cutoff is the positive root of the expression set equal
to the threshold `p_thr`, for the first row
`q* = sqrt(p_thr·2^256/3200) − h`, and the largest budget satisfying the
strict inequality is `ceil(q*) − 1`.

| Term | `log2` value at `q = 2^64` | `log2` value at `q = 2^128` | Boundary for `2^-64` | Boundary for 1/2 |
| --- | ---: | ---: | ---: | ---: |
| `3200·Q^2 / 2^256` | −116.356 | +11.644 | 90.178072 | 121.678072 |
| `2720·Q^3 / 2^512` | −308.590 | −116.590609 | 145.530203 | 166.530203 |
| † `6·sqrt(3)·T·q^(1/4) / 2^128` | −64.622556 | −48.622556 | 66.490225 | 318.490225 |
| † `6·T·sqrt(q) / 2^256` | −177.415037 | −145.415037 | 290.830075 | 416.830075 |
| `2·T·(q + 3)^2 / 2^512` | −339.000 | −211.000 | 201.500000 | 233.000000 |
| `3·T·sqrt((T + q) / 2^2112)` | −978.415 | −946.415037 | 1892.830075 | 2018.830075 |
| `3·T·sqrt((T + q) / 2^832)` | −338.415 | −306.415037 | 612.830075 | 738.830075 |
| `24·n·sqrt((q + n·T) / 2^384)` | −145.955 | −113.955606 | 227.911212 | 353.911212 |
| `3·T·sqrt(256·n·q / 2^384)` | −105.685322 | −73.685322 | 147.370643 | 273.370643 |

Four constant terms are below both thresholds for every `q`:
`16·n·2^-256 = 2^-242.540568`, `2^-255`, `2·T·2^-256 = 2^-211` and
`4·256·n·T^2·2^-384 = 2^-276.540568`. The very large formal roots are
arithmetic results, not assertions that a theorem applies at those budgets.

The numerical-only subtotal, with every primitive advantage set to zero:

- crosses `2^-64` near `q = 2^66.490225` and 1/2 near `q = 2^121.678072`;
- at `q = 2^64` is about `2^-64.622556`;
- at `q = 2^128` is about `3200 + 2.30757 × 10^-15`, so it yields only the
  probability bound 1.

Isolated static quadratic terms, as `log2 Q`:

| Coefficient | Boundary for `2^-64` | Boundary for 1/2 |
| ---: | ---: | ---: |
| 400 | 91.678072 | 123.178072 |
| 1,600 | 90.678072 | 122.178072 |

The PRP switching multiplier of the comparison is `ρ_PRP` of (59). It is
multiplicative, not an additive probability term, and `ρ_PRP < 2` at the
final witness lengths.

The comparison also contains primitive terms:

```text
8·δ_OWF + 2·T·δ_H3 + 2·T·{δ_root + 33·(12·δ_tree + δ_leaf)}
        + 6·T·sqrt(13·δ_tree + δ_leafcommit)
```

the quantum PRF and PRP advantages of the actual reduction adversaries; the
leaf term includes the multi-query leaf-expansion advantage and the
witness-length expansion advantage. They cannot be assigned query cutoffs
without concrete bounds on those adversaries, and none has a justified value
merely because its implementation uses AES-256.

| Primitive term | Requirement for `< 2^-64` | Requirement for `< 1/2` |
| --- | --- | --- |
| `8·δ_OWF` | `δ_OWF < 2^-67` | `δ_OWF < 2^-4` |
| `2·T·δ_H3` | `δ_H3 < 2^-109` | `δ_H3 < 2^-46` |
| `2·T·[δ_root + 33·(12·δ_tree + δ_leaf)]` | Bracket `< 2^-109` | Bracket `< 2^-46` |
| `6·T·sqrt(13·δ_tree + δ_leafcommit)` | Radicand `< 2^-221.169925` | Radicand `< 2^-95.169925` |

**[R]**, reproduced **[D]**. For illustration only, substituting
`δ_tree = δ_leafcommit = q^2 / 2^256` makes the last term about
`2^-15.511360` at `q = 2^64`, so the numerical subtotal cannot justify a
complete `2^-64` advantage guarantee there. The construction's own bound (84)
has no primitive advantage under a square root.

For the ballot construction:

- the `H3` derivation term is absent: the fresh tape replaces that derivation
  (section 6.5.2);
- the plain-FAEST `δ_OWF` term does not transfer; its place is taken by the
  assumptions of section 8.4, and substituting a credential-search estimate
  is not a proved transformation;
- the square-root commitment term and the two † rows, which belong to the
  unsalted first challenge, have no counterpart: challenge 1 is charged by
  (67);
- none of these changes licenses deleting any other unresolved term.

Arithmetic under the earlier `2^128` floor, kept because it shows why
retuning within the published rows does not help; none of it is an attack
estimate or an available parameter recommendation:

- Changing parameters within the published `lambda ≤ 256` rows cannot repair
  the quadratic bound: grinding receives no extra divisor in it, changing
  `T_open` does not remove it, and the degree-seven and degree-fourteen
  configurations supply no margin.
- With its coefficient held fixed, the 3,200 term alone needs `lambda ≥ 269`
  to fall below 1/2 at `2^128`.
- Modelling a PRG advantage as `q^2 / 2^s`, the term
  `6·T·sqrt(13·q^2 / 2^s)` alone needs about `s ≥ 355` to fall below 1/2 at
  `2^128`.
- Wider fields, seeds and final challenges with redesigned PRG and commitment
  instantiations could remove these arithmetic obstacles. That is new backend
  specification, proof and measurement work, and it would leave the adaptive
  soundness and joint zero-knowledge theorems unproved. The review does
  not recommend a speculative `lambda = 384` backend.

Nominal generic attack scales, starting points for the attack report and not
an exhaustive lower bound: about `2^128` queries for 256-bit seed or challenge
search, `2^175` for ideal shared-function search across `2^34` 384-bit
secrets, and `2^170.67` for ideal 512-bit collision search. Neither a `2^106`
multi-transcript seed attack nor its absence follows from counting
transcripts: the IV-dependent predicates and their implementation costs
matter.

### 8.4 Explicit assumptions

Every written argument of section 6 rests on the following and on nothing
else of a cryptographic kind. None has a quantitative justification for this
construction. Each must be evaluated at the full resources of the reduction
that uses it, not at the adversary's `2^64` queries alone.

**1. The backend oracle model.** The designated backend hash domains (the
role-prefixed `H0`, `H1`, `H4`, `H5`, the `mu` hash and the three challenge
hashes) are independent quantum-accessible random oracles. The credential
functions are **not** modelled as random oracles: the assumptions on them
are about the concrete functions.

**2. The CRT generator games.**

| Term | Game |
| --- | --- |
| `ε_root` | Quantum generator-to-uniform distinguishing advantage for the joint two-tweak root output (root expansion and high-mask expansion together; 5 blocks) |
| `ε_tree` | The same for a hidden GGM-path expansion (4 blocks) |
| `ε_leaf` | The same for the correlated hidden leaf material (the 144-byte leaf expansion, 9 blocks) |
| `ε_expand` | The same for a hidden expanded VOLE row of the actual length `l^` (419 blocks for the fast-row vote relation) |

The four games keep shared-IV and cross-role PRG correlations and use the
actual query counts and lengths. The adversary in each game includes the
entire surrounding reduction. Even for ideal AES permutations the direct
generator-to-uniform formulation incurs the switching distances `D_sw` of
section 8.5; if PRP-native accounting is used instead, the factor `ρ_PRP` of
(59) is kept. Quantum pseudorandomness of the actual generators is an
assumption, not established by conformance vectors. The outer composition
has no primitive game of its own.

**3. `P`: selective-entry pseudorandomness with public leakage.**

> For the specified concrete four-tag SHAKE family, the experiment (23) of
> section 5.1, including real commitments, both authorization families,
> adaptive corruption of unprotected handles, the common simulator and all
> public quantum computation, has distinguishing advantage at most the
> recorded `α_P(ℛ)`:
>
> `α_P(ℛ) = sup_A | Pr[A^(P_0) = 1] − Pr[A^(P_1) = 1] |`

This is stronger and more specific than ordinary single-key PRF security. It
is an explicit assumption, not a consequence established here of generic
"SHAKE256 security". The tags establish disjoint input encodings; they do
not prove independence of concrete outputs. `P` implies both
authorization-prediction premises (42) and the privacy premise of
section 6.5.3. It does **not** imply `U`.

**4. `U`: selected-context existential uniqueness.** Run the **real-proof**
common environment. The adversary designates a legal collection

```text
𝒦 ⊆ { PCR1, PNF1 } × {0,1}^512
```

with separate bounds `m_C`, `m_N` on the number of commitment contexts and of
nullifier scopes. It wins if

```text
∃ (t, x) ∈ 𝒦,  ∃ s ≠ s' ∈ {0,1}^384 :   f_t(s, x) = f_t(s', x)          (95)
```

with `f_PCR1 = Com`. The adversary need not output, know or efficiently find
the two secrets.

> The probability of (95), with all adaptive exploration and preprocessing
> charged, is at most `δ_U(ℛ, m_C, m_N)`.

Its three restrictions:

| Restriction | Contexts | Used by |
| --- | --- | --- |
| `δ_Com,seal` (`u_C,seal`) | Commitment uniqueness at authenticated seals | Property 3 |
| `δ_Com,target` (`u_C,target`) | Commitment uniqueness at registration-origin targets, **including unsealed recontextualizations** | Property 8 |
| `δ_tag,target` (`u_N`) | Nullifier uniqueness at designated scopes; it implies the target-opening condition `BadTagOpen` | Property 2 |

- Computational joint zero knowledge is not applied to the predicate
  (95): it is not an efficiently decidable distinguishing event.
- **`P` cannot imply `U`.** Modify an otherwise secure family at two fixed
  secret keys so that their long outputs coincide for every context.
  Random-key pseudorandomness changes only when one of those exceptional keys
  is sampled, with probability at most about `2·U / 2^384`, while every
  context map is noninjective.
- Computational collision resistance does not imply `U` either: inability to
  produce two colliding openings does not exclude their existence.
- **Interpretive requirement.** Concrete SHAKE is fixed; there is no
  unexplained probability over "a random SHAKE implementation". The event at
  a deterministic context is a structural fact. Uncharged
  primitive-dependent advice that contains a bad legal context would defeat
  a selected-context claim. A qualification must retain a costed
  preprocessing model and state exactly which deployment randomness and
  which context-selection process its probability concerns. Computationally
  bounded selection alone is not a proof of existential uniqueness.
- The record must not claim injectivity simultaneously for every possible
  context. The ideal-map diagnostics of section 8.2 are not a proof of `U`.

`P` and `U` are two independent clauses of the credential assumption package.
They may share one name but keep separate bounds.

**5. The frame collision assumptions.** `ε_CR,REG`, `ε_CR,VOTE` and
`ε_CR,VOTE,batch`: finding distinct legal registration frames `Y`, or
distinct legal vote frames `Y_v`, with equal SHA3-512 digests, by a quantum
adversary. They can be restrictions of one global legal-frame collision game
`F`. If application claims identify scopes or policies by their underlying
structured meanings and not by exact digest bytes, the corresponding
context-frame collisions belong in `F` as well; the privacy coupling of
section 6.5.3 uses exact bytes and needs no such exclusion.

**Written arguments that the bounds also use.** These are not assumptions;
they are arguments awaiting independent review: adaptive relation soundness
in single-output and batch form (section 6.1) and the joint zero-knowledge
chain (section 6.5), together with the deterministic premises (public
validation, encoding equivalence, the implemented backend).

### 8.5 The consolidated ledger

The ledger is the review's, for the candidate row. All quantities are upper
bounds, not measured attack advantages. **No line is a certificate.**

**Components** at `q = 2^64` adversarial queries and `T = 2^44`. Values are
the review's; each numerical value is reproduced **[D]** from the formula
shown.

| Term | Formula | Value at the ceilings |
| --- | --- | ---: |
| Soundness, single output | (37) at (38) | `< 2^-119.8687268` |
| Soundness, batch | (39) | `< 2^-109.9015005` |
| Global leaf ambiguity `δ_leaf,all` | `33·(1 − 2^-256)·2^-256` | `2^-250.95560588` |
| Interactive lifetime sum (not added to the above) | `T · eps_run`, (21) | about `2^-208.99996` |
| Challenge-1 programming `ε_P1` | `(3/2)·T·sqrt((q + T)·2^-256)` | `2^-51.41503681` |
| Challenge-2 programming `ε_P2` | `(3/2)·T·sqrt((q + T)·2^-2112)` | `2^-979.41503681` |
| Challenge-3 programming `ε_P3` | `(3/2)·T·M_ctr·sqrt((q + T)·2^-832)` | `2^-319.41503681` |
| Initial `H5` programming `ε_initial` | `(3/2)·T·sqrt(256·704·(q + 1408·T)·2^-384)` | `7.6702489205 × 10^-33` |
| Multi-hiding exceptions `δ_MH` | `2·2^-256 + T·2^-256 + 2·704·T^2·256·2^-384` | about `2^-212` |
| Assignment collisions `δ_sep` | `(T + 2·704·T^2)·2^-256` | `2^-157.54056838` |
| Twice hidden-label deletion | `2·(2·(q + 704·T)·2^-128 + δ_salt)` | about `2^-61.99903172` |
| `K_sim` | Sum of the six preceding lines without challenge 1 | `2.16986018285 × 10^-19` |
| Bounded-simulator correction `σ` | `T·e^(−2·M_ctr/7360)` | `2^-367.08027043` |
| Honest secret repetition `ρ_rep` | `binom(U, 2)·2^-384` | `< 2^-317` |
| Authorization guessing | `q_guess·2^-512`; `g_batch ≤ 1,001,000·2^-512` | `2^-512` for one guess; `< 2^-492.0669` |
| CRT generator term | `T·e_gen` | Unknown |
| Credential pseudorandomness | `α_P(ℛ)` | Unknown; ideal-table benchmark `2^-109` at `q = 2^64` |
| Selected-context uniqueness | `δ_Com,seal`, `δ_Com,target`, `δ_tag,target` | Unknown; fixed-context diagnostic `< 2^-233` for `2^24` contexts |
| Frame collisions | `ε_CR,REG`, `ε_CR,VOTE`, `ε_CR,VOTE,batch` | Unknown concrete-SHA3 terms |
| Accidental equal random test outputs | Preserved by the coupling | Zero additional hybrid loss |

The interactive errors are components, not an alternative proof of adaptive
Fiat–Shamir soundness.

```text
Z ≤ ε_P1 + T·e_gen + K_sim + σ
```

**The switching subtotal.** Direct generator-to-uniform accounting must
still include the permutation-switching distances. With the block counts
5, 4, 9 and 419 of the four generator games,

```text
D_sw = T · [ 10 + 396·6 + 33·(36 + binom(419, 2)) ] / 2^128
     = 1.49586152902 × 10^-19                                           (96)
```

(reproduced **[D]**; `10`, `6` and `36` are `binom(5, 2)`, `binom(4, 2)` and
`binom(9, 2)`). The known subtotal, including switching and before the
computational generator advantages, is

```text
ε_P1 + K_sim + D_sw + σ ≈ 3.3343363838 × 10^-16
```

**`D_sw` must not be relabelled as a computational assumption.** With the
alternative PRP-native proof the factor is
`ρ_PRP = exp(1.2650301513 × 10^-17)` at these dimensions (reproduced **[D]**
from (59)); the two formulations must not be mixed.

**The six game inequalities**, deployment-wide:

| Game | Bound |
| --- | --- |
| Property 1 | `ε_snd,mix` of (37) |
| Property 2 | `ε_2 ≤ ε_snd,mix + δ_tag,target + ε_CR,VOTE + Z + α_P + ρ_rep + g_V` |
| Property 3 | `ε_3 ≤ ε_snd,batch + δ_Com,seal + ε_CR,VOTE,batch + Z + α_P + ρ_rep + g_batch` |
| Property 8 | `ε_8 ≤ ε_snd,mix + δ_Com,target + ε_CR,REG + Z + α_P + ρ_rep + g_R` |
| Joint zero knowledge | `Adv_JZK ≤ Z` |
| Anonymity and unlinkability | `≤ 2·Z + 2·α_P + 2·ρ_rep` |

Combined non-frameability is bounded by the sum of the property 2 and
property 8 rows. `P` and `U` keep their definitions, with their environments
taken at the frozen prover and simulator.

**The nominal resource normalisation.** A "nominal" value needs a resource
convention. The review fixes `Q* = 2^77` for the consolidated nominal
substitution; dropping to `2^68` would omit adversarially induced
verification work. The accounting behind it:

- one full candidate commitment costs at most 2,764,797 AES blocks;
- heavy public verification costs at most 2,750,672 AES blocks and entails
  at least 740 charged backend calls;
- `2^16` non-counter Keccak permutations are reserved per honest invocation
  or heavy verification;
- retry permutations contribute at most `4·M_ctr·T = 2^66`;
- `2^12` primitive evaluations are reserved per public request for bounded
  validation work outside the backend.

With the declared nominal conditions `q_pub ≤ 2^64`,
`q_direct,primitive ≤ 2^64` and `N_public requests ≤ 2^64`, the pooled
inventory of AES blocks and Keccak permutations is

```text
W ≤ q_direct,primitive + ((2,750,672 + 2^16)/740)·q_pub + 2^12·N_public requests
    + 2·2,764,797·T + 4·M_ctr·T + 2^16·T + final-comparison allowance
  < 2^77                                                                (97)
```

The displayed subtotal has `log2 W ≈ 76.95` (reproduced **[D]** without the
final-comparison allowance, which the review does not quantify).

What `Q* = 2^77` does and does not mean:

- The three conditions are **declared nominal resource conditions**, not
  additional deployment rules.
- **A backend-query ceiling alone cannot determine a primitive or gate
  budget**: direct AES computation and validation-only requests need their
  own accounting.
- `Q* = 2^77` is a defensible explicit nominal substitution. It is not an
  unconditional all-cost certificate derived solely from `q_pub`, and the
  ledger does not assume that oracle calls, AES evaluations, Keccak
  permutations and elementary gates are interchangeable.

**The nominal table (hypothetical substitution).** The shapes substituted for
the unknown terms are hypotheses chosen to check the arithmetic. None is an
established bound:

```text
each of the four CRT generator terms:   Q*^2 · 2^-256 = 2^-102, plus D_sw
α_P     = 4·Q*·sqrt( 2^34 / (2^384 − 2^34) ) ≈ 2^-96
δ_Com,·, δ_tag,target  <  2^-233
frame collision terms  ≤  64·Q*^3·2^-512 = 2^-275
```

The uniqueness substitutions are assumptions, not derived adaptive SHAKE
bounds. Under these values `T·e_gen` is
`463 · 2^44 · 2^-102 = 1.6063539388 × 10^-15` (`463 = 1 + 396 + 33 + 33`
**[D]**) and `Z ≈ 1.9397875771 × 10^-15`.

| Game | Nominal bound **under the hypothetical substitution** | Below 1/2? | Below `2^-64`? |
| --- | ---: | :---: | :---: |
| Property 1 | `8.23982 × 10^-37` | Yes | Yes |
| Property 2 | about `1.93979 × 10^-15` | Yes | No |
| Property 3 | about `1.93979 × 10^-15` | Yes | No |
| Property 8 | about `1.93979 × 10^-15` | Yes | No |
| Joint zero knowledge | about `1.93979 × 10^-15` | Yes | No |
| Anonymity and unlinkability | about `3.87958 × 10^-15` | Yes | No |
| Combined non-frameability | about `3.87958 × 10^-15` | Yes | No |

The table is the review's; the arithmetic is reproduced **[D]**. The
property 1 row contains no hypothetical term: it is (37) in its stated
model. **Every other row is a hypothetical substitution, not a bound for the
construction.** The numerical premises that remain unknown are `e_gen`,
`α_P`, the restrictions of `U` and the frame collision terms, evaluated at
the complete resource vectors, together with the concrete justification of
the backend oracle model.

**Crossing conditions.** Put `C = ε_P1 + K_sim + σ`, so `Z ≤ C + T·e_gen`.
Each written upper bound reaches 1/2 when:

| Game | Condition |
| --- | --- |
| Property 1 | `ε_snd,mix = 1/2` |
| Property 2 | `T·e_gen + α_P + δ_tag,target + ε_CR,VOTE + g_V + ρ_rep = 1/2 − ε_snd,mix − C` |
| Property 3 | `T·e_gen + α_P + δ_Com,seal + ε_CR,VOTE,batch + g_batch + ρ_rep = 1/2 − ε_snd,batch − C` |
| Property 8 | `T·e_gen + α_P + δ_Com,target + ε_CR,REG + g_R + ρ_rep = 1/2 − ε_snd,mix − C` |
| Joint zero knowledge | `T·e_gen = 1/2 − C` |
| Privacy | `T·e_gen + α_P + ρ_rep = 1/4 − C` |

With the other unknowns zero, the aggregate ceiling on `e_gen` is about
`2^-45` for a singly charged `Z` and `2^-46` for privacy; an individual
weighted generator term has that ceiling divided by 396 or 33. A singly
charged `α_P`, uniqueness term or frame term has a residual of about 1/2;
the `α_P` of privacy has about 1/4. These are **individual ceilings, not
simultaneous allocations**.

**The `2^-64` threshold.** Even with every unknown computational term set to
zero, the written bounds that contain `Z` cannot certify `2^-64`:
challenge-1 programming alone, `2^-51.415`, exceeds it. This is a limitation
of the written upper bounds, not an attack establishing that the actual
advantage exceeds `2^-64`.

### 8.6 Status of the total

- Sections 2 to 4 and the arguments, reductions and event inclusions of
  section 6 are written by the review. None has been independently reviewed.
- Published component bounds can be used only with their checked local
  hypotheses (section 7).
- No published complete computational bound applies as stated to this
  construction.
- Property 1 has a written bound in the backend oracle model. Every other
  game has a written inequality whose unknown terms have no established
  value. No design decision gives a missing term a numerical value, and the
  nominal table is a hypothetical substitution.
- The conformance results and timings reported for the earlier relation
  (section 9.3) are implementation evidence. They discharge none of these
  assumptions.
- The owner's eventual record must say that knowledge extraction has been
  removed, that authorization is instead established by the separate
  origin-security reductions, and that `P` and `U` are additional
  assumptions. It must keep the existing security ceilings, statistical
  budget and engineering limits, and contain the actual complete thresholds
  at advantages `2^-64` and 1/2, the independently reviewed attack-cost
  assessment and the explicit contract change. The recommendation of
  section 8.1 does not establish that the row meets it.

## 9. Dependencies, remaining work and what would falsify the construction

### 9.1 Dependency table

The table is the review's, reconciled with what is now written: where a
later text of the review supplies an item that the table called missing, the
last column says so. A written argument that awaits review is not an
established result.

| Item | Premises | Result and status |
| --- | --- | --- |
| Canonical relation correctness | Frozen encodings, authenticated state, correct constraint evaluation | Deterministic obligation; the strengthened relation must be checked (section 2 carries the implementers' extension) |
| Adaptive relation soundness | Backend oracle model, algebraic bounds, the conditioning on induced-seed uniqueness, the resource inventory | Written argument (37), (39), awaiting review; the original local-transition step and the real-game retry tail are open (section 6.1) |
| Total padded joint simulator | CRT mask argument, generator assumptions, programming, retries, totality | Conditional argument (sections 6.5.1 and 6.5.2), bound (84); unreviewed; generator terms unquantified |
| `P` | The concrete four-tag family in the experiment (23) | Explicit unproved primitive assumption |
| `U` | The concrete existential experiment (95) | Explicit unproved structural assumption |
| Registration prediction, vote prediction | `P` | (42), proved reduction |
| Pair decorrelation | `P` | Direct restriction of `P` to tests (86) |
| Association hiding | Pair decorrelation, the equality restrictions | (88), conditional coupling |
| Property 1 | Adaptive soundness | The written argument above |
| Property 2 | Soundness, `δ_tag,target`, `ε_CR,VOTE`, `Z`, `P` | (43) |
| Property 3 | Batch soundness, `δ_Com,seal`, `ε_CR,VOTE,batch`, `Z`, `P` | (45); the direct batch reduction |
| Property 4, unlinkability | `Z`, `P`, the disclosure exclusions | (88) |
| Property 4, non-frameability | Properties 2 and 8 | Endpoint identity reductions; the union is bounded by `ε_2 + ε_8` |
| Property 5, joint zero knowledge | The backend simulator premises | (84) |
| Property 5, anonymity | Joint zero knowledge and association hiding | (88) |
| Property 6 | All bounds at the actual resources, and the statistical ledger | Not qualified (section 8.5) |
| Property 7 | Implementation, deterministic bounds, envelopes and measurements | Separate engineering qualification (section 6.7) |
| Property 8 | Soundness, `δ_Com,target`, `ε_CR,REG`, `Z`, `P` | (90) |

Any hybrid that uses simulated false intermediate statements needs the total
simulator interface of section 6.5.2.

### 9.2 Remaining proof work

1. Independent review of the soundness argument of section 6.1: first the
   auxiliary-function conditioning and the local-witness predicate, then the
   constraint equivalence at the final dimensions (sections 2 to 4 carry the
   implementers' extension and recomputation **[D]**; the review has not
   restated them) and the compact-conversion ledger.
2. The original local-transition step for late `H4` and `H0` completions,
   or a decision to rely on the conditioning argument alone; and a real-game
   tail theorem for the retry count, if a ledger below the deterministic
   ceiling is wanted.
3. Restatement and independent review of the CRT-layer argument for the
   extended backend (salted `H5`, nine-block leaf expansion, 112-byte leaf
   commitments), and review of the revised outer composition.
4. Resource-qualified concrete bounds for the CRT generator games, `P`, `U`
   and the frame collision terms, at the complete resource vectors, together
   with the concrete justification of the backend oracle model.
5. Closing the resource and statistical ledgers: all retry permutations, the
   row expansion, the switching distances, the simulator work and the exact
   interpretation of the `2^-128` budget.
6. The independent attack-cost assessment, the exact production envelopes
   and the implementation qualification.

Efficient adaptive knowledge extraction is not in this list: the design no
longer requires it (section 10). The review's instruction stands: the launch
gate stays false until these obligations and independent review are
completed.

### 9.3 Evidence still required

**Implementer evidence, in the review's priority order.**

1. **Exact Rust relation conformance.** Source-bound fixed-tape comparisons
   with the Python prototype for both relations and rows, including
   intermediate constraints, corrections, challenges and coefficients, at
   `S = 3`, 500 and 1,000.
2. **Adversarial verification evidence.** Malformed statements and lengths,
   truncation and trailing bytes, noncanonical padding and openings, wrong
   role, descriptor, context or list, altered authorization value or
   nullifier, and late-failing proofs; bounded parser fuzzing.
3. **Deterministic and randomness behaviour.** Scalar, x86 and ARM byte and
   acceptance parity; entropy failure; fresh tapes; forced retry and
   exhaustion tests; counter-independent verifier work; erasure on every
   exit.
4. **Resource tables and measurements.** Complete allocations and work
   counts; cold and warm verification; late-invalid cases; proving
   distributions and retry histograms; peak memory. Source revision,
   compiler, hardware and measurement method pinned.
5. **Envelope accounting.** Naked proof lengths are not complete envelope
   lengths. Exact dossier-level framing and accounting, without prematurely
   implementing the production schemas and integration.

**Implementation state.** As reported by the implementers; none of it is
evidence for the frozen construction.

- The Rust backend reproduces all twelve official FAEST v3.0.2 signatures.
  That is conformance of **reference mode** only.
- The Rust relations and the reviewed Python prototype implement the earlier
  two-permutation vote relation on the prefix-only backend. The crate's
  compiled suite and descriptor confirm that it is not the frozen
  construction **[C]** (section 1).
- A prototype of the strengthened relation and an extended backend mode are
  being built. No result from either is recorded in this file.
- First measurements exist **only for the earlier relation, on a
  development machine that is not a qualification baseline** (Apple M2
  Ultra, one thread, release build). Candidate row: proving about 215 ms and
  verification about 105 ms with hardware AES, about 390 ms and 270 ms
  portable, about 3 MiB peak heap. Comparator row: about 390 ms and 275 ms
  with hardware AES, about 2.0 s and 1.9 s portable. They measure neither
  the three-permutation vote relation nor the extended backend, they are not
  measurements on the validator or phone baselines, and they establish
  nothing about the limits of property 7.
- The prototype evidence that the review records as completed on the
  implementers' report (conformance, proof sizes and digests, exhaustive bit
  flips, semantic faults, 103 detected mutations, an independent evaluator)
  was produced for the earlier construction. The review states that it
  establishes neither quantum simulation nor knowledge extraction. Because
  the descriptor digest, the vote relation and the backend change, every
  proof byte changes, and the evidence has to be produced again **[E]**.
- The descriptor digests of section 1.1 await cross-checking against a
  second implementation.

The decisions the review asked to be confirmed are confirmed and are not
outstanding: the pad bit order, the rejection of an inconsistent supplied
`B`, and the retention of degree seven (sections 1.1, 1.7 and 4).

**Independent reviewer and owner.**

1. Independent review of the games, the reductions, the oracle modelling and
   the concrete accounting, including the conditional arguments of
   section 6.5 and the soundness argument of section 6.1.
2. Independent attack-cost assessment against the `2^128`-elementary-gate
   requirement, with preprocessing, coherent lookup, memory and parallel work
   counted.
3. Independent implementation review of constant-time behaviour, randomness
   and erasure; named validator and phone qualification.
4. Owner records: the explicitly weakened security contract (section 8.1);
   the weakening of property 1 from knowledge extraction to soundness, with
   authorization established by the separate origin-security reductions; the
   assumptions `P` and `U` as additional assumptions; and eventual activation
   qualification.
5. Later production authentication, lifecycle, SDK, restart and rollback,
   network and release qualification.

Selection continues to require complete foundational arguments and a
complete ledger. Passing implementation checks does not substitute for those
conditions.

### 9.4 What would falsify the construction

This list is the implementers' consolidation **[E]** of the failure conditions
the review states in the parts above; the stop and switch conditions of
profile record section 11.5 apply unchanged.

- **Encoding.** A witness in `K^l` that satisfies every constraint of
  section 1.5 without encoding a valid relation witness, or an implementation
  whose constraint stream differs from it in content or order.
- **Hash bounds or core soundness.** An error in (13), (14) or (15) large
  enough to lift a round error above `7 · 2^-256`, or a failure of the
  imported leaf-hash and CRT injectivity conditions for the actual tables.
- **Property 1.** A false accepted statement; an error in the conditioning on
  induced-seed uniqueness, in the predicate or in the transition table of
  section 6.1; or a leaf commitment with two induced seeds at some IV and
  tweak of a role namespace.
- **Properties 2 and 8.** A second opening of a target nullifier or of a
  target commitment in a context the adversary can select; a collision of
  SHA3-512 on legal frames; predictability of `Auth_d(sk)` or `AuthV_d(sk)`
  from the public values; an authorization value exposed without being
  logged.
- **Property 3.** A sealed commitment with two openings, whether or not
  anyone can find them efficiently together with an accepted proof.
- **Property 5.** A distinguisher against the padded protocol with fresh
  tapes, in particular through the CRT labels or the counter distribution; a
  distinguisher for the experiment of assumption `P`; or a prover deployment
  in which the pad, the salt or the tape is fixed,
  reused or disclosed, to which the target theorem does not apply.
- **Primitive assumptions.** Failure of any assumption of section 8.4 for the
  concrete functions, or primitive advantages at the full reduction resources
  that leave (84) or (88) at or above 1/2, or a legal context in which a
  commitment or nullifier map is noninjective.
- **Ledger.** A complete ledger whose bound is not below 1/2 at `2^64` quantum
  queries, a statistical total above `2^-128`, or an independently assessed
  attack below `2^128` gates.
- **Property 7.** Any accept or reject difference between conforming
  implementations, or a hard resource limit exceeded after grouping and
  streaming.
- **Composition.** A later protocol that treats a ballot or registration
  proof as a proof of possession or of extractable knowledge. The
  construction does not provide that (section 5.2).

Selection for integration continues to require the complete dossier of
profile record section 11.1 with its contract condition amended as in
section 8.1 here. Missing foundational proofs prevent selection. Accepting and
recording activation qualification is the owner's responsibility alone, and
`parliament_binding_ballot_available()` stays false.

## 10. Knowledge extraction: analysis of a requirement that is not imposed

**The design no longer requires knowledge extraction.** Property 1 is
adaptive relation soundness (section 5.2). This section keeps the review's
analysis of efficient extraction, written while the requirement stood, as
analysis only. It establishes no extractor. **If a later protocol needed
knowledge of the credential** (proof of possession, extractable knowledge or
a simulation-extractable credential), it would have to prove the theorem
described in section 10.5 or change the construction; nothing in this file
supplies it.

The review wrote the analysis for the two-permutation vote relation on the
backend before its four extensions. Nothing in sections 10.2 to 10.4 depends
on the application relation beyond its length and its constraint evaluation;
the figures that depend on the dimensions, the leaf commitment or the proof
layout are restated for section 1 and marked **[D]**.

### 10.1 What extraction the properties would need

An extractor gets neither uncorrupted credentials nor honest proving tapes as
auxiliary input. An assertion that it can inspect a quantum query requires a
justified oracle-simulation or measurement interface.

| Property | Conclusion wanted | Extraction requirement |
| --- | --- | --- |
| Knowledge authorization (the requirement that was removed) | Recover a semantic witness for a fresh accepted statement | Unavoidable for that requirement: ordinary soundness cannot establish it, and even a language with exactly one witness per statement can have computationally hard witness recovery |
| 2: target-origin unforgeability | Prevent unauthorized use of an honest target's nullifier | One-witness extraction from the final fresh forgery would suffice; the event split of section 6.2 replaces it |
| 3: excess distinct nullifiers | Prevent more than `k` nullifiers outside the honest-issued set | Joint extraction for one adversary's output collection would suffice; soundness plus existential opening uniqueness replaces it (section 6.3) |
| 8: registration origin | Prevent fresh registration authorization for an honest target | No extractor is needed for the event split (section 6.8) |

The removed requirement, for the record of what an extraction theorem would
have to deliver. With `Fresh(R, x) ⇔ (R, x) ∉ Issued`, where `Issued` holds
the exact public inputs of both honest proof types, an instrumented execution
would have to produce witnesses `ŵ` with

```text
Pr[ V_R(x, π) = 1 ∧ Fresh(R, x) ∧ ¬R_R(x; ŵ) ] ≤ κ_1                    (98)
```

together with an explicit bound on execution disturbance, oracle queries and
running time. A semantic witness would suffice: the deterministic trace is
regenerated and the pad discarded.

Qualifications the analysis attaches to the extraction routes:

- For property 2 the freshness is per target handle, whereas (98) exempts
  statements issued to any handle; hence the event `CrossIssued_2` of
  section 6.2, which (98) does not cover.
- An external credential-security reduction must answer honest proof requests
  without knowing the challenge secret. It needs extraction compatible with
  the joint simulator, or a direct combined reduction. Ordinary knowledge
  soundness and ordinary zero knowledge do not automatically compose into
  that guarantee.
- For property 3, recovering every retained witness is stronger than
  necessary: one witness selecting an honest entry, or two different openings
  of the same controlled commitment that explain different nullifiers, would
  suffice. Obtaining those certificates from separately restarted quantum
  executions is not justified; they must concern the same winning output
  collection, with the extraction disturbance accounted for.

### 10.2 Route (a): reading the oracle queries directly fails

There is no ordinary classical query log in the QROM; measuring all queries
would change the experiment. More importantly, **even granting a classical
record of all prescribed query inputs does not expose the necessary seeds
directly.** The exact leaf calculation is

```text
(sd, b0, b1) = AESPRG(k, iv, tweak; 1152 bits),      (h0, h1) = H0(iv)
c0 = embed(sd) · h0 + b0        in F_(2^768)
c1 = low128(sd · h1) + b1       in F_(2^256)                            (99)
```

(the review cites the leaf implementation in
`crates/iroha_zkp_vole/src/bavc.rs` and `LeafHash` in `universal_hash.rs`).
Consequences:

- `H0` exposes the IV and the universal-hash key, not a secret seed.
- `H1` preimages expose leaf commitment values and vector digests, not leaf
  keys or `sd`.
- Challenge 1 exposes the corrections and the aggregate commitment.
- Challenge 2 exposes `d` and the compressed consistency values, not the full
  `u`.
- Challenge 3 exposes the claimed polynomial coefficients and the counter.
- `H5` exposes gate labels. Correctly identifying both labels of a gate can
  reveal their 256-bit offset `u[0, 256)`. This covers the padded prefix, not
  the remaining application-witness mask.

For every candidate `sd`, (99) has an algebraic solution for `(b0, b1)`
(**[D]** for the 112-byte commitment; the review made the statement for the
96-byte one).
Recovering the actual seed requires enforcing the AES-PRG image restriction;
no polynomial-time inversion follows from the universal-hash equation. The
clear corrections satisfy, for honestly consistent material,

```text
c_i = u ⊕ u_i[0, l),        d = W ⊕ u                                  (100)
```

They turn recovery of one complete `u_i` into witness recovery; they do not
supply `u_i`.

This is **a failure of the direct-read extraction argument**, not an
impossibility theorem for every conceivable extractor. Exhaustive inversion
remains possible but is not efficient. The published FAEST analysis expressly
permits an inefficient extractor, because its security reduction switches to
false statements (FAEST v3 sections 10.5 and 10.7); that theorem cannot be
relabelled as efficient knowledge extraction. Two further published
techniques do not supply an extractor either: a lossy-key argument bounds
acceptance after switching to a false instance and recovers no witness on a
true instance, and adaptive reprogramming controls a distributional change,
not witness recovery.

### 10.3 Route (b): what multiple accepting transcripts establish

`Ω` is the set of admissible final challenges. The final challenge is 256
bits; its eight grinding bits must be zero; its remaining 248 bits select one
hidden leaf in each of 33 vectors (fast row).

**Lemma 1 (two different BAVC openings recover one complete vector).**
Suppose two verified openings share the namespace, the IV and the aggregate
commitment. Exclude (1) inconsistent `H1` preimages for the same digest and
(2) different induced leaf seeds consistent with one leaf commitment. If
their accepted final challenges differ, their 248-bit index vectors differ:
for some vector `i` the hidden indices are `h ≠ h'`. The first opening
reveals every seed except `sd_i,h`; the second reveals `sd_i,h`. Binding
makes their overlapping revelations consistent, so their union supplies all
seeds in vector `i`. Compute

```text
u_i = XOR_{j=0}^{N_i − 1} AESPRG(sd_i,j, iv, 2^31 + i; l^)             (101)
```

For honestly consistent correlations,

```text
u = u_i[0, l) ⊕ c_i  (c_0 := 0),        W = d ⊕ u                      (102)
```

The root `r` need not be recovered. The opening threshold does not invalidate
the argument: every accepted opening still reveals all but one leaf in each
vector. Grinding also preserves it: accepted challenges have identical zero
grinding bits, so different accepted strings differ in their index vectors.

**Lemma 1 is not two-transcript special soundness.** Malicious corrections
need not describe honestly generated correlations, and even honest
correlations do not make two accepting polynomial evaluations prove the
relation.

**Proposition 2 (two-transcript special soundness is false; seven
transcripts can also be insufficient).** Take a publicly valid false instance
and any Boolean extended assignment `W`. Generate genuine BAVC and VOLE
material and set `d = W ⊕ u`. Outside the constraint-hash cancellation event,
the aggregated violated constraints have a nonzero coefficient `ζ`. The final
verification discrepancy is (17). Choose seven distinct admissible points
`r_1, ..., r_7` and choose the claimed coefficients so that

```text
E(X) = −ζ · prod_{t=1}^{7} (X − r_t)                                   (103)
```

All seven openings then accept with the same messages before the final
challenge, although no witness exists.

Admissible points are available under the exact threshold. For the
hidden-index patterns `I^(h) = (h, ..., h)`, `h = 0, ..., 7`, the frozen tree
rule gives the frontier counts

```text
11, 12, 11, 13, 11, 12, 11, 15
```

all below 229 (reproduced **[D]** from the position and marking rules of
`bavc.rs`, read as text). This is an algebraic counterexample to the
special-soundness implication. It is **not** an efficient Fiat–Shamir
forgery: arranging the corresponding random-oracle output remains a separate
problem.

**Lemma 3 (conditional reconstruction from eight supplied branches).**
Assume:

1. Before challenge 1, commitment binding fixes a partial response graph
   `g : D_Δ → K^(l+10) ∪ {⊥}`.
2. The second message fixes `(ũ, Ṽ, d)` before challenge 2.
3. Eight accepting branches share these messages and all claimed coefficients
   `ã_0, ..., ã_6`.
4. Their final field points `Δ_t` are distinct.
5. Neither the affine-consistency bad event of (15) nor the ZKHash
   cancellation event of (16) occurs.

Reconstruct from each opening the public response
`q_t = (Q_t, q̄_t,0, ..., q̄_t,9)`. Outside the first bad event all passing
responses lie on one affine line. From any two branches compute

```text
U* = (q_1 − q_0)/(Δ_1 − Δ_0),     V* = q_0 − Δ_0·U*,     W* = d + U*_[0, l)   (104)
```

and evaluate the complete constraint vector `Z(W*)`. If it is nonzero, the
no-cancellation hypothesis gives `ζ ≠ 0`, making (17) a degree-seven
polynomial; eight distinct roots are impossible. Hence `Z(W*) = 0`, and
Booleanity with the encoding equivalence of section 2 yields a valid semantic
witness.

The algorithm is efficient **given the eight branches**: it reconstructs
verifier responses, performs field arithmetic and checks the constraints. It
need not invert the PRG or enumerate the response graph; a straightforward
implementation costs at most eight verifier reconstructions plus the slope
calculation and one constraint evaluation. The relevant independently sampled
interactive bad-event bounds are (15) and (14), whose values at the final
dimensions are in section 4; they are **not** probabilities for adversarially
selected QROM forks.

Two transcript qualifications:

1. A final-oracle fork fixes the complete query, including the reconstructed
   `ã_0` and the counter. Equal serialized coefficients `ã_1, ..., ã_6` do
   not establish that condition. Earlier chain inputs, including the
   reconstructed `Ṽ`, must also agree, or their disagreement must be charged
   as a binding failure.
2. The challenge distribution matters: the root probability is `7 / 2^256`
   under a raw uniform challenge and only `7 / |Ω|` conditioned on
   admissibility (section 4). A reduction cannot program an admissible
   challenge and keep the unconditioned denominator without accounting for
   the change.

Lemma 3 does not say how the eight branches, or equivalent witness
information, are obtained.

**The generic multi-round transformation is vacuous at this row.**
Don–Fehr–Majenz's multi-round result gives, for its normalized
`2n + 1`-message protocol,

```text
p_IP ≥ ( n! / (2q + n + 1)^(2n) ) · p_FS − ε_order,     ε_order = n! / |𝒞|   (105)
```

after summing the statement-specific errors, and its knowledge-preservation
corollary assumes that the interactive protocol already is a quantum proof of
knowledge (Corollaries 13 and 15, as the review reads them). The frozen
protocol has different challenge lengths and rejection predicates, so literal
application additionally requires normalization or a proved extension. Even
granting the favourable three-challenge calculation,

```text
L_gen = (2q + 4)^6 / 6 ≈ 2^387.415037        (q = 2^64)                (106)
```

A Fiat–Shamir success probability 1/2 then supplies only about
`2^-388.415037` interactive success before the additive error. Even ignoring
that error and borrowing the interactive error of (21), multiplication by
`L_gen` gives about

```text
2^134.4151 > 1                                                         (107)
```

(**[D]** with the fast-row vote coefficient of (21); the review's own
evaluation was made for the FAEST v3 leaf commitment, whose coefficient is
about 41). The route provides no concrete certificate.
Obtaining eight branches, quantum rewinding, honest-proof simulation and
extraction disturbance would require further analysis, not remove this loss.
The result is a **vacuous reduction**, not an attack on FAEST.

### 10.4 Route (c): extraction commitments

**A root tag fails.** An extra root commitment of the form
`t = H_E(PREFIX_R, mu, iv, r)` does not suffice, even if `t` is included in
challenge 1. A malicious prover can compute `t` from `r_tag`, construct its
BAVC using `r_tree ≠ r_tag`, and otherwise execute the protocol with `t`
included in the challenge chain. No verification equation checks
`com = BAVC.Commit(r_tag, iv)`. Extracting `r_tag` therefore need not recover
the mask used in `d`. Including `com` in the hash preimage does not fix this:
it binds a claimed association without checking it. A verified relation
between the tagged root and the actual tree is necessary; revealing the root
would reveal the witness through `d`, and proving the relation privately is a
substantial additional construction.

**Checked per-leaf tags are an unproved variant.** A more plausible
experimental variant could compute a 512-bit oracle tag of each leaf key,
with namespace, IV, vector and leaf position; include each tag beside its
existing leaf commitment in the inner `H1` input; recompute the tag from
every revealed leaf key; and transmit the tag of each hidden leaf. Hashing
the leaf key, not merely an unrelated claimed seed, lets an extractor
recompute both the induced seed and the original leaf commitment and check
their association. For this illustrative fast-row layout:

```text
additional proof bytes = 33 · 64 = 2,112
naked sizes: 162,260 bytes (registration), 235,124 bytes (vote)
additional leaf-tag evaluations per honest proof: 6,400
```

(the sizes are `160,148 + 2,112` and `233,012 + 2,112` **[D]**). No root tag
is needed for that design. **These are design arithmetic, not a frozen
revision or a security theorem.** The review's decision adds no root tags and
no extraction commitments.

The relevant published primitive is the extractable random oracle of
Don–Fehr–Majenz–Schaffner. Its Theorem 4.3 supplies an extraction interface
for values related to oracle outputs; for ordinary hash-preimage extraction
its commutation error is `8·sqrt(2)·2^(-n/2)` per applicable swap, and the
runtime includes `O(q_RO·q_E + q_RO^2)`. It extracts a hash preimage, not
automatically a valid protocol witness. For perspective, a crude swap sum
with 512-bit tags, `q_RO = 2^64` and `q_E = 6,400 · 2^44` is

```text
8·sqrt(2) · q_E · q_RO · 2^-256 ≈ 2^-131.856144                        (108)
```

and with 256-bit tags about `2^-3.856144` (both reproduced **[D]**). Neither
expression is the modification's extraction error: aggregate-commitment
extraction, missing preimages, challenge search, witness validity, simulation
and additional queries remain unaccounted for.

The ordinary and Merkle commit-and-open theorems additionally require their
protocol syntax and an efficient `𝔖`-soundness* reconstruction (the notion
of Definition 3.5 of the commit-and-open paper, with its Theorems 4.2 and
5.2, as the review reads them; it is not special soundness). Their bounds cannot be imported merely because the
modified backend contains seed hashes and a tree: the frozen protocol has
three challenge stages and intervening consistency and polynomial messages.

The zero-knowledge consequences would also require a new proof. Such tags
create oracle correlations with precisely the hidden seeds replaced in the
multi-hiding hybrids. The CRT mask bijection remains an algebraic identity,
but the seed-replacement hybrids and the "public baseline independent of
latent pads" argument of section 6.5.1 would have to be re-established with
the new tag oracle and all later queries.

Accordingly: root-tag-only extraction fails its consistency requirement;
checked leaf tags are a plausible research variant; no cited theorem
establishes that variant's complete online extraction or preservation of the
CRT simulation argument.

### 10.5 What would have to be proved

A protocol that needed knowledge extraction would need a protocol-specific
adaptive QROM extraction theorem, with Lemma 3 as a possible algebraic
reconstruction step. Its hypotheses would be:

- the exact frozen relations, constraints, namespaces, tape and retry
  procedure;
- the stipulated quantum-accessible backend random oracles;
- separately quantified assumptions for the actual AES-based generators and
  commitment binding, including their IV and tweak usage;
- authenticated public contexts and the specified classical application
  interfaces;
- quantum auxiliary information and adaptive statements as permitted by the
  game;
- no access to honest credential secrets or tapes;
- explicit handling of both real honest proofs and, where a reduction
  simulates, the designated joint simulator.

Its conclusion would have to provide one efficient extractor satisfying (98),
with an explicitly bounded observable simulation error, and it would have to
explain **how the required branches or equivalent witness information are
obtained**. Lemma 3 alone does not do that, and the proof may not use the
exponential response graph as an executable subroutine. A use of extraction
for target-origin unforgeability would additionally have to cover the
compatible simulated-proof environment, excluding the logged statements and
charging `CrossIssued_2`; a use for nullifier uniqueness without the
selected-seal uniqueness premise would have to extend to the joint output
collection of at most 1,001 ballots. The generic `q^6`
reduction is not a usable route, and a root-hash tag is not a fix.

**Expected concrete loss: unknown.** No justified numerical value for `κ_1`,
for a joint extraction and simulation error or for extractor resource use
follows from the available results. The only evaluated generic route is
vacuous at `q = 2^64`. A feasibility target would be an additive,
protocol-specific bound of the shape

```text
κ_1 + ν ≤ ε_primitives + ε_joint + C_2·Q_eff^2·2^-256
          + C_3·Q_eff^3·2^-512 + δ_stat                                (109)
```

**(109) is a theorem target, not a proved bound and not an asserted property
of FAEST.** At `Q_eff = 2^64` its displayed query terms would be
`C_2 · 2^-128` and `C_3 · 2^-320`, which is why a sufficiently tight
specialized theorem could fit the contract whereas the generic three-round
loss does not.

All resources would have to remain explicit: the honest-proving and
verification query counts of (38); extractor repetitions, reprogramming,
verification and primitive evaluation; AES work; and compressed-oracle
simulation time, where an `O(q^2)` simulation has an operation count of about
`2^128` at this query ceiling before its other factors.

**Status of the analysis.** Proved in the review's text, each under its
stated hypotheses: the conditional two-opening reconstruction (Lemma 1), the
counterexample to two-through-seven-transcript special soundness
(Proposition 2), the conditional efficient eight-branch reconstruction
(Lemma 3), and the arithmetic showing that the generic reduction fails. Open,
and no longer required by the design: efficient quantum branch acquisition or
an alternative extractor for the frozen backend, its adaptive honest-proof
composition and its concrete costs.
