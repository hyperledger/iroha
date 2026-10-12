# Parliament ballot proof: written arguments awaiting independent review

Status: written arguments of 2026-10-12 for the eight properties of
[parliament_private_ballot_design.md](parliament_private_ballot_design.md)
section 5 (the "ballot design"), for the construction frozen for investigation
in [parliament_ballot_proof_profile.md](parliament_ballot_proof_profile.md)
(the "profile record"). They were written by the second-opinion review (profile
record section 3) in three parts, corrected by its reconciling decisions of
the same day and completed by its further text of that day (the property 5
game, the property 8 event split, the query offset and the byte-level freeze).
The implementers consolidated them here without changing their
content: overlapping statements are merged, the reconciling decisions are
applied wherever the parts differed, and the final dimensions are used
throughout. **Every statement is [R] unless labelled otherwise**; the labels
are those of the profile record. FIPS 202 was not read by us. The FAEST v3.0
specification was read by us only in the parts listed in profile record
section 3; citations of its other parts (among them section 6 with Figure 6.2,
Lemma 7.3, Lemmas 10.24, 10.26, 10.40, 10.51 and 10.52, Corollaries 10.27 and
10.41, and games G5 and G6 of Theorem 10.42) are the review's and unverified.
The reading status of every other paper named below is that of profile record
section 13. **This file selects no profile and qualifies nothing.** No property
of the gate is established by it, and the security contract is not met.

Each part has one of three statuses:

- **complete (awaiting review)**: every step is written; no independent review
  has taken place;
- **conditional**: a reduction to stated premises that are themselves unproven;
- **incomplete**: a named step is missing.

| Part | Status |
| --- | --- |
| 1. Protocol the arguments are about | Frozen for investigation for the standalone construction, including the byte level (descriptor, CRT serialisation, role prefixes, `mu` preimage, proof layout and tape rules: profile record section 6); production encodings and envelopes are later obligations; not implemented |
| 2. Encoding equivalence | Complete (awaiting review) |
| 3. Universal-hash bounds at the final dimensions | Complete (awaiting review) |
| 4. Soundness for false instances, response-graph experiment | Complete (awaiting review); it is not a knowledge or Fiat–Shamir theorem |
| Property 1, authorization (knowledge) | Incomplete: efficient extraction is missing |
| Property 2, unforgeability | Incomplete: joint simulation and extraction, and the mixed-list reduction, are missing |
| Property 3, nullifier uniqueness | Conditional on properties 1 and 2 and adaptive-context commitment collision resistance |
| Property 4, unlinkability and non-frameability | Conditional on joint zero knowledge, a secret-prefix pseudorandomness assumption, and properties 2 and 8 |
| Property 5, zero knowledge and anonymity | Incomplete: the game for the decided target is written; no argument is written for it; the padded CRT hidden-label simulation lemma, the programming-location bounds and the retry and exhaustion coupling are missing |
| Property 6, concrete security | Incomplete: the complete ledger is unestablished |
| Property 7, deterministic bounded verification | Conditional: a design argument whose premises are a completed verifier and, for production, the envelope and Norito mappings, which are not written |
| Property 8, registration authorization | Incomplete: the event split and a conditional bound are written; its cryptographic premises are unproven (adaptive target-opening uniqueness, adaptive registration soundness, SHA3-512 collision resistance on registration frames, joint simulation, adaptive authorization prediction) |

Notation. `K = F_2[α]/(α^256 + α^10 + α^5 + α^2 + 1)` is the FAEST
polynomial-basis field `F_(2^256)`; Boolean values are embedded as `0, 1 ∈ K`;
all sums are field sums, so addition and subtraction coincide. `l` is the
witness length in bits and `M` the number of constraints of a relation (the
review's `𝒞`; `M' = M + 1` is its `C'`), kept distinct from the credential
commitment `C`. `sk` is the review's `s`. `lambda = 256`, `tau`, `w_grind`,
`T_open` and `d_zk = 7` are the backend parameters. Lifetime symbols:
`U = 2^34` registrations, `T = 2^44` honest transcripts, at most `2^10` per
credential, `J = 2^24` body scopes, `S ≤ 1,000`, and `q` the adversary's
quantum query budget.

## 1. The protocol

Framing, `P16`, `Frame`, `Enc`, `B`, `scope`, `R`, `policy_hash`, the list `L`
and the message `m` are those of profile record sections 6.1 and 6.2 and are
not repeated. The authorization digest, the authorization value and the
registration message are new and are stated in section 1.1.

The protocol is frozen for the standalone construction, including the byte
level. The bytes are stated in profile record section 6 and are not repeated
here: the descriptor `DESC` with its `SUITE` string and its 64-byte digest
`D = SHA3-512(DESC)`; the canonical CRT serialisation `CRT_BYTES` and its
digest `T_crt`; the digest values for both rows; the role namespaces `NS_REG`
and `NS_VOTE` and the 77-byte role prefix
`PREFIX_R = ASCII("PARL/FAEST/v1") || NS_R` carried by every ballot backend
hash call, with each call's body, suffix byte and output length; the preimages
`F_REG` and `F_VOTE` of `mu_R`; the length bounds and boundary rules of the
public inputs; the naked proof layout, the opening layout and its padding
rule; the test-only statement codec; and the tape allocation, the uses of `r`
and the erasure rule.

- The standalone construction's public inputs are bounded opaque byte strings.
  It neither imports node types nor parses their encodings, and it applies no
  conversion, normalization, delimiter or terminator to an opaque input. Core
  must supply and validate the pinned canonical Norito representations; the
  proof construction does not detect two encodings of one node-level value.
- The verifier selects a compiled, fixed descriptor. It does not accept a
  caller-defined descriptor.
- With these decisions the review holds condition 1 of the selection rule
  (profile record section 11.1) to be satisfied **for the standalone
  construction**: no relation or transcript choice remains open. Conditions 2
  and 3 still fail. Production Norito mappings, production envelopes and
  authenticated integration remain later obligations, and their absence must
  not be hidden by claiming that the standalone verifier validates node-level
  canonicality. Implementation, resource measurements and qualification remain
  unfinished, and the feature stays disabled.

No module of this protocol beyond the backend's stage 1 (parameters, fields,
PRG, hash roles, VOLEHash, ZKHash, LeafHash) is implemented **[C]**. The
constraint order below is a protocol choice, not a description of implemented
behaviour.

### 1.1 Functions, relations and public validation

```text
Com_B(sk)  = SHAKE256("PCR1" || P16 || sk[48] || B[64],     128 bytes)
Tag_x(sk)  = SHAKE256("PNF1" || P16 || sk[48] || x[64],      64 bytes)
Auth_d(sk) = SHAKE256("PAU1" || P16 || sk[48] || d[64],      64 bytes)

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

- In `Auth_d`, `d` is any 64-byte digest argument; `auth` uses `d = D_reg`.
- The descriptor includes the parameter row and all fixed protocol choices.
  The descriptor field of `D_reg` (the review's
  `Enc(complete_profile_descriptor)`) is exactly the 64 bytes
  `D = SHA3-512(DESC)`: not `DESC` and not a Norito wrapper around `D`.
  `body_context` and `authoritative_body_context` name the same byte string.
  Registration verification recomputes `B` and `D_reg`; it does not trust
  caller-supplied derived digests.
- `D_reg` excludes `auth`, `mu`, the proof bytes and the prover randomness. Its
  role field is the literal `REG`, not a backend seed.
- The registration fields, including `auth`, enter `mu_REG` through `F_REG`,
  and the descriptor digest `D` enters it through `PREFIX_REG` (profile record
  section 6), so `auth` is bound through `mu` into the IV and the challenge
  chain. It is also constrained inside the registration relation.
- There is no authorization value in the vote relation. It would not establish
  uniqueness of the secret underlying a target nullifier.

After public validation the semantic relations are:

```text
R_reg(x_reg; sk)      ⇔  WellFormed_reg(x_reg)
                          ∧ C = Com_B(sk)
                          ∧ auth = Auth_(D_reg)(sk)

R_vote(x_vote; sk, i) ⇔  WellFormed_vote(x_vote)
                          ∧ 0 ≤ i < S
                          ∧ C_i = Com_B(sk)
                          ∧ nf = Tag_scope(sk)
                          ∧ vote ∈ {0, 1, 2}
```

`x_reg` contains the authoritative body context, the fixed descriptor and the
complete `m_reg`. `x_vote` contains `B`, the validated ordered list
`L` itself (its canonical bytes, not merely `R`), the descriptor and the
complete `m`.

`WellFormed` (public validation) covers, in the standalone construction, the
length bounds of profile record section 6.1, the compiled fixed descriptor,
the recomputed body-context digest `B`, for registration the recomputed
`D_reg`, and, for voting, `3 ≤ S ≤ 1,000`, exactly `S` strictly ordered
distinct commitments (unsigned bytewise order), the recomputed list digest
`R` and a vote byte in `{0, 1, 2}` **[R]**. Canonicality of the typed values
behind the opaque inputs is validated by Core on its pinned Norito
representations, not by public validation. These checks contribute no
witness constraints. Authenticity of the seal is an external premise supplied
by the finalized-board model: a caller-supplied `L` is never sufficient.
Registration eligibility, account authorization and assignment policy remain
separate Core checks.

The algebraic equations alone do not establish transcript binding: the
complete public statement and message must enter `mu` as profile record
section 6.3 prescribes, and all bytes read by verification are bound into the
transcript identity. `REG`, `VOTE` and the parameter rows are separated by the
explicit role prefix on every backend hash call; each call keeps its reference
suffix byte (profile record section 6.3). Dependence of a hash input on `mu` is causal dependence
only and is not the disjoint-domain statement adopted here: without the prefix
`H0` reads only the IV and `H1` reads commitment material without a namespace,
so different roles can reach identical oracle inputs **[R]** (the review cites
`crates/iroha_zkp_vole/src/hash.rs` and `bavc.rs`; not re-read by us for this
record). The AES PRG is unchanged and keeps its tweaks; it is not converted
into an independently namespaced random oracle, and its IV and cross-instance
security remain proof obligations. Binding the full list, statement and descriptor in every
relevant transcript domain simplifies adaptive statement localization; it
requires a new exact transcript argument and does not supply extraction.

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
coordinates, which are projected away when an application witness is
extracted.

### 1.2 SHAKE inputs, padding and state bits

Each unpadded SHAKE256 message is 132 bytes:

| Byte interval | Commitment | Authorization (registration) | Nullifier (vote) |
| --- | --- | --- | --- |
| `[0, 4)` | ASCII `PCR1` | ASCII `PAU1` | ASCII `PNF1` |
| `[4, 20)` | `P16` | `P16` | `P16` |
| `[20, 68)` | `sk` | the same `sk` | the same `sk` |
| `[68, 132)` | `B` | `D_reg` | `scope` |

- Append `1f 00 00 80` to obtain the 136-byte rate block, then 64 zero capacity
  bytes, giving the initial state `A_D^(0)` for `D ∈ {C, A, N}` (commitment,
  authorization, nullifier).
- Serialized byte bit `j` is the bit of value `2^j`, `0 ≤ j < 8`; state bytes
  and lanes are little-endian under this convention. State coordinates are
  flattened by `t = 64·(x + 5y) + z`, `0 ≤ x, y < 5`, `0 ≤ z < 64`.
- Secret bit `j` occupies initial-state bit `160 + j` of every permutation of
  the relation.
- After the permutation the commitment is state bits `[0, 1024)` and the
  authorization value and the nullifier are state bits `[0, 512)`, packed with
  the same convention. No output needs a second squeezing permutation.
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
| Authorization state `A_A^(2g)` | `[18240 + 1600(g-1), 18240 + 1600g)` | none |
| Nullifier state `A_N^(2g)` | none | `[18240 + 1600(g-1), 18240 + 1600g)` |
| Selector `a_0, ..., a_31` | none | `[35840, 35872)` |
| Selector `b_0, ..., b_31` | none | `[35872, 35904)` |
| **Total `l`** | **35,840** | **35,904** |

**[D]** `256 + 384 + 2 × 11 × 1,600 = 35,840`; adding 64 selector bits gives
35,904.

The pad occupies the positions whose backend masks define the CRT label
offset: the gates use labels with `L_e^1 = L_e^0 ⊕ u[0, 256)` while the proof
publishes `d = w ⊕ u`, so a party that knows `w[0, 256)` learns the offset
(FAEST v3 section 6, Figure 6.2, cited by the review; not read by us). The pad
is prover randomness sampled per proof (section 1.7). It participates in exactly its 256 Booleanity constraints
and in no other application constraint; its coordinates take part in the
backend commitment, correction and consistency machinery like any other
witness coordinate.

### 1.4 Constraints

Transitions, for every permutation `D` of the relation:

```text
A_D^(2g)[t] + G_g(A_D^(2g-2))[t] = 0,     1 ≤ g ≤ 11,  0 ≤ t < 1600      (1)
O_D = G_12(A_D^(22))                      // an expression, not a witness
```

Registration outputs:

```text
O_C[t] + C[t]    = 0,     0 ≤ t < 1024                                    (2)
O_A[t] + auth[t] = 0,     0 ≤ t < 512                                     (3)
```

Vote selector, with `p_i = a_floor(i/32) · b_(i mod 32)`:

```text
a_j · sum_{k<j} a_k = 0,    b_j · sum_{k<j} b_k = 0,     0 ≤ j < 32       (4)
1 + sum_{j<32} a_j = 0,     1 + sum_{j<32} b_j = 0                        (5)
1 + sum_{i<S} p_i = 0                                                     (6)
```

Vote outputs:

```text
O_C[t] + sum_{i<S} p_i · C_i[t] = 0,     0 ≤ t < 1024                     (7)
O_N[t] + nf[t] = 0,                      0 ≤ t < 512                      (8)
```

Booleanity, supplied once by the generic wrapper for every witness coordinate,
selectors and pad included:

```text
w_i · (w_i + 1) = 0                                                       (9)
```

The multiplexer in (7) has degree two, because each `C_i[t]` is a public
scalar; its equality with the computed output has degree at most four. No
second selector-Booleanity block is appended.

### 1.5 Constraint order

| Registration block | Constraint indices |
| --- | --- |
| Booleanity (9), increasing witness index | `[0, 35840)` |
| Commitment transitions (1) | `[35840, 53440)` |
| Commitment output (2) | `[53440, 54464)` |
| Authorization transitions (1) | `[54464, 72064)` |
| Authorization output (3) | `[72064, 72576)` |
| **Total `M`** | **72,576** |

| Vote block | Constraint indices |
| --- | --- |
| Booleanity (9), increasing witness index | `[0, 35904)` |
| `a`-prefix constraints (4) | `[35904, 35936)` |
| `a`-sum (5) | `35936` |
| `b`-prefix constraints (4) | `[35937, 35969)` |
| `b`-sum (5) | `35969` |
| Range constraint (6) | `35970` |
| Commitment transitions (1) | `[35971, 53571)` |
| Commitment output (7) | `[53571, 54595)` |
| Nullifier transitions (1) | `[54595, 72195)` |
| Nullifier output (8) | `[72195, 72707)` |
| **Total `M`** | **72,707** |

Within a transition block the order is by `g`, then by state coordinate `t`.
Outputs are ordered by `t` and selector prefixes by `j`. Both identically zero
`j = 0` prefix constraints are retained: removing them would change every
later ZKHash position. Reordering any block changes ZKHash and therefore the
protocol.

Count ledger **[D]** (block lengths of the tables above, summed by kind):

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
| **Total `M`** | | **72,576** | **72,707** |

These are assigned degree bounds, not claims that every specialised coordinate
polynomial has exactly that degree; two prefix equations are zero polynomials.
The maximum native degree is four.

### 1.6 Homogenisation to nominal degree seven

For a constraint polynomial `f` of assigned degree `e` and formal witness
commitments `ρ_i(X) = V_i + w_i·X`:

```text
f^(X) = X^(7-e) · Hom_e(f)(ρ(X), X) = X^7 · f(ρ(X)/X)                    (10)
```

The expression is a polynomial because `deg f ≤ e ≤ 7`, and its coefficient of
`X^7` is exactly `f(w)`. Operationally: degree-aligned addition, then lifting
to seven. For example the degree-two multiplexer is aligned to degree four
before it is added to the degree-four Keccak expression. Every constraint
handed to ZKHash has nominal degree seven. A native degree of four is
compatible with `d_zk = 7` because (10) keeps the constraint as the top
coefficient and never exceeds degree seven; it does not justify replacing
seven by four in the root count of section 4.

### 1.7 Backend row, proving tape and counter rule

| Row | `lambda` | `tau` | `w_grind` | `T_open` | `d_zk` | CRT gates | Role |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Fast | 256 | 33 | 8 | 229 | 7 | 704 | Sole integration candidate |
| Small | 256 | 22 | 6 | 225 | 7 | 696 | Measurement comparator only |

The FAEST v3 leaf commitments are kept unchanged: leaf expansion, field
representation, universal-hash construction, tweaks, tree layout and
commitment lengths. The official CRT tables and gate order are kept. Official
component and plain-FAEST signature vectors are conformance targets for the
unchanged reference-mode backend only; the ballot namespaces, padded witnesses
and custom relations need their own vectors, and passing the official vectors
does not validate their composition. The role prefix is a namespace parameter
added to the ballot hash invocations; the primitive algorithms, suffix bytes,
field representation, PRG, CRT tables and leaf-commitment formula are
retained. An empty prefix reproduces the original hash inputs in reference
mode; genuine signature reference mode must also retain the official OWF and
`H3` derivation. **Empty-prefix mode is not an accepted ballot mode.**

Each proof invocation obtains exactly 80 fresh bytes from the caller's
fallible cryptographic RNG:

```text
r      = tape[0..32]
iv_pre = tape[32..48]
pad    = tape[48..80]
```

- In the security model these are independent uniform coins, independent of
  the application witness, the public message and previous tapes.
- An entropy failure returns an error and produces no proof. There is no
  secret-derived, deterministic or zero-filled production fallback. Fixed tapes
  are permitted for reproducible tests.
- The raw pad is supplied only as witness bits `[0, 256)`. It then necessarily
  affects `d`, the pad Booleanity constraints, the masked response
  calculations and the downstream challenge hashes; those derived effects are
  not excluded.
- `r` feeds the ordinary backend root expansion and the existing high-mask
  expansion `PRG(r, iv, 2^31 − 1; n_mask · w_grind bits)`. The second use is
  already part of the backend's VOLE commitment (the review cites
  `crates/iroha_zkp_vole/src/vole.rs`), not an additional tape derivation.
- **There is no `H3` call in ballot proving.** `iv = H4(iv_pre || mu)` is
  retained, under the role prefix. `iv_pre` is transmitted and is hashed
  directly in `H4` and in the first challenge. There is no separate hash of
  the tape, of the raw `r` or of the raw pad.
- Owned tape buffers, `r`, the pad and transient secret witness, VOLE, tree
  and hash material are erased on success, error and exhaustion, including
  temporary copies of the credential secret (not the wallet's retained
  credential). The public `iv_pre` need not be erased from the returned
  proof; its copy inside the tape buffer is erased.
- The commitment, the corrections, the first two challenges and the response
  coefficients are computed once. The prover then tries every counter in order
  from `0` through `0xffff_ffff` inclusive:

  ```text
  chall_3 = H2^3(chall_2 || ToBits(ã_0, ..., ã_6) || LE32(ctr), 256 bits)
  ```

  with the role prefix `PREFIX_R` before the stated body and the suffix byte
  `0b` after it (profile record section 6). `ã_0` is hashed and is not
  serialised in the proof. An attempt is rejected unless its grinding
  suffix is zero and its canonical BAVC opening fits the row's threshold. The
  first success is returned.
- On exhaustion the prover returns `GrindingExhausted`. It never wraps. A later
  invocation needs an entirely fresh 80-byte tape.
- The verifier checks the supplied counter and opening once. It does not
  establish counter minimality and never replays earlier attempts.

The arguments must analyse this exact fresh-randomness, incrementing-counter
prover. A verifier-only false-statement analysis may use the unchanged
acceptance predicate; the joint zero-knowledge and authorization proofs must
reproduce the honest transcript and stopping distribution.

Raw proof sizes **[R]**, reproduced **[D]** from
`11,748 + 33·l/8` (fast) and `10,554 + 22·l/8` (small):

| Proof | Fast row, bytes | Small row, bytes |
| --- | ---: | ---: |
| Registration, `l = 35,840` | 159,588 | 109,114 |
| Vote, `l = 35,904` | 159,852 | 109,290 |

The public `auth` adds 64 bytes to the registration statement. Statement and
envelope framing are additional; envelope compliance needs measurement against
the exact schema.

Changes considered by the review and not adopted: widening the 64-bit
evaluation points (unnecessary at these dimensions, section 3); direct
domain-separated hash commitments to leaf seeds (not an established solution
to the extraction problem); a public salt in the credential commitment (it
establishes neither knowledge nor non-malleability, and a conventional salt
would cross the 136-byte rate and add a permutation); a vote authorization
value (section 1.1); a `lambda = 384` backend to compensate for the comparison
bound of section 8.

## 2. Encoding equivalence

Status: complete (awaiting review). The review's proof covers the commitment
and nullifier permutations and the selector; the pad and the authorization
permutation are covered by the same steps, as marked **[D]**.

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

1. Every coordinate is Boolean, so (9) holds, for the pad as well **[D]**.
2. (1) holds by construction, for each permutation.
3. Each selector vector has one active entry, so (4) and (5) hold.
4. Exactly one pair product is one and its index is below `S`, so (6) holds.
5. The multiplexer equals `C_i`; the hash equalities of the relation give (7)
   and (8), or (2) and (3) for registration **[D]** for (3).

**Reverse.** Suppose every constraint vanishes for `w ∈ K^l`.

1. *Booleanity.* `K` is a field, so `w_i·(w_i + 1) = 0` implies
   `w_i ∈ {0, 1}`. This applies to every coordinate: pad, secret, committed
   state bits and selectors. The pad occurs in no other constraint, so it is an
   arbitrary Boolean string and is projected away **[D]**.
2. *Keccak.* `A_D^(0)` is fixed by the public bytes and the shared secret
   coordinates `[256, 640)`. Induction over `g = 1, ..., 11` in (1) forces
   every committed state to equal the actual state after `2g` rounds, so `O_D`
   is the actual final state and its leading bits are exactly the required
   SHAKE output. The same induction applies to the authorization permutation,
   whose only differences are the public bytes `PAU1` and `D_reg` **[D]**.
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
5. *Outputs.* (7) equates the commitment output to exactly `C_i` and (8) the
   nullifier output to `nf`; for registration (2) gives `C = Com_B(sk)` and (3)
   gives `auth = Auth_(D_reg)(sk)` **[D]** for (3).

All permutations of a relation read the same 384 secret coordinates; there is
no independently chosen nullifier or authorization secret. Through (10) this
gives the implication used in section 4:

```text
every top coefficient Z is 0  ⇒  a Boolean valid witness exists           (11)
```

The implication needs the wrapper's Booleanity constraints: effective
witnesses in the soundness analysis lie in the extension field, not
necessarily in `{0,1}^l`. The AES key-validity restriction of plain FAEST is
unnecessary for (11); its separate role in FAEST's false-key argument is a
different matter (section 6, property 2).

## 3. Universal-hash bounds for the larger relation

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
expansion length `l^ = l + 80` is the polynomial length.

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
eps_v ≤ 2^(-4·lambda) · (1 + (l' - 1)^5 / 2^64)                           (12)
```

For an input with zero polynomial part and nonzero additive part a zero hash
is impossible; otherwise the additive part only specifies a target for the
calculation above. This is almost universality. Uniform independent additive
masks also give the hash's hiding property directly.

### 3.2 ZKHash

The polynomial part has `M` coordinates, so its degree is at most
`M - 1 = M' - 2`. For a nonzero such `P`, the two independent evaluations
`P(s)`, `P(t)`, with `s` uniform in `K` and `t` uniform in the short subset,
vanish together with probability at most `(M - 1)^2 / 2^(lambda + 64)`. Outside
that event, multiplication by the independently uniform row `(r_0, r_1)` gives
a uniform field element. Accounting for the final additive coordinate:

```text
eps_zk ≤ 2^(-lambda) · (1 + (M - 1)^2 / 2^64)                             (13)
```

The form with `(M' - 1)^2 = M^2`, which uses the conservative degree bound
`M`, is valid but slightly loose; (13) is the form to record. The independent
final additive coordinate gives perfect hiding at any vector length. Hash
hiding alone is not protocol zero knowledge.

### 3.3 Substitutions at the final dimensions

**[R]**, each value recomputed **[D]** from (12) and (13) with the inputs
shown.

| Quantity | Registration | Vote |
| --- | ---: | ---: |
| `l` | 35,840 | 35,904 |
| `l' = l + 6` | 35,846 | 35,910 |
| `n = l + 5` | 35,845 | 35,909 |
| `M` | 72,576 | 72,707 |
| `M' = M + 1` | 72,577 | 72,708 |
| `1 + n^5 / 2^64` | 3208.917576670 | 3237.658150124 |
| `log2` of the bound (12) | −1012.352129 | −1012.339265 |
| `(M - 1)^2 / 2^64` | 2.8553172332 × 10^-10 | 2.8656343986 × 10^-10 |

Both hash bounds are independent of the parameter row; the row enters in
section 4 through the size of the challenge set.

**Neither 64-bit evaluation point needs widening.** The challenge lengths stay
`|chall_1| = 8·lambda + 64 = 2,112` and `|chall_2| = 3·lambda + 64 = 832` bits
with the existing short-point injection. Widening to `b` bits would replace
`2^64` by `2^b` in (12) and (13), change the challenge lengths to
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

which (12) bounds by `eps_v`. A union over triples gives the first bad event:

```text
eps_1 ≤ eps_v · binom(|D_Δ|, 3)                                           (14)
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
knowledge extractor.**

**Effective witness.** Split the line into witness and mask coordinates. The
effective witness is `w* = d + u* ∈ K^l` with commitments
`ρ_i(X) = V_i* + w_i*·X`. Applying the ordered constraint system and (10)
gives `sum_{j=0}^{6} A_j·X^j + Z·X^7`. By (11), `Z = 0` would make `w*` a
Boolean valid witness for `x` (its pad coordinates included and then
discarded). The instance is false, so `Z ≠ 0`. This replaces the AES-specific
relation step of the original argument and needs no key-validity restriction.

**Second challenge.** `Z` is fixed before it, so
`ζ = ZKHash(chall_2, (Z, 0))` vanishes with probability at most

```text
eps_2 ≤ eps_zk                                                            (15)
```

The six QuickSilver mask correlations contribute
`M_mask(X) = sum_{j=0}^{5} (v̄_j* + ū_j*·X)·X^j = sum_{j=0}^{6} p_j·X^j` and no
degree-seven coefficient. With `a_j = ZKHash(chall_2, (A_j, p_j))`, linearity
gives, for a passing response on the extracted line,
`q̃ = sum_{j=0}^{6} a_j·Δ^j + ζ·Δ^7`.

**Third challenge.** Before it the prover fixes its claimed coefficients
`ã_0, ..., ã_6`. Outside the second bad event, acceptance requires

```text
E(Δ) = 0,     E(X) = sum_{j=0}^{6} (ã_j - a_j)·X^j - ζ·X^7                (16)
```

a nonzero polynomial of degree exactly seven. The raw third challenge is
uniform over `2^256` strings; a nonzero grinding suffix rejects, and the
remaining strings map injectively to `D_Δ`. At most seven raw strings reach
roots of (16):

```text
eps_3 ≤ 7 · 2^-256                                                        (17)
```

The fourth, dummy challenge contributes zero.

**Conclusion.** Define a flag that is set at any of the three bad events and
stays set. An accepted false-instance transcript with the flag clear would lie
on the extracted line, have `ζ ≠ 0` and satisfy (16), contradicting the
absence of the third event.

Round errors. Fast row **[R]**, reproduced **[D]**; small row **[D]** by the
same formulas with `|D_Δ| = 2^250`, consistent with the coefficients the
review gives for that row:

| Core round | Fast, registration | Fast, vote | Small, registration | Small, vote |
| --- | ---: | ---: | ---: | ---: |
| 1: `log2` of the bound (14) | −270.937091 | −270.924228 | −264.937091 | −264.924228 |
| 2: bound ÷ `2^-256` | 1 + 2.8553 × 10^-10 | 1 + 2.8656 × 10^-10 | the same | the same |
| 3: bound | `7 · 2^-256` | `7 · 2^-256` | `7 · 2^-256` | `7 · 2^-256` |
| 4 | 0 | 0 | 0 | 0 |

Round 1 uses `eps_1 < (1 + (l + 5)^5 / 2^64) / 6 · 2^-280` on the fast row and
`· 2^-274` on the small row. On both rows the **core maximum round error** is

```text
eps_core,rbr ≤ 7 · 2^-256 = 2^-253.192645                                 (18)
```

This is not conditioned on a successful grinding suffix: under that
conditioning alone the root-count bound is `7 / 2^248` (fast). Conditioning
further on an opening that fits `T_open` requires the size of that accepted
subset. The opening threshold can only remove accepting raw challenges, so it
does not worsen (17).

**Additional rounds imported from the standard analysis.** For the expanded
interactive protocol of standard FAEST the further challenge errors are

```text
eps_-3 = eps_-1 = eps_0 = 0,      eps_-2 = tau · 2^-lambda                (19)
```

that is `33 · 2^-256` (fast) and `22 · 2^-256` (small). The event concerns
leaf-hash injectivity. (19) imports the unchanged leaf-hash analysis (FAEST v3
Lemma 10.48) with the extended core argument substituted into the later
rounds, so (18) is the maximum for the core, not for all seven challenges. The
structural assumptions are the standard FAEST leaf construction, the specified
CRT maps and their injectivity. On the fast row there are 17 eight-bit and 16
seven-bit small-VOLE challenges, 248 bits and 6,400 leaves, and the elementary
parameter conditions hold: `tau > 1`, `3 × 128 > 2`,
`(tau + 1)·2^8 = 8,704 < 2^31`. These checks certify no implementation of
those maps.

Sum of the seven interactive challenge errors for one execution:

```text
fast:   eps_run ≤ [41 + (1 + (l+5)^5/2^64)/(6·2^24) + (M-1)^2/2^64] · 2^-256   (20)
small:  eps_run ≤ [30 + (1 + (l+5)^5/2^64)/(6·2^18) + (M-1)^2/2^64] · 2^-256
```

| Coefficient of `2^-256` | Registration | Vote |
| --- | ---: | ---: |
| Fast row | 41.00003187801757 | 41.00003216353056 |
| Small row | 30.00204017513642 | 30.00205844790195 |

**[R]**, reproduced **[D]**.

**What this is not.**

- It is not an efficient knowledge extractor. The extraction map is
  mathematical and may inspect the whole response graph.
- It is not the Fiat–Shamir proof-of-knowledge game. It is the response-graph
  experiment that underlies the algebraic argument, for a false instance.
- It is not a lifetime ledger. For a separately justified collection of at
  most `2^44` fresh interactive executions, even with adaptation between
  executions, the union bound from (20) is about `2^-206.642447` on the fast
  row, below `2^-128`. That is an interactive component calculation: the
  honest-transcript ceiling does not bound adversarial Fiat–Shamir queries or
  retries, and no argument here converts those queries into at most `2^44`
  fresh-challenge opportunities.
- It is not an authorization argument. A list that contains adversarial
  credentials need not become a false statement when an honest entry is
  replaced (section 6, property 2).

## 5. Oracle environment and games

### 5.1 Common environment

Distinctions that every argument below keeps:

1. **Constraint correctness** is the deterministic statement of section 2. It
   needs no assumption that credential SHAKE behaves as a random oracle.
2. **Backend QROM arguments** model the designated transcript and commitment
   hashes as quantum-accessible random oracles and require the specified
   quantum PRG and commitment assumptions.
3. **Credential hiding, pseudorandomness and hidden-key recovery** require
   separate quantitative assumptions or ideal-model theorems about the
   commitment, nullifier and authorization functions, including their joint
   use under one secret.
4. An argument that programs an abstract credential oracle must explain its
   consistency with the fixed Keccak circuit being proved. Changing the oracle
   does not change the circuit's accepted relation.

The adversary is a resource-bounded quantum algorithm with coherent access to
every explicitly modelled public oracle. Initial quantum advice is independent
of fresh honest secrets and of the sampled random oracles; oracle-dependent
preprocessing is charged to the query budget. Honest proof-generation,
registration, corruption and submission queries are classical. Superposition
access to an honest prover is a stronger game and is not claimed.

APIs, with classical requests and replies:

1. `NewHonest(B)` samples a fresh 384-bit secret, records a handle `j` and
   publishes its commitment **before registration**.
2. `RegisterMalicious` accepts arbitrary canonical commitment and proof
   submissions and applies the stated verification policy. It never demands
   disclosure of a malicious registrant's secret.
3. `Seal` creates an admissible, authenticated, immutable list from the
   registration state.
4. `RegProof(j, request)` generates a fresh honest registration proof for a
   permitted request and logs its exact canonical public input. The
   authorization is logged before `auth` is exposed, including when the
   subsequent proof generation fails (section 6.8).
5. `VoteProof(j, request)` generates a fresh honest vote proof when the
   handle's commitment belongs to the list, computes its correct nullifier and
   logs its exact canonical public input.
6. `Corrupt(j)` releases that credential's secret, subject to the exclusions
   of the particular game.

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

### 5.2 Games

**Property 1: fresh-authorization knowledge extraction.** "Every submitter
knows the secret" cannot hold literally: a published proof can be copied
without learning its witness. For every adversary `A` there must exist an
efficient extractor `E` that runs an instrumented execution of `A` in the
common environment and outputs a candidate witness `ŵ` whenever `A` outputs
`(role, x, π)`. With `Fresh(role, x) ⇔ (role, x) ∉ Issued`, where `Issued`
holds the exact public inputs of both honest proof types, require

```text
Pr[ V_role(x, π) = 1 ∧ Fresh(role, x) ∧ ¬R_role(x; ŵ) ] ≤ κ_1(q, T, U)    (21)
```

together with an explicit bound on the extractor's running time, oracle
queries and disturbance of the adversary's observable execution. The
extractor receives public replies and legitimate corruption replies; it does
not receive uncorrupted honest secrets or proving tapes; it cannot clone
unknown quantum states or inspect arbitrary private registers; it may use a
specifically proved compressed-oracle extraction interface. A semantic witness
`sk` or `(sk, i)` suffices (the Keccak trace is regenerated and the pad is
projected away). Same-input replay and rerandomization are exempt; honest
proofs for other messages remain available to the adversary. This is stronger
than an isolated argument-of-knowledge experiment without honest proof
oracles.

**Property 2: target-origin chosen-message unforgeability.** Run the common
environment with malicious registrations, mixed lists, both honest proof
oracles and adaptive corruption. The adversary outputs `(j, x*, π*)` for a
vote and wins exactly when

```text
V_vote(x*, π*) = 1,
j is uncorrupted through the final output,
Com_(B*)(sk_j) ∈ L*,
nf* = Tag_(scope*)(sk_j),
(j, x*) ∉ VoteLog                                                         (22)
```

This includes changing the vote, the policy or another bound field under an
observed honest nullifier, and excludes exact-input replay and
rerandomization. A mixed-list ballot whose nullifier belongs to no honest
target is not automatically a forgery: it may be a legitimate adversarial
member's ballot.
Unexplained additional nullifiers are the subject of properties 1 and 3. No
game defines winning by the unobservable phrase "the adversary does not know
the key".

**Property 3: nullifier uniqueness.** Fix an authenticated seal `(B, L, S)`
and its scope; the adversary has the entire preceding adaptive registration
and proof history. Partition the sealed entries into honest entries whose
secrets remain uncorrupted through the adversary's output, and adversarially
registered or corrupted entries. `k` is the size of the second class; an
adversarial registration counts in it even if the registering party knows no
opening, which avoids assuming registration knowledge in the definition of
"controlled". `H` is the set of tags returned by honest ballot-proof queries
for this seal and scope. The adversary wins if it supplies cryptographically
accepted ballots with more than `k` distinct tags outside `H`. Exact replay or
rerandomization under an existing tag does not increase the count.

**Property 4: cross-scope unlinkability.** The adversary sees the honest
commitments and the registration mapping, makes adaptive registration and
ballot-proof queries, registers malicious credentials and corrupts
non-challenge credentials. It names two eligible, uncorrupted honest
credentials `sk_0`, `sk_1` and two distinct scopes `x`, `y`. It may hold a
labelled reference tag for `sk_0` at `x`. At `y` it receives a challenge
ballot from `sk_b` for a hidden bit `b`.

- The challenge credential and scope pairs must not already be exposed through
  labelled queries; later queries must not reveal either pair's label or
  either challenge secret.
- Public votes, eligibility, list membership and all other permitted public
  leakage have the same distribution for both values of `b`.
- `Δ_link = | Pr[A outputs 1 | b = 0] − Pr[A outputs 1 | b = 1] |`.
- Excluded: identification from a distinctive vote, transport identity,
  timing, an anonymity set reduced to one by public information, or later
  secret disclosure. The construction deliberately permits retrospective
  linkage after the secret is disclosed.

**Property 4: non-frameability.** The literal statement "nobody can produce a
valid proof under another participant's entry" is false, because published
proofs can be copied; the claim concerns fresh authorization. A *vote frame*
is an accepted ballot with `nf = Tag_scope(sk_j)` for an uncorrupted honest
credential `j` whose honest prover never authorized the complete message `m`.
A *registration frame* is a win in the property 8 game. Exact-message replay
and rerandomization are excluded.

**Property 5: joint zero knowledge.** The target is standard adaptive
multi-theorem joint zero knowledge for **arbitrary application witnesses and
arbitrary auxiliary information about those witnesses**, not an
honest-key-only simulation game.

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
   `auth`, nullifier or other fields.
5. For a valid request, respond as follows.
   - **Real:** obtain an independent uniform 80-byte tape, construct the
     padded extended witness and run the exact prover, including the
     incrementing counter and the exhaustion outcome.
   - **Simulated:** invoke `Sim(role, x)`. The simulator receives neither the
     application witness, the selected index, the trace, the pad, nor the
     adversary's private auxiliary state. Return its proof or exhaustion
     outcome.
6. The simulator may program only the designated backend oracle domains. It
   cannot alter credential functions, public statements, authoritative context
   or application authentication decisions.
7. The adversary may interleave requests with quantum oracle queries,
   verification, malicious registrations and other application operations. It
   may retain, disclose and use application witnesses at any time. There is
   **no tape-selection or secret-coins-disclosure interface**. The transmitted
   `iv_pre` is public and is expressly permitted.
8. After the final proof request, continue allowing quantum oracle access
   until the adversary outputs a bit. Define

   ```text
   Adv_JZK = | Pr[A → 1 | b = 0] − Pr[A → 1 | b = 1] |
   ```

   Count preprocessing, interleaved queries and subsequent queries. Apply the
   recorded lifetime ceilings, including repeated proof generation: at most
   `2^10` fresh transcripts per credential and `2^44` in total.

Two clarifications:

- "Identical public-input rules" does not mean that the adaptive executions
  remain identical after different replies.
- This game imposes no hidden-honest-key requirement. The separate anonymity
  game keeps its challenge-secret disclosure exclusions. Simulator totality on
  syntactically valid **false** statements remains an additional interface
  requirement for property 4 (section 6.4); the joint zero-knowledge
  experiment invokes simulation only for valid witnessed statements.

A prover that accepts an adversarially fixed or disclosed tape or pad is a
different algorithm, to which the target theorem is not claimed to apply.

**Property 5: anonymity.** A separate left/right game, because a
zero-knowledge proof can coexist with publicly identifying statement values.
It keeps hidden honest challenge credentials and its disclosure exclusions.

1. The adversary selects two uncorrupted honest handles whose commitments
   occur in the same authenticated list and body.
2. It supplies common public voting fields except the nullifier.
3. A hidden bit selects which handle supplies the nullifier and the proof.
4. Registration proofs and other-scope vote proofs remain available before
   and afterwards.
5. Identified vote or nullifier queries for either candidate at the challenge
   scope are forbidden, including prior queries. Later disclosure of either
   candidate is excluded.
6. The adversary guesses the bit.

For multiple challenge queries the equality patterns must be identical in the
two worlds, for every pair of challenge requests `s`, `t`:

```text
[(j_0,s, scope_s) = (j_0,t, scope_t)] = [(j_1,s, scope_s) = (j_1,t, scope_t)]
```

Otherwise public nullifier equality itself distinguishes.

**Property 6: concrete security.** Not a game: the requirement that every
game of this section has a complete deployment-wide bound that satisfies the
contract of section 8.1.

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
(j, x_reg*) ∉ RegLog                                                      (23)
```

`RegLog` is kept per honest handle, together with the log of authorization
digests `AuthLog[j]`, under the logging rule of section 6.8. The challenger
knows `sk_j`, so the third condition is efficiently decidable even for a new
body `B*`. Publishing the commitment before registration covers
front-running. Freshness covers changed authorities, assignments and contexts.
Exact-input replay and rerandomization do not win. `x_reg*` contains `auth*`
through `m_reg` (section 1.1).

## 6. Arguments by property

### 6.1 Property 1: authorization

Status: incomplete.

Assumptions: the backend QROM model and its PRG and commitment assumptions;
authenticity of the seal. To be proved: (21).

Skeleton:

1. Canonical verification supplies the exact public statement and the
   authenticated list.
2. A putative efficient extractor recovers an effective committed witness.
3. Booleanity, grouped-Keccak correctness and the selector lemma give (11)
   (section 2).
4. Projection gives the secret, the selected index and the correct nullifier
   (for registration, the secret and the correct `auth`) required by (21).

Steps 1, 3 and 4 are written. **Step 2 is missing.** Why the published
techniques do not supply it:

| Technique | Why it does not supply step 2 |
| --- | --- |
| Published FAEST soundness route (section 4 here) | Its mathematical extraction may inspect an entire response graph or invert commitment-generation functions with no polynomial-time guarantee. That suffices for a false statement, where no witness exists; it is not an algorithm satisfying (21). The specific obstacle: a preimage of the aggregate commitment hash can reveal leaf commitment values without revealing the PRG seeds needed to reconstruct the witness. |
| Lossy-key argument | It bounds acceptance after switching to a false instance. It recovers no witness on the real true instance. |
| Adaptive reprogramming | It controls a distributional change, not witness recovery. |
| Online extractability for ordinary and Merkle commit-and-open protocols (Don–Fehr–Majenz–Schaffner, Definition 3.4, Theorems 4.2 and 5.2; the paper was read by us in part, profile record section 13; the cited definition and theorems and their use here are the review's **[R]**) | Requires efficient special-soundness reconstruction for the specified protocol forms. FAEST's corrections, masked polynomial responses and multiple challenges do not satisfy those hypotheses merely because it uses a tree. |
| Running a standalone extractor repeatedly on a quantum adversary | The composition, its disturbance of the adversary's state and its query overhead are themselves part of the missing theorem (needed by property 3). |

Technique to try: first an efficient reconstruction theorem for the underlying
interactive VOLE protocol, then a quantum extraction transformation compatible
with the exact multi-round transcript and the honest-proof environment. The
FAEST v3 leaf commitments are kept; direct hash commitments to leaf seeds
would make compressed-oracle seed recovery more plausible but are not an
established solution and would not alone give multi-round knowledge
extraction.

Difficulty: hard but plausible research. A sufficiently tight extractor that
meets the lifetime contract is unresolved. The registration authorization
value does not remove this obligation.

### 6.2 Property 2: unforgeability

Status: incomplete.

Assumptions: as for property 1, plus a primitive game for the credential
functions that includes public commitment leakage, other-scope outputs,
multiple users and adaptive contexts. An isolated hash-preimage statement does
not replace it.

Extraction-based reduction:

1. Provide both honest proof types under the target secret without exposing
   that secret to the reduction.
2. Extract `sk*` from a fresh successful forgery.
3. Relation correctness gives `Com_(B*)(sk*) ∈ L*` and
   `Tag_(scope*)(sk*) = Tag_(scope*)(sk_j)`.
4. If `sk* = sk_j`, the reduction recovers the honest secret.
5. Otherwise it obtains an explicit target nullifier collision or second
   preimage.
6. Charge simulation, extraction, primitive-security and adaptive-target
   losses.

**Steps 1 and 2 are missing, including their composition.** A standalone
zero-knowledge theorem and an ordinary knowledge theorem do not compose
automatically: extraction may use oracle access that observes programming
hidden from an ordinary distinguisher. A joint extraction and simulation lemma
is needed. Simulation-extractability would suffice but is stronger than the
only possible route.

False-instance route, and why it is not available as is:

- Dropping the AES key-validity restriction does not preserve the plain-FAEST
  unforgeability proof. The restriction is used in the signature reduction's
  false-key transition; the custom list relation has no lossy-key step.
- An adversarial list entry does not automatically keep a statement with a
  fixed honest nullifier true: its opening must also produce that nullifier.
  Conversely, making one honest commitment lossy does not establish that every
  alternative list witness has disappeared; an adversary can choose a tag
  supported by its own entry.
- A complete false-instance proof must eliminate all alternative witnesses.
  Ordinary computational collision resistance is insufficient for that
  existential step when the reduction never obtains the alleged colliding
  secrets. The 512-bit nullifier is not globally injective on the 384-bit
  secret space.

Neither the single-key lossy argument, static compressed-oracle soundness,
adaptive reprogramming nor the existing commit-and-open theorem supplies the
adaptive mixed-list reduction. A reduction that guesses one target among `U`
honest registrations may lose a factor up to `2^34`; a multi-user proof must
avoid or charge it.

Technique to try: the joint extraction and simulation lemma above, after
registration origin (property 8), whose range is sparse. Difficulty: hard but
plausible.

### 6.3 Property 3: nullifier uniqueness

Status: conditional.

Premises:

1. **Joint adaptive knowledge authorization (property 1).** An extractor for
   the relevant collection of adversarial output proofs, in the environment
   with both honest proof types. Except with total error `ε_K` it returns valid
   witnesses `(sk, i)` for every retained accepted output; the guarantee
   includes preservation of the adversary's output distribution and all
   extraction failures and distinguishing losses.
2. **Adaptive multi-user ballot unforgeability (property 2).** `ε_2` bounds
   the probability of any fresh-message ballot authorization under an
   uncorrupted honest credential, with malicious registrations, corrupt
   credentials and both honest proof interfaces, in a game that accepts a
   bounded list of candidate outputs and wins if any is a forgery.
3. **Adaptive-context commitment collision resistance.** `ε_C` bounds success
   in producing `(B, sk, sk')` with `sk ≠ sk'` and `Com_B(sk) = Com_B(sk')`,
   with adversarially selected valid contexts and the reduction's complete
   extraction overhead.
4. The validated-list contract, relation correctness (section 2) and complete
   message binding hold.

**Conditional theorem.**

```text
Pr[Win_3] ≤ ε_K + ε_C + ε_2                                               (24)
```

Reduction:

1. Retain `k + 1` accepted outputs with distinct tags outside `H`.
2. Apply the joint extractor; charge failure or output-distribution error to
   `ε_K`.
3. Suppose an extracted output selects an honest entry `C_i` generated from
   `sk_i`. If its extracted secret differs from `sk_i`, the pair is a
   commitment collision. Otherwise its tag equals `Tag_scope(sk_i)`; that tag
   is outside `H`, so no honest ballot query authorized it in the target
   scope, the complete output message was not authorized, and the accepted
   proof is a property 2 forgery.
4. Otherwise all `k + 1` outputs select controlled entries. By the pigeonhole
   principle two select the same one of the `k` entries. Their tags differ and
   `Tag_scope` is a deterministic function, so their extracted secrets differ:
   a commitment collision.

The cases exhaust a winning execution. The collision reduction generates the
honest credentials itself and knows their openings; the unforgeability
reduction forwards candidate outputs and does not need the honest secrets.

If property 2 is available only as a single-output game, selecting a uniformly
random retained output gives

```text
Pr[Win_3] ≤ ε_K + ε_C + 1000 · ε_2,single                                 (25)
```

The factor is needed only in the honest-entry case, where `k < S` and so
`k + 1 ≤ 1,000`.

Notes:

- No collision resistance of the tag function is needed: tag collisions only
  reduce the number of distinct tags.
- Determinism is unconditional: equal `sk` and equal scope give equal tags,
  independently of the vote and the proof randomness.
- Property 8 is not required for (24) under the conservative partition. It is
  required for an interpretation in which account registration establishes
  honest credential origin despite front-running and recontextualization;
  then add the deployment-wide registration-origin failure `ε_8`. If
  "controlled" means "has a known opening", registration knowledge is also
  required to justify the partition.
- A different route replaces extraction and computational collision
  resistance by ordinary soundness and **global injectivity** of `Com_B` in
  all relevant contexts. That is a stronger premise; computational collision
  resistance does not establish it when no reduction obtains the purported
  openings.

At the contract ceilings (24) is
`ε_K(q_K, U, T, J) + ε_C(q_C, J) + ε_2(q_2, U, T, J)`, where the query budgets
include each reduction's work. **None of the three has an established
numerical value for this construction.** Substituting zero for them would
invalidate the quantitative conclusion.

### 6.4 Property 4: unlinkability and non-frameability

Status: conditional.

**Unlinkability.** Premises:

1. `ε_Z`: the joint adaptive multi-theorem quantum zero-knowledge gap for both
   proof types (property 5), in the same auxiliary environment.
2. `ε_SP`: **secret-prefix pseudorandomness with public commitment and
   simulation access.** Given `Com_B(sk_j)` for the honest secrets, the
   permitted auxiliary data and corrupted secrets, and quantum access to the
   primitive interfaces, the functions `x ↦ Tag_x(sk_j)` of the remaining
   honest credentials are indistinguishable from independent random functions
   on scopes. The experiment must permit the exact backend-simulator and
   oracle-programming interface used in the reduction and account for all its
   work. Registration also publishes `auth = Auth_(D_reg)(sk_j)`, so the
   auxiliary data of this assumption includes the authorization values **[D]**
   (consequence of section 1.1; the review's statement of the assumption does
   not mention `auth`).
3. The joint simulator is a total efficient oracle machine on syntactically
   valid public inputs; it programs only the backend transcript namespaces,
   not the credential, tag or authorization primitive namespaces; and the
   `ε_SP` game supports running it.

The assumption concerns the same secret in the public commitment and in the
secret-prefix tag function. It is not implied by ordinary SHAKE collision
resistance, ordinary preimage resistance, or PRF security without that
auxiliary commitment. Domain separation makes the inputs distinct; it does not
prove the assumption for the concrete sponge.

The simulator premise matters because replacing a correct tag by an
independent random value generally creates a false ballot statement. The
zero-knowledge guarantee is needed only at the true-statement endpoints;
running the simulator on an intermediate false statement asserts no zero
knowledge for false statements.

| Hybrid | Change | Gap |
| --- | --- | ---: |
| `H_0` | Real execution, challenge identity 0 | — |
| `H_1` | Replace all honest registration and ballot proofs by the joint simulator | ≤ `ε_Z` |
| `H_2` | Replace honest tag functions by independent random tables, preserving repeated-input equality | ≤ `ε_SP` |
| `H_3` | Change the challenge identity from 0 to 1 | 0 |
| `H_4` | Restore the real tag functions | ≤ `ε_SP` |
| `H_5` | Restore the real honest proofs | ≤ `ε_Z` |

The zero-cost transition is exact: the challenge uses a fresh random-table
entry, independent of the public commitments and of entries at other scopes,
and both branches have identical permitted leakage. Accidental equal random
outputs need not be excluded; their distribution is also identical. The
primitive distinguisher implements each tag replacement by forwarding the
credential and scope queries to its real-or-random interface and running the
same simulator on the resulting public statements. The endpoint
zero-knowledge distinguishers run the adversary and the corresponding
true-statement proof environment.

```text
Δ_link ≤ 2·ε_Z + 2·ε_SP                                                   (26)
```

Alternative route: program the hidden secret-prefix inputs of the tag oracle
consistently with the ideal tags, keeping the statements true throughout.
That needs a quantitative quantum hidden-point programming theorem and its
composition with the joint backend simulator. **That step is missing.**
Ordinary joint zero knowledge plus an unqualified PRF assertion does not
supply it.

At the lifetime ceilings the conclusion is
`2·ε_Z(q_Z, 2^34, 2^44, 2^24) + 2·ε_SP(q_SP, 2^34, 2^44, 2^24)` with the
per-credential `2^10` limit. **Neither term is quantified.**

**Non-frameability.**

- If property 2 uses the tag-based winning condition (22), the reduction is
  the identity: forward the environment and return the framed ballot.

  ```text
  Pr[Frame_vote] ≤ ε_2                                                    (27)
  ```

  If property 2 instead attributes a forgery by extracted witness origin, a
  tag-collision term is needed to translate it into the observable tag-based
  game. An accepted proof hides its selected index, so "under an entry" must
  not stay undefined.
- Registration framing, including a fresh registration message or a
  recontextualization under an uncorrupted honest credential, is property 8:

  ```text
  Pr[Frame_reg] ≤ ε_8                                                     (28)
  ```

Cross-scope observations therefore give no additional framing capability
**conditional on the joint oracle-access games of properties 2 and 8**, which
must already permit observations of both proof types.

### 6.5 Property 5: zero knowledge and anonymity

Status: incomplete.

Assumptions: the backend QROM model; the PRG and multi-hiding assumptions at
the actual lengths, tables and randomness; for anonymity additionally a
hidden-input assumption on the credential functions. To be proved: a bound on
`Adv_JZK` for the game of section 5.2, and the anonymity bound.

**Why the pad.** If the first 256 witness bits are known, then
`u[0, 256) = d[0, 256) ⊕ w[0, 256)` is known and, under the free-XOR-label
analysis, the intended CRT-mask hiding is defeated. A layout whose first 256
bits are credential bits cannot give unrestricted all-witness zero knowledge:
uniform sampling of a secret is not conditional entropy once its commitment,
which may determine it, is public. With the pad those positions hold fresh
proof coins independent of the application witness. The padded protocol
requires a modified-backend proof. **Adding the pad supports the stronger
target; it does not establish it.**

**The pad argument, precisely.** Split the extended witness `W`, the VOLE
mask `U` and the correction `d` at bit 256:

```text
W = (P, W_app),    U = (U_P, U_app),    d = (P ⊕ U_P, W_app ⊕ U_app)
```

- Knowing the application witness reveals `W_app`, including its trace, and
  therefore reveals `U_app` from `d`. The argument must tolerate this.
- The CRT label offset is `U_P`. The first part of `d` masks it with the fresh
  proof coins `P`. In an ideal uniform-mask hybrid one can sample `d_P`, the
  first part of `d`, and define `P = d_P ⊕ U_P`; this preserves that
  elementary distribution.
- **It does not prove conditional hiding after the complete proof is
  exposed.**

**Candidate witness-free simulator.** The review wrote this simulator and the
hybrid list below for the honest-key game of its part 3 and for the layout
whose first witness bits are credential bits. For the padded protocol and the
decided target, in which the simulator receives neither the application
witness nor the pad and the adversary may know the application witness, the
review decides how each step carries over (table below). **The distribution of
the carried-over simulator is not proved, and no argument has been written for
the decided target.**

1. Compute the fully bound `mu`; sample the root seed and `iv_pre` as the
   prover does; construct a BAVC tree.
2. Choose the final challenge and the opening according to the distribution
   being simulated.
3. Sample the correction strings, the CRT corrections and `d` uniformly at
   their prescribed lengths, with canonical padding.
4. Reconstruct the verifier's `Q`, `q̄` from the opening and the public `H5`.
5. Choose and program the first challenge.
6. Sample the four-field consistency mask `ũ`; set the consistency response so
   that `D = Q̃ + Δ·ũ`.
7. Choose and program the second challenge.
8. Sample `ã_1, ..., ã_6`; compute `ã_0` from the verifier's public relation
   calculation.
9. Program the final challenge at the exact coefficient-and-counter input and
   serialize.

With successful, consistent programming this produces an accepting proof
without the witness. **Existence of the algorithm is not a proof that its
distribution is correct.**

Carry-over of the steps to the decided target:

| Step | Decision |
| --- | --- |
| 1: compute `mu`, sample the root and `iv_pre`, construct the BAVC | Retain, using the frozen namespaces and independent coins; no `H3` |
| 2: choose the challenge and the opening | Replace the isolated-success description by the complete bounded retry distribution |
| 3: sample the corrections, the CRT corrections and `d` | Retain as candidate operations at the final lengths. Their joint distribution still needs proof |
| 4: reconstruct `Q`, the mask keys | Retain |
| 5 and 7: program challenges 1 and 2 | Retain as candidate operations; programming must be justified despite complete knowledge of the application witness |
| 6: consistency-mask calculation | Retain the algebra, once its required mask distribution is justified |
| 8: sample the coefficients and reconstruct `ã_0` | Retain, including the pad's Booleanity constraints |
| 9: program challenge 3 and serialize | Account for every attempted counter, the earlier failures, opening-limit rejection and exhaustion, not merely the successful query |

**Retry stopping law.** Let `G` be the set of 256-bit challenges whose
grinding suffix is zero and whose canonical opening fits the row, and
`p = |G| / 2^256`. **In the ideal fresh-query experiment** the target stopping
law for the stopping counter `C` is

```text
Pr[C = c] = (1 − p)^c · p    (0 ≤ c < 2^32),
Pr[exhaustion] = (1 − p)^(2^32)
```

Conditioned on `C = c`, the preceding challenge values lie uniformly outside
`G` and the final value lies uniformly inside `G`. The simulator must realize
the corresponding oracle interactions at the exact counter inputs. **This
distributional description does not establish that the required QROM
programming is valid when the adversary has already queried, or later
queries, those locations.**

**Intended hybrids.**

- Replace seed-derived hidden material by its idealized distribution,
  charging the exact PRG and multi-hiding losses.
- Justify first-challenge programming through commitment unpredictability.
- Use the four consistency masks and the six QuickSilver mask degrees of
  freedom to remove witness dependence from the response coefficients.
- Replace `d = w ⊕ u` by a uniform string.
- Remove the remaining witness dependence from the programmed hidden-label
  locations.
- Preserve indistinguishability under every later quantum query and every
  adaptive request to either proof role.

The mask algebra is reusable after checking the new circuit and lengths.

Requirements on these hybrids for the decided target:

- The PRG idealization framework, the commitment plumbing and the four
  consistency plus six QuickSilver mask degrees of freedom remain the intended
  proof structure.
- Replacing `d` by a uniform string must preserve the joint distribution with
  the known `W_app`, the exposed `U_app`, the corrections, the responses and
  the oracle state.
- The hidden-label transition must use the pad argument. It cannot rely on
  secrecy or entropy of the application witness.
- Every continuation guarantee must survive later disclosure of the
  application witness and later quantum queries.

**Where it stops.**

1. **The padded CRT hidden-label simulation lemma is the first missing
   bridge.** To be proved: the real correlated material and the simulator's
   ideal material, including any `H5` programming, are indistinguishable given
   arbitrary application-witness auxiliary information and all subsequent
   quantum oracle access. Pad independence at sampling and witness-independent
   marginals of the proof bytes do not establish this.
2. **Programming-location bounds.** Adaptive reprogramming bounds
   (Grilo–Hövelmanns–Hülsing–Majenz, Theorem 1; the paper was read by us in
   part, profile record section 13; the cited theorem and its use here are the
   review's **[R]**) have the form

   ```text
   sum_t ( sqrt(q^_t · p_max,t) + (1/2) · q^_t · p_max,t )                (29)
   ```

   The conditional location bounds `p_max,t`, or a computational
   unpredictability replacement, must be established first; the theorem does
   not establish them. A public transcript nonce may help pre-publication
   unpredictability of programming locations; it does not solve hidden-label
   queries after the nonce and the proof are published.
3. **Retry and exhaustion coupling.** The simulator must reproduce the
   stopping law above together with the failed preceding challenge
   evaluations, rejection caused by the opening limit and the exhaustion
   outcome of section 1.7, at the exact counter inputs and under earlier and
   later adversarial queries to them. Programming only the final successful
   attempt gives the wrong joint counter and oracle distribution, and
   conditioning a one-attempt simulator on success changes the experiment
   unless separately justified. FAEST's published analysis does treat the
   retry loop: Theorem 10.42, games G5 and G6, handles the iterations and the
   successful opening, and QROM Theorem 10.53 follows that game sequence; the
   single-attempt formulation of section 10.11.6 serves the soundness
   argument. What remains is to establish those extensions for this padded,
   joint-relation protocol with independent fresh randomness and no `H3`.

**Anonymity.** After both proof roles are replaced by the joint simulator, the
remaining step hides the relation between public commitments (and
authorization values **[D]**) and nullifiers under the same secret. A
conditional decomposition:

```text
Adv_anon ≤ 2·ε_JZK + ε_hidden-input + ε_accidental-equality               (30)
```

The hidden-input term needs its own adaptive multi-user quantum proof. Domain
separation alone does not establish it.

Technique to try and difficulty: the mask identities and layout checks are
routine; joint full-oracle simulation and the stopping-time analysis are hard
but plausible.

### 6.6 Property 6: concrete security

Status: incomplete. The ledger and its status are section 8. No game of
section 5.2 other than the statistical component calculations has a bound, so
no deployment-wide total exists.

### 6.7 Property 7: deterministic bounded verification

Status: conditional (a design argument; not an implementation certificate).
The standalone descriptor, the proof layout and the length rules are frozen
(profile record sections 6.1 and 6.6); the production envelope and the
production Norito mappings are not written.

The property is algorithmic. Its proof needs no SHAKE collision resistance,
AES pseudorandomness, knowledge soundness or zero knowledge. It needs exact
functional specifications and a bounded implementation.

**Argument.** For a frozen descriptor, define verification as a total
deterministic function of the canonical proof bytes and the authenticated
public context. Each parser operation, hash, AES evaluation, field operation,
index calculation, constraint evaluation and comparison has prescribed
semantics and a finite bound. Induction over that operation sequence proves
identical acceptance results on all conforming hardware.

Premises not yet met: the proof codec, the CRT layer, the vector commitment,
the VOLE layer, the constraint check and both relations are not implemented
**[C]**.

**Descriptor contents.** The descriptor is `DESC` of profile record
section 6.1, with digest `D` **[R]**. It carries:

- `P16`, `ASCII("FAEST-3.0")` and the parameter tuple
  `(lambda, tau, w_grind, T_open, d_zk, n_mult)` of the one accepted row;
- `T_crt`, the digest of the exact CRT tables. The official 704-gate fast-row
  tables are pinned; tables from another generator with a different gate
  count cannot replace them under the same descriptor and size ledger;
- the relation dimensions `(l_reg, M_reg, l_vote, M_vote)`;
- `SUITE`, which immutably names the relation, the constraint ordering, the
  encodings, the transcript and the randomness rules. Those rules are the
  witness order, the Keccak bit order and the complete ordered constraint
  sequence (sections 1.2 to 1.5), including the tautological constraints and
  the homogenisation; every backend hash input and length (profile record
  section 6.3); the exact proof lengths, the padding and the opening order
  (profile record section 6.6); and the sampling of `r`, `iv_pre` and the
  pad, the counter rule and the aborts (profile record section 6.7).

The preimage of `mu_R` is `PREFIX_R || F_R || hex("08")`, with `F_REG` and
`F_VOTE` of profile record section 6.3; `F_VOTE` contains the list bytes
`concat(L)`. The public inputs are bounded opaque byte strings with the
bounds of profile record section 6.1. Norito layouts, flags, field order and
nesting are not descriptor content of the standalone construction: they and
the envelope are production obligations of Core and are not written.

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
   trailing bytes **[R]**. The production envelope and its canonical form are
   a later obligation and are not written.
4. Validate `3 ≤ S ≤ 1,000`, the exact list length, strict ordering,
   uniqueness and authentication to the seal.
5. Reject invalid vote values, an inconsistent public context, malformed or
   insufficient openings, nonzero unused padding, a third challenge that fails
   the grinding check, and a final challenge mismatch.
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
12,799 GGM nodes, ten masks, `n_mult = 704`.

**Raw proof layout by field** **[D]**: the review's field list with
`(tau − 1)·l/8`, `10·nbar_mult/8`, `4·lambda/8`, `l/8`, `6·lambda/8`,
`T_open·lambda/8 + 3·tau·lambda/8`, 32, 16 and 4 bytes. The fast-row fixed
fields sum to 11,748 and the small-row ones to 10,554, as in profile record
section 9.1; the totals equal the sizes of section 1.7.

| Field, in order | Fast, registration | Fast, vote | Small, registration | Small, vote |
| --- | ---: | ---: | ---: | ---: |
| `c_1, ..., c_(tau-1)` | 143,360 | 143,616 | 94,080 | 94,248 |
| `c_mult` | 880 | 880 | 870 | 870 |
| `ũ` | 128 | 128 | 128 | 128 |
| `d` | 4,480 | 4,488 | 4,480 | 4,488 |
| `ã_1, ..., ã_6` | 192 | 192 | 192 | 192 |
| Opening | 10,496 | 10,496 | 9,312 | 9,312 |
| Third challenge | 32 | 32 | 32 | 32 |
| `iv_pre` | 16 | 16 | 16 | 16 |
| Counter | 4 | 4 | 4 | 4 |
| **Total** | **159,588** | **159,852** | **109,114** | **109,290** |

The fast-row opening holds 33 hidden leaf commitments and at most 229 seeds in
the prescribed reconstruction order, with canonical unused padding.

**Input caps.** The complete envelope cap is 262,144 bytes and the separate
list-context cap 163,840 bytes; at `S = 1,000` the raw list is 128,000 bytes.
The caps allow at most 425,984 bytes of combined bounded input, not 262,144
**[R][D]**. The specified list frame at `S = 1,000` is 128,114 bytes and takes
1,780 SHA3-512 permutations **[R]**, reproduced **[D]** from the `Frame`
definition and the 72-byte rate.

**Work bounds, fast row.** With `l^ = l + 80`: 35,920 (registration) and
35,984 (vote) **[D]**.

| Quantity | Formula | Registration | Vote |
| --- | --- | ---: | ---: |
| AES block encryptions, conservative | `4 × 6,399 + 6,367 × (8 + ceil(l^/128))` | 1,865,659 | 1,872,026 |
| VOLEHash field products | `5·(l + 6) + 4` | 179,234 | 179,554 |
| ZKHash field products | `2·M + 2` | 145,154 | 145,416 |
| Leaf-hash products in `F_(2^768)` | at most 6,367 | 6,367 | 6,367 |
| Relation permutations | 24 rounds × 1,600 nonlinear products each | 2 (76,800 products) | 2 (76,800 products) |
| Backend SHAKE calls | 1 `H0` + 34 `H1` + 4 transcript-role + 1 `H4` + 704 `H5` | 744 | 744 |

All values **[D]** from the review's formulas at the final dimensions.
Registration has two relation permutations. There is no prover-randomness
`H3` call. Selector work is bounded by `S` selector products and `1,024·S`
public-bit selections and additions. Booleanity, equality and degree-lifting
work is linear in the frozen witness and constraint counts; powers of `Δ`
through degree seven can be precomputed. A frozen straight-line constraint
schedule supplies the remaining exact operation tally.

Backend hash inputs, fast row, without the 77-byte role prefix `PREFIX_R`
and with the one suffix byte:

| Hash input | Maximum bytes |
| --- | ---: |
| `H0` | 17 |
| All `H1` inputs combined | 616,546 |
| `H4` | 81 |
| First challenge, registration / vote | 144,385 / 144,641 |
| Second challenge, registration / vote | 5,001 / 5,009 |
| Third challenge | 333 |
| Each `H5` | 53 |
| `mu_R`, registration / vote at `S = 1,000` | 5,947 / 128,375 |

Every row is **[D]** from the bodies and suffix bytes of profile record
section 6.3, at `l = 35,840` (registration) and `l = 35,904` (vote):

- `H0`: `17 = 16 + 1` (`iv`, suffix).
- All `H1` inputs: `616,546 = 6,400 × 96 + 33 × 64 + 34` (the leaf
  commitments over the 33 inner calls, the 33 vector digests of the outer
  call, and one suffix byte for each of the 34 calls).
- `H4`: `81 = 16 + 64 + 1` (`iv_pre`, `mu`, suffix).
- First challenge: `64 + 64 + (tau − 1)·l/8 + 880 + 16 + 1 = 32·l/8 + 1,025`
  (`mu`, `com`, the corrections, `c_mult`, `iv_pre`, suffix).
- Second challenge: `264 + 128 + 128 + l/8 + 1 = l/8 + 521` (`chall_1`,
  `ũ`, `Ṽ`, `d`, suffix).
- Third challenge: `333 = 104 + 7 × 32 + 4 + 1` (`chall_2`, `ã_0` to `ã_6`,
  the counter, suffix).
- Each `H5`: `53 = 16 + 4 + 32 + 1` (`iv`, `u32_le(e)`, the label, suffix).
- `mu_R`: the maximum of `F_REG` is
  `2 + 14 + 2 + 10 × 4 + 4,096 + 6 × 256 + 64 + 128 + 64 = 5,946` bytes and
  that of `F_VOTE` at `S = 1,000` is
  `2 + 15 + 2 + 8 × 4 + 64 + 64 + 64 + 2 + 128,000 + 64 + 1 + 64 = 128,374`
  bytes, from the `Frame` definition and the bounds of profile record
  section 6.1; each takes one suffix byte.

The figures for `H0`, `H1`, `H4`, the third challenge and `H5` equal those the
review gave **[R]**. A SHAKE256 invocation with `m` input bytes, a fixed
prefix of `h` bytes and `o > 0` output bytes uses at most
`floor((m + h)/136) + ceil(o/136)` permutations; here `h = 77`.

**Memory.** A bounded implementation processes one small-VOLE instance at a
time, streams transcripts into hashes and streams constraints into ZKHash.
Principal vote buffers, fast row:

| Buffer | Formula | Bytes |
| --- | --- | ---: |
| Maximum envelope plus list object | `262,144 + 163,840` | 425,984 |
| GGM node seeds, leaf seeds, leaf commitments and marks | `12,799 × 32 + 6,400 × 32 + 6,400 × 96 + 12,799` | 1,241,567 |
| Two maximum-size small-VOLE conversion buffers | `2 × 256 × l^/8` | 2,302,976 |
| Raw small-VOLE columns | `248 × l^/8` | 1,115,504 |
| Full-field witness keys | `32·l` | 1,148,928 |
| Optional materialized constraint vector | `32·M` | 2,326,624 |
| Three Keccak field-state buffers | `3 × 1,600 × 32` | 153,600 |
| Selector products and five packed CRT matrices | not reconstructed | 114,752 |
| **Subtotal** | | **8,829,935** |

The review gave buffer totals without formulas. The formulas shown are ours
**[D]**: each was fitted to a figure the review gave for other dimensions, is
unconfirmed against an implementation, and is evaluated here at `l = 35,904`,
`M = 72,707`. The last row could not be reconstructed; it is the review's
figure **[R]**, carried on the judgement that selector products and CRT
matrices do not depend on `l` or `M` **[E]**.
The optional constraint vector is eliminated by streaming. One architecture
reserves a 64 MiB arena before verification with fixed regions for bounded
inputs, BAVC, VOLE conversion, field and relation work, tables and auxiliary
storage; no per-gate heap allocation or recursive tree traversal is needed.
The subtotal is not a complete allocation certificate: decoder metadata,
alignment, provider scratch space, stack and the exact public-input schema
are not inventoried.

**Omitted pending measurement or implementation.**

- The small-VOLE conversion byte-XOR count. The review states a figure with
  no operation model; the fit `2 × 6,367 × l^/8` would give 57,175,660
  (registration) and 57,277,532 (vote) **[D]**, not recorded as a bound.
- A registration buffer table, small-row work, hash-input and buffer figures,
  and every time figure. None was given by the review at the final
  dimensions.

Remaining evidence: the production envelope and Norito mappings; the
implemented circuit; a completed parser and verifier; complete arena and work accounting; independent field and CRT checks
and backend conformance vectors; scalar, x86 and ARM parity; malformed-input
and late-failure tests; cold-context measurements at `S = 3`, 500 and 1,000.
The 250 ms requirement is a separate measurement on the validator baseline;
boundedness alone does not establish it.

### 6.8 Property 8: registration authorization

Status: incomplete.

Assumptions: the backend QROM model and the premises of the table below. To
be proved: a bound `ε_8` on (23). The route is the opening-uniqueness route.
It requires neither a uniform-commitment replacement nor programming of the
credential functions.

**Frames and logs.** Write

```text
Y(x) = Frame("PARL/REG-AUTH/v1"; ...),    d(x) = SHA3-512(Y(x))
```

where `Y` contains every registration field except `auth`, exactly as in the
`D_reg` preimage of section 1.1; `d(x)` is the `D_reg` of the statement `x`.
For each honest handle `j` the challenger maintains:

- `RegLog[j]`: the complete statements authorized by permitted
  registration-proof requests;
- `AuthLog[j]`: their authorization digests.

**Logging rule.** The authorization is recorded **before `auth` is exposed**,
including when the subsequent proof generation fails. An aborted request must
not expose an unlogged authorization value.

**Event split.** Consider a winning output `(j, x*, π*)` of the property 8
game, with `d* = d(x*)`.

1. If `x*` is false, it belongs to the adaptive false-statement soundness
   event.
2. Otherwise a witness `s'` satisfies its commitment and authorization
   equations.
3. Outside the target-opening ambiguity event

   ```text
   ∃ s' ≠ s_j :  Com_(B*)(s') = Com_(B*)(s_j)
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
Win_8 ⊆ FalseAccepted ∪ BadOpen ∪ FrameCollision ∪ FreshAuthCorrect       (31)
```

**Premises**, complete for this route:

| Premise | Originating experiment or rule |
| --- | --- |
| Public validation, encoding equivalence, injective framing, fixed descriptor, honest log correctness and disclosure restrictions | The deterministic construction and the rules of the property 8 game |
| Adaptive target-opening uniqueness | The same common environment; the adversary selects an uncorrupted `j` and `B*`; the bad event is the existence of another opening of the target commitment |
| Adaptive registration soundness with both honest proof interfaces | A win on an accepted registration statement outside the language |
| Quantum collision resistance of SHA3-512 on legal registration frames | Output of distinct `Y`, `Y'` with equal SHA3-512 digests |
| Joint simulation | The arbitrary-application-witness game of section 5.2 |
| Adaptive multi-user authorization prediction | Public commitments, authorization values, nullifiers, permitted corruptions and quantum queries remain available; proof replies use the joint simulator; the output is an uncorrupted `j`, `d` and `a` with `d ∉ AuthLog[j]` and `a = Auth_d(s_j)` |

- The uniqueness premise is **existential almost-injectivity**, not ordinary
  computational collision resistance. Without extraction, a collision-finding
  assumption cannot simply replace it. Ideal-map injectivity calculations
  (section 8.2) are neither a concrete-SHAKE guarantee nor a statement about
  adaptively chosen contexts.
- The soundness premise is the Fiat–Shamir, adaptive statement with both
  honest proof oracles; section 4 is the interactive response-graph statement
  only.
- The prediction premise covers adversarial exploration of contexts; a union
  bound over only the contexts eventually published does not justify that
  exploration.

**Conditional bound.**

```text
ε_8 ≤ ε_snd,mix + δ_open + ε_CR,REG + ε_JZK + ε_pred                       (32)
```

with the work and the oracle queries of every reduction charged. The terms
bound, in order, `FalseAccepted`, `BadOpen`, `FrameCollision`, the joint
simulation step and `FreshAuthCorrect` after simulation **[D]** (the
assignment follows the premise table; the review writes the sum without
it).

**Where joint zero knowledge is applied.** Apply it to the efficiently
checkable `FreshAuthCorrect` prediction event, whose challenger knows the
honest keys. Do not apply it to deciding whether an arbitrary statement is
false or has another opening.

**Status of the premises.** The explicit SHA3-512 collision premise on
registration frames is new relative to the review's part 3. The other
cryptographic premises were already named and remain unproved. Exact logging
is the necessary clarification of the game. No term of (32) has an
established value.

The authorization value does not remove the knowledge obligation of
property 1 and does not solve voting (section 6.2).

**Routes other than the event split**, which the review also gives, which are
not the route adopted above and which remain unproven:

- *Counting fact.* For every fixed `B`, even for concrete SHAKE,
  `|im Com_B| ≤ 2^384`, hence

  ```text
  Pr_{Y ← {0,1}^1024}[ Y ∈ im Com_B ] ≤ 2^-640                            (33)
  ```

  This is unconditional counting. The absence of the AES restriction is
  therefore not intrinsically fatal to a false-instance argument for
  registration. What is missing is the computational transition that makes the
  counting useful.
- *False-instance route for an exposed target context.* (1) Replace the
  target's honest registration and vote proofs by one joint simulation.
  (2) Replace its commitment by a uniform `Y`, consistently updating dependent
  lists, digests and messages. (3) Show that a fresh forged registration
  cannot exploit earlier programmed transcript locations. (4) Except for the
  image event (33), apply soundness to a false registration statement.
  (5) Account for adaptive target selection and corruption. **Steps 1 to 3 and
  the adaptive form of step 4 are unproved.** Step 2 needs a correlated-output
  pseudorandomness argument whose auxiliary information includes nullifiers
  and both proof types, not merely the range bound. Step 3 is a
  freshness-localization argument under oracle programming; ordinary soundness
  does not imply it.
- *New context.* Outputting `C* = Com_(B*)(sk_j)` for a new `B*` already
  predicts a new secret-dependent output, which suggests a reduction to
  adaptive hidden-key output prediction after joint simulation.
- *Extraction route.* (1) Simulate the two honest proof oracles. (2) Extract
  `sk*` from the fresh registration forgery. (3) If `sk* = sk_j`, recover the
  target secret. (4) Otherwise output two distinct openings of `C*`. Step 2
  needs extraction compatible with the simulated-proof environment.
  Simulation-extractability would suffice; a direct origin-unforgeability
  argument could avoid it.

Technique to try: the event split, with registration origin proved before the
mixed-list voting case. Difficulty: hard but plausible; the adaptive
correlated simulation and freshness arguments are substantial new work.

## 7. Audit of imported results

References are to the FAEST v3.0 specification. "May be used" is conditional
on checking the stated local hypotheses for the actual lengths, tables and
randomness.

| FAEST v3 result | May be used | May not be used |
| --- | --- | --- |
| Lemmas 4.6, 4.7 (VOLEHash, ZKHash) | The proof technique, re-derived as (12) and (13) | The lemmas as stated: their dimension hypotheses fail |
| Lemma 7.3 (polynomial roots) | The root step for a fixed nonzero polynomial of degree ≤ 7 and the independently sampled raw challenge, after the degree and challenge checks | — |
| BAVC structural conditions | The row satisfies `tau > 1`, `3·N_i > 2`, `(tau + 1)·2^8 < 2^31` | As a certificate of the implemented CRT maps or their primitive bounds |
| Lemma 10.26, Corollary 10.27 | The affine-line argument with the revised hash error; (14) and the extraction map give the required extension | — |
| Lemma 10.40 | `d_zk = 7` satisfies its degree choice; the response-graph proof of section 4 re-establishes it, with section 2 replacing the relation step | The lemma as stated: its relation and dimension hypotheses fail |
| Theorem 10.30, Corollary 10.41 | — | Their signature-security conclusions are not imported |
| Theorem 10.42 (games G5, G6) | The published treatment of the retry iterations and the successful opening, as the template to extend | As covering this padded, joint-relation protocol with fresh independent randomness: the extension is an open obligation |
| Theorem 10.46, Lemmas 10.48, 10.49 | A conditional static false-statement soundness route; Lemma 10.48's leaf-hash round error (19). Lemma 10.49's query count `Q = Q~ + 85` is that of its explicit-leaf intermediate experiment; the compact proof uses `Q~ + 125` (section 8.3) | As adaptive knowledge extraction or a multi-user game; the offset 85 as the compact-proof offset |
| Lemma 10.50 (false-key reduction) | — | Not supplied for the custom relations: the false-key reduction requires a new instance-distribution argument. Stated separately by the review, with no lemma number: the relations have no key restriction and the list relation has no lossy-key step (section 6.2) |
| Lemmas 10.24, 10.51 (hiding components) | After checking actual lengths, tables and randomness. Arbitrary witness length is permitted in the relevant multi-hiding formulation; the soundness lemmas' size restrictions are not to be attributed to every hiding result | As joint quantum zero knowledge |
| Lemma 10.52 | Commitment unpredictability component | — |
| Theorem 10.53, Corollary 10.54 (QROM, chosen message) | The game sequence, which follows Theorem 10.42 and treats the retry loop; the formula as a numerical comparison only (section 8.3) | No direct transfer to this construction, to two proof types under one secret or to its multi-user games: they are single-key results for plain FAEST |
| Section 10.11.6 (single-attempt formulation, random `r` and `iv_pre`, fixed `H5`) | The verifier is unchanged, so the false-statement acceptance predicate is unaffected by the honest retry behaviour | As a description of the honest transcript distribution in zero-knowledge or chosen-message reductions |

**Retry loop.** FAEST's published analysis addresses the retry loop
(Theorems 10.42 and 10.53). The open obligation is the extension to this
protocol.

Not relied upon: Baum et al., ePrint 2026/164. The review reached the landing
page only; no theorem that appears only in that paper is used.

## 8. Numeric ledger

**The complete ledger is unestablished.** The fast row meets neither the
earlier contract nor the recalibrated contract today: applicable bounds for
properties 1, 2, 5 and 8 do not exist, so no deployment-wide total can be
formed. The only presently justified universal numerical upper bound on the
construction's computational advantages is 1. This is not evidence of an
attack.

### 8.1 Contract and lifetime ceilings

The earlier contract (profile record section 8.8) required at least `2^128`
total quantum queries for any break with success or distinguishing gap at
least 1/2. The review's reconciling decisions recommend replacing it by two
requirements. **This expressly weakens the earlier proven `2^128`-query
requirement.** The 64/128 split is the review's recommended policy; it is not
a theorem and not an equivalent restatement of the earlier contract.

- **Proven-bound requirement.** Every required computational game has a
  complete, applicable deployment-wide bound below 1/2 at an adversary budget
  of `2^64` quantum queries, including both relations, all lifetime ceilings,
  concrete primitive terms and the actual simulator and extractor query and
  time overhead. The largest budgets justified at advantage `2^-64` and at
  advantage 1/2 are recorded.
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
the comparison arithmetic of section 8.3.

### 8.2 Statistical and ideal-model entries

| Quantity | Value and qualification |
| --- | --- |
| Honest 384-bit secret collision among `U` samples | `binom(U, 2) / 2^384 < 2^-317`; elementary statistical bound |
| Collision among `T` independent ideal 512-bit tag-table values | `< 2^-425`; applies to the ideal hybrid only |
| Global commitment non-injectivity, one fixed ideal-map context | `binom(2^384, 2) · 2^-1024 = 2^-257 − 2^-641` |
| The same for `J` fixed, independently selected contexts | `< 2^-233`; does **not** cover adaptive quantum context selection |
| Ideal multi-target secret-search benchmark `4·U·q^2 / 2^384` | `2^-92` at `q = 2^128` **[R]**, `2^-220` at `q = 2^64` **[D]**; a search benchmark, not a proved privacy or authorization bound |
| Generic 512-bit quantum-collision scaling `q^3 / 2^512` | `2^-128` at `q = 2^128` **[R]**, `2^-320` at `q = 2^64` **[D]**; before theorem constants and overhead; not a concrete-SHAKE certificate |
| Generic 1,024-bit output-collision scaling `q^3 / 2^1024` | `2^-640` at `q = 2^128` **[R]**, `2^-832` at `q = 2^64` **[D]**; the same qualification |
| Adaptive commitment binding for concrete SHAKE | Unknown |
| Public-commitment secret-prefix pseudorandomness | Unknown |
| Joint label hiding and quantum zero knowledge | Unknown |
| Properties 1, 2 and 8 for this protocol | Unknown |
| Transfer of the published retry analysis to this protocol | Unknown |

The **[D]** exponents are `2 + 34 + 2·64 − 384`, `3·64 − 512` and
`3·64 − 1024`. Ideal-map injectivity is kept distinct from concrete SHAKE guarantees and from
adaptively chosen contexts: it cannot be multiplied by the number of
adversarially selected contexts without analysing that selection, and
requesting 1,024 output bits from SHAKE256 does not by itself establish an
ideal 1,024-bit random-map claim for the concrete sponge. The table has no
entry for the registration authorization value; the review supplied none.

Interactive component audit, fast row, at most `T` independently challenged
executions:

| Component | Lifetime union bound |
| --- | ---: |
| Leaf-hash injectivity | `33·T·2^-256 = 2^-206.955606` |
| Vote first-round (effective-line) failure | ≈ `2^-226.924228` **[D]** (`2^44 × 2^-270.924228`) |
| ZKHash failure | ≈ `2^-212` |
| Final polynomial-root failure | `7·T·2^-256 = 2^-209.192645` |
| **Sum** | ≈ `2^-206.642447` |

**This is not lifetime NIZK soundness.** `T` counts honest prover transcripts,
not adversarial attempts. Fiat–Shamir challenges are searchable oracle
outputs; the query-dependent analysis, including its quadratic loss, cannot be
replaced by multiplying an interactive error by `T`. Likewise the birthday
probability for 128-bit IVs is not automatically a failure term: the relevant
event must include `iv = H4(iv_pre || mu)`, the seeds, the contexts and how an
IV coincidence could affect the particular proof.

### 8.3 Comparison with the published formula

A numerical diagnostic only. It substitutes the lifetime transcript ceiling
into FAEST v3 Corollary 10.54 as if all `T` transcripts were one key's signing
queries. That is a comparison with a published single-user formula, not a
proved multi-user reduction, and the corollary is not established for the
ballot relations.

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
coefficients 340 and 400 are kept; they recompute **[D]** from the published
key-only formula quoted in profile record section 8.1: `340 = 10·(tau + 1)`,
`400 = 10·(tau + d_zk)` and, below, `2720 = 8 × 340`. **This remains a
conditional comparison, not an established adaptive ballot bound.**

Inputs: `T = 2^44`, `n = 704`, `h = 37·T + 125 ≈ 2^49.21`, `Q = q + h`, where
`q` is the external adversary budget. The offset `h` is the published query
offset `(tau + 4)·Q_sig + 3·tau + d_zk + 19` of profile record section 8.1 at
`Q_sig = T` **[D]**; its constant 125 is the compact-proof offset above.
Individual
oracle counts are bounded by `q`, and `Q_2,0 + Q_2,1 ≤ q`; the two square-root
rows marked † separate one published term using
`sqrt(x + y) ≤ sqrt(x) + sqrt(y)`. Boundary columns give `log2 q` at which the
term alone equals the threshold **[R]**, reproduced **[D]**; the value columns
are **[D]** (the `2^128` column also **[R]**). The boundaries are rounded
logarithms; the exact cutoff is the positive root of the expression set equal
to the threshold `p`, for the first row `q* = sqrt(p·2^256/3200) − h`, and the
largest budget satisfying the strict inequality is `ceil(q*) − 1`.

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

Other query-dependent benchmarks, as `log2 q`:

| Benchmark | Boundary for `2^-64` | Boundary for 1/2 |
| --- | ---: | ---: |
| `4·U·q^2 / 2^384`, `U = 2^34` | 142 | 173.5 |
| `q^3 / 2^512` | 149.333333 | 170.333333 |
| `q^3 / 2^1024` | 320 | 341 |

The fixed statistical collision entries and the interactive lifetime sums of
section 8.2 are below both thresholds. The adaptive-context counterparts and
the missing property reductions have **no established numerical cutoff**.

The PRP switching multiplier of the comparison is

```text
ρ = exp( T · (β_root^2 + 4·tau·ceil(log2 N − 1)·β^2 + tau·a_leaf^2) / 2^128 )
```

with `β = 2`, `β_root = 5`. It is multiplicative, not an additive probability
term, and `ρ < 2` at the final witness lengths **[R]**. **[D]** The review
gave `a_leaf` values for other dimensions without a formula; they fit
`2,048 + ceil(l^/128)`, and on that inferred, unconfirmed formula `a_leaf` is
2,329 and 2,330 and the exponents are about `2^-56.585` and
`2^-56.583`.

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
  authorization and joint zero-knowledge theorems unproved. The review does
  not recommend a speculative `lambda = 384` backend.

### 8.4 Primitive-term requirements

The comparison also contains

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
complete `2^-64` advantage guarantee there.

For the ballot construction:

- the `H3` derivation term is removed by the randomness decision of
  section 1.7;
- the plain-FAEST `δ_OWF` term does not transfer; its replacement
  credential-security terms must be proved, and substituting a
  credential-search estimate is not a proved transformation;
- neither change licenses deleting any other unresolved term.

Nominal generic attack scales, starting points for the attack report and not
an exhaustive lower bound: about `2^128` queries for 256-bit seed or challenge
search, `2^175` for ideal shared-function search across `2^34` 384-bit
secrets, and `2^170.67` for ideal 512-bit collision search. Neither a `2^106`
multi-transcript seed attack nor its absence follows from counting
transcripts: the IV-dependent predicates and their implementation costs
matter.

### 8.5 Status of the total

- Sections 2 to 4, the conditional reductions (24) to (28) and (30) and the
  conditional event split (31) and (32) are arguments written by the review.
- Published component bounds can be used only with their checked local
  hypotheses (section 7).
- No published complete computational bound applies as stated to this
  construction.
- No finite lifetime bound for `κ_1`, joint simulation or the two
  unforgeability advantages has been proved.
- The owner's eventual record must contain the actual complete thresholds at
  advantages `2^-64` and 1/2, the independently reviewed attack-cost
  assessment and the explicit contract change. The recommendation of
  section 8.1 does not establish that the row meets it.

## 9. Remaining proof tasks and what would falsify the construction

### 9.1 Tasks in priority order

The review's task of repairing the CRT entropy dependency is discharged as a
decision (the pad of section 1.3 and the property 5 target); its proof is not.
Its task of freezing the protocol and the games is discharged for the
standalone construction: witness placement, constraint order, CRT tables,
randomness, the retry rule, the byte level (section 1 and profile record
section 6) and the games, including the property 5 game for the decided
target (section 5.2), are written. Production Norito mappings, production
envelopes and authenticated integration are later obligations outside this
list (section 1). The order of the remaining tasks:

| # | Task | Difficulty |
| ---: | --- | --- |
| 1 | **Complete the algebraic foundation.** Independent review of the grouped-Keccak compiler, selector and homogenisation implication (section 2) and of (12), (13) and their propagation (sections 3 and 4), at the final dimensions | Written; independent review only |
| 2 | **Resolve efficient extraction feasibility.** A polynomial-time interactive reconstruction theorem for the VOLE protocol, before investing in a full QROM knowledge reduction (property 1) | Hard but plausible research; a sufficiently tight extractor is unresolved |
| 3 | **Prove joint simulation for both roles.** First the padded CRT hidden-label simulation lemma (section 6.5): real correlated material against the simulator's ideal material, including any `H5` programming, given arbitrary application-witness auxiliary information and all subsequent quantum oracle access. Then the programming-location bounds, shared secrets, complete future quantum oracle access and adaptive public inputs; then the anonymity game with its exclusions (property 5) | Mask identities and layout checks routine; full-oracle simulation hard but plausible |
| 4 | **Analyse the exact counter loop.** Extend the published retry analysis (Theorems 10.42, 10.53) to the stopping law, the retry and exhaustion coupling and the oracle-state hybrids of this prover (section 6.5) | Hard but plausible |
| 5 | **Prove the adaptive authorization reductions.** Registration origin first, through the event split (31) and its premises (property 8); then the mixed-list, target-nullifier voting case (property 2) | Hard but plausible; substantial new work |
| 6 | **Build the deployment-wide ledger.** All primitive terms, extractor overhead, simulation losses, target selection, transcript counts and statistical events, against the recalibrated contract; commission the independent attack-cost assessment; and revisit the parameter row if the resulting bound remains inadequate | Depends on tasks 2 to 5 |

Properties 3 and 4 follow from tasks 2, 3 and 5 through (24) and (26) once
`ε_C` and `ε_SP` are also established; those two primitive assumptions about
concrete SHAKE need their own assessment.

### 9.2 What would falsify the construction

This list is the implementers' consolidation **[E]** of the failure conditions
the review states in the parts above; the stop and switch conditions of
profile record section 11.5 apply unchanged.

- **Encoding.** A witness in `K^l` that satisfies every constraint of
  section 1.5 without encoding a valid relation witness, or an implementation
  whose constraint stream differs from it in content or order.
- **Hash bounds or core soundness.** An error in (12), (13) or (14) large
  enough to lift a round error above `7 · 2^-256`, or a failure of the
  imported leaf-hash and CRT injectivity conditions for the actual tables.
- **Property 1.** A demonstration that no efficient extractor exists for the
  kept leaf commitments in the stated environment, or that the only available
  extractor's loss cannot meet the contract.
- **Property 2.** An alternative-witness attack on mixed lists, or the absence
  of any joint simulation and extraction argument.
- **Property 5.** A distinguisher against the padded protocol with fresh
  tapes, in particular through the CRT labels or the counter distribution; or
  a prover deployment in which the pad or tape is fixed, reused or disclosed,
  to which the target theorem does not apply.
- **Property 8.** Two efficiently findable openings of one commitment in a
  context the adversary can choose, or predictability of `Auth_d(sk)` from the
  public values.
- **Primitive assumptions.** Failure of adaptive-context commitment collision
  resistance or of secret-prefix pseudorandomness with public commitment for
  concrete SHAKE256.
- **Ledger.** A complete ledger whose bound is not below 1/2 at `2^64` quantum
  queries, a statistical total above `2^-128`, or an independently assessed
  attack below `2^128` gates.
- **Property 7.** Any accept or reject difference between conforming
  implementations, or a hard resource limit exceeded after grouping and
  streaming.

Selection for integration continues to require the complete dossier of
profile record section 11.1 with its contract condition amended as in
section 8.1 here. Missing foundational proofs prevent selection. Accepting and
recording activation qualification is the owner's responsibility alone, and
`parliament_binding_ballot_available()` stays false.
