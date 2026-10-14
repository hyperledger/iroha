# Sumeragi consensus

Sumeragi is the Byzantine-fault-tolerant consensus protocol of Iroha. There is one version of
this protocol; it is called Sumeragi. The sans-IO core crate `crates/iroha_sumeragi` implements
it, with its deterministic simulator; this document is the contract of that core and of the node
driver it relies on. The daemon runs this core through the `iroha_core::sumeragi` node driver.
Remaining implementation and qualification work is tracked in
[`specs/sumeragi_goals.md`](sumeragi_goals.md).

Wire and storage formats have one first-release definition. Retired layouts, raw-body transport
constructors and alternate decoders are not supported. Appendix E reconciles the text with
the implementation: the rules
the simulator and code review showed to be incomplete are amended in place, and every other
code-level choice is listed.

Normative keywords: MUST, MUST NOT, SHOULD, MAY. "Honest" = follows this spec. Notation:
`h` height, `v` view, `I` instance id, `n` committee size, `B` block, `R` execution result,
`g` genesis height, `H(x)` the chain hash (production: `iroha_crypto::Hash`, 32 bytes), `‖` byte
concatenation, `be64(x)` 8-byte big-endian, `be32(x)` 4-byte big-endian, `be16(x)` 2-byte big-endian.

---

## 1. Model and assumptions

The generic core models multiple committee sizes below. The global production
instance has the stricter validator-staking contract: exactly `3f + 1` seats,
`1 <= f <= 10`, and exactly `2f + 1` equal votes per Prepare, Commit or Timeout
certificate. Genesis, live scheduling and restored/historical membership must
enforce this boundary. Candidate and observer pools may have other sizes but
cannot become a voting roster directly. The first-release epoch preparation,
authority-generation, fresh-randomness and signed RS16 requirements are tracked
in [the integration goals](sumeragi_goals.md#validator-staking-integration-requirements);
the native implementation does not yet satisfy that complete production contract. Signed RS16
payload availability has a Core/worker integration candidate (§12.8); whole-node and network
qualification remain open. The interface
and wire definitions below describe that candidate, not a claim of release or live qualification.

1. **Validators.** Height `h` of instance `I` has a committee `C_h`: an ordered list of `n_h ≥ 1`
   distinct consensus public keys in *canonical order* (ascending by `kb(pk)`, §3.1). `C_h` is a
   pure function of committed state (§10). Every committee member has one equal vote. Signer
   indices in certificates index canonical order, never a topology.
2. **Fault threshold.** `f_h = floor((n_h − 1) / 3)`, quorum `q_h = n_h − f_h`. For `n = 3f+1`
   this is `2f+1`. For other sizes the formula still holds: n=4→(f=1,q=3), n=5→(1,4),
   n=6→(1,5), n=7→(2,5), n=20→(6,14), n=22→(7,15). Two quorums intersect in at least
   `2q − n = n − 2f ≥ f + 1` members, i.e. in at least one honest member. `n = 1` is allowed
   (f = 0, q = 1: a single validator commits alone; used for dev). `n ∈ {2,3}` has f = 0.
   The implementation MUST use `q = n − f` for every quorum and certificate. The only other
   count is the R2 anchoring threshold `2f + 1` (§7.4), computed from `f` and never through
   `quorum`; `2f + 1` MUST NOT appear anywhere else in code.
3. **Adversary.** At most `f_h` members of `C_h` are Byzantine (arbitrary behaviour, colluding,
   adaptive scheduling of the network before GST, full knowledge of the protocol and topology).
   Everything else is honest but may crash and restart any number of times. Durable storage
   survives a crash. Storage that is *lost* (safety record deleted, block-store tail missing, or
   both at once) makes the node abstain from signing wherever it may already have signed (§7.4 R2,
   R6). Storage that is *corrupt* halts that instance (§12.5). A safety record is never rolled back:
   record files are never restored from backups or copied (§7.4 record provenance); a rolled-back
   record is outside the model, exactly like a second Byzantine node.
4. **Network.** Partial synchrony: there is an unknown Global Stabilisation Time (GST) after which
   every message between honest validators is delivered within an unknown bound `Δ`. Before GST
   messages may be dropped, delayed, duplicated, reordered. Any peer (member or not) may relay,
   drop, strip or corrupt any *unsigned* part of a message. Channels are authenticated (the P2P
   layer tells the core the sending public key, which is the sender's consensus key). The core
   never relies on channel authentication for safety: every safety-relevant object is signed or
   bound by a signed hash, including the probe replies that anchor a key whose record was lost
   (signed echoes, §3.3, §7.4 R2). The authenticated sender is used only for per-peer rate
   limits, replies and fetch sources.
5. **Clocks.** Each node has a local monotonic clock (`now`, milliseconds) with bounded drift
   (`|rate − 1| ≤ ρ`, default assumption ρ ≤ 1%). Clocks are never compared across nodes and no
   validity rule depends on a local clock. **Application exception (§4.5):** the application
   executor MAY answer `Failed` from a local wall-clock comparison (`ClockAhead`,
   `StaleDueWork`) for a block executed with `certified = false`. This is liveness-only: it
   delays only that node's Prepare vote and is never a validity verdict.
6. **Cryptography.** EUF-CMA signatures with aggregation. Production: BLS12-381 in the min-pk
   setting, `iroha_crypto::Algorithm::BlsNormal` (public key = compressed G1 point, 48 bytes;
   signature and aggregate = compressed G2 point, 96 bytes). Proof-of-possession is checked by the
   application when a key enters a committee, so rogue-key attacks are excluded. Collision-resistant
   `H`. The simulator uses a fake scheme with identical interfaces and provenance tracking (§13).

   **Consensus signing suite (application binding).** The current signer/verifier migration
   is implemented; combined runtime and network qualification remain open. Production
   signatures of kinds `0x01`–`0x05` (§3.3) and of the RS16 availability statements (§12.8) are
   made and checked only through the consensus API `iroha_crypto::bls::consensus`. It signs
   `m = SHA-256(P)` for an allowlisted preimage `P`, as `sk · hash_to_G2(m, DST_SIG)` with
   `DST_SIG = ASCII("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")`, the IETF min-pk
   proof-of-possession ciphersuite. `ConsensusDigest::from_preimage(P)` returns `SHA-256(P)` iff
   `P` matches one row exactly (the prefix is `TAG_SIG ‖ kind ‖ I ‖ E`, 85 bytes):

   | Context | Prefix | Exact length |
   |---|---|---|
   | Proposal | `TAG_SIG ‖ 0x01` | 165 |
   | Prepare / Commit vote | `TAG_SIG ‖ 0x02` / `0x03` | 165 |
   | Timeout | `TAG_SIG ‖ 0x04` | 102 (byte 101 = `0x00`) or 110 (byte 101 = `0x01`) |
   | Echo | `TAG_SIG ‖ 0x05` | 101 |
   | RS16 manifest / row (§12.8) | `"sumeragi/availability/sign" ‖ 0x00` / `0x01` | 179 / 219 |

   Signing and aggregation are fallible local operations. A refusal produces a typed local
   fault, never a signature, certificate, evidence, or block-invalid verdict. Failed signing
   publishes, pools, records-as-sent and caches nothing for Proposal, Prepare, Commit, Timeout,
   Echo, RS16 manifest or row. Any preceding durable sign-once reservation remains binding:
   a retry may sign only its identical preimage. Failed certificate aggregation retains the
   verified input votes and emits no certificate.

   A preimage that is not allowlisted is refused: signing returns an error, which the driver
   handles like any signing failure, and verification returns `false`. The production
   `Signer`/`Crypto` implementations (`KeyPairSigner`, `BlsCrypto`, `ProofCrypto`, and the
   `CryptoRef` and lane signers that delegate to them) MUST route through this API; the generic
   `iroha_crypto::Signature` API cannot emit a `DST_SIG` signature. `FastAggregateVerify`
   requires `k ≥ 1` keys, each admitted with a w3f proof of possession or committed by an
   authenticated committee root, `apk ≠ O`, and a canonical, in-subgroup, non-identity `σ`;
   `AggregateVerify` over groups (timeout certificates) keeps its distinct-message and
   distinct-key checks under `DST_SIG`. The simulator's fake crypto never calls this API, so
   sans-IO (MS/ML) mutations that change a preimage layout are unaffected by the exact-length
   allowlist; Core (HC) mutations run with real crypto and MUST NOT change a preimage layout.

   **Registry of `BlsNormal` signing contexts.** A new context requires an entry here and a
   review. Every aggregate user takes a PoP-verified key type.

   | Context | Hash-to-curve domain | Message |
   |---|---|---|
   | Sumeragi kinds `0x01`–`0x05`; RS16 statements | `DST_SIG` | `SHA-256(P)`, allowlist only |
   | Consensus-key proof of possession | w3f transcript | `H("iroha:bls:pop:v1" ‖ pk)` |
   | P2P handshake and relay digests; Torii finality attestation; block-header signatures; `SignatureOf`; genesis signature; consensus-key lifecycle certificates; private settlement; jurisdiction; KAGEMUSHA reserve and state certificates; BLS account controllers; SoraFS | w3f transcript (unchanged) | unchanged bytes |

   Only the consensus API hashes under `DST_SIG`, so no signature obtained in another context (a
   chosen-challenge node attestation, a relay digest) can verify as a vote or certificate share,
   and a w3f proof of possession is never a consensus signature. The global beacon keeps its own
   DST, and the Ethereum sync-committee verifier stays a separate verify-only API that shares only
   hash-to-curve with the consensus API. `TODO:` unify every other BLS signature on RFC 9380
   suites in a later release.
7. **Execution.** `exec(S_{h−1}, B) → Valid(R, S_h) | Invalid` is a deterministic pure function of
   the committed parent state and the block; it terminates within a chain-parameter budget
   (`E_max`, enforced by gas/size limits). `R` is a 32-byte execution commitment (§4.1; for
   instances that use `ExecutionResultCommitment`, the certified result of §4.1.1). A local
   executor *failure* (panic, I/O error, resource exhaustion) is not an outcome of `exec`: it is
   reported as `Failed` and never treated as invalidity (§4.2).
8. **Instances.** One core instance per chain: the global (SORA Nexus) chain and every dataspace /
   lane chain run the *same* core with their own committee and instance id
   `I = H("sumeragi/instance" ‖ genesis_hash ‖ chain_id_bytes ‖ kind:u8 ‖ be32(index))`
   (kind 0 = global, 1 = dataspace, 2 = lane; derivation is the application's; the core only sees
   32 opaque bytes). `I` is in every signing preimage and every block header. Instances never
   wait on each other inside the core, and the driver isolates them (§12.3 O9).
   An independent root ledger MUST select `SumeragiRootScope` in its signed genesis context.
   `Global` owns the universal dataspace and derives kind 0, index 0. `Dataspace` binds an
   exact parent `NetworkId` and a non-universal 64-bit `DataSpaceId`, owns that execution
   scope, and derives kind 1, index 0 from its own genesis hash and chain label. The full
   dataspace identifier is committed by genesis; it MUST NOT be narrowed into the 32-bit
   instance index. Missing scope metadata is invalid. Node startup, finality readers and
   historical evidence MUST derive the same instance from this authenticated scope.
   An independently authenticated Permissioned private root may register
   `DataspaceRestricted` asset definitions in its sole restricted home H only while both
   captured State and World routes are H and its actual/configured catalogs retain the
   canonical restricted, fully replicated lane-zero geometry. World catalog identity must
   match that same physical catalog. This grants no SNS ownership or alias permission;
   those original checks remain mandatory. Confined balances use `Dataspace(H)` only;
   a bare asset identifier canonicalizes to H and does not create a Global bucket. Global
   definitions and general restricted homes on a Global root remain refused.

Properties (per instance):
- **Agreement:** no two honest nodes commit different `(block_hash, R)` at the same height.
- **Validity:** a committed block extends the committed parent, was proposed by the leader of its
  origin round, its payload bytes are the ones its header commits to, and its committed `R` equals
  `exec(S_{h−1}, B)`.
- **Liveness:** after GST, if at least `q_h` members of `C_h` are honest and running and valid
  transaction work is available to an eligible honest leader, every honest running node commits
  height `h` within a bound derived from the configuration (§8.2). Idle chains do not advance. A member
  with an unanchored key (§7.4 R2) counts as faulty until it anchors, and a member whose key
  abstains at `h` (R2, R6) counts as faulty at `h`.

---

## 2. Topology per (height, view)

The heart of Sumeragi (after B-Chain): each round `(h, v)` overlays a total order on the committee
and assigns roles by position.

### 2.1 Definitions

Let `C = C_h` (canonical order, length `n`, with `f`, `q` of `C_h`).

1. **Committee permutation.**
   ```text
   committee_digest(C) = H(TAG_COMMITTEE ‖ be32(n) ‖ kb(C[0]) ‖ … ‖ kb(C[n−1]))
   seed_C              = H(TAG_TOPOLOGY ‖ I ‖ E ‖ leader_seed ‖ committee_digest(C))
   perm_C              = prf_shuffle(seed_C, n)

   prf_shuffle(seed, n):
       slots = [0, 1, …, n−1]; out = []; ctr = 0
       while slots not empty:
           r   = be64_to_u64(H(seed ‖ be64(ctr))[0..8])
           pos = r mod len(slots)
           out.push(slots.swap_remove(pos))   // remove slots[pos], move the last element into pos
           ctr += 1
       return out                             // out[i] = canonical index at permutation position i
   ```
   The permutation depends only on the committee (application state), never on a block that a
   proposer can shape, so nobody can grind it.
2. **Demotion set `D_h` (skipped leaders only).** Window `J_h = [max(g+1, h−1−W), h−2]` of
   committed headers; `W = demotion_window`, a per-instance constant fixed at genesis
   (`Init.demotion_window`; it is not a chain parameter and never changes, so every node uses the
   same window). The core holds every header of `J_h` when it enters `h`: entry requires
   `applied ≥ h − 2`, `BlockApplied` events arrive in height order and carry the applied header
   (§6.13), and `Init` carries the last `W + 2` headers. A member `m ∈ C_h` is a *candidate*
   if `m ∈ skipped_leaders_j` (§3.2: the leaders of views of height `j` that ended without a
   commit) for some `j ∈ J_h`; `last(m)` = the highest such `j`. `D_h` = the candidates sorted by
   (`last` descending, canonical index ascending), truncated to the first `f_h`. Only headers up
   to `h − 2` are used because a node enters `h` before it necessarily holds block `h − 1` (§6.8).
   Nothing else demotes a member: silent or slow set-A members and proxy tails are handled by the
   stage ladder alone (§5.2).
3. **Non-demoted list.** `nd_h` = the members of `C_h \ D_h` in `perm_C` order;
   `a_h = n − |D_h| ≥ q`. `pos(m)` = the permutation position of `m` (`perm_C[pos(m)] = m`).
4. **Order of round `(h, v)` (slot substitution).**
   ```text
   k0(h)         = the index in nd_h of the first non-demoted member at permutation positions
                   h mod n, (h+1) mod n, …        // a demoted member's slot passes to its successor
   L(h, v)       = nd_h[(k0(h) + v) mod a_h]      // views rotate over non-demoted members
   base_{h,v}[i] = perm_C[(pos(L(h, v)) + i) mod n]        for 0 ≤ i < n
   order_{h,v}   = base_{h,v} stably partitioned: members ∉ D_h first, then members of D_h,
                   each group in base order
   ```
   With `D_h = ∅` this is exactly `order_{h,v}[i] = perm_C[(h + v + i) mod n]`. With demoted
   members, the view-0 slot of height `h` is still the permutation slot `h mod n`; only a slot
   whose owner is demoted passes to the next non-demoted member. (Rotating views by permutation
   slots as well, `base_{h,v}[i] = perm_C[(h+v+i) mod n]`, would give the member after a demoted
   slot two consecutive views and break the `f + 1` distinct-leaders property below.)
5. **Roles in `(h, v)`.**
   - leader `L(h,v) = order[0]`;
   - **set A** = `order[0 .. q−1]` (first `q = n − f` positions);
   - **proxy tail** `P(h,v) = order[q − 1]` (last member of set A; equals the leader iff `q = 1`);
   - **set B** = `order[q .. n−1]` (remaining `f` positions; empty if f = 0).

Properties used by §8:
- Demoted members never hold the leader, proxy-tail or any set-A position (`a_h ≥ q`).
- Fairness: with `C_h` and `D_h` fixed, over any `n` consecutive heights every permutation slot
  anchors view 0 exactly once. A non-demoted member `m` is the view-0 leader at its own slot and at
  the slots of the demoted members immediately preceding it in cyclic permutation order, i.e.
  `1 + (that number)` times, and never less than once. The view-0 proxy tail
  (`nd_h[(k0(h) + q − 1) mod a_h]`) likewise visits every non-demoted member at least once.
- Locality: demoting or reinstating `m` changes the view-0 leader only at the heights whose slot
  is (or passes to) `m`: its own slot and those of the demoted members immediately preceding it.
  Within one round it moves `m` into or out of the demoted tail; members before `m` in that
  round's base keep their positions, and members after it move by one position. No height is
  re-indexed (unlike a rotation modulo `a_h`, whose modulus changes with `|D_h|`).
- Within any `f + 1` consecutive views of one height the leaders are `f + 1` consecutive entries
  of `nd_h` (cyclically), hence `f + 1` distinct members because `a_h ≥ q ≥ f + 1`; at least one is
  correct when at most `f` members are faulty.
- The failed leader of view `v` sits at position `a_h − 1` in view `v + 1`: in set B when
  `a_h > q`; when `|D_h| = f` (so `a_h = q`) it is that view's proxy tail, whose failure the stage
  ladder (§5.2) absorbs within about `2·t_retx`.
- Set-A entry: with `D_h` fixed, `k0` advances by one at every height except those anchored at a
  demoted slot, and a non-demoted member's view-0 position `(index − k0) mod a_h` then decreases by
  one. When `a_h > q` it therefore enters set A at position `q − 1` (as proxy tail), passes
  through set A to the leader position 0, then moves to the end of the non-demoted list: it
  enters set A exactly once per `n` consecutive heights. When `a_h = q` every non-demoted member
  is in set A at every height.

### 2.2 Why this shape (B-Chain justification)

B-Chain (Duan, Meling, Peisert, Zhang) runs a chain of `2f+1` active replicas (head … proxy tail)
with `f` standby replicas and re-chains suspected replicas into the standby set. Sumeragi keeps:

- (a) only `q` members (set A) must act in the normal case — `q` is exactly the minimum that can
  form a certificate;
- (b) a designated aggregator (proxy tail) makes the normal case `O(n)` messages, with signature
  verification concentrated at one node;
- (c) a standby set B of size `f` that joins only when set A cannot finish (§5.2);
- (d) re-chaining: a leader whose view failed moves to the demoted tail (set B) for `W` heights and
  its slots pass to its successor. It is computed from committed headers (`skipped_leaders`), so
  every honest node derives the same order without accusation messages. Unlike B-Chain, other
  suspected members are not re-chained: a failed leader costs a whole view timeout, but a silent
  set-A member costs only set B's votes via `P` (stage 1, started at once by the hint of §5.2) and a
  silent proxy tail about `2·t_retx` at each of its proxy-tail turns (about once per `n` heights). Re-chaining those would need absence
  records in headers that a Byzantine proxy tail can bias by omitting honest votes; revision 2
  had them and revision 3 removed them as not worth their complexity (Appendix B).

Changed: B-Chain relays along the chain (`O(n)` hops). Sumeragi uses a star (leader → all,
set A → proxy tail → all). The normal case takes **5 one-way hops** until every member commits
(proposal; votes → P; PrepareQC → all; Commit votes → P; CommitQC → all). P itself commits after 4.
All-to-all voting (stage 2, §5.2) takes 3 hops. The star trades about `2Δ` per height for
`3(n−1) + 2(q−1)` messages instead of `(n−1) + 2n(n−1)`, and for `2(q−1)` signature verifications
at P instead of `2(n−1)` at every node. Under load (`pace = 0`) the next proposal carries the
CommitQC (§3.3), so most members learn finality from the next proposal anyway.

Topology affects only liveness and routing, never safety: every safety rule below is independent of
positions. The schedule is predictable as soon as the committee and recent headers are known (§15).

---

## 3. Data types, signing preimages, certificates

Wire and persisted encodings use Norito derives. **Signing preimages and hash preimages are fixed
byte layouts defined here** (not Norito), so they are exact and codec-independent.

### 3.1 Constants and encodings

```text
TAG_SIG       = ASCII "sumeragi/sig"          TAG_BLOCK    = ASCII "sumeragi/block"
TAG_PAY       = ASCII "sumeragi/payload"      TAG_ATT      = ASCII "sumeragi/attach"
TAG_QC        = ASCII "sumeragi/qc"           TAG_TC       = ASCII "sumeragi/tc"
TAG_COMMITTEE = ASCII "sumeragi/committee"    TAG_TOPOLOGY = ASCII "sumeragi/topology"
KIND_PROPOSAL = 0x01, KIND_PREPARE = 0x02, KIND_COMMIT = 0x03, KIND_TIMEOUT = 0x04, KIND_ECHO = 0x05;
availability signatures use the separate domain of §12.8
Hash32 = [u8; 32]; ValidatorIndex = u32 (canonical index into C_h)

kb(pk)    = be16(len(raw)) ‖ raw    // raw: 48-byte compressed G1 point (production); 32 bytes (simulator)
keys(l)   = be32(len(l)) ‖ kb(l[0]) ‖ … ‖ kb(l[len(l)−1])
enc(None) = 0x00 ; enc(Some(w)) = 0x01 ‖ be64(w)     // optional view
opt(None) = 0x00 ; opt(Some(x)) = 0x01 ‖ x           // optional digest
blobs(l)  = be32(len(l)) ‖ be32(len(l[0])) ‖ l[0] ‖ … ‖ be32(len(l[k−1])) ‖ l[k−1]   // byte strings
sig bytes = canonical compressed encoding (96 bytes for BLS)
```

### 3.2 Block

```rust
struct BlockHeader {
    epoch: EpochId, // authenticated scheduling epoch and complete context
    instance: Hash32,                 // I
    height: u64,                      // h
    origin_view: u64,                 // view in which this block was first (freshly) proposed
    parent_hash: Hash32,              // block_hash of the committed block at h−1
    parent_result: Hash32,            // R certified by the CommitQC of h−1
    payload_hash: Hash32,             // H(TAG_PAY ‖ payload)
    availability_digest: Hash32,      // complete ordered original RS16 row table (§12.8)
    payload_len: u32,                 // 0 < len(payload) ≤ max_block_bytes(h)
    proposer: ValidatorIndex,         // == idx(L(h, origin_view))
    skipped_leaders: Vec<PublicKey>,  // [L(h, x) for x in 0..min(origin_view, a_h)]
    control_witness: ControlWitness,  // occupied canonical bytes in fixed inline capacity 2048
                                      // checked by deterministic execution at every view
}
// AvailableBody is an opaque local custody owner (§12.8), not a wire-decoded struct.
// Its read-only accessors expose source(), header(), availability(), payload().
```

```text
block_hash = H(TAG_BLOCK ‖ I ‖ E ‖ be64(h) ‖ be64(origin_view) ‖ parent_hash ‖ parent_result ‖
               payload_hash ‖ availability_digest ‖ be32(payload_len) ‖ be32(proposer) ‖ keys(skipped_leaders) ‖ be32(control_len) ‖ control_witness)
body_ok(b) := len(b.payload()) == b.header().payload_len ∧
              H(TAG_PAY ‖ b.payload()) == b.header().payload_hash ∧
              complete original signatures and every canonical RS16 row match (§12.8)
```

Keys (not indices) are used in headers so that demotion (§2.1) is computable from headers alone,
even across committee changes. At `h = g + 1`: `parent_hash`/`parent_result` are the genesis block
hash and result.

**Body intake rule.** Proposals and sync entries carry mandatory original availability evidence,
never application payload bytes. Only `AvailableBody` from actual authoring, reconstruction or
source-bound stored-body restoration enters execution, storage or publication. Its immutable
`AvailabilitySource` binds the expected instance, height, hash and complete authenticated
`HeightConfig`; Core and each consuming store compare that source with their independently
selected authority, and check admission to the original State allocation pool. Matching only an
epoch number, header hash or filename is insufficient. Manifest possession authenticates the
original authorizations but proves no received rows, reconstructed body or durable storage.
A failed body/row is discarded without an execution verdict or fabricated evidence, and a local
resource refusal retains the same job for retry. A held body is never replaced. Votes and QCs
bind the header hash, including payload and availability commitments; `R` need not repeat them.

The block's *own* result `R` is **not** in its header; it is bound by the votes and certificates
of that block (§4). The next block binds it again via `parent_result`. The builder result
`None` (called `EMPTY` in the work-driven rules) means no work is available; it is never a block.
`Some(PayloadBytes)` is nonempty and funded by the original State allocation pool. Every proposal and
stored body must have a nonzero payload, and the application must reject a decoded payload
with no transaction entrypoints. Genesis is applied through its separate startup path.

### 3.3 Signed messages and preimages

`E = be64(epoch) ‖ epoch_context_id` binds the scheduling epoch and the hash of its complete
canonical application context. The context commits to network, consensus mode, epoch bounds and
authorization, immutable authority generation, complete ordered BLS roster with verified proofs
of possession, and fresh authenticated leader randomness (§10). It contains no local certificate
or signer subset. Every header, vote, QC, timeout, TC and probe echo carries this identity;
verification requires equality with the authenticated context installed for that height.

```text
prop_preimage(h, v, bh, ad)      = TAG_SIG ‖ 0x01 ‖ I ‖ E ‖ be64(h) ‖ be64(v) ‖ bh ‖ ad
vote_preimage(kind, h, v, bh, R) = TAG_SIG ‖ kind ‖ I ‖ E ‖ be64(h) ‖ be64(v) ‖ bh ‖ R
                                                         (kind ∈ {0x02, 0x03})
tmo_preimage(h, v, hq)           = TAG_SIG ‖ 0x04 ‖ I ‖ E ‖ be64(h) ‖ be64(v) ‖ enc(hq)       (hq = view of the carried PrepareQC)
echo_preimage(nonce, height)     = TAG_SIG ‖ 0x05 ‖ I ‖ E ‖ be64(nonce) ‖ be64(height)        (probe echo, §3.5, §7.4 R2)

ad = att_digest(justify, parent_qc)
   = H(TAG_ATT ‖ opt(justify.map(tc_digest)) ‖ opt(parent_qc.map(qc_digest)))
qc_digest(c) = H(TAG_QC ‖ c.kind ‖ I ‖ E ‖ be64(c.height) ‖ be64(c.view) ‖ c.block_hash ‖ c.result ‖
                 be32(len(c.signers)) ‖ c.signers ‖ c.agg_sig)
tc_digest(t) = H(TAG_TC ‖ I ‖ E ‖ be64(t.height) ‖ be64(t.view) ‖ be32(len(t.entries)) ‖
                 [be32(idx) ‖ enc(hq)] for each entry ‖ t.agg_sig ‖ opt(t.high_pqc.map(qc_digest)))
```

Domain separation: tag, kind, instance, scheduling epoch/context, height and view are in every consensus preimage; block
hash and result in every vote. There is no other consensus voting
object. The probe echo (kind `0x05`) binds the prober's nonce
and the replier's reported height, carries no sign-once obligation (a node signs one per probe it
answers), is never recorded, and cannot verify as a vote, proposal or timeout because of its kind
byte.
The original author's manifest and per-row authorizations use separate availability domains
(§12.8), signed by the original header proposer under the complete authenticated height source.
They are retained unchanged across re-proposals, publication and serving; later leaders do not
re-sign them. A proposal signature binds its complete header and QC/TC attachments. A
`ProposalMessage` additionally carries the mandatory original availability table. Corrupting
that carrier or an actual row cannot frame the leader for a different signed proposal.

The preimages are what is signed, not the signed message itself: production signatures over
kinds `0x01`–`0x05` and the availability statements are `Sign(sk, SHA-256(preimage))` under
`DST_SIG`, through the consensus API of §1 item 6.

```rust
struct Proposal {
    instance: Hash32, height: u64, view: u64,  // round of this proposal (≥ header.origin_view)
    header: BlockHeader,
    justify: Option<TimeoutCert>,  // Some iff view > 0: a TC for (height, view − 1)
    parent_qc: Option<Qc>,         // a CommitQC of height − 1; None iff height == g + 1
    sig: Signature,                // by L(height, view) over prop_preimage(height, view, bh, ad)
}
struct ProposalMessage { proposal: Proposal, availability: AvailabilityFrame }
struct Vote {
    epoch: EpochId, // authenticated scheduling epoch and complete context
    kind: VoteKind,                // Prepare | Commit
    instance: Hash32, height: u64, view: u64,
    block_hash: Hash32, result: Hash32,
    signer: ValidatorIndex, sig: Signature,   // over vote_preimage(kind, h, v, bh, R)
}
struct TimeoutVote {
    epoch: EpochId, // authenticated scheduling epoch and complete context
    instance: Hash32, height: u64, view: u64,
    high_pqc: Option<Qc>,          // the signer's lock at signing time; view ≤ self.view
    signer: ValidatorIndex, sig: Signature,   // over tmo_preimage(height, view, high_pqc.map(|q| q.view))
}
```

#### 3.3.1 External verification surface (frozen)

Contracts on other chains verify global `CommitQC`s directly (`specs/sccp.md` §3.8), so these
parts of the protocol are frozen for the first release:

- the Commit vote preimage layout `vote_preimage(0x03, h, v, bh, R)` (165 bytes) and the `I`
  derivation of §1 item 8;
- the signer bitmap order: bit `i` is canonical index `i`, LSB-first within each byte;
- `n ≤ 31` and `q = n − f` exactly;
- the consensus suite of §1 item 6: `DST_SIG` over `SHA-256` of the preimage;
- `RESULT_TAG` and the 221-byte finality header layout of the certified result (§4.1.1).
  Destinations take the body digest `D_body` as given, so `RESULT_BODY_TAG` is not part of
  this surface.

Changing any of them requires a new SCCP route revision with new destination contracts,
activated by the SCCP governance, not only a node release. The golden test
`crates/iroha_sumeragi/tests/destination_surface_golden.rs` pins the preimage, `I`, the bitmap
order and the quorum for `n ∈ {4, 7, 31}` (target; `TODO:` WP-C5).

### 3.4 Certificates

```rust
struct Qc {
    epoch: EpochId, // authenticated scheduling epoch and complete context
    kind: VoteKind, instance: Hash32, height: u64, view: u64,
    block_hash: Hash32, result: Hash32,
    signers: Bitmap,               // exactly ceil(n_h/8) bytes, bit i = canonical index i, spare bits 0
    agg_sig: AggregateSignature,
}
struct TimeoutCert {
    epoch: EpochId, // authenticated scheduling epoch and complete context
    instance: Hash32, height: u64, view: u64,
    entries: Vec<(ValidatorIndex, Option<u64>)>, // strictly increasing index; hq view per signer
    agg_sig: AggregateSignature,                 // aggregate of the individual timeout signatures
    high_pqc: Option<Qc>,                        // the PrepareQC with view == max(entries.hq)
}
```

**verify_qc(qc, C_h)**: `qc.instance == I`; `qc.epoch` equals the authenticated scheduling
epoch/context for its height; bitmap length exact and spare bits zero; `popcount == q_h`;
`AggVerify({pk_i : bit i set}, vote_preimage(kind, h, v, bh, R), agg_sig)`. Every PrepareQC
and CommitQC has exactly `q_h` equal validator votes;
otherwise valid signer supersets are rejected. Different exact-quorum signer subsets remain
valid for the same authenticated value. The committee used is always
`C_{qc.height}`; a certificate for a height whose committee is not known is buffered (bounded,
§8.4) or dropped, never verified against another committee.

**verify_tc(tc, C_h)**: `tc.instance == I`; `tc.epoch` equals the authenticated scheduling
epoch/context for its height; `len(entries) == q_h`; indices strictly increasing and
`< n_h`; every `hq ≤ tc.view`; group entries by `hq` value and check
`AggVerifyMulti([(agg_pk(group_g), tmo_preimage(h, tc.view, hq_g))]_g, agg_sig)` (cost: `#groups+1`
pairings); let `m = max(hq)` over entries (None if all None): `high_pqc` MUST be `None` iff
`m = None`, and otherwise `high_pqc.kind == Prepare`, `high_pqc.height == h`,
`high_pqc.view == m`, `verify_qc(high_pqc, C_h)`.

*Uniqueness lemma used throughout:* two valid PrepareQCs with the same `(I, h, v)` certify the same
`(block_hash, R)` (they share ≥ `f+1` signers, one honest, and honest nodes sign one Prepare per
`(I,h,v)`, §7.1). Hence "the PrepareQC of view `m`" is unambiguous and a TC need not sign the hash.

**Formation.** An aggregator (proxy tail, or any member at stage 2) keeps at most one vote per
`(kind, view, signer)` and forms a certificate as soon as it holds `q_h` valid votes with identical
`(kind, h, v, block_hash, R)`, using exactly those `q_h`. The QC formation API rejects larger input lists;
it never emits a signer superset. A TC is formed from any `q_h` valid
timeout votes for `(h, v)` (honest aggregators pick the `q_h` with the highest `hq`, §6.7); its
`high_pqc` is the PrepareQC carried by the entry with the maximal `hq`. The aggregator's own entry
is its stored signed message (§6.6), never a re-signed one. Verification cost is bounded by the
cheap-reject rules and the verified-certificate cache (§6.1 rule 5).

### 3.5 Unsigned messages

```rust
pub enum WireMessage {
    Proposal(Box<ProposalMessage>),
    Vote(Vote),
    Qc(Qc),
    Timeout(Box<TimeoutVote>),
    Tc(Box<TimeoutCert>),
    Status(Box<Status>),
    SyncRequest(SyncRequest),
    SyncResponse(SyncResponse),
    PayloadRequest(PayloadRequest),
    PayloadManifest(PayloadManifest),
    ApplicationControl(ApplicationControl),
    PayloadChunk(PayloadChunk),
}
pub struct SyncRequest {
    pub instance: Hash32,
    pub from_height: u64,
    pub max_count: u16,
    pub max_bytes: u32,
}
pub struct SyncResponse { pub instance: Hash32, pub blocks: Vec<SyncEntry> }
pub struct SyncEntry {
    pub manifest: PayloadManifest,
    pub commit_qc: Qc,
}
pub struct PayloadManifest {
    pub header: BlockHeader,
    pub availability: crate::availability::AvailabilityFrame,
}
pub struct PayloadRequest {
    pub instance: Hash32,
    pub height: u64,
    pub block_hash: Hash32,
}
pub struct PayloadChunk {
    pub instance: Hash32,
    pub height: u64,
    pub block_hash: Hash32,
    pub index: u32,
    pub bytes: crate::availability::RowBytes,
}
struct Status {                // periodic "state, not custody" summary (§6.11)
    instance: Hash32,
    height: u64, view: u64,                   // sender's current round (while awaiting: tip.height + 1, view 0)
    committed_qc: Option<Qc>,                 // CommitQC of height − 1 (None at the first height)
    high_pqc: Option<Qc>,                     // sender's lock at `height` (None while awaiting)
    high_tc: Option<TimeoutCert>,             // highest TC the sender holds at `height` (None while awaiting)
    proposal_hash: Option<Hash32>,            // block hash of the (height, view) proposal it holds
    want_proposal: bool,                      // holds no proposal of (height, view) and asks for it (§6.11)
    probe: Option<u64>,                       // nonce: "answer me with your Status" (§7.4 R2); set in
                                              //   every Status while one of the sender's keys is unanchored
    echo: Option<Echo>,                       // signed answer to a probe (§7.4 R2)
}
struct Echo {
    epoch: EpochId, // authenticated scheduling epoch and complete context
    nonce: u64,                               // the probe nonce this Status answers
    key: PublicKey,                           // replier's signing key at its height, else its first configured key
    sig: Signature,                           // by `key` over echo_preimage(nonce, Status.height) (§3.3)
}
```
While `awaiting` (§6.8) a node's `Status` has `height = tip.height + 1`, `view = 0`,
`committed_qc = tip.commit_qc`, no `high_pqc`, `high_tc` or `proposal_hash`, and
`want_proposal = false`.

**Wire tags, version and traffic classes.** A `WireMessage` travels as one canonical Norito frame
(`WireMessage::encode` / `decode`). Its enum tag (a `u32`) is the variant's position in the list
above, 0 to 11. `PROTOCOL_VERSION = 1` names the sole wire format in the P2P handshake;
every incompatible change replaces the layout directly. No earlier decoder is accepted. The traffic class of a message
(§12.3 O8) depends only on the canonical enum tag:

| Tag | Message | Class |
|---|---|---|
| 0 | `Proposal(ProposalMessage)` | Proposal |
| 1, 2, 3, 4 | `Vote`, `Qc`, `Timeout`, `Tc` | Control |
| 5, 6, 8 | `Status`, `SyncRequest`, `PayloadRequest` | Control |
| 7, 11 | `SyncResponse`, `PayloadChunk` | Bulk |
| 9 | `PayloadManifest` | Proposal |
| 10 | `ApplicationControl { context, bytes }` | Control; bytes are bounded to 2048 and nonempty |

`ApplicationControlContext = { instance, epoch: EpochId, height, parent_hash, parent_result }`.
The envelope is view independent. Only a current committee sender with exactly the receiver's
current applied parent/context reaches the application reducer. The application independently
verifies the same State source, the sender's DKG index and complete threshold signature context.
The native producer binds the current parent to the opaque original execution tip and
the hash journal captured in the same State publication. Control retries borrow these fixed
identities without decoding a durable block again. Missing or mismatched publication authority
rejects before signing; provider readiness is probed afresh even when that parent is unchanged.
The core retains at most one timestamp per sender, and admits at most one such input per sender
per rebroadcast interval. The driver retains at most one pending input per sender, hard capped
by `MAX_COMMITTEE_SIZE`; the production committee bound remains enforced by application admission.

`traffic_class_of_frame(bytes)` computes the same class from the declared canonical Norito
frame header and enum tag before decoding. For every accepted frame it agrees with
`WireMessage::traffic_class`. Availability messages use this same `WireMessage` owner and codec;
there is no second schema-dispatched availability protocol. A proposal always carries signed
metadata and its original availability table; actual row bytes travel only in `PayloadChunk`.

### 3.6 Evidence

```rust
enum Evidence {
    ProposalEquivocation(Proposal, Proposal),   // same (I,h,v), both signed by L(h,v), different (bh, ad)
    VoteEquivocation(Vote, Vote),               // same (kind,I,h,v,signer), different (bh, R)
    TimeoutEquivocation(TimeoutVote, TimeoutVote), // same (I,h,v,signer), different hq
    InvalidProposal { proposal: Proposal, defect: Defect }, // signed-content defect, §6.2 step 7
    ConflictingCertificates(Qc, Qc),            // CommitQCs of the same committed height, different value (§7.6)
}
```

Equivocation evidence is self-verifying. Two certificates of the same `(I, h, v, kind)` with
different values attribute their signer intersection (each signed two values in one view). For
conflicting CommitQCs of one height at different views the core attributes nobody: honest members
can legitimately sign both once more than `f` members are faulty, and forensics (who signed Commit
at `v` and later a timeout at `≥ v` with `hq < v`, who voted for a proposal violating the TC rule)
are the application's. `InvalidProposal` is verifiable from its content by re-checking the signed
fields against the committed chain. **Only signed-content defects produce evidence.** A block that
executes to `Invalid` produces none: the leader does not execute before proposing (§4.2), so an
honest leader can propose a poison transaction without knowing it, and a single divergent executor
would otherwise accuse honest leaders. Penalties are the application's.

**Application evidence (SCCP forgery; target, not yet implemented).** The application may record
evidence the core never produces. SCCP records a `CommitQC`-valid certificate of a committee
generation whose block hash or certified result differs from the global chain's at that height
(`specs/sccp.md` §4.9). The committed evidence record carries
`RecordedEvidenceV1 { Native(Evidence), SccpForgery(Box<SccpForgeryRecordV1>) }`, with the scope
`EvidenceScope::SccpGeneration { generation }`. An SCCP record is self-contained: its offence
height is the generation's start height and its offenders are the validator registrations
resolved when the generation was created, so the penalty uses neither the peer-key lookup nor the
locator tenure filter, and the native evidence horizon does not apply to it (Governed NPoS
reconfiguration, below).

Message sizes include complete authenticated epoch context and the declared Norito framing.
A proposal or manifest additionally carries the exact availability table of §12.8
(`4 + 96 + N·(32 + 96)` inner bytes, before its Norito envelope). Earlier estimates excluding
this mandatory table do not describe the wire size. Votes and certificates carry only their
canonical consensus fields, including exact BLS signatures and signer bitmaps; the decoder
rejects retired extension fields and trailing bytes. Execution-result preimages remain local
publication and certified-read evidence, never vote or QC sidecars.

The canonical execution-result witness carries each complete authorized epoch context once:
the current context, the optional boundary's next context, and its optional frozen preparation.
Each ready successor slot carries only its exact height and lag-two parameters, deriving its
epoch from the boundary's next context when present and otherwise from the current context.
Pending-boundary slots retain their explicit predecessor identity and boundary height. Encoding
rejects an owned ready slot that differs from its derivable context; decoding reconstructs and
validates the complete graph while charging the additional owned credentials to the inherited
decode allocation budget. This keeps supported 31-member boundary/preparation graphs within
the same 64 KiB witness limit, with no alternate or repeated-context result decoder.


---

## 4. Execute-before-vote

### 4.1 What is executed and what is bound

- A committee member executes a proposed block `B` at height `h` against `S_{h−1}`: the applied
  state (after `BlockApplied(h−1)`, §12) or, earlier, the executor's cached post-state of the
  committed parent block. The core allows the latter only when this node executed that parent and
  obtained exactly the certified result (`tip.exec_ok`, §6.8), so durable apply of the parent is
  not on the vote path. If the driver no longer holds that post-state (evicted, lost on restart)
  it recomputes it; a missing cache entry is never a verdict (§12.3 O4). Execution is requested by
  `Action::Execute { block, req, certified }` (`certified` only exempts the block from the
  application's clock guards, §4.2, §4.5) and answered exactly once by
  `Event::Executed { block_hash, req, outcome }`,
  `outcome ∈ {Valid(R), Invalid, Failed, Cancelled}`; `req` is a per-core request counter, so an
  answer to a request the core has since discarded never matches a live entry (§6.3).
- `R` is the application's 32-byte execution commitment. It MUST commit to everything the chain
  must agree on for that block: at least the post-state root, the root of per-transaction outcomes
  (accepted/rejected + reason), the event root, and the height configuration scheduled by this
  block (`C_{h+2}` and chain parameters, §10). The core treats `R` as opaque. After G.3, `R` binds
  `parent_keyed_state_root = root(P_{h−1})` and the post-execution
  `keyed_state_root = root(X_h)`, as specified in §16; until then E51 describes the as-built
  behaviour. For instances that use `ExecutionResultCommitment`, §4.1.1 fixes how `R` binds the
  finality header that external verifiers read.
- The Prepare vote, the PrepareQC, the Commit vote and the CommitQC all sign
  `(I, h, v, block_hash, R)`. A CommitQC therefore finalizes order **and** result. The next
  block's header repeats the certified `R` as `parent_result`.

#### 4.1.1 Certified result of `ExecutionResultCommitment` instances (application binding)

**Status.** The current Rust candidate uses this sole result layout in the execution producer,
Kura readers and portable verifiers. `iroha_data_model::sumeragi_finality::certified_result`
owns `SccpFinalityHeaderV1`, the fallible public `result_of_preimage`, and `CertifiedResultV1`;
the body-only result hash API is removed. TODO: complete the current candidate's Core execution,
replay and external-consumer qualification before treating WP-C2 as delivered. The core still
treats `R` as opaque; this subsection fixes how the application computes it, because external
verifiers pin it (§3.3.1).

Every instance whose result is an `ExecutionResultCommitment` (the global chain, dataspace roots
and private developer anchors) computes:

```text
body   = norito::encode_canonical(ExecutionResultCommitment)     // ≤ MAX_RESULT_BODY_BYTES = 65 315
D_body = H(RESULT_BODY_TAG ‖ body)                                // RESULT_BODY_TAG = "iroha/sumeragi/result-body/v1"
R      = SHA-256(RESULT_TAG ‖ F ‖ D_body)                         // RESULT_TAG = "iroha/sumeragi/result/v1"; 277-byte input
```

- `F` is the 221-byte finality header `SccpFinalityHeaderV1` (`specs/sccp.md` §3.6 calls it `X`;
  it is unrelated to the post-execution State `X_h` of §16). It names the network, height and
  block time, and on the global chain, once SCCP exists, the block's SCCP commitment, the history
  accumulator and the committee generation that certifies the block. Every other instance, and
  the global chain before SCCP exists or when its inputs are missing, uses the inactive form
  `magic ‖ network_id ‖ be64(h) ‖ be64(t(h)) ‖ 0x00 ‖ 0^156`.
- The executor produces `F` after execution, from the post-execution state and the authenticated
  schedule inputs, as a pure function that reads no clock, configuration or Kura. It travels with
  the original execution owner and is never recomputed from another state view. Voters need no
  separate check: each voter's own `F` enters its own `R`, so a divergent `F` is a divergent `R`
  (`ExecutionMismatch`, §4.2). SCCP bookkeeping never makes a block `Invalid`.
- The stored result preimage (`CommitCertificate.result_preimage`) is `F ‖ body`, at most
  `MAX_RESULT_PREIMAGE_BYTES = 65 536` bytes in total, so the body bound is 65 315 bytes.
  It remains local publication and certified-read evidence; it is never a vote or QC sidecar.
  The worst supported graph, a 31-seat boundary with a frozen preparation, has a body of
  30 763 bytes, measured and pinned against the body bound by the `iroha_data_model` test
  `maximal_31_seat_boundary_with_frozen_preparation_fits_the_result_body_bound`, so the
  preimage bound stays 65 536 bytes.
  The layout does not alter `FRAME_OVERHEAD`, `T_req` or the core wire.
- `R` is a raw SHA-256 output: it is never passed through `Hash::prehashed`, `HashOf` or any
  type that checks or sets the `H` marker bit. `result_of_preimage(p)` is the only `R` function,
  for voters and readers alike; it returns nothing when `len(p) < 222`, `len(p) > 65 536` or `F`
  does not parse, and callers treat that as a mismatch, never as a local fault.
- Readers that hold `F ‖ body` without executing it decode it through
  `CertifiedResultV1::decode(p, scope)`, which performs C1–C4 and the scope rule of
  `specs/sccp.md` §3.6: `F` parses, its height equals the body's, its network equals the
  scheduled epoch context's, its committee root matches that context's committee, a boundary
  decision in the body is reflected in `F`, and a `NonGlobal` scope requires the inactive form.
  A reader that also holds the block then calls
  `CertifiedResultV1::check_block(height, timestamp_ms)`, which performs C5: `F` names the
  block's height and canonical time. `ExecutionResultCommitment` retains only the body codec;
  `R` cannot be computed from the body alone. Structural readers may inspect a candidate with
  the permissive Global scope, but the authenticated reader must enforce the original signed
  genesis scope against the same retained `F` before granting authority. An AMX tracker retains
  its independently registered result scope; a received header cannot select that scope.
- Lane instances keep their own `LANE_RESULT_TAG` result and carry no `F`.

### 4.2 Verdicts

- The leader makes **no** result claim in the proposal and does not execute before proposing (it
  executes after sending, in parallel with everybody else; its Prepare vote carries its own `R`).
  Execution is therefore on the critical path once, not twice.
- Every voter binds the `R` it computed. Votes with different `R` are different values and never
  aggregate together. With deterministic execution all honest voters compute the same `R`; a
  certificate exists only for an `R` computed by ≥ `q − f ≥ f + 1` honest members.
- **Certified blocks.** A block is *certified at `h`* for a node if the node holds a valid
  PrepareQC `Q` at `h` for it (every re-proposal is: its TC names `Q`). Its expected result is
  `Q.result`. If the local outcome is `Invalid`, or `Valid(R)` with `R ≠ Q.result`, the local
  executor disagrees with ≥ `f + 1` honest executions: `Action::LocalFault(ExecutionMismatch)`, no
  Prepare vote in this view, **no evidence and no early timeout**; the node keeps participating
  otherwise (timeouts, Commit votes, aggregation). If a CommitQC for `Q.result` later reaches
  apply, the apply path detects the divergence and halts that instance (§12.5). The core tells
  the executor whether a block is certified: `Action::Execute { block, req, certified }` carries
  `certified = true` iff the node holds a PrepareQC at `h` for the block (§6.2 step 9). The
  verdict never depends on the flag; it only exempts the block from the application's
  local-clock guards (§4.5).
- **Deterministic invalidity** of a proposal is either (a) a defect in its signed content
  (§6.2 step 7), or (b) `Executed = Invalid` for a `body_ok`, uncertified, fresh block. Then: no
  Prepare vote and an immediate timeout of the view (§6.6) if it is the current view; in case (a)
  `ReportEvidence(InvalidProposal)`; in case (b) no evidence (§3.6) and `PayloadRejected{height,
  view, block_hash}` to the driver. The payload builder MUST NOT quarantine a transaction merely
  because it was in a rejected block: it re-checks that block's transactions one by one against its
  current state and quarantines only a transaction that makes a block `Invalid` on its own (a
  Byzantine leader can wrap honest transactions in an invalid block). All honest nodes reach the
  same verdict, so the view is abandoned by everyone. Transactions that fail inside a valid block
  are *not* block invalidity; they are recorded as rejected inside `R`.
- **Local failure.** Executor panics, I/O errors and resource exhaustion MUST be reported as
  `Failed`, never `Invalid`. `Failed` → `LocalFault(ExecutorFailed)` and a retry of `Execute`
  after a backoff (100 ms, doubling, capped at `rebroadcast_interval`) while the block is still
  needed; no vote meanwhile, no evidence, no early timeout.
- **Cancelled work.** Every `DiscardExecution` removes the core's execution entries (pending or
  finished) of the blocks it does not keep, and the driver drops their post-states and answers
  their outstanding requests `Cancelled`. A block that comes back later (e.g. re-proposed after a
  PrepareQC this node had not seen) is executed again from scratch; a stale answer is ignored.
- Missing or corrupt payload bytes (`body_ok` fails) are never invalidity: the body is fetched
  (§6.9).
- **Nonempty work.** Zero-length payloads are invalid at every height. The application also
  rejects a decoded payload with no transaction entrypoints (§3.2).

### 4.3 The complete Prepare-vote predicate (no local refusal reasons)

An honest committee member of `C_h` signs `Prepare(h, v, bh, R)` iff **all** hold:
1. it is in round `(h, v)`, has a signing key at `h` (§7.4), and `timeout_view < v` (it has not
   timed out view `v` or later);
2. it has not signed a Prepare at `(h, v)` (sign-once record);
3. it holds a Proposal for `(h, v)` that passed §6.2 (signature, leader, attachments, header, TC
   rule), whose body it holds (`body_ok`) and has handed to `StoreBody`;
4. `Executed(bh) = Valid(R)`, and if `bh` is certified, `R == Q.result`;
5. it is in set A of `(h, v)`, or its stage for `(h, v)` is ≥ 1 (§5.2).

Nothing else may gate a vote: not load, queue state, mempool contents, recovery state, peer
connectivity, disk pressure, clock readings (except through the executor's `Failed` answers
named in §1 item 5 and specified in §4.5, which only withhold condition 4 for an uncertified
block), other instances, or a local lock (there is no voter-side lock check; §7.3 explains why
the TC rule makes it unnecessary for safety and why it would harm liveness). Slowness only delays
conditions 3–4; the vote is still sent when they become true, as long as condition 1 holds.

### 4.4 Why this does not reintroduce the v2 common-mode stall

The v2 root cause was that votes depended on each node's local conditions, so one bug or one
slow resource stopped every honest node at once. Here:
1. **Value dependence is deterministic.** The only data-dependent input is `exec`, a pure function
   of committed data. A deterministic "Invalid" verdict is shared by all honest nodes and costs
   one view (early timeout, next leader; the leader of that view is recorded as skipped), and
   `PayloadRejected` lets builders drop the culprit transactions. Progress requires available
   valid work and a functioning deterministic executor; empty blocks never conceal an executor
   defect.
2. **Timing dependence is absorbed by the pacemaker.** Execution latency only delays votes. View
   timeouts grow ×1.5 per failed view up to `T_max ≥ T_req` (§8.2 L3; the same formula is the
   config validation rule, §9.4), and the start level adapts across heights (§9), so the view
   eventually outlasts execution. Timers are separate events (`Tick`) that the driver delivers
   ahead of every other event (§12.3 O5); the core never blocks.
3. **Consensus does not wait on local apply/storage.** Entering `h+1`, timing out, Commit-voting
   and aggregating need neither execution nor apply; a Prepare vote needs the block executed, which
   needs the parent's post-state, available from the speculative cache before apply. Consensus runs
   at most two heights ahead of durable apply (§10.2).
4. **Execution never waits on another instance or on external data.** Everything execution reads
   besides `S_{h−1}` (AMX proofs, remote commit proofs, time) is carried in the payload.
5. **Local faults stay local.** A node with a broken, failing or slow executor is one faulty node;
   up to `f` such nodes (in any positions) are masked because set B joins (§5.2). Such a node never
   produces evidence (execution verdicts never do, §3.6); certified-block mismatches and `Failed`
   are local faults only; an `Invalid` it computes for an uncertified block costs one early
   timeout and a local `PayloadRejected`, i.e. the timeout of one faulty node, which the `q` (TC)
   and `f + 1` (join) thresholds already tolerate.

### 4.5 Application clock guard on Prepare votes (application layer)

**Status.** Clock policy belongs to the application executor (`iroha_core`). The sans-IO
core supplies the genuine `certified` flag and retains the application's source-bound local
admission owner with a successful execution. It checks that owner immediately before a first
Prepare signature, including cached execution and signing retries. Core implements CT1 for
full State roots and routing lanes. Native CT5 covers original governance/SCCP due work and
Global AMX Begin/Decision effects at execution, completion and first Prepare signing. The
simulator models source-bound clock admission and original parent/creation-floor pacing
(§13.1). Current component controls do not establish network qualification.
`specs/sccp.md` §4.3 and `specs/parliament_private_ballot_design.md` §3.4 rely on them.

Block time is the original timestamp in the authenticated resultless block body, bound by
its signed RS16 payload and finality certificate. Validity requires
`t(block) >= max(parent + cadence, lane time_floor_ms, max tx.creation_time + 1)`.
A fresh proposer chooses the maximum of that floor and one captured wall-clock reading,
rounded down to milliseconds; the same reading governs input selection and the final SCCP
forgery recheck. The original timestamp is compared with the local clock before uncertified
full-State execution. Genesis keeps its original wall-clock validation.

A fresh view can therefore propose the exact same still-admissible signed inputs at a later
authenticated time after an idle period or partition. It needs no replacement payment signature,
keepalive or unrelated transaction. A retained payload retry keeps its original bytes and time;
a PrepareQC-certified or locked block is never restamped. Followers, apply and cold replay derive
execution from the original authenticated timestamp, never from their own clocks. This changes
neither transaction TTL nor Queue expiry, and does not authorize empty blocks. Without these
guards a Byzantine leader could move the chain's clock arbitrarily far forward with a post-dated transaction, or anchor due work at a
stale time with an old one. Deadlines of the SCCP and governance applications are anchored at
certified block times, so both directions need a bound. No validity rule reads a clock:

| # | Rule |
|---|---|
| CT1 | **Clock ahead.** For every non-genesis block of every instance of the network (global and lanes) executed with `certified = false`, the executor MUST answer `Failed(ClockAhead)` while `t(block) > local_wall_ms + max_clock_drift_ms`. It MUST NOT answer `Invalid`. Under §4.2 that is `LocalFault(ExecutorFailed)` and a retry with backoff; meanwhile no `Valid` is recorded, so §4.3 condition 4 withholds the Prepare vote. Commit votes are not guarded directly: `try_commit` Commit-votes a PrepareQC of the current view without executing, and the bound reaches every CommitQC through that PrepareQC. |
| CT2 | **Scope.** The apply and replay path of CommitQC-certified blocks never consults the clock. Genesis keeps its existing wall-clock check. |
| CT3 | **Builder pacing.** The payload builder MUST NOT include a transaction with `creation_time_ms > local_wall_ms`. A fresh full-State proposal chooses `max(captured local_wall_ms, required time floor)` and MUST NOT publish while its original timestamp, including lane merge floors, exceeds `local_wall_ms`; it waits instead. Routing-lane batches keep their anchor/input-derived time rule. |
| CT4 | **Bound.** `max_clock_drift_ms` is a committed chain parameter (`SumeragiParameters`), not a node-local setting, so every honest voter's guard uses the same value. Genesis validation and `validate_parameter_change` MUST enforce `max_clock_drift_ms ≤ MAX_CLOCK_DRIFT_BOUND_MS = 60 000`. |
| CT5 | **Stale due work** (global executor). An uncertified candidate that applies time-sensitive effects MUST defer while `local_wall_ms − t(block) > sumeragi.due_work_max_lag_ms`: before returning a successful execution and again before the first Prepare signature. The native owner currently recognizes Global AMX Begin and Decision writes, including indirect execution and finalizers; a partial Yes that creates no Decision is outside this rule. Governance and SCCP classification, including `specs/sccp.md` §4.7.4 K2, remains required. Refusal is local (`Failed(StaleDueWork)` or typed signing refusal), never `Invalid`, never on certified apply or replay. `SumeragiParameters::due_work_max_lag_ms` is committed, defaults to 60 000, and MUST be at least `2·max_clock_drift_ms + 4·block_cadence_ms` with checked arithmetic. A fresh proposal can authenticate a later time without replacing its signed inputs. |

**Clock-drift parameter ownership.** `max_clock_drift_ms` belongs to the application State;
it is absent from the lag-two `ChainParamsRecord`. The guard for height `h` reads the committed
parent State. A successful `MaxClockDriftMs` update at `h` first governs the guard at `h + 1`,
and cannot change the guard of its own block. The single model-owned CT4 bound is enforced by
structured genesis authoring, validation of the executed genesis State, and `SetParameter`
validation, including genesis instructions. Lane policy validation applies the same bound
before copying its parameters into an incarnation; that incarnation retains its pinned allowance.
Zero and the exact 60 000 ms bound are permitted;
larger values reject deterministically without consulting a clock. CT4 does not itself implement
the local guards or establish a real-time expiry guarantee; their implementation scope is below.

The same parent-State rule governs `DueWorkMaxLagMs`. Genesis, lane policy admission and
parameter changes validate the combined drift/lag/cadence bound. A parameter write cannot
weaken its own block's admission. The native execution owner captures the parent lag before
executing any instruction; cached admission does not reread a later State or node setting.

**Certified re-proposals.** The core sets `certified = !certified_results(bh).is_empty()` whenever
it emits `Execute` (§6.2 step 9), re-evaluated when a `RetryAt` entry re-emits it; this covers a
re-proposal's `Q` and the node's own lock. The executor skips CT1 and CT5 iff `certified` is
true, and the verdict never depends on it. Without the exemption, nodes that discarded the
execution on a view change, sat behind a hidden PrepareQC (F33) or restarted would answer
`StaleDueWork` forever for a re-proposal, which keeps its original time, and a due-work block
whose PrepareQC was hidden for longer than `sumeragi.due_work_max_lag_ms` could never gather Prepare
votes again, breaking L4. The exemption is sound by induction over the PrepareQCs of the block.
The first one formed has `q` Prepare signers, at least `f + 1` of them honest; no PrepareQC of
the block existed when they voted, so each executed it with `certified = false` and passed CT1
and CT5. Every later Prepare vote for the block is either guarded the same way or exempted by a
PrepareQC that this argument already covers, so the bound of that first PrepareQC holds for all.

**Properties.** Let every honest wall clock `W_i` be within `ε` of real time, with
`2ε ≤ max_clock_drift_ms` (the liveness assumption).

- **Upper bound.** If `C_h` has at most `f` Byzantine members, a CommitQC at `h` has at least
  `f + 1` honest Commit signers, and an honest member Commit-votes only on a PrepareQC of the
  block in its current view. By the induction above, the bound of every PrepareQC of the block
  is the bound of the first one formed: its `q` Prepare signers include at least `f + 1` honest
  ones, each of which executed the block with `certified = false` and passed CT1 at some real
  time `τ`, so `t(h) ≤ τ + ε + max_clock_drift_ms`. Every later Prepare vote for the block,
  guarded or exempted, and the commit come after that `τ`. At any later real time an individual
  honest clock reads `W_j ≥ τ − ε`, so `t(h) ≤ W_j + 2·max_clock_drift_ms`. A deadline anchored
  at certified time can therefore fire up to `2·max_clock_drift_ms` early relative to an
  individual honest clock, and wallets and relayers submit at least that plus inclusion latency
  before a deadline. A cached `Valid` from an earlier view only lowers `τ`; a restart re-sends a
  durable Prepare that was guarded when first signed; the Prepare votes of a certified
  re-proposal are exempt and rest on that first PrepareQC.
- **Lower bound for anchors.** Every block that anchors governance work or an SCCP heartbeat
  has `t(h) ≥ W_i − sumeragi.due_work_max_lag_ms` for some honest first Prepare voter, at the time of
  that first Prepare. Between the first honest Prepare and the commit, view changes, a hidden
  PrepareQC or a halt can add unbounded delay, so an anchor can be older than wall time at
  commit; the applications state their recovery rules (`specs/sccp.md` §4.3).
- **Liveness.** An honest leader's fresh block satisfies CT1 at every honest voter whose clock is
  within `max_clock_drift_ms` of the leader's. Its captured proposal time also satisfies CT5;
  certified re-proposals are exempt, and larger skew only delays votes.
- **Determinism.** `Valid(R)` / `Invalid` is unchanged and never depends on `certified` or a
  clock; only the timing of Prepare votes does.

**Core ownership.** Full State roots (Global and independent dataspaces) forward the core's
`certified` flag through the driver and serialized executor request. CT1 reads an injected
Unix clock only after original header/authority binding and before execution effects. A refusal
retains its source for retry and never enters the deterministic negative cache. Authenticated
CommitQC preparation and cold replay bypass the guard. Routing `LaneBatch` derives its effective
timestamp from its authenticated anchor time and signed input creation times (§3 of
`specs/sumeragi_lanes.md`), using the allowance pinned in its incarnation. The lane executor
retains its original decoded admission across clock waits and rejoins the original anchor identity.

**First-Prepare ownership.** The implementation's successful outcome is
`ExecOutcome::Valid { result, admission }`. `admission` has no wire decoder: it retains the
original paid application owner and binds instance, epoch, height, original block hash and
result. Native sensitivity includes original governance/SCCP due work and, on the Global root,
the schema-owned AMX witness-key classifier after original witness authentication. A final clock read follows
encoding and resource waits; a stale result discards the provisional overlay, fees and writes,
returning the original decoder for retry without negative caching. Cached `Live` execution
rechecks the same rule. The retained signing owner checks a fresh injected wall clock after
stage or backend waits; only a genuinely matching PrepareQC held by the core exempts it.
A decoded safety reservation cannot supply admission. Once a Prepare signature succeeds,
its exact bytes are persisted before publication and may be reused after restart without
creating a later first signature. These rules bound first-Prepare admission, not commit time.

**Builder ownership.** Global and routing-lane selection leave future signed inputs in their
original Queue admission. Future-only work returns a clock retry instead of an empty answer, so the driver's
timer retries the final input without another admission. The original assembled header gates
publication, including parent cadence and certified lane floors. Global clock waiting retains
the same source, input lease and funded output; completed output reuse rechecks the clock after
the physical parent and Queue lease. The current routing-lane candidate also carries that
existing Queue admission lease through selected batches and funded encoding. It rechecks
expiry, withdrawal and admission generation before work and after encoding, retaining the
original output only while its original admission remains live; runtime qualification is open.
Global merge still enforces monetary expiry and duplicate
validity. A local clock regression withholds the retained output until the boundary recovers,
without changing its canonical bytes or any validity result.

**Verification.** Full-State CT1 and certified-flag forwarding have Core controls HC257/HC258
(SC5 and the CT1 portion of SC17). Global CT3 input and canonical publication pacing have
HC259/HC260 controls, including original retained output and certified lane floors (SC6).
Routing-lane CT1 and effective builder pacing have HC268/HC269 controls; future-only lane
retry is HC264. Native CT5 due-work refusal and its certified exemption have HC281/HC282
controls (SC12/SC17); HC334 checks completion resampling, and HC334–HC337 cover the
source-bound native admission through encoding, cached execution and first signing.
Their current-candidate strict mutation and network qualification remain required. The machine's
emission of `certified` is MS51, killed by `det_s51_execute_certified_flag` and
`f33_hidden_prepareqc_due_work_block_commits_after_lag`. The deterministic simulator models CT1
and CT5 in its toy application (§13.1): per-machine wall clocks with skew, block times stamped
by the builders at their wall clock (so honest blocks satisfy CT3), honest executors that answer
`Failed` for uncertified executions and skip both rules for certified ones. Successful
World execution retains the exact source and a shared clock updated by the same event
owner. First Prepare checks that current clock after execution, stage and durability waits;
AMX sensitivity comes from the actual Global Begin/Decision result records. The
`det_ct5_world_retained_execution_rechecks_clock_at_first_prepare` control exercises clock
steps and ordinary event advancement, exact-source refusal and certified admission.
Clock-enabled builders also retain the certified parent's cadence and original queued creation
floors. They answer `EMPTY` while the floor is ahead, retain the original work, and deliver
one request-bound `PayloadReady` after the wall clock catches up. Deterministic validation
checks those floors during execution and replay; Core SC6 additionally covers native lane
floors and funded publication. The simulator's tests are:

- `clock_guard_liveness_with_f_plus_one_slow_clocks` (n = 4 and 7): `f` Byzantine members
  withhold every vote and propose far-future blocks, `f + 1` honest clocks run at real time and
  the others at `+max_clock_drift_ms`. Every height commits, the fast leaders' blocks included.
  When the fast clocks jump 30 s ahead, none of their blocks commits; after the clocks converge,
  their blocks commit again, and no far-future block ever commits.
- `clock_guard_certified_time_within_two_drifts`: two honest clocks at `+max_clock_drift_ms` and
  one at real time, and a Byzantine member that votes and proposes in turn blocks dated
  `+2·max_clock_drift_ms` and far-future blocks. The oracle O-TIME (§13.2) holds at every commit,
  some certified time exceeds an honest clock by more than one drift, and no far-future block
  commits. It kills MS52, the simulator mutation that deletes CT1.
- `f33_hidden_prepareqc_due_work_block_commits_after_lag`: in F33, every transaction applies due
  work, and a hidden PrepareQC delays the re-proposal past `sumeragi.due_work_max_lag_ms`. The honest
  members execute it with `certified = true` and it commits. With MS51, CT5 refuses it forever.
- `clock_guard_due_work_lower_bound_at_first_prepare`: a Byzantine voter backdates due-work
  proposals beyond the permitted lag. Honest executors refuse them, honest leaders still
  progress, and O-TIME checks freshness at the first genuine honest Prepare of each due-work
  block. It kills MS65, which deletes simulated CT5; delayed certified re-proposals and commits
  retain the original first-Prepare evidence without a new freshness requirement.
- `clock_guard_committed_parent_wait_retains_work_until_clock_recovery`: an actual committed
  parent and separately the original queued creation time survive a clock regression; no
  payload is published until its floor is reached, duplicate wakeups do not consume a current
  request, and the original work commits after natural catch-up or clock correction (MS68).
- `clock_guard_parent_and_creation_floors_hold_independently_at_equality` places the wall
  between the two floors in both orders and tests exact equality. Creation metadata travels
  in the immutable toy transaction, so registering or deleting a workload ID cannot change
  replay validity. Custom and AMX toy inputs without creation metadata impose no creation floor.
- `clock_guard_completed_payload_waits_after_build_latency_backstep` regresses the wall
  between construction and completion, retains the exact original completed bytes and publishes
  them only at clock recovery; stale callbacks cannot consume them (MS69).
- `clock_guard_fresh_proposal_waits_after_authored_queue_backstep` moves the wall back after
  successful construction, while the original authored body is queued. The final admission
  check withholds that exact body before Core can sign a fresh proposal and resumes after
  recovery; certified re-proposals remain exempt (MS70).
- `clock_guard_accepts_exact_drift_allowance`: a slow honest voter accepts a block stamped by
  an honest leader exactly `max_clock_drift_ms` ahead. It kills MS66, which removes the allowance.
- F39 (§13.3) is the randomized scenario of MS51, MS52, MS65 and MS66.

A simulator test cannot kill a Core mutation. The full-State CT1 portion of SC17 has the
Core controls above; `certified_execution_skips_clock_guards` additionally exercises a genuine
certificate and cold replay. Routing-lane controls retain the corresponding original admission
and encoding. Native CT5 controls exercise original-parent due work, completion, certified
retry and the final Prepare-signing boundary; simulator evidence does not substitute for their
named Core mutation kills.

---

## 5. Message flow

### 5.1 Normal case (stage 0, all roles responsive), round (h, v)

| Step | Who | Sends | To |
|---|---|---|---|
| 1 | leader `L` | `Proposal` (StoreBody + persist proposal record first) | members of `C_h` (set A first), plus `C_{h+1} \ C_h` if known |
| 2 | every member | validates (§6.2), stores the body, executes once the parent state is available | — |
| 3 | set A member | `Vote(Prepare, R)` (persist first) | proxy tail `P` (local if self) |
| 4 | `P` | on `q` matching Prepares: `Qc(PrepareQC)` | all other members |
| 5 | every member | on PrepareQC: update lock; set A member sends `Vote(Commit)` (persist first) | `P` |
| 6 | `P` | on `q` matching Commits: `Qc(CommitQC)` (§6.8 step 1a), then commits | all other members (+ `C_{h+1} \ C_h`) |
| 7 | every member | on CommitQC: commit, enter `(h+1, 0)` | — |

Set B members receive the proposal and PrepareQC, execute (so they are ready for stage 1 and for
apply), update their lock, but do not vote at stage 0. Latency: 5 one-way hops until non-P members
commit (4 at `P`), one execution, two record persists (the body write overlaps execution), and the
leader's pacing. Every vote sent to `P` is retransmitted to `P` at `t_retx`, doubling, until that
phase's QC is known (§6.11). A lost QC costs one retransmit period: `P`, when it already holds the
PrepareQC a received Prepare belongs to, answers the voter with it (once per voter per view,
§6.4); a Commit vote retransmitted after `P` committed arrives at a lower height and is answered
with `P`'s `Status`, whose `committed_qc` is that CommitQC (§6.1 rule 3).

### 5.2 Graded fallback (the stage ladder)

Each node has, per round `(h, v)`, a `stage ∈ {0, 1, 2}` that only increases within the round and
is set to the round's *initial stage* on every round entry (height entry and view change).
`t_ready` = the time at which §4.3 conditions 1–4 first held at this node (it could Prepare).
`t_lastvote` = the time of this node's latest vote in the round (for a set-B member that has not
voted: `t_ready + t_retx`). `t_retx` (§9.1) is about three times the locally observed vote-to-QC
latency. The ladder is local routing only; it has no safety impact. Silent or slow set-A members
and proxy tails are handled by this ladder alone; nothing demotes them (§2.1).

- **Initial stage (hint).** 1 if the parent CommitQC `c = tip.commit_qc` has a signer outside
  `setA(h−1, c.view)` (the previous height needed set B, so a set-A member is probably silent and
  set B votes at once), else 0. It is a pure function of the parent CommitQC this node holds
  (normally the one `P` broadcast, so members agree; a disagreement only changes routing): no
  timer, no stored state. Its cost when wrong is `2f` extra vote messages per phase and
  their verification at `P`, never latency. It can stay on in all-honest runs: once set B votes,
  `P` forms each certificate from the first `q` matching votes, and whenever a set-B vote beats a
  set-A vote the next parent CommitQC again has a set-B signer. That is accepted: it happens only
  when a set-B member was faster than a set-A member, so set B's votes shorten the round. A
  Byzantine proxy tail can keep it on only by certifying set-B votes, i.e. while set B is voting
  anyway.
- **Stage 0 (normal).** Set A votes to `P`; set B does not vote.
- **Stage 1 (set B joins through `P`).** Entered at round entry by the hint, or when (a) the QC
  of the current phase is overdue: `now ≥ t_ready + t_retx` and no PrepareQC for `(h, v)` is held,
  or `now ≥ t_pqc + t_retx` and no CommitQC for `h` is held (`t_pqc` = when this node first held
  the PrepareQC of `(h, v)`; this catches a member that Prepares but withholds its Commit), or (b)
  a PrepareQC for `(h, v)` is held whose signers include a set-B member of `(h, v)` (a set-A vote
  was missing in the Prepare phase, so it will be missing in the Commit phase too). Set B votes,
  still only to `P`.
- **Stage 2 (broadcast; every member aggregates).** Entered when no CommitQC for `h` is held and
  (a) `now ≥ t_lastvote + 2·t_retx` without the QC of the phase of that vote, or
  (b) `now ≥ anchor + φ·T(level)` (backstop, also for nodes that never became ready, §9.1), or
  (c) *contagion*: the node is not `P` and holds verified votes of `(h, v)` (either kind) from
  ≥ `f + 1` distinct signers other than itself. Such votes show that at least one honest member
  has voted; they may have been relayed (votes are relayable signed objects), so a Byzantine `P`
  that forwards the honest votes it receives can move every member to stage 2 at its proxy-tail
  turns — a cost it can cause anyway by withholding its QCs (stage 2(a)). `f` Byzantine signers
  cannot trigger contagion alone. Only verified votes exist in pools (§6.4), so no trigger of this
  ladder ever counts an unverified vote.
- **On entering stage 1 or 2** the node re-sends once, with the new routing, each own vote of the
  round whose phase QC it does not hold, and restarts that vote's retransmit schedule from this
  send (§6.11); it then calls `try_prepare()` and `try_commit()` (§6.3, §6.5). There is no other
  path to a vote: §4.3 and S3 (§7.1) stay the only predicates.
- **Routing.** `route(vote)` = `Send(P)` at stages 0–1 (nothing if `P == me`), `Broadcast` to
  `C_h \ {me}` at stage 2. The node's own vote enters its own pool through `pool_insert` exactly
  once, when it is signed (§6.4), never through `route`. Every member aggregates whatever votes it
  receives (§6.4); a member that forms a PrepareQC uses it locally, and a member that forms a
  CommitQC commits. Only `P` broadcasts the QCs it forms (§6.5 2d, §6.8 step 1a); other members
  rely on §5.1's QC answers, on `Status`, and on the next proposal's `parent_qc`. `P` accepts
  votes from anyone at any stage.

Failure coverage:
- silent or slow non-`P` set-A member → stage 1: at the first height where it is missed, set B
  supplies the missing vote to `P` about `t_retx` later (trigger a); at every following height
  whose parent CommitQC needed set B the hint starts stage 1 at once, so set B's votes reach `P`
  together with set A's and the member costs `2f` extra vote messages per phase but no latency. It
  is never demoted for this;
- silent, withholding or selective proxy tail → stage 2 about `2·t_retx` after the members'
  votes. A member is the view-0 proxy tail at least once and at most `1 + |D_h|` times per `n`
  heights (§2.1), so this cost recurs at that rate; it is not demoted for it;
- silent, invalid or equivocating leader → no quorum in the view → view timer (or at once, on a
  signed defect or proven equivocation, §6.6) → TC → next leader
  (a different non-demoted member); the failed leader is recorded in `skipped_leaders` and demoted
  for `W` heights. A crashed member is therefore demoted at its first turn as leader, after at most
  one proxy-tail turn (stage 2) and the set-A turns in between (stage 1; after the first, the hint
  removes the `t_retx` wait). Exception: a re-proposal keeps its original header, whose
  `skipped_leaders` lists only views before its `origin_view` (§3.2), so a leader that fails in a
  view after a block was locked (PrepareQC formed, no commit) is not recorded at that height and is
  demoted at a later turn.

### 5.3 Message complexity (point-to-point messages per height)

| Case | Formula | n = 4 (q=3, f=1) | n = 22 (q=15, f=7) |
|---|---|---|---|
| Stage 0 (normal) | `3(n−1) + 2(q−1)` | 13 | 91 |
| Stage 1, one silent non-P set-A member | `3(n−1) + 2(q−2+f)` | 13 | 103 |
| Stage 1 from round entry (hint), every member responsive (can persist, §5.2) | `5(n−1)` | 15 | 105 |
| Stage 2, silent proxy tail | `(n−1) + (q−1) + 2(n−1)²` | 23 | 917 |
| View change (per failed view) | `n(n−1)` timeouts `+ (n−1)` TC → next leader | 15 | 483 |
| Status while unsettled (per `rebroadcast_interval`, per unsettled node) | `n − 1` | 3 | 21 |
| Status while settled (per `status_keepalive`, all nodes) | `n(n−1)` | 12 | 462 |
| Late entry or lost proposal copy: `Status{want_proposal}` + one proposal re-push | 2 | 2 | 2 |

For comparison, all-to-all two-phase voting costs `(n−1) + 2n(n−1)` = 27 / 945 per height.
These counts cover consensus metadata messages, excluding signed RS16 rows, manifests and
repair traffic (§12.8). Actual byte and message costs require those additional frames; no
end-to-end bandwidth result follows from this table.

---
## 6. Handlers

### 6.0 Core state (per instance)

```rust
struct Core {
    local: LocalParams,                  // §9.3 / §12.4
    w: u64,                              // demotion window W (Init.demotion_window, genesis constant, §2.1)
    keys: Vec<LocalKey>,                 // configured and retired keys: {pk, signer: Option<Signer> (None if retired),
                                         //   abstain_below: u64, unanchored: bool, restore: Option<SafetyRecord>} (§7.4)
    nonce: u64,                          // Init.nonce: probe nonce of this process lifetime (§7.4 R2)
    probe: BTreeMap<PublicKey, u64>,     // while a key is unanchored: lowest height reported per member key of
                                         //   C_{tip.height+2} in a fresh, verified echo (§6.11)
    // committed chain (consensus view of it)
    tip: Tip,                            // {height, block_hash, result, commit_qc: Option<Qc>, exec_ok: bool,
                                         //  exec_req: Option<u64>, prev: Option<(Hash32, Hash32)>}
                                         //  (§6.8 step 2, §6.3 step 0; prev = (bh, R) of tip.height − 1, §7.6)
    applied: u64,                        // highest height acknowledged by BlockApplied (durable)
    configs: BTreeMap<u64, HeightConfig>,// {committee, chain params} for tip.height−1 ..= applied+2
    recent_headers: VecDeque<BlockHeader>, // committed headers, the last W + 2 up to `applied`
    pending_apply: VecDeque<PendingApply>, // {height, commit_qc, parent_hash, parent_result}: committed,
                                         //   CommitBlock not yet emitted (≤ 2), strictly increasing height
    awaiting: bool,                      // committed `tip.height`, config of tip.height+1 not yet known
    // current round
    h: u64, view: u64,                   // h == tip.height + 1 (h == tip.height while awaiting)
    t_enter: Millis, t_prop: Option<Millis>, anchor: Millis, // §9.1
    t_body: Option<Millis>,              // when this node first held proposal and its body (§6.2 step 9, §9.2)
    late_entry: bool,                    // this height was entered late (§6.8 step 5); reset on view change
    asked: bool,                         // a Status{want_proposal} was sent to L(h, view) in this round (§6.11)
    signer: Option<usize>,               // index into `keys` of the key that signs at h; None = observer
    timeout_view: Option<u64>,           // highest view this node signed a timeout for at h
    proposal: Option<Proposal>,          // the accepted proposal of (h, view)
    build: Option<(u64, BuildPhase)>,    // outstanding BuildPayload request id (initial build / bounded retry / view > 0)
    stage: u8, t_ready: Option<Millis>, t_pqc: Option<Millis>, t_lastvote: Option<Millis>, // §5.2
    mine: Mine,                          // exact signed messages of this round: proposal, prepare, commit, timeout,
                                         //   each with its t_vote (time of its latest send by route) for §6.11
    blocks: BTreeMap<Hash32, AvailableBody>,     // bodies in memory (≤ 6, §8.4); all are also in the driver's body store
    exec: BTreeMap<Hash32, ExecState>,   // blocks of height h: Pending{since, req} | Valid(R) | Invalid | RetryAt{t, attempt}
    next_req: u64,                       // request counter for Execute and BuildPayload (§6.3, §6.10); never reused
    wants: BTreeMap<Hash32, Want>,       // {height, reason, sources, attempt, next_retry}: sole owner of body fetches
    repropose: bool,                     // leader of (h, view) waiting for the body of TC.high_pqc's block
    votes: VotePools,                    // (kind, view ∈ {view−1, view, view+1}) → one vote per signer
    timeouts: Vec<Option<TimeoutVote>>,  // highest-view timeout per signer at h (len n_h)
    high_pqc: Option<Qc>,                // lock: highest-view PrepareQC seen at h
    high_tc: Option<TimeoutCert>,        // highest-view TC seen at h
    safety: SafetyRecord,                // last value handed to PersistSafety for the signing key (§7.4)
    pm: Pacemaker,                       // start_level, fast_streak, last_exec_ms (maximum over h), latency_ewma, qc_lat_ewma (§9)
    sync: SyncState,                     // §6.9 (target, target_verified, sources, buffer, outstanding request)
    peers: PeerTable,                    // bounded LRU (n + max_observers): last Status, rate-limit and re-push stamps
    cert_cache: CertCache,               // LRU of digests of certificates verified at h (capacity 4n)
    reported: BTreeSet<EvidenceKey>,     // evidence already emitted: (kind, view, signer) for pool views, (view) for proposals
    deadlines: Deadlines,                // propose/build, stage, retransmit, view, rebroadcast, status, probe, sync, fetch, exec retry
}
```

`handle(now, event) -> Vec<Action>` runs one handler to completion; `next_wakeup()` returns the
earliest pending deadline. Helpers used below: `C = C_h`; `n, f, q, a` of `C_h`;
`order/L/P/setA/setB` of `(h, view)` (§2); `route(msg)` (§5.2); `recipients` = members of `C_h`
except self, set A of `(h, view)` first, and for a `Proposal` or a CommitQC broadcast also
`C_{h+1} \ C_h` when `C_{h+1}` is known; `sign(..)` = sign with `keys[signer]` (signatures are
deterministic: the same key and preimage always give the same bytes, §12.1);
`persist()` = `safety.lock = high_pqc.clone(); safety.high_tc = high_tc.clone();` push
`PersistSafety(safety.clone())`. Every signed message is created *after* `persist()` in the same
action list, and O2 (§12.3) holds every externally visible action after a `PersistSafety` until
the record is durable. A node whose `signer` is `None` at `h` (not in `C_h`, or its key abstains
or is unanchored, §7.4) runs every rule except those that sign ("observer"); its `Status` to
`C_h` makes members reply with theirs, whose `committed_qc` drives its sync (§6.9).

**Own messages.** The node's own votes and timeouts never go through the network or `route` to
itself (O7). Each is inserted exactly once, right after it is signed, by the same insertion
routine that handles a verified received one: `pool_insert(vote)` (§6.4 step 4: insert,
contagion check counting signers other than `me`, QC formation) and `timeout_insert(t)` (§6.7:
store, TC formation, join). Formation therefore runs on own insertions too
(the node's own vote can be the `q`-th; with `n = 1` every certificate forms this way).

**Evidence dedup.** Before emitting `ReportEvidence`, the core checks `reported` (key: kind, view,
signer, or kind and view for proposals); each key is reported at most once. Keys of views outside
the vote-pool window are pruned with the pools; all are cleared on height entry.

**Names used by the mutations of §13.4.** Handlers: `on_proposal` (§6.2), `on_executed` (§6.3),
`on_vote` (§6.4), `on_qc` (§6.5), `on_timeout` and `on_tc` (§6.7), `commit_height` and
`enter_height` (§6.8), `on_sync_response`, `on_body` and `on_block_request` (§6.9), `on_tick`
(§6.11), `on_status` (§6.11), `on_block_applied` (§6.13), `restore` (the Init procedure, §7.4).
Helpers: `request_exec`, `discard_exec`, `try_prepare`, `pool_insert`, `try_commit`,
`sign_timeout`, `timeout_insert`, `form_tc`, `propose`, `advance_to`, `persist`, `route`,
`request_proposal` (§6.11), `initial_stage`, `quorum`, `verify_qc`, `verify_tc`, custody/source acceptance,
`demoted_set`, `leader`, `level`, `anchor`. An implementation may structure code differently but MUST keep each safety predicate identifiable so
that a mutation targets the actual current validation site.

### 6.1 Intake filter (all messages)

1. Drop if `msg.instance ≠ I`.
2. **Service messages** (`Status`, `SyncRequest`, `SyncResponse`, `PayloadRequest`, `PayloadManifest`, `PayloadChunk`)
   bypass the round-height filter; they go to §6.9 / §6.11. Actual rows reach a worker only
   for an outstanding exact-height/hash want, with the authenticated transport sender preserved.
   Every message also passes structural limits and original-pool byte admission before dispatch.
3. **Round messages** with `height < h`: a `Vote` or `Timeout` from a member of the current
   committee proves the sender is behind → `Send` it our `Status` (at most once per peer per
   `rebroadcast_interval`). A `Qc(Commit)` with `height ≤ tip.height` → safety monitor (§7.6).
   Everything else is dropped.
4. Round messages with `height == h + 1`: a `Proposal` → §6.2 step 0 (its `parent_qc` commits
   `h`); a `Qc(Commit)` → §6.9. A `Vote`, `Timeout`, `Qc(Prepare)` or `Tc` from a member of `C_h`
   → `Send` the sender our `Status` (rate-limited as above; its reply carries CommitQC(h)), then
   drop. Heights `> h + 1`: a `Qc(Commit)` or a proposal's `parent_qc` → §6.9 sync hint; else drop.
5. **Cheap rejects before any signature check:** an object byte-identical to one held; a vote
   whose `(kind, view, signer)` slot already holds the same `(bh, R)`; a PrepareQC with view
   `< high_pqc.view` (or equal: same value by the uniqueness lemma); a TC with view
   `≤ high_tc.view` that is not a proposal's `justify`; a CommitQC for a committed height equal in
   value to the committed one; a timeout equal in `(view, hq)` to the stored one of its signer.
   Every object held by the core (pool entries, timeouts, certificates, proposals) was verified or
   formed locally from verified parts, so a cheap reject only ever compares against verified
   entries. These rules apply to top-level objects; a certificate nested in another object (a
   timeout's `high_pqc`, a TC's `high_pqc`, a proposal's `justify`) is verified (or found in
   `cert_cache`) as part of its container and then handled by the container's rules (§6.5 2a
   compares views itself). A certificate whose digest is in `cert_cache` is valid without
   re-verification; every certificate verified at `h` enters the cache (LRU, capacity `4n`;
   cleared on height entry).
6. Signed objects are accepted from any peer (relays are fine); authenticity comes from the
   signature under `C_h[signer]`. Every signature is verified before its object enters any pool
   or changes any state; there is no deferred or optimistic verification.

### 6.2 On `ProposalMessage { proposal: p, availability }` (round `(h, w)`, `w = p.view`)

0. **Height.** If `p.height == h + 1`: if `h` is not yet committed and `p.parent_qc` is a
   CommitQC for `h`, run §6.8 on it (verification included); continue only if the node is now in
   round `h + 1` (not awaiting); otherwise drop (an awaiting node gets the proposal again through
   its late-entry `Status`, §6.11).
   If `p.height > h + 1`: pass `p.parent_qc` to §6.9 as a sync hint and drop.
1. **Authenticate.** `bh = block_hash(p.header)`, `ad = att_digest(p.justify, p.parent_qc)`.
   Verify `p.sig` under `C_h[L(h, w)]` over `prop_preimage(h, w, bh, ad)`. Failure → drop silently
   (a relay may have tampered; nothing is attributable).
2. **Duplicates and equivocation.** If a proposal for `(h, w)` is already held: same `(bh, ad)` →
   pass the carrier to the wanted acquisition (step 8); this grants no body custody; stop.
   Different `(bh, ad)` → `ReportEvidence(ProposalEquivocation(held, p))` (deduplicated, §6.0);
   keep the held one; if `w == view`, `sign_timeout(view)` (early timeout, §6.6: the leader of
   the current view is proven faulty, whether or not this node already Prepared the held
   proposal); stop. At most one proposal per `(h, w)` is ever held, and only in the current view
   (`advance_to` drops it), so twins of a view the node already left are never compared.
   Both proposals passed step 1, so the evidence carries two different preimages of `(h, w)`
   signed by `L(h, w)`: an honest leader never signs two (S1), and bytes a relay can change (the
   availability carrier or actual rows) do not change `(bh, ad)` (§3.3), so an honest leader cannot be framed (§7.5).
3. **Justify.** `w == 0`: `p.justify` MUST be `None`. `w > 0`: `p.justify` MUST be a valid TC
   (§3.4) for `(h, w − 1)`; run the TC handler (§6.7) on it (it may advance `view` to `w`).
   A violation is a signed defect → step 7.
4. **View.** If `w < view`: if `bh` is wanted (§6.9), pass the original manifest to
   acquisition under the independently selected historical source; stop. If `w > view`: drop.
5. **Parent.** `p.parent_qc` is `None` iff `h == g + 1`; otherwise it MUST be a valid CommitQC
   (under `C_{h−1}`, cached) for `(tip.block_hash, tip.result)`. A violation is a signed defect →
   step 7.
6. **Header (signed content).** `header.instance == I`, `header.height == h`,
   `parent_hash == tip.block_hash`, `parent_result == tip.result`,
   `payload_len ≤ max_block_bytes(h)`, and:
   - **TC rule** — `w > 0` and `p.justify.high_pqc = Some(Q)`: `bh == Q.block_hash` (re-proposal;
     `expected_R = Q.result`). No other header check: `Q`'s honest signers checked this header
     against the same parent.
   - **Fresh block** — `w == 0`, or `p.justify.high_pqc = None`: `origin_view == w`;
     `proposer == idx(L(h, w))`; `skipped_leaders == [L(h, x) for x in 0..min(w, a_h)]`;
     `payload_len > 0` at every view, including certified re-proposals (§3.2).
7. **Signed defect.** A failure in step 3, 5 or 6 is attributable to `L(h, w)`:
   `ReportEvidence(InvalidProposal{p, defect})` (deduplicated, §6.0), and if `w == view`,
   `sign_timeout(view)` (early timeout, §6.6). Stop.
8. **Accept.** `proposal = p`; `t_prop = now` (recompute `anchor` and deadlines, §9.1).
   Unless exact custody is held, create `want(bh, Proposal)` with sources `L(h, w)`, `Q`'s
   signers for a re-proposal, and members whose `Status` reported `bh`. Supply the mandatory
   manifest to `AcquirePayload` with the independent `AvailabilitySource`. Missing or corrupt
   rows never supply a body or a deterministic execution defect. Only a matching opaque
   `BodyAvailable` completion can satisfy the want (§6.9).
9. **Execute.** If the body is held and `t_body` is unset, `t_body = now` (the committing view's
   duration is measured from here, §9.2; this step runs again when the body arrives). If the
   body is held, the parent state is available (`applied ≥ h − 1`, or
   `tip.exec_ok`) and `exec[bh]` is absent: `request_exec(bh)`. If `exec[bh]` already holds an
   outcome, continue at §6.3 step 3. (Otherwise execution is requested when the body arrives,
   when `BlockApplied(h−1)` arrives, or when this node's own execution of the committed parent
   finishes with the certified result, §6.9, §6.13, §6.3 step 0; an entry removed by a
   `DiscardExecution` is absent, so a re-proposed block is executed again, §4.2.)

`request_exec(bh)`: `req = next_req; next_req += 1; exec[bh] = Pending{since: now, req}`; push
`Execute{block: blocks[bh], req, certified: !certified_results(bh).is_empty()}`, where
`certified_results(bh)` are the results of the PrepareQCs at `h` for `bh` that the node holds (a
re-proposal's `Q`, or its lock). The flag is computed at every emission, so a due `RetryAt`
(§6.3 step 2) re-evaluates it; it only exempts the block from the application's clock guards
(§4.5).

`discard_exec(keep)`: for every `Pending{since}` entry whose block is not in `keep`,
`pm.last_exec_ms = max(pm.last_exec_ms, now − since)` (a lower bound of an execution that
outlasted its view, §9.2; its answer will be ignored); then remove every `exec` entry whose
block is not in `keep`; push `DiscardExecution{height: h, keep}`. It is the only way the core emits `DiscardExecution`
(§6.8 step 4, §6.12). It never touches the committed block's execution tracked in `tip.exec_req`
(that block is of height `tip.height`, and `DiscardExecution` is per height).

### 6.3 On `Executed { block_hash: bh, req, outcome }`

0. **Committed block.** If `bh == tip.block_hash` and `req == tip.exec_req` (the execution of the
   committed block was still pending when it committed, §6.8 step 2): `tip.exec_req = None`;
   `Valid(R)` with `R == tip.result` → `tip.exec_ok = true`, and if the current proposal's body is
   held with no `exec` entry, `request_exec` it (§6.2 step 9); `Valid(R ≠ tip.result)` or
   `Invalid` → `LocalFault(ExecutionMismatch)` (apply will report `ApplyDiverged`, §12.5);
   `Failed`/`Cancelled` → nothing (the driver executes the block when it applies it). Stop.
1. Ignore unless `exec[bh] == Pending{since, req}` with this `req` (a stale answer to a discarded
   or superseded request, including every `Cancelled` for one, is ignored). Record the outcome;
   `pm.last_exec_ms = max(pm.last_exec_ms, now − since)` (the longest execution at `h`, §9.2).
2. `Failed` or `Cancelled` → `exec[bh] = RetryAt{t: now + backoff, attempt}` (§4.2: 100 ms ·
   2^attempt, capped at `rebroadcast_interval`; `attempt` counts consecutive failures of this
   block at `h`), and for `Failed` `LocalFault(ExecutorFailed)`; stop. (The driver cancels only
   work that a `DiscardExecution` left out of `keep`, whose entries the core had already removed,
   so a matching `Cancelled` is a driver anomaly and is retried like a failure.) A due `RetryAt`
   calls `request_exec(bh)` if the block is still needed (§6.11).
3. If `bh` is the current proposal's block (otherwise stop), with `expected_R(bh)` = the result of
   a held PrepareQC at `h` for `bh` (a re-proposal's `Q`, or `high_pqc` if it names `bh`):
   - `Invalid` and `bh` uncertified → `PayloadRejected{h, view, bh}`,
     `sign_timeout(view)` (early timeout); stop. (No evidence, §3.6.)
   - `Invalid` and `bh` certified, or `Valid(R)` with `R ≠ expected_R(bh)` →
     `LocalFault(ExecutionMismatch)`; stop.
   - `Valid(R)`: if §4.3 conditions 1–4 hold and `t_ready` is unset: `t_ready = now`; schedule
     the stage timers (§5.2).
4. `try_prepare()`.

`try_prepare()`: if the §4.3 predicate holds for `proposal` (condition 3 includes
`proposal.view == view`; condition 2 is `safety.prepare` having no entry at `view`):
```text
safety.prepare = Some((view, bh, R)); persist()
vote = sign(Prepare, h, view, bh, R); mine.prepare = vote
route(vote); pool_insert(vote); t_lastvote = now
```
(The body's `StoreBody` was emitted at acceptance; the `PersistSafety` above is durable only after
it, §12.3 O2.)

### 6.4 On `Vote x` (from the wire; own votes enter at step 4 through `pool_insert`)

1. Require `x.height == h`, `x.view ∈ {view−1, view, view+1}`, `x.signer < n`; else drop.
2. If `x.kind == Prepare`, `me == P(h, x.view)` and this node holds a PrepareQC of `x.view`:
   `Send` it to `x.signer` (at most once per signer and view; no signature check is needed to
   send a certificate); the voter evidently lacks it. This step precedes the duplicate check,
   because retransmissions are exact duplicates. (A Commit vote for `h` cannot meet a CommitQC of
   `h` here: the node that holds one has committed `h`, and the vote is then handled by §6.1
   rule 3.)
3. Apply §6.1 rule 5 (an exact duplicate stops here); verify `x.sig` under `C[x.signer]`; failure
   → drop. If the pool `(x.kind, x.view)` already has a vote from `x.signer`: same
   `(bh, R)` → drop; different → `ReportEvidence(VoteEquivocation)` (deduplicated), drop.
4. `pool_insert(x)`: insert (only votes verified in step 3, or the node's own, ever enter a pool).
   If `x.view == view`, `me ≠ P` and the pools of view `view` now hold votes from ≥ `f+1` distinct
   signers other than `me`: enter stage 2 (§5.2 contagion). If the pool now holds `q` votes with
   identical `(kind, view, bh, R)` and no QC of that kind and view is held: form the Qc from
   exactly those `q` (§3.4) and run §6.5 with `formed_locally = true`.

Any member aggregates any votes it receives; the proxy tail is only the *designated* receiver.
Every vote is signature-checked individually before it is pooled (at most `2(n−1)` checks per
round at `P` at stage 0–1, bounded per view by the one-vote-per-slot rule); aggregation never
verifies unverified votes in bulk.

### 6.5 On `Qc c`

1. `c.kind == Commit`: `c.height == h` → §6.8 (passing `formed_locally`); `c.height > h` → §6.9;
   `c.height ≤ tip.height` → safety monitor (§7.6).
2. `c.kind == Prepare`, `c.height == h`: verify (skip if formed locally or cached).
   a. If `high_pqc` is `None` or `c.view > high_pqc.view`: `high_pqc = c` (lock). The new lock is
      written with the next `persist()` (§7.4).
   b. If `c.view > view`: `advance_to(c.view)` (§6.12). (The lock is updated first so that the
      `keep` list of that view change includes `c`'s block and its execution survives.)
   c. If the body of `c.block_hash` is not held: create `want(c.block_hash, Lock)` with sources the
      signers of `c`.
   d. If `formed_locally && me == P`: `Broadcast(Qc(c))` to `recipients`.
   e. If `c.view == view`: set `t_pqc = now` if unset; if `c.signers` includes a member of
      `setB(h, view)`, raise the stage to ≥ 1; `try_commit()`.

   When this step runs on the `high_pqc` of a TC (§6.7, TC handler rule 3), only 2a and 2c apply:
   the TC's own view change follows at once, and `q` members have timed out of
   `tc.view ≥ c.view`, so no CommitQC can form at `c.view`.

`try_commit()`: if in `(h, view)`, `signer` is set, `timeout_view < view`, `mine.commit` is
`None`, `high_pqc.view == view`, and (`me ∈ setA` or `stage ≥ 1`), with `Q = high_pqc`:
```text
persist()                                                   // writes lock = Q (SR25)
vote = sign(Commit, h, view, Q.bh, Q.R); mine.commit = vote
route(vote); pool_insert(vote); t_lastvote = now
```
A Commit vote does not require local execution of the block or its header. The verified
PrepareQC supplies the certified block hash and result. There is no separate "commit"
entry in the record: a Commit at `(h, v)` is always for the lock of view `v` (unique per view by
Lemma 1 and never replaced within a view, §6.5 2a), and that lock is durable before the vote
leaves (SR25). After a restart, `try_commit()` may sign it again; the preimage and, with
deterministic signatures, the bytes are identical.

### 6.6 Timing out (local timer, early timeout, join)

`sign_timeout(w)` with `w ≥ view`, `signer` set, and (`timeout_view` is `None` or `< w`); no-op
otherwise:
```text
if w > view: advance_to(w)                // enter w directly in timed-out state
timeout_view = Some(w)
safety.timeout = Some((w, high_pqc.clone())); persist()    // the exact carried PrepareQC is recorded
t = sign TimeoutVote(h, w, high_pqc); mine.timeout = t
Broadcast(t) to C_h \ {me}; timeout_insert(t)
```
No timeout, whatever its caller, changes the start level: §9.2 raises it only for a slow
execution or a slow *committing* view, never for a view that failed.
`mine.timeout` is the only timeout for `w` this node ever sends: every re-send, the node's own
entry in a TC it forms, and the restart path (§7.4 R4, which rebuilds it from the recorded view and
carried PrepareQC) use exactly it. It is never rebuilt from the current `high_pqc`, which may have
risen since.

Callers:
1. **Early timeout** — the current view's leader is proven faulty or its block is invalid: a
   signed defect in the current view's proposal (§6.2 step 7), proven equivocation of
   `L(h, view)` (§6.2 step 2: two different proposals for `(h, view)`, both validly signed by it),
   or `Invalid` for the proposal's uncertified body (§6.3) → `sign_timeout(view)`.
2. **View deadline** `t_view(h, view)` fires and no CommitQC for `h` is known →
   `sign_timeout(view)`.
3. **Join** (§6.7, `timeout_insert`) → `sign_timeout(w*)`.

After `sign_timeout(w)` the node stays in view `w` (voting closed) until a TC for `(h, ≥ w)`, a
PrepareQC for a view `> w`, a CommitQC for `h`, or a join to a higher view. No further view
deadline fires for `w`; the timeout is re-sent at every rebroadcast.

### 6.7 On `TimeoutVote t` and on `TimeoutCert tc`

On `t` (height `h`, from the wire):
1. Apply §6.1 rule 5. `t.signer < n`; `t.high_pqc` (if any) is a valid PrepareQC for `(I, h)`
   with view `≤ t.view`; `t.sig` verifies over `tmo_preimage(h, t.view, t.high_pqc.map(view))`.
   Failure → drop.
2. Let `old = timeouts[t.signer]`. If `old.view > t.view` → drop. If `old.view == t.view`: same
   `hq` → drop; different `hq` → `ReportEvidence(TimeoutEquivocation)` (deduplicated), drop.
3. If `t.high_pqc` is `Some(Q)`: run §6.5 on `Q` (lock update / round sync).
4. `timeout_insert(t)`.

`timeout_insert(t)` (also for the node's own timeout, §6.0):
- store `t` as `timeouts[t.signer]`;
- **TC formation** (`form_tc`). Let `S = {j : timeouts[j].view == t.view}`. If `|S| ≥ q` and no
  TC for `(h, t.view)` is held: form `tc` from the `q` members of `S` with the highest `hq` (ties:
  lower index), `high_pqc` = the PrepareQC of the maximal `hq`; run the TC handler below;
- **Join (f + 1 rule).** Let `w*` = the `(f+1)`-th largest value of `timeouts[j].view` over all
  `j` (undefined if fewer than `f+1` entries). If `w*` is defined, `w* ≥ view`, and
  (`timeout_view` is `None` or `< w*`): `sign_timeout(w*)`. At least one honest node has
  given up on `w*`, so joining can never be forced by `f` Byzantine nodes alone.

On `tc` (height `h`; from wire, from a proposal's `justify`, from `Status`, or formed locally):
1. Verify (§3.4) unless formed locally or cached. Failure → drop.
2. If `high_tc` is `None` or `tc.view > high_tc.view`: `high_tc = tc`.
3. If `tc.high_pqc = Some(Q)`: run §6.5 steps 2a and 2c on `Q` (lock and want only, §6.5).
4. If `tc.view ≥ view`: `advance_to(tc.view + 1)`; then, if `L(h, tc.view + 1) ≠ me` and `tc`
   did not arrive as that leader's own `justify`, `Send(Tc(tc))` to `L(h, tc.view+1)` (one unicast
   per node: the new leader gets its justification even if it missed timeout votes); if
   `L(h, tc.view+1) == me`, propose (§6.10).

### 6.8 On `CommitQC c` for the current height, commit, and height entry

1. Verify `c` under `C_h` (skip if formed locally or cached).
   1a. If `formed_locally` and `me == P(h, c.view)`: `Broadcast(Qc(c))` to the `recipients` of
   `(h, c.view)` (which include `C_{h+1} \ C_h` when known). This happens before step 5 changes
   `h`; O2 holds it until `P`'s own Commit record is durable.
2. `tip = {height: h, block_hash: c.block_hash, result: c.result, commit_qc: c,
   exec_ok: exec[c.block_hash] == Valid(c.result), exec_req, prev: (old tip.block_hash, old
   tip.result)}` where `exec_req = Some(req)` if
   `exec[c.block_hash] == Pending{req, ..}`, else `None`. `exec_ok` holds only while the entry
   exists, i.e. no `DiscardExecution` has dropped that execution since the driver reported it, so
   the driver still holds that post-state unless it evicted it on its own (then it recomputes,
   O4). A pending execution of the committed block is not lost: its answer is handled by §6.3
   step 0 and may set `exec_ok` later.
3. If `pending_apply` is empty and the body `blocks[c.block_hash]` is held:
   `CommitBlock{block, commit_qc: c}` (the driver applies its cached post-state of that block or
   executes it, and compares, §12.3 O3). Otherwise append `{h, c, parent_hash, parent_result}`
   (the previous tip's hash and result) to `pending_apply`, and if the body is not held create
   `want(bh, Apply)` with sources the signers of `c` and members whose `Status` reported `bh`;
   `CommitBlock` is emitted when every earlier entry has been emitted and the body is held
   (§6.9 rule 6). `CommitBlock` actions are thus emitted in strictly increasing height.
4. If `exec[c.block_hash]` is still `Pending{since}` (kept as `tip.exec_req`),
   `pm.last_exec_ms = max(pm.last_exec_ms, now − since)`; `discard_exec([c.block_hash])` (§6.2,
   which does the same for the other pending executions); pacemaker update (§9.2) with `c.view`
   and `d_c = now − t_body` if `c.view == view`, `proposal` is for `c.block_hash` and `t_body` is
   set (otherwise `d_c` is undefined).
5. **Enter `h+1`** if its configuration is known (iff `applied ≥ h − 1`, §10.2); otherwise set
   `awaiting = true`. While awaiting, the round state of the committed height `h` is frozen (no
   round timers, no signing at `h`); round messages for `h` are handled as for a committed height
   (§6.1 rule 3) and those for `h + 1` as in §6.1 rule 4, except that a proposal for `h + 1`
   cannot be verified yet and is dropped. `Status` (content: §3.5) goes out at the unsettled
   cadence; sync, fetch and `pending_apply` continue.
   Entering: `h += 1; view = 0; t_enter = now; t_prop = t_body = None; timeout_view = None;
   proposal = None; build = None; asked = false; stage = initial stage (§5.2 hint, from c);
   t_ready = t_pqc = t_lastvote = None; mine = empty; repropose = false;
   votes, timeouts, high_pqc, high_tc, exec, cert_cache, reported := empty; blocks and wants :=
   only those of pending_apply; signer = the configured (not retired) key in C_h that does not
   abstain at h and is not unanchored (§7.4); safety = SafetyRecord::fresh(key, h, parent_commit_qc = c)` (in
   memory; written by the next `persist()`) unless a restored record for `(key, h)` exists (§7.4
   R6). While a key is unanchored and `C_{tip.height+2}` is known, drop the `probe` entries whose
   key is not in it and re-check anchoring (§7.4 R2); while it is not known yet, keep them. Recompute topology, `anchor` and deadlines
   (§9), and if `me == L(h, 0)` schedule the proposal (§6.10).
   **Late entry.** `late_entry = true` if this entry did not come from a CommitQC that was formed
   locally, arrived as a `Qc` message, or arrived as a proposal's `parent_qc` — i.e. it came from
   `awaiting` (§6.13), from sync (§6.9 rule 3) or from a `Status` — and after a restart (§7.4);
   otherwise `false`. A late entrant without a proposal asks `L(h, view)` for it at the end of the
   `handle` call (or of `Core::new`) through `request_proposal` (§6.11); sync may enter and leave
   several heights in one call, and only the round the call ends in counts.

The consensus height advances on the CommitQC alone; applying (storage) runs behind it, at most
two heights (§10.2).

### 6.9 Catch-up (sync) and block-body fetch

1. **Trigger.** A `CommitQC` (direct, `Status.committed_qc`, or a proposal's `parent_qc`) for height
   `H > h` sets `sync.target = max(sync.target, H)` and remembers the sender as a source. If `C_H`
   is known the QC is verified first (`sync.target_verified`); otherwise the target is only a hint
   (only accepted from members of `C_h`), never makes the node unsettled (§6.11), and is dropped
   after two consecutive empty `SyncResponse`s from different sources.
2. **Request.** While `sync.target ≥ h`: keep exactly one
   `SyncRequest{from_height, max_count: sync_batch, max_bytes: sync_max_bytes}` outstanding, with
   `from_height = max(h, highest buffered height + 1)`, to one source, rotating to the next
   source on *every* request (sources: the senders of target CommitQCs and members whose `Status`
   shows a higher height); deadline `now + sync_retry`. Before a request, buffered entries above
   a gap in the heights from `h` on are dropped (they are fetched again), so `from_height`
   always continues the contiguous buffered prefix. If a deferred donor alternative fails
   authentication at the current missing-body height, retain the original verified carrier and
   refresh that height with this same one-outstanding requester and source rotation, even when
   the contiguous buffer is full. The verified original QC sustains the refresh target. Empty or
   invalid replies and timeouts do not clear refresh; a validated same-value donor refresh or
   actual height advance does. A request unanswered by its deadline counts
   as an empty response for rule 1. The next request is sent as soon as a
   response has been checked, so fetching the next batch overlaps applying the buffered one, but
   not while the buffer holds ≥ `sync_batch` entries.
3. **Response** `SyncResponse{blocks}` answering an unanswered `SyncRequest` of this node to that
   source (processed whenever it arrives, also after that request was retried elsewhere; its
   entries are self-verifying). Each request is answered by at most one response, which starts at
   that request's `from_height` (an empty response answers the source's latest request); other
   responses are dropped. Before it is checked, buffered entries above a gap in the heights from
   `h` on are dropped (rule 2). Entries below `h` are skipped; every
   other entry must satisfy `c.kind == Commit`, `c.height == manifest.header.height`,
   `block_hash(manifest.header) == c.block_hash`,
   mandatory structurally valid availability table, consecutive heights. The entry
   for the current `h` additionally needs `C_h` known, `verify_qc(c, C_h)`,
   `header.parent_hash == tip.block_hash`, `header.parent_result == tip.result` and the exact
   scheduled epoch. Without body custody the entry
   remains buffered, creates a want or merges its sync responders into the existing want,
   and starts source-bound acquisition. The merge preserves the original height/hash and
   retry state, deduplicates peers within the existing bound, and applies even when a restart
   left the want without fetch sources. Each buffered entry retains its exact requested responder,
   whose maximum key storage is reserved at initial buffer admission. A late carrier with the same complete
   manifest and certified value may refresh that responder only after its own CommitQC
   verifies under the authenticated height config; different valid exact-q signer subsets are
   allowed. The original carrier is retained. Before that config is known, retain at most one
   deferred donor/certificate alternative per entry. Initial admission reserves an architecture-independent
   record allowance, the maximum QC bitmap and both maximum responder keys against the same
   buffer bound, even when that slot is empty; legal donor refreshes therefore need no extra capacity.
   A newer unverified alternative
   may supersede it. Verify the retained alternative at that height; if it fails, discard only
   the alternative and refresh this current height as in rule2, while continuing acquisition
   from the valid original carrier. After the current-height checks above, the responder enters the want even
   when its peer list is full: replace the first nonmember of the wanted-height committee,
   preserving the `n+8` cap and every retained member. The latest verified responder is pinned
   in subsequent retries, and a donor change emits at most one immediate one-peer fetch without
   changing the retry cursor, attempt or deadline. Reprocessing the same donor adds no fetch.
   These rules address finite stale-source history; they do not assert resistance to unlimited
   authenticated relay churn. It cannot advance sync merely from the signature table.
   Once custody is held it runs §6.8 (commit, enter the next
   height), and buffered entries are processed in the same way in
   height order. Entries for heights `> h` are buffered (≤ `2·sync_batch`) until their turn. The
   first failing entry is dropped together with the rest of that response. A prefix shorter than
   requested is normal; an empty response counts as empty for rule 1.
4. **Serving** (service messages at any height; driver per-peer quotas apply). A
   `SyncRequest` emits bounded `ServeBlocks`. The reply carries consecutive
   `SyncEntry { manifest, commit_qc }`, total ≤ `max_bytes` unless one entry, or an empty
   response when absent. A `PayloadRequest { height, block_hash }` emits `ServePayload`.
   The driver independently resolves the historical source, restores exact original custody,
   and serves its original manifest and derived rows. It never substitutes raw full bodies.
5. **Wants** own fetch retries for the current proposal, recorded proposal, highest PrepareQC,
   TC-selected re-proposal and each body missing from `pending_apply`. At creation and each
   `fetch_retry`, emit `FetchPayload { source, peers }`, where `source` binds the independently
   selected instance, height, hash and complete authenticated height config. Select the next
   `min(2^(attempt+1), |sources|)` peers cyclically. If the latest verified sync responder is
   absent from that batch, replace its final peer with the responder: fanout and the cyclic
   cursor update are unchanged. The driver first starts or resumes a typed
   local read/restoration job. Actual absence permits `PayloadRequest`; temporary admission/I/O
   refusal retains the same read, and corruption is an error rather than absence. A source
   change cannot silently replace an in-flight owner.
6. **Custody completion.** `BodyAvailable { block }` is accepted only for an exact-height/hash
   outstanding want, with `block.source()` equal to the independently selected full source and
   `block.admitted_to(original_pool)`. A held body is never replaced. Core emits `StoreBody`,
   retains the immutable body and removes the want. It flushes `pending_apply` in order, checking
   parent hash/result against each committed entry before `CommitBlock`; mismatch halts as
   `SafetyRecordInconsistent`. Current-proposal custody resumes §6.2 step 9; retained certified
   custody resumes re-proposing. A worker's semantic `ManifestRejected` removes only the exact
   matching buffered sync carrier. Resource refusal must not emit that event.
7. While `sync.target > h + 1` the node still runs the round rules for `h`; nothing waits for sync
   to finish.

### 6.10 Work-driven proposing

A leader proposes only nonempty work. Eligibility still requires being `L(h, v)` with a signing
key, `timeout_view < v`, and no proposal recorded at `(h, v)`.

0. **Never regenerate.** After restart, re-send the exact recorded valid proposal and its
   attachments once the body is available. Never build a second proposal in that view.
1. **Build.** At view 0 request work at `t_propose = t_enter + pace`. At every later view, if the
   TC has no PrepareQC, request fresh work immediately. Each request has a new `req` and a
   `build_timeout`; only the matching outstanding answer can be used.
2. **No empty fallback.** An empty answer, missed build deadline or oversized payload never
   creates a block. Wait until `now + payload_retry_interval`, or until `PayloadReady{req}`
   announces new work, then request a new build. Remember readiness that arrives before its
   matching empty answer. At every view an eligible leader can wake immediately for work;
   consensus view timers remain independent of local queue contents. An idle chain retains
   its committed height while timeout certificates may advance views.
3. **Preserve certified work.** If a later-view TC carries `Q`, re-propose exactly `Q`'s valid
   nonempty block. Fetch a missing body from its signers; never replace certified work with a
   fresh payload or an empty block.
4. **Authenticate application control.** After retaining the first matching nonempty bounded
   payload, request `BuildControlWitness { req, context: { height, view, epoch, parent_hash,
   parent_result } }`. No absent, late or oversized payload starts this request. Retain that
   original payload while awaiting the explicit exact-source `ControlWitnessBuilt` response;
   even a no-demand response is explicit. Missing control never creates a block. A duplicate
   payload cannot replace retained work; a response for another request, epoch, view or parent
   is ignored. View timers continue while local resource retries use bounded backoff.
5. **Construct and send.** A fresh header binds the current height, view, committed parent,
   nonempty payload, exact control witness, proposer and skipped leaders. Core emits `AuthorPayload` with
   that template, the exact config and original funded payload. The worker completes canonical
   encoding and original signatures; Core accepts `PayloadAuthored` only for that request,
   header (apart from its computed availability digest), complete source and original pool.
   It then stores the body and signs the round proposal behind the existing durability barrier.
   A re-proposal keeps `Q`'s header unchanged. Store the body, persist the exact proposal record, sign and
   broadcast it under the existing persist-before-send barrier, then accept it locally.

The leader does not wait for its own execution or parent apply to request work. A builder that
must wait for apply supplies `PayloadReady` when work becomes includable. Retired heartbeat and
forced-empty-view chain parameters are not accepted.

### 6.11 Tick, retransmission, rebroadcast ("state, not custody") and Status

On `Tick`, fire every due deadline in this order: propose/build (§6.10), stage timers (§5.2), vote
retransmits, view `t_view` (§6.6), rebroadcast, Status, probe, sync retry, fetch retry, execution
retry.

- **Vote retransmit.** Votes are re-sent only by this schedule and by the one re-send at stage
  entry (§5.2). An own vote of the current round whose phase QC is not held (a PrepareQC of
  `view` for the Prepare, a CommitQC of `h` for the Commit) is re-sent via `route()` (to `P` at
  stages 0–1, broadcast at stage 2) at `t_vote + t_retx · (2^k − 1)`, `k = 1, 2, …`, spacing
  capped at `rebroadcast_interval`, where `t_vote` is the time of the vote's first send or of its
  stage-entry re-send, whichever is later.
- **Rebroadcast** (every `rebroadcast_interval`):
  First retry certificate formation from retained verified votes, selecting exactly
  `q = n − f` inputs under §6.4/§6.7 even if more votes arrived during a local refusal.
  Then retry unsent reserved signatures under their ordinary signing conditions, using only
  the identical reserved preimage. Keep a recorded proposal's retry obligation while its
  original body is unavailable; an earlier-view `mine.timeout` does not satisfy the current
  view's Timeout reservation. If these retries change the height or enter `awaiting`, stop
  this round's rebroadcast. Otherwise:
  1. Re-send `mine.timeout` by broadcast only if `timeout_view == Some(view)` and
     `mine.timeout.view == view`.
  2. Leader of `(h, view)` holding its proposal: re-send it (with its original availability table) once per member per
     view, to each member whose latest `Status` is for `(h, view)`, was received at least
     `rebroadcast_interval` after the proposal was first sent, and does not report
     `proposal_hash == bh`. Members that learn `bh` otherwise (PrepareQC, Status) pull the body
     through their wants.
- **Late-entrant re-push** (on receipt, not on `Tick`; exempt from the `Status` rate limit, below).
  A leader of `(h, view)` holding its proposal that receives, from a peer among its `recipients`
  (§6.0), a `Status` for `(h, view)` with `want_proposal` set and without `proposal_hash == bh`
  re-sends the proposal (with its original availability table) to that member at once — no interval gate — at most once
  per member per view (independently of rule 2 above). Only members that lack the proposal and
  entered late or hold evidence of it set the flag (proposal request, below), and the cap holds
  however many flagged `Status` messages arrive, so this cannot amplify: at most one extra proposal carrier
  copy per member per view.
- **Proposal request** (`request_proposal`, at the end of every `handle` call and of
  `Core::new`). If the node is not `awaiting`, `L(h, view) ≠ me`, no proposal for `(h, view)` is
  held, `asked` is false, and either (a) `late_entry` holds, or (b) the node holds evidence that a
  proposal of `(h, view)` exists — a verified vote of view `view` in its pools, a PrepareQC of
  `(h, view)`, or a peer's latest `Status` reporting a `proposal_hash` for `(h, view)` — then
  `Send(Status{want_proposal: true, ..})` to `L(h, view)` and `asked = true`. A late entrant thus
  asks in the call in which it entered (§6.8 step 5), and an on-time member whose copy of the
  proposal was lost asks once per view as soon as it sees such evidence (at the latest when the
  other members' stage-2 votes reach it, §5.2). `want_proposal` is set in every `Status` sent
  while (a) or (b) holds and no proposal for `(h, view)` is held.
- **Status.** `Broadcast(Status)` to `C_h ∪ C_{h+1}` (if known) every `rebroadcast_interval`
  while *unsettled* — timed out in the current view, `view > 0`, `awaiting`, a verified
  `sync.target > h`, `late_entry` with no proposal held for `(h, view)`, or stage 2 in the
  current round — and every `status_keepalive` otherwise. (At stage 2 the members that got a
  PrepareQC from a withholding proxy tail no longer re-send their Prepare, so the others learn
  the lock only from `Status`.)
- **Probe** (§7.4 R2; only while some key is unanchored). Every `rebroadcast_interval`,
  `Send(Status{probe: Some(nonce), ..})` to each member of `C_{tip.height+2}` other than itself
  (not sent while that configuration is unknown). While some key is unanchored, every `Status`
  the node sends — broadcast, reply, proposal request or probe — carries `probe: Some(nonce)`, so
  probe answering uses its own successful-Echo rate limit independently of ordinary Status intake.

On `Status s` from peer `p` (`p` is the authenticated sender, §1.4), in this order:
1. **Echo** (exempt from the rate limit). If `s.echo = Some(e)`, `e.nonce == nonce`, some key is
   unanchored, `C_{tip.height+2}` is known, `e.key` is a member of it and not one of this node's
   keys, and `probe` holds no entry for `e.key` at or below `s.height`: verify `e.sig` under
   `e.key` over `echo_preimage(nonce, s.height)` (§3.3); on success `probe[e.key] = s.height` and
   check anchoring (§7.4 R2). The reply is fresh (it echoes a nonce drawn at this `Init`) and the
   signature, not the channel, identifies the member, so a relayed copy counts for its signer.
   Proposal requests and probe requests below have their own bounded admission.
2. **Proposal request** (exempt from the rate limit). If `s.want_proposal`, `(s.height, s.view)
   == (h, view)` and this node leads `(h, view)`: apply the late-entrant re-push (capped at once
   per member per view).
   **Probe request** (independent of the general Status rate limit). If `s.probe = Some(x)`, the node
   has a configured key, and none of its keys (retired ones included) is unanchored or abstaining
   at the current height (R2, R6): `Send(p, our Status with echo: Some(Echo{nonce: x, key, sig}))`
   (at most one successful Echo per peer per `rebroadcast_interval`; a signing refusal consumes
   no allowance), where `key` is its signing key at `h`
   (`keys[signer]`), else its first configured key, and `sig = sign(echo_preimage(x, height))`
   over the `height` of that `Status` (across a key rotation a reply may name a key that is not
   in the prober's `C_{t'+2}`; it then does not count, and replies after the change height do).
3. **Rate limit.** The rest of a `Status` is processed for at most one `Status` per peer per
   `rebroadcast_interval / 2`; for any other `Status`, stop here — except that its
   `committed_qc` alone is still used (§6.8 for height `h`, §6.9 above it) if its height is
   `≥ h` and above every `committed_qc` height processed from that peer (at most two extra
   verifications per peer and height): the §6.1 rule-3 reply that carries the CommitQC a
   lagging voter lacks often follows the peer's periodic `Status` within the window.
4. Record `(p, s.height, s.view, s.proposal_hash)` in `peers`.
   Then, after §6.1 rule 5: `s.committed_qc` → §6.8 (height `h`), §6.9 (height `> h`), or §7.6
   only if its value differs from the committed one; `s.high_tc` → §6.7 if its view is
   `> high_tc.view`; `s.high_pqc` → §6.5 if its view is `> high_pqc.view`. If `s.height < h`,
   reply with our `Status` (rate-limited, §6.1). If `s.proposal_hash` is a wanted hash, add `p` as
   a source.

No message is ever tracked for delivery: a lost message is replaced by the next re-send of the
sender's current state, and memory holds only the current state.

### 6.12 Round synchronisation (`advance_to(w)`, `w > view`)

`view = w; t_enter = now; t_prop = t_body = None; proposal = None; build = None; late_entry = false; asked = false;
stage = initial stage (§5.2 hint); t_ready = t_pqc = t_lastvote = None; mine.prepare =
mine.commit = None; repropose = false;` (recorded votes are never re-sent once the view changed)
drop vote pools (and their `reported` keys) outside `{w−1, w, w+1}`; drop the proposal want;
`keep = [blocks of high_pqc and high_tc.high_pqc]`; `blocks :=` the bodies of `keep` and of
`pending_apply`; `discard_exec(keep)` (§6.2; the executor cancels the rest and prioritises the
next `Execute`; the current proposal's body and execution are dropped unless it is one of these,
and are fetched and requested again if that block is re-proposed; every body stays in the
driver's body store); recompute `anchor`, reschedule the stage timers and `t_view` with
`level(h, w)` (§9); if entered via `TC(w−1)` and `me == L(h, w)`, propose (§6.10). Triggers (any
valid certificate seen, from any message, including `Status` and a proposal's `justify`):
- TC for `(h, x)` with `x ≥ view` → `advance_to(x + 1)`;
- PrepareQC for `(h, x)` with `x > view` → `advance_to(x)` (the node may Commit-vote in `x`);
  not for a TC's `high_pqc`, whose TC moves the node past `x` at once (§6.5);
- CommitQC for `h` → §6.8;
- `f+1` timeouts at `≥ w*` → join (§6.7 `timeout_insert`) enters `w*` timed-out.
`view` never decreases within a height.

### 6.13 On `BlockApplied{height: a, block_hash, header, config}`

Require `a == applied + 1`, `header.height == a`, `block_hash(header) == block_hash`, and the
exact block this core committed at `a`: the current tip or its immediate predecessor. The
header must carry the installed context for `a`, within that context's inclusive bounds.
Validate the whole `AppliedConfig` before mutating `applied` or the configuration window:

- An ordinary height returns `Continuation { after_next }`. If `a+2` remains in the current
  epoch, its `Ready` config must retain the exact epoch authority and ordered committee; only
  chain parameters may change. If `a+2` crosses the boundary, the only output is
  `PendingBoundary { boundary_height: B, predecessor: current_epoch_id }`. It contains no
  provisional committee, seed or generation.
- Only `a == B == current_epoch.last_height` may return `Boundary { next, after_next }`.
  `next` starts at `B+1`, has epoch number incremented
  exactly once, a distinct complete context ID and valid bounds. Retaining an authority
  generation retains its ordered committee. `after_next` authorizes `B+2` under exactly that
  new epoch, with its independently lagged parameters. The existing `B+1` slot must be the
  exact pending boundary slot. No conflicting replacement or replay is accepted.

Any violation halts with `DriverAnomaly` without partial installation. On success set
`applied = a`, install the validated output atomically, retain the header window and prune old
configurations. If waiting on this boundary, only now enter `B+1`. Other ordinary heights retain
the existing two-height consensus/apply pipeline. Retry buffered sync entries and execution
whose certified parent is now applied. Probe replies from a preceding context cannot authorize
anchoring under the newly installed context.

---

## 7. Safety

### 7.1 Sign-once rules and the complete list of safety rules

Per instance `I`, height `h`, signing key:
- **S1 Proposal.** At most one proposal per `(h, v)` (`safety.proposal`); after a restart only
  the recorded one is re-sent.
- **S2 Prepare.** At most one Prepare per `(h, v)`; only in the current view `v`; only if
  `timeout_view < v`; only for a proposal of that view that passed §6.2 (TC rule included) with
  `Valid(R)` (and `R == Q.result` for a certified block).
- **S3 Commit.** At most one Commit value per `(h, v)`; only in the current view; only if
  `timeout_view < v`; only for `(bh, R)` of the lock, a valid PrepareQC of view `v`, which is
  durable in the record before the vote leaves (the lock is the record of the Commit).
- **S4 Timeout.** At most one timeout per `(h, v)`; only for `v > timeout_view`; it carries the
  signer's lock at signing time (`hq ≤ v`), and only that exact message is ever re-sent.
  **Timeout fence:** after signing a timeout for `w` the node never signs Prepare or Commit at any
  view `≤ w` (S2/S3 conditions).
- **S5 Monotonicity.** `view` never decreases within a height; heights never decrease; the lock
  never decreases within a height.

Every rule the agreement and validity arguments rely on, with the mutation (§13.4) that must be
killed by a named deterministic test:

| Rule | Statement | Where | Mutation |
|---|---|---|---|
| SR1 | ≤ 1 proposal per `(h,v)`; a restarted leader re-sends the recorded proposal or nothing | §6.10 | MS1 |
| SR2 | ≤ 1 Prepare per `(h,v)` (`safety.prepare` checked by `try_prepare`) | §6.3 | MS2 |
| SR3 | Prepare only for the held proposal of the current view | §4.3 | MS3 |
| SR4 | Timeout fence (no Prepare/Commit at a view ≤ `timeout_view`) | §4.3, §6.5 | MS4 |
| SR5 | Commit only on a PrepareQC of the current view (no stale-QC Commit) | §6.5 | MS5 |
| SR6 | ≤ 1 Commit value per `(h,v)`: derived from SR5, SR7 and SR25 (a Commit is signed only over the lock of the current view, which is unique per view and never replaced within it) | §6.5 | — (MS6 removed: equivalent mutant, Appendix C) |
| SR7 | Lock = highest-view PrepareQC, never decreasing within a height | §6.5, §7.2 | MS7 |
| SR8 | A timeout carries the lock held at signing time | §6.6 | MS8 |
| SR9 | ≤ 1 timeout per `(h,v)`; only the stored exact timeout is re-sent or used as own TC entry | §6.6 | MS9 |
| SR10 | Voter TC rule: a TC-justified proposal must be `TC.high_pqc`'s block, and `R == Q.result` | §6.2, §6.3 | MS10a, MS10b |
| SR11 | TC formation: `high_pqc` = PrepareQC of the maximal signed `hq` | §6.7 | MS11 |
| SR12 | TC verification recomputes the maximal `hq` and checks `high_pqc` against it | §3.4 | MS12 |
| SR13 | Quorum `q = n − f` everywhere | §1.2 | MS13 |
| SR14 | Every Prepare, Commit and Timeout certificate needs exactly `q` distinct, valid equal-vote signers | §3.4 | MS14, MS39, MS40, MS41 |
| SR15 | Certificates verified only under `C_{cert.height}` | §3.4 | MS15 |
| SR16 | Instance id in every preimage and header | §3.2–3.3 | MS16 |
| SR17 | Result bound in every vote preimage | §3.3 | MS17 |
| SR18 | Proposal signed by `L(h,v)` over `(h, v, bh, ad)` | §6.2 | MS18 |
| SR19 | Header linkage (`parent_hash`, `parent_result` == committed tip; `parent_qc` verified) | §6.2 | MS19 |
| SR20 | Every body intake verifies its independently selected source, actual received-row digests, payload hash and complete reconstructed/restored codeword before granting custody | §3.2 | MS20, MS20b–MS20e |
| SR21 | Commit only on a verified CommitQC, on every path (live, Status, `parent_qc`, sync, R5) | §6.8 | MS21 |
| SR22 | Sync entry checks (`block_hash == qc.block_hash`, parent link, consecutive heights) | §6.9 | MS22 |
| SR23 | Persist-before-send for signed messages | §7.4, O2 | MS23 |
| SR24 | O2 total barrier: no externally visible effect (own-signed certificates, `CommitBlock`, served blocks, evidence) before durability | O2 | MS24 |
| SR25 | The lock is written with every record, in particular with the Commit | §6.0 `persist()` | MS25 |
| SR26 | Timeout recorded with its exact carried PrepareQC; `timeout_view` restored | §6.6, R4 | MS26 |
| SR27 | Prepare recorded and restored | §6.3, R4 | MS27 |
| SR28 | (removed in revision 4: the record's `commit` field is gone; SR25 records the Commit through the lock) | — | — |
| SR29 | Proposal (view, bh, justify) recorded and restored | §6.10, R4 | MS29 |
| SR30 | The recorded lock is restored into `high_pqc` | R4 | MS30 |
| SR31 | A missing record makes the key abstain wherever it may have signed: unanchored until fresh probe replies signed by `2f + 1` member keys of `C_{t'+2}` other than its own report committed heights `≤ t'`, then abstaining at heights `≤ t' + 2`; a node with an unanchored or abstaining key answers no probe; only replies that echo the probe nonce under a valid echo signature (§3.3) count, for the key that signed them | R2 | MS31, MS31b, MS31c, MS31d, MS31e |
| SR32 | R5 verifies the recorded parent CommitQC; every `pending_apply` flush checks parent linkage; R6 abstains below the record's height | R5, §6.9, R6 | MS32a, MS32b, MS32c |
| SR33 | One record per (instance, key), never rolled back, copied or dropped (retired keys included), initial record only at the installation event, never over an existing record file, and "generated on this node" trusted only while the installation log's store id matches the record store's; the signing key is chosen by membership in `C_h`; restart composes all keys into one starting round | §7.4 | MS33a, MS33b, MS33c, MS33d |
| SR34 | Apply compares the resulting commitment (cached post-state or re-execution) with `commit_qc.result` | O3 | MS34 |
| SR35 | Evidence only from signed-content defects; early timeouts only from those, from proven equivocation of the view's leader (two different proposals for `(h, view)` both signed by it), or from `Invalid` of an uncertified `body_ok` block | §6.2, §6.3 | MS35 |
| SR36 | Execution mismatch on a certified block (or `Failed`) is a local fault, never an early timeout or `PayloadRejected` | §4.2 | MS36a, MS36b |
| SR37 | Safety monitor halts on a conflicting CommitQC for a committed height | §7.6 | MS37 |
| SR38 | Every vote is signature-verified before it is pooled; locally formed certificates are therefore valid without re-verification | §6.1, §6.4 | MS38 |
| SR43 | An original publication that cannot safely retry halts the local instance without new execution or signing; reversible refusal retains its original owner | §12.3 O3, §12.5 | MS42 |
| MS43 | `put_epoch` — omits scheduling epoch and complete context from all domains | `det_s43_every_signature_binds_epoch_and_complete_context` | — | O-SIGN |
| MS44 | `applied_config_updates` — accepts an early next-epoch lag-2 config | `det_s44_lag_two_cannot_install_next_epoch_early` | — | O-CERT |
| MS46 | header hash omits control bytes | `det_s46_control_witness_is_bound_by_header_hash_and_proposal_signature` | — | O-SIGN |
| MS47 | real work invents an absent authenticated control response | `det_s47_nonempty_work_waits_for_independent_control_and_preserves_original_payload` | — | O-LIVE |
| MS48 | control completion accepts another exact source | `det_s48_control_response_requires_exact_request_epoch_view_and_parent_source` | — | O-SIGN |
| SR44 | All signatures and certificate/header hashes bind the installed scheduling epoch and complete context | §3.3, §10 | MS43 |
| SR45 | Authority activation is atomic only after its certified predecessor boundary is applied | §6.13, §10 | MS44 |

### 7.2 Lock

`high_pqc` is the highest-view PrepareQC seen at the current height (from votes, QCs, TCs,
timeouts, proposals, Status). It is carried in every timeout vote, written with every safety
record, restored on restart, and reset only when the height changes. It is *not* a voting filter.

### 7.3 TC rule (Jolteon / HotStuff-2 style) and why there is no voter-side lock check

- A proposal at view `v > 0` MUST carry a valid TC for `(h, v−1)`. If `TC.high_pqc = Some(Q)`, the
  proposal MUST be `Q`'s block and voters bind `Q.result`; if `None`, any fresh valid block.
- `TC.high_pqc` is the PrepareQC with the maximum `hq` over the TC's *signed* entries. Verifiers
  recompute the maximum from the signed `hq` values (§3.4); an aggregator cannot attach a lower
  PrepareQC than its signers declared, and a signer cannot inflate `hq` because the individual
  timeout vote must carry a valid PrepareQC of that view to be aggregated.
- A TC formed from any `q` timeouts is valid; honest aggregators prefer entries with the highest
  `hq` (§6.7), but safety does not depend on that.
- The `justify` TC and the parent CommitQC are covered by the leader's signature (`ad`). Safety does
  not need this (both are self-verifying), but it makes every TC-rule violation attributable to the
  leader and denies relays any way to make an honest leader's proposal look defective.
- **No voter-side lock check.** Safety follows from the TC rule alone (§7.5). A lock check
  ("refuse unless the proposal matches my lock or the TC shows a higher QC") would make the vote
  depend on local state: when a Byzantine node or a race composes TCs from `q` timeouts that exclude
  the honest lock holders (legal: any `q` suffice), the lock holders refuse, the Byzantine withhold,
  and the view fails; this can repeat indefinitely before and after GST. That is precisely a local
  refusal reason (v2 needed "late TC upgrade" machinery for it). Sumeragi votes on the TC's
  verdict; the lock's job is to be *carried* into timeouts.

### 7.4 Persisted safety record, body durability, persist-before-send, restart

```rust
struct SafetyRecord {
    instance: Hash32,
    epoch: EpochId,                                  // authenticated scheduling context
    key: PublicKey,                                  // the consensus key this record belongs to
    height: u64,                                     // round height the record describes
    parent_commit_qc: Option<Qc>,                    // CommitQC of height − 1 (None at g + 1)
    proposal: Option<(u64, Hash32, Option<TimeoutCert>)>, // (view, bh, justify) of the last proposal reserved for signing
    prepare: Option<(u64, Hash32, Hash32)>,    // (view, bh, R) of the last Prepare reserved for signing
    prepare_signature: Option<Signature>,            // exact successful signature; None for an unsigned reservation
    timeout: Option<(u64, Option<Qc>)>,              // (view, exact PrepareQC carried) of the last timeout reserved for signing
    lock: Option<Qc>,                                // high_pqc at write time; also the record of every Commit (§6.5)
    high_tc: Option<TimeoutCert>,                    // high_tc at write time (the certificate that justified the view)
}
```
A current-only canonical Norito envelope binds the consensus signature-suite identity and the
certified-result contract identity together with this record; `H(envelope encoding)` checksums
both identities and all retained data. The driver keeps one file per `(instance, key)` and writes
it atomically (temp file, fsync, rename, fsync dir). An envelope of any other identity, a retired
layout, or a bad checksum is a local startup fault. Startup refuses the record without deleting,
refreshing, or reinterpreting it. Before installing any retained lock or certificate cache, it
verifies every retained and nested QC and TC under the authenticated committee for that
certificate's height and the current suite, including the parent CommitQC (required above
`g + 1`). A failed verification refuses the record in the same way. An ahead record remains
untrusted and abstaining until its height's authenticated configuration is available; this
also holds for R5 at a pending epoch boundary when the record retains a QC or TC at its own
height. If its only certificate is the parent CommitQC, R5 verifies that certificate under
the authenticated parent-height committee and recommits the boundary; boundary application
must authenticate the next epoch before any retained reservation is restored or signed. Size is
bounded by the envelope and certificate limits. Nothing else is persisted by the core; the block
bodies it relies on are written by the driver on `StoreBody`.
Votes, pools, pacemaker level and routing stage are re-derived or re-fetched.

`prepare_signature` is a mandatory current-layout field. `Some(signature)` requires a
matching `prepare` and must verify under the retained key over the exact instance, epoch,
height, view, block hash and result. Restore checks this signature as well as the complete
certificate graph. A checksum alone is insufficient. `None` preserves the sign-once
reservation but proves no successful signature; a restart must reacquire ordinary execution
admission before first signing. Successful Prepare bytes are persisted through the same
safety barrier before they enter a vote pool or transport. They are reused exactly on retry,
rebroadcast and restart. There is no alternate signature journal or retired-layout decoder.

**Body durability.** Every body the core accepts is handed to `StoreBody`, and a `PersistSafety`
is durable only after every earlier `StoreBody` (§12.3 O2). Hence the body of every block this node
proposed or Prepare-voted is durable before that signature leaves the node. The driver keeps stored
bodies of height `x` until `x` is applied (the committed body then lives in the block store).
Consequence (liveness): the block of every PrepareQC is durably held by ≥ `q − f ≥ f + 1` honest
members until its height is applied, and every committed block is held by them until its height is
durably in their block stores. Bodies must not be deleted merely because a newer Prepare
replaced an earlier local record: an older valid PrepareQC may still arrive and require that
body. The production store has a finite 1 GiB cap and fails closed on exhaustion. An unbounded
sequence of uncommitted views can exhaust it; safe earlier reclamation requires an additional
availability proof and is not implemented. This limitation never authorizes an empty block.

**Persist-before-send (O2).** No externally visible effect of anything a node does after a
`PersistSafety` may exist outside the node until that record is durable: no message, no
certificate containing its signature (including one it formed itself), no block written to the
block store and served from there, no evidence. A crash before durability therefore takes every
such effect with it. Invariant (oracle O-PBS): whenever a signed message, or any object containing
this node's signature, leaves a node, the node's *durable* record covers each such signature — for
a proposal, Prepare or timeout: the same height and entry, a later entry of the same kind at a
higher view, or a higher height; for a Commit at `(h, v)`: a record at `h` whose lock has view
`≥ v`, or a higher height. Probe echo signatures (§3.3) are exempt: they carry no sign-once
obligation and are never recorded.

**Record provenance (normative for the driver and operators).** R3–R6 below trust a `Present`
record to describe the key's latest signatures for `I`. Therefore:
1. A record file is written only by `PersistSafety` and by the installation event below. It MUST
   NOT be restored from a backup, copied to another disk or node, or moved together with a key;
   backups MUST exclude record files. (A rolled-back record would let R3/R4 sign again below the
   key's real history; like a second Byzantine node, this is outside the model, §1.3.)
2. **Installation event.** The driver keeps, outside the record files (e.g. in the node's key
   store), a durable *installation log*: one entry per key stating whether the key was generated
   on this node or imported (from a KMS, a backup or another node), and one entry per
   `(instance, key)` ever started on this node. When the node starts instance `I` with key `K` and
   the log has no `(I, K)` entry, the driver — only if `K` counts as generated on this node
   (rule 3), or the operator asserts that `K` has never signed for `I` (e.g. at `I`'s genesis) —
   first writes and syncs the initial record `{instance: I, key: K, height: g, everything else
   None}`, unless a record file for `(I, K)` already exists (the installation event never replaces
   a record file: a rolled-back log can lack the entry of a record in use); then it writes and
   syncs the `(I, K)` entry; only then does it start the core. A key generated on this node and
   never exported cannot have signed for `I` anywhere else, so a dataspace or lane created after
   the key was installed gets its initial record automatically.
3. **Store id.** "Generated on this node" is bound to the record store. Every log entry is written
   with a freshly drawn random 128-bit *store id*: the driver writes and syncs the id in a file
   next to the record files (part of the record store: never backed up or restored, like the
   records), then writes and syncs the entry carrying the same id. At start, before any
   installation event, the driver compares the id next to the record files with the id in the
   log's newest entry. If they differ, or one of them is missing while the log has entries, the
   log does not describe these record files (the key store was restored from a backup older than
   some installation event, e.g. older than a dataspace instance, or the record store is new or
   was replaced): before anything else the driver durably marks every key in the log as imported
   (with a fresh id, like every entry). The marks are one event: the driver appends all of them
   with one fresh id and only then writes and syncs that id next to the record files, so a crash
   before the id is written leaves the mismatch for the next start, which marks again (E53).
   Every key is then treated as imported, so no initial record
   is written without an operator assertion and every missing record is `Absent`. (A crash
   between the two writes of an entry also shows a mismatch; that is safe and only costs operator
   assertions for instances created later.)
4. Once the `(I, K)` entry exists, a missing record file is `Absent`; the driver never re-creates
   it. Without an initial record the core also sees `Absent`. Reinstalling a key (new disk, lost
   key store, import from a KMS) or restoring the key store from a backup therefore yields
   `Absent` for every missing record unless the operator asserts, per instance, that the key has
   never signed there.

**Restart.** `Init` carries, for every configured or retired key (**Keys** below),
`RecordState = Present(bytes) | Absent`,
plus the block-store tip `t` (header, result, CommitQC), the configurations of `t` (needed to
verify proposals' `parent_qc` and the stage hint at `t + 1`; omitted when `t = g`), `t+1` and
`t+2`, the last `W + 2` committed headers, `demotion_window` and `nonce` (a fresh random 64-bit
value drawn by the driver for every `Init`; the simulator draws it from its seeded PRNG).
`restore` composes all keys into one starting round:
1. **R1** For every key: `Present` but envelope identity/checksum/decode fails, or `instance`/`key` mismatch →
   `Halt(SafetyRecordCorrupt)`.
2. **R5** If some `Present` record has `height == t + 2` (the block store lost the last commit: a
   crash after entering `t+2`, before the apply of `t+1` was durable): first verify every
   retained/nested round certificate under authenticated `C_{t+2}` and then its
   `parent_commit_qc` under `C_{t+1}` as a CommitQC for `t + 1`; failure →
   `Halt(SafetyRecordInconsistent)`. If `C_{t+2}` is still pending and the record contains a
   round QC or TC, retain the record inert as R6 until ordinary catch-up authenticates it.
   If the only certificate is its parent CommitQC, no round-certificate check needs `C_{t+2}`:
   verify and recommit the parent, then authenticate `C_{t+2}` through boundary application
   before restoring the reservations. On success commit it (§6.8 steps 2–3: `tip` becomes `t + 1`;
   the `pending_apply` entry carries the old tip's hash and result as parent, and its want looks in
   the local body store first; that the block extends the old tip is checked when the body
   arrives, §6.9 rule 6), and continue with `t := t + 1`. At most one key has a record at any
   height (two configured keys in one `C_h` sign with neither, **Keys** below).
3. Every key is then classified against `t`:
   - **R2** `Absent` → the key is *unanchored* (below).
   - **R3** `record.height ≤ t` → nothing to restore: those heights are committed and never
     signed again.
   - **R4** `record.height == t + 1` → this record restores the round (step 4).
   - **R6** `record.height ≥ t + 2` (the block store lost its tail) → the key abstains at heights
     `< record.height` (`abstain_below = record.height`), `LocalFault(StoreBehindRecord)`; the
     node syncs, and on reaching `record.height` the round is restored from this record as in R4
     (§6.8 step 5).
4. **Round.** The node starts in round `t + 1` (a late entry, §6.8 step 5). If a key has an R4
   record whose `parent_commit_qc` is not a valid CommitQC of `t` for `(tip.block_hash,
   tip.result)` (or is present at `g + 1`, absent above it), the record contradicts the block
   store: `Halt(SafetyRecordInconsistent)` (its parent CommitQC would be the `parent_qc` of a
   re-sent proposal). Every other retained/nested certificate must also verify under its
   authenticated height committee before installing any round state. Otherwise restore from it: `proposal`, `prepare`, `timeout`, `lock`, `high_tc` into `safety`;
   `high_pqc = lock`; `high_tc = record.high_tc`; `timeout_view = timeout.view`; `mine.timeout` =
   the timeout rebuilt from the recorded `(view, carried QC)` (re-signing an identical preimage
   gives identical bytes, §12.1); `view` = the maximum of `proposal.view`, `prepare.view`,
   `timeout.view`, `lock.view` and `high_tc.view + 1` over the entries present (0 if none; the
   views of `parent_commit_qc` and of certificates nested inside entries are not used); timers
   start at `now`. The recorded timeout is re-sent at the first rebroadcast. A recorded Prepare
   of the current view is re-sent on the retransmit schedule with `t_vote = now` only when
   its stored `prepare_signature` verified; the exact bytes are reused. An unsigned reservation
   requests the original body and retains its sign-once constraint, but cannot synthesize a
   first signature on restore. `try_commit()` is called
   (it re-signs the identical Commit if the lock is of the current view); a recorded proposal is
   re-sent only as recorded (§6.10 rule 0). If `me == L(h, view)`, no proposal is recorded at
   `view` and `timeout_view < view`: at `view > 0` with `high_tc` = TC(`view − 1`) propose as
   §6.10 rule 2 with it; at `view = 0` schedule the proposal as §6.10 rule 1. Without an R4
   record the round starts fresh at `t + 1`.

**R2 (lost record).** An unanchored key signs nothing; `LocalFault(RecordMissing)`. The node
probes (§6.11): every `rebroadcast_interval` it sends `Status{probe: Some(nonce)}` to the members
of `C_{tip.height+2}` other than itself, and every other `Status` it sends carries the probe too.
It keeps, per member key of `C_{tip.height+2}`, the lowest `height` reported in a *fresh* reply —
a `Status` whose `echo` carries this node's `nonce` and a valid signature of that key over
`echo_preimage(nonce, height)` (§3.3). The signature, not the channel, identifies the member and
binds the reported height, so relayed replies count and a relay can neither forge nor alter one.
A node answers probes only while none of its keys (retired ones included) is unanchored or
abstaining at its current height. Let `t' = tip.height` (the node's committed height; its round
is `t' + 1`). On every fresh reply, every height entry and every `BlockApplied` that makes
`C_{t'+2}` known (at a height entry it usually is not known yet, and later replies report
higher heights, which never lower an entry) the node checks: if `C_{t'+2}` is known
and fresh replies signed by `2f + 1` distinct member keys of `C_{t'+2}` other than the node's own
keys (`f` of `C_{t'+2}`) each report `height ≤ t' + 1` (a committed height `H_m ≤ t'`), the key becomes
*anchored*: it abstains at every height `≤ max(t', H) + 2 = t' + 2` (`H` = the highest reported
committed height; `abstain_below = t' + 3`) and signs normally, with a fresh record, from
`t' + 3`. Lemma 0 (§7.5) proves that no signature the key made before the loss is at a height
above `t' + 2`, whatever else was lost (the block-store tail included) and however the committee
changed. The threshold is `2f + 1`, not `q`: it is the smallest count that meets the honest
signers of every CommitQC of `C_{t'+2}` (Lemma 0), and with the node that lost its record counted
as one of the `f` faults, `n − f = q ≥ 2f + 1` honest other members can answer. Reported heights
need no verification beyond the echo signature: only an honest reply can make the check fail, and
a Byzantine member can at most count as one of the `2f + 1`. The probe waits until the node has
caught up with `2f + 1` members of the next height's committee; until then the node is an
observer, and for liveness it counts as faulty until it anchors (§1, §8.1). With `n = 1` there is
no other member, so a lost record can never be anchored (re-signing without the record could
commit two blocks at one height); with `n ∈ {2, 3}` (`f = 0`) one fresh reply anchors, because
every certificate contains every member.

**Keys.** The core signs at `h` with the unique configured key that is in `C_h`, is anchored and
does not abstain at `h`; if two configured keys are in `C_h` it signs with neither
(`LocalFault(KeyConflict)`). The application MUST NOT schedule a committee that contains two keys
of one validator: a key rotation replaces the old key by the new one at a single height (§10.3)
(a two-step, make-before-break rotation would make that node sign with neither key while both
are members). A key that is no longer configured for signing but has an installation-log entry
for `I` is *retired*: the driver keeps its record and still passes it in `Init`, and `restore`
treats it like any other key (R1–R6, probing and the probe-answer rule) except that it never
signs. The driver never drops a retired key's record or its log entries: with the `(I, K)` entry
in the log, a dropped record would be `Absent` at every later restart (rule 4 above), leaving the
key unanchored and the node answering no probe (§6.11) until it anchors again; nodes restarting
together in that state could not anchor one another. Size bound: the record store holds one
record (≤ ~3 KB at n = 31) per `(instance, key)` ever installed on the node, i.e. per instance
≤ ~3 KB × (1 + number of key rotations), and `Init.records` and `keys` have one entry per such
key. Key rotation therefore needs no special handling: configure both keys across the change
height.

### 7.5 Agreement proof sketch

*Lemma 0 (anchoring after a lost record).* Let key `K` of node `X` lose its record, let `h_r` be
the highest height at which `K` signed before the loss, and let `K` be anchored with committed
height `t'` (R2). Then `h_r ≤ t' + 2`, so abstaining at every height `≤ t' + 2` covers every
height at which `K` may have signed.
*Proof.* Suppose `h_r ≥ t' + 3`. `X` was in round `h_r`, which it can enter only after committing
every lower height through a valid CommitQC, so a valid CommitQC `c` for height `t' + 2` existed
before the loss. Let `S` be its honest signers other than `X`: `|S| ≥ q − f − 1` (`n`, `f`, `q` of
`C_{t'+2}`). The anchoring replies are signed by a set `Q` of `2f + 1` member keys of `C_{t'+2}`
other than `X`'s, so `|Q ∩ S| ≥ (2f + 1) + (q − f − 1) − (n − 1) = q + f − n + 1 = 1` (`q = n − f`;
`2f + 1` is the smallest size for which this holds for every `n`). Take `y ∈ Q ∩ S`. `y` signed
its Commit at `t' + 2` in round `t' + 2`, before the loss, hence before `X`'s probe. Its reply's
echo is signed by `y` over `X`'s nonce, drawn at `X`'s `Init`, and over the reported height
(EUF-CMA: no relay or other node can produce or alter it), so `y`'s node signed it after that
Commit, reporting its own height. When it answered, `y`'s node had no unanchored or abstaining
key, retired keys included (§6.11, §7.4 Keys), so its current round
was `≥ t' + 2`: without a restart since its Commit, its round never decreased; after a restart
with its record present (never rolled back, record provenance), R3–R5 resume at a round `≥` the
record's height `≥ t' + 2`, and under R6 it does not answer below that height; after a restart
with its record lost, it answers only once anchored and past its abstention, at a round
`> t'_y + 2 ≥ t' + 2` by this lemma applied to `y`'s own earlier anchoring (its Commit at
`t' + 2` preceded its loss; induction on the time of anchoring). So `y`'s signed echo reported
`height ≥ t' + 2`, contradicting the anchoring condition `height ≤ t' + 1` for every member of
`Q`. ∎ The lemma needs no assumption about `X`'s block store (it may have lost any tail), about
committee changes (only `C_{t'+2}` is used, and it is the committee of `c`), or about the channel
a reply arrived on (the echo is signed).

*Lemma 1 (one value per view).* Two valid PrepareQCs (or two CommitQCs) of the same `(I, h, v)`
certify the same `(bh, R)`: they share ≥ `2q − n = n − 2f ≥ f + 1` signers, one of them honest,
and S2/S3 allow one value per kind per view.

*Lemma 2 (committers carry the lock).* Let `c` be a CommitQC for `(B, R)` at `(h, v)` that exists
anywhere other than in the volatile memory of a node that then crashes (by O2 this covers every
CommitQC an honest node can commit on, relay or serve). Let `S` be its honest signers,
`|S| ≥ q − f`. Each `s ∈ S` held a PrepareQC of view `v` as lock when it signed Commit (S3), and
its record containing that lock was durable before its vote, or any certificate containing it,
left `s` (persist-before-send, SR25; O2's total barrier when `s` formed `c` itself). The record is
never rolled back (record provenance) and is restored on restart (R4–R6), and a lost record keeps
`s` from signing at `h` again (R2, Lemma 0: `h ≤ h_r ≤ t' + 2`), so `s` never signs at `h` with a
lower lock. By the timeout fence, `s` signed no timeout for a view `≥ v`
before that Commit. Since the lock never decreases, every timeout `s` signs at `h` for a view `≥ v`
carries `hq ≥ v`.

*Lemma 3 (TCs see committers).* A valid TC for `(h, x)`, `x ≥ v`, has ≥ `q` signers of timeouts for
view `x`; `|TC ∩ S| ≥ q + (q − f) − n = n − 3f ≥ 1`. By Lemma 2 its maximal `hq` is `≥ v`, and
`≤ x` by validity, so `TC.high_pqc` has view in `[v, x]`.

*Theorem.* If a CommitQC for `(B, R)` exists at `(h, v)` (in the sense of Lemma 2), every valid
PrepareQC at `(h, v')`, `v' ≥ v`, certifies `(B, R)`. Induction on `v'`. `v' = v`: the CommitQC has
an honest signer holding a PrepareQC of `v` for `(B, R)` (S3); Lemma 1. `v' > v`: the PrepareQC has
≥ `q − f ≥ 1` honest signer, who accepted a proposal for `(h, v')` justified by a valid TC for
`(h, v'−1)` and applied the TC rule. By Lemma 3 that TC's `high_pqc` has view in `[v, v'−1]` and by
induction certifies `(B, R)`; so the proposal is `B` and the honest signer bound `R` (it votes only
if its own result equals `Q.result`). Lemma 1 gives the whole PrepareQC.

*Corollary (agreement).* Take CommitQCs at `(h, v)` and `(h, v')`, `v ≤ v'`. The one at `v'` has an
honest signer holding a PrepareQC of `v'`, which by the theorem certifies `(B, R)`; S3 binds that
value. Honest nodes commit only on a valid CommitQC (SR21), so all commit `(B, R)`. Chain agreement
follows by induction on height: each header binds `parent_hash` and `parent_result`, `C_h` is a
function of the agreed prefix (§10), and certificates are verified only against `C_h`.

*Views and late certificates.* The argument does not depend on arrival order: a CommitQC of an
old view that surfaces after later TCs is still consistent with everything certified later.
*Timeouts are always safe.* Nothing above uses why or when a node signs a timeout, only S4 (one
per view, carrying the lock, then the fence) and lock durability, so any trigger of
`sign_timeout` — the deadline, a join, or an early timeout on a signed defect, an `Invalid`
block or proven leader equivocation (§6.6) — preserves agreement; a Prepare already signed in
that view stays as it is, and the fence forbids a Commit after it. Early timeouts can only cost
liveness, and only in views whose leader is faulty or whose block is deterministically invalid:
`ProposalEquivocation` consists of two different preimages of `(h, v)` both signed by `L(h, v)`,
which an honest leader never produces (S1: at most one proposal per view, re-sent byte-identical
after a restart), no one else can forge (EUF-CMA), and a relay cannot create by changing unsigned
bytes (the payload is bound through the signed header, so `(bh, ad)` does not change, §3.3).
*Restarts.* The proof uses only S1–S5 and lock durability; R4–R6 restore exactly what was durable
(a `Present` record is the latest one, record provenance), R2 (Lemma 0) and R6 make a key abstain
wherever its record cannot prove what it signed, and O2 guarantees no signature exists outside a
node without its record (a crash before durability only loses messages). R3 is safe because a node
never signs at a height `≤ t` again. Restart composition gives one starting round: R5 commits
`t + 1` before any key is classified, and at most one key has a record at a height, so the round
state comes from a single record and the tip never moves backwards. *Instances.* `I` is in
every preimage and header, so a vote, QC or TC of one instance never verifies in another, even with
identical committees.
*Validity.* A PrepareQC has ≥ `f + 1` honest signers, each of which executed a `body_ok` body of
`B` on the agreed parent state and obtained `R`; `bh` fixes the payload bytes (§3.2), so with
deterministic execution `R = exec(S_{h−1}, B)`. Apply re-checks it (O3, SR34).

### 7.6 Safety monitor

- A valid CommitQC for a committed height `x ∈ {tip.height − 1, tip.height}` whose configuration
  is retained (after a restart `C_{t−1}` is not, so only `tip.height` until the next commit) with
  `(bh, R)` different from the committed value (the core keeps the committed `(bh, R)` of both
  heights) →
  `ReportEvidence(ConflictingCertificates)` and `Halt(SafetyViolation)`: agreement is broken, so
  more than `f` members of `C_x` are faulty. Values are compared first; a signature check happens
  only on a mismatch, and verifies the exact authenticated Commit quorum:
  `q` Commit signatures on another value prove the violation. CommitQCs for older heights
  are dropped (§10.7).
- Nothing else is monitored. Conflicting certificates of the current, uncommitted height are
  never even verified (a second PrepareQC of a view already locked is cheap-rejected, §6.1 rule
  5); forensics for them are the application's (§14.6).


---
## 8. Liveness

### 8.1 Assumptions after GST

Transaction progress requires valid work available to an eligible honest leader and durable
body storage with room to preserve each prepared proposal (§7.4). An idle chain, a permanently
invalid workload, or exhausted durable storage has no height-progress guarantee. Sparse local
queues may require multiple leader turns; the continuous-load per-gap bounds below do not
apply while the current leader has no work.

At least `q_h` members of `C_h` are honest and running, where a member with an unanchored key
(§7.4 R2) counts as faulty until it anchors, a member whose key abstains at `h` (R2, R6)
counts as faulty at `h`; honest-to-honest delay `≤ Δ` for every
required proposal/manifest and sufficient authenticated rows to reconstruct a bounded payload,
including the complete sequential egress to the destination peers (the driver's traffic classes, §12.3 O8, keep control traffic independent of bulk
load); local signing/verification/persist per message `≤ δ`; parent apply `≤ A_max`; execution
`≤ E_max`; the driver delivers `Tick` within `δ` of `next_wakeup()` ahead of every other event
(O5); `σ = rebroadcast_interval + Δ`; `F = ⌈log2(f+1)⌉ · fetch_retry` (body fetch, §6.9 rule 5).
`Δ` is unknown to the nodes, but view timers stop growing at `T_max_eff` (§9.1), so liveness
needs the post-GST `Δ` (and `A_max`, `E_max`) to satisfy `T_req ≤ T_max_eff` (§8.2 L3); the
simulator's post-heal delays respect this, and §9.4 validates the nominal case.

### 8.2 Argument

- **L1 View synchronisation (including restarts).** Let `w` be the highest view at `h` that an
  honest node is in (in memory, or durably after a restart). Consider the first honest node to
  reach `w`. It did not get there by joining: a join needs a timeout at `≥ w` from an honest node,
  which would have reached `w` earlier. So it entered via `TC(w−1)` or a PrepareQC of view `≥ w`.
  If it has signed anything in `w`, that certificate is in its durable record (`persist()` writes
  `high_tc` and the lock every time) and is restored on restart. If it has not, a restart takes it
  back to a lower view and it no longer holds `w`. The node is unsettled (`view > 0`), so its
  `Status` carries the certificate every `rebroadcast_interval`, and every honest node reaches a
  view `≥ w` within `σ`. Joins spread through broadcast and re-sent timeouts.
- **L2 Failed views end.** If honest nodes are in `w` and no CommitQC forms, each times out by
  `t_view`, the `≥ q` honest timeouts are broadcast (and re-sent), and every honest node forms or
  receives `TC(w)` within `Δ` (after GST) of the last honest timeout; the `f+1` join pulls
  laggards out of `w` within `Δ` of the `(f+1)`-th honest timeout. A view whose leader is proven
  faulty ends earlier: every honest node that holds both of its twin proposals, or a signed
  defect, times out at once (§6.6 caller 1); once `f + 1` honest nodes have, every honest node
  joins within `Δ` and forms or receives `TC(w)` within `Δ` more; otherwise the view ends by
  `t_view` as above. An early timeout never delays a good view: the
  proof needs a faulty leader (§7.5).
- **L3 Timers become long enough.** `level(h, v) = min(level_cap, start(h) + v)` grows by one per
  failed view, so after at most `k* = min{L : T(L) ≥ T_req}` failed views
  `T ≥ T_req = 2·(σ + build_timeout + 3Δ + F + A_max + E_max) + 4δ` (the `3Δ + F` covers a body
  fetch for a re-proposal). Config validation (§9.4) enforces `T_max ≥ T_req(nominal)` with this
  exact formula, and the effective `T_max` is never below it. This growth within a height is
  independent of the start level: `start(h) ≥ 0` only shortens the path to `k*`, so liveness does
  not depend on the §9.2 adaptation (which only prices failed views at later heights; payload
  progress under executions longer than the payload views' timers does, §9.2).
- **L4 A good view commits.** Consider a view `w` whose leader is honest, entered by all honest
  within `σ`, with `T(level) ≥ T_req` and valid work available. The leader builds at TC entry
  or at `pace` (view 0), then proposes the nonempty result. A fresh honest block is valid. A re-proposed block has a PrepareQC, so ≥ 1 honest node
  computed `Valid(Q.result)` and, by determinism, all honest do; its body is durably held by
  ≥ `f + 1` honest members (§7.4), so the leader and the voters fetch it within `3Δ + F`. A node
  that enters `h` late (after apply, sync or a restart) gets the proposal from the leader within
  `2Δ` of entering, through its `want_proposal` Status (§6.11), which the leader acts on even
  when the rest of that `Status` is over its rate limit; a member whose copy was lost asks the
  same way as soon as it holds a vote, PrepareQC or `Status` showing the proposal exists, at the
  latest when stage-2 votes reach it. All honest nodes execute within
  `σ + build_timeout + 3Δ + F + A_max + E_max ≤ φ·T`. An honest member Commit-votes after
  receiving the PrepareQC and durably recording its lock, without waiting for execution. If every set-A
  member and `P` are honest, stage 0 forms both certificates within 4 hops. With faulty non-P
  set-A members (at most `f`, and set B supplies the missing votes), stage 1 does so within
  `t_retx` more, or with no delay when the hint started the round at stage 1. With a faulty `P`,
  stage 2 starts within `2·t_retx` of the members' votes (at the latest at `anchor + φ·T`), and
  broadcast voting forms
  the PrepareQC and CommitQC within `2Δ + 2δ ≤ (1−φ)·T`. No honest node times out first, so the
  CommitQC exists and reaches every honest node within `σ`.
- **L5 Honest leaders recur.** The leaders of any `f + 1` consecutive views of a height are
  `f + 1` consecutive entries of `nd_h`, hence distinct (§2.1, slot substitution rotates views
  over non-demoted members only), so one is correct.
- **L6 Committed bodies are obtainable.** A node that commits without the body fetches it with
  `PayloadRequest`, which any holder answers with the original manifest and actual rows at
  any height (§6.9); ≥ `f + 1` honest members hold it
  durably (§7.4). So `pending_apply` drains, `applied` advances, and the next configuration becomes
  known.

**Bound (used by O-LIVE).** After heal/GST at time `t_g`, every honest running node commits a new
height by `t_g + B_live` with
`B_view = T_max_eff + payload_retry_interval + 2·build_timeout + 2·rebroadcast_interval + 4Δ + F`
and
`B_live = (f + 2 + level_cap) · B_view + ⌈lag / sync_batch⌉ · (sync_retry + 2Δ + sync_batch · (E_max + A_max))`,
where `lag` is how many heights the node is behind (synced blocks have no cached post-state, so
the driver executes each before applying it). This bound is deliberately loose. It only catches
stalls; performance regressions are caught by the tighter bounds below.

**Performance bounds (used by O-PERF, §13.2).** Let `G_norm = X + E + 5Δ + 4δ`, where `X` is
`block_time` while transactions are pending and `payload_retry_interval + build_timeout` for an empty build retry; idle time is excluded from height-progress guarantees, and let
`t̂ = φ·T(level(h, 0))/2`, the upper end of the `t_retx` clamp (§9.1). The bounds use `t̂`, not the
measured `t_retx`, because a Byzantine proxy tail can inflate the measured value up to the clamp.
- **P1** All honest, loss ≤ 1 %: p99 of commit gaps ≤ `G_norm`, and every gap ≤
  `G_norm + 2·rebroadcast_interval + Δ` (a proposal copy lost to two members the quorum needs is
  recovered by their proposal request once they see evidence of it, at worst the stage-2 votes,
  or by the leader's re-push). This includes heights at which one member enters late (apply
  up to `A_max`, or just synced): its re-pushed proposal adds about `2Δ + E` for that member only.
- **P2** One member that withholds its votes (in either phase or both) but proposes and
  aggregates correctly, lossless links: every gap ≤ `G_norm + t̂`, and with `D` fixed at most one
  gap per `n` consecutive heights exceeds `G_norm` (its entry into set A when the hint is off;
  while it stays in set A the parent CommitQC needs set B, so the hint starts every round at
  stage 1, §5.2). It is never demoted, so this recurs indefinitely.
- **P3** Silent or withholding proxy tail: each gap ≤ `G_norm + 2·t̂ + Δ`. A given member
  causes such a gap only at its view-0 proxy-tail turns: at most `1 + |D_h|` heights per `n`
  consecutive heights (§2.1 fairness; demoted slots pass to successors).
- **P4** Crashed member: per `W` consecutive heights, at most one gap up to
  `P(0) + T(start) + G_norm`, plus `2·t̂ + Δ` when `a_h = q` (then the crashed member is view 1's
  proxy tail, §2.1) — its view-0 leader turn; it is demoted two heights later — plus one more
  such gap for every honest leader recorded in `skipped_leaders` inside the window (an honest
  skip, e.g. through a poison transaction, can displace it from `D_h` because `|D_h| ≤ f`); at most
  two P3 gaps (its proxy-tail turn before that, and, when `a_h = q`, the height right after it)
  and at most one P2 gap (its first set-A height with the hint off); every other gap meets P1. A
  failed view followed by a re-proposal does not record its leader (§5.2); scenarios that check
  P4 do not lock blocks without committing them.

Throughput consequences (revision 3, no absence demotion). Under load the pace (§9.1) makes the
cycle time `max(block_time, commit latency)`, so a gap above `block_time` costs throughput one for
one. A vote-withholding member costs at most one `t_retx` per `n` heights (P2) plus `2f` vote
messages at every hinted height; with `f` withholding members at `n = 22` the hint is on almost
always, set B votes at every height (105 instead of 91 messages, up to 21 instead of 14 vote
verifications per phase at `P`), and gaps meet P1. A crashed or withholding proxy tail costs
`2·t_retx + Δ` per turn (P3); at `n = 22` with the default `t_retx ≈ 750 ms` and one faulty member
that is ≈ 1.6 s extra once per 22 heights (≈ 6 % throughput loss at a 1 s block time); `f = 7`
Byzantine members that withhold as proxy tail but lead correctly (never demoted) cost it at
roughly one height in three (≈ 30 % throughput loss). Crashed members stop costing after their
first leader turn (demotion) until they are reinstated `W` heights later. Revision 2 also removed
silent members from set A after `f + 1` heights; revision 3 keeps paying P3 at their proxy-tail
turns in exchange for no absence records in headers.
- **P5** After heal at `t_g`, in scenarios where every member is honest and none restarted
  (F9–F12 with heal): first commit at every honest node by
  `t_g + P(0) + Σ_{L=ℓ..max(ℓ, k*)} (T(L) + Δ) + 2σ + F + E + 5Δ`, where `ℓ` is the lowest level of
  an honest node's current view at `t_g` and `k*` is as in L3 (views may fail until
  `T(L) ≥ T_req`; every leader is honest, so the first such view commits).
- **P6** Under the F29 flood, every `Tick` is handled within `ε_tick` of `next_wakeup()`.

### 8.3 Scenario checklist

| Fault | Mechanism | Typical cost |
|---|---|---|
| Silent/crashed leader | view timer → TC → next leader; `skipped_leaders` demotes it for `W` heights and its slots pass to its successor; the start level is unchanged (§9.2) | `P(0) + T(start)` (7.2 s at `n = 4` defaults, idle or loaded) once per `W` heights |
| Silent / slow non-P set-A member | stage 1 (set B → `P`); from the next height the hint (parent CommitQC needed set B) starts stage 1 at once; never demoted | `t_retx` once per `n` heights, then `2f` extra messages per height |
| Silent / withholding / selective proxy tail | stage 2 (readiness timer or contagion), every member aggregates; never demoted | `≈ 2·t_retx + Δ` per proxy-tail turn (1 to `1 + |D|` turns per `n` heights) |
| Member that Prepares but withholds its Commit | stage 1 on the overdue CommitQC (`t_pqc + t_retx`) | `t_retx` |
| Late entrant (slow apply, joiner, just synced, restarted) | `Status{want_proposal}` to the leader → immediate re-push, even if the rest of that `Status` is rate-limited | `≈ 2Δ` for that member |
| Lost proposal copy at an on-time member | a vote, PrepareQC or `Status` of the round shows the proposal exists → one `Status{want_proposal}` per view to the leader → immediate re-push | `≈ 2Δ` after that evidence (at worst the stage-2 votes, `≈ 2·t_retx`) |
| Equivocating leader | ≤ 1 PrepareQC per view (S2); evidence; every honest node holding both twins times out early (§6.2 step 2), `f + 1` of them pull the rest (join); a failed view never raises the start level (§9.2) | `TC` `≈ 2Δ` after both twins reach `f + 1` honest nodes; one view `T(level)` if fewer see both |
| Adversarial TC composition | no voter lock check; TC rule only | none |
| Relay tampering (payload, attachments) | signature covers attachments; `body_ok`; silent drop + fetch; no evidence | none |
| Byzantine body / sync responder | `body_ok`, wanted-only acceptance, rotation over sources | one fetch retry |
| Lossy links (10–30 %) | vote retransmit to `P`, QC answers (Prepare) and Status replies (Commit), state rebroadcast, proposal re-push, body pull | a few `t_retx` |
| Slow executors (≤ f) | they fall into the `f` that stage 1/2 tolerates | `t_retx` |
| Slow executors (all) | level grows ×1.5 per failed view; start level adapts (an execution — also one discarded unfinished, as a lower bound — or the committing view `> T(start)/2`, §9.2); `exec_budget` caps block cost at `φ·T_base/2`; nonempty work may be retried at every view | converges in `k*` views; payload resumes once the start level covers `E` |
| Late but valid leader (proposal or body sent as late as the view still commits) | the view commits; `d_c` is measured from `t_body`, so the start level is unchanged (§9.2); never skipped, no evidence | its own delay, `< P(v) + T(start)` per turn |
| Poison transaction | `Invalid` → early timeout + `PayloadRejected` → builder quarantines the culpable transaction only; no evidence; start level unchanged | one or two views; that view's (honest) leader is demoted once |
| Lost safety record (with or without block-store loss) | key unanchored until signed probe echoes from `2f + 1` members of `C_{t'+2}` show it caught up; abstains through `t' + 2` | that key signs nothing until then; the node counts as one of the `f` faults until it anchors |
| Lagging node | `Status.committed_qc` / `parent_qc` → sync (one request outstanding, fetch overlaps apply); others never wait | none for others |
| Whole-cluster restart | records (lock, `high_tc`, exact timeout) and stored bodies restored; Status re-synchronises views | ≤ one view |

### 8.4 Bounded memory and storage (what is retained, when it is discarded)

| Item | Bound | Discarded |
|---|---|---|
| vote pools | `3 views × 2 kinds × n` votes | on view advance (outside `{v−1, v, v+1}`), all on commit |
| timeouts | `n` (highest-view per signer) | on commit |
| fresh proposal parts | one payload ≤ `max_block_bytes`, one inline 2048-byte control witness | proposal, view advance or height advance |
| application-control ingress | one timestamp per current member; driver one pending 2048-byte partial per sender | bounded cadence; obsolete source or halt clears |
| certificates | `high_pqc`, `high_tc`, `tip.commit_qc`; `cert_cache` ≤ `4n` digests (LRU) | replaced monotonically / LRU / on commit |
| block bodies in memory | ≤ 6: current proposal, `high_pqc`'s, `high_tc.high_pqc`'s, 2 `pending_apply`, 1 in flight | `advance_to` keeps only `high_pqc`'s, `high_tc.high_pqc`'s and `pending_apply`'s; height entry keeps only `pending_apply`'s (all reloadable from the body store) |
| body store (driver, disk) | finite configured capacity (production default 1 GiB), fail closed if exhausted; no unproved early deletion | when the height is applied |
| `exec` entries | one per body in memory, plus `tip.exec_req` | at every `DiscardExecution` not keeping them (view change, commit); all on height entry except `tip.exec_req` (cleared by its answer) |
| probe table | ≤ `n` member keys of `C_{tip.height+2}` | entries of other keys at height entry; all when the key is anchored |
| keys (configured and retired) and their records | one per key with an installation-log entry for `I`; records ≤ ~3 KB each on disk (§7.4 Keys) | never: retired records are kept |
| `wants` | ≤ 5 | when satisfied / no longer needed |
| `pending_apply` | ≤ 2 (consensus ≤ 2 heights ahead of apply) | when `CommitBlock` is emitted |
| sync buffer | ≤ `2·sync_batch` entries and ≤ `2·sync_max_bytes` bytes (one outstanding request) | when processed or on failure |
| peer table | ≤ `n + max_observers` (LRU) | LRU eviction |
| recent headers / configs | `W + 2` / ≤ 4 | sliding window |
| evidence dedup set (`reported`) | ≤ `3 views × (3n + 1)` keys | with the vote pools' window; all on height entry (evidence itself is emitted immediately) |

No in-memory structure grows with the number of views, with time, or with message volume; the
only on-disk structure that does is the body store, by one header-sized body per failed view until
the height is applied. Messages for
heights `> h` (other than those listed in §6.1) and views outside the window are dropped, not
queued; rebroadcast re-delivers the current state later.

---

## 9. Pacemaker

### 9.1 Formulas

```text
T(L)         = min(T_max_eff, T_base · 1.5^L)
level(h,v)   = min(level_cap, start(h) + v)
level_cap    = ceil(log_1.5(T_max_eff / T_base))
P(0)         = payload_retry_interval + build_timeout ;   P(v > 0) = build_timeout
anchor(h,v)  = min(t_enter + P(v),  t_prop)
               // t_prop: time the (h,v) proposal was accepted (if any)
t_view(h,v)  = anchor(h,v) + T(level(h,v))                       // view timeout
t_retx       = clamp(3 · qc_lat_ewma, 50 ms, φ · T(level(h,v)) / 2)
t_s1         = min(t_ready + t_retx  [no PrepareQC],  t_pqc + t_retx  [no CommitQC])  // stage 1 (§5.2)
t_s2         = min(t_lastvote + 2 · t_retx,  anchor + φ · T(level(h,v)))   // stage 2, φ = 0.5
t_propose    = t_enter(h,0) + pace,  pace = max(0, block_time − latency_ewma)
exec_budget  = min(e_max, φ · T_base / 2)                         // hint to the payload builder
```
`latency_ewma` = EWMA (weight 1/8) of `t_commit(h) − t_proposal_received(h)` measured locally.
`qc_lat_ewma` = EWMA (weight 1/8, initial 250 ms) of the time from sending an own vote to
receiving that phase's QC, sampled for every own vote whose phase QC arrives, each sample capped
at `2 × qc_lat_ewma` (so a persistent change, such as execution skew in set A, is learned within a
few rounds, and one slow or adversarially delayed round moves the estimate by at most 1/8).
`exec_budget` depends only on `e_max` and `T_base`, never on the leader's level: a leader at a
high level must not build blocks that voters at level 0 cannot execute within their timers. It is
the builder's estimate of execution time in milliseconds (e.g. gas at a calibrated rate); the
core only passes it. Deadlines are recomputed whenever `anchor` moves; `anchor` only moves
earlier within a round. All timers are local; nodes need not agree on them. No timer depends on
the node's own transaction queue: a local queue affects only when this node proposes (§6.10).

### 9.2 Start level adaptation (on commit of `h`)

Let `v_c` be the view of the CommitQC with which this node commits `h`, and
`d_c = t_commit(h) − t_body(h, v_c)`, where `t_body` is when this node first held the proposal of
`(h, v_c)` together with its body (§6.2 step 9), if this node is in round `(h, v_c)` when it
commits and holds that view's proposal of the committed block with its body. Otherwise `d_c` is
undefined: this node left `v_c` for a higher view, never reached it, or holds a twin or no body,
so it never measured that view. `pm.last_exec_ms` is the longest execution at `h`: the maximum of
`now − since` over every answered execution at `h` (§6.3 step 1), every execution still pending
when a view change discarded it (§6.2 `discard_exec`), and the committed block's execution if it
is still pending at the commit (§6.8 step 4). The last two are lower bounds of executions that
outlasted their view.
- **Raise:** if `pm.last_exec_ms > T(start(h)) / 2` (an execution at `h` took more than half the
  base timer here) or `d_c > T(start(h)) / 2` (the committing view was slow here):
  `start(h+1) = min(start_cap, start(h) + 1)`, `fast_streak = 0`.
- **Decay:** else if `v_c == 0`: `fast_streak += 1`; when
  `fast_streak ≥ decay_after`: `start(h+1) = max(0, start(h) − 1)`, `fast_streak = 0`.
- **Otherwise** unchanged. No failed view raises the level by itself, whatever ended it
  (deadline, join or early timeout, §6.6) and whether or not this node held its proposal; a
  crashed leader costs `T(start)`, not more. Only an execution can: a failed view whose execution
  was still running when the view ended counts that execution's elapsed time.
- After restart `start = 0`, `fast_streak = 0` (safe; only costs time).

*Why executions that outlast their view count.* A nonempty execution may be cancelled when a
view ends, then retried in a later view with a larger timeout. Its elapsed duration is a lower
bound on required execution time. Keep the maximum observed duration at the height so that a
quick later execution does not hide earlier slow work; after a real commit, that measurement
improves the next height's start level. Every view can build nonempty work, so transaction
progress does not depend on committing a synthetic empty height first.

*Why the proposal and its body, not the view entry or the anchor.* At view 0 the entry is
followed by the deliberate wait for the proposal — about `block_time` under load (the pace) and
a bounded payload retry while idle — which alone exceeds `T(0)/2` at every idle
height and, at `n = 4` (`T(0)/2 = 1 s`), at most loaded ones: measured from the entry, the
simulator's healthy idle chain sat at `start_cap` and its loaded `n = 4` chain at level 1. The
anchor `min(t_enter + P(v), t_prop)` removes that wait but still counts a leader's lateness. A
leader whose valid proposal arrives `T(start)/2 + ε` after `t_enter + P(v)`, or which sends the
proposal at once without its payload and serves the body `T(start)/2 + ε` later, makes
`d_c > T(start)/2` at every honest node while the view still commits before its deadline. The
view succeeds, so that leader is never skipped or demoted and leaves no evidence. Measured from
the anchor (or from `t_prop`), such leaders raised every honest node to `start_cap` in the
simulator (F36), and every crashed leader then cost `P(0) + T(4)` — 15.3 s at `n = 4`, 20.4 s at
`n = 22` — instead of `P(0) + T(0)`. From `t_body` the leader controls neither: an honest
proposal supplies metadata and a separate row stream; `t_body` is when both verified proposal
and actual body custody are held. Acquisition wait is excluded from this execution-based
adaptation metric; it is still part of end-to-end latency and the liveness delivery assumptions.

*Why this resists Byzantine members.* (1) A failed view never raises by itself. A faulty leader
that equivocates (early timeout, §6.2 step 2), sends a valid proposal to too few members
(deadline or join timeout while holding it), signs a defect or stays silent costs at most its
view (§8.2 L2) and leaves every honest node's start level unchanged. Revision 4.1 raised whenever
a view timed out while this node held its proposal, which every faulty leader could trigger at
each of its turns; at `n = 22` successive equivocating leaders held honest nodes at levels 3–4
and one height took 26 s (F5 seed 279). (2) Faulty members cannot stretch `d_c` through the
proposal or its body (above), nor through a twin (`d_c` is undefined at a node that holds the
other twin). They can only delay certificates, and only until the stage ladder bypasses them:
each phase at the latest by stage 2 at `t_lastvote + 2·t_retx` (§5.2), so a committing view they
stretch lasts at most about `E + 4·t_retx + 4Δ` from `t_body`. `t_retx ≈ 3·qc_lat_ewma` does not
depend on the level until its clamp, and a delayed round moves `qc_lat_ewma` by at most 1/8
(§9.1), while `T(L)/2` grows ×1.5 per level; so this exceeds `T(L)/2` only at the lowest levels
(level 1 in F2/F3). That bound, not decay, is what limits the level they can hold: faulty members
lead or collect at about `f` of every `n` heights (every 3–4 heights at `n = 3f + 1`), more often
than `decay_after = 8` heights, so a lever that raised the level at every faulty turn would hold
it at `start_cap` however `decay_after` is chosen. (3) Only a view this node measured counts: a
CommitQC of a view it has left, or for a twin of the proposal it holds — for example the first
twin of an equivocating leader, committed through members that voted before the second arrived —
does not. (4) The execution clause: a valid block that takes longer than `T(start)/2` to execute
raises the level whoever proposed it; execution is bounded by `e_max` (§9.4), and a persistently
slow executor is what the level exists for (§4.4 item 2). A discarded execution counts only its
elapsed time, never more than it would once finished.

*Why liveness does not depend on it.* Within a height the level still grows by one per failed
view (`level(h, v) = start(h) + v`), so the view timer reaches `T_req` after at most `k*` failed
views whatever `start(h)` is (§8.2 L3). The start level only shortens that path at later heights
when the symptom persists — an execution, or a committing view, longer than half the base timer —
and prices failed views; it rises by one per such height until `T(start)/2` covers it (F15).
Pending valid payloads can progress at any view once the timeout covers their execution.

### 9.3 Defaults (1 s target block time)

| Parameter | Kind | n = 4 | n ≈ 20 (≤ 31) |
|---|---|---|---|
| `block_time` | chain | 1000 ms | 1000 ms |
| `payload_retry_interval` | chain; polls unusable/absent work without advancing height | 5000 ms | 5000 ms |
| `demotion_window W` | genesis constant per instance (SHOULD be ≥ `4n`) | 128 heights | 128 heights |
| `e_max` / `a_max` | chain | 4000 / 1000 ms | 4000 / 1000 ms |
| `max_block_bytes` | chain | 16 MiB | 16 MiB |
| `build_timeout` | local | 200 ms | 200 ms |
| `T_base` | local | 2000 ms | 3000 ms |
| growth | fixed | 1.5 | 1.5 |
| `T_max` | local (effective ≥ `T_req`, §9.4) | 30 000 ms | 30 000 ms |
| `level_cap` | derived | 7 | 6 |
| `start_cap` / `decay_after` | local | 4 / 8 heights | 4 / 8 heights |
| `φ` | fixed | 0.5 | 0.5 |
| `rebroadcast_interval` (≤ `T_base/2`) | local | 500 ms | 1000 ms |
| `status_keepalive` | local | 5000 ms | 5000 ms |
| `fetch_retry` | local | 250 ms | 500 ms |
| `sync_batch` / `sync_retry` | local | 64 / 1000 ms | 64 / 1000 ms |
| `sync_max_bytes` (≥ `max_block_bytes` + `FRAME_OVERHEAD`) | local | 16 MiB + `FRAME_OVERHEAD` | 16 MiB + `FRAME_OVERHEAD` |
| `max_observers` | local | 64 | 64 |

View-0 timelines at n = 4, start level 0. **Under load:** the leader proposes about
`block_time − latency_ewma` after the parent commit; stage 1/2 fire a few `t_retx` after a member
became ready; the view times out at `t_prop + 2.0 s`. **Idle:** no block is proposed;
new work wakes the current eligible leader and timed-out views continue via timeout certificates. A crashed leader is detected at `t_enter + 5.2 s + 2.0 s`, idle or under load
(§15.2). `T(L)` for n = 4: 2.0, 3.0, 4.5,
6.75, 10.1, 15.2, 22.8, 30 s. Chain parameters MUST be identical on all validators (they come from
committed state, §10); local ones only change performance.

### 9.4 Config validation

`T_req(nominal)` is the §8.2 L3 formula with `Δ = Δ_nom = 500 ms`, `δ = δ_nom = 50 ms`,
`σ = rebroadcast_interval + Δ_nom`, `F = ⌈log2(f+1)⌉ · fetch_retry` for the committee size, and the
chain's `a_max`, `e_max`. Defaults: n = 4 → 16.1 s; n = 22 → 19.6 s; both ≤ 30 s.
`Core::new` rejects a local config if `T_max < T_req(nominal)` for the initial configurations,
`rebroadcast_interval > T_base / 2`, `sync_batch < 1`,
`sync_max_bytes < max_block_bytes + FRAME_OVERHEAD`, `fetch_retry > rebroadcast_interval`, or
`demotion_window < 1`. The application MUST reject chain parameters with
`block_time > payload_retry_interval`, `payload_retry_interval == 0`, or
`max_block_bytes + 2·FRAME_OVERHEAD > transport_limit` (§12.3 O10). The latter leaves room
for a local sync budget of at least `max_block_bytes + FRAME_OVERHEAD` and its bounded
outer response allowance. The first-release transport budget is 16 MiB plus both allowances,
within the 17 MiB P2P plaintext cap. `Δ_nom` must cover manifest and complete encoded-row delivery for
each maximum payload to the intended peer list, including RS16 expansion, table/signature
bytes, worker time and framing. The earlier raw-payload-only uplink estimate does not apply.
The application SHOULD choose limits using measured complete delivery cost or operators raise
`T_max`. When a
later committed configuration raises `T_req`, the core uses `T_max_eff = max(T_max, T_req(nominal))`
and reports `LocalFault(ConfigTooTight)` instead of halting.

---

## 10. Validator set changes, chain parameters and epochs

1. **Authenticated authority.** `HeightConfig { epoch: EpochConfig, committee, params }` carries
   an inclusive scheduling interval, scheduling epoch/context identity, immutable authority
   generation ID and fresh leader seed. The application verifies the full canonical context,
   exact committee geometry/order, complete PoPs, generation ownership and certified decision.
   The core checks ID equality, interval membership, exact epoch continuity and retained-generation
   committee equality. Context IDs never depend on which exact quorum produced a local receipt.
2. **Lagged parameters, applied authority.** Ordinary chain parameters retain lag two. At the
   penultimate height `B−1`, `BlockApplied` installs an explicit pending slot for `B+1`.
   It MUST NOT install a prospective roster or copy incumbents into that slot. Height `B` is
   certified by the current authority's exact-quorum CommitQC. Only the
   original applied execution of `B` atomically supplies the authority/config of `B+1` and the
   lagged parameters of `B+2` (§6.13). Application contexts must cover at least those two heights;
   the global application requires an epoch of at least three consensus heights.
3. **Boundary barrier.** A CommitQC for `B` alone does not enter `B+1`. Until `B` is applied,
   there are no proposals, votes, timeouts, signed probe replies or restart anchoring under the
   successor context. Sync may retain bounded future entries but cannot verify them using a
   guessed committee. Ordinary nonboundary heights retain the pipeline and apply bound: at
   most two heights ahead of durable application, using the certified speculative parent state.
4. **Preparation and activation.** The application freezes a complete candidate committee one
   epoch ahead, prepares its keys and DKG, then verifies every target seat's custody and the
   finalized transcript. The current exact quorum authorizes atomic activation. A missed cutoff
   is a certified cancellation plus a new scheduling authorization retaining the existing
   immutable generation. Subsequent selection creates a new transition/transcript. A frozen
   committee cannot shrink or reroll in place. Key rotation takes effect only with its complete
   authenticated context, never through an in-place core config replacement.
5. **Fresh scheduling and obligations.** Even retained committees receive fresh authenticated
   epoch leader randomness, consumed by the actual topology permutation. Retention extends a
   generation's lifetime and makes no forward-security claim. Exit requests do not end voting
   or slashing obligations before authenticated replacement. On a network with SCCP
   (application layer, `specs/sccp.md` §4.8), slashing obligations extend further: destination
   contracts trust a committee generation until its anchored deadline, so a departed member's
   stake is released only after no generation that contained it is still liable, and the
   unbonding delay MUST cover the destination validity window plus the evidence grace period.
   Exit itself is never blocked. Current and pending credentials
   and their separate durable safety records survive restart. No key signs if its record's
   epoch/context differs from the active authority at that height.
   Bootstrap admission and restored active beacon custody bind the transcript's signed
   authority generation to that authorization; an identical participant roster does not
   authorize a different generation's DKG.
6. **Sync and other instances.** Each QC is verified under its own installed historical context.
   A boundary's old-authority certificate and applied authenticated result establish the next
   context before successor signatures are considered. A lane/dataspace carries any governing
   global decision into its own certified execution and applies this same boundary rule; the
   core does not read another instance. A sequential verifier advances an authenticated prefix
   with bounded working authority, not an unbounded committee cache.
7. **Long-range scope.** Removed members cannot certify later epochs. Historical verification
   still relies on the application's signed genesis/checkpoint trust root; later compromise of
   old keys does not confer forward security. This rule is not a committee override. SCCP
   destinations, which verify global CommitQCs directly, bound how long they trust a departed
   committee and make its misuse slashable (`specs/sccp.md` §9.9).
8. **Quorum loss.** Failure to prepare replacements can be resolved only by the current exact
   quorum's certified retention decision. If that quorum is absent, the instance halts safely.
   There is no local committee override, unsigned retention, observer padding or provisional
   activation.

---

## Governed NPoS reconfiguration

**Application-layer governance.** This section is not a core rule. The NPoS application applies
these on-chain parameters when it elects validators and schedules committees and chain parameters
for the core through §10.

Evidence retention and penalty scheduling are governed on-chain rather than
read from local node config. The first-release defaults are:

- `SumeragiNposParameters.reconfig.evidence_horizon_blocks = 7200`;
- `SumeragiNposParameters.reconfig.activation_lag_blocks = 1`;
- `SumeragiNposParameters.reconfig.slashing_delay_blocks = 3600`.

Node penalty preparation reads one immutable parent view and prepays a flat validator lookup
from its original evidence-preparation pool, including exact peer-key and account allocations.
The lookup retains peer/lane/account ordering and original tenure bounds; slash ceilings come
from the unchanged parent stake index. Decoded evidence/history graphs, stake-index quantities
and penalty arithmetic remain separate resource-accounting work (S8).

The current signed `ChainParamsRecord.epoch_length_blocks` is the epoch authority.
The NPoS policy must carry the same length; genesis signing, parameter admission, and schedule
publication reject a contradiction. The global application requires its threshold pulse at
height `h` exactly when the chain is NPoS and `(h + 1) % epoch_length_blocks == 0`. Governance
state creates no pulse obligation: Parliament sortition waits governance-locally for the
consensus-native pulse at its frozen slot (`specs/parliament_private_ballot_design.md` §9), and
a pending governance slot never makes a pulse mandatory, admissible or a condition of a block.
A pulse is bound to the exact network, active public DKG session, scheduled
validator roster, height, and committed parent. It is committed by the block header's dedicated
`global_beacon_pulse_hash` and carried in `global_beacon_pulse`; it never authorizes a block
without transaction work.

The node starts pulse production after selecting real work, or after receiving a cryptographically
valid partial from that slot's authenticated validator. Idle polling and malformed traffic do
not start signing. Current partial frames have a distinct fixed wire domain, a 4 KiB bound, and
one bounded worker queue; signature verification runs off P2P ingress. Missing shares or signer
custody keep the real work pending. Retries retransmit the same parent-bound share and wake the
payload builder when the threshold is met. Block admission and application independently check
the required pulse and persist its unique history; they never substitute local status or a
retired consensus context for authority.

The evidence horizon, slashing delay, and epoch length are
immutable after the initial signed installation. The
horizon plus delay may span at most three epochs, matching the fixed
four-roster committed-evidence capacity. Other admitted fields may be governed
through the on-chain parameter path; validators and executor upgrades must
never replace consensus-owned values with local TOML or executor defaults.

**SCCP liability (application layer; target, `specs/sccp.md` §4.8–§4.9; not yet implemented).**
While SCCP exists, the genesis-pinned staking policy MUST satisfy
`nexus.staking.unbonding_delay_ms ≥ committee_validity_ms + forgery_evidence_grace_ms` and
`nexus.staking.max_slash_bps ≥ 1`; genesis, `irohad` start-up and the SCCP parameter path enforce
it. `FinalizePublicLaneUnbond`, zero-custody pruning and a replacing re-registration are refused
while an SCCP committee generation that contained the validator is liable, or while an SCCP
forgery record naming it is pending. SCCP forgery records are applied by the same penalty
pipeline after `slashing_delay_blocks`, but they are self-contained (§3.6): the offence height is
the generation's start height (`ConsensusSlashLiability::Root(start_height)`), offenders come
from the record and must still be the same registration, and the three-epoch evidence horizon
does not apply to them, because SCCP liability is bounded by its own liability clock.

A staged mode transition preserves the joint-consensus rule that the outgoing
set authenticates the boundary: `mode_activation_height requires next_mode to be set in the same block`.

---

## 11. Dataspace-local finality and AMX via two-phase commit (application layer)

The core is not involved beyond the exports listed at the end. Participants: the global chain `G`
and dataspaces `D1..Dk`, each a separate core instance with its own committee.

1. **Finality.** A DS block is final when its DS CommitQC exists (DS-local finality). A global
   block is final when its global CommitQC exists. Neither depends on the other.
2. **Begin (G).** An AMX transaction `X` (`x = H(X)`, participant set, global deadline height `d`)
   is first committed in `G` as `Begin{x, participants, d}` at a global height `b < d`. From then on
   `G`'s state knows `x`; a second `Begin` for `x` is rejected.
3. **Prepare (DS).** Each participant `Di` includes `X` with a `G` proof of `Begin` (§11.7) in a
   DS block. DS execution checks the proof and that `x ∉ prepared_Di`, adds `x` to `prepared_Di`,
   and either escrows (locks) the touched state and records `Prepared{x, Di, Yes, effects_hash}`,
   or records `Prepared{x, Di, No}`; the record is committed in `R_Di`. A second inclusion of `x` is
   a rejected transaction. If `Di` already holds a proof of `G`'s decision for `x`, it records `No`
   and escrows nothing.
4. **Relay.** Any node submits to `G` a proof: DS header, DS CommitQC, Merkle proof of the record
   in `R_Di`. `G`'s executor verifies it with the foreign-committee tracker (§11.7). Relaying
   affects liveness only; the validators of each participant SHOULD relay their own `Prepared`
   records (their payload builders include pending proofs).
5. **Decide (G).** `G`'s execution records `Decision{x, Commit}` in the first global block at
   height `≤ d` that holds `Yes` proofs from every participant; `Decision{x, Abort}` on the first
   valid `No` proof, or deterministically in the first global block with height `> d` if no decision
   exists yet (`G` knows `x` from `Begin`, so abort needs no proof). One decision per `x`,
   immutable; later proofs for `x` are ignored.
6. **Settle (DS).** Each `Di` includes the decision proof (global header, global CommitQC, Merkle
   proof of the decision) in a later DS block; DS execution verifies it, checks
   `x ∈ prepared_Di \ settled_Di`, applies or releases the escrow, and adds `x` to `settled_Di`.
   **A DS MUST NOT release a `Yes` escrow by any other means** (no local timeout, no operator
   release). Escrow is bounded in global heights (`G` decides by `d + 1`) but not in wall-clock
   time: it lasts while `G` is halted or while no decision proof is relayed.
7. **Foreign-committee tracking (light client).** An instance `J` whose certificates another
   instance verifies (`G`, and every DS taking part in AMX) changes committees only at epoch starts:
   heights `s` with `(s − g_J − 1) mod E_J == 0`, `E_J = epoch_length` (a chain parameter of `J`).
   The applied certified boundary result `R_{s−1}` authenticates the complete next context (§10). A verifier tracks, per foreign instance, the latest epoch
   `e` it has verified with `C_{J,e}`, and also `C_{J,e−1}`. Ordinary foreign proofs require
   `epoch(x) ∈ {e − 1, e}` and `verify_commit_qc(I_J, C_{J,epoch(x)}, qc)`. A participant also
   retains authenticated older contexts needed to settle its unresolved `Yes` obligations.
   Each such obligation binds its certified `Begin` height `b` and deadline `d`, checked as
   `0 < d − b ≤ MAX_AMX_DEADLINE_WINDOW`. Before eviction, an authenticated context is
   retained iff its height interval intersects `[b, d + 1]` for an unresolved `Yes`. These
   contexts verify only that obligation's `Decision`: a `Commit` must be in `[b, d]` and an
   `Abort` in `[b, d + 1]`. They never admit old `Begin` proofs, unrelated decisions, or
   handoffs. Authority is retained from the sequential authenticated history, never accepted
   from a committee supplied with a delayed proof. The retained contexts and obligation
   bindings are committed participant State and survive authenticated restart. Checking a
   decoded archive's shapes and interval coverage alone does not authenticate historical
   committees; restoration requires authenticated enclosing State or original certified replay.
   Contexts are
   reclaimed when no unresolved `Yes` needs them, without releasing escrow by timeout.
   At most `MAX_AMX_PENDING × (MAX_AMX_DEADLINE_WINDOW + 2)` distinct older contexts are
   needed: epochs have disjoint nonempty height intervals, and each bounded obligation
   intersects at most one distinct epoch per height. To
   advance to `e + 1` it needs a *handoff proof*: the header of height `s − 1` (`s` = first height of
   epoch `e + 1`), its CommitQC verified under `C_{J,e}`, and a proof of the complete authenticated next epoch context in
   `R_{s−1}`. Handoffs are relayed in sequence, one per epoch even if the committee is unchanged.
   Members removed at an epoch start therefore cannot certify any height of a later epoch. A proof
   for an epoch beyond `e` waits for the handoffs; if they do not arrive before `d`, `X` aborts.
8. **Properties.** Atomicity: all participants apply `X` iff `G` recorded `Commit`, `G` records
   `Commit` only with `Yes` from all, and no participant releases a `Yes` escrow without `G`'s
   `Abort` proof. Idempotence: per-`x` prepared and settled sets. Non-blocking: no DS block and no
   global block ever waits for another instance; a slow DS only makes its AMX transactions abort.

**What the core exposes for this (and nothing else):** (a) the instance id in every signing
domain and header; (b) the committed-block output (`CommitBlock{block, commit_qc}`) from which
proofs are built; (c) pure functions `block_hash(&BlockHeader)`, `committee_digest(&Committee)` and
`Verifier::verify_commit_qc(&Qc, Option<&BlockHeader>) -> bool` for foreign-instance light
verification. The verifier is bound to the independently authenticated instance, epoch/context
and ordered committee. A supplied header must match the certificate's height, epoch and block hash.

**As built.** Each daemon hosts its independently signed Global or dataspace root, including
its own State, Kura, allocation pool and mandatory native context archive. Native participant
instructions, signed-genesis installation and managed original G1/H2 acquisition exist.
Explicit administrative parent registration retains its original signer, fee/time terms and
signed transaction until independently verified Global execution supplies success or rejection.
Managed lifecycle qualification, complete outbound proof custody, durable validator relaying
and whole-network qualification remain open.
Choices beyond the rules above are Appendix E, E58 (node) and E59 (simulator).

- *Transaction and records* (`iroha_data_model::sumeragi_amx`): `X` is `AmxTransactionV1`, 2–16
  legs in strictly increasing dataspace order (an opaque payload per participant), the deadline
  `d` and a client nonce; `x = H("iroha/sumeragi/amx/transaction/v1" ‖ norito(X))`. The records
  are `AmxBeginV1`, `AmxPreparedV1` and `AmxDecisionV1`.
- *Record proofs*: the instance that creates a record writes it into the block's execution
  witness under the reserved key `0xD9 ‖ kind ‖ x`, so the ordinary-write root of `R` commits it
  and `R`'s layout is unchanged. `AmxRecordProofV1` is the block's canonical core header, its
  `CommitQC`, the canonical result preimage and the sparse-Merkle path of the write in that root.
  Proof construction rejects a write set whose path does not match the canonical result's
  ordinary-write root; omitted mandatory context writes therefore fail before relay. The
  receiving tracker separately authenticates the certificate and its result-preimage binding.
  The mandatory native context archive retains each root executor's complete original write
  sets. `iroha_core::sumeragi::amx::amx_record_proof` authenticates the exact historical carrier
  and archive root before serving records, including after deadline pruning and certified
  replay. Initial genesis acquisition keeps its original charged raw frame and prepaid
  shared body across local constructor refusal. Successful signed-genesis authentication
  transfers both into the same chain; genesis-prefix retries borrow that body after fresh
  original slot/object membership checks. Partial genesis-result/authority graphs still
  retire under the unchanged cumulative decoder, and initial acquisition still borrows its
  State view. After that same reader certifies the carrier and pins the archive descriptor,
  `try_detach` moves the exact partial read, original pool and completed graph into an owned
  job that can outlive its State view. Refusal retains the borrowed job; namespace, commitment
  and one-shot delivery checks remain mandatory. Complete prefix/decoder resource qualification
  and connected validator relaying remain open.
- *Local Prepared intent* (`query::native_context_archive`, `sumeragi::executor`):
  the original Worker captures one finite, prepaid `.ami` coordinates frame alongside its
  unchanged `.nrt` before publishing State. Selection uses the complete committed witness,
  so same-block pruning or settlement cannot erase a historical Prepared record. The frame
  binds the original signed carrier, ordinary-write root, transaction/key/value digest,
  participant and authenticated signed G1/H2 parent. It contains no parent signing or fee
  authority; those remain unresolved. Both original buffers survive local refusal; commit
  acknowledgement follows create-only durable publication, and authenticated native replay
  checks existing bytes without replacing them. The borrowed
  `query::native_receipts::prepared_amx_relays(view, height)` selects that carrier from the
  captured authenticated State hash journal and retains its original descriptor and charged
  frame. Before first delivery it joins the advertised count to the native proof reader's
  authenticated complete Prepared writes; ordered distinct rows still require their exact
  certified record proofs. The original proof and funded instruction survive local admission
  or final namespace refusal for the same-source retry. Delivery returns a move-only
  `NativeAmxRelayIntentV1`: its exact source network/scope, carrier height/hash, record key
  and authenticated target network/scope/instance accompany the same original funded
  instruction graph. The copied descriptor is only a durable identity and route selector;
  it cannot decode or reconstruct proof authority. Fresh signing after restart requires
  reauthentication of the source. Delivery supplies no signing or fee authority and does
  not acknowledge the intent. The authorized parent signer/fee boundary,
  durable transaction journal and autonomous submission remain unimplemented; this is not
  submitted relay or complete H2 qualification.
- *Tracker* (`AmxForeignInstanceV1`, item 7): the complete authenticated contexts `C_{J,e}` and
  `C_{J,e−1}`. A certified block verifies only if its header's epoch is one of them and contains
  its height, exactly `q` members of that epoch's committee signed the `CommitQC` (the core's
  `Verifier::verify_qc`), and the result preimage hashes to the certified `R` and names that
  height and context. A handoff proof is the certified last block of `e`: the boundary decision in
  its result preimage, validated against `C_{J,e}`, names `C_{J,e+1}`. Participant State retains
  evicted decision contexts only while unresolved `Yes` obligations need their bounded height
  intervals. The same certificate verifier uses that retained authority for the matching
  delayed decision; ordinary tracker proofs and sequential handoffs keep the two-epoch rule.
- *`G`* (`iroha_core::sumeragi::amx`): the World cell `sumeragi_amx` holds the registered
  participant dataspaces with their trackers and the transactions whose deadline has not passed.
  `RegisterAmxDataspaceV1` (in genesis, or by an authority holding `CanSetParameters`) anchors a
  tracker at an authenticated epoch context of the dataspace's instance; `BeginAmxV1` (item 2),
  `RelayAmxPreparedV1` (items 4–5) and `RelayAmxHandoffV1` (item 7) are its transactions. After
  every block's transactions the deadline step aborts each undecided transaction with `d < h` and
  drops each transaction with `d < h` from the state; its `Decision` stays provable from the
  block that recorded it.
- *Participant* (`AmxParticipantStateV1` over the `AmxEscrow` interface that a dataspace's
  executor implements): prepare (item 3), settle (item 6) and `G`'s handoffs. A `Prepare` is also
  rejected once the participant has verified a `G` block above `d`: `G` has then decided `x`, and
  without this vote only `Abort`. The fallible escrow interface preserves a host's typed local
  failure separately from protocol rejection: refused preparation emits no vote, and refused
  apply/release changes neither the prepared entry nor the verified global-height cursor.
  The same proof can retry against the original escrow. Native signed-genesis installation
  retains the participant graph and exact escrows in its original State pool. Complete outbound
  proof funding, managed lifecycle qualification and durable validator relaying remain open.
  Root startup derives its Kura and configured chain identity from the original State; callers
  cannot supply a second store or chain identity. Component tests run separate signed
  Permissioned/Bootstrap dataspace roots through the production driver, with full-width IDs,
  independent pools/stores, scoped PipelineGas payments and certified replay. These do not
  qualify whole-network isolation/restart, parent-Nexus fee settlement, or queue/transport owner
  affinity. Separate roots may run in separate daemons; §11 does not require a shared process.
  Foreign network inputs still require original-root validation before execution.
- *Simulator* (`sim::amx`, F31): the same protocol as a toy application on every instance's
  committed blocks, checked by O-AMX (§13.2) and the `MX` mutations (§13.4). Its executor
  consumes the same signed RS16 `AvailableBody` owners as the other scenarios. A held
  decision followed by a late `No` preparation retains one settlement and makes no ledger
  movement; the oracle rejects a changed decision or a second monetary effect.

---

## 12. Sans-IO node interface

### 12.1 API

```rust
pub struct Core { /* §6.0 */ }
impl Core {
    pub fn new(local: LocalParams, init: Init, signers: Vec<Arc<dyn Signer>>, crypto: Box<dyn Crypto>,
               body_budget: AllocationBudget, now: Millis)
               -> Result<(Core, Vec<Action>), ConfigError>;  // applies R1–R6 (§7.4)
    pub fn handle(&mut self, now: Millis, event: Event) -> Vec<Action>;
    pub fn next_wakeup(&self) -> Millis;                   // earliest deadline; driver sends Tick
    pub fn status(&self) -> CoreStatus;                    // read-only diagnostics (height, view, level, stage, t_retx,
                                                           //   leader and proxy tail of (h, view), high PrepareQC view, footprint)
}
pub struct Init {
    records: Vec<(PublicKey, RecordState, bool)>, // one per configured or retired key: Present(bytes) | Absent; retired flag
    genesis_height: u64,
    demotion_window: u64,                     // W, fixed at genesis (§2.1)
    nonce: u64,                               // fresh random value for this Init (R2 probe)
    tip: CommittedTip,                        // height t, header, result, CommitQC (None at genesis)
    configs: Vec<(u64, ConfigSlot)>,        // for t (unless t = g), t+1 and t+2
    recent_headers: Vec<BlockHeader>,         // last W + 2 committed headers (≤ t)
}
pub struct EpochId { epoch: u64, context: Hash32 }
pub struct EpochConfig { id: EpochId, authority_generation: Hash32, first_height: u64, last_height: u64, leader_seed: Hash32, da_layout: DataAvailabilityLayout }
pub struct HeightConfig { epoch: Box<EpochConfig>, committee: Committee, params: ChainParams }
pub enum ConfigSlot { Ready(HeightConfig), PendingBoundary { boundary_height: u64, predecessor: EpochId } }
pub enum AppliedConfig {
    Continuation { after_next: ConfigSlot },
    Boundary { next: HeightConfig, after_next: HeightConfig },
}
pub struct ApplicationControlContext { instance: Hash32, epoch: EpochId, height: u64, parent_hash: Hash32, parent_result: Hash32 }
pub struct ControlWitnessContext { height: u64, view: u64, epoch: EpochId, parent_hash: Hash32, parent_result: Hash32 }
pub enum Event {
    Tick,
    Message {
        from: PublicKey,
        msg: WireMessage,
    },
    PayloadBuilt {
        req: u64,
        payload: Option<PayloadBytes>,
    },
    PayloadAuthored {
        req: u64,
        body: AvailableBody,
    },
    ControlWitnessBuilt {
        req: u64,
        context: ControlWitnessContext,
        witness: crate::types::ControlWitness,
    },
    ApplicationControlBuilt {
        message: crate::message::ApplicationControl,
    },
    PayloadReady {
        req: u64,
    },
    Executed {
        block_hash: Hash32,
        req: u64,
        outcome: ExecOutcome,
    },
    BodyAvailable {
        block: AvailableBody,
    },
    ManifestRejected {
        manifest: crate::message::PayloadManifest,
    },
    BlockApplied {
        height: u64,
        block_hash: Hash32,
        header: Box<BlockHeader>,
        config: crate::types::AppliedConfig,
    },
    PublicationRecoveryRequired {
        height: u64,
    },
    ApplyDiverged {
        height: u64,
        block_hash: Hash32,
        local_result: Hash32,
    },
}
pub enum Action {
    PersistSafety(Box<SafetyRecord>),
    StoreBody {
        block: AvailableBody,
    },
    Send {
        to: PublicKey,
        msg: WireMessage,
    },
    Broadcast {
        to: Vec<PublicKey>,
        msg: WireMessage,
    },
    BuildControlWitness {
        req: u64,
        context: ControlWitnessContext,
    },
    DriveApplicationControl {
        context: ApplicationControlContext,
    },
    ReceiveApplicationControl {
        from: PublicKey,
        message: crate::message::ApplicationControl,
    },
    BuildPayload {
        req: u64,
        height: u64,
        view: u64,
        max_bytes: u32,
        exec_budget_ms: u32,
    },
    AuthorPayload {
        req: u64,
        config: HeightConfig,
        header: BlockHeader,
        payload: PayloadBytes,
    },
    AcquirePayload {
        source: AvailabilitySource,
        manifest: crate::message::PayloadManifest,
    },
    ReceivePayloadChunk {
        from: PublicKey,
        chunk: crate::message::PayloadChunk,
    },
    DisseminatePayload {
        peers: Vec<PublicKey>,
        body: AvailableBody,
    },
    Execute {
        block: AvailableBody,
        req: u64,
        certified: bool,          // the node holds a PrepareQC at h for the block (§4.2, §6.2 step 9);
                                  // never changes the verdict; exempts the block from §4.5 CT1/CT5
    },
    DiscardExecution {
        height: u64,
        keep: Vec<Hash32>,
    },
    CommitBlock {
        block: AvailableBody,
        commit_qc: Qc,
    },
    FetchPayload {
        source: AvailabilitySource,
        peers: Vec<PublicKey>,
    },
    ServePayload {
        to: PublicKey,
        height: u64,
        block_hash: Hash32,
    },
    ServeBlocks {
        to: PublicKey,
        from_height: u64,
        max_count: u16,
        max_bytes: u32,
    },
    PayloadRejected {
        height: u64,
        view: u64,
        block_hash: Hash32,
    },
    ReportEvidence(Box<Evidence>),
    LocalFault(LocalFault),
    Halt(HaltReason),
}
pub trait Signer: Send + Sync {
    fn public_key(&self) -> &PublicKey;
    fn sign(&self, preimage: &[u8]) -> Result<Signature, SigningError>;
    fn sign_prepare(&self, request: &PrepareSigningRequest, admission: &ExecutionAdmission)
        -> Result<Signature, SigningError>;
} // deterministic; SigningError is owned by iroha_sumeragi, independent of the backend
pub trait Crypto {                                  // pure; BLS in production, fake in the simulator
    fn hash_chunks(&self, chunks: &[&[u8]]) -> Hash32; // required; exact concatenation without bulk copy
    fn hash(&self, bytes: &[u8]) -> Hash32 { self.hash_chunks(&[bytes]) }
    fn verify(&self, pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool;
    fn aggregate(&self, sigs: &[Signature]) -> Result<AggregateSignature, AggregationError>;
    fn verify_aggregate(&self, pks: &[&PublicKey], msg: &[u8], agg: &AggregateSignature) -> bool;
    fn verify_aggregate_multi(&self, groups: &[(Vec<&PublicKey>, Vec<u8>)], agg: &AggregateSignature) -> bool;
}
```
`Signer::sign` runs inside `handle` and MUST be local and non-blocking (an in-memory key or a
local device with bounded latency); a remote signer would block the core and its timers. It MUST
be deterministic (same key and preimage → same bytes; BLS signatures are): the core re-creates
recorded proposals, Commits and timeouts after a restart by signing their recorded preimages
again (§6.10 rule 0, §7.4). Prepare instead reuses its exact stored successful signature.
`sign_prepare` checks the source-bound application admission immediately before calling the
backend, then derives the canonical Prepare preimage from the private core-owned request;
it cannot sign an unrelated supplied preimage. Local admission and backend refusals neither
publish nor pool a vote. An unsigned reservation retries the check after a backend refusal.
Signers are shared as immutable `Arc<dyn Signer>` between Core and the bounded author worker.
Availability signatures are made outside `handle` after exact request/config validation; ordinary
consensus signatures retain the local bounded-latency requirement above. Payload hashing uses
`hash_chunks(&[TAG_PAY, payload])`; implementations preserve exact concatenation semantics
without allocating a full-prefix-plus-payload copy. `AvailableBody` is not serializable or
publicly constructible. `BodyRestoration` is the sole stored-body custody issuance path.

### 12.2 Driver responsibilities

Transport (authenticated P2P, routing by instance id, per-peer rate limits, traffic classes),
timer (`Tick` at `next_wakeup()`), durable safety records (one file per instance and key,
retired keys' included, never dropped) with the record-provenance rules, installation log and
store id of §7.4, a fresh random `Init.nonce` per start,
durable body store, block store (Kura), executor with a speculative-state cache keyed by block
hash (chained on certified parents), payload builder (queue; `BuildPayload` only peeks,
a successor request waits until Core has accepted the original parent's `BlockApplied` and its
exact applied-parent height/view source is live; that first activation preserves the queued
request, while later source or view withdrawal cancels its original custody;
transactions leave the queue when a block containing them is applied; `PayloadReady{req}` at most
once after an `EMPTY` answer to `req`; on `PayloadRejected` it quarantines only transactions that
make a block `Invalid` on their own, §4.2), serving `ServeBlocks`/`ServePayload`/`FetchPayload`
(`ServeBlocks` may answer with an empty `SyncResponse`), reporting executor panics and I/O errors
as `Failed`, the applied header in `BlockApplied`, and signed RS16 payload availability (§12.8):
proposals include mandatory original availability metadata, actual bytes travel as signed
rows, and Core receives only opaque `BodyAvailable`/`PayloadAuthored` custody. Core emits
`StoreBody`; O2 makes durability a prerequisite for later signature effects, not an attribute
asserted by a decoded manifest. One core instance per consensus instance; instances share nothing inside the core and
are isolated by the driver (O9).

Native Queue admission wakes the original global driver and the owned live-lane runner.
A certified lane body is separately ready for global merge only after its original
CommitQC and complete signed availability become durably published by the lane store.
That success, including an exact idempotent durable retry, wakes only the original global
driver after the store lock is released. Member and observer stores use the same edge;
local execution or a refused publication never announces a merge. Store notification
retains only a weak exact Queue bound to its original reserved/active State pool. A foreign
cold pool or replacement Queue refuses without rebinding; successful Queue retirement
suppresses delivery, and ordinary restart uses a fresh Queue. Original source checks,
coalescing, publication retry/error order and idle-no-block behavior remain unchanged.

The process-lived native worker prepares local BLS signing receipts from the retained original
execution result and exact canonical preimage, retaining each receipt across mailbox contention.
Only publication permits `Valid`, Prepare/certificate publication and application. Discard clears
the receipt before releasing its source. Mailbox custody, release-driven scheduling and
separately admitted execution-witness checks retain their bounded ownership requirements.

A new request may borrow the exact completed nonempty global payload while its original
State-funded backing and selected-input table remain live. This requires the same applied
native parent, State publication generation, height, view, byte limit and execution budget;
every request first reads and authenticates the physical canonical parent. The actual Queue
mutation fence captures the admission high-water before selection. Each original funded
Queue owner carries a checked, non-reusable incarnation, and each prepaid selected-input row
binds its exact hash and incarnation. Capture refuses rows admitted after the selection;
lending rechecks the exact live incarnations, pending status and expiry. Unrelated insertion
or removal preserves the completed payload, while selected removal or same-hash readmission
revokes it. Exhaustion latches refusal before a new input or fee reservation can publish.
The earliest actual selected-input expiry bounds physical retention; the Worker
reclaims the original owner on an idle receive timeout after rechecking its actual TimeSource,
and checks source and Queue withdrawal before every request. These checks acquire one
nonblocking State view. A genuine busy reader or publisher retains only the original paid
owner until its actual expiry, preserves the physical release observation when returning a
refusal, and permits no lend. Completing a State publication revokes the old generation;
a reader release without publication may retry the same backing. Scope capture borrows the
view whose physical parent was authenticated. The original allocation pool retains refund
notifications around the complete build body, so all State views and Queue guards retire
before a reentrant capacity callback can affect a later selection. Freed credits remain
available immediately within that original pool. Explicit queue attachment,
source or request withdrawal, rejection and execution or discard at that height retire the
retained owner. Mixed lane/Queue payloads cannot borrow completed Queue-only custody. This
preserves the Core's 200 ms build deadline and never produces an empty block or substitutes
retained bytes for unavailable native history.

A completed lane-bearing builder retains its actual original source and admitted output in
the same job. A new build request with the same height, view and complete policy may borrow
that exact output only after the fresh physical parent, stable State generation and actual
certified lane ranges and time floor are rechecked. A mixed source also retains and rechecks
its original Queue lease and actual expiry. No copied certificate or cached tip grants lending
authority. The sole canonical writer and shared-control admission are not repeated on that
same-source retry; a changed view, request, parent, journal or selected-input admission
withdraws reuse. Execution, discard, rejection or Queue attachment retires the corresponding
completion. Its original source and output retire under the existing original-pool refund
fences. This changes no Core deadline or protocol retry interval; actual autoscale and full
affected default-stack component controls must pass before liveness qualification.

A retained partial global builder must pass those fresh parent and current-scope checks
before returning its first completed output. Its signed lane merge section must equal the
current proposal from the actual lane journals, including its time floor; newly mandatory
lane work withdraws the old plan. Every selected Queue input, including in a mixed payload,
retains its original admission receipt before encoding. Selected-input removal or readmission,
actual expiry or completed State publication withdraws that receipt, so a later request rebuilds from current
inputs. The Worker checks this non-lending storage lease before unrelated State/native
refusals and includes its actual earliest expiry in the idle receive timeout. Thus expired
partial bytes refund even while their physical parent remains unavailable without a new build
request. A lane-only source borrows no Queue admission or residence deadline. A genuine busy reader or publisher,
typed resource refusal or unavailable physical parent preserves the same paid partial job
and permits no output; restoring the unchanged original source can finish the same encoded
backing without replacement or reencoding.

### 12.3 Ordering and scheduling guarantees the driver MUST honour

- **O1** Actions of one `handle` call are executed in order.
- **O2 Persist before effect.** After a `PersistSafety`, every later action (this or any later
  call) except `Execute`, `DiscardExecution`, `BuildPayload`, `AuthorPayload`, `AcquirePayload`, `ReceivePayloadChunk`,
  `BuildControlWitness`, `DriveApplicationControl`, `ReceiveApplicationControl`, `PayloadRejected`, `LocalFault` and
  `StoreBody` takes effect only after that record is durable. In particular `Send`, `Broadcast`,
  `CommitBlock` (and anything later served from the block store), `ServeBlocks`, `ServePayload`,
  `FetchPayload`, `DisseminatePayload` and `ReportEvidence` wait. A `PersistSafety` counts as durable only after every
  `StoreBody` emitted before it is durable. Records replace each other atomically; a failed write
  is retried (the instance is silent meanwhile), never skipped.
- **O3 Commit order.** `CommitBlock` actions are applied strictly in height order. The block and
  its CommitQC are durable in the block store before `BlockApplied` is reported, and
  `BlockApplied` events are reported in height order, one per height, each with the header of the
  block applied. To apply, the driver uses its original post-state of exactly that block hash
  when held, including an execution still in flight. Only a missing original before publication
  begins may execute again. If the original commitment differs from `commit_qc.result`, it
  reports `ApplyDiverged`; it cannot replace that execution by rerunning it. A missing cache
  entry is never reported as divergence. After preparation the original overlay, capture and
  certificate remain pinned through reversible refusal. Publication errors are typed: a
  `Retryable` refusal retains that owner. Certificate authority-read and certificate-part/control
  allocation refusals carry `Deferred` with their original typed source through preparation and
  the queued commit; their diagnostic text is not allocation authority. The scheduler retains
  the exact pool release observation through backoff until preparation completes. Release-driven
  dispatch and propagation from deeper execution/control/build phases remain implementation gaps.
  `RecoveryRequired` means consuming publication may have started or its worker was lost. The latter stops scheduling immediately and reports
  `PublicationRecoveryRequired`, without reexecution or a successful `BlockApplied`.
- **O4 Execution.** Execution runs off the core thread; results may arrive late or out of order;
  the most recent `Execute` is served first. The driver answers **every** `Execute` exactly once
  with its `req`: `Valid(R)`, `Invalid`, `Failed`, or `Cancelled` when a later `DiscardExecution`
  of that height left the block out of `keep` before the work finished. On a `DiscardExecution` it
  also drops the post-states of the blocks not kept (a finished execution's `Executed` may already
  be in flight; the core ignores it). It keeps the post-state of every other `Valid` execution
  until that block is applied or discarded. A post-state it needs but no longer holds (evicted
  under memory pressure, lost on restart) is recomputed: for an `Execute` whose parent is
  certified but not yet applied, by re-executing the parent from its stored body or by waiting
  for the parent's apply (bounded by `A_max`, which §8.2 L3 already budgets); for `CommitBlock`,
  as in O3. A missing cache entry is never answered `Failed` or `Invalid`.
- **O5 Event priority.** The driver delivers events to `handle` in this priority: `Tick`, then
  `Executed`/`BlockApplied`/`ApplyDiverged`/`PayloadBuilt`/`PayloadAuthored`/`PayloadReady`/
  `BodyAvailable`/`ManifestRejected` and typed publication failures, then
  control-class messages, then other messages. `Tick` is delivered within ε of `next_wakeup()`
  regardless of execution, storage or network load; the core never waits for I/O.
- **O6** Local transport admission is explicit: `Admitted` transfers one exact frame to the
  transport, while `Backpressured` returns its original message and admission ticket. The
  serving worker retains one encoded frame and original retry owner per recipient stream,
  and gives independent streams bounded turns over one shared funded codeword. A refused
  recipient cannot prevent the others from receiving later rows. Admission of a manifest
  precedes its rows for each recipient. Only admitted frames count toward
  serving charges. Closed or permanently rejected streams stop the worker. Retry handles
  obey the original node-wide gate, including closure after the first attempt. Protocol
  messages with Core retransmission timers may explicitly cancel an unadmitted occurrence.
  Proactive dissemination and requested historical responses have independent bounded job
  quotas, as do local fetches and historical reads; all use the same charged byte budget.
  Metadata replies retain at most one response per requesting peer. A newer response request
  supersedes only that peer's previous occurrence. Completed responses may be requested again.
  The Core's `DiscardExecution { height, keep }` lifetime also releases obsolete proactive
  codewords and tickets through a non-droppable `Retain` worker command before new authoring;
  application completion retires obsolete proactive streams. Retained bodies remain available
  through the authenticated serving path. Fetch retries may change their selected peer set:
  retained occurrences for peers still selected survive, removed peers are cancelled, and newly
  selected peers receive the exact source-bound request. A refused peer cannot block another
  metadata recipient, fetch source or outgoing row stream.
  Network messages may be dropped under load (lowest class first). Events other than
  `Message` MUST NOT be dropped. Ingress is bounded per `(peer, class)`, keeping the latest
  `Status` per peer and dropping the oldest message otherwise. Within a class the driver SHOULD
  serve peers round-robin, so one flooding peer cannot starve the others' control traffic.
- **O7** The driver never delivers the node's own messages back to it.
- **O8 Traffic classes.** *Control*: `Vote`, `Qc`, `Timeout`, `Tc`, `Status`, `SyncRequest`,
  `PayloadRequest`, `ApplicationControl`. *Proposal*: `Proposal`, `PayloadManifest`.
  *Bulk*: `SyncResponse`, `PayloadChunk`. The single first-release `WireMessage` table serves
  decoded objects and canonical frame classification (§3.5); no payload-presence sniffing or
  second availability frame schema is used. Egress/ingress prioritize control > proposal >
  bulk, with a guaranteed minimum share for bulk so acquisition and sync can progress.
- **O9 Instance isolation.** Each instance has its own event loop, its own record files and O2
  barrier, its own ingress queues and network quotas. A stalled or flooding instance never delays
  another instance's events, persistence or messages.
- **O10 Frame limit.** The transport accepts messages up to `max_block_bytes + FRAME_OVERHEAD` and
  `sync_max_bytes + FRAME_OVERHEAD`; the driver checks this at startup against the committed
  chain parameters. Every committed payload limit must admit a sync setting that fits both
  constraints, so chain validation reserves both frame allowances.
  It decodes every frame within the transport limit, which every later configuration is
  validated against (§9.4), never within a limit derived from the parameters at startup, and
  reports a committed configuration that exceeds the transport limit.

### 12.4 Config

`LocalParams { t_base, t_max, start_cap, decay_after, rebroadcast_interval, status_keepalive,
build_timeout, fetch_retry, sync_batch, sync_retry, sync_max_bytes, max_observers }`.
`ChainParams { block_time, payload_retry_interval, e_max, a_max, max_block_bytes,
epoch_length }` arrive in `HeightConfig` (§10.1); `demotion_window` arrives in
`Init` (genesis constant). Validation: §9.4.

### 12.5 Error policy

The core halts an instance (`Action::Halt`, then emits nothing but serving) **only** on:
1. a corrupt or incompatible local safety envelope, any retained or nested certificate that
   fails verification under its authenticated height committee and current suite (R1, R5), or a
   committed body that does not extend the committed parent (§6.9 rule 6, local corruption);
2. a detected safety violation (§7.6: a valid CommitQC conflicting with a committed block);
3. `ApplyDiverged` — the local state or executor disagrees with a certified result, so the node
   cannot follow the agreed chain; it needs an operator restore (state snapshot or re-sync);
4. `DriverAnomaly` — a driver contract violation the core detects (a `BlockApplied` out of order,
   whose header does not hash to its `block_hash`, or whose `block_hash` is not the block the core
   committed at that height, §6.13);
5. `PublicationRecoveryRequired` — the original local publication owner was consumed, may be
   visible, or was lost. The driver suppresses queued consensus effects and stops executor
   scheduling immediately. Pending safety-record writes retain their ordering and serving
   continues; only explicit recovery/restart may resume this instance.

A signer refusal yields `Action::LocalFault(LocalFault::SigningFailed { kind, height, view,
error })` and no signature or associated effect. This applies to Proposal, Prepare, Commit,
Timeout, Echo, RS16 manifest and row; a durable reservation survives failure and permits only an
identical-preimage retry. Retry reservations survive unavailable proposal bodies, and a successful
Timeout of an earlier view cannot suppress retry of the current view's reserved Timeout. `form_qc` and `form_tc` return `FormError::AggregationFailed` on
aggregation refusal, retain verified votes for retry and report `LocalFault::AggregationFailed`
without publishing or locally trusting a certificate. The existing bounded rebroadcast cadence
retries aggregation from those retained verified inputs, always selecting exactly `q = n − f`
votes even if more have arrived. `SigningError` and `AggregationError` are
object-safe Sumeragi-owned errors; no crypto-backend dependency enters the sans-IO crate. These
failures are local faults, never evidence or `Invalid` execution verdicts.

Everything else is drop / evidence / abstain / backoff: malformed or badly signed messages are
dropped; signed misbehaviour becomes `ReportEvidence`; proposals with signed-content defects, and
a leader's twin proposals in the current view, cause evidence and an early timeout; blocks that
execute to `Invalid` cause an early timeout and
`PayloadRejected`, never evidence; unattributable defects (bad payload bytes, tampered copies) are
dropped silently; executor failures and certified-block mismatches are local faults; a missing
record or a block store behind the record makes the key abstain (R2, R6); storage write failures are retried by the
driver with backoff (the node is merely slow); overload drops network messages (rebroadcast
recovers). The core never panics on any input (the decoder and every handler are fuzzed); other
instances keep running when one halts.

### 12.6 Verification discipline

The core remains one sans-IO state machine with explicit protocol and custody owners.
Changes preserve authenticated source binding, exact quorums, persist-before-effect ordering,
deterministic execution and bounded resources. Specification traceability and quorum checks
run with the crate tests; deterministic simulator scenarios and the §13.4 mutation gate
exercise safety and liveness. Whole-node and network qualification is optional engineering
evidence, never a release-signing or deployment prerequisite; governance owns deployment policy.

### 12.7 Reading the committed chain (application layer)

Not part of the core; recorded here because application code relies on the driver's block store
(Appendix E, E57). `iroha_core::sumeragi::certified_chain` reads the committed chain from Kura,
which holds one frame per height: the result-bearing block and its `CommitCertificate` (the
canonical core header, the `CommitQC` and the preimage of `R`); genesis carries a result-only
certificate (no header, no `CommitQC`) and is the chain's trust root (its hash is the network id
every transaction binds). The reader offers two reads over one State view:

1. **Committed read** (`committed_block`): the frame must be the block the view committed at the
   height (its hash in the view's block-hash journal), its core header must name the height and
   certify the block's payload (§3 rule 2: the re-derived payload hashes to `payload_hash`), and
   the preimage must commit the exact result-bearing block wire (length and hash). The receipt
   is the block, the header, `block_hash = H(header)`, `R` and the decoded preimage, and the
   certified block id `H("iroha/sumeragi/certified-block/v1" ‖ block_hash ‖ R)`. It never decodes
   the `CommitQC`. **Certificates are per node**: a header binds `parent_hash` and
   `parent_result`, never the parent's certificate, so honest nodes may store different valid
   `CommitQC`s (any `q` signers) for one block, while header and preimage are identical on every
   honest node. Deterministic code — instruction execution and anything that feeds `R` — uses
   only this read.
2. **Certified read** (`CertifiedChain::certified`, `walk`): the committed read plus the local
   `CommitQC`, which must be a Commit certificate of this height, block hash, `R`, epoch/context
   and instance `I`, and verify under `C_height`. The complete ordered keys and BLS proofs of
   possession of `C_height` are retained in `next_committee` in the preimage of `R_{height−2}`.
   Verification starts from the signed genesis registrations and iteratively authenticates each
   preceding certificate, result preimage, executed-wire identity and both parent links. A
   scheduling result cannot authenticate itself with the authority it proposes. The reader
   retains only its current parent and two upcoming authorities, so rotated-away committees
   need neither a live World registration nor an unbounded historical key cache. Verification
   always checks the exact BLS quorum under this authenticated authority. `walk` also checks
   that each block extends the previous one (core
   `parent_hash`/`parent_result` and the iroha parent hash). Off-chain consumers (signers, Torii,
   provers, bridges) use this read.

**Trust boundary.** Every non-genesis certified read verifies a genuine exact-quorum BLS
certificate under its authenticated historical authority. Missing frames, missing authority,
reordered keys, incomplete or forged proofs of possession and broken parent links are errors;
local append history is not a substitute for verification. The canonical result preimage is
at most 64 KiB and decodes under explicit Norito collection, field, allocation and nesting
limits. Authority has exactly 4..31 members in `3f + 1` geometry, 48-byte BLS-normal keys and
96-byte proofs. Genesis block and transaction signatures are verified against its network-pinned
body before the reader uses its registered authority. Genesis's `Genesis` receipt authenticates
that signed body, not the result-only execution preimage added afterwards: `R_g` is anchored by
the verified height-2 certificate's signed `parent_result`, or by independent deterministic
replay evidence. A genesis-only receipt must not be treated as independently certified execution.
No genesis quorum certificate is synthesized. `committed_block` remains the separate,
certificate-independent read for deterministic execution. Every validator retains the frames
its instructions may name, and independent certified reads require the contiguous authenticated
prefix from genesis (goal S7). Sequential reads reuse a bounded cursor; earlier-height reads
reverify from the trust root.

**Execution-time authority.** An instruction that needs the committee of a height (a
threshold-key lifecycle certificate) reads the World schedule entry for that height (§10.1), and
NPoS staking derives its scheduling epochs from the committed, immutable epoch length and the
incumbent validator generation from the authenticated epoch context in World
(`specs/staking_validator_completion.md`). None of them reads a certificate.

### 12.8 Payload availability (mandatory signed RS16 custody)

Sumeragi owns the signed layout, author/source rules, canonical availability evidence and
custody transitions. Its core includes those protocol rules; the existing
`iroha_primitives::erasure::rs16::compact` owner implements only checked codec geometry,
encoding and reconstruction. The native driver's bounded worker performs expensive jobs
outside the Core event loop. Whole-node/network qualification of this integrated candidate
remains open as engineering evidence, without blocking release signing or deployment.

**Authenticated layout.** `EpochConfig.da_layout` is mandatory and comes from authenticated
application state, never from received evidence or local defaults. Global epoch contexts bind
it. A native lane's signed creation policy pins it into the record/incarnation and genesis
result. Successor configs retain the exact layout in the absence of an authorized protocol
change. `DataAvailabilityLayout` and its validation have one owner in `iroha_sumeragi`.
The config rejects a block maximum above its signed payload maximum and validates every
`MAX_DA_*` cap. A shape is defined only for nonempty payloads within those caps.

**Canonical compact geometry.** Let maximum even row size be `c`, data count `d`, parity count
`p`, nonempty payload length `L`, and `s = ceil(L/(c·d))`. The first `s−1` stripes have row
length `c`. The last has `r = L−(s−1)c·d` bytes and row length
`ell = 2·ceil(r/(2·d)) ≤ c`. Each stripe contains `d` consecutive data rows then `p` parity
rows; flat indices are stripe-major. Only the terminal data padding is zero-filled. Thus
`N = s·(d+p)` and encoded bytes are `(s−1)c(d+p) + ell(d+p)`. All products are checked.
RS16 operates on little-endian GF(2^16) symbols with bit-identical scalar/SIMD outputs.
Small payloads use the compact terminal stripe, not a full maximum-size stripe.

**One canonical evidence format.** `AvailabilityFrame` is the existing semantic Norito
ByteSequence with a declared frame identity, carrying this exact opaque signed table:

```text
row_hash_i = H(ASCII "sumeragi/availability/row" ‖ row_i)
content    = be32(N) ‖ row_hash_0 ‖ … ‖ row_hash_(N−1)
availability_digest = H(ASCII "sumeragi/availability/content" ‖ content)
frame_inner = content ‖ manifest_sig ‖ row_sig_0 ‖ … ‖ row_sig_(N−1)
statement(kind) = ASCII "sumeragi/availability/sign" ‖ kind:u8 ‖ I ‖ E ‖
                  be64(h) ‖ be64(origin_view) ‖ bh ‖ availability_digest
manifest_sig = Sign(original_author, statement(0))
row_sig_i    = Sign(original_author, statement(1) ‖ be32(i) ‖ be32(row_len_i) ‖ row_hash_i)
```

Every signature is 96 bytes; the exact inner length is `4 + 96 + N·(32+96)`, with
`N ≤ MAX_DA_CHUNK_COUNT`. The content digest excludes signatures and the resulting `bh`, so
header hashing has no circular dependency. The complete header hash then binds that digest,
and every signature binds the resulting hash. Ordered indices and lengths are derived from
the authenticated layout, not a caller-supplied second geometry. This opaque signed table is
not a second transport codec: outer messages, certificates and the byte-domain envelope are
canonical Norito with declared layouts. A non-genesis missing table is invalid. The only empty
certificate availability field is the independently verified result-only genesis exception.

**Authority and custody.** The original author is the header's canonical proposer index under
the independently authenticated full `HeightConfig`. Core separately verifies fresh leader,
parent, epoch, TC and finality predicates; author-signature verification alone does not prove
those conditions. Re-proposals preserve the original header/table/signatures. A manifest or
row from another epoch, authority, instance, height, hash, index or exact length is rejected.
`AvailabilitySource` immutably binds the independently requested `(I,h,bh,HeightConfig)`;
`AvailableBody` retains it alongside the exact header, frame and payload. Core acceptance,
execution and publication compare it against their own independently selected source.

The complete signature table authenticates authorizations, **not received or durable body
custody**. `PayloadAcquisition` counts only distinct actual row bodies that pass the table's
signature/hash/length checks and original-pool admission. Any `d` rows per stripe reconstruct;
all received rows, terminal zero padding, payload hash/length, and every derived data/parity
row commitment must match. Only that exact verified reconstruction can become immutable
`AvailableBody`. A portable proof reader may use `verify_availability` and `verify_payload`
with caller-owned scratch; those borrowed checks cannot manufacture native custody.

**Worker and persistence contract.**

1. `AuthorPayload` retains the original funded nonempty builder payload and exact header/config.
   `PayloadAuthoring` computes the codeword and all original signatures once. A local allocation
   refusal retains completed phases and the same owners; no refusal becomes `EMPTY` or invalid
   execution. `PayloadAuthored` returns exact custody for the original request. Core rechecks
   source, header and original pool before using it.
2. `AcquirePayload` supplies the independently selected source and mandatory manifest.
   `ReceivePayloadChunk { from, chunk }` preserves the authenticated relay identity across a
   refused row. The relay identity is not original-author authority. Only successful distinct
   row admission counts as received custody. Rejected rows leave the acquisition outstanding;
   a proven manifest semantic error is distinct from resource refusal.
3. `BodyAvailable` and `PayloadAuthored` are custody completions, not durability receipts. Core
   emits `StoreBody`. The existing ordered body/safety barrier makes all required body writes
   durable before later signatures, external dissemination and commit effects (O2).
4. `BodyReader::begin_read(source)` and its retained `BodyReadJob` distinguish absence, pending
   allocation/I/O, corruption and complete `BodyRestoration`. Storage supplies untrusted bytes,
   never a trusted-local body. Restoration checks the exact independent source, complete
   original signatures, actual payload and every canonical codeword row under the original pool.
   `BodyRestoration` is the sole stored-body issuance path; no filename/existence shortcut or
   alternate trusted constructor is accepted.
5. Append/publication consumes opaque admitted custody together with the independently checked
   QC/source. Payload, frame and QC stay under the original publication owner through reversible
   refusal. Retry preserves exact original bytes; a different signature table or QC cannot
   replace an in-flight original. Once publication may be visible, owner loss requires typed
   recovery, never a new execution or fabricated successful apply.
6. `DisseminatePayload` and `ServePayload` derive rows from the original retained codeword or
   exact restored payload and reuse all original authorizations. No post-commit signing occurs.
   The current worker sends the manifest and each row to its requested peer list, with bounded
   queues, original-pool backing and serving quotas. It does not claim the retired holder-based
   forwarding bandwidth reduction. `PayloadRequest` triggers original-manifest/row repair at
   any needed height; sync carries manifests plus QCs and separately obtains actual row custody.

**Bounds and liveness scope.** Complete signed layout caps constrain row count, payload,
codeword and scratch. The State allocation pool funds retained payload/frame/row/codeword
backing and shared controls across asynchronous retries; bounded existing header hashing is a
separate metadata allocation. Worker slots and ingress/per-peer quotas bound pending work.
After GST, liveness still requires enough honest original row holders and fair worker/network
service to deliver sufficient rows. RS16 encoding, signature-table verification, acquisition,
storage and full-prefix proof costs must be included in native performance measurements;
consensus metadata counts alone are not evidence of those costs or of live settlement success.

---
## 13. Verification plan (deterministic simulator, scripted tests, driver conformance)

### 13.1 Harness

- Single-threaded discrete-event scheduler in virtual milliseconds; every random choice comes
  from one seeded PRNG; a failing run is reproduced from `(scenario, seed)`. Seed count via
  `SUMERAGI_SIM_SEEDS` (CI default 200 per scenario; nightly 10 000).
- Runs the **unmodified** `Core` (no simulation branches in protocol code) with a fake driver per
  node honouring §12.3: network model (per-link delay distribution, bandwidth, loss, duplication,
  reordering, asymmetric partitions, delay spikes); per-node clock offset and drift; per-node
  single-threaded event queue with the O5 priority lanes and O8 classes, and a virtual CPU cost
  per pairing/verification; per-node safety-record files, body store, block store and executor
  cache whose writes become durable after a latency and are **all** lost if the node crashes first;
  a deterministic executor `R = H(parent_R ‖ payload)` with per-node latency, optional poison
  payloads, injected `Failed` outcomes and an optional divergent node, which honours O4 exactly
  (answers every `Execute` once, `Cancelled` for discarded work, possibly after a `Valid` for the
  same block is already in flight; a discarded running job either finishes first or, per node,
  is aborted and answered at once) and, in F15, evicts cached post-states at random and slows
  non-empty payloads beyond the builder's estimate; a payload
  builder with a per-node transaction queue (clients may submit to any subset of nodes), request
  ids, peek semantics, `PayloadReady{req}` and per-transaction quarantine; a record store with the
  installation log and store id of §7.4 (initial record only at the installation event and never
  over an existing file, `Absent` otherwise; the key store, with its log, can be restored from an
  older snapshot, and the record store can be replaced by an empty one);
  `Init.nonce` drawn from the seeded PRNG; deterministic fake aggregate crypto that records the
  provenance `(node, key, preimage)` of every honest signature.
- Optional application clock guard of the toy application (§4.5; F39 and the named clock-guard
  tests). Each machine has a wall clock: its local clock plus a wall offset that a script may
  step without moving the core's monotonic `now`. Builders stamp each non-empty payload with a
  leading block-time record. Honest builders wait until their wall reaches the original
  committed-parent cadence and queued-transaction creation floors, retaining the original
  queue and request across clock backsteps and stale wakeups (CT3). A completed original
  payload is checked again after build latency and retained unchanged if its stamp is ahead.
  Fresh authored bodies are checked again when their queued event reaches Core, immediately
  before synchronous proposal signing; this does not gate certified re-proposals.
  Creation metadata is bound into immutable transaction bytes; Byzantine builders may
  post-date or back-date with `wall + lead`. Execution rejects stamps below the exact
  parent or original creation floors without consulting a local clock, including on
  certified replay (§4.5 "Verification"). A transaction flag marks due work. Honest
  executors answer `Failed(ClockAhead)` (CT1) and `Failed(StaleDueWork)` (CT5) only for
  `Execute { certified: false }`, never `Invalid`, and record the rule they skip for a certified
  execution. Byzantine executors run no guard, and apply never consults a clock (CT2). Without
  the guard, payloads carry no block time and no execution reads a clock (F12).
- Crash points: before/after every action and at every I/O completion (in particular between
  `PersistSafety` and its durability, between local QC formation and durability, and inside apply).
  Restart rebuilds `Init` from the fake stores.
- Byzantine nodes run scripted strategies with their own keys only; the network adversary is
  adaptive (sees all traffic, delays/drops before heal) and may relay, strip or corrupt unsigned
  parts of messages. The simulator MAY pick which identities are Byzantine after computing the
  deterministic topology of a target height (static corruption with hindsight), which is what
  exposes collector- and leader-position attacks.
- Several instances can run in one world (global + DS) with overlapping committee keys.
- **Scripted deterministic tests** drive 1–4 cores by hand (explicit event sequences, harness-held
  keys when a test needs certificates that more than `f` members signed). Every mutation in §13.4
  has one; the randomized scenarios are an additional layer, not the acceptance criterion.

### 13.2 Oracles (checked after every event; failure prints seed and trace)

| Id | Oracle |
|---|---|
| O-AGR | Agreement and prefix: per instance and height, all honest committed `(bh, R)` are equal; each honest chain is contiguous. |
| O-VAL | Validity: every honest-committed block links to the committed parent, its payload satisfies `body_ok` and is the one the proposer built, its `R` equals the reference execution, its proposer is `L(h, origin_view)` by ground-truth topology. |
| O-SIGN | Honest sign-once across restarts and record loss, per key (provenance log; probe echoes, which have no sign-once rule, are excluded): no two different preimages of one kind at `(I, h, v)`; no Prepare/Commit at a view `≤` a timeout view the key already signed at `h`; no timeout at `(h, w)` carrying `hq < v` after the key signed a Commit at `(h, v)`, `v ≤ w` (Lemma 2). |
| O-PBS | Persist-before-effect: whenever an honest signature other than a probe echo leaves a node in any form (message, certificate, block served from the block store, evidence), the node's *durable* record covers it (§7.4). |
| O-CERT | Certificate integrity: every QC/TC an honest core accepts is ground-truth valid: exactly `q_h` distinct members of `C_h`, every signature genuinely produced for exactly that preimage and instance, TC `high_pqc` equal to the true maximum. |
| O-LIVE | After heal time `t_g` (partitions healed, loss at the scenario's post-heal level, `≥ q` honest running, where a node with an unanchored key counts as faulty until it anchors and a node whose key abstains at a height counts as faulty at that height, §7.4 R2, R6), every honest running node commits a new height by `t_g + B_live` (§8.2) and again within every later window of `B_live`. |
| O-PERF | The scenario's performance bounds P1–P6 (§8.2) hold after `t_g`; F35 checks the leader-turn bound of sparse local work (E62). |
| O-CQ | Chain quality: in scenarios without crashes, over every window of `4n` committed heights that starts at least `W` heights after both `t_g` and the last height whose `skipped_leaders` names an honest member (honest demotions pass slots to successors, which may be Byzantine), the share of blocks proposed by honest members is ≥ `(n − f)/n − 0.05`. |
| O-TXP | Transaction progress: with a poison transaction present, every non-poison transaction submitted after `t_g` commits within `B_live`. |
| O-MEM | Bounded memory and storage: after every event, `status().footprint` of each core and each fake body store is within the §8.4 bounds computed from `n` and the config; for a host that owns its scheduling (§13.5), its queues (`Host::backlog`: held effects, queued records and bodies, executor operations other than `Execute`s, serving requests) are within bounds that do not grow with time. |
| O-HALT | No honest halt, except at a node where the scenario injected record corruption or a divergent executor. |
| O-EVID | Evidence soundness: honest nodes never report evidence against honest nodes. |
| O-FAULT | Local-fault soundness: an honest node emits `LocalFault(ExecutorFailed)` or `LocalFault(ExecutionMismatch)` only where the scenario injected executor failures or divergence; cancelled, discarded or evicted executions never surface as faults, `Failed` or `ApplyDiverged`. |
| O-TIME | (F39 and the clock-guard tests, §4.5) At the first honest commit of a block that carries a block time `t`, `t` is at most the smallest honest wall clock plus `2·max_clock_drift_ms`. At the first genuine honest Prepare of a due-work block, `t` is at least that signer's wall clock minus `gov.due_work_max_lag_ms`; later certified re-proposals and commits may be arbitrarily late. |
| O-AMX | (F31) Over every instance's committed reference chain: at most one `Begin`, one `Decision` and, per participant, one `Prepared` and one settlement per transaction (idempotence); `G` records `Commit` only at a height `≤ d` with a committed `Yes` from every participant, `Abort` before `d + 1` only on a committed `No`, and decides every transaction by `d + 1`; a participant applies a `Yes` escrow only on `G`'s `Commit` and releases it only on `G`'s `Abort` (an escrow leaves only through a settlement), and its ledger moves only by its escrows and settlements (atomicity); every transaction `G` decided at least the settle window (20 s) before the end is settled by every participant by the end. Non-blocking is O-LIVE, which exempts only the stalled instance. |

### 13.3 Fault scenarios (each over `n ∈ {1, 4, 5, 7, 22}` where meaningful)

F4's eight-height progress requirement is observed for at least the configured 40/60 s
window. If heights remain, the simulator captures each unfinished honest replica's existing
absolute O-LIVE deadline and fixed height target. Only a timely, oracle-observed commit may
start the next already-derived O-LIVE window; restarting a timer or changing the liveness
precondition grants no extension to a captured deadline. An empty event queue crosses that
same deadline and fails. All normal per-event and final oracles remain enabled. Named
`f04_progress_*` regressions cover slow leader rotations, noncommitting hosts, empty queues,
changed oracle windows and commits after the captured deadline.

F1 crashed leaders (≤ f, permanent) · F2 silent proxy tail · F3 withholding proxy tail (forms QCs,
delivers to a chosen subset / one node / nobody) · F4 silent or slow set-A members · F5
equivocating leader (two blocks to two halves) · F6 `f` Byzantine members withholding their votes
(in set A, as proxy tails, or both) while leading correctly · F7 adversarial TC composition
(Byzantine aggregators build TCs from the lowest-`hq` timeouts; network delays lock holders'
timeouts) · F8 split-brain (selective CommitQC delivery + partition of the committer) · F9 loss
10/20/30 %, 5 % duplication, reordering · F10 delay spikes (10× Δ windows, heavy tails) · F11
asymmetric and minority/majority partitions with heal · F12 clock skew ±10 s, drift ±1 % · F13
crash-restart at every action boundary and I/O completion, random and targeted · F14
whole-cluster simultaneous crash/restart with lost non-durable writes · F15 slow executors (one
node 10×; all nodes with `E > T_base`; injected `Failed`; random eviction of cached post-states;
all nodes with `E ∈ [T(1), e_max)` for non-empty blocks only, unforeseen by the builder, and an
executor that aborts discarded work at once — non-empty blocks must commit)
· F16 validator-set change at an epoch
boundary (add, remove, replace a majority) under load and crashes, including joiners that must
fetch their parent's body · F17 node joining 10 000 heights behind; Byzantine sync responders
(forged blocks, invalid QCs, withholding). The run budgets each height's certified-metadata and
signed-payload round trips, execution, body/block persistence and application, plus 60 s for
source rotation and live progress; the joiner must pass the complete prebuilt prefix.
· F18 floods of votes/timeouts for huge views and
heights, oversize messages · F19 poison payload (executor rejects every block holding a given tx)
→ early timeout, quarantine and a later nonempty retry · F20 cross-instance replay with shared keys · F21
nondeterministic executor at one honest node (only that node may halt) · F22 idle chain for 10⁵
retry intervals (zero committed idle heights, bounded live memory) · F23 `n ∉ {3f+1}` (5, 6, 8) with `f` Byzantine and
partitions · F24 injected safety-record corruption (that node halts, others continue); record
deletion (that key is unanchored until its probe succeeds); record deletion together with Kura
tail loss of up to 40 heights (whole-volume restore that excludes records) under the F8 / MS10a
adversary; key reinstallation (all instances `Absent`); a dataspace instance created after key
installation, whose record is later deleted; the key store (with its installation log) restored
from a backup older than a dataspace instance, once with that instance's record deleted and once
onto a new, empty record store (both → `Absent` for that instance, never an initial record, and
the existing records of other instances stay `Present`); probe echoes forged, replayed or
relayed by Byzantine peers. A node whose record was deleted counts as one of the `f` faults until
it anchors: no F24 script pairs a deletion with `f` other members that ignore probes (Byzantine,
crashed or partitioned from the prober; the Byzantine members of the F8 / MS10a adversary answer
probes), and O-LIVE counts that node as faulty until it anchors · F25 relay tampering: availability carrier or actual rows withheld or corrupted, copies from
non-members, duplicates with the same `bh`, delivered before and after the genuine proposal · F26
Byzantine body responders: corrupted actual `PayloadChunk` rows under a genuine original manifest (solicited and
unsolicited) and `SyncResponse`, answering re-proposal fetches, `pending_apply` fetches and R5 ·
F27 benign storage faults: ENOSPC/EIO on records, bodies and Kura (retried), Kura tail loss, Kura
restore from backup (records are never restored) · F28 key rotation across `h_new` with restarts on
both sides of the change, including one key at R4 and the other at R5 · F29
CPU flood: `Status` with maximal-group TCs, votes for huge views, all at the per-peer rate limit ·
F30 maximum-size blocks with the transport frame limit and sync byte caps · F31 toy AMX
application (§11): `G` and two or three dataspaces with their own committees under loss and
reordering, `G` and a dataspace stalled in turn, both relayers down for a while, a forging
relayer, one machine crash, short deadlines and legs that cannot be escrowed, and two epoch
changes per instance (a member replaced on odd seeds) → O-AMX, O-LIVE · F32 whole-cluster restart after a PrepareQC was
locked everywhere but before any CommitQC formed, and after a CommitQC formed but before any block
store made it durable · F33 hidden PrepareQC: a Byzantine proxy tail forms PQC(B, v) and delivers
it to one honest node only; the others time out with `hq < v`, discard B's execution on entering
`v + 1`, and must execute B again when TC(v+1) carries the hidden PQC and B is re-proposed ·
F34 apply-bound late entrants: one member's `BlockApplied` delayed by up to `A_max` at every
height, with `f` members crashed; joiners and just-synced nodes entering at the frontier;
executions still pending at commit · F35 local-queue asymmetry: transactions submitted only to
`f + 1` random members (the holders) of an idle chain, with and without one crashed non-holder;
no timer moves on a local queue, so workless leaders time out → every height commits by the first
view `v ≥ 1` led by a running holder, within the leader-turn bound of entering it, and every
transaction by the second height first committed after its submission (E62) ·
F36 late leaders: up to `f` members send their view-0 proposal `T(start)/2 + 100 ms` after the
honest anchor `t_enter + P(0)`, or the proposal at once without its payload and the body that much
later (requests are withheld until row release, then served so reordered rows can be fetched),
so that every such view still commits → no honest start level rises before the deliberate
crash; later one honest member crashes → every gap stays within the P4 leader-turn bound.
A crash during certificate exchange may legitimately raise the start level when actual
body-to-commit latency exceeds `T(start)/2` (§9.2); seed 1813 distinguishes this from waiting
for a late body · F37
exact-quorum adversary (`sim::scenarios::exact_quorum_adversary`): a Byzantine aggregator
over-aggregates genuine votes into `q + 1`-signer certificates; the certificates must be refused
while exact-quorum traffic still commits. The named test
`exact_quorum_under_genuine_superset_attack` checks certificate validity and continued progress
→ O-CERT, O-LIVE · F38 a lane
instance next to the global one (`specs/sumeragi_lanes.md` §4.1): the lane's pinned committee is
four of the global validators, every other machine follows the lane as an observer (a node runs
every instance), the lane stalls while the global instance keeps finalizing, and a global validator
that only observes the lane crashes and restarts → every replica of both instances, observers
included, commits after the lane recovers (O-LIVE, O-AGR) · F39 application clock guard (§4.5):
every honest wall clock is within `[0, max_clock_drift_ms]` of real time, a third of the
transactions apply due work, and `f` Byzantine members run no guard. Their builders date blocks
`+2·max_clock_drift_ms`, far in the future, or older than `sumeragi.due_work_max_lag_ms`, in turn.
Variant 0: the Byzantine members vote or withhold every vote. Variant 1: as variant 0, and one
honest wall clock jumps 30 s ahead for 15 s, then converges back. Variant 2: an F33 hidden-PrepareQC
proxy tail, and every transaction applies due work, so re-proposals are older than the lag and
execute only as certified. → O-TIME, O-LIVE, O-AGR, O-FAULT (the guard's refusals are local
faults).

### 13.4 Mutations that MUST be detected

Each mutation exists only in a test build (`cfg(sumeragi_mutation = "Mxx")`) and is exactly the
code change given in the table: a named function (§6.0 names; "fake driver" means the
simulator's driver, and the production driver in §13.5) and the change made to it. CI runs a
**meta-check**: for every mutation it builds the mutated crate, runs the named deterministic
test(s) of that row, and fails unless at least one of them fails; the unmutated build must pass
them all. CI additionally runs the listed randomized scenario (≤ 200 seeds) as a second line.
Every named test was checked against the other guards of this specification so that the mutated
rule is the only thing standing between the scenario and the failure; where an in-process guard
masks a rule (noted in the table), the test uses a restart or a nested certificate instead.
Detection needs targeted adversaries: random faults alone did not kill the TC-rule,
`tc-min-highqc` or `forget-timeout` mutations in the previous attempt.

**Safety rules (one mutation per rule of §7.1).**

| Id | Site — change | Named deterministic test (setup → expected) | Randomized scenario | Oracle |
|---|---|---|---|---|
| MS1 | `propose` — rule 0 skipped: after a restart the leader builds a new block although `safety.proposal` holds one at `(h, view)` | `det_s1_leader_restart_no_second_proposal`: n=4, X = L(h,0) proposes B; crash after its `PersistSafety` is durable and the proposal is signed, before the `Broadcast` executes; restart; the builder now returns C → X sends B (identical bytes) or nothing, never C | F13 targeted at leaders | O-SIGN |
| MS2 | `try_prepare` — condition 2 (`safety.prepare` has no entry at `view`) deleted | `det_s2_s27_prepare_once_across_restart`: n=4, harness-signed twins B, B′ of L(h,v); X Prepares B, record durable; crash; restart (R4, record intact); deliver B′ and `Executed(Valid)` for it → no Prepare for B′. (In-process the mutation is masked by §6.2 step 2, which holds only the first twin; hence the restart.) | F5 + F13 | O-SIGN |
| MS3 | `advance_to` keeps `proposal` **and** `try_prepare` checks only that a proposal is held, not `proposal.view == view` (SR3 has two guards; the mutation removes both) | `det_s3_no_prepare_for_old_view_proposal`: n=4, X accepts proposal(B, v), `Execute{B, r1}` pending; harness TC(v) with `high_pqc = PQC(B, v)` (so B's entry survives the discard); X enters v+1; `Executed(r1, Valid(R))` → no Prepare until a proposal of v+1 is accepted, then exactly one Prepare(h, v+1, B, R) | F10 + F33 | direct assertion (the premature Prepare has the legitimate preimage, so O-SIGN cannot see it) |
| MS4 | `try_prepare` and `try_commit` — `timeout_view < view` deleted | `det_s4_fence_across_restart`: X signs timeout(h, w, hq = None), durable; crash; restart (view = w, timeout_view = w); deliver proposal(w) with `Executed(Valid)`, then PQC(w) → no Prepare and no Commit at w | F7+F13: delay PQC(B,v) past honest timeouts, release it while v+1 commits C | O-SIGN, O-AGR |
| MS5 | `try_commit` — `high_pqc.view == view` deleted | `det_s5_no_commit_stale_qc`: X in (h, v+1) via TC(v) with no PrepareQC, no proposal at v+1; deliver PQC(B, v) (lock rises; §6.5 2e does not fire); advance time past `anchor + φ·T` so stage 2 is entered and `try_commit()` runs → no Commit | F8 | O-AGR, direct assertion |
| MS7 | `on_qc` step 2a — `high_pqc = c` unconditionally | `det_s7_lock_monotone`: X locks PQC(B1, v1); deliver W's harness-signed TimeoutVote at view v1 carrying PQC(B0, v0), v0 < v1 (a top-level `Qc` would be cheap-rejected, §6.1 rule 5); X times out → its timeout carries hq = v1 | committer receives an older PQC nested in a timeout | O-SIGN, O-AGR |
| MS8 | `sign_timeout` — carries `None` instead of `high_pqc` | `det_s8_timeout_carries_lock`: lock PQC(v), time out at v → hq = v | MS10a scenario, committer inside the TC | O-SIGN, O-AGR |
| MS9 | `on_tick`, rebroadcast rule 1 — re-signs `TimeoutVote(h, w, high_pqc)` instead of re-sending `mine.timeout` | `det_s9_timeout_resend_exact`: timeout(w, None); then PQC(w−1) arrives (lock rises, no view change); rebroadcast tick → the re-sent timeout is byte-identical (hq = None); a TC X forms then has X's entry with hq = None | F9 + F7 | O-SIGN, O-EVID |
| MS10a | `propose` rule 2 always builds a fresh block **and** `on_proposal` step 6 checks every TC-justified proposal as fresh | `det_s10a_tc_rule_forces_reproposal`: X = L(h, v+1) gets TC(v) with `high_pqc = PQC(B, v)` → X re-proposes B's header unchanged; voter Y gets a harness-signed fresh C justified by that TC → no Prepare, evidence | F8 n=4: Byzantine P(h,v) forms PQC+CQC(B), delivers the CQC only to X, partitions X until TC(v) forms; the leader proposes C | O-AGR |
| MS10b | `on_proposal` step 6 — the TC-rule branch deleted (a TC with `high_pqc = Some(Q)` is checked like a fresh block) | `det_s10b_voter_rejects_tc_violation`: harness-signed fresh proposal C at v whose TC names Q with `C ≠ Q.bh` → no Prepare, `InvalidProposal` evidence, early timeout | n=7, f=2: Byzantine P(h,v) and L(h,v+1) | O-AGR |
| MS11 | `form_tc` — chooses the `q` entries with the lowest `hq` and sets `high_pqc` to the PrepareQC of the lowest non-`None` `hq` | `det_s11_tc_max_hq`: n=4, X receives timeouts for (h, v2) with hq = None, v0, v1 in that order → the TC formed at the third has `high_pqc` of view v1 | B0 locked by Y only, B1 committed by X only, TC(v1) holds Y and Z | O-AGR, O-CERT |
| MS12 | `verify_tc` — the check `high_pqc.view == max(entries.hq)` deleted | `det_s12_tc_verify_rejects_low_high_pqc`: harness TC with max hq = v1 and `high_pqc` = PQC(v0) → rejected, no view change | Byzantine L(h,v+1) attaches an older PQC to honest timeouts | O-CERT, O-AGR |
| MS13 | `quorum(n)` returns `2·f + 1` | `det_s13_quorum_n5`: n=5 (q=4): a QC with 3 valid signers is rejected, and 3 matching votes form no QC | F23 n=5 split | O-CERT, O-AGR |
| MS14 | `verify_qc` — accepts `popcount ≥ q − 1` | `det_s14_qc_popcount`: QC with q−1 valid signers → rejected | Byzantine P + partition | O-CERT, O-AGR |
| MS15 | every caller of `verify_qc` passes the configuration of `tip.height` instead of `C_{qc.height}` | `det_s15_committee_of_height`: one member replaced at h_new; X in round h_new; harness CommitQC(h_new) signed by `q` members of `C_{h_new−1}` including the removed one → rejected, no commit | F16 | O-CERT, O-AGR |
| MS16 | `vote_preimage`, `prop_preimage`, `tmo_preimage` omit `I` | `det_s16_cross_instance_replay`: instances I1, I2 with one committee; a vote and a QC of I2 with the unsigned `instance` field rewritten to I1 (else §6.1 rule 1 drops them) → rejected by I1 | F20 | O-CERT, O-AGR |
| MS17 | `vote_preimage` omits `R` | `det_s17_result_bound`: a genuine PQC(B, R) with `result` rewritten to R′ → rejected | Byzantine P rewrites `result` in its QCs | O-VAL, O-HALT |
| MS18 | `on_proposal` step 1 — verifies `p.sig` under any member of `C_h` instead of `C_h[L(h, w)]` | `det_s18_non_leader_proposal_dropped`: proposal signed by non-leader W with `proposer = idx(L(h, w))`, otherwise valid → dropped silently: no Prepare, no evidence, no timeout | Byzantine non-leaders race proposals every view | O-VAL, O-LIVE |
| MS19 | `on_proposal` steps 5–6 — `parent_qc`, `parent_hash` and `parent_result` checks deleted | `det_s19_wrong_parent_rejected`: signed proposal on a stale parent → evidence, early timeout, no Prepare | Byzantine leader builds on a stale parent | O-VAL, O-AGR |
| MS20 | `VerifiedAvailability::accepts_row`: actual received-row digest equality skipped, retaining exact row shape | `acquisition_rejects_corrupt_actual_row_before_counting_custody`: altered actual bytes fail at `PayloadAcquisition::push`, before row counting or ownership admission; wrong length/index also reject and preserve the original input | F26 | O-VAL |
| MS20b | `AvailabilitySource::check_header`: independent instance/height/epoch/block-hash bindings skipped, retaining structural bounds | `source_bound_storage_job_never_confuses_refusal_with_absence_or_rebinds_source`: the same stored bytes cannot be rebound to another requested source after local resource recovery | — | O-VAL |
| MS20c | `VerifiedAvailability::check_payload`: payload hash equality skipped, retaining length | `signed_inconsistent_codeword_and_payload_commitments_are_rejected`: valid original row signatures cannot authorize a reconstructed payload with another signed payload hash | — | O-VAL |
| MS20d | `VerifiedManifest::reconstruct`: regenerated row commitments skipped, retaining codec and row shape checks | `signed_inconsistent_codeword_and_payload_commitments_are_rejected`: k correct received rows cannot authorize a signed inconsistent withheld parity row | — | O-VAL |
| MS20e | `VerifiedAvailability::check_codeword`: complete re-encoded row commitments skipped, retaining codeword shape | `stored_body_restoration_checks_actual_codeword_without_resigning_or_copying_payload`, `signed_inconsistent_codeword_and_payload_commitments_are_rejected`: stored and portable payloads must match every original signed row commitment, including withheld rows | — | O-VAL |
| MS21 | `commit_height` step 1 — no verification when the CommitQC came from a `Status` or a proposal's `parent_qc` | `det_s21_forged_commitqc_via_status`, `det_s21_forged_commitqc_via_parent_qc`: forged CommitQC for h → no commit | Byzantine Status/proposal with a forged CommitQC | O-CERT, O-AGR |
| MS22 | `on_sync_response` — `block_hash(header) == c.block_hash` and the parent checks deleted | `det_s22_sync_forged_block`: a genuine CommitQC paired with a forged block → rejected, no commit | F17 Byzantine responder | O-VAL, O-AGR |
| MS23 | `try_prepare` — `route(vote)` emitted before `persist()` | `det_s23_crash_between_persist_and_durable`: equivocating leader (twins B, B′); X Prepares B; crash before the record is durable; restart; B′ delivered → the network never carries Prepares of X for both B and B′ | F13 targeted | O-PBS, O-SIGN |
| MS24 | fake driver — the O2 barrier holds only `Send`/`Broadcast` | `det_s24_local_cqc_not_exposed_before_durable`: X = P forms CommitQC(B,v) including its undurable Commit, W sync-requests, X crashes → nothing carrying X's signature left X; the two-block commit of the revision-2 review scenario is impossible | F13 at every I/O completion | O-PBS, O-AGR |
| MS25 | `persist` — does not copy `high_pqc` into `safety.lock` | `det_s25_lock_persisted_with_commit`: X Commits at (h,v); the CommitQC reaches only W; X crashes before timing out; restart; X times out → hq = v | F8 + F13 (Commit, CommitQC to one node, crash before timing out) | O-SIGN, O-AGR |
| MS26 | `sign_timeout` — `safety.timeout` not set (forget-timeout) | `det_s26_forget_timeout`: durable timeout at v (hq = None), crash, restart, deliver PQC(B, v) → no Commit at v | targeted restart after timeout while v+1 commits C | O-SIGN, O-AGR |
| MS27 | `try_prepare` — `safety.prepare` not set (forget-prepare) | `det_s2_s27_prepare_once_across_restart` (as MS2) | F5 + F13 churn | O-SIGN |
| MS29 | `propose` — `safety.proposal` not set | `det_s29_forget_proposal`: MS1's scenario → X sends B or nothing, never C | F13 at leaders | O-SIGN |
| MS30 | `restore` step 4 — `high_pqc` not set from the recorded lock | `det_s30_lock_restored`: record with lock PQC(v); restart; time out → hq = v | MS10a scenario with committer restart | O-SIGN, O-AGR |
| MS31 | `restore` — `Absent` classified as R3 (fresh at `t + 1`) | `det_s31_deleted_record_abstains`: n=4, X Commits at (t+1, 0), record deleted, block store intact; restart → X signs nothing at t+1 or t+2; after W, Y, Z (`2f + 1 = 3`) report heights ≤ t'+1 in signed echoes it signs from t'+3 | F24 deletion under the MS10a adversary | O-SIGN, O-AGR |
| MS31b | `restore`, R2 — anchors at once with `abstain_below = t + 3` from the local block-store tip (the revision-3 rule), no probe | `det_s31b_record_and_store_lost`: n=4 (W, X, Y honest, Z harness-Byzantine); at (100, 0) X, Y, Z Prepare B; Z gives PQC(B,0) to X and Y only; X and Y Commit; CommitQC(B,0) reaches Y only; Y's messages are delayed; X's record is deleted and its Kura truncated to 60; restart; X syncs 61..99 from W and enters 100 → X signs nothing at 100 while Y's fresh reply (height 101) is missing; no second block commits at 100 | F24 deletion + Kura tail loss under F8 | O-SIGN, O-AGR |
| MS31c | `on_status` — answers probes while a configured key is unanchored or abstaining | `det_s31c_abstaining_node_does_not_answer`: Y has an `Absent` record (unanchored); X's probe → Y sends no `Status` with `echo`; after Y is anchored and past `abstain_below` → it answers | F24 with two simultaneous deletions | O-SIGN, O-AGR |
| MS31d | `on_status` — counts every `Status` from a member of `C_{t'+2}` as a probe reply for its sender (`echo` not required) | `det_s31d_stale_status_is_not_a_reply`: X's record deleted; a `Status` Y sent before X's crash (height ≤ t'+1) arrives late, Y's fresh reply reports t'+2 → X stays unanchored | F24 + F10 | O-SIGN, O-AGR |
| MS31e | `on_status` step 1 — the echo signature is not verified (a reply counts for the key its `Echo` names) | `det_s31e_echo_signature`: n=4 (W, X, Y honest; Z harness-Byzantine, leader of (t+3, 0)); X Prepared B at (t+3, 0), then lost its record and its Kura above t; W and Y are in round t+3; X restarts at tip t; Z sends X, with X's nonce, echoes that name W and Y, report height t+1 and carry Z's signature, plus its own valid echo → X stays unanchored; X syncs to t+2; Y's valid echo (height t+3) reaches X only relayed by Z, W's directly → X anchors at t' = t+2 (a relayed signed echo counts) and never Prepares Z's twin B′ at (t+3, 0) | F24 with forged, replayed and relayed echoes | O-SIGN, O-AGR |
| MS32a | `restore` step 2 — R5 commits `parent_commit_qc` without verifying it | `det_s32a_r5_forged_parent_qc`: record at t+2 (valid checksum) whose `parent_commit_qc` does not verify under `C_{t+1}` → `Halt(SafetyRecordInconsistent)`, no commit | F26 at R5 | expects `Halt` |
| MS32b | `restore` step 3 — R6 classified as R3 | `det_s32b_store_behind_record`: record at t+5 with a Commit (lock) at (t+5, v); Kura at t; restart → X signs nothing below t+5 and resumes at t+5 with the lock | F27 Kura tail loss | O-SIGN, O-AGR |
| MS32c | `on_body` (§6.9 rule 6) — the parent-link check of the `pending_apply` flush deleted | `det_s32c_r5_block_not_extending_tip`: R5 with a harness-valid CommitQC(t+1) whose block's parent is not the local tip (simulated block-store corruption) → `Halt(SafetyRecordInconsistent)` when the body arrives, no `CommitBlock` | — | expects `Halt` |
| MS33a | fake driver record store — one file per instance for all keys | `det_s33_key_rotation_restart` (a): rotation K1 → K2 at h_new, restarts at h_new − 1 and h_new → each key keeps its own record, no halt, no double signature | F28 | O-SIGN, O-HALT |
| MS33b | `enter_height` — `signer` = the first configured key, regardless of membership in `C_h` | `det_s33_key_rotation_restart` (a): X signs at h_new with K2, never with K1 | F28 | O-SIGN, O-LIVE |
| MS33c | `restore` — keys classified against the pre-R5 tip rather than the advanced tip | `det_s33_key_rotation_restart` (b): one authenticated committee, K1 retired after its real height-t+1 round, active K2 with a real record at t+2; truncate the store to t and retain both original records → start in round t+2 from K2's record, exactly one `CommitBlock` for t+1, the tip never moves back | F28 with R4/R5 splits | O-AGR, O-SIGN |
| MS33d | fake driver record store — the store-id comparison deleted (a rolled-back log is trusted: a key it lists as generated on this node gets an initial record for every instance the log lacks) | `det_s33d_installation_log_rollback`: key K generated on X; dataspace instance I created later (initial record, `(I, K)` entry, new store id); X Prepares B at (t+1, 0) for I, block store at t; X's key store is restored from a snapshot taken before I existed and X's record for I is deleted; restart → the driver marks K imported, `Init` carries `Absent` for (I, K), and X does not Prepare the twin B′ at (t+1, 0); variant: the same old key store onto a new, empty record store → `Absent` likewise | F24 (key store restored from an older backup) | O-SIGN, O-AGR, direct assertion on `Init` |
| MS34 | fake driver apply — the commitment comparison skipped | `det_s34_apply_divergence_halts`: X's executor diverges deterministically (cached and re-executed commitments differ from `commit_qc.result`) → `ApplyDiverged` → `Halt` | F21 | O-VAL, O-HALT |
| MS35 | `on_manifest_rejected`: an unsigned availability-carrier rejection early-times-out the held current-view proposal | `det_s35_relay_tamper_no_evidence`: altered or stripped carrier bytes cannot accuse or time out the original author; the genuine carrier still executes and Prepares | F25 | O-EVID, O-PERF |
| MS36a | `on_executed` step 3 — the certified branch (`Invalid` for a certified block, or `Valid(R ≠ expected_R)`) handled like uncertified `Invalid` | `det_s36_certified_mismatch_is_local` (a): re-proposal of certified B; X's executor returns `Invalid` → `LocalFault(ExecutionMismatch)`, no early timeout, no `PayloadRejected`; X still Commit-votes on PQC | F21 | O-FAULT, O-LIVE |
| MS36b | `on_executed` step 2 — `Failed` handled like `Invalid` | `det_s36_certified_mismatch_is_local` (b): uncertified block, executor returns `Failed` → `LocalFault(ExecutorFailed)`, retry, no early timeout, no `PayloadRejected` | F15 with injected `Failed` | O-FAULT, O-LIVE |
| MS37 | `on_qc` step 1 — the §7.6 monitor branch deleted | `det_s37_conflicting_commitqc_halts` (harness keys): conflicting CommitQC for `tip.height` → `Halt(SafetyViolation)` | — | expects `Halt` |
| MS38 | `on_vote` — `pool_insert` before the signature check | `det_s38_forged_votes_never_pooled`: n=4, `q − 1` forged Commit votes under honest signer indices plus one genuine one reach `P` → no CommitQC, no commit, no stage change; the genuine votes still form a QC later | F18 with forged-signature votes at every node | O-CERT, O-AGR |
| MS39 | `verify_qc` — accepts more than `q` genuine signers | `det_s39_qc_exact_signer_count`: exact `q` subsets verify for Prepare/Commit; `q + 1` genuine signers are rejected | — | O-CERT |
| MS40 | `verify_tc_inner` — accepts more than `q` genuine timeout entries | `det_s40_tc_exact_signer_count`: both full and cached-high-QC paths reject under/over counts while accepting differing exact-quorum subsets; TC formation from a larger pool projects exactly `q` | — | O-CERT |
| MS41 | `form_qc` — emits a QC from more than `q` votes | `det_s41_form_qc_exact_signer_count`: each vote kind accepts exactly `q` and rejects `q - 1` / `q + 1` inputs; preserved signer order | — | O-CERT |
| MS42 | `PublicationRecoveryRequired` handler — ignores the irreversible local failure | `det_s42_original_publication_recovery_halts`: the original publication cannot retry, so halt immediately, sign/schedule nothing and retain serving | — | O-HALT, O-SIGN |
| MS49 | Native codec converts scoped resource refusals to malformed-frame text | `scoped_decode_refusal_is_not_malformed_native_evidence`, `codec_resource_errors_survive_lossless_norito_conversion`: preserve exact typed refusals, retry identical bytes outside the refused scope, and continue rejecting corrupt frames | — | typed refusal and exact retry |
| MS50 | Static byte-domain length violations become retryable local resource refusals | `protocol_byte_lengths_are_terminal_codec_errors`: reject empty or oversized availability rows and oversized control witnesses as malformed bytes; valid rows still retry after local decode limits are removed | — | permanent wire bounds versus local limits |
| MS51 | `request_exec` — emits `Execute { certified: false }` for a block that a held PrepareQC certifies (the application clock guard of §4.5 then applies to certified re-proposals) | `f33_hidden_prepareqc_due_work_block_commits_after_lag`: n=4 F33 with the simulator's clock guard, every transaction applies due work; a Byzantine proxy tail hides PQC(B) of a due-work block B; the views fail until a TC carries PQC(B) and B is re-proposed past `sumeragi.due_work_max_lag_ms` of the honest wall clocks → the honest nodes execute B with `certified = true` (CT5 skipped), Prepare, and B commits in a later view. `det_s51_execute_certified_flag`: a fresh block and its retry after `Failed(ClockAhead)` are executed with `certified = false`; after TC(1) carries the hidden PQC(B, 0), the re-proposal and its retry after `Failed(StaleDueWork)` are executed with `certified = true`, and X Prepares `Q.result`; on a second core, a PQC(C, 0) formed by the others reaches X while the guard refuses C, and the retry of C is executed with `certified = true` (the node's lock) | F39 | O-LIVE |
| MS52 | fake driver executor (the simulator's model of §4.5) — CT1 deleted: an honest executor never answers `Failed(ClockAhead)` | `clock_guard_certified_time_within_two_drifts`: n=4, two honest wall clocks at `+max_clock_drift_ms`, one at real time; a Byzantine member that votes proposes in turn blocks dated `+2·max_clock_drift_ms` and far-future blocks → the far-future blocks are refused and never commit, and every committed block time is within `2·max_clock_drift_ms` of the smallest honest wall clock. Under MS52 a far-future block commits. `clock_guard_liveness_with_f_plus_one_slow_clocks` also detects it | F39 | O-TIME |
| MS53 | Accept a zero-length proposal at a later view | `empty_proposals_are_rejected_at_every_view`: reject empty fresh proposals and certified re-proposals at every view | — | O-SIGN, nonempty work |
| MS54 | A refused local signature is published and pooled | `det_signing_refusal_prepare_preserves_reservation_without_pooling`: refusal retains the reservation, emits only a local fault and permits only the identical retry | — | O-SIGN, O-CERT |
| MS55 | A refused aggregation is accepted as a locally formed certificate | `det_aggregation_refusal_retains_verified_votes_without_certificates`: QC/TC refusals retain verified votes and publish no certificate | — | O-CERT |
| MS56 | Safety envelope accepts another consensus suite or certified-result contract identity | `det_s56_safety_record_refuses_other_protocol_identity`: a checksummed foreign envelope is refused without reinterpretation | — | O-SIGN |
| MS57 | Restart skips verification of retained or nested QCs and TCs | `det_s57_restart_verifies_every_retained_certificate`, `det_s57_recommit_refuses_unverified_retained_lock_before_advancing_tip`: every corrupted retained/nested certificate refuses startup before installing a lock or advancing the tip | — | O-CERT, O-SIGN |
| MS58 | Skip aggregation retry from retained verified input votes | `det_aggregation_refusal_retains_verified_votes_without_certificates`: recovery of the local backend permits an exact-quorum QC or TC on the bounded retry cadence | — | O-LIVE, O-CERT |
| MS59 | RS16 authoring substitutes a signature after local refusal | `det_signing_refusal_manifest_retains_original_request`, `det_signing_refusal_row_retains_completed_signatures`: no completed body appears and the identical original request resumes | — | O-SIGN |
| MS60 | Skip reserved local signature retry on the rebroadcast cadence | `det_signing_refusal_proposal_preserves_reservation_without_publication`, `det_signing_refusal_timeout_preserves_original_high_qc_on_retry`: backend recovery resumes only the identical reserved preimage on a due tick | — | O-LIVE, O-SIGN |
| MS61 | General Status admission suppresses a probe retry after refused Echo signing | `det_signing_refusal_echo_does_not_consume_rate_limit`: refusal consumes no successful-Echo allowance, identical retry succeeds and subsequent successful sends remain rate-limited | — | O-LIVE |
| MS62 | A retained earlier-view Timeout suppresses current-view signing retry | `det_signing_refusal_current_timeout_retries_with_prior_timeout_retained`: the current reserved Timeout retries despite an earlier successful Timeout | — | O-LIVE, O-SIGN |
| MS63 | Periodic proposal retry consumes its marker while the original body is unavailable | `det_signing_retry_retains_restored_proposal_until_delayed_body_arrives`: the marker survives a due tick, and delayed original body delivery resends the exact recorded proposal | — | O-LIVE, O-SIGN |
| MS71 | first Prepare signs without consulting its original application admission | `det_ct5_cached_execution_waits_for_stage_and_checks_actual_first_signing_time`, `det_ct5_world_retained_execution_rechecks_clock_at_first_prepare` | — | Cached Valid cannot bypass first-Prepare freshness after stage delay; a retained World result must not sign after its actual wall clock advances. |
| MS72 | restore synthesizes a successful signature from an unsigned Prepare reservation | `det_ct5_unsigned_prepare_reservation_restart_never_synthesizes_first_signature` | — | a durable unsigned reservation cannot synthesize a first Prepare without fresh source-bound execution or a genuine matching PQC. |
| MS73 | restore accepts a checksummed fabricated successful Prepare signature | `det_ct5_successful_prepare_signature_is_exact_durable_and_authenticated_on_restart` | — | a checksummed fabricated successful signature is not restart authority. |
| MS64 | Parent-only R5 recommit waits for the successor authority that applying the parent activates | `det_s64_recommit_parent_only_record_authenticates_boundary_before_resuming`, `det_s33_key_rotation_restart`: independently verify the parent CommitQC, recommit it once, then authenticate and restore the successor key's reservation; retained successor-height QCs/TCs still require their own authenticated authority before any installation | — | O-LIVE, O-CERT |
| MS65 | Simulated execution and first-Prepare admission omit CT5 | `clock_guard_due_work_lower_bound_at_first_prepare`: a Byzantine voter backdates due-work proposals beyond the allowed lag; the first genuine honest Prepare oracle detects stale acceptance, while the baseline rejects stale proposals and permits honest leaders to progress | F39 | O-TIME |
| MS66 | Fake driver executor omits CT1's clock-drift allowance | `clock_guard_accepts_exact_drift_allowance`: an honest block exactly one allowed drift ahead of a slow honest voter remains admissible; `clock_guard_liveness_with_f_plus_one_slow_clocks` also exercises this allowance across four- and seven-node worlds | F39 | Direct assertion, O-LIVE |





Removed as equivalent mutants (revision 4, Appendix C): **MS6** (Commit sign-once check deleted)
and **MS28** (Commit not recorded). A second, different Commit in one view is unreachable
whatever the check: `try_commit` signs only over `high_pqc` of the current view, a second
PrepareQC of a locked view is cheap-rejected (§6.1 rule 5) and never replaces the lock (§6.5 2a
strict `>`), and the lock is durable before the Commit leaves and restored after a restart (SR25,
SR30). Revision 4 therefore removed the redundant `commit` field; SR6 is covered by MS5, MS7, MS25
and MS30.

**Liveness rules.**

| Id | Site — change | Named deterministic test (setup → expected) | Randomized scenario | Oracle |
|---|---|---|---|---|
| ML1 | `level` — returns `start(h)` (ignores `v`) | `det_l1_levels_grow`: n=4, every execution takes `1.5·T_base` → the height commits within `k* + 1` views | F15: all executors `1.5·T_base` | O-LIVE |
| ML2 | `on_tick`, rebroadcast rule 1 deleted | `det_l2_lost_timeout_resent`: the first broadcast of every timeout is dropped → TC forms after the re-sends | F9 20 % | O-LIVE |
| ML3 | `try_prepare`/`try_commit` — condition "in set A or stage ≥ 1" replaced by "in set A" | `det_l3_setb_joins_stage1` (a): n=4, a non-P set-A member silent → view 0 commits through set B | n=7: two Byzantine set-A members withhold votes but lead correctly | O-PERF P2, O-LIVE |
| ML4 | stage-2 triggers (a) and (c) deleted (only `anchor + φ·T` remains) | `det_l4_stage2_timing`: silent P → stage 2 at `t_lastvote + 2·t_retx` (asserted time) | F3 | O-PERF P3 |
| ML5a | `on_tick` — vote retransmit deleted | `det_l5_lost_vote_retransmitted` (a): X's Prepare to P dropped once → re-sent at `t_vote + t_retx` | F9 5 % at n=22 | O-PERF P1 |
| ML5b | `on_vote` step 2 (PrepareQC answer) deleted | `det_l5_lost_vote_retransmitted` (b): P holds PQC(v); a retransmitted Prepare of v arrives → P sends the PQC to that voter | F9 5 % at n=22 | O-PERF P1 |
| ML6 | §9.2 decay branch deleted | `det_l6_level_decays`: after `decay_after` fast commits the start level drops by one | F15 transient | O-PERF P1 |
| ML7 | `demoted_set` returns ∅ | `det_l7_demotion_golden`: leader of (h,0) silent, commit at view 1 → from h + 2 it is in `D`, its slot's view-0 leader is its successor, other heights' leaders unchanged | F1 | O-PERF P4 |
| ML8 | `timeout_insert` — join rule deleted | `det_l8_join_f_plus_1`: `f + 1` other members' timeouts at w ≥ view → X signs a timeout at w | F11 | O-LIVE |
| ML9 | `persist` — `high_tc` not copied | `det_l9_restart_after_tc_entry`: n=4, D silent, X alone forms TC(6), enters 7, times out, restarts → all reach 7 and commit | F13 + F11 | O-LIVE |
| ML10 | `on_proposal` step 8 — `StoreBody` omitted | `det_l10_cluster_restart_lock_no_cqc`: PQC(B) locked everywhere, no CQC, whole-cluster restart → B is re-proposed and commits | F32 | O-LIVE |
| ML11 | `on_block_request` — ignores requests for heights ≤ `tip.height` | `det_l11_pending_apply_after_peers_moved_on`: X committed h without the body while peers moved on → X's `PayloadRequest` is answered, `pending_apply` drains | F16 joiners; equivocating leader | O-LIVE |
| ML12 | fake driver scheduler — FIFO ingress without the O5 priority lanes | `det_l12_tick_ahead_of_flood`: a flood of `Status` at the rate limit → every `Tick` handled within `ε_tick` | F29 | O-PERF P6, O-LIVE |
| ML13 | Suppress fresh payload building after view 0 | `det_l13_late_views_build_nonempty_work` | F19 | O-VAL, O-TXP |
| ML14 | fake builder — ignores `PayloadRejected` | `det_l14_poison_quarantined`: poison transaction proposed once, then never again by that builder; other transactions commit | F19 | O-TXP |
| ML15 | `on_tick`, Status — keepalive cadence only | `det_l15_unsettled_status_rate`: X at view > 0 broadcasts `Status` every `rebroadcast_interval` | F13 + F11 | O-LIVE |
| ML16 | `initial_stage` returns 0 | `det_l16_hint_from_parent_commitqc`: n=7, parent CommitQC with a set-B signer → a set-B member sends its Prepare to `P` as soon as it is ready, before `t_ready + t_retx`; parent CommitQC of set A only → it does not | F6 at n=22, one withholding member, lossless | O-PERF P2 |
| ML17 | `discard_exec` — emits the action but leaves the `exec` entries | `det_l17_hidden_pqc_reexecutes` (below) | F33 | O-LIVE, O-FAULT |
| ML18 | `leader` — `base_{h,v}[i] = perm_C[(h+v+i) mod n]` (views over permutation slots) | `det_l18_f_plus_1_distinct_leaders`: n=4, `D = {B}`, `perm = [A, B, C, D]`, height anchored at B's slot → leaders of views 0 and 1 differ (C, then D) | F1 + F6 with the Byzantine member right after a demoted slot | O-LIVE, O-PERF P4 |
| ML19a | `request_proposal` — clause (a) deleted (no `Status{want_proposal}` after a late entry) | `det_l19_late_entrant_repush`: n=4, D crashed; C's `BlockApplied(h−1)` delayed until 100 ms after proposal(h+1, 0) reached it; E = `exec_budget`; C's `Status` timer phase pinned so that its last awaiting-cadence `Status` reaches the leader A 10 ms before its `want_proposal` `Status` (inside A's per-peer rate-limit window); run with the n=4 and with the n=22 default timings (`T_base`, `rebroadcast_interval`) → C gets the proposal within `2Δ` of entering h+1, view 0 commits, A ∉ `skipped_leaders` | F34 | O-PERF P1, P4 |
| ML19b | `on_status` — the late-entrant re-push deleted (only the interval-gated rebroadcast re-push remains) | `det_l19_late_entrant_repush` | F34 | O-PERF P1, P4 |
| ML19c | `on_status` — the proposal-request step runs after the rate limit (a rate-limited `Status` with `want_proposal` is dropped whole) | `det_l19_late_entrant_repush` (the pinned `Status` phase makes C's request arrive inside the rate-limit window) | F34 | O-PERF P1, P4 |
| ML20 | `commit_height` step 1a deleted (P does not broadcast its CommitQC) | `det_l20_p_broadcasts_commitqc`: n=4, P forms CommitQC(h) → in the same `handle` call it emits `Broadcast(Qc)` to the other members and `C_{h+1} \ C_h`, before `CommitBlock`; L(h+1, 0) enters h+1 one hop later | F9 1 % at n=22 | O-PERF P1 |
| ML21 | `anchor` — the revision-3 `t_tx` term restored (any `PayloadReady` sets `anchor = min(anchor, now + block_time + build_timeout)` in view 0) | `det_r4_payload_ready_moves_no_timer` verifies queue readiness cannot pull in a view deadline; `det_l21_idle_work_wakes_without_heartbeat` verifies an idle chain never commits and later real work commits with or without one crash | F35 | O-LIVE, O-TXP |
| ML22 | stage 1 trigger (a) — the Commit-phase clause (`t_pqc + t_retx` without CommitQC) deleted | `det_l3_setb_joins_stage1` (b): a set-A member Prepares but withholds its Commit, hint off → set B's Commits reach P by `t_pqc + t_retx + Δ`; commit before stage 2 | F6 with Commit-only withholders | O-PERF P2 |
| ML23 | `commit_height`/`enter_height` — the committed block's pending execution is dropped (`tip.exec_req` not kept, §6.3 step 0 absent) | `det_l23_commit_before_own_execution`: X commits h while `Execute{B_h}` is pending; proposal(h+1) arrives; `Executed(Valid(R_h))` arrives before `BlockApplied(h)` → X emits `Execute{B_{h+1}}` at once | F34 | O-PERF P1 |
| ML24 | `request_proposal` — clause (b) deleted (only late entrants ask for the proposal) | `det_l24_lost_proposal_copy`: n=4, `order_{h,0} = [A, C, B, D]` (A leads, B = P, C in set A), D crashed, hint off; A's proposal copy to C is dropped once; C's keepalive `Status` phase pinned so that none is sent during view 0 → C receives A's and B's stage-2 Prepare broadcast, sends one `Status{want_proposal}` to A, gets the proposal at once and Prepares; view 0 commits | F9 (lost proposal copies) | O-PERF P1, O-LIVE |
| ML25 | `sign_timeout` / `on_commit` — the revision-4.1 raise restored: a timeout signed while the view's proposal is held raises the start level at the next commit | `det_l26_raise_only_on_slow_commit_or_exec`: n=4 (the join case n=7), X in set A; (a) the leader's twin reaches X after X executed and Prepared the first → early timeout, TC, view 1 commits at once → `start = 0`; (b) the valid proposal reaches X but no quorum (2f members) → X times out on its deadline holding it → `start = 0`; (c) as (b) ending by the `f + 1` join → `start = 0`; (d) CommitQC of view 0 arrives after X left it → `start = 0`; (e) view-0 commit exactly `T(0)/2` after the proposal → 0, then `T(0)/2 + 1` → 1; (f) the same at view 1 → 1; (g) real-work proposal after `payload_retry_interval` of idle time, committed 100 ms later → 0; (h) execution `T(0)/2 + 1` in a failed view, view 1's block executed at once and committed at once → 1 | F5 | direct assertion (start level), O-LIVE |
| ML27 | `discard_exec` / `commit_height` — a `Pending` execution that is discarded, or still pending at the commit, records nothing | `det_l27_pending_execution_counts`: n=4, X in set A; (a) views 0 and 1 time out with their executions pending, view 2 commits valid retry work executed in 0 ms → `start = 1`; (b) X enters view 1 through a TC carrying PQC(A) with A's execution still pending (kept), CommitQC(0, A) arrives `T(0)/2 + 1` after the request → `start = 1`; (c) control: the execution finished at once, the view failed, view 1 commits → 0 | F15 variant 5 | direct assertion (start level, non-empty blocks) |
| ML28 | `record_exec` — keeps the last execution of the height, not the maximum | `det_l28_exec_duration_is_the_height_maximum` (3.3 s, then 10 ms → raised), `det_l26_raise_only_on_slow_commit_or_exec` (h), `det_l27_pending_execution_counts` (a) | F15 variant 5 | direct assertion (start level, non-empty blocks) |
| ML29 | `commit_height` — `d_c` measured from the anchor `min(t_enter + P(v), t_prop)` (the E40 rule) | `det_l29_late_leader_does_not_raise`: n=4, X in set B; (a) the view-0 proposal arrives `T(0)/2 + 100` after `t_enter + P(0)`, commit 50 ms later → `start = 0`; (b) the same at view 1 → 0; (c) a proposal whose authenticated rows are delayed at once, its body `T(0)/2 + 100` later → 0; (d) X holds A from the start, CommitQC of its twin B `T(0)/2 + 100` later → 0; (e) control: body at once, commit `T(0)/2 + 1` later → 1 | F36 | direct assertion (start level), O-PERF P4 per gap |
| ML30 | `commit_height` — `d_c` measured from `t_prop` of any held proposal (a late body or a twin counts) | `det_l29_late_leader_does_not_raise` (c), (d) | F36 (body variant) | direct assertion (start level) |
| ML31 | `validate_chain` — outer sync response allowance omitted | `det_l31_chain_parameters_leave_a_feasible_sync_frame_budget`: a 16 MiB payload requires both allowances; exact budget passes, one byte less and the former payload-only budget fail | none; deterministic configuration boundary | direct assertion (an available sync setting) |
| ML32 | `process_sync_buffer` — an existing body want does not learn sync responders | `det_l32_sync_enriches_restored_body_want`: restore a recorded proposal after original body loss, with an empty or stale peer list; a verified sync entry enriches the same bounded want without resetting retries, and only actual rows permit ordered commits. `f28_seed177_restored_empty_body_want_catches_up` retains the original failure in short ordinary runs. | F28, including seed 177 | O-LIVE, original body custody |
| ML33 | `process_sync_buffer` — omit verified responder retention and retry pinning | `det_l33_verified_sync_donor_survives_saturated_history`: a requested later-generation donor enters an `n+8` stale list, preserves member peers and retry state, accepts a different valid exact-q certificate for the same manifest/value, and survives cyclic retries without extra fanout; unsolicited, invalid and foreign-value carriers cannot promote donors | none; deterministic saturation boundary | O-LIVE, original body custody |
| ML34 | `process_sync_buffer` — rejected deferred donor does not refresh the current missing-body height | `det_l34_deferred_sync_donor_failure_refetches_current_height`: valid then invalid alternative while C_h is unknown; preserve the original carrier, prepay full deferred storage, and once C_h is known retry the same height through empty/invalid replies and timeout until a valid donor refresh; only actual rows allow commit | none; deterministic deferred-authority boundary | O-LIVE, original body custody |
| ML26 | `on_proposal` step 2 — no early timeout on proven leader equivocation (evidence only) | `det_l25_equivocating_leader_early_timeout`: n=4, X in set A; twin B of the held A (both signed by `L(h, 0)`), with and without X's Prepare of A first → `ProposalEquivocation` evidence and exactly one timeout at view 0 (`hq = None`); no further vote at view 0, even with PQC(A); the twin again → nothing; `q − 1` other timeouts → view 1 at once; not equivocation (no evidence, no timeout): a same signed proposal with a damaged availability carrier of A, B signed by another member, B carrying A's signature, twins of view 0 after X entered view 1 | F5 | direct assertion, O-LIVE |

Shared tests: `det_s2_s27_prepare_once_across_restart` kills MS2 and MS27;
`det_s33_key_rotation_restart` (a) kills MS33a and MS33b, (b) kills MS33c;
`det_s36_certified_mismatch_is_local` (a) kills MS36a, (b) MS36b; `det_l3_setb_joins_stage1` (a)
kills ML3, (b) ML22; `det_l5_lost_vote_retransmitted` (a) kills ML5a, (b) ML5b;
`det_l19_late_entrant_repush` kills ML19a, ML19b and ML19c. `det_l26_raise_only_on_slow_commit_or_exec`
kills ML25 and `det_l25_equivocating_leader_early_timeout` ML26 (the test numbers follow the
order in which the rules were added); `det_l26` (h) and `det_l27` (a) also kill ML28, and
`det_l29` kills ML29 and ML30. Every other test kills exactly the mutation in its row.

`det_l17_hidden_pqc_reexecutes` (n = 4: W, X, Y, Z; X under test; harness keys): (1) X accepts
proposal B of `(h, v)` and emits `Execute{B, req = r1}`; the harness withholds the answer.
(2) The harness forms PQC(B, v) from W, Y, Z and hides it from X; X, W, Y time out with
`hq = None`; X forms TC(v) and enters `v + 1` → `DiscardExecution` without B. (3) The harness
delivers the answer to `r1` — variant a `Cancelled`, variant b `Valid(R)` (finished before the
discard) — and X ignores it (no vote, no `LocalFault`). (4) View `v + 1` fails; TC(v+1) includes
Z's timeout carrying PQC(B, v), so `L(h, v+2)` re-proposes B. Expected: in the `handle` call that
accepts the re-proposal X emits `Execute{B, req = r2}` with `r2 ≠ r1`; on `Valid(R)` for `r2` it
Prepares `(h, v+2, B, R)`; no `LocalFault` at any point. Variant c delivers the answer to `r1`
only after the re-proposal: X still re-executes at once and ignores the stale answer.

**AMX application rules (§11).** The simulator's toy AMX application (`sim::amx`); the named
tests drive a state transition or a tracker over harness-signed certificates of synthetic
blocks.

| Id | Site — change | Named deterministic test (setup → expected) | Randomized scenario | Oracle |
|---|---|---|---|---|
| MX1 | `GlobalState::vote` — one `Yes` decides `Commit` | `det_amx_commit_needs_every_yes`: three participants; `Yes` from two → no decision; the third → `Commit` | F31 | O-AMX |
| MX2 | `GlobalState::vote` — the `h ≤ d` condition of `Commit` deleted | `det_amx_no_commit_after_deadline`: the completing `Yes` is relayed at `d + 1` → no `Commit`; the deadline step aborts | F31 | O-AMX |
| MX3 | `GlobalState::expire` — the deadline abort deleted | `det_amx_deadline_aborts_at_d_plus_1`: no votes → undecided at `d`, `Abort` at `d + 1`, nothing later | F31 | O-AMX |
| MX4 | `GlobalState::begin` — a second `Begin` for `x` replaces its entry | `det_amx_second_begin_rejected`: `Begin`, a `Yes`, the same `Begin` → no record, the vote stays | F31 | O-AMX |
| MX5 | `GlobalState::vote` — the vote's proof is not verified | `det_amx_forged_vote_rejected`: a `No` certified by another dataspace's committee, relabelled to the voter's instance, or signed by `q − 1` → no decision | F31 (forging relayer) | O-AMX |
| MX6 | `DataspaceState::prepare` — `x ∉ prepared` not checked | `det_amx_prepare_once`: a second inclusion of `x` → no record, escrowed once | F31 | O-AMX |
| MX7 | `DataspaceState::prepare` — a held decision is ignored | `det_amx_held_decision_votes_no`: `G`'s `Abort` held before the prepare → `No`, nothing escrowed | F31 | O-AMX |
| MX8 | `DataspaceState::settle` — a `Yes` escrow is applied whatever the decision | `det_amx_settle_follows_decision`: `Commit` applies the leg, `Abort` restores it, a replay changes nothing | F31 | O-AMX |
| MX9 | `DataspaceState::observe` — a local timeout releases a `Yes` escrow once a verified `G` block is above `d` | `det_amx_no_release_without_abort_proof`: a verified `G` block above `d` and a forged `Abort` → the escrow stays until `G`'s `Abort` | F31 | O-AMX |
| MX10 | `Tracker::context` — the tracked epoch need not contain the certified height | `det_amx_tracker_epoch_window`: epoch 0's committee certifies a height of epoch 1 under epoch 0's id → rejected; epoch 1 verifies only after its handoff, and a removed committee cannot certify it | — | direct assertion |
| MX11 | `Tracker::handoff` — `C_{J,e−1}` is not kept | `det_amx_handoff_keeps_previous_epoch`: a record of epoch 0 relayed after the handoff into 1 still verifies; handoffs only in sequence and from the last block; a replay is stale | — | direct assertion |
| MX12 | `Tracker::verify` — the result-preimage check deleted | `det_amx_record_bound_to_result`: a genuine `Yes` whose disclosed record is rewritten to `No` → rejected | F31 (forging relayer) | O-AMX |
| MX13 | Simulator relayer omits expiry work learned from authenticated Begin | `amx_final_payment_silent_participant_requires_actionable_abort`: the only payment has one silent participant and real Yes escrow on the healthy participant; the healthy Global root must certify Abort and release that escrow without unrelated transactions or height advancement | — | Exact final obligation and escrow outcome |
| MX14 | Simulator Global vote accepts Commit at or after signed time expiry | `det_amx_time_expiry_orders_last_yes_and_expire_identically`: last Yes and explicit Expire, in both orders at one millisecond before, exactly at and after expiry, produce one immutable Commit before the boundary and Abort at or after it | — | Exact certified-time boundary and decision |
| MX15 | Simulator carrier classification omits Begin and Vote from stale-time admission | `det_amx_time_sensitive_carriers_refuse_stale_time_but_certified_replay_is_exempt`: original registered Begin, Vote and Expire carriers pass at the freshness boundary, defer one millisecond beyond it, and bypass that guard when the certified execution flag is set | — | Actual carrier classification and clock-admission outcome |

MX13–MX15 cover the simulator candidate for final-payment progress: signed terms bind
an absolute ledger-time expiry; a relayer reconstructs due work from authenticated Begin
after restart and submits a real Expire input. Only execution of that input for a known,
undecided, due obligation emits Abort. The same certified-block-time predicate prohibits
Commit at the expiry boundary. Local scheduler time cannot release participant escrow.
Begin, Vote and Expire carriers all enter the simulator's CT5 stale-time guard; certified
re-proposals and replay retain the same exemption. That bounds their first uncertified
Prepare admission, not the time a hidden certificate or interrupted chain finally commits.
The simulator's 60-second window is a harness policy, not a wall-clock settlement
guarantee. The native implementation now carries signed ledger-time expiry, committed
freshness bounds, funded expiry dispatch and authenticated Decision recovery alongside
the height deadline in §11. These remain an implementation candidate: current-source
native and daemon checks and the independent-root, final-payment network scenario must
pass before this establishes whole-node settlement readiness.

The node's AMX rules live outside the crate the gate mutates; their deterministic tests are
`iroha_data_model::sumeragi_amx::tests` (`sumeragi_amx_commit_needs_every_yes_by_the_deadline`,
`sumeragi_amx_first_no_or_the_deadline_aborts`,
`sumeragi_amx_begin_rejects_duplicates_unregistered_participants_and_bad_deadlines`,
`sumeragi_amx_tracker_verifies_records_under_the_tracked_committee_only`,
`sumeragi_amx_tracker_hands_off_epoch_by_epoch`, `sumeragi_amx_write_proof_matches_the_certified_write_root`
and the `sumeragi_amx_participant_*` tests: escrow once and apply on `Commit`, release only with
the `Abort` proof, `No` without escrow, a held decision votes `No`, late prepares and pruning,
`G`'s handoffs) and `iroha_core::sumeragi::amx::tests`
(`sumeragi_amx_begin_and_decisions_are_witness_writes_of_the_block`,
`sumeragi_amx_deadline_step_aborts_in_the_first_block_after_the_deadline`,
`sumeragi_amx_registration_needs_genesis_or_permission`).

Core-owned evidence rules have a separate strict gate (`--core`), not simulator fault
switches. Its `SUMERAGI_CORE_MUTATION` selector requires the Core `mutation-testing` feature;
normal library/node builds with that feature fail to compile, and the hooks additionally require
`cfg(test)`. Baseline and mutant use the same profile, test by default, preserving dependency
decode counters and debug-only controls. The report records that profile. Explicit
`--core-profile release` runs remain available for optimized diagnostics; test-profile results
do not establish release-profile qualification. Protocol and daemon gates retain their release
profile and the same strict named-test, normal-exit and complete-harness requirements.

| Id | Core site — change | Named deterministic test (setup → expected) | Oracle |
|---|---|---|---|
| HC1 | `committed_evidence_record_is_prunable` — use native lane subject height as the global replay clock | `lane_terminal_replay_fence_uses_immutable_retirement_deadline_and_original_incarnation`: live native heights 1 and `u64::MAX` retain their terminal fence; retirement 20 and immutable horizon 7 retain through 27, prune only after 27, and absent/substituted custody never grants pruning | Exact original incarnation, installed policy and inclusive retirement deadline |
| HC2 | `ConsensusSlashLiability::names_registration` — omit original lane custody and registration checks | `original_lane_liability_checks_exact_registration_before_exposure`, `lane_liability_rejects_changed_incarnation_policy_and_same_tenure_escrow` | Creation-time account, activation, peer, escrow, incarnation and immutable policy remain the sole monetary target |
| HC3 | `PenaltyApplier::parent_snapshot` — use the native lane subject height for the global penalty delay | `original_lane_liability_slashes_retired_owner_without_using_native_height`, `native_lane_original_genesis_escrow_is_debited_only_by_delayed_authenticated_admission` | Delayed effects begin from the original global admission carrier; native subject height cannot accelerate or postpone the debit |
| HC4 | `AdmissionRead::capture` — omit the original retirement admission deadline preflight | `lane_admission_capture_checks_inclusive_deadline_and_missing_original_incarnation` | Inclusive retirement-plus-horizon boundary; expired, reclaimed and recreated inputs cannot reopen capture. Capture success still requires original-history authentication before admission |
| HC5 | `admission::retryable` — retain terminal local-source failures as pending jobs | `terminal_lane_source_failure_cannot_pin_competing_original_admission_forever`, `local_proposer_skips_terminal_lane_source_without_deleting_observation` | A failed source grants no authority and cannot hold unrelated same-cut admissions; original signed local observations remain retained |
| HC6 | `LaneEvidenceRead::finish_history` — discard the completed history on a decoder-field-limit refusal | `completed_lane_history_retains_original_owner_on_finish_decode_refusal` | The exact original history and every prepaid charge survive local refusal through consuming handoff |
| HC7 | `EvidenceAdmissionError::from(CodecError)` — classify a typed local decoder refusal as invalid proof | `native_decode_refusal_refunds_capture_without_blaming_original_proof`, `persisted_root_decode_refusal_retains_original_validation_cut_for_retry` | Admission refunds partial capture without blaming the original proof; persisted root validation retains its original cut across refusal, and both retry the unchanged signed bytes |
| HC8 | `Worker::run_execution_with_finisher` — classify local payload decoder refusal as invalid | `payload_decode_refusal_retains_available_owner_without_negative_cache` | Genuine available custody survives narrower surviving caller field/allocation/depth ceilings; refusal is `Failed` with no negative cache, and the same source/pool executes after the limit is removed. Malformed available application bytes remain deterministically invalid |
| HC10 | `state_certificate::query_scratch_admission` — skip original caller scratch admission | `state_certificate_signed_availability_scratch_uses_original_query_allowance`; `terminal_amx_prefix_refuses_original_payload_scratch_without_advancing`; `terminal_amx_prefix_refuses_original_rs16_scratch_without_advancing` | Genuine signed RS16 availability and the real terminal AMX prefix refuse independently derived payload/scratch-minus-one allowances before allocation, retain the original target, predecessor, body and authority, and retry at exact canonical demand under the same enclosing context. The callback enforces an already-active caller allowance; it installs no pool or scope and does not close the remaining original-pool cryptographic/decoded graph or durable relayer ownership boundaries. |
| HC11 | `certified_chain::read_durable_pinned_block` — accept Kura's decoded cache instead of the current durable certificate | `durable_certificate_read_rejects_checksum_valid_corruption_after_cache_warm` | State-backed and pinned restoration readers reject checksum-valid wrong-height and forged-signature QCs after cache warming, then accept the restored original frame |
| HC12 | Beacon session construction omits the complete original prepaid remainder check | `beacon_verification_reserves_exact_buffers_and_refuses_before_unfunded_work` | One byte below the exact graph, control and scratch demand refuses before any physical allocation and preserves the original reservation unchanged. The same authentic source with exact funding succeeds; no parallel logical callback or unbudgeted session constructor exists. |
| HC13 | Core executed-successor query constructs aggregate pairing scratch without charging the inherited request allowance | `state_certificate_pairing_constructor_refusal_preserves_original_source_for_retry` requires exact typed refusal before verification, preserves the original certified source/parent, and retries under the original request model | Core test-only constructor callback; no node fault control |
| HC15 | `StoredBodyRead::poll_with_qc` — deep-copy the original decoded quorum certificate at body handoff | `committed_read_returns_original_qc_backing_after_projection_refusal_and_retry` | Genuine certified restoration returns the original QC bitmap backing across projection refusal/retry, preserving the source identity of the original availability table and payload; the body-only adapter drops unused proof owners before returning. Initial metadata allocation remains a separate accounting obligation |
| HC16 | Core lane custody handoff skips original-pool signer admission | `original_signer_state_handoff_retains_backing_and_refuses_foreign_pool`, `original_signer_world_handoff_admits_both_generations_before_replacing_either`, `native_lane_signer_snapshot_retains_exact_raw_source_until_both_cuts_are_funded` | Immutable sparse backing/control must retain the original execution pool across World clones and both snapshot generations. Local refusal preserves the original source and refunds partial copies; outer lane vectors, Cell controls and complete snapshot authority remain separate obligations |
| HC17 | `NativeBeaconProducer::parent_source` — accept the original tip with a different published hash journal | `control_requires_original_tip_and_matching_published_hash_journal` | The exact current State height, opaque original execution tip, native parent hash/result and Iroha hash journal must agree before control or readiness. A copied journal without its original tip grants no authority; rejected observations withdraw readiness |
| HC18 | Core lane sample handoff skips original-pool backing/control admission | `sample_state_admission_refuses_unfunded_source`, `sample_finalizer_refusal_preserves_exact_source_and_retry_funds_only_suffix`, `native_lane_sample_snapshot_retains_raw_source_through_both_cut_refusal_and_retry` | Immutable samples share original backing across State clones; exact actual suffix plus appended row is funded before allocation. Refusal retains the original source, both snapshot cuts must be funded before raw input is consumed, and positive-u32 window policy remains unchanged. Outer lane/custody vectors and Cell controls remain separate obligations |
| HC19 | AMX instruction error boundary — turn an inherited decoder resource refusal into a deterministic instruction failure | `amx_anchor_decode_refusal_cannot_publish_even_when_instruction_error_is_caught`, `amx_relay_decode_refusal_keeps_original_undecided_record_and_retries_proof` | Anchors, records and proof codecs preserve the exact local refusal; the original executing State retains it outside canonical outcomes through child discard or caught errors. No refused attempt publishes AMX votes or World effects; the original proof remains retryable |
| HC20 | Stored result validation — classify local decoder refusal as corrupt storage | `stored_result_decode_refusal_retains_original_decoded_owners_and_retries`, `committed_result_decode_refusal_keeps_original_read_slot_and_retries` | The exact local operational refusal remains retryable through stored-body projection and the outer Kura read slot, including competing-height polls. Original certificate, availability, QC and witness backing remain retained; malformed preimages still fail as storage corruption |
| HC21 | Core root startup substitutes a fresh store for the original State Kura | `prepared_root_uses_original_state_store` | Storage, replay and retained lane registry derive from one original State owner. Configured chain identity is State-owned, whereas NetworkId is signed-genesis identity; neither permits caller-supplied storage substitution. Queue/transport startup ownership remains separate |
| HC22 | Core queue omits the signed entrypoint security-domain check | `queue_rejects_preaccepted_foreign_external_before_custody`, `queue_rejects_preaccepted_foreign_commitment_before_custody`, `queue_rejects_preaccepted_foreign_reveal_before_custody` | Preacceptance in another network cannot authorize local queue custody. Compare the original signed domain with the supplied committed State before fee holds, indexes or gossip; preserve the original rejected carrier and accepted batch prefix. Native execution independently revalidates the domain. Same-domain State/Queue/Net ownership remains separate |
| HC23 | Core P2P startup ignores the retained actor's subscription refusal | `network_start_rejects_closed_retained_actor_before_driver_files` | Subscribe through the actor owned by `StartInputs.net` before installing key records or constructing the driver; no independent receive actor may substitute for a closed sender. A live retained actor still delivers authenticated signed native frames. Generic `start` is unchanged; a multi-root daemon must separately own one shared subscription router |
| HC24 | Stored result refusal allocates a replacement boxed diagnostic | `stored_result_decode_refusal_retains_original_decoded_owners_and_retries`, `committed_result_decode_refusal_keeps_original_read_slot_and_retries` | Outward local refusal is a bare `WouldBlock` without another allocation. The original certificate, availability, QC, witness and pool remain retained across retry; malformed result preimages retain their typed terminal corruption errors |
| HC25 | Stored certificate decoder misclassifies physical allocator refusal | `stored_certificate_allocator_refusal_keeps_original_read_and_retries`, `committed_certificate_allocator_refusal_retains_original_slot_and_retries` | A real refused decoder allocation preserves the original certificate job, exact source and pool, and yields allocation-free `WouldBlock`. The same read resumes cryptographic and full-codeword verification after relief. Declared wire/decode limits and malformed certificates remain terminal; this classification does not fund the remaining metadata graph |
| HC26 | Core private bootstrap acquires global AMX coordinator authority | `signed_private_genesis_cannot_install_global_amx_coordinator`, `every_amx_coordinator_instruction_rejects_private_execution_before_proof_decoding` | All four coordinator instructions require the authenticated global root before private bootstrap or proof decoding. Genuine signed private genesis cannot publish coordinator state; global genesis remains valid. Owned, borrowed and boxed execution share the same scope owner. Native participant State, escrow and relayers remain separate S6 work |
| HC27 | Core execution drops inherited metadata decode refusal before publication | `signed_private_work_keeps_scope_decode_refusal_local_and_retries_original_carrier` | Original signed private work defers on zero or late metadata decode budget refusal, retains the local refusal through attempted overlay publication, and retries the same carrier with exact scoped fees. Malformed metadata remains rejected; absence never grants Global scope. This covers the mutable execution-root boundary, not all read-only routing projections or complete decoded-graph funding |
| HC28 | Core read-only scope decoder refusal becomes a completed query or VM error | `signed_private_manifest_query_does_not_turn_scope_refusal_into_permanent_error`, `signed_private_host_query_keeps_scope_refusal_out_of_completed_vm_errors` | The manifest query and boxed/ephemeral dispatch retain an internal `ExecutionAttemptError`; the VM host handles `Deferred` before ordinary missing/gas/permission mappings. Client transport projection may report capacity. Malformed and foreign metadata stay terminal; query permission checks borrow the exact canonical global grant without constructing a JSON token |
| HC29 | Native lane batch decode classifies local pressure as Byzantine invalidity | `original_signed_batch_decode_preserves_exact_local_refusal_and_terminal_limits`, `authenticated_registry_batch_decode_refusal_is_retryable_not_byzantine`, `signed_four_validator_lane_execution_refusal_never_caches_invalid_or_publishes`, `signed_four_validator_lane_recovery_keeps_available_phase_and_exact_original_owners` | Exact local decoder refusal stays separate from deterministic lane admission. Signed RS16 registry reads retain the original body, QC backing, pool and store lock; execution cannot cache Invalid or publish under refusal; recovery retains its available-body phase and retries the original source. Intrinsic malformed/depth limits remain terminal. These are native storage/execution component controls; complete graph funding, signed global genesis, fees and whole-network qualification remain separate |
| HC31 | Lane canonicalization allocates replacement input and output payloads | `signed_lane_batch_canonical_validation_preserves_original_bytes_without_new_allocations` | Decode borrows the original signed batch bytes and shared Norito canonical comparison streams over the same source. Exact allocation census must equal the original borrowed decoder, with no additional canonicalization buffer. This removes redundant payload copies; decoded-graph funding, native finality and whole-network qualification remain separate |
| HC30 | Core registry, exact permission and fee-policy readers erase local decoder refusal | `signed_private_contract_lookup_does_not_turn_scope_refusal_into_vm_permission_denial`, `signed_private_account_permission_read_defers_without_constructing_a_json_token`, `signed_fee_runtime_read_does_not_turn_scope_refusal_into_a_nonmatching_origin`, `original_retained_fee_registry_does_not_publish_local_decode_refusal_as_malformed`, `signed_payout_scope_refusal_cannot_publish_a_parliament_terminal_outcome` | Original scope and retained grant/registry reads preserve nonserializable deferral through host, fee effects, restore and due Parliament execution; local refusal cannot publish absence, denial, exemption, Superseded or EffectFailed. Malformed/foreign/revoked inputs remain terminal; complete decoded-graph funding and whole-State restoration remain open |
| HC32 | Shared decoder classifier erases original reward-credit, native worker and Kaigi refusals | `original_fee_credit_alias_decode_refusal_preserves_balance_and_retries`, `original_fee_credit_owner_decode_refusal_preserves_exact_binding_and_retries`, `sumeragi::executor::publication_tests::context_proof_decoder_refusal_retains_original_inputs_and_retries`, `sumeragi::executor::publication_tests::native_context_archive_decoder_refusal_retains_original_execution_and_retries`, `smartcontracts::isi::kaigi::typed_deferral_tests::stored_record_refusal_is_sticky_and_retries_original_json_without_publication`, `smartcontracts::isi::kaigi::typed_deferral_tests::indexed_record_refusal_preserves_unregister_guard_and_original_retry`, `state::deserialize::kaigi_typed_deferral_tests::restored_kaigi_record_refusal_is_deferred_and_retries_original_snapshot`, `smartcontracts::isi::kaigi::relay_typed_deferral_tests::registration_refusal_preserves_original_relay_retirement_and_retry`, `smartcontracts::isi::kaigi::relay_typed_deferral_tests::feedback_refusal_preserves_both_original_relay_rows_and_retry`, `smartcontracts::isi::kaigi::relay_typed_deferral_tests::allowlist_refusal_prevents_domain_metadata_publication_and_retries_original_json`, `smartcontracts::isi::kaigi::relay_typed_deferral_tests::checked_record_writer_refusal_keeps_original_create_unpublished_and_retries`, `state::deserialize::kaigi_relay_typed_deferral_tests::restored_registration_refusal_retains_original_snapshot_and_retry`, `state::deserialize::kaigi_relay_typed_deferral_tests::restored_allowlist_refusal_retains_original_snapshot_and_retry`, `state::world_construction_tests::world_constructor_registration_refusal_is_fallible_and_retries_original_source`, `state::world_construction_tests::world_constructor_record_refusal_is_fallible_and_retries_original_source`, `smartcontracts::isi::kaigi::relay_typed_deferral_tests::lineage_refusal_preserves_original_relay_retirement_and_retry`, `smartcontracts::isi::kaigi::relay_typed_deferral_tests::primary_alias_refusal_preserves_original_registration_and_retry`, `execution_attempt::tests::json_scoped_refusal_preserves_original_context_source_and_retry`, `smartcontracts::isi::kaigi::relay_typed_deferral_tests::live_manifest_dependency_refusal_preserves_original_route_and_retry` | Reward-credit alias/owner reads preserve their exact original backing and balances. Native result-proof and archive preparation retain the original overlay, witness, input/result graph and pool through a captured enclosing decoder refusal, retry that same execution, and persist the exact archive after certified commit. Kaigi call and indexed dependency reads retain the sticky World refusal before transaction publication; the real World projection restore returns typed `ExecutionDeferred` and retries the unchanged borrowed snapshot. Registration, feedback, governance allowlist and checked Kaigi JSON writer refusals use the same original classifier; relay-registry restoration forwards the typed refusal. The manifest delegates to the sole stored registration decoder, with exact manifest predicates retained. SNS lineage and primary-alias resolution move the original typed refusal into the sticky World bridge before relay mutation. Separate genuine controls admit the exact lineage prefix before registration and feedback, preserve retained lease/Json pointers and indexes, and retry the same original finite context. The live-manifest lifecycle guard forwards indexed-record refusal into that same sticky owner before key rotation or retirement; retry against unchanged source returns the completed active-route protection. Completed SNS/record/key/relay corruption stays terminal. Fallible World construction preserves the same typed rebuild deferral before returning any World; retry retains the original pool/context and shared Json source backing. Ordinary input/index/crypto graph funding remains open. This does not authenticate complete State or close nested graph funding. The shared JSON error owner delegates an original scoped error while its exact decoder observer is active; same-source retry retains the original charged input and counter pool. A saved same-context sibling error keeps its original tag and remains terminal even after a fresh swallowed refusal. Captured decoder provenance survives scope retirement without inventing a pool waiter. Malformed commitments and intrinsic format limits remain terminal; full decoded-graph funding and network qualification remain separate |
| HC33 | Core decode refusal classifier borrows an unrelated active scope | `norito_global_archive_cap_is_terminal_inside_an_outer_decode_scope`, `norito_inner_format_limits_are_terminal_under_a_wider_outer_scope` | Actual global archive and stricter inner field/sequence/cumulative limits remain deterministic rejections under a wider outer scope. Local retry requires the original error dimension and ceiling to match a surviving scope; genuine inherited credit allocation refusal still defers. No allocation-pool owner or release notification is invented |
| HC35 | SNS permission projection publishes an original local refusal as a completed rejection | `original_sns_alias_domain_permission_refusal_retries_without_a_rejection`, `original_sns_domain_transfer_permission_refusal_retries_without_a_rejection` | The active outer decode budget can defer authoritative SNS reads without changing original NameRecord bytes or permanently denying domain authority; the same bytes succeed after budget release |
| HC36 | Claim fee exemption publishes original metadata or SNS refusal as a paid fee verdict | `original_claim_metadata_refusal_defers_fee_quote_and_retries_exact_payload`, `original_claim_alias_refusal_after_metadata_defers_fee_quote_and_retries` | Both original metadata reads and authoritative SNS records preserve local deferral through quotes, queue admission and the execution latch. Refusal cannot debit or publish; exact signed payloads retry after relief. Malformed/empty metadata remains completed; complete allocation funding remains separate |
| HC37 | Canonical account or NPoS currency pin refusal becomes selector absence | `original_canonical_account_refusal_does_not_fall_through_to_alias_absence`, `original_network_xor_pin_refusal_defers_quote_and_retries_same_parameter` | Typed canonical address and original committed currency reads preserve local deferral instead of falling through to alias absence or invalid fee configuration. Exact canonical literals and parameter bytes succeed after relief; foreign, malformed and intrinsically invalid selectors remain completed |

| HC34 | Native maintenance omits applied native source accounting | `native_authorization_has_no_entry_until_an_applied_transcript_and_drops_atomically`, `native_pool_overflow_cannot_borrow_ordinary_or_governance_reservations` | Applied native maintenance transcripts own one exact native permit. No entry exists before Apply, dropping the permit releases its entry atomically, and native-pool overflow cannot consume ordinary or governance reservations. Original SNS decode refusal still defers before debit or publication; complete decoded-graph funding and accelerated whole-State restoration remain open |
| HC40 | Account target or matcher turns an unfinished original SNS/canonical account read into a completed route | `original_account_target_refusal_never_selects_the_default_route`, `original_canonical_account_matcher_preserves_decode_refusal_and_retry`, `original_signed_account_matcher_refusal_is_not_a_mismatch_or_panic`, `original_native_policy_account_matcher_retains_refusal_before_route_selection` | Original account targets and exact, wildcard, instruction and query matchers propagate local refusal through configured and native route selection. Canonical matching uses the typed account parser without formatting panic. Ordered first-match evaluation and authoritative maintained directories remain unchanged; complete decoded-graph funding remains open |
| HC42 | SNS auto-renew rejects current-owner replacement after authenticated multisig rekey | `signed_rekey_current_owner_can_replace_stale_auto_renew_configuration`, `signed_rekey_same_configuration_requires_owner_replacement_cas`, `signed_rekey_disabled_clean_record_requires_exact_owner_revision` | The current authenticated lease owner may replace or disable stale owner-pinned configuration only at the exact persisted revision. Identical stale configuration still requires Apply. The actual Time sweep authenticates the exact persisted record and admits any payment under its separate committed native-maintenance quota; intrinsic refusal advances deterministic retry state without moving balances, renewing the lease, or retaining a source entry. Prior/unrelated owners and stale revisions stay rejected; rekey never transfers debit authority implicitly |
| HC44 | Execution worker discards original validation or prepared-certificate read refusal | `original_post_merge_validation_refusal_retains_worker_owner_and_exact_available_retry`, `original_prepared_certificate_read_refusal_retains_worker_owner_and_funded_execution` | The exact local carrier survives diagnostics with the original available source or funded execution. The same source retries without quarantine, negative verdict, publication, or replacement of an already executed overlay. Decoder counters do not invent pool release notifications |
| HC45 | Payload worker drops the original typed local decoder refusal | `original_available_payload_local_decode_refusal_transfers_typed_original_reason_and_retry` | Original signed available custody, source and bytes remain unchanged; the worker retains the exact local reason before a diagnostic, publishes no verdict, and retries the same body after the field/allocation limit is removed. Scoped counters invent no allocation-pool release owner. |
| HC46 | Decode classifier treats a surviving narrower caller depth as invalid | `original_surviving_narrow_decode_depth_refusal_retries_identical_bytes`, `original_available_payload_narrow_depth_refusal_transfers_typed_original_reason_and_retry` | Actual canonical bytes under a matching surviving decode-budget depth defer with their typed worker owner; exact bytes execute after scope removal. Dropped inner depth, global archive and canonical nesting ceilings remain terminal. |
| HC49 | Staking payload converts original preparation refusal into a diagnostic string | `original_staking_payload_refusal_retains_evidence_pool_and_exact_assembly_retry`, `original_staking_payload_worker_retains_pool_refusal_and_exact_queued_retry` | Payload assembly and its worker retain the exact evidence or State admission owner before diagnostics. Releasing the original occupied pool retries the same parent, evidence and queued transaction without dequeue, publication or a deterministic rejection. This boundary does not establish complete staking graph funding |

| HC38 | Routing turns an original SNS read refusal into a completed route error | `original_dataspace_alias_read_refusal_keeps_routing_retryable`, `original_physical_policy_read_refusal_never_enters_captured_row`, `original_private_instruction_routing_refusal_latches_before_scope_verdict` | The original SNS bytes retain a typed local refusal through queue/native routing and physical capture; private execution latches it before effects. Semantic absent/inactive routes remain completed outcomes; real-network qualification and complete allocation funding remain separate |
| HC39 | Native routing erases original root or lane-policy decode refusal | `original_root_scope_read_refusal_does_not_publish_invalid_native_context`, `original_lane_policy_read_refusal_after_root_keeps_exact_capture_retryable` | The root read and a policy read after its exact measured root prefix retain local deferral through Snapshot and pristine capture. No invalid carrier row is published, original metadata bytes remain unchanged and fresh owners retry the exact source; absence or completed malformed metadata stays distinct from local refusal |
| HC41 | Parameter control follows a private account rule in physical policy | `parameter_control_preserves_global_physical_route_before_private_account_rule`, `alias_registry_routing_paid_post_genesis_dataspace_domain_and_renewal`, `alias_registry_routing_cold_replay_with_expanded_catalog_preserves_paid_bootstrap` | Genuine signed parameter batches keep universal physical and native scope before account routing, while the same owner’s ordinary application retains its private route. Paid catalog/bootstrap, immutable genesis and certified cold replay remain mandatory; no physical dataspace mismatch guard is bypassed |


| HC47 | Runtime availability converts local historical refusal to corruption, or drops the original append/metadata retry owner | `original_availability_history_refusal_is_pending_without_corruption`, `original_availability_constructor_refusal_retries_without_installing_authority`, `append_refusal_keeps_original_commit_and_release_owner_until_durable`, `refused_metadata_owner_cannot_be_replaced_by_another_peer_during_backoff` | Non-wire local attempts retain the original State/source, capacity owner and queued work through storage and driver retry. The sole refused metadata slot cannot be replaced during backoff; payload work still progresses. Malformed artifacts remain terminal. Historical lane-prefix cause retention and full graph funding remain separately open |
| HC87 | Stake-index magnitude charges drop before the retained quantities | `stake_index_quantities_prepaid_and_borrowed_from_original_pool` | The complete exact account, descriptor and four aggregate layouts are admitted atomically before retained allocation. One-byte refusal preserves the original World and pool for retry. Repeated exposure reads borrow the same originally funded magnitude through move and drop; released charges cannot qualify a live physical aggregate. Bounded stack arithmetic preserves the original bonded-plus-complete-pending grouping. Evidence/history and penalty-action graphs remain separate resource obligations. |
| HC94 | Retired replay completion accepts replacement source configuration | `replay_completion_retirement_keeps_exact_source_and_original_pool_retry` | Only the same worker's successful historical execution and archive completion issue fixed process-local evidence. The large Published frame is retired. Every retry still admits its original body and witness, compares complete epoch, parameters and ordered committee, binds the current opaque State tip, and funds exact canonical header, QC and availability encoding from the same finite pool. Altered certificates, even another valid quorum, and replacement parameters are refused without duplicate events. Original capacity refusal preserves that evidence until the same bytes can retry after release. No decoded or persisted completion grants execution authority. |
| HC53 | Node time omits host suspension from admission timestamps, probe expiry or RTT | `suspend_inclusive_clock_advances_admission_and_expires_retained_probes`, `suspend_inclusive_clock_counts_entire_probe_round_trip` | One Unix anchor advances with the actual process-bound native suspend-inclusive elapsed clock. The same elapsed timeline owns probe deadlines, sample retention and RTT; no wall-clock reconsult or larger admission drift masks sleep. Clock refusal, regression or overflow retains the last representable floor and reports unhealthy fallback, never healthy peer samples. This is node-local time accounting and does not authenticate a Unix timestamp or change consensus timers. |
| HC51 | Lane history erases the original archive, certificate-prefix, evidence handoff or proposal policy refusal | `original_archive_read_refusal_preserves_pool_release_and_same_lane_prefix`, `original_certificate_projection_refusal_preserves_pool_release_and_exact_carrier`, `original_lane_evidence_handoff_preserves_actual_decode_refusal_and_exact_cut`, `original_native_lane_authority_refusal_reaches_merge_and_original_pool_retry`, `original_lane_history_refusal_reaches_evidence_without_recovery_or_rejection`, `original_lane_policy_proposal_refusal_retains_worker_owner_and_exact_queued_retry` | Original finite-pool release evidence and surviving caller decode refusal remain local through the retained history, merge, evidence and actual proposal Worker consumers. Retry preserves the exact selected archive descriptor, carrier, State cut and original ceiling. Decoder scopes invent no pool release. Typed Kura acquisition and full decoded/crypto graph funding remain separate obligations. |
| HC48 | Incumbent history or a signed credential/lifecycle decoder converts local refusal into a completed instruction failure | `original_incumbent_history_refusal_keeps_authority_and_same_source_retry`, `original_credentials_authority_refusal_keeps_command_and_same_source_retry`, `original_credentials_command_decode_refusal_has_no_publication_and_retries`, `original_beacon_public_state_decode_refusal_defers_before_installation`, `original_tle_public_state_decode_refusal_defers_before_installation`, `original_staking_authority_refusal_keeps_exit_overlay_and_same_signed_retry` | The original non-wire attempt reaches State before any credential/key installation or validator exit; the same signed source retries. Signed malformed public state remains terminal. General NPoS parameter-read propagation has the separate HC50 control; complete decoded-graph funding remains open |
| HC50 | Original signed NPoS policy read turns a local decoder refusal into missing authority | `original_npos_parameter_refusal_does_not_become_missing_staking_policy`, `original_npos_exit_policy_refusal_keeps_stake_and_same_signed_retry`, `original_npos_reserve_validation_refuses_without_changing_current_or_undo`, `original_npos_policy_refusal_preserves_host_seed_projection_and_retries`, `original_npos_policy_refusal_cannot_prune_retained_evidence`, `late_original_npos_activation_read_refusal_rolls_back_and_same_signed_retry`, `original_lane_observer_late_policy_refusal_retains_observation_and_retries` | The same original policy remains available for retry through staking preparation and signed Exit, current and undo reserve validation, host seed projection and charged evidence pruning, including cumulative refusal after completed earlier activation or lane-observer policy reads. Refusal cannot publish a deterministic rejection, clear a completed projection or release retained proof bytes. Malformed policy remains terminal; complete graph funding and whole-State restoration remain separate obligations. |
| HC52 | Original checkpoint binary decoding becomes completed invalidity | `original_checkpoint_binary_refusal_is_local_and_retries_exact_original_source` | Exact original decoder fields survive portable checkpoint import. Core applies the shared surviving-caller-limit classifier before any rejection diagnostic; a live caller refusal retains retry while a dropped inner format ceiling remains terminal. The independently selected original checkpoint remains byte-identical and retries. This does not fund the complete decoded graph or authenticate a remotely supplied checkpoint. |
| HC54 | Bootstrap or restored beacon custody ignores the DKG transcript's authority generation | `committee_bootstrap_rejects_genuine_dkg_from_another_generation`, `committee_restore_rejects_genuine_dkg_from_another_generation` | Genuine signed DKG transcripts for the same ordered roster and network require the exact authenticated generation. Bootstrap and installed retention restore reject foreign generations; matching-generation transcripts remain accepted. This component check does not qualify whole-node restart or committee transitions. |
| HC95 | Native AMX accepts a certified Begin for a different signed debit source | `native_amx_paid_commit_survives_certified_restart_and_rejects_bypass` | The authenticated Global Begin binds the exact transfer digest, signed source authority and dataspace custody. A genuine foreign certificate cannot authorize another signed debit. The original paid commit/restart control rejects the substituted source before escrow; local resource refusal retains the original owner for retry. This component rule does not qualify daemon supervision or validator relayers. |
| HC55 | A fee reward claim ignores its signed custody, entitlement or beneficiary preconditions | `signed_fee_reward_claim_rejects_every_changed_binding_before_mutation` | Execution reproduces the exact lifecycle, recovered beneficiary revision, scoped XOR transfer, full accrued credit and next receipt sequence before releasing reserves. Explicit absence of a fee claim authorizes no additional payout. This component control does not qualify fee enactment or the complete monetary network lifecycle. |
| HC56 | Shared custody omits fee obligations from the combined staking and reward reserve floor | `shared_fee_stake_reward_custody_is_additive` | A source holding fee proceeds or fee rewards plus public-lane stake and rewards protects their sum. Individually backed obligations cannot authorize a debit that underfunds their combined liability. Network conservation and full restoration qualification remain separate gates. |
| HC57 | Startup replay acknowledges a changed certificate or source as an exact retry | `completed_replay_rejects_altered_certificate_and_source_without_losing_exact_retry` | The serialized worker retains only its original completed tip and exact certificate, availability, payload and source identity after releasing the heavy execution owner. Changed retries reject; original-pool scratch refusal preserves the exact retry and a subsequent forward commit invalidates the receipt. This component control does not qualify all-seat recovery. |
| HC58 | Shared network currency accepts a substitute asset, scoped balance policy or wrong precision | `canonical_network_xor_is_required_before_fee_reward_state_changes`, `network_xor_rejects_wrong_definition_scope_and_precision`, `staking_registration_rejects_wrong_xor_shape_with_transaction_rollback`, `public_fee_reward_claim_rejects_wrong_network_xor_without_writes_and_retries_original_plan` | `state/network_xor.rs` supplies the shared exact network identity and global scale-nine guard. Governance admission, active and restored policy, staking deposits, funded conversion and public fee-claim preparation enforce it before reserving or paying funds. The public claim control preserves original credit, receipt sequence, balances and staking principal on refusal, then retries the unchanged original authorized plan after exact currency restoration. The enacted fee asset remains distinct. Connected network conservation and full restoration remain separate qualification gates. |
| HC59 | The bounded beacon reducer retains an unverified partial signature | `threshold_beacon_inline_reducer_rejects_invalid_share_without_losing_original_slots` | Every share is verified against the exact public transcript and pulse before occupying an inline seat slot. Rebound or forged proofs cannot replace an original verified share. Fixed 31-seat storage and canonical subset order preserve the unique output; remaining transcript and cryptographic allocation funding is a separate release obligation. |
| HC60 | Publication preparation drops the original local resource source at the scheduler handoff | `certificate_capacity_refusal_reaches_scheduler_with_original_release_and_execution` | Actual exhaustion of the original State pool at QC encoding, availability encoding and original shared-control admission retains the same execution, preimage and queued commit. The exact release observation survives the worker boundary and backoff; foreign-pool release grants no retry credit, while release of the actual occupied owner permits the unchanged prepare, append and apply. This source-retention control does not establish release-driven scheduling or complete graph funding. |
| HC61 | Lane admission converts an original anchor-history capacity refusal into an invalid anchor verdict | `anchor_read_refusal_retains_original_lane_body_until_capacity_returns`, `anchor_history_refusal_retains_exact_source_through_lane_evidence_retry` | Admission, evidence verification and publication preserve the original anchor pool refusal without caching Invalid or changing the signed lane body. A foreign pool release grants no retry credit; releasing the actual occupied owner permits the unchanged body to reproduce its certified result. Component coverage does not qualify network scheduling. |
| HC62 | Prepared publication accepts an independently allocated control containing identical certified bytes | `prepared_block_moves_original_graph_and_rejects_replaced_shared_control` | The original executed entrypoint graph moves without cloning into one fallibly prepaid immutable block control. Committed execution, staged publication and Kura retain the same pointer and original State pool; substituting a fully funded same-pool control with identical bytes requires recovery before State visibility. Nested graph allocation and whole-network qualification remain separate open work. |
| HC63 | State publication replaces an original pool or physical-lock refusal with a retry string | `state_publication_lock_refusals_reach_scheduler_with_original_execution_and_release`; `state_execution_and_membership_refusals_preserve_actual_release_owners` | The worker and scheduler retain the exact original State allocation, hash writer, publication participant or membership writer release observation. Unrelated releases cannot wake it, locks carry no invented allocation demand, and retry preserves the original queued execution, overlay, shared certified block and durable append before one successful application. Timer-based dispatch remains; retaining a release observation alone does not establish release-driven scheduling. |
| HC64 | Committed archive capture replaces original authenticated-history or index contention with a retry string | `committed_archive_index_refusal_retains_original_release_and_exact_publication`; `committed_archive_cold_history_refusal_retains_original_pool_and_exact_publication` | After State is visible, the worker retains its exact pending decision, original precharged context bytes and actual history-pool or archive-index release source. An unrelated release grants no retry credit. Unchanged retry completes immutable archives and emits original events once without reapplying State; invalid certificates remain distinct failures. Native context publication performs I/O over already admitted bytes and invents no allocation source. Complete archive graph funding and release-driven network scheduling remain separate obligations. |
| HC65 | Cold publication preparation replaces the original unfinished execution refusal with a retry string | `cold_prepare_refusal_retains_original_finishing_owner_and_exact_release`; `cold_prepare_validation_refusals_retain_original_storage_owners` | World, hash-history and membership writers, context-proof scratch, original context archive and result encoding refusals preserve the exact original pool and release observation through cold Prepare and the scheduler. Retry retains the original overlay, witness allocations and queued decision; unrelated releases and changed certificates cannot acquire its retry source. Exact validation wrapper errors retain pool demand, lock role, predecessor observation and decoder counters. Impossible layout, poisoned storage and custody-identity failures require recovery; a pool ceiling has no invented release source. Execution and native receipt failures stay typed until the terminal execution report. Mailbox contention preserves its actual lock release without invented allocation demand; physical wait registration and complete nested graph funding remain separate obligations. |
| HC66 | Opaque host output or supplied proved replay derives unsigned staking monetary authority | `raw_ivm_staking_trigger_requires_signed_monetary_plan`; `supplied_proved_staking_effects_require_signed_monetary_plan` | The common consumption check recursively rejects monetary plans before the first queued effect, including raw VM trigger registration and resolved multisig approval. Actual transaction rollback preserves exact XOR balances, reserves and accruals; direct signed monetary instructions and ordinary nonmonetary raw output remain allowed. Supplied replay coverage tests the consumption boundary; production proof acceptance remains closed until the complete native STARK execution relation exists. |
| HC67 | Live multisig proposal reads turn an original bounded-decoder refusal into malformed authority | `live_multisig_proposal_decode_refusal_retries_original_signed_xor_transfer` | Opaque traversal and native approval retain the actual local decoder refusal before any approval or monetary write. Discarding the refused overlay and retrying the unchanged signed approval performs its exact original XOR transfer while preserving reserved staking principal. Missing, malformed and differently bound proposal rows remain deterministic outcomes. A cumulative Norito ceiling has no invented allocation pool or release notification. |
| HC68 | A retained multisig proposal changes its body or physical source while preserving an approved hash | `live_multisig_proposal_body_binding_rolls_back_original_signed_xor_transfer`; `live_multisig_proposal_missing_malformed_and_rebound_state_are_not_deferrals`; `persisted_multisig_body_binding_and_local_refusal_reach_signed_queue_admission`; `restored_multisig_proposals_require_exact_body_and_preserve_local_read_refusal` | Native execution, queue admission and restoration share exact account/key/content validation. The occurrence control changes the account, approved hash, nonce, occurrence ID, network and TTL and requires deterministic rejection, distinct from local decoder refusal. The existing V1 typed hash streams into its hash owner and retains original serializer refusal. Rejected operations roll back their actual transaction; unchanged signed transfers and serialized state retry. Controller changes require invalidation of outstanding occurrences; original terminal history remains bound to its original identity. Valid depth chains and repeated sibling approvals retain traversal coverage. |
| HC69 | Cancellation or expiry treats unfinished custom-instruction decoding as an ordinary nonmatch | `cancel_wrapper_decode_refusal_rolls_back_and_retries_original_signed_approval`; `expiry_child_decode_refusal_rolls_back_and_retries_original_signed_approval` | A measured original decoder budget completes the retained row read but refuses child classification. The native attempt retains that refusal before terminal records or pruning, and actual transaction rollback preserves proposal bytes. The unchanged signed approval retries with available capacity; cancellation wrappers remain excluded from terminal records, and ordinary non-multisig contents remain valid. |
| HC70 | Queue expansion ignores the native multisig execution depth bound | `persisted_multisig_chain_is_checked_in_linear_expansions` | A bottom-up graph of exact approved instruction hashes traverses 64 nodes in 64 expansions. One additional authenticated proposal rejects at the native 64-proposal bound; the guard unwinds and valid repeated siblings remain independent. |
| HC71 | Original World Cell acquisition loses physical contention through infallible initialization | `cold_prepare_validation_refusals_retain_original_storage_owners` | Cold Prepare acquires original Cell writers nonblockingly and retains their exact current or undo release observation through State validation and scheduler retry. Real held World, hash and membership writers cannot manufacture allocation demand or abandon the original queued decision. The test releases and joins its foreign lock holder on a finite deadline, so a blocking regression fails without hanging the test process. Partial acquisition retains prepaid generations and earlier guards until aggregate release; permanent poison remains terminal. |
| HC72 | Prepared-certificate acquisition stringifies an actual State reader refusal | `prepared_certificate_busy_retries_same_execution_after_original_reader_release` | The single nonblocking State view engine preserves each physical reader's original release source. A real held header writer defers the unchanged certified execution; release before polling remains observable, and retry preserves the original overlay, result, witness and availability custody. Exhaustive World/configuration release holders defer callbacks beyond enclosing fences on success and unwind. New State release controls use the original finite execution pool; this does not claim existing World initializer controls, EBR graphs or waiter registrations are fully funded. |
| HC73 | Physical history contention observes logical membership cleanup instead of its actual writer | `physical_history_busy_ignores_logical_cleanup_and_retries_actual_release`; `state_publication_lock_refusals_reach_scheduler_with_original_execution_and_release` | The logical membership writer and physical historical-tree writer have distinct notification controls, admitted together from the original membership pool. Logical cleanup and unrelated refunds cannot wake physical contention. No-edit admission retains the actual physical guard through refusal, success and unwind; deferred notification occurs after enclosing logical locks are released. Original preparation and publication retry retain the same execution and predecessor. This split prevents that self-wake source; HC74 covers prepaid registration and release-driven dispatch for the committed head. |
| HC74 | Committed-head prepare, append or commit retries use a timer instead of their original refusing source | `committed_head_waits_for_original_release_across_prepare_append_and_commit` | Each stage retains the exact queued decision and original source. A prepaid reusable registration and charged driver wake preserve the final drain-to-park edge without allocating a wake message. Foreign releases, elapsed retry ticks and stale prior-source callbacks do not authorize retry. Source replacement and recovery cancel the original slot. HC76 separately covers execution producers and controls; Shared ingress retries and complete execution funding remain separate gates. |
| HC75 | Cold DA reconstruction refunds its original allocation while physical writers remain held | `original_cold_da_refunds_follow_all_rebuild_and_rewind_writers` | Genuine signed genesis is decoded from the retained durable Kura frame. Its original execution-pool refund wakes only after every rebuild fence, index guard and retained replacement writer retires on success, decoder refusal and unwind. Failed reconstruction preserves indexes and the journal, retains the exact original decoder refusal, and retries the same committed prefix. The capacity observer admits no artificial pressure hold and callback probes require actual physical writers rather than decoding under the caller's refused allowance. |
| HC76 | Payload, witness, local-control or peer-partial retry uses a timer instead of its original physical refusal | `every_execution_producer_retains_original_source_until_actual_release` | Every bounded execution producer has a reusable registration admitted before Core starts. Exact fixed peer-slot backing and all `4 + MAX_COMMITTEE_SIZE` controls retain original pool custody. Elapsed time, repeated identical requests and accepted shares do not release a physical refusal. Different peers progress independently; complete context changes cancel obsolete work, and the original inbound input returns through the worker before any retry. Source-less failures keep bounded backoff. Shared ingress admission and complete execution-graph funding remain separate gates. |
| HC78 | A cancelled in-flight producer becomes current again when the identical context and request return | `cancellation_stays_final_when_the_identical_context_and_request_return` | Cancellation stays with the actual original worker attempt until its completion returns. Re-entering the same instance, epoch, parent, height, view or request cannot revive an old success or refusal. A fresh queued request retains independent retry state, and a cancelled inbound owner keeps its seat until returned and retired. A consuming failure still requires recovery even after cancellation. |
| HC77 | Pending decoded ingress retries without its actual original capacity release | `pending_capacity_requires_original_release_despite_foreign_wake_and_huge_clock` | A single original-pool registration is admitted before workers spawn. The exact decoded frame, partial byte backing and typed refusal remain in that one slot. Buffer and shared-control capacity failures watch only their original release; clock jumps, ordinary loop progress and foreign releases cannot authorize admission. Source replacement and successful, rejected or shutdown retirement cancel the prior registration. Source-less allocator and limit refusals use configured bounded backoff, included in the actual loop deadline. |
| HC79 | Completed replay acknowledgement stringifies its original encoding refusal | `completed_replay_retains_exact_receipt_through_original_pool_scratch_refusal` | Header, certificate and availability scratch retain the exact original State pool refusal without retiring the completion receipt or re-executing the block. A foreign refund grants no retry; the actual source release permits exact acknowledgement. The serialized executor and startup replay error preserve the typed publication or storage owner. Post-visibility archive failure, unwind, and physical retirement have separate connected regressions. |
| HC80 | Admitted ingress eviction refunds its original pool while pending or ingress mutexes remain held | `admitted_ingress_eviction_refunds_only_after_pending_and_ingress_mutexes_release` | A real admitted witness evicts another same-pool witness while an exact capacity refusal remains pending. Original-pool refund notifications defer through both mutexes; the callback independently probes both physical owners. The same test checks pending retry eviction and shutdown retirement without artificial pressure release, and cancels its observer before the final owner refunds. |
| HC81 | Native beacon readiness admission loses its original resource owner at worker or node startup | `beacon_startup_retains_original_capacity_through_worker_channel_and_node` | The fixed readiness control is admitted by the original State pool. Capacity refusal preserves its exact release source through the serialized executor and typed node error; no producer is attached or existing execution replaced. Actual release permits the same attachment, while duplicate attachment remains terminal. Native receipt-mailbox and driver startup errors retain their concrete owners; allocator failures carry their actual error without inventing a release. Beacon transcript and cryptographic scratch funding remain separate work. |
| HC82 | Cold World-root verification stringifies an original storage refusal | `world_root_verification_preserves_original_writer_refusal_and_exact_retry`, `world_root_verification_preserves_original_capacity_refusal_and_exact_retry` | The complete cold World capture keeps actual writer Busy and original-pool Capacity distinct from canonical capture errors and stored-root mismatch, including through startup replay errors. Unrelated refunds cannot authorize retry. Releasing the original writer or occupied original pool permits verification of the unchanged certified World; a stale accumulator remains a typed mismatch. |
| HC83 | Scheduler destruction refunds retained original controls before cancelling every linked waiter | `cancelling_and_dropping_scheduler_unlinks_all_waiters_before_original_refunds` | Cancellation retires all same-pool registrations before dropping original bodies, input owners, refusal carriers or registration backing. The real capacity callback remains silent during context cancellation, recovery and scheduler destruction; an earlier refunded control must never wake a later still-linked registration. |
| HC84 | Startup assembly converts original committed-history refusal into invalid configuration | `startup_history_retains_original_cold_kura_refusal_and_exact_retry` | Actual cold Kura admission keeps the original State pool and release observation through `assemble_init` and the typed node error. A failed read creates no missing entry or partial startup input; the same signed tip and complete header window retry after actual release. Global and lane callers preserve local deferral, while missing history and completed I/O or corruption errors retain their exact height and category. This boundary does not claim complete cold decoder or startup graph funding. |
| HC85 | An authenticated shared beacon session is reused under a substituted current context | `shared_authenticated_session_rechecks_every_current_external_binding` | Network, session, ordered-roster and transcript bindings are checked against the immutable sealed graph on every borrowed use. Sharing its original charged owner grants no new epoch or authority. Separate graph controls prove exact aggregate admission, preconstruction refusal, same-pool release, zero-allocation clones, last-reader credit retention and canonical lifecycle encoding; this does not claim complete DKG construction, snapshot decode or credential registry funding. |
| HC86 | An original local execution custody invariant is treated as retryable resource pressure | `original_local_custody_invariant_halts_worker_without_fee_result_or_quarantine`, `native_authority_prepaid_custody_errors_require_recovery` | The sticky host-local invariant abandons the original transaction without fees and requires native recovery before publishing a result. Clearing a local fault cannot authorize worker retry, quarantine, or a deterministic invalid-transaction verdict. Foreign native-authority custody, short prepaid reservations and compact-key layout faults also require recovery at the actual parent-service publication boundary. Real capacity refusals retain their distinct original release source. |
| HC88 | A beacon session decoder classifies its surviving original resource scope as malformed input | `session_decoder_preserves_actual_local_scope_without_invalidity_or_fabricated_pool` | Actual inherited decoder allocation refusal retains the original typed Norito source without charging the session graph or fabricating an allocation-pool release. The same canonical bytes retry successfully after the scope ends; malformed frames remain invalid. Raw decoder backing remains a separate physical funding obligation. |
| HC89 | Credential decoding collapses an actual inherited-scope or physical allocator refusal into invalid input | `credential_decoder_captures_original_scope_before_unwind_and_retries_unchanged_bytes`, `credential_decoder_physical_refusal_keeps_exact_allocator_cause_and_retries` | The canonical admission decoder captures the original Norito cause before scopes end. Header, global beacon and TLE imports carry that cause to startup and terminal boundaries; local refusal is unavailable and cannot consume the original launch credential. Intrinsic limits, malformed bytes and existing identity failures remain rejection. The same original frame retries after local capacity returns. Raw decoded graph and frame backing still require a separate physical funding cutover. |
| HC90 | Native journal verification relabels original block-control capacity refusal as invalid evidence | `native_cursor_preserves_original_pool_refusal_and_retries_identical_prefix` | The complete independently pinned journal reuses one caller operation pool. Its exact original refusal and release source survive verification and provisioning; no callback or cursor update occurs on refusal. Foreign refunds cannot authorize retry; the identical prefix succeeds after actual source release. Canonical block/header checks remain strict and malformed source remains rejected. Raw source, decoded graphs and index backing still require separate full retained funding. |
| HC91 | Live DKG discards its pre-claim signature output and reconstructs it after RNG begins | `prepared_local_outputs_are_complete_before_randomness_at_four_and_thirty_one` | A local attempt physically prepares original-pool row, signature, private-share and maximum canonical public-frame backing before its one-shot durable claim or randomness. Generation and each signed phase use that same backing without late allocation, for exact 4- and 31-seat geometry. Public reducer imports/snapshots/finalization retain the original pool and refuse without changing the event cursor. Raw input DTO/transport and final credential encoding still require separate retained funding. |
| HC92 | A beacon credential producer allocates a second whole secret frame after private extraction | `prepared_credential_uses_exact_original_output_without_late_growth_at_four_and_thirty_one` | The exact global-beacon public inventory prepares the original-pool output before extraction. Share validation borrows unchanged source owners and canonical encoding uses that same backing without growth for 4 and 31 seats. Errors scrub only initialized output and retain sources for retry; final export retains actual descriptors, offsets and completed-file identity. Raw input graph funding and a retained command-wide attempt loop remain separate requirements. |
| HC93 | Broker signing re-verifies and re-admits the same beacon session at every request phase | `beacon_operation_reuses_original_graph_across_ingress_dispatch_and_response` | One authenticated operation retains its original-pool sealed session through ingress, real signing and full response verification. Every reuse checks the complete canonical record and external binding. Exact 4/31 phase tests succeed under full original-pool saturation; the repeated-admission mutant must fail. The daemon-only mutation lane uses test-only compilation, never a node fault control. Original deadlines remain enforced; raw decoder backing is a separate obligation. |
| HC96 | Validation-fee permission delegation erases a failed protected registry read | `malformed_protected_registry_rejects_account_grant_before_permission_mutation` | The exact protected registry must complete before account Grant/Revoke or role Register/Grant changes permissions. Malformed retained DATA rejects without events or mutation; original local decoding refusal retains its attempt owner and unchanged inputs for retry. Recognized runtime permission names require complete typed payloads, while unrelated names and absent registries preserve their original contract. |
| HC97 | Trigger permission delegation erases recognized original payload rejection or refusal | `malformed_trigger_permission_rejects_account_grant_before_mutation` | Each recognized trigger-control permission must finish its original typed JSON read before account Grant or role Register/Grant mutates delegation. Malformed DATA rejects without events or mutation; original local decoding refusal retains its attempt owner and exact DATA for retry. Unrelated names bypass this decoder, valid external triggers remain unprotected, and enacted payout-trigger authority stays nondelegable. This boundary does not qualify complete decoder graph funding. |
| HC43 | Certified history turns original local result or source decoding refusal into malformed committed input | `original_result_frame_refusal_is_local_and_same_bytes_retry`, `original_successor_history_refusal_is_local_and_same_source_retries`, `state_certificate_native_qc_decode_refusal_is_capacity_and_retries_original_source` | The original State history reader and successor schedule boundary preserve non-wire local attempt refusal. Funded query readers retain the exact original decoder-limit fields. Same signed bytes retry after the caller limit releases; altered result preimages remain completed rejections. No pool notification or retained partial decoder is invented; downstream application adapters and complete graph funding remain separately open |

| HC98 | Native source publication change halts local storage instead of authenticating a fresh cut | `native_source_publication_change_retries_without_recovery_or_quarantine` | Exact original proposal and lane expansion generation checks remain mandatory. A newer publication of the same State requires fresh source acquisition and authentication; it does not authorize rejection, quarantine, reuse of stale authority or a storage halt. Foreign State substitution, poisoned owners, reader custody mismatch and corrupt durable indexes remain terminal. |
| HC99 | A concurrent State publication replaces an original unfinished local capacity refusal | `native_local_refusal_after_source_publication_retains_original_capacity` | The exact original refusal and its finite pool survive rejection observation unchanged, with no events or committed effects. A newer State cut cannot replace local resource custody. Only release of the original occupied capacity permits its same-pool retry; pre-existing terminal owners also retain identity. |
| HC100 | Candidate ranking binds the election to E+1 instead of E+2 | `genuine_candidate_pools_choose_largest_equal_vote_committee` | Real BLS candidate pools of 4, 5, 8, 11 and 32 independently reproduce the exact E+2 domain-separated ranking and ordered equal-vote roster. The frozen preparation interval and certified publication remain separate checks. |
| HC101 | A single funded target substitutes for custody of every frozen target seat | `prepared_boundary_readiness_requires_every_frozen_seat_custody` | Genuine attempt-bound paired and beacon readiness plus independently reconciled Global XOR source rows pass only when every frozen seat meets its original floor. Reducing each seat independently below that floor refuses readiness while preserving exact additive backing; target quorum does not authorize activation. This is the production boundary condition's component gate; certified retention and whole-network rotation remain separate. |
| HC102 | A target quorum substitutes for the complete signed readiness roster | `prepared_boundary_readiness_requires_every_frozen_seat_custody` | Six valid, distinct readiness proofs cannot activate an immutable seven-seat target. The same production condition also requires every target's frozen monetary custody; invalid proofs remain rejected by their unchanged admission owner. |
| HC103 | Certified retention requires fresh incumbent key publications | `frozen_boundary_refusal_returns_original_pool_and_does_not_need_fresh_incumbent_keys` | Exact original-pool retry retains the authenticated current committee and authority after its fresh candidate key records expire; no new election is fabricated. The current exact quorum, installed beacon and fresh epoch randomness remain mandatory. |
| HC104 | A foreign clock supplies DKG generation source authority | `signed_genesis_authority_keeps_original_wider_cutoff_and_authenticates_no_h1_result` | Core constructs private-field checkpoint authority only from the exact signed genesis or verified frozen selection and genuine native cursor. Signed H1 authorizes generation and supplies no execution result. Every phase retains the original network, chain, schedule and applicable source window. |
| HC105 | Generation restoration ignores an original input marker or later producer intent | `input_marker_or_later_intent_cannot_restore_generation_or_grant_a_new_interval` | Only a complete canonical generation intent/checkpoint/publication/head set before any input consumption or later producer intent may reopen the generation phase. Complete later prefixes restore their original phase owners sequentially from durable inputs and genuine native proofs; partial input/producer and aggregate/extraction restoration remain closed. An interrupted later producer cannot reroll or reopen generation. |
| HC106 | Generation restoration accepts a replaced inherited input stream | `generation_reload_rejects_foreign_provider_original_cutoff_fake_h1_result_and_replaced_input` | The immutable producer intent inside AEAD binds original claim root/child/path, lifecycle/provider and both inherited stream identities. Restart borrows those original streams and cannot reopen a named FIFO or substitute another source. |
| HC107 | Generation restoration grants a fresh caller interval | `actual_native_boot_origin_freeze_restore_cannot_extend_admitted_deadline` | Original expiry binds the suspend-inclusive native clock and actual OS boot identity before claim. Restart rejects origin regression, reboot and expiry, conservatively converts the remaining interval without rounding extension, and only tightens all input/claim deadlines. |
| HC108 | DKG extends its original signed genesis cutoff | `signed_genesis_authority_keeps_original_wider_cutoff_and_authenticates_no_h1_result` | The exact original wider cutoff comes from signed epoch authorization or the frozen preparation target; it is distinct from individual commitment/delivery/acceptance windows. Generation restore cannot choose another schedule or cutoff. Source controls and mutation runs do not qualify the unfinished all-phase/all-seat network graph. |
| HC109 | Generation restoration treats visible complete files as already durable | `visible_complete_original_head_is_synced_before_restored_claim_and_publication` | Complete head bytes can survive a process interruption before their original fsync. Restoration resumes sync through the exact retained intent/head/publication/private descriptors, then the original child/root directories, before adopting the claim or reporting publication durable. Refusals retain the original owners and pending barrier; no file rewrite, secret reroll or fresh interval is permitted. |
| HC110 | Verified target proof transport is consumed before its original durable preservation | `original_verified_target_proof_publication_refusal_retains_frame_and_never_advances_twice` | A genuine native target journal advances the sole clock only once. Its exact charged FIFO frame, canonical decoder and source stay retained across an actual exclusive-create refusal until the original file/directory barrier completes; no reread or second clock advance is allowed. |
| HC111 | Complete later restoration ignores a surviving partial extraction or final-session intent | `complete_original_later_head_never_reopens_partial_next_read_or_extraction_intent` | Only a complete original intent/private/output/head prefix may restore a later phase. A next read marker, incomplete producer or extraction intent closes the previous head before any FIFO read or one-way producer operation; it cannot authorize reopening, rerolling or a fresh deadline. |
| HC112 | Delivery restoration retires the original polynomial before durable publication | `actual_native_heads_restore_original_delivery_then_acceptance_without_signing_or_growth` | The move-only restored delivery owner retains its original polynomial and checkpoint until the daemon completes all original private/output/head file and directory barriers. Core restoration never signs, re-proves or rerolls an output; only that subsequent barrier permits retirement. |
| HC113 | Acceptance restoration omits original signed capsule/private component checks | `original_signed_capsule_relation_is_checked_before_any_accepted_owner_or_row_moves` | Public signatures and an AEAD-bound checkpoint alone cannot authenticate their private relation. Restoration decrypts every actual signed own-recipient capsule and compares every original private component before moving accepted owner backing or public rows. A validly re-signed corrupted capsule remains a completed refusal. |
| HC114 | Aggregate authority omits the actual finalized native-tip height binding | `aggregate_checked_context_refuses_nonfinal_native_tip_zero_intent_and_changed_original_checkpoint` | A distinct private-field aggregate context requires the genuine original native tip at or after the frozen acceptance boundary and exactly the sealed public session's finalization height, below the original cutoff. A preparatory zero intent hash permits only immutable intent serialization; private production or restoration still requires the actual nonzero extraction intent. Raw crypto binding bytes never grant protocol authority. |
| HC115 | Aggregate production erases original contributions and acknowledgments before durable handoff | `actual_native_h4_aggregate_stays_original_until_explicit_retirement_and_restores_small_owner` | One original pre-funded aggregate-only bank retains the actual96-byte scalar leaf and immutable ciphertext. Producing that aggregate leaves all original individual contributions and acknowledgments live until the sole daemon publisher completes the original checkpoint/head file and directory barriers and requests the move-only handoff. Completed-head restore decrypts and checks exact original scalars/public equations without rebuilding private phase graphs, RNG, signing or re-aggregation. These component controls do not establish whole31-seat restart or production release qualification. |
| HC116 | Aggregate restoration omits original held-source file and directory durability barriers | `original_complete_aggregate_and_four_output_heads_restore_genuine_h3_h4_ancestry_same_claim_and_exact_private_bytes` | Genuine H3→H4 ancestry and checked complete context precede private restoration. All nine original source extents and fixed intent/head descriptors retain their exact names, inodes, bytes and pool across refusal. Their actual file and parent-directory barriers complete, with every original name rechecked after blocking sync, before the same inherited claim or export owner is adopted. A complete visible head is never sufficient durability evidence. |
| HC117 | Aggregate export restoration treats a partial output set as a fresh destination | `original_aggregate_head_rejects_partial_final_output_prefix_before_private_export_adoption` | Completed aggregate reload admits only no final outputs or all four exact verified original outputs. A mixed or partial published prefix cannot reopen an encoder, recover invented offsets, replace source custody or authorize a preceding phase. Complete outputs restore through their same held descriptors and actual durability barriers without rewrites, RNG or re-signing. Original incomplete producers and partial output recovery remain explicitly closed. |
| HC118 | Native journal source omits its original prepared pool binding | `native_reader_rejects_foreign_prepared_source_pool_before_decode_or_control_admission` | A private canonical journal frame preserves the actual charged source owner and exact source span. Core rejects a prepared source from another operation pool before decoder work, control admission or authentication; the unchanged source still retries with its original pool. Ordinary offchain journals cannot manufacture charged provenance. This source seam does not fund the complete nested SignedBlock payload/result/DA graph. |
| HC119 | DKG native replay pins a foreign charged proof source before checking its original pool | `durable_native_replay_rejects_foreign_source_pool_without_pinning_or_advancing` | Restore consumes the actual original durable proof-bank owner. Foreign pool input cannot pin the journal or restored source, advance the real native clock, consume FIFO state or obtain replacement credit. A same-pool original frame subsequently restores genuine H2 ancestry with unchanged pointer/hash, deadline and stream generation. Storage provenance grants no finality authority and completed semantic proof graphs remain separate obligations. |
| HC120 | Signed evidence treats original immutable-root JSON refusal as missing or malformed input | `original_signed_evidence_root_scope_refusal_stays_local_and_retries_same_state`, `original_root_observation_refusal_keeps_pending_bytes_and_same_state_retry` | Original root metadata decoding must complete before history grants evidence authority. Genuine enclosing JSON allocation refusal remains local through the existing native-history, admission and block-validation owners, without a fabricated allocation-pool notification. The same original State and signed QC pair retry after the enclosing scope ends; observation leaves pending frames untouched on refusal and retains one original charged canonical frame on successful retry. Missing/malformed metadata, foreign instance, invalid epoch and invalid signatures remain completed rejection. This rule does not establish full proof/context/crypto graph funding or network slashing qualification. |
| HC121 | Quantity capture replaces the original producer invocation dataspace with temporary fee storage | `paid_merged_lane_burn_keeps_original_nonuniversal_source`, `original_invocation_capture_keeps_fee_storage_separate_and_rejects_call_lane_confusion` | Each actual Network, Pipeline and Time producer binds its exact invocation call, route and authenticated root before body or fee execution. Quantity journal and transfer captures reuse that fixed original owner while fees retain their actual global or restricted balance storage. Changed call or lane identity rejects. Completed private-root callbacks retain the captured root namespace in canonical output order. Mandatory finalized journal/context equality remains strict; no supplied capture grants invocation authority or finality. The named paid lane-to-global control must pass on the repaired current source and kill the temporary-storage mutant. |
| HC122 | Retain a retired historical ready store after its final reader closes | `retired_historical_ready_store_releases_last_owner_after_completed_reader` | Returned readers and original pending read, publication and batch work pin the same memory and exclusive lock. Once all are gone, reconciliation releases the sole ready owner while preserving certified disk frames. No physical deletion is authorized. |
| HC123 | Discard an original pending read or publication before a batch owner exists | `retired_ready_store_preserves_original_read_refusal_before_batch_population`, `retired_ready_store_preserves_original_unfinished_publication_until_exact_retry`, `retirement_pending_work_probe_retains_each_held_mutex_without_waiting` | Both retirement entrypoints retain the actual original frame or prepared output through refusal. Separate nonblocking probes preserve a busy state or batch mutex without changing the lock order. The unchanged available body and certificate retry in the original finite pool, then the completed final owner can release. |
| HC124 | Cancel runtime recovery after an actual historical caller joined its retained opening | `historical_join_of_runtime_opening_retains_original_recovery_after_lane_retirement` | Historical joining interest is recorded independently of runtime ownership before recovery resumes. Runtime retirement cannot discard that exact independently authenticated prefix, original allocation charge or native lock. Unjoined runtime-only openings may still cancel after drivers and recovery jobs stop. |
| HC125 | Report cached lane tip despite an unfinished original read failure or refusal | `ready_tip_preserves_same_original_authentication_failure_without_reopening`, `ready_tip_retains_original_pool_refusal_and_completed_read_until_normal_consumption` | A fallible historical tip observation completes the same original pending read under its actual State mutex and pool before reporting durable height. Authentication rejection and exact local Capacity/release provenance propagate unchanged. Completed read custody stays in its original slot for normal consumption; no new decoder, authority, allocation pool or runtime height semantics are substituted. |
| HC126 | Reuse a local BLS credential after its proof of possession changes | `repeated_exact_pop_admission_retains_original_credential`, `repeated_committee_admission_retains_owners_and_failed_batch_is_atomic` | The same key and exact canonical proof reuse only the original request or node owner. Any changed or malformed proof still verifies and rejects without replacing that credential; a failed batch publishes no new members. An exact credential published during batch verification survives publication. No global admission cache or transfer between unrelated owners is permitted. |
| HC127 | Core Nexus snapshot writes a retained runtime predecessor without its explicit present-value frame | `snapshot_runtime_requires_exact_retained_predecessor_and_roundtrips_both_cuts` | The actual full-State producer borrows the original runtime current/undo pair and uses the sole explicit MV framing before component restoration. A present original value is not an absent predecessor. This Core hook mutates only the manual Nexus writer: separate owning MV optional-value, attached/detached and real-revert controls qualify the dependency writers; complete-State and certified-history restoration remain open. |
| HC128 | Publish local proposal wire before original-pool empty signature preparation | `original_local_payload_signature_refusal_keeps_job_and_exact_release_owner` | The actual local payload job prepares only its original empty signature leaf before the sole canonical writer. A refused exact control retains the same block, children, job and typed original release observation; retry never grants a foreign pool or rewrites transaction bytes. Completed preparation survives output refusal idempotently. This rule supplies no transaction, DA, result, execution, availability or finality authority, and does not establish complete block graph funding. |
| HC129 | Retry native validation after a consuming unwind lost its original graph | `consuming_validation_unwind_requires_recovery_after_original_owner_is_lost` | A real caught unwind releases the consumed original owner; the resulting local condition requires recovery and cannot request ordinary reexecution. Successful validation returns its same original owner. This classification does not establish complete unwind-safe graph custody. |
| HC130 | Discard an original completed decoded proposal and reenter canonical decoding on retry | `completed_decoded_retry_borrows_original_graph_without_canonical_reentry` | The existing original-source attempt retains the completed canonical graph and its prepared leaves until an explicit retirement or actual validator transfer. Same-pool/address/whole-wire identity remains mandatory. Every retry reruns current parent, schedule, height/view and lane/source checks before production validation; retained decoding is no execution or finality authority. A local validator error returns the actual block and only its exact canonical resultless projection may rejoin the original attempt. Projection refusal or source mismatch retains that graph and fails closed. Full transaction/DA/result funding, post-validation refusals and consuming-panic ownership remain open. |
| HC131 | Accept an independently prepared signature collection with equal canonical wire in the same source pool | `same_source_same_pool_distinct_prepared_signature_owner_is_refused_at_both_boundaries` | At both completed-decoding reuse and validator-return recovery, the block must retain the exact original prepared signature control. Same source bytes, canonical proposal, pool and signature values do not substitute an independently admitted owner. The allocation-free Model observation checks the decoder's unchanged original input and compares the physical collection control. This Core mutant bypasses only the two physical-control requirements; Model equality and all source, pool, wire, height/view, current schedule/authority checks remain unchanged. The named unmutated control covers both boundaries; its completed-boundary refusal assertion kills the mutant. This rule qualifies only signature-control identity, not transaction/DA/result graph funding, consuming-unwind custody or full H1/H2 integration. |
| HC133 | Output finalizer ignores the original lane-step outcome and seals after local custody refusal | `original_lane_finalizer_refusal_returns_same_graph_before_seal_and_publishes_after_retry` | A genuine signed four-validator autoscale genesis and actual available proposal encounter finite original-pool pressure at the native lane finalizer. Validation must return the same entrypoint/signature graph before sealing, without publication, negative verdict, quarantine or replacing the source. Restoring the unchanged pool retries that graph through actual quorum certification, durable append and State publication. The mutant ignores only the lane finalizer's propagated outcome; authority, original input, schedule, exact quorum and availability checks remain. The native boundary adds closed non-wire phase provenance to the same `ExecutionDeferred`, preserving the exact resource reason, refusal and original release source. The control stops only at this real finalizer boundary; a resource category or post-validation take alone cannot claim coverage. It uses real capacity refusals without protocol or allocator hooks. Its signed autoscale window is 2,048 and its 1,024 nonempty E0 blocks pass actual execution, exact four-validator quorum certification and publication. Every retained sample is aligned with its authenticated committed height and time; each non-genesis sample has its real successful clock-work transaction. The finalizer must request the exact next retained-suffix backing plus shared-control layout, exceeding earlier observed transient execution allocation requests. The original 128 probes and named-test deadline remain unchanged; runtime and HC133 mutation qualification require the fresh candidate run. Complete transaction/DA/result graph funding, paid settlement, restart and whole-network qualification remain separate. |
| HC134 | Witness handoff promises retry after the original captured witness is absent or source-invalid | `validated_witness_guard_failure_requires_recovery_without_reexecuting_original_source` | The actual native validator seals one signed four-validator available proposal with original-pool signature custody. Its private production handoff must retain the same successful graph through real quorum certification and publication; prior one-shot extraction or an actual empty application after the output seal makes witness extraction refuse. Neither fault is a local allocation continuation. The handoff must latch recovery before dropping the sole validated graph and overlay, and a subsequent Execute must stop before decoding or re-execution, without a negative verdict, queue quarantine or publication. The mutant restores only the former Retryable witness-absence branch. Faults use existing State/accessor APIs without protocol hooks or mutating funded wire buffers. Complete graph funding, restart, paid settlement and whole-node qualification remain separate. |
| HC135 | Deep-copy the original graph while cloning an authenticated borrowed accepted transaction | `native_amx_persisted_paid_borrowed_prepared_proof_clone_retains_original_graph_and_lifetime` | An accepted borrow retains its original source and Rust lifetime when cloned; it cannot silently promote that borrow into a replacement owned graph. The named control uses actual signed four-validator global and independent private roots, paid native escrow, genuine registered persisted Prepared certificates and nonempty original proof buffers. It checks original object/buffer identity, canonical bytes/hash, retained validation time and shared cache, ends borrowed wrappers, then moves the same source through actual owned admission and paid global Commit. The mutant restores only the old borrowed clone promotion. This narrow rule neither repairs owned-entrypoint or Queue enumeration copies nor establishes complete physical graph funding: Queue fee admission holds still retire at logical removal; the separate original shared-owner rule below retains its resident estimate and physically prepaid control through the final reader. Nested decoded/cache allocations and detached owned copies remain separate open funding boundaries. Reader scratch, owning producer/decoder and publication/restart custody remain separate open boundaries. |
| HC136 | Erase the original finite-pool refusal during native signer pinning, State admission or sample finalization | `original_signer_pinning_refuses_then_retries_the_same_pool_and_stake_cut`, `sample_finalizer_refusal_preserves_exact_source_and_retry_funds_only_suffix` | Native custody retains exact `Capacity` fields and its pre-refund original-pool `ReleaseWait`, and exact `ExceedsLimit`/`DemandOverflow` as `ExecutionDeferred`. Foreign original pools and insufficient prepaid backing/control are local invariants requiring recovery; only physical allocator refusal reports `AllocationUnavailable`. Invalid sparse signer bounds/order remain deterministic. Real pinning and sample-finalizer controls preserve source/stake cuts, exact suffix demand, release notification and same-pool retry/last-owner refunds. This rule neither funds outer lane vectors/Cell controls nor establishes whole-node or complete transaction custody. |
| HC137 | Refund original Queue resident admission credit when only its map slot is removed | `removed_pending_owner_retains_original_resident_credit_until_last_reader` | The actual production shared accepted owner retains the original Queue resident policy estimate and its exact State-pool control charge through the final original reader. Queue metadata/fee admission holds retire at their existing logical boundary; removed accepted readers cannot grant resident admission credit while still live. Real signed inputs and an actual four-validator State/manifest fixture exercise retained byte pressure, original instruction/canonical-cache identity, refusal and same-Queue retry after final destruction. Exact ledger and shell layouts are prepaid from the original finite State pool; original pool refusals keep their release observations and physical refunds/watches follow Queue fences. The mutant restores only the old early resident subtraction. The encoded-size expansion remains an estimate: nested decoded/proof/cache allocations, owned clones, detached enumeration/gossip copies, fee-hold policy, paid AMX restart and whole-node custody remain separate open boundaries. |
| HC138 | Observe absent Queue resident custody before acquiring its actual mutation fence | `cold_queue_retirement_holds_original_fence_until_first_admission_can_publish` | Cold retirement must acquire the existing original Queue writer before observing its shared resident ledger. A competing first admission cannot initialize and publish an accepted owner between that observation and removal. The same original finite pool, typed refusal and graph remain; the actual Queue guard releases before after-unlock actions, watch updates or physical refund callbacks. Nexus revalidation preserves Nexus-before-Queue acquisition and retains that original Nexus owner through its after-unlock actions. An independent thread synchronously probes the real cold writer, then actual prepared signed four-validator admission retains original graph/cache identity and exact ledger/shell charges; real original-pool pressure and retirement verify exact release after both physical guards. The mutant skips only the original Queue writer; no allocator/protocol hook, timing sleep, new lock or alternate owner is introduced. Full nested graph funding, detached owned copies, monetary/network/restart and complete mutation qualification remain open. |
| HC139 | Rewalk complete executed ancestry when selecting the signed-genesis root for a new certificate or native successor context | `prepared_certificate_uses_bounded_signed_root_without_rewalking_execution_history`, `successor_context_uses_original_parent_and_bounded_signed_root_without_history_rewalk` | Root instance selection consumes only the exact durable State-pinned signed genesis through the existing `CertifiedChain::new` reader. Network/journal identity, complete signed proposal commitments, genesis signatures and original decode/pool refusals remain mandatory. The original current-parent native tip read continues to authenticate execution `R` and all three parent identities; signed genesis grants no result-only genesis execution, current World authority, restoration or cached-body trust. Actual four-validator chains measure the completed original single-root/current-parent decode cut, refuse the unnecessary historical walk under that same original limit, preserve exact certificate quorum and native context negatives, and publish the unchanged original funded execution. Both test-only mutations restore only the unnecessary executed-genesis read. No history/sample edits, cached verdict, pool replacement, deadline change or whole-node qualification is introduced. |
| HC140 | Reuse a pending-input lease after actual certified State publication withdraws its original cut | `pending_payload_lease_retires_on_actual_certified_state_publication` | A real signed clock block executes and publishes on the existing exact four-validator CertifiedTestChain. The Queue still holds the original unexecuted input, but the earlier even publication generation grants no current lease. The mutant skips only the authoritative current-lease publication-generation comparison; original State publisher Busy/release observations, Queue fence, applied-input/expiry checks and pool ownership remain. This is a component custody rule; full paid nested graph funding, whole-node/restart and full mutation qualification remain separate. |
| HC141 | Adopt same-hash clear/readmission during an earlier pending-input selection | `pending_payload_selection_cannot_adopt_clear_and_readmission_during_selection` | Selection captures the original Queue admission high-water before its actual bounded signed-input snapshot. Clear and same-hash readmission preserve the exact ingress timestamp yet create a new checked incarnation. Capture must refuse a row whose incarnation exceeds the prior selection high-water and refund its temporary admission table; the current selection must succeed. The mutant skips only that incarnation comparison, preserving actual inputs, State generation and original mutation fence. This is a component custody rule; full paid nested graph funding, whole-node/restart and full mutation qualification remain separate. |
| HC142 | Lend an original selected-input lease through a foreign Queue | `pending_payload_lease_uses_original_backing_and_retires_on_expiry_withdrawal_or_foreign_queue` | Two actual Queues admit the same signed input from the same certified State and original finite pool. Equal input bytes, pool and generation do not make their Queue identity interchangeable. The mutant skips only the authoritative current-lease Queue-address check; original State identity, generation, expiry, applied-input and hash checks remain. This is a component custody rule; full paid nested graph funding, whole-node/restart and full mutation qualification remain separate. |
| HC143 | Treat zero or expired original selected-input residence as a current lend | `pending_payload_lease_uses_original_backing_and_retires_on_expiry_withdrawal_or_foreign_queue` | The actual mock clock advances beyond the original Queue TTL while the signed input still occupies its original Queue. Before withdrawal the original lease must already refuse lending. The mutant admits zero remaining residence and skips only the matching live-input expiry check in the authoritative current-lease read. Actual time, Queue parameters, ownership/State generations, applied-input checks and timer-only storage fallback are unchanged. This is a component custody rule; full paid nested graph funding, whole-node/restart and full mutation qualification remain separate. |
| HC144 | Erase original pending-input capture Capacity refusal into absent work | `pending_payload_lease_preserves_original_capacity_refusal_and_refuses_generation_wrap` | The original certified State pool is genuinely saturated after a prepaid release registration. Hash-table capture must return the exact original Capacity fields and pre-refund ReleaseWait, notify after the held charge drops, and retry from the same pool. The mutant converts only a ChargedBuffer Admission failure to Ok(None), without allocating replacement backing, replacing the budget or publishing a lease; physical allocator errors remain errors. This is a component custody rule; full paid nested graph funding, whole-node/restart and full mutation qualification remain separate. |
| HC145 | Wrap an exhausted original Queue admission high-water instead of refusing new custody | `pending_payload_lease_preserves_original_capacity_refusal_and_refuses_generation_wrap`; `pending_payload_admission_exhaustion_refuses_before_input_publication` | Actual expiry or a new admission encounters the original high-water at u64::MAX. Exhaustion must latch the original admission fault, retire the previous lease and refuse selection/capture and new input publication; admission-table, release registration and Queue ledger charges conserve exactly. The refused new input cannot appear in the Queue or take a fee reservation. The mutant changes only checked incarnation increment to wrapping increment. The fixed representation and actual removal/refund/lock order are unchanged. This is a component custody rule; full paid nested graph funding, whole-node/restart and full mutation qualification remain separate. |
| HC146 | Omit exact compiled native descriptor/key admission before State dedup publication | `unsupported_retired_and_claimed_backends_fail_state_admission`, `native_compiled_descriptor_refusal_preserves_key_admission_and_original_retry` | State preserves its payload size/budget guards and current CoreZK backend, activity, commitment and canonical metadata refusal order using a fresh one-entry admission cache. Before publishing a Native PIPA-R dedup key, supplied bounded verifier originals must match the locally compiled relation, including descriptor/parameter identity and processed key. Consistently rehashed foreign descriptors, keys, foreign relations, bare/trailing carriers and oversized originals refuse without poisoning retry; exact original native proofs/keys remain admitted and share the existing explicit/resolved-commitment dedup preimage. STARK keeps its independent admission. The test-only mutant skips only the Core caller's compiled native material guard. Lightweight preverification does not establish cryptographic verification or admit retired names, monetary authority or compatibility labels. |
| HC147 | Replace an original native AMX archive-write pool refusal with a generic source failure | `persisted_amx_original_read_retains_acquired_inode_and_exact_pool_through_decode_refusal` | The authenticated archive reader retains the exact capacity cause, original pool and release observation; refusal is neither record absence nor substituted authority. The control saturates the actual pool after bounded acquisition, compares the original refusal and release wake, then retries the same source. |
| HC148 | Discard an acquired original AMX archive prefix after its owning decode refuses | `persisted_amx_original_read_retains_acquired_inode_and_exact_pool_through_decode_refusal` | A pending producer keeps the original descriptor and charged complete prefix through physical and inherited decoder refusal. Replacing the pathname cannot replace that source on retry; exact charge conservation and successful verification of the same certified record are required. |
| HC149 | Decode a native AMX leg through a fresh foreign allocation pool | `native_leg_decode_refuses_occupied_original_pool_before_any_copy_and_retries_exact_source` | Actual Prepare must admit compact keys, multisig member/key ledgers, transient sequence spans and Quantity digits from its original execution pool before those allocations. A genuinely occupied original pool refuses before any copied graph or alignment scratch; retry preserves the original signed source and typed refusal/release identity, and the last decoded owner refunds exactly its retained layouts. The test-only mutant substitutes a fresh pool with the same finite limit. Original Worker partial/completed decode retention is separately covered by HC150 and HC222; indirect invocation, diagnostic String custody and witness publication remain open. |
| HC150 | Retire a completed native AMX leg and its canonical decoder controls before the same Worker retry | `original_paid_amx_post_decode_refusal_retains_worker_leg_and_exact_retry` | A Candidate capacity refusal retains the actual completed graph, original pool and decoder controls with the same original signed block attempt. Releasing real capacity reruns current authority/proof/balance/fee/effect checks without materializing that canonical leg twice. This is not execution-result caching; HC222 separately covers partial decode retention; indirect/lane invocation and diagnostic custody remain TODOs. |
| HC151 | Accept a replaced original SignedBlock input graph for completed AMX reuse | `completed_amx_worker_bank_refuses_replaced_source_parent_and_foreign_pool` | Retention binds the actual original charged RS16 source and original signed-input backing in its signature attempt, original pool. An equal-content clone cannot authorize reuse; every execution attempt separately authenticates its exact current native parent/result/epoch before borrowing completed legs. The mutant omits only the original input backing check. |
| HC152 | Collapse distinct equal Prepare occurrences into one completed leg | `completed_amx_worker_bank_preserves_equal_occurrences_and_metadata_refusal` | Each exact signed input and instruction ordinal retains its own original leg frame and successful decoder work. Equal values do not collapse occurrences. Metadata admission occurs after completion; its refusal retains the inline completed owner and real controls, with no fresh pool or whole-frame preview. |
| HC153 | Substitute committed membership for the exact staged original successor | `original_publication_pair_matches_real_advance_replace_and_repeat` | Both maps and the frontier come from one already admitted retained publication writer. The staged current map differs from an independently committed observation before publication, and the exact pair must match that same writer's subsequent real publication. The mutant replaces only staged visitation with the predecessor committed view. This is a non-authorizing complete-State capture prerequisite; full cells/history, publication integration and finality remain open. |
| HC154 | Retain the repeated tip in the successor rollback map | `original_publication_pair_matches_real_advance_replace_and_repeat` | Ordinary advance, replacement and exact repeated publication preserve their actual current and predecessor cuts. A repeated tip is excluded from its rollback just as it is after real publication; shadowed predecessor values survive. The mutant omits only this repeated-tip exclusion. |
| HC155 | Lend a prepared writer after terminal publication markers | `original_membership_cut_refuses_started_published_unwind_and_completed_phases`, `detached_membership_cut_refuses_started_published_unwind_and_released_phases` | Attached and fully reacquired detached readers refuse started/published markers, including a phase retained by caught unwind, and refuse completed/released owners. Private marker models and real successful publication exercise reader admission; they do not claim an injected production-kernel panic. Pool identity of a borrowed refund scope does not prove batch lifetime: the complete aggregate must retain its existing StatePublication refund owner through sibling release and provisional-node cleanup. No capture output authorizes publication or finality. |
| HC156 | Accept a borrowed refund scope from another original pool | `original_membership_scope_partial_foreign_and_released_owners_refuse` | The scoped encoder derives its allocation budget from the actual retained State and refuses a foreign refund-scope pool before constructing nodes. Equal finite limits do not identify the same original pool. The mutant omits only this identity refusal; batch lifetime remains the future aggregate owner's separate obligation. |
| HC157 | Accept a prepared original from foreign membership storage | `original_membership_scope_partial_foreign_and_released_owners_refuse` | Equal staged rows and heights cannot replace the State's actual membership family. The source check uses retained storage addresses, not an equal-content map or caller root. The mutant omits only membership-family identity. |
| HC158 | Mix replacement membership with an ordinary frozen World | `original_membership_scope_partial_foreign_and_released_owners_refuse` | A same-storage prepared writer still must match the actual frozen World mode. The control supplies a real same-storage replacement writer beside an ordinary World, and capture refuses without issuing either root. The mutant omits only mode agreement. These grouped captures remain non-authorizing prerequisites, not complete-State roots or finality. |
| HC159 | Discard a completed original portable AMX proof after its final archive namespace guard refuses | `persisted_amx_completed_proof_retains_exact_graph_through_final_namespace_refusal` | The retained native reader distinguishes not-built, authenticated absence, completed graph and delivered states. A final namespace refusal preserves the exact original-pool proof backing and its successful decode work. Restoring the original directory inode permits allocation-free, zero-new-quota retry and one-shot delivery; failed guards never become absence or success. Last-owner destruction refunds the actual graph layouts. Durable validator relay and target-payload integration remain separate open boundaries. |
| HC160 | Erase the exact physical compact-key allocator refusal while constructing pending consensus penalties | `pending_penalty_peer_key_allocator_refusal_preserves_original_source_and_retries` | The pending plan copies each original accepted BLS peer key through its exact prepaid original-pool allocation. Physical refusal returns the actual layout and preserves the accepted row/source; no infallible Clone or fabricated pool wake substitutes for that local cause. Retry retains the real key and charge in the existing value-before-charge tuple, and last-owner destruction refunds the actual pending backing. The test-only mutant maps the physical refusal to a bookkeeping invariant. This local control does not establish real-peer slashing or fund the remaining evidence/action graph. |
| HC161 | Erase the original typed AMX deadline record resource refusal | `amx_deadline_record_refusal_keeps_original_pending_state_and_typed_retry` | A failed second record write retains the whole pending state and its original allocation; retry publishes the same keyed Abort records before pruning. Resource refusal remains the exact typed local cause through the deadline driver. This callback-injection control does not simulate a physical allocator or prove complete State/witness funding. |
| HC162 | Turn an AMX deadline resource refusal into a rejected block | `amx_deadline_finalizer_preserves_exact_local_refusal_without_rejection` | The actual finalizer adapter retains physical and cumulative resource causes in State storage admission, and the real block-error classifier emits no protocol rejection. Genuine malformed records and encodings preserve their execution-context rejection and diagnostic. |
| HC167 | Bind completed byte-only AMX decode custody to the first State visibility publication | `original_paid_amx_post_decode_refusal_retains_worker_leg_and_exact_retry` | A real State writer visibility interval between an original Candidate refusal and retry preserves the same signed source, physical completed leg and original pool. Fresh NativeHeaderSource and pristine StateBlock gates authenticate the current committed parent/result/epoch, and monetary checks rerun; no State verdict is cached. `original_paid_amx_worker_retry_reauthenticates_changed_native_parent` separately refuses a genuinely signed changed parent result before monetary execution. |
| HC168 | Reset cumulative original package traversal work on a deferred retry | `original_package_read_same_limit_retry_preserves_monotonic_work_and_exact_source` | The same finite work ceiling refuses after the completed prefix; retry cannot refund or restart admitted work, replace the source, or rebuild funded positions. |
| HC169 | Discard completed current positions when later undo backing refuses | `original_package_read_retains_completed_current_index_on_later_physical_refusal` | Actual original-pool refusal retains the exact completed current index, cursor, charge and work; the same-source retry neither copies nor rebuilds it. |
| HC170 | Acknowledge original reader retirement while physical readers remain | `retained_field_readers_and_positions_refuse_thaw_without_a_writer_wait` | An actual retained read or row position refuses return to the detached writer phase without inventing a lock release wait; all readers must retire before the same original pair can thaw. |
| HC171 | Return a retained group callback result after its original State source changes | `original_musubi_group_callback_state_publication_refuses_and_drops_exact_result` | A real independently staged State commit inside the callback changes the shared parent and generation. The post-callback source check drops that exact result and retains original readers, scope and cumulative work; a later stale retry admits no work or callback. This structural control does not establish complete-State authentication. |
| HC172 | Substitute equal staged revision allocations under the same target/predecessor | `original_musubi_group_equal_same_predecessor_revision_substitution_retains_original_pair` | The State group retains both actual original current/undo EBR allocations. Equality of values, target, predecessor, mode or visibility generation cannot replace those allocations; refusal retains the original scope, map indexes and work and admits no callback. This is structural custody, not complete-State authentication. |
| HC173 | Acknowledge Cell retirement while an actual original revision reader remains | `original_musubi_group_revision_reader_refusal_retains_completed_tables_and_exact_scope` | Both original Cell allocations must be unique before the revision returns to its detached writer phase. Holding either actual reader refuses without a mutex-release wait; all fourteen completed map thaws, original revision backing, scope and cumulative work survive retry until that reader retires. |
| HC174 | Select the staged current row instead of its original undo at an equal key | `retained_predecessor_ordered_merge_matches_exact_original_before_rows_in_both_modes` | Ordered original current/undo descriptors include untouched and removed predecessor rows, select the actual original before-value allocation, and omit inserted-only/absent rows in Ordinary and Replace modes. Descriptor allocation and every actual structural resolve/comparison use the original pool/work owner; this finite structural stage is not semantic Musubi or complete-State authentication. |
| HC175 | Discard completed predecessor descriptors/frontiers on a later comparison-work refusal | `retained_predecessor_later_work_refusal_preserves_descriptor_heads_frontiers_and_pool` | The actual tree bounds define a ceiling after one completed descriptor and both next comparison heads. Same-source retry retains their exact charged backing/frontiers and cumulative successful work, performs no new allocation, and consumes no fresh quota interval. Semantic query admission/materialization remains separate. |
| HC176 | Discard completed original semantic rows on a later local refusal | `retained_semantic_original_rows_and_cursor_survive_later_refusal` | The original iterator, pending row, exact canonical key backing, completed digests, ordered tree and lookup frontier survive local refusal in the caller's original pool. Retry consumes monotonic admitted work without restarting successful source or encoder stages; actual children retire before the last clone of the already admitted refund scope. These scoped pairs do not authenticate complete State. |
| HC177 | Discard a completed Musubi validation stage after a later original publication writer refuses | `retained_state_successful_musubi_validation_survives_late_writer_refusal` | Both live and universal validators succeed on the same frozen journals before a genuine late World writer refusal. The original publisher retains that success through repeated refusals and one-shot publication; retail policy checks retain their original prefix priority. A changed State visibility or equal-value lower Musubi predecessor still requires recovery, with no rebase or new pool. This rule does not provide complete-State or incremental semantic authority. |
| HC178 | Discard complete live-projection success after the same original universal scratch refuses | `retained_state_live_musubi_success_survives_universal_capacity_refusal` | The actual State pool has capacity for its original live directory-reference array but not the later per-package universal accumulator. That typed capacity refusal retains the completed live phase and original rows, pool and publisher; repeat retry advances no earlier successful pass. Release permits universal completion and one-shot publication. Retail priority and fresh visibility/exact predecessor gates remain unchanged. Unfinished work inside either validator, incremental semantics and complete-State authority remain separate open boundaries. |
| HC179 | Discard the completed native World-cut capsule after its final original shared control refuses | `original_worker_world_cut_retains_completed_tail_after_final_control_refusal` | A genuine executed, certified and durably appended Worker block completes its native frozen-tail reconstruction before an actual same-pool final shell refusal. The same immutable publisher retains those original rows, exact tip/root and original budget through the returned local deferral. Release permits final-shell delivery without hashing the completed tail again, even when retired reconstruction scratch already makes room at the unchanged limit. Fresh State visibility and exact predecessor gates still run; changed visibility requires recovery. This rule closes only final-shell retry custody, not unfinished journal work, complete-State restoration or a new source authority. |
| HC180 | Substitute a fresh finite pool while constructing the verified native offender graph | `lane_verified_offender_graph_refuses_occupied_original_pool_and_retries` | Complete original lane ancestry and proof verification do not grant an independent allocation pool. Each compact key, the exact canonical offender vector and its physical charge ledger are admitted before allocation and retained through immutable native verification and AdmittedEvidence. Occupying the actual original execution pool refuses with its exact local Capacity and preserves the original source; release permits the same proof and source to retry. Physical allocation refusal retires partial values before their charges. The immutable World record body and explicit original-pool snapshot restoration retain the proof/offender backing; enclosing maps, earlier decoded proof/crypto storage and partial graph progress retention remain explicit open boundaries. This rule does not qualify real-peer slashing. |
| HC181 | World evidence COW recopies immutable proof/offender allocations instead of sharing the original charged body | `sumeragi::evidence::lifecycle_tests::world_evidence_current_undo_and_cow_retain_original_proof_and_offender_allocations` | First direct COW clone must preserve the actual original proof, offender-vector and compact-key pointers; actual certified penalty application preserves Pending undo and Applied current over that same body. Restore is an explicitly funded claim and still requires original native-history authentication. |
| HC182 | Discard the original acquired archive frame when detaching its certified AMX source | `sumeragi::amx::proof_tests::persisted_amx_detached_source_keeps_original_frame_pool_and_retry_after_view_drop` | A move-only source issued by the existing certified reader retains its exact charged frame, archive descriptor and pool after the StateView retires. Local decode refusal retries that original acquisition; namespace/source guards and one-shot proof delivery remain mandatory. Native-prefix graph funding and durable relay submission remain separate boundaries. |
| HC183 | Native Prepared commit acknowledgement omits the original durable outbound intent | `original_paid_prepared_commit_captures_durable_intent_before_acknowledgement` | Genuine paid independent signed roots execute a Prepared write and publish through actual Worker/Kura; the exact original `.ami` must exist before the commit is acknowledged. The separate same-block pruning, real-pool refusal, namespace retry, substitution and historical replay controls retain original source/buffer identity. Signing/fees/target authority and actual validator submission remain unresolved. |
| HC184 | Off-chain G1 status substitutes the State execution pool for its original admitted query frame pool | `genesis_status_prefix_retains_original_admitted_pool_and_cumulative_refusal_work` | The genuine signed G1/H2 prefix must preserve exact original physical refusal and cumulative decoder work in the admitted query pool, then retry with the same pool and retain its exact authenticated graph until the last carrier owner retires. G1 still requires actual H2; missing/substituted successor controls refuse despite cached status. Successor HTTP status uses the existing opaque native State tip/checkpoint verifier; deterministic execution and internal reconciliation retain full-prefix metering. |
| HC185 | Reopen the selected AMX archive descriptor when issuing its first refused job | `query::native_receipts::amx_read::issuer_tests::owned_issuer_retains_first_refused_archive_descriptor_after_original_view_drop` | Issuance may move the exact native-certified pending job together with its unchanged typed refusal only after a genuine archive poll has selected its descriptor and length. A real occupied original pool, rename/substitution and StateView retirement must not rebind that descriptor, repeat prefix certification, refund acquired backing or establish proof success. Subsequent namespace and complete original-proof authentication remain mandatory; prefix-owner accounting and durable recovery/relay authority remain separate open boundaries. |
| HC186 | Discard the acquired original native frame after terminal AMX shared-body control refusal | `query::native_receipts::amx_read::certification_tests::terminal_amx_raw_frame_survives_original_shared_shell_refusal` | The actual public AMX reader fills its exact occupied raw extent, then an original-pool shared-control Capacity refusal must retain that same charged frame. Repeated refusal retains its pointer and cumulative metadata work; retry uses the same body decoder, source and pool before full certification and one-shot original proof delivery. Raw bytes are an acquired snapshot, never continuing disk-byte or finality authority. |
| HC187 | Ignore the originally captured native index start before raw body admission | `kura::native_execution_read_tests::native_frame_original_start_refuses_same_inode_relocation_before_body_admission` | Same journal inode, height, hash and length cannot replace the captured BlockIndex start. Relocation must refuse before raw backing admission or body I/O, preserving the occupied original pool and actual source without repair. This direct old-API control is independently applicable before the repair. |
| HC188 | Forget the completed original terminal AMX target after a later missing-predecessor refusal | `query::native_receipts::amx_read::certification_tests::terminal_amx_target_survives_original_later_gap_capacity_and_proof_retry` | A real original-pool gap Capacity after target decoding must retain its exact committed slot/body/result backing and the cumulative caller decoder. Successful gaps move once into the same certified predecessor cursor; the terminal target moves once into the archive/proof owner only after the unchanged certificate, availability, boundary and fallible schedule checks. Foreign height/pool or source substitution cannot clobber the pending original. Public ordinary/reset semantics remain independently covered. Partial genesis-result/authority work, partial certificate/schedule work and nested graph funding remain open; no durable Worker relay or signing authority is established. |
| HC189 | native queue admission: omit original global driver wake | `sumeragi::node::tests::queue_wake_tests::native_queue_admission_wakes_original_global_driver_after_empty` | After a real EMPTY response reaches Core and the startup Transactions edge is consumed, actual Queue admission alone must wake the original global driver before the unchanged signed retry interval. No idle blocks or timer workaround; weak original wake/inputs and normal dispatch remain coalesced. |
| HC190 | native queue admission: omit original live lane runner wake | `sumeragi::node::tests::queue_wake_tests::native_queue_admission_wakes_original_live_lane_after_empty` | A healthy global notification cannot hide missing live-lane delivery. Actual enqueue after the signed lane is active and its EMPTY response reaches Core must wake the owned runner and merge the original input. Admission never walks or waits on the live lane map. |
| HC191 | native queue startup: omit early exclusive original-owner refusal | `sumeragi::node::tests::queue_wake_tests::native_queue_owner_refuses_duplicate_prepared_start_and_requires_fresh_queue_restart` | Prepared::start reserves the original Queue before executor attachment, safety-record/body writes or driver launch. Reserved, successful and permanently retired owners exclude another startup. Failed reservation releases only its exact ticket; ordinary certified restart uses a fresh Queue. |
| HC192 | native queue startup: omit cold reserved original-pool admission binding | `queue::sumeragi_wake::tests::reserved_original_pool_refuses_foreign_resident_admission_before_allocation` | A cold Queue reserved for native startup rejects foreign-pool first admission before resident control allocation. The same original mutation fence and pool remain authoritative; no substitute pool or refund-before-retirement. |
| HC193 | native queue startup: omit existing resident original-pool binding | `sumeragi::node::tests::queue_wake_tests::native_queue_reservation_refuses_foreign_funded_pool_without_changing_original_pending` | Previously funded Queue residents cannot be reassigned to a foreign execution pool at startup. Actual pending input, canonical signed source, original resident charge and refusal cause remain unchanged; no silent graph migration. |
| HC194 | native queue retirement: omit terminal admission refusal | `sumeragi::node::tests::queue_wake_tests::native_queue_owner_refuses_duplicate_prepared_start_and_requires_fresh_queue_restart` | Successful native retirement rejects actual new Queue admission before original resident allocation/publication. The same mutation fence serializes retirement with final admission; existing original residents and refunds remain intact and ordinary restart uses a fresh Queue. |
| HC195 | durable lane publication: omit original global merge wake | `sumeragi::node::tests::queue_wake_tests::native_queue_admission_wakes_original_live_lane_after_empty` | After the original signed lane body and CommitQC become durably available, both member and observer stores wake only the global driver to select that merge. Publication refusal never announces readiness; idempotent durable retry may repeat the hint. The original store/Queue pool and identity remain bound, retirement suppresses delivery, and no lane-build feedback or protocol retry interval change is introduced. |
| HC196 | durable lane merge source: omit original cold State pool binding | `sumeragi::lanes::store::publication_tests::lane_merge_wake_binding_preserves_original_queue_and_pool_across_retry` | A foreign Queue's first attempt refuses before the original store's weak binding slot is set. The actual original store pool and empty slot remain unchanged; recovery binds only the node's original reserved/active Queue pool. |
| HC197 | durable lane merge source: accept a foreign original Queue identity | `sumeragi::lanes::store::publication_tests::lane_merge_wake_binding_preserves_original_queue_and_pool_across_retry` | A second Queue cannot be acknowledged as bound even under an equivalent same State pool. Only exact original Queue retry is idempotent; the original weak slot, charges and source identity remain intact. |
| HC198 | DKG publication omits exact mode initialization of its newly exclusively created original public descriptor | `beacon_bootstrap::seat_export::tests::public_output_initializes_exact_original_creation_mode_before_publication_and_restore` | The producer initializes its exact public `0644` or private `0600` mode before any byte, independently of the caller umask. A mode-operation refusal retains the original descriptor and unfinished stage. Published or recovered descriptors retain exact mode custody and are never repaired by retries; complete original file/directory durability and authentication remain mandatory. |
| HC199 | completed certified lane payload discards original source and output on same-scope build retry | `sumeragi::executor::payload_owner::tests::completed_certified_lane_payload_keeps_original_output_across_same_scope_build_retry` | A later build request under the exact original height, view, policy, parent, generation, certified lane plan and mixed Queue lease borrows the same admitted output. The original job and source survive a Core deadline without repeated canonical encoding. Actual source withdrawal, expiry, execution, rejection and discard retire that custody; no cached output replaces current authentication. |
| HC200 | DKG aggregate restoration applies the live adjacent-height rule to complete durable certified history | `beacon_bootstrap::seat_attempt::finality::tests::aggregate_restart_replays_complete_original_history_before_next_phase_and_keeps_cutoff` | Restore authenticates the complete original journal from genesis through H3 and then H4, including every intermediate certificate and execution receipt; target heights must increase and precede the original cutoff. The live FIFO still requires adjacent heights. Exact source custody, refusal retry and ancestry verification remain mandatory. |
| HC201 | Block-event execution repeats the completed genesis prefix instead of authenticating its original recent source | `smartcontracts::isi::tx::native_carrier_reader_tests::event_carrier_reads_recent_certified_source_under_original_finite_work` | The event projection captures the original immutable State hash generation and opaque executed tip without a World view. Signed genesis, every reverse core/result/Iroha parent, the target's actual original native descriptor and exact QC/availability/schedule/boundary checks remain mandatory under the same finite source allowance and execution pool. Historical reads include each intervening original frame; output identity and fresh canonical target membership remain checked. This is an off-chain projection, not State authority, complete nested-graph funding or measured proof of the earlier H3 delay. |
| HC202 | Block-event State capture spins across an odd or changed publication rather than returning the original physical release | `state::event_carrier_tests::event_carrier_returns_from_original_writer_refusal_without_waiting` | Before and after source I/O, the event reader captures the original hash generation and opaque execution tip once. An active or changed State writer returns the exact original `StateViewBusy` release observation; visibility completion alone is not physical writer retirement. Execution allocation/decoder causes and canonical rejection stay distinct, including G1/H2. Torii retains the event and cause, but this does not add autonomous event retry, across-call source retention or new execution authority. |
| HC203 | Status actor World sampling waits through an original State publication instead of returning its local refusal | `telemetry::tests::classified_status_tests::status_prelude_refuses_original_publication_before_service_deadline`, `telemetry::tests::classified_status_tests::status_final_world_sample_refuses_publication_after_verified_chunk` | Mode/local membership and final World gauges each use one original nonblocking State acquisition. Busy publication returns the existing typed status refusal under the unchanged 500 ms service deadline; already verified classification chunks remain actor-owned. Release/join permits a fresh current classified snapshot. This does not cache authority, extend deadlines, add autonomous release retry, qualify complete status graph funding or prove that observed H3 503 warnings came from this path. |

| HC204 | Discard the initial native AMX genesis acquisition after original shared-body control refusal | `query::native_receipts::amx_read::issuer_tests::public_amx_initial_shell_refusal_retains_original_genesis_frame_without_reread` | The actual public borrower retains its original genesis descriptor and charged raw frame through typed Capacity, then moves the same prepaid body/source into its certified chain. Prefix retries lend that body after fresh original slot/object checks; relocation remains refused before another body read. The caller decoder and original pool stay cumulative. Partial genesis-result/authority graphs, complete nested funding, StateView-free initial recovery and the durable `.ami` validator consumer remain open. |
| HC205 | Repeat the original completed signed metadata decode after complete canonical genesis epoch validation | `sumeragi::certified_chain::tests::signed_genesis_initialization_does_not_repeat_completed_scope_decode` | The actual same Kura body and original cumulative decoder complete exactly one canonical authenticated-genesis pass. Its epoch and Copy root scope move from that sole validator without a second JSON reconstruction; the original finite allowance, source pointer and pool remain unchanged. Portable finality initialization retains the same scope, and later scope reads consume no decoder credit. Original signature, commitment, roster, policy and epoch validation order remains mandatory; partial result/authority graph custody and nested physical funding remain separate boundaries. |
| HC206 | Erase the original cumulative durable metadata refusal during native carrier preflight | `smartcontracts::isi::tx::native_carrier_reader_tests::full_prefix_carrier_preserves_original_cumulative_metadata_refusal`, `smartcontracts::isi::tx::native_carrier_reader_tests::event_carrier_preserves_original_cumulative_metadata_refusal`, `smartcontracts::isi::tx::native_carrier_reader_tests::bounded_native_extent_preserves_original_cumulative_metadata_refusal`, `state::block_proofs::native_proof_reader_tests::native_block_proof_preserves_original_cumulative_metadata_refusal`, `sumeragi::finality::compact_source::tests::compact_source_preserves_original_cumulative_metadata_refusal_before_body_io` | Both actual State readers and original bounded extent, block-proof and compact certificate readers preserve the original active Norito marker refusal as local ActiveMemoryCapacity before any body acquisition. Repeated attempts retain the same cumulative context and pool; malformed storage and substituted slots remain deterministic rejection. No pool release is invented for a codec ceiling. |
| HC207 | Admit a restricted home without its original authenticated private-root binding | `smartcontracts::isi::domain::isi::private_root_home_tests::restricted_home_requires_original_private_root_not_global_missing_or_foreign_scope` | Valid physical geometry and routes cannot replace the original execution root. Global, absent, foreign or genesis-shaped source scope refuses before registration; original local metadata refusal remains sticky on the State attempt. |
| HC208 | Admit a private restricted home without both original captured route coordinates | `smartcontracts::isi::domain::isi::private_root_home_tests::original_private_home_requires_both_exact_captured_routes` | The actual private-root source and canonical geometry do not authorize missing, foreign or inconsistent State/World routes. Internal read contexts allowing no route do not grant registration authority. |
| HC209 | Admit a private restricted home without canonical original physical geometry | `smartcontracts::isi::domain::isi::private_root_home_tests::original_private_home_requires_canonical_single_root_geometry` | Authenticated source and routes cannot replace the exact actual/configured single-root catalog, derived storage, lane-zero routing, World catalog identity or absence of autoscale state. The shared geometry-only kernel is also used by daemon startup after its unchanged signed scope/mode checks. |
| HC210 | finite finality interval: discard completed original prefix between consecutive outputs | `sumeragi::finality::proof_reader_tests::finite_finality_interval_under_original_codec_checks_each_real_quorum_once` | One original finite request keeps the genuine signed genesis, epoch schedule and exact QC/availability prefix through at most 64 outputs. Actual QC and body-read counters and independent portable proof equality prove linear native work. The original request prepays a finite eight-group live-graph workspace and bounded diagnostic scratch; native refusal text retires before the workspace and only heapless rejection facts escape. Stage counters may reset only inside that retained workspace, while a held target and independently inherited counters remain cumulative. Cold frames and exact proof destinations retain their separate original pool; no authority cache or wider deadline is used. |
| HC211 | finite finality interval: omit final original raw source join | `sumeragi::finality::interval::tests::finite_interval_rejects_earlier_real_qc_changed_after_verification_before_publication` | Completed native checks cannot authorize output after earlier original durable bytes or journal objects change. One final complete original-pool raw scan joins the entire authenticated prefix; corrupted earlier QC and same-byte object replacement both refuse without a response. |
| HC212 | finite finality interval: omit original deadline and cancellation stop | `sumeragi::finality::interval::tests::finite_interval_stop_retires_real_original_cursor_without_next_native_read` | The original absolute deadline and cancellation are checked before and between physical stages. Refusal retires the original cursor/response before refund; a single in-progress storage, allocator or crypto operation is not forcibly preempted and its physical worker admission must remain retained. |
| HC213 | portable proof destination: omit actual original compact public-key backing charge | `sumeragi::finality::proof_destination::tests::original_proof_destination_charges_each_actual_compact_key_before_clone_and_refunds` | Both interval and existing checkpoint cursor share one portable destination. Actual wire, committee, PoP and compact-key layouts plus the exact 2+2n charge ledger are admitted from the original pool before copy. All values retire before their charges on success/refusal; nested verifier graphs remain a separate funding obligation. |
| HC214 | finite finality State source: omit final one-shot captured-generation membership join | `state::finality_proof_interval::tests::interval_post_read_writer_refusal_retires_response_and_preserves_original_release` | The exact configured State captures its versioned hash owner twice without World or a writer guard. Busy preserves the original physical ReleaseWait, stable tip append preserves historical membership, and changed final membership refuses. Signed genesis/full prefix and the raw source join remain independent mandatory checks. |
| HC215 | native AMX original policy: discard completed signed policy on metadata refusal retry | `query::native_receipts::amx_read::issuer_tests::public_amx_signed_policy_retains_completed_npos_stage_on_metadata_refusal` | The same original native slot, raw bytes, body, pool and cumulative decoder retain the completed admitted policy through metadata refusal. A retry rechecks the original source before reusing the exact signed instruction; physical policy backing and original refusal remain retained. No reset, replacement policy or authority cache is accepted. |
| HC216 | Native execution tip restoration erases the original local history refusal into an invalid snapshot field | `state::native_execution_tip::tests::restore_preserves_original_pool_refusal_release_and_same_source_retry`, `state::native_execution_tip::tests::restore_preserves_cumulative_prefix_decode_refusal_and_same_source_retry` | The same pinned native constructor, execution anchor and certified prefix retain original pool Capacity fields/release and cumulative decoder ActiveMemoryCapacity through tip restoration, StateRestoreError and snapshot error projection. A same-source retry authenticates current/undo and refunds its original Cell; actual corrupt history remains a completed schema rejection. Nonempty snapshot startup stays blocked pending complete-State authentication; this does not grant World snapshots restore authority. |
| HC217 | Restarted Prepared intent omits final original namespace join after actual instruction admission | `sumeragi::amx::native::tests::paid_borrowed_custody::restarted_paid_intent_delivers_exact_native_prepared_relay_and_refunds_original_pool`, `sumeragi::amx::native::tests::paid_borrowed_custody::restarted_paid_intent_final_namespace_refusal_retains_exact_funded_instruction_until_original_retry` | Genuine paid commit and native replay produce the original canonical `.ami`. The reader pins its descriptor and charged bytes, authenticates the actual history/parent and complete Prepared write through the existing proof owner, and retains the exact funded instruction through final namespace refusal and same-source retry. Delivery is move-only; zero authority does not grant signing, fee or submission permission. Durable transaction journaling/autonomous validator relaying and remaining native-prefix graph funding stay open. |
| HC218 | Restarted Prepared intent trusts an untrusted row subset instead of its authenticated complete witness | `sumeragi::amx::native::tests::paid_borrowed_custody::restarted_paid_intent_refuses_authenticated_row_subset_before_any_delivery` | A genuine same-carrier two-Prepared-row commit and native replay refuse a validly re-encoded one-row `.ami` subset before first delivery by comparing against the existing native verifier's retained authenticated full writes. Sorted distinct keys and exact per-row proofs remain mandatory. Restoring the original frame delivers both exact funded rows without signer or submission authority. |
| HC219 | Returned native AMX global context deep-copies the epoch without original-pool custody | `sumeragi::amx::native::tests::returned_context::native_amx_returned_global_context_keeps_every_original_graph_charge_until_retirement` | Genuine signed genesis and real H2 authenticate the parent through the sole verifier. The returned committee Vec, compact key boxes, PoP Vecs and exact ledger remain funded by the original pool through refusal and final registration admission. Pointer identity, original release/retry and last-owner refund are mandatory; this does not close the shared verifier’s separate nested decode/crypto graph funding. |
| HC220 | Core upload account-key reader erases its original decoder refusal into a terminal diagnostic | `state::account_key_refusal_tests::upload_account_key_preserves_original_refusal_fields_scope_and_same_source_retry` | The real upload-key reader uses the canonical Model AccountId key owner. Original scoped observer and unscoped resource fields survive unchanged, while malformed keys retain terminal context. Same source/context retry and exact original counter-owner refund are mandatory. Governance JSON fields use the canonical BTreeMap admission owner. |
| HC221 | Public fallible World construction restores an infallible expect around its sole shared initializer | `state::world_construction_tests::world_constructor_registration_refusal_is_fallible_and_retries_original_source`, `state::world_construction_tests::world_constructor_record_refusal_is_fallible_and_retries_original_source`, `state::world_construction_tests::world_constructor_rejects_malformed_kaigi_without_panicking` | Initial storage refusal retains the original release owner before consuming entity iterators. Kaigi rebuild quotas return typed incomplete attempts, malformed sources return completed errors, and no partial World escapes. The same finite original pool/context and shared Json backing retry unchanged; physical nested graph admission remains separate. |
| HC222 | Discard original partial AMX Worker decoder controls, completed fields and multisig member prefix after a genuine refusal | `sumeragi::executor::amx_retry_tests::partial_amx_worker_leg_refusal_retains_original_controls_and_release_wait`, `sumeragi::executor::amx_retry_tests::partial_amx_worker_leg_refusal_retains_completed_source_prefix_without_reallocation`, `sumeragi::executor::amx_retry_tests::partial_amx_worker_leg_refusal_retains_original_multisig_member_prefix_without_reallocation` | The actual original paid signed-source Worker bank retains the same finite pool, canonical controls, completed fields, member/spans/key ledgers and native digits across refusal. Its original Capacity ReleaseWait stays Pending while the external blocker lives; an unchanged retry allocates no replacement prefix. Real blocker retirement permits the same source to finish and exact last-owner refund. Every cached canonical field/element boundary still checks enclosing limits. Only the test-only omission drops that partial owner after the unchanged error. Diagnostic Strings, indirect invocation and full proof/crypto graph funding remain open. |
| HC223 | Omit resumption of a preceding parked original AMX Worker occurrence | `sumeragi::executor::amx_retry_tests::rejected_amx_worker_occurrence_retains_source_prefix_and_replays_before_later_partial_occurrence` | A late malformed Quantity rejects signed input A after both original keys and digits were admitted; a separately signed valid B still executes through actual Worker validation. The same original bank then replays A while B holds a genuine partial Capacity refusal. Each original occurrence keeps its admitted prefix and re-enters the canonical parser, without a cached verdict or replacement backing; A returns its exact canonical cause, B retains its exact ReleaseWait until real external release, and all occurrence metadata/graphs retire with the bank. The test-only omission refuses retrieval of only the preceding parked occurrence. Exact wait/generation evidence is scoped to the bank; complete State/World execution custody remains open. |
| HC224 | Core native pulse demand also treats a committed Parliament slot row as mandatory control (`epoch_beacon::required`) | `pending_parliament_slots_create_no_native_control_demand_and_never_block_unrelated_work` | Consensus demand is the NPoS pre-boundary height only. On a Permissioned Global chain holding a sortition generation awaiting slot 9, `required` is false, no producer opens a round, signs or reports a source failure even without a beacon session, and every block of unrelated signed work with the empty control witness executes `Valid` and commits from the slot far past it. A genuine pulse carried at the slot is refused as not requested. No pulse row appears, the request stays pending on its original slot with an unchanged index, and cold replay reproduces the certified results. A timed-OVN release slot at the next height is likewise no demand. |
| HC225 | SCCP outbound: ignore the committed parent degradation run | `smartcontracts::isi::sccp::outbound::tests::degraded_parent_refuses_before_money_nonce_or_leaf_and_recovers` | A nonzero parent degraded run refuses before money, nonce, liability or leaf effects; clearing the run restores the actual paid path. |
| HC226 | SCCP rotation X: certify the successor generation at the outgoing height | `smartcontracts::isi::sccp::hook::tests::native_heartbeat_certificate_keeps_outgoing_generation_then_uses_successor` | A genuine signed nonempty native heartbeat block seals and persists X with the outgoing generation while World installs its successor. The next native height uses the successor. This is not a 4-to-7 election qualification. |
| HC227 | SCCP G7: end the old generation at recovery time instead of the authenticated parent time | `smartcontracts::isi::sccp::generations::tests::resync_uses_real_native_parent_time_then_boundary_rotates_again` | Recovery ends the retained predecessor at the opaque native parent height/time, then an explicit boundary may independently rotate again. The structural plan test does not certify a fabricated election. |
| HC228 | SCCP A1: omit the original parent anchor append including degraded heights | `smartcontracts::isi::sccp::hook::tests::degraded_hook_still_appends_original_parent_anchor_and_recovers_without_rotation` | The actual native parent core hash and R are appended even when G4 inputs are unavailable; a fresh original retry emits an active header without a spurious rotation. |
| HC229 | SCCP S0: advance liability by the full halt duration instead of the bounded increment | `smartcontracts::isi::sccp::hook::tests::begin_block_clamps_halt_time_using_original_native_parent` | Before instructions run, liability advances by at most heartbeat plus slack using the original parent time; a long halt cannot consume the full window. |
| HC230 | SCCP G6: resolve frozen registration tenure at execution height instead of generation start | `smartcontracts::isi::sccp::generations::tests::handoff_resolves_original_registration_for_successor_tenure_and_freezes_it` | Original-at-execution registrations are resolved for the created generation start. Activation at h+1 is included in G2; deactivation at h+1 is excluded. G1/G7 use their unchanged start heights and the frozen binding survives later registry replacement. |
| HC231 | SCCP height custody: substitute an unfunded canonical graph for the original retained schedule | `smartcontracts::isi::sccp::height::tests::height_capture_preserves_original_graph_without_admission_at_full_pool` | At genuine original-pool exhaustion, height capture and projection keep the exact original peer, key, proof and schedule backing with zero new allocation. Original charges survive World overlay retirement and refund only after the final captured reader. |
| HC232 | Terminal native verification custody: discard pending receipt/result slots after late refusal | `sumeragi::certified_chain::terminal_selection::tests::terminal_target_result_slot_refusal_keeps_original_wait_and_refunds_on_cancel`, `sumeragi::certified_chain::terminal_selection::tests::terminal_gap_result_slot_refusal_keeps_original_wait_and_refunds_on_cancel` | Target and gap selection retain the original charged receipt slot when the result slot refuses. The exact returned release stays pending until external release; retry uses the same native body and source, and cancellation refunds all original owners. |
| HC233 | Native cursor initialization: discard its original acquisition and verification slots after a later refusal | `sumeragi::finality::cursor::tests::native_cursor_genesis_result_slot_refusal_retains_original_source_until_release` | The actual later result-slot refusal retains the original raw/body/prefix/receipt backing. The exact release stays pending; retry lends the same body and pool. A different Kura with the same signed genesis is refused, and cancellation refunds the complete retained attempt. |
| HC234 | Native cursor successor: discard its original output, acquisition and verification slots after a later refusal | `sumeragi::finality::cursor::tests::native_cursor_successor_result_slot_refusal_retains_original_source_until_release` | A successor's actual result-slot refusal cannot refund its earlier output/source/receipt owners or advance the native prefix. Original release resumes the same source into genuine native QC and portable finality; cancellation refunds its original backing. |
| HC235 | Native cursor final projection: discard original output, raw carrier and decoder custody after late refusal | `sumeragi::finality::cursor::tests::native_cursor_output_shell_refusal_retains_projection_and_observes_new_tip` | The genuine final carrier shell refusal parks on the original pool without refunding earlier slots or rereading raw bytes. A later committed tip resumes the old projection before authenticating the new current result; cancellation and the last output reader refund exact custody. |
| HC236 | Native cursor checkpoint preparation: discard its partial proof, original decoder envelope and exported checkpoint after refusal | `sumeragi::finality::cursor::tests::native_cursor_pending_last_key_refusal_retains_original_graph_and_release`, `sumeragi::finality::cursor::tests::native_cursor_pending_envelope_refusal_retains_original_graph_and_release`, `sumeragi::finality::cursor::tests::native_cursor_pending_checkpoint_refusal_retains_original_graph_and_release` | Each real late admission retains preceding wire/key/PoP/checkpoint allocations and the original release generation. Retry borrows the same graph and independently verifies genuine native progress before publishing the canonical checkpoint; cancellation refunds all original charges. |
| HC237 | SCCP control cause: replace the exact World-authenticated certificate ID with its proposal ID | `smartcontracts::isi::world::isi::tests::parliament_due_sccp_control_binds_exact_certificate_and_complete_pause_state` | The stored valid due certificate executes through the unchanged exact-context owner; the recorded leaf/event must retain GovernanceCertificateId::derive_v1(certificate) and the original effect hash, distinct from the proposal ID. |
| HC238 | SCCP control recorder: omit the actual active destination fast-pause expiry | `smartcontracts::isi::world::isi::tests::parliament_due_sccp_control_binds_exact_certificate_and_complete_pause_state` | A Parliament effect changes only its own flag; the current 199-byte control records the actual active independent expiry, exact cause, hash and event, preserving the original pause record. |
| HC239 | Native epoch construction: forget the original charge ledger after partial payload unwind | `sumeragi::epoch_election::owned::tests::partial_epoch_committee_unwind_refunds_retired_nested_backing` | A real nested committee construction unwinds after admitted backing exists. Destroyed payloads must refund their exact original pool; an existing retained schedule keeps its bytes and key identity, retry succeeds, and its final reader releases the remaining credit. |
| HC250 | SCCP G6 resolves a global signer's liability across participant staking lanes | `smartcontracts::isi::sccp::generations::tests::global_member_binding_ignores_participant_staking_registration`: simultaneous global and participant registration retains the global binding at generation start | — | O-VAL |
| HC251 | SCCP destination clearance scans cleared generation history before limiting work | `smartcontracts::isi::sccp::generations::tests::destination_clearance_visits_only_bounded_pending_index_after_cleared_history`: historical cleared records do not increase the at-most-64 visited pending records | — | O-LIVE |

| HC240 | SCCP retained fast Taira pause: omit the active network hold from original consumers | `smartcontracts::isi::sccp::outbound::tests::record_obeys_fast_pause_network_revision_and_exact_expiry_without_effects`, `smartcontracts::isi::sccp::settle::tests::taira_fast_pause_holds_inbound_only_without_losing_proof_money_or_retry`, `smartcontracts::isi::sccp::settle::tests::taira_fast_pause_keeps_void_refund_pending_without_stranding_or_moving_money` | The original native consumer must retain its exact hold, time and pre-block facts. Every declared control must fail at its own causal assertion under this test-only mutation. |
| HC241 | SCCP retained destination pause: omit the active exact-revision outbound hold | `smartcontracts::isi::sccp::outbound::tests::record_obeys_fast_pause_network_revision_and_exact_expiry_without_effects` | The original native consumer must retain its exact hold, time and pre-block facts. Every declared control must fail at its own causal assertion under this test-only mutation. |
| HC242 | SCCP committed pause time: substitute the executing timestamp for the original native prefix | `smartcontracts::isi::sccp::hold::tests::committed_pause_time_binds_original_native_prefix_and_ignores_executing_header` | The original native consumer must retain its exact hold, time and pre-block facts. Every declared control must fail at its own causal assertion under this test-only mutation. |
| HC243 | SCCP eligibility: replace original pre-block facts with the executing writes | `smartcontracts::isi::sccp::eligibility_tests::original_eligibility_preimages_survive_siblings_rollback_and_replacement` | The original native consumer must retain its exact hold, time and pre-block facts. Every declared control must fail at its own causal assertion under this test-only mutation. |
| HC244 | Network failure-fee settlement: swallow the original local execution deferral as a completed rejection | `state::output_capacity::producer::tests::network::fees::sccp_failure_fee_decoder_refusal_keeps_original_deferral_and_retry`, `state::output_capacity::producer::tests::network::fees::ordinary_failure_fee_decoder_refusal_keeps_original_deferral_and_retry`, `state::output_capacity::producer::tests::network::penalties::refusal::fee_decoder_refusal_after_actual_ballot_penalty_rolls_back_and_retries_once` | Actual rejection settlement must preserve the original local deferral before terminal projection; abandon the poisoned block and qualify original-source retry with exactly-once fee/slash effects. Every declared control must fail at its own causal assertion under this test-only mutation. |
| HC245 | Network ballot-penalty settlement: swallow the original local execution deferral as a completed rejection | `state::output_capacity::producer::tests::network::penalties::refusal::actual_ballot_penalty_decoder_refusal_keeps_original_deferral_and_retry` | Actual rejection settlement must preserve the original local deferral before terminal projection; abandon the poisoned block and qualify original-source retry with exactly-once fee/slash effects. Every declared control must fail at its own causal assertion under this test-only mutation. |
| HC246 | SCCP fast-pause lifecycle: omit Global G4 expiry cleanup after enactments | `smartcontracts::isi::sccp::read::native::control_producer_tests::lapse_tests::native_fast_pause_lapse_uses_exact_time_and_preserves_parliament_confirmation`, `smartcontracts::isi::sccp::read::native::control_producer_tests::lapse_tests::native_fast_pause_lapse_cancellation_keeps_original_record_and_retries_once` | At the exact original block timestamp, remove only the expired original record; preserve Parliament state, subject heads and leaves, retain its original reader, and publish one event only after successful native certification. Cancellation discards the effect and fresh original-source retry publishes once. Every declared control must fail at its own causal assertion. Panel and casting-open producers remain separate open requirements. |
| HC247 | Payload producer retry: erase the original resource refusal at the driver boundary | `sumeragi::executor::publication_tests::original_lane_policy_proposal_refusal_retains_worker_owner_and_exact_queued_retry`, `sumeragi::executor::publication_tests::original_staking_payload_worker_retains_pool_refusal_and_exact_queued_retry` | Return the original typed refusal from the actual queued worker. Preserve the exact pool release and keep the waiter pending until an external release; retain the queued transaction and retry the same source. Policy-capacity refusals without a release owner remain typed without inventing one. Every declared control must fail at its own exact assertion; worker controls retain their original child and join panic ownership. |
| HC248 | Drop the retained original parent-service preparation on its actual refusal | `sumeragi::executor::parent_service_custody_tests::parent_service_validation_retains_original_receipts_without_waking_its_own_retry`; `sumeragi::executor::parent_service_custody_tests::parent_service_assembly_retains_original_parent_and_queue_before_capacity_retry` | The actual worker validation control must fail at its own Pending assertion. The assembly control must fail at its first-refusal full-pool assertion before inspecting retained pointers; it also preserves the subsequent original Pending, unchanged receipt pointers, queue and external-release retry checks. Original native receipts and physical carrier bodies remain with the same caller attempt until external release, cancellation or explicit candidate replacement; final source/proposal authentication is unchanged. The separate constructor baseline proves original-pool admission, and nested decoder/output custody remains open. Every declared control must fail at its own exact assertion; worker controls retain their original child and join panic ownership. |
| HC249 | An impossible native-authority prepaid custody plan is relabeled as capacity pressure | `native_authority_prepaid_custody_errors_require_recovery` | The already admitted original pool cannot repair foreign custody, a short reservation, or a compact-key layout mismatch. The mapper preserves LocalInvariantViolation before the parent-service driver requires recovery. Original actual capacity and physical allocator refusal keep their distinct causes. |
| HC252 | Native commit retry keeps callback-delayed polling while executed State writers remain retained | `sumeragi::executor::payload_owner::tests::retained_partial_payload_idle_expiry_wakes_original_commit_with_live_execution` | Actual Queue expiry retires the original partial payload and returns its pool credits while preserving the same Live overlay, commitment, source and result. Callback-free original-pool wakeup must make the scheduler retry the Arc-identical committed head before independent pressure is released. Generic callbacks and physical-lock release still wait for their original safe boundary. The mutation must fail at its exact scheduler-retry assertion under the original worker and join panic owners. |
| HC253 | Native parent reads classify unavailable original journal path bindings as corrupt history | `sumeragi::executor::payload_owner::tests::retained_partial_payload_refuses_missing_original_parent_and_resumes_same_paid_wire`; `sumeragi::executor::payload_owner::tests::retained_partial_payload_refuses_substituted_original_parent_and_resumes_same_paid_wire` | Missing or replaced paths must refuse before body I/O while retaining the exact paid payload, queue lease and pool charge. Restoring the original journal must resume that same payload. This availability classification applies only to the original pathname/descriptor binding; malformed bytes and contradictory durable slots remain errors. |
| HC265 | A direct payment retry consumes another execution fee after its payer-scoped business identity succeeded | `executor::settlement_replay::tests::direct_payment_replay_two_carriers_charge_once_and_recover_after_certified_restart` | Distinct signed carriers of the same owner-authorized singleton intent charge once, preserve the original receipt and recover its original successful block after certified replay. The mutant must fail at the exact fee-balance assertion. A typed retry outcome rejects the new carrier; verification of the original successful execution remains mandatory. |
| HC266 | AMX relay outcome omits its freshly authenticated source-instruction and explicit-authority binding | `amx_relay::ledger::proof_tests::relay_journal_identity_cannot_substitute_an_unrelated_successful_carrier` | A valid exact-quorum block and exact input/output proof for a different native instruction cannot complete the relay. The mutant removes only the fresh source instruction/authority comparison; genesis, finality, exact carrier identity and successful execution checks remain. The deterministic test uses real certificates over synthetic results and does not establish whole-network AMX qualification. |
| HC270 | AMX discovery requires a coordinates file for a certified height with no AMX writes | `native_amx_discovery_advances_ordinary_global_height_then_delivers_both_final_tip_decisions` | The reader authenticates the complete original execution witness and its zero record count before advancing an ordinary height with no `.ami` file. It then discovers genuine Begin and final-tip Decision deliveries from the same replayed Global root. |
| HC327 | Routing-lane builder lends a retained payload after its original Queue admission retires | `lane_original_queue_lease_retires_expiry_and_withdrawal_during_clock_wait`; `lane_original_queue_lease_rechecks_withdrawal_after_actual_encoding`; `lane_original_queue_lease_preserves_same_output_across_clock_rewind_and_retires_readmission` | Actual Queue selection retains its original admission lease through clock waits and encoding. Expiry, withdrawal and same-hash readmission retire that source; clock rewind alone preserves the same output. These named controls require current-source runtime and mutation qualification. |
| HC328 | Omit the captured proposer time for a fresh view | `fresh_view_refreshes_authenticated_block_time_without_replacing_signed_input` | Genuine Queue work retains byte-identical payloads within one view and the exact signed input across a fresh view. Advancing the clock must refresh only the new authenticated header time, without another payment or unrelated input. |
| HC329 | Reject an authenticated timestamp above the required parent/input floor | `authenticated_proposer_time_above_floor_executes_and_replays_without_restamping` | The real worker executes a signed RS16 proposal with a later timestamp and unchanged signed inputs. After a local clock rewind, uncertified execution waits; genuine quorum preparation and cold replay retain the original result and exact body time. |
| HC330 | Omit authenticated epoch-boundary handoff discovery when no AMX record exists | `native_amx_handoff_discovery_delivers_final_boundary_without_record_and_replays_both_roots` | Actual native execution at the final epoch boundary must produce its handoff without an AMX coordinates row or a successor block. Independently executed roots apply the original proof and replay it after restart. |
| HC333 | Accept a substituted execution source at routing-lane first Prepare signing | `native_lane_first_prepare_admission_binds_original_source_and_retains_its_charge` | The paid admission retains its original lane, epoch, height, block and execution result through the final signer check. Certification cannot exempt source substitution. |
| HC338 | Accept a Decision read from a child root as a Global expiry decision | `native_amx_expiry_recovery_authenticates_final_decision_after_restart_and_rechecks_cached_positive` | Recovery joins the original Global root, instance, Begin, intent and authenticated Decision. A child root at the same height cannot supply that authority. |
| HC339 | Promote a cached positive Decision height without rereading authenticated source | `native_amx_expiry_recovery_authenticates_final_decision_after_restart_and_rechecks_cached_positive` | Cached coordinates retain progress only. Capacity refusal on the original source read remains deferred, including after restart. |
| HC340 | Treat decoded terminal expiry journal state as fresh exact-carrier evidence | `independently_decided_expiry_recovers_only_the_existing_exact_carrier_without_dispatch` | An independent Decision suppresses new expiry dispatch but does not establish an unknown existing carrier outcome. Read-only recovery requires current authenticated evidence for that exact carrier. |
| HC341 | Omit the exact direct private-root AMX consent classifier | `native_amx_exact_owner_grant_revocation_and_separate_relay_preserve_settlement`, `native_amx_approval_proof_requires_owner_grant_and_rechecks_exact_private_cut` | A bank must route direct account Grant/Revoke of exact `CanPrepareAmx` consent to its existing debit-owner authorization. The classifier binds the immutable parent, bank network, instance and dataspace; it grants no authority to a holder or role. Omitting it reproduces the actual paid owner-Grant rejection (`instruction has no reviewed private-root scope owner`) before consent publication. Local decode refusal remains retryable. |
| HC342 | Acquire an unrelated destination's target graph before route selection | `native_amx_route_discovery_retains_refused_handoff_while_another_destination_advances` | Complete common-source authentication precedes route selection. A refused route retains its original funded graph while another destination can acquire and deliver only its own target graph. |
| HC331 | Omit recovery of handoffs already applied by an independent relayer | `fresh_relayer_recovers_independent_native_handoffs_after_two_epochs_and_restart` | A fresh relay must authenticate the original successful destination effect after two epochs, even when the source epoch is no longer tracked. Local journal state, a rejected carrier, or a substituted proof cannot establish completion. |
| HC332 | Extend the source scan frontier on every pass | `growing_source_tip_cannot_starve_pending_original_handoff_retry` | Each bounded sweep pins a finite frontier so continuous source growth cannot prevent retry of an earlier pending handoff. This scheduling control does not establish whole-network liveness. |
| HC334 | omit native final freshness after original encoding and admission waits | `ct5_post_encoding_clock_advance_rolls_back_actual_begin_and_fees_with_original_decode`, `sccp_ct5_completion_resamples_clock_and_retains_original_for_certified_retry` | time-sensitive effects must be locally deferred after the last encoding wait. |
| HC335 | reuse cached native Valid without checking the actual wall clock | `ct5_cached_native_valid_rechecks_freshness_and_exact_signing_source` | cached native Valid cannot bypass a fresh local clock check. |
| HC336 | allow a first-Prepare request to substitute the original native result | `ct5_cached_native_valid_rechecks_freshness_and_exact_signing_source` | a certificate flag cannot substitute another result. |
| HC337 | omit native first-signing freshness after execution | `ct5_cached_native_valid_rechecks_freshness_and_exact_signing_source`, `sccp_ct5_prepare_signing_resamples_original_after_valid_and_binds_every_coordinate` | native first signing must recheck the actual wall clock after execution. |
| HC271 | Begin delivery skips the original successful-input and namespace join after Prepare admission | `native_amx_begin_delivery_final_namespace_refusal_preserves_original_instruction` | Genuine paid Global Begin execution and native replay retain the original signed input. Replacing its archive namespace after the Prepare proof and fields are admitted must refuse delivery without releasing or replacing them; restoring the original namespace resumes the same proof and transaction pointers with exact final refund. |
| HC272 | State publication makes actual effect-index contention irreversible before visibility | `actual_state_effect_reader_refusal_retains_original_and_retries_after_release`, `actual_state_effect_writer_refusal_retains_original_and_retries_after_release`, `signed_lifecycle_index_refusal_precedes_geometry_and_replays_final_cursor_journal` | A real last-index reader or writer must return its exact original wait before visibility. Three attempts retain the same publisher, prepared effects, staged rows and pool while releasing all sibling writers. Releasing only the blocker wakes the original wait, then that same owner publishes once; a completed retry cannot duplicate the State generation. An authenticated signed lifecycle also leaves physical geometry untouched on refusal, then persists the final cursor journal and converges through original certified-frame replay. |
| HC273 | Lifecycle preflight discards its original manifest writer refusal | `signed_lifecycle_manifest_writer_refusal_retains_preflight_and_original_retry` | Each original manifest read preserves its error precedence and returns the actual local writer refusal before geometry. Repeated refusals release the publication fences and retain the same signed lifecycle owner; releasing that writer lets the original carrier publish once with its final durable cursor journal. |
| HC274 | Kura publication releases notify before enclosing original State owners retire | `original_kura_partial_refusal_callbacks_follow_all_state_siblings`, `original_kura_success_callbacks_follow_all_state_siblings`, `original_kura_unwind_callbacks_follow_all_state_siblings` | Partial acquisition, completion and unwind release actual Kura fences into four original fixed batches. Callbacks run only after the actual State fences and effect writers are free; exact original waits, empty-batch behavior, finite-pool refund and borrowed Kura identity remain checked. |
| HC345 | Queue acquires SCCP committed history for ordinary nonexempt inputs | `ordinary_sccp_admission_needs_no_history_but_exempt_shapes_bind_original_time` | Ordinary fee-paying work and absent SCCP grant no exemption and need no SCCP history. An actual exempt shape with SCCP present still rejects missing original committed time before eligibility or custody. |
| HC348 | Lane registry retirement or recovery releases original-pool callbacks under the registry lock | `original_runtime_opening_explicit_retirement_refunds_after_registry_unlock`, `original_runtime_opening_applied_retirement_refunds_after_registry_unlock`, `original_runtime_opening_recovery_refunds_after_registry_unlock`, `original_runtime_retirement_refunds_after_registry_and_runner_unlock` | Genuine signed openings retain their original bytes and refusal owners. Explicit retirement, applied-set retirement and successful recovery notify only after every registry/store guard retires; exact original State-pool refunds can reenter the registry and enclosing runner safely. |
| HC352 | Geometry claim release wakes original watch callbacks under physical publication owners | `original_geometry_captured_rollback_watch_follows_physical_cleanup`, `original_geometry_applied_rollback_watch_follows_physical_cleanup`, `original_geometry_catalog_watch_follows_physical_cleanup`, `original_geometry_pure_drop_watch_follows_physical_cleanup`, `original_geometry_partial_error_watch_follows_physical_cleanup`, `original_geometry_unwind_watch_follows_physical_cleanup`, `original_geometry_watch_follows_direct_state_completion`, `original_geometry_watch_follows_all_state_sibling_owners`, `original_geometry_watch_follows_all_state_sibling_unwind`, `original_geometry_capture_error_watch_follows_physical_cleanup`, `original_geometry_capture_unwind_watch_follows_physical_cleanup` | Original Tokio watch senders travel with the exact physical lease cleanup through all State and Kura fences, including pure/captured/applied rollback, catalog completion, partial failure, capture refusal and unwind. The original claim becomes retryable immediately; callbacks run after cleanup on the default stack. Detached notices do not hold or wait for unrelated claims, and callback reentry/concurrent successor ownership preserve source identity. |
| HC355 | Native metadata or prepaid body read wakes original physical release callbacks beneath sibling storage fences | `original_native_frame_metadata_success_notifies_after_storage_fences`, `original_native_frame_metadata_absence_notifies_after_storage_fences`, `original_native_frame_metadata_refusal_notifies_after_storage_fences`, `original_native_frame_body_success_notifies_after_storage_fences`, `original_native_frame_body_refusal_notifies_after_storage_fences`, `original_native_frame_partial_refusals_retain_exact_storage_errors`, `original_native_frame_unwind_notifies_after_each_acquired_prefix` | Exact prune/canonical release sources outlive every acquired Kura and block-store guard for metadata capture and admitted body reads. Success, absent slots, original admission/storage refusal and acquired-prefix unwind keep the original bytes, finite pool and error classification; callbacks reenter the same Kura on the default stack. Physical notification custody remains separate from the existing allocation-refund scope. |
| HC356 | Restored-capacity publication wakes original physical release callbacks under sibling fences or before refusal accounting is invalidated | `original_capacity_recovery_success_notifies_after_final_accounting`, `original_capacity_restore_success_notifies_after_final_accounting`, `original_capacity_recovery_capacity_refusal_notifies_after_invalidation`, `original_capacity_recovery_prune_refusal_notifies_after_invalidation`, `original_capacity_recovery_canonical_refusal_notifies_after_invalidation`, `original_capacity_recovery_accounting_refusal_notifies_after_invalidation`, `original_capacity_recovery_unwind_notifies_after_each_acquired_prefix` | All four original release sources outlive the complete recovery-capacity operation, including outer error invalidation. Exact capacity, prune, canonical-journal and physical accounting refusals retain their causes; success and each acquired-prefix unwind release all physical guards before callbacks reenter the same Kura. The restored-lane completion path exercises this boundary with finite original release registration and unchanged default stacks. |
| HC357 | Durable append or nested debug publication wakes original physical waiters before enclosing storage writers and sibling fences retire | `original_durable_append_notifies_after_every_storage_fence`, `original_durable_retry_notifies_after_every_storage_fence`, `original_durable_refusal_notifies_after_every_storage_fence`, `original_durable_debug_append_notifies_after_outer_writer_retires` | The durable append operation owns all four exact physical notification batches before acquiring prune/canonical guards. Debug publication borrows its geometry/sidecar batches from that outer operation, so callbacks run after the physical writer, block data, debug path and all publication guards release. Real append, exact retry, original height-gap refusal and debug line controls preserve canonical bytes and physical inventory with finite original release registration on default stacks. |
| HC358 | Retained FASTPQ artifact persist/read wakes original physical release callbacks beneath sibling storage fences | `original_artifact_persist_success_notifies_after_storage_fences`, `original_artifact_exact_retry_notifies_after_storage_fences`, `original_artifact_quota_refusal_notifies_after_storage_fences`, `original_artifact_content_conflict_notifies_after_storage_fences`, `original_artifact_read_success_notifies_after_storage_fences`, `original_artifact_read_refusals_retain_exact_errors_and_bytes`, `original_artifact_partial_refusals_retain_exact_storage_errors`, `original_artifact_unwind_notifies_after_each_acquired_prefix` | Each artifact operation retains its exact prune/canonical/sidecar release sources before acquisition, plus geometry for persistence. Real opaque bytes, exact retry and quota/content/absence refusals retain their original files and causes. Acquired-prefix unwind releases every physical fence before actual same-Kura reentry using a finite original release registration. Controls cover retained Unix artifact API correctness; they do not qualify a compact producer or live daemon integration. |
| HC359 | Diagnostic pipeline/FASTPQ writers release original physical callbacks under the enclosing prune fence or before proof retry queues finalize | `original_direct_pipeline_success_notifies_after_outer_prune`, `original_direct_pipeline_io_refusal_retains_exact_bytes`, `original_queued_pipeline_writer_notifies_after_outer_prune`, `original_queued_fastpq_writer_notifies_after_attachment_publication`, `original_queued_fastpq_retry_and_exhaustion_finalize_before_notice`, `original_queued_fastpq_hash_refusal_retains_exact_bytes`, `original_standalone_fastpq_flush_notifies_after_retry_queue_finalizes`, `original_queued_sidecar_unwind_notifies_after_each_acquired_prefix` | The real writer-loop flush pass and direct pipeline operation own original prune/sidecar batches before acquiring guards. Nested writers borrow those exact batches through queue drain, publication, retry merge and accounting. Original finite release registrations reenter the same Kura only after all fences and queue guards retire; controls retain exact bytes, retry/exhaustion/hash outcomes and acquired-prefix unwind on default stacks. These retained APIs use test-populated queues and do not establish production producer integration. |
| HC360 | Emergency Fast snapshot boundary or hash mapping wakes original physical callbacks beneath sibling startup storage fences | `original_snapshot_boundary_empty_notifies_after_storage_fences`, `original_snapshot_boundary_native_hash_notifies_after_storage_fences`, `original_snapshot_mapping_empty_notifies_after_storage_fences`, `original_snapshot_mapping_native_bytes_notifies_after_storage_fences`, `original_snapshot_mapping_height_refusal_retains_exact_journals`, `original_snapshot_corrupt_journal_refusal_retains_exact_error_and_bytes`, `original_snapshot_partial_refusals_preserve_storage_and_mode_errors`, `original_snapshot_unwind_notifies_after_each_acquired_prefix` | Both startup read operations retain the exact prune/canonical notifications before acquisition and until block-store custody retires. Real Strict-to-Fast reopen controls use original certified native block hashes and read-only journal bytes, preserving empty/nonempty results, mode/height/corrupt/prune/poison refusals and acquired-prefix unwind on default stacks. Finite original release waiters reenter the same Kura after unlock; no history or State authentication claim follows from these Unix startup API controls, and positive-height State replay refusal remains unchanged. |
| HC361 | Physical inventory reconciliation or nested FASTPQ inventory validation wakes original source callbacks beneath outer storage fences or before final family invalidation | `original_inventory_absent_artifacts_publish_before_source_notice`, `original_inventory_retained_artifacts_publish_exact_counts_before_notice`, `original_inventory_artifact_refusal_invalidates_every_family_before_notice`, `original_inventory_tree_refusal_invalidates_every_family_before_notice`, `original_inventory_busy_owner_refusal_invalidates_before_prefix_notice`, `original_inventory_acquired_prefix_refusal_invalidates_before_notice`, `original_inventory_unwind_notifies_after_each_acquired_prefix` | Reconciliation owns prune, canonical and sidecar notifications outside its result closure; nested artifact validation borrows that sidecar source. Finite original physical waiters observe all six physical family publications or typed invalidations before aggregate reentry. Real file-backed fixtures preserve exact retained bytes, successful counts, busy-owner and invalid-file refusals, partial acquisition and unwind on default stacks. Constructor/re-audit API coverage does not establish live daemon or operator qualification. |
| HC363 | Recapture a native lane instance namespace after refusal or skip its original custody join after authentication | `lane_proof_original_namespace_survives_funded_refusal_and_identical_replacement`, `completed_lane_proof_rejoins_original_namespace_before_attribution`, `funded_lane_frame_late_namespace_refusal_retains_completed_original_body` | A complete ancestry read retains one original directory and all ancestors across finite-pool refusals and descriptor-relative frame reads. Replacing that namespace with identical certified bytes cannot transfer authority. Late real-BLS authentication refusal preserves the exact completed body, original configuration and QC for allocation-free same-owner retry. Completed attribution rejoins the original namespace. Missing-instance retry remains distinct from changed-custody rejection; genesis-only evidence requires no lane directory. These reader controls do not authorize physical deletion: complete genesis-to-tip history and every referenced retired frame remain retained until an authenticated history-release owner exists. |
| HC364 | Hold the shared lane registry while one original lane opening authenticates/restores and synchronizes retained frames | `original_lane_recovery_allows_ready_disjoint_owner_during_native_sync`, `original_lane_recovery_retains_in_flight_historical_join_through_retirement`, `original_lane_recovery_runtime_refusal_cancels_only_after_active_owner_returns` | Only the same per-key recovery owner is busy. Already-ready disjoint owners remain immediately available at actual native recovery I/O; same-key attempts preserve retryable refusal without recapturing authority. Active original Arcs and historical joins retain recovery across retirement; idle runtime-only refusals cancel. A pre-publication join observes the same completed Ready owner. Full original bytes, finite-pool charges and certificate checks are unchanged; physical deletion is not authorized. |
| HC365 | Omit original native receipt-purpose admission for the block-start retail sweep | `original_idle_sweep_admits_exact_native_receipts_before_carrier_execution`, `original_idle_sweep_keeps_bounded_month_prefix_and_fair_native_share`, `original_one_entry_native_policy_alternates_retail_and_sns_admission` | Each selected collected receipt owns its actual native quota entry through the original physical transaction generation, receipt bytes and moved delta. State, source and witness roll back together on refusal. Retail keeps the existing twelve-month/128-wallet bounds and shares the unchanged finite native pool with SNS: half, with the odd slot alternating by height. Only exact admitted month boundaries and actually processed cursor keys advance; original remaining debits are retained. Independent sibling, decode-refusal, shared-pool and witness controls remain mandatory. |
| HC366 | Omit the individual SNS renewal witness rollback owner | `original_sns_late_fee_refusal_drops_witness_before_retry_metadata` | A late fee-evidence refusal after actual payment preparation drops child State, native quota and witness before ordinary retry metadata is committed. The unchanged same-source payment succeeds on retry; no failed transfer witness escapes into Time. |
| HC367 | Select total native invocation capacity instead of the original remaining pool | `original_time_sns_sweep_uses_only_capacity_left_by_exact_retail_prefix` | The sole Time token captures actual remaining E after the retail prefix. Selection cannot turn shared-pool contention into SNS payment failure or cursor advancement. Genuine Time integration covers 32 retail plus 32 SNS entries in the unchanged 64-entry pool and both one-entry height slots, including untouched retry fields and zero-capacity witness preservation. This mutation leaves retail admission and SNS witness rollback intact. |
| HC368 | Discard the completed frozen-table selector after a later work refusal | `ordinal_encoder_admits_count_before_backing_and_retains_refused_planning_work` | Retain completed selector work and its static result in the original encoder. Repeated insufficient cumulative grants preserve progress; the exact selector-plus-registry allowance prepares the same canonical kernel without starvation, allocation before cardinality admission, or replacement scope. |
| HC369 | Discard completed canonical sort geometry after a later work refusal | `retained_sort_geometry_survives_exact_cumulative_work_refusal` | Retain the exact sort demand in the original encoder. Repeated insufficient cumulative grants neither repeat nor recharge geometry; the exact comparison allowance completes the sort before separately charged finalization. No work grant is inferred from used work or output. |
| HC370 | Original Musubi lookup: forget paid comparison while its native row reborrow refuses | `retained_lookup_keeps_paid_geometry_and_comparison_across_native_refusal` | A retained exact query keeps the original key geometry, search bounds and successful comparison admission through a later native reborrow refusal. Exact cumulative work completes the same current/predecessor midpoint without recharging the comparison or replacing the original row. |
| HC371 | Original Musubi scheduling: retry native reads before retained minimum demand is covered | `retry_demand_waits_without_granting_charging_or_forgetting_the_original_field` | A real native work refusal retains its original field and measured minimum retry demand. Scheduling waits without reading, allocating, charging or granting work until the independently granted ceiling covers that demand. A separate one-unit configured-grant control must complete both original semantic images while preserving monotonic actual work. |
| HC372 | Original State capture grants: reconstruct cumulative allowance from consumed work | `configured_work_grants_accumulate_independently_of_consumed_source_work` | The pinned local State capture policy increments only the previous explicit grant ceiling. Consumed native work, semantic row counts and allocation bytes cannot replenish or replace work authority. Zero-quantum and independent memory/source-policy refusal controls preserve the original source. |
| HC373 | Original publication: stop source grants after retained semantic completion | `real_publication_grants_native_work_after_semantics_complete` | Both original semantic images may finish before canonical encoders finish native row acquisition. Every scheduled capture attempt grants independent native and encoding work until capture completes; neither consumed work nor semantic success supplies or suspends authority. |
| HC374 | Original publication: discard canonical nodes while retiring original source readers | `real_publication_retires_sources_but_retains_canonical_nodes_after_late_refusal` | Retire the actual original source descriptors/readers before writer installation, while the same charged admission owner retains completed canonical table trees. A late original World writer refusal cannot rebuild, replace or discard those nodes. |
| HC375 | Original publication: reread paid source rows while encoding demand remains unmet | `real_publication_encoding_wait_does_not_repeat_paid_source_reborrows` | Retain an unmet encoding operation demand and wait for the independent cumulative encoding grant before reborrowing original source rows. Waiting neither charges native work again nor grants work from consumed output. |
| HC376 | Original publication: reopen retired source descriptors after an outside-reader refusal | `real_publication_reader_retirement_refusal_resumes_without_reopening_source` | Once all three canonical tables finish, retry original source-reader retirement directly. An outside reader may refuse after descriptor retirement; retained tables, work, scope and physical-fence release remain unchanged. Full State/cell/history authority and physical lane retirement remain separate incomplete boundaries. |
| HC362 | Completed recovery substitutes optional or cached capacity accounting for exact durable journal authentication | `original_capacity_recovery_canonical_refusal_notifies_after_invalidation`, `original_capacity_recovery_cached_boundary_cannot_mask_corrupt_journals`, `original_capacity_recovery_poisoned_boundary_cannot_publish_accounting` | Recovery authenticates the canonical durable boundary under prune/canonical ownership before later storage locks, independent of capacity limits and accounting caches. Corrupt index/hash journals and poisoned storage retain their exact refusal; original waiters observe final invalidation after all fences release. Repaired journals retry successfully on default stacks. |
| HC354 | Geometry recovery wakes original physical release callbacks beneath sibling fences | `original_geometry_preflight_success_notifies_after_all_fences`, `original_geometry_preflight_refusal_notifies_after_all_fences`, `original_geometry_replay_success_notifies_after_all_fences`, `original_geometry_replay_refusal_notifies_after_all_fences`, `original_geometry_startup_success_notifies_after_all_fences`, `original_geometry_startup_refusal_notifies_after_all_fences`, `original_geometry_recovery_partial_refusals_keep_exact_errors_and_release_sources`, `original_geometry_recovery_unwind_notifies_after_every_acquired_fence` | Exact source-bound release owners outlive the complete prune/canonical/geometry/sidecar guard prefix in configured-primary preflight, authenticated replay and journal-owned instance recovery. Success, original storage refusal, partial acquisition and unwind notify only after every acquired physical fence releases; callbacks reenter the same Kura on the default stack. Retained journal evidence, cursor authentication and additions-only retirement remain unchanged. |
| HC353 | Native lane authority releases original State reader callbacks under scan or registry locks | `original_native_history_reader_success_reenters_after_scan_unlock`, `original_native_history_reader_absence_reenters_after_scan_unlock`, `original_native_history_reader_error_reenters_after_scan_unlock`, `original_native_history_reader_reentry_preserves_concurrent_ready_owner`, `original_native_history_partial_reader_refusal_retains_exact_source_after_unlock`, `original_authority_recheck_retains_reentrant_opening_and_historical_interest` | The caller retains exact State reader notices outside the scan frame, including complete, absent, corrupt-history and partial-reader refusal exits. Physical contention returns its original typed release source without spinning. Authority lookup runs outside the lane registry; reacquisition joins any original Ready or Opening owner and preserves historical interest, finite funding and authenticated frame bytes. |
| HC351 | Native lane history refunds original authenticated scan owners under the scan mutex | `original_history_scan_progress_refunds_after_scan_unlock`, `original_history_scan_finish_refunds_after_scan_unlock`, `original_history_scan_cancellation_refunds_after_scan_unlock`, `original_history_scan_stale_cut_refunds_after_scan_unlock`, `original_history_scan_terminal_cleanup_refunds_after_scan_unlock`, `original_history_scan_cancelled_error_refunds_after_scan_unlock`, `original_history_scan_invalid_prefix_refunds_after_scan_unlock`, `original_history_scan_refused_retry_refunds_after_scan_unlock` | The actual original State pool defers callbacks until every scan guard and its large owner frame retire. Signed historical progress, completed transfer, cancellation, stale publication, terminal namespace/prefix errors and refused original-descriptor retry preserve authentication and exact funding; callbacks reenter the real reader on the default test stack. |
| HC350 | Direct lane store completion releases original charged owners under state or enclosing batch guards | `original_lane_body_refund_waits_for_state_unlock`, `original_lane_batch_refund_waits_for_both_original_guards`, `original_lane_entry_refund_waits_for_state_unlock`, `original_lane_authenticated_height_refund_waits_for_state_unlock`, `original_lane_append_refund_waits_for_state_unlock`, `original_lane_repeated_append_refund_waits_for_state_unlock`, `original_lane_rejected_append_refund_waits_for_state_unlock`, `original_lane_opening_refund_follows_complete_recovery_cleanup` | Real signed body, batch, entry, retained-tip, new/repeated/rejected publication and startup recovery paths retain their original pool. Nested notifications wait for the outermost state/batch operation and complete recovery cleanup; exact original source, durable bytes, refusal retry and final refunds remain checked. |
| HC349 | Lane reconciliation retains its running-map lock through original store retirement | `original_runtime_retirement_refunds_after_registry_and_runner_unlock` | The actual reconciler uses the captured committed lane set and one topology writer. It stops retired drivers before starting replacements, joins outside the map guard, and retires pending originals only after both registry and runner locks release. A real signed opening and its original State-pool callback probe both actual locks without blocking. |
| HC347 | Ingress route retirement refunds the original driver while its route writer is held | `ingress_unregister_refunds_outside_original_route_lock` | Removing or replacing a route retires the original funded sink only after unlocking. Delivery retains that same sink outside the lookup lock, so it can unregister itself. Real finite-pool refusals wake exactly once after backing storage retires; nonblocking probes prove callback reentry and exact final refund without a deadlock timeout. |
| HC346 | Native Queue sampling acquires SCCP history before an eligible candidate needs it | `native_sampling_only_requires_original_time_for_live_sccp_candidates` | Ordinary candidates and absent SCCP grant no exemption and need no SCCP history. A live exempt-shaped candidate with committed SCCP parameters still refuses missing original time, retaining its complete carrier, original bytes, pending owner and queue counts. |
| HC344 | Certified lane merge replaces the original sealed reveal with its inner external transaction | `certified_merge_retains_sealed_carrier_and_enforces_original_salt_before_execution` | Real four-validator lane availability, execution, prepare, persisted QC and recovery retain the complete source. The actual source-bound Expansion preserves commitment and salt before global execution; wrong salt refuses without consuming its pending commitment or authenticating the inner replay identity. |
| HC275 | Native append discards its original physical State authority read release | `original_append_driver_retains_manifest_release_without_timer_or_foreign_wake` | The original global authority read captures State once without blocking and preserves its typed physical refusal. The actual executor-thread append completion retains that same release in the existing committed-head scheduler: elapsed time and unrelated releases cannot dispatch it, while the actual writer release permits the same certified frame to append and only then reach commit. |
| HC267 | Decision delivery skips the original Begin/Decision namespace join after instruction admission | `native_amx_decision_delivery_final_namespace_refusal_preserves_original_instruction` | Genuine paid execution and native replay produce the original Decision. Replacing its archive namespace immediately after funded instruction admission must refuse delivery while retaining that exact instruction; restoring the original namespace permits delivery with unchanged proof pointers and complete refund. |
| HC257 | Omit CT1 in full State execution | `sumeragi::executor::clock_tests::prepare_withheld_while_block_time_ahead` | A genuine future block returns local Failed before effects and without a negative cache entry. Advancing the injected clock to the exact committed allowance boundary permits the same original execution. |
| HC258 | Drop `Execute.certified` in the production driver | `sumeragi::driver::tests::sched::certified_execution_flag_reaches_the_application_without_inference` | False and true reach the application unchanged on every request, including repeated original execution. `certified_execution_skips_clock_guards` additionally exercises the actual worker request, identical result, certificate authentication and cold replay. |
| HC259 | Global and routing-lane selection includes future signed inputs | `proposer_clock_selection_retains_future_signed_inputs_until_the_exact_time`; `lane_proposer_clock_selection_preserves_future_inputs_and_resumes_after_advance` | A valid queued input one millisecond ahead of the injected proposer clock remains resident and unselected; advancing to its exact time selects its unchanged identity, and rewinding withholds it again. |
| HC260 | Publish an original canonical payload before its proposer clock boundary | `proposer_clock_retains_final_input_and_canonical_output_until_due`; `proposer_clock_retains_certified_lane_floor_and_completed_original` | Genuine signed Queue inputs and certified lane ranges wait through canonical assembly and completed output reuse. Advancing the injected clock releases the same original backing; rewinding withholds it again. `clock_ahead_payload_retries_without_another_queue_notification` separately checks the actual scheduler's timed retry with no new input. |
| HC264 | Routing lane builder collapses a clock wait into an empty answer | `sumeragi::lanes::executor::tests::future_only_lane_work_retries_without_an_empty_answer_or_new_traffic` | Future-only work yields a local retry and no empty callback. Advancing the injected clock lets the unchanged queue source produce the same signed transaction without another admission event. |
| HC268 | Omit routing-lane CT1 before caching original admission | `sumeragi::lanes::executor::native_decode_tests::signed_lane_clock_retains_original_admission_until_exact_boundary_and_certified_replay` | A signed four-validator lane body retains one original decoded admission at the anchor/input clock boundary, resumes at equality, and produces the same result during certified execution and authenticated stored recovery. A separate foreign-anchor control refuses changed identity. |
| HC269 | Publish a routing-lane payload ahead of its effective clock | `sumeragi::lanes::executor::tests::lane_builder_effective_clock_retains_original_payload_across_clock_rewind` | Both the anchor and latest signed input can set the clock floor. Local waiting retains the same original batch and completed funded bytes; rewinding withholds the same output until its exact boundary recovers. |
| HC254 | Retire the original lane geometry owners without final physical authentication | `state::tests::geometry_completion_tests::completed_publication_refuses_substituted_journal_namespace_and_retries_original_owner`; `state::tests::geometry_completion_tests::prepublication_refuses_substituted_tiered_directory_and_retries_original_owner`; `state::tests::geometry_completion_tests::completed_publication_refuses_substituted_tiered_directory_and_retries_original_owner` | Logical phase flags cannot replace original journal and tiered-directory identity. All three independent controls refuse substitution before releasing either retained owner, preserve the runtime catalog and journal direction, and restore the same original physical source before successful retry. The journal namespace test preserves original journal metadata rather than weakening ctime checks. This does not grant physical lane retirement authority. |
| HC255 | Reopen an already-applied tiered plan before an original-path identity refusal | `state::tests::geometry_completion_tests::completed_retry_preserves_original_applied_progress_on_tiered_identity_refusal` | Retry of a completed publication authenticates its retained tiered plan immutably. Refusal preserves applied progress, both original owner addresses, catalog phase and cursor progress; restoring the original directory resumes that same operation. |
| HC256 | A completed publication accepts a changed configured baseline | `state::tests::geometry_completion_tests::completed_publication_refuses_changed_baseline_and_retries_original_owner` | Completion rejoins the configured baseline retained by the original raw publication owner. Both an absent and a different baseline refuse without changing journal bytes or releasing either owner; only the original baseline permits retry. |

The finite Core full-proof interval is request-owned. Its Torii/SDK callers retain actual query, worker and response owners separately under the existing route and SDK absolute deadlines. Nested signed-genesis/result/authority graph funding remains open. These controls do not attribute the observed H3 timeout to prefix work or qualify the paid transition.

DataModel allocation-custody rules execute only under `--model` in its own `mutation-testing`
unit-test compilation (`SUMERAGI_MODEL_MUTATION`, `sumeragi_model_mutation`). The library rejects
this feature in every non-test build; no selector is propagated to Core or a dependency. The
positive baseline and each mutant use the test profile, unchanged per-build/named deadlines,
exact discovered terminal accounting and strict named-test kills. These controls establish local
resource ownership only. Native source authority, debit authority, paid execution, transport,
restart and full release qualification remain separate required controls.

| Mutation | Fault | Named deterministic test | Rule exercised |
|---|---|---|---|
| DM1 | Deep-copy the concrete AMX instruction instead of retaining its original shared graph | `original_amx_instruction_clone_retains_exact_graph_and_pool_through_last_reader` | Every actual backing pointer, canonical wire/type identity and original finite-pool charge must remain through local instruction Clone and the last reader. Returning an unfunded DTO loses that ownership and may refund its source while the clone remains live. |
| DM2 | Omit the actual Begin participant allocation from the portable proof admission plan | `original_amx_instruction_admits_complete_actual_layouts_before_copy_and_retries_same_pool` | All five actual proof Vec capacities, ledger storage, Prepare arrays and shared shell must have exact original-pool credit before copying. The control derives those concrete layouts independently from the demand helper, refuses one missing byte, retains the source and retries the same pool. |
| DM3 | Retain the final additional ledger after destroying its instruction fields | `original_amx_instruction_last_owner_destroys_fields_and_refunds_exact_ledger` | Nonfinal readers retain every original charge; the final owner destroys its fields and returns all exact proof, additional-ledger and shared-shell credits once. Leaked final credit cannot masquerade as a completed release or future capacity. |
| DM4 | Skip only Begin's canonical participant-field payload context during the original source scan | `original_begin_record_scan_preserves_canonical_depth_refusal_and_exact_retry` | A borrowed stack projection must keep the original canonical Vec field depth, ceiling, flags and boundary. The same original frame must refuse the exact enclosing depth at scanner limit three and retry at four; ordinary whole-frame owning decode adds its separate root level. The mutant keeps canonical framing, participant/count parsing, exact consumption, deadline, fixed leaves and allocation ownership, but omits only the Vec field payload context. |

| DM5 | Materialize the canonical transaction frame in public AMX identity hashing | `observer_counts_all_three_allocation_routes_and_resets_after_unwind`, `transaction_id_streaming_matches_canonical_frames_without_heap_allocations` | The independently materialized canonical frame/hash oracle precedes observation. On a fresh worker thread, valid minimum/maximum participant and leg bounds retain exact input pointers and request no `alloc`, `alloc_zeroed` or `realloc`. The calibrated test allocator forwards original System contracts and resets after unwind; no decode-budget proxy or process-cold cryptographic claim is made. |
| DM6 | Reconstruct a heap-owning Begin during an original-field match | `observer_counts_all_three_allocation_routes_and_resets_after_unwind`, `begin_matches_borrows_original_graph_without_heap_allocations` | Begin matching must compare the original participant iterator, deadline and canonical transaction id without copying a Vec. The same actual allocator observer checks minimum/maximum bounds on a fresh worker thread, with exact canonical IDs and retained graph pointers. The mutation changes only test-local reconstruction; monetary encoding, authority and proof admission remain unchanged. |
| DM7 | Materialize the canonical native monetary leg frame during effects hashing | `observer_counts_all_three_allocation_routes_and_resets_after_unwind`, `native_transfer_effects_stream_exact_monetary_fields_without_heap_allocations` | Paid Prepare and retained escrow validation must hash the original canonical UUID/scope, account controllers, compact keys and bounded Quantity without a temporary frame or nested serializer heap scratch. The independently encoded domain/frame oracle precedes fresh-thread allocator observation; single/multisig fields, wide scaled quantities, layout independence and every monetary-field substitution remain exact. The real paid native control additionally retains its authenticated escrow graph in the occupied original pool. Ordinary owning leg decode and witness publication require separate complete funding. |
| DM8 | Mark an AMX deadline decision before all record callbacks succeed | `sumeragi_amx_expiry_refusal_and_unwind_preserve_original_pending_graph` | First/second callback refusal and unwind preserve every original pending field and backing allocation. All expired decisions are streamed without temporary vector ownership; only successful completion prunes the original source. Retry emits each exact Abort once into the accepted keyed destination. |
| DM9 | Convert an AMX codec allocation refusal into a string error | `sumeragi_amx_encoding_keeps_exact_physical_allocator_refusal` | The actual codec-error boundary preserves the allocation refusal and requested bytes as a local resource error; malformed data keeps its encoding verdict. The deterministic boundary control supplies the original allocator error value; it does not inject a physical allocation failure or close witness allocation accounting. |
| DM10 | pinned genesis: repeat completed canonical authentication over the original body | `sumeragi_finality::genesis_dataspace::tests::pinned_signed_genesis_uses_one_original_decode_and_retains_metadata` | Independently selected exact raw/hash/network/signature/transaction/mode/roster pins remain mandatory. One actual canonical binary acquisition and complete signed-genesis pass retains its Copy metadata without a second decoder. Original binary refusal kind/fields or signed JSON cause survives the existing portable error chain; actual contexts/pools and intrinsic bounds remain unchanged. This is synchronous Model reading, not complete nested graph funding or durable validator relaying. |
| DM11 | pinned genesis: erase original binary decoder refusal provenance | `sumeragi_finality::genesis_dataspace::tests::pinned_signed_genesis_preserves_original_binary_refusal` | Independently selected exact raw/hash/network/signature/transaction/mode/roster pins remain mandatory. One actual canonical binary acquisition and complete signed-genesis pass retains its Copy metadata without a second decoder. Original binary refusal kind/fields or signed JSON cause survives the existing portable error chain; actual contexts/pools and intrinsic bounds remain unchanged. This is synchronous Model reading, not complete nested graph funding or durable validator relaying. |
| DM12 | pinned genesis: erase original signed JSON decoder refusal provenance | `sumeragi_finality::genesis_dataspace::tests::pinned_signed_genesis_preserves_original_json_refusal_and_retry` | Independently selected exact raw/hash/network/signature/transaction/mode/roster pins remain mandatory. One actual canonical binary acquisition and complete signed-genesis pass retains its Copy metadata without a second decoder. Original binary refusal kind/fields or signed JSON cause survives the existing portable error chain; actual contexts/pools and intrinsic bounds remain unchanged. This is synchronous Model reading, not complete nested graph funding or durable validator relaying. |
| DM13 | consensus fingerprint: reopen completed authenticated metadata | `sumeragi_finality::tests::consensus_fingerprint_reuses_original_authenticated_metadata_under_one_pass_budget` | Canonical authentication supplies its exact Copy metadata and epoch once. Fingerprinting retains all seven explicit signed instruction requirements, current canonical output, original JSON refusal and finite cumulative decoder work. No new authority graph, funding pool or nested physical-custody claim is introduced. |
| DM14 | initial chain parameters: reopen constructor-authenticated metadata | `sumeragi_finality::tests::initial_chain_parameters_reuses_constructor_authenticated_metadata_under_one_pass_budget` | The independently selected portable constructor retains one exact metadata scalar; parameter reads and root scope reuse it without another metadata decode. Missing, repeated or invalid explicit instructions remain rejected. Source, committee and instance validation is unchanged; a successful parameter read is not execution finality. |
| DM15 | original signed genesis policy: repeat completed exact instruction decoding | `sumeragi_finality::genesis::original_policy::tests::original_completed_policy_survives_metadata_refusal_without_another_decode` | The sole canonical authentication kernel preserves signature, domain, duplicate-policy, metadata and complete epoch order. Only the completed same-body instruction reuses its original funded policy. A later policy is parsed before the duplicate verdict; zero decoder quota reaches the original metadata refusal without redoing policy work. The caller still owns partial decode and nested epoch/result graph custody. |
| DM16 | Reconstruct a temporary generation roster during signed epoch validation | `sumeragi::epoch::tests::epoch_validation_retains_original_signed_roster_without_generation_allocation` | Public validation borrows the exact original signed committee while preserving the fixed-width generation transcript and original validation/error order. Real allocator requests, native key/PoP identity, source wire/hash, cumulative decoder and original pool/refund observations precede the named zero-request assertion. Retained output epoch/authority graph funding and later preparation generation copies remain separate obligations. |
| DM17 | Reconstruct the fixed synthetic stake identity during original NPoS record transfer | `parameter::system::npos_json::tests::admitted_npos_record_moves_exact_original_quantity_backing_and_funded_charge_ledger`, `parameter::system::tests::sumeragi_npos_synthetic_identity_is_exact_and_validation_never_allocates`, `nexus::committee::tests::frozen_policy_validation_borrows_fixed_synthetic_identity_without_allocation` | The fixed UUID bytes must equal genuine canonical `nexus.universal/xor` derivation. Both signed-parameter and frozen-policy validators compare that exact scalar without rebuilding domains, names or format storage. The original admitted record's physical allocation/retirement observer and the two actual validator controls must fail if the same fixed identity is reconstructed; all rejection predicates, error labels and order remain unchanged. This does not fund complete epoch/crypto graphs. |
| DM18 | Reconstruct a temporary owning generation in public committee readiness | `nexus::committee::tests::public_readiness_borrows_original_roster_with_only_canonical_transcript_work` | The public readiness context keeps exact original peer/PoP backing, canonical authority identity and signing digest. Real allocator routes equal independently measured mandatory beacon/transition transcript work; extra roster requests fail the named assertion. The mutant restores only the temporary generation at the original identity expression. This local relation does not fund complete authority or crypto graphs. |
| DM19 | Reconstruct a temporary owning generation in public Activate validation | `nexus::committee::tests::public_activation_borrows_original_generation_beyond_existing_readiness_work` | The actual complete Activate relation keeps original outcome coordinates, full readiness and transcript/crypto work. Its measured requests equal the genuine no-outcome validation plus the additional canonical transition transcript. Only the last short-circuited generation relation is restored by the mutant; earlier readiness, beacon, authorization and error ordering remain exact. This is local allocation custody, not paid rotation qualification. |
| DM20 | Multisig contract recognition: turn original scoped JSON refusal into nonmatch | `smart_contract::multisig_call::tests::canonical_recognition_preserves_original_scoped_refusal_and_same_envelope_retry` | The genuine canonical instruction pair retains the original JSON observer error unchanged. Refusal is distinct from malformed or nonmatching policy; the same original context retries the unchanged envelope after the narrower allowance retires. Exact scoped identity, canonical wire, instruction pointer and pool/refund assertions precede successful recognition. The mutation omits only the scoped error arm; it grants no new scope, signer, fee or finality authority. |
| DM21 | Erase canonical address original resource fields and scope | `account::address::tests::canonical_address_json_preserves_original_refusal_fields_scope_and_retry`, `account::address::tests::account_address_value_and_map_key_json_decoders_are_borrowed_and_measured`, `account::address::tests::address_resource_conversions_preserve_fields_and_anonymous_bounds_without_minting_scope` | The sole decoder cause owner preserves exact unscoped quota/allocation fields and the original scoped identity; anonymous arithmetic limits remain distinct. Genuine value/key/document readers retry the same input and original finite context and preserve cumulative debit and pool refund. |
| DM22 | Replace canonical account original Address error with a fieldless bound | `account::json_tests::canonical_account_json_preserves_original_refusal_fields_scope_and_retry`, `account::json_tests::account_id_json_roundtrips_large_multisig_as_canonical_i105`, `account::json_tests::account_id_value_and_map_key_json_decoders_are_borrowed_and_measured`, `account::json_tests::canonical_account_public_parser_preserves_original_address_cause_and_diagnostics` | The sole canonical I105 parser preserves the actual Address cause through AccountId and JSON. Stable diagnostic codes, malformed input, prefix/checksum precedence and canonical re-encoding remain unchanged; the mutation retains the code while omitting only the cause. |
| DM23 | Continue numeric I105 candidates after original resource refusal | `account::address::tests::numeric_i105_resource_refusal_stops_at_original_candidate_without_later_allocations` | The public parser stops at its first genuine admitted-controller refusal. Original physical allocator requests equal the exact first-candidate canonical cut, including legitimate numeric sentinel formatting and all pre-refusal buffers. The test-owned mutation omits only the terminal guards, restoring later candidate work; exact scope, cumulative debit, unchanged source, same-context retry and pool refund remain mandatory. |
| DM24 | Retry expected-prefix payload diagnostics after original resource refusal | `account::address::tests::expected_i105_prefix_diagnostics_do_not_retry_original_resource_refusal` | The same real numeric public parser with and without an expected prefix performs identical work when its original controller admission refuses. The mutation omits only the diagnostic terminal guard and restores the extra payload decode; numeric candidate terminal guards, typed cause identity, checksum/malformed/foreign-prefix behavior and original-context retry remain intact. |
| DM25 | persisted AccountId storage keys: erase original typed refusal at canonical delegation | `json_key_codec::tests::account_storage_keys_preserve_original_refusal_fields_scope_and_retry` | The actual canonical AccountId key owner admits the original literal and preserves carried resource fields and exact scoped identity through real mv Storage restoration. The test retries the unchanged source with the same original finite context and verifies cumulative debit and context-pool refund. The mutation stringifies only a genuine typed refusal after the current canonical decode; valid/malformed parsing and writer bytes remain unchanged. |
| DM26 | persisted role assignment keys: erase original account refusal at canonical delegation | `role::native_assignment_tests::role_assignment_storage_keys_preserve_original_account_refusal_and_retry` | The account component of the actual `account|role` storage key uses canonical AccountId JSON admission while role grammar errors remain terminal. Direct keys and real committed role Storage restoration preserve original fields/scope, retry and refund. The mutation omits only the returned account refusal cause; it restores no retired text parser or alternate decoder. |
| DM27 | Kaigi participant metadata: erase original typed refusal at canonical map delegation | `kaigi::tests::kaigi_participant_metadata_preserves_original_account_refusal_and_canonical_map` | The actual KaigiRecord participant map uses canonical BTreeMap node/key admission and duplicate rejection while retaining its deterministic lexical serializer. Every below-demand quota through the genuine helper/full DTO preserves original fields/scope, same-input retry and context refund; exact writer/binary parity and malformed/duplicate keys remain mandatory. The mutation stringifies only a genuine typed refusal returned by this canonical delegation; it creates no raw Value/manual decoder. |
| DM28 | instruction archive: retry after original borrowed-pair refusal | `isi::instruction_decode_refusal_tests::archived_instruction_refusal_stops_without_allocating_an_owned_pair_retry` | The archived reader stops at the first real borrowed-pair refusal without retry allocation. Original resource fields and scope survive, and retry uses the same input and cumulative context. |
| DM29 | instruction slice: erase original scoped resource refusal | `isi::instruction_decode_refusal_tests::instruction_slice_retains_original_scoped_refusal_and_retry` | The canonical direct-slice reader preserves the original scoped refusal through its framing adapter. Malformed frames remain terminal, and the same source and context can retry. |
| DM30 | instruction JSON: stringify original nested binary refusal | `isi::instruction_decode_refusal_tests::instruction_json_retains_original_scoped_refusal_and_retry` | Canonical base64 JSON preserves the real nested instruction decoder refusal, its original fields and scope, and same-context retry. The genuine multisig proposal metadata reader exercises this production boundary. |
| DM31 | instruction base64: omit cumulative scratch admission | `isi::instruction_decode_refusal_tests::instruction_base64_scratch_is_admitted_before_decode_and_retries_original_input` | The actual base64 scratch capacity is cumulatively admitted before allocation and decoding. Below-capacity admission refuses with exact fields; the same source retries. This does not claim physical original-pool ownership of the decoded graph. |
| DM32 | structured asset instructions: erase original canonical account refusal | `isi::instruction_decode_refusal_tests::structured_asset_instructions_preserve_original_account_refusal_and_retry` | All four structured asset-transfer instructions borrow the account literal and delegate to canonical AccountId JSON admission. Genuine scoped shortages retain their fields and original observer through the public InstructionBox reader; the same input/context retries and malformed or padded account literals remain terminal. |
| DM33 | Allocate a diagnostic String instead of retaining the original intrinsic native AMX multisig cause | `sumeragi_amx::native::leg_decode::tests::invalid_native_multisig_threshold_replay_preserves_original_cause_without_diagnostic_allocations`, `sumeragi_amx::native::leg_decode::tests::invalid_native_multisig_member_replay_preserves_original_cause_without_diagnostic_allocations` | The sole canonical policy/member validators retain their Copy cause by value, including original dynamic version, curve, count and threshold fields. Replay of the already materialized invalid owner preserves the exact original pool, controls, keys, member/charge ledger and spans without a diagnostic or replacement allocation; ordinary canonical diagnostic parity remains exact. The test-only omission restores only the old String conversion. Core maps this intrinsic cause to the existing terminal diagnostic without inferring local retry provenance. Ordinary codec diagnostics, the final Core diagnostic and complete graph funding remain separate open boundaries. |
| DM34 | Reconstruct an owning canonical epoch snapshot for optional validation reuse | `sumeragi_finality::epoch_graph::validation_tests::epoch_scope_retains_exact_context_without_a_hidden_heap_graph` | The actual cache retains all original scalar and ordered key/PoP values inline under the native maximum of 31. Mandatory context validation is measured independently; the named physical-allocation assertion runs with adequate original capacity before optional insertion assertions. A separate full-pool phase checks fresh insertion/hits, unchanged cumulative debit and final refund. Exact fields, last-member/order/overflow refusal, source independence and default-stack layout remain required; complete authority/configuration/source graph funding is still separate. Every declared control must fail at its own exact assertion; worker controls retain their original child and join panic ownership. |
| DM35 | Discard an evicted authenticated global context while an unresolved AMX Yes still needs it | `sumeragi_amx_delayed_decisions_survive_three_rotations_and_restart` | A delayed genuine Commit or Abort remains verifiable after three authenticated committee rotations and canonical participant State serialization/restart. Handoffs never release escrow, the successful decision creates exactly one effect, and replay cannot create another. Missing required historical authority fails restored-State validation. |
| DM36 | Omit the shared CT4 clock-drift bound | `parameter::system::tests::clock_drift_bound_accepts_exact_limit_and_rejects_excess_without_overflow` | Zero and 60 000 ms are admitted; 60 001 ms and `u64::MAX` are rejected by the single model validator used by structured genesis, executed genesis and committed parameter changes. No local clock enters deterministic parameter validity. |
| DM37 | Omit the committed due-work margin and checked arithmetic | `parameter::system::tests::due_work_policy_checks_combined_margin_and_overflow_without_local_clock` | Admit the exact `2 × drift + 4 × cadence` lag boundary; refuse one below, zero cadence and multiplication/addition overflow. The same committed policy is checked before signing genesis, after executing genesis and on parameter changes. |
| DM38 | Accept an exact debit permission under a foreign certified root | `sumeragi_amx::approval_proof::tests::exact_debit_approval_rejects_substituted_roots_terms_relays_schema_and_permission_preimages` | A genuine Global certificate over the same synthetic permission preimages cannot authenticate private-root debit consent. Exact parent, participant, instance, terms, relay, schema and World preimages remain independently selected. Native Grant/Prepare qualification is separate. |
| DM39 | last Yes ignores signed ledger-time expiry | `sumeragi_amx::tests::time_tests::sumeragi_amx_time_boundary_is_exclusive_and_height_boundary_inclusive` | late Yes must never decide Commit. |
| DM40 | time expiry mutates a pending decision before its original writer accepts | `sumeragi_amx::tests::time_tests::sumeragi_amx_time_expiry_preserves_all_pending_rows_on_writer_refusal` | failed witness publication cannot prune time-expired obligations. |

SDK public-read and Deploy managed-bootstrap rules use separate owning `--sdk` and
`--deploy` unit-test families (`SUMERAGI_SDK_MUTATION`/`sumeragi_sdk_mutation` and
`SUMERAGI_DEPLOY_MUTATION`/`sumeragi_deploy_mutation`). Their `mutation-testing`
features are rejected in every non-test library; neither forwards a selector to SDK,
Core or another dependency. Both use the test profile, the original 1200/900/3600-second
per-step deadlines, a positive baseline, exact discovery/terminal accounting and strict
named-test kills. The baseline retains both new SDK controls and all six Deploy source
controls, including advanced-checkpoint/reopen and real private signing/staging positives.
The public transport tests establish bounded request/media policy;
Deploy source tests use actual executed canonical G1/H2. These rules do not establish
whole-network bootstrap, complete nested verifier allocation or durable validator relay.

| Mutation | Fault | Named deterministic test | Rule exercised |
|---|---|---|---|
| SDK1 | Accept missing or foreign response media for a canonical public source read | `public_norito_reads_refuse_missing_foreign_media_and_elapsed_requests` | Fixed credential-free Norito reads refuse foreign/missing media while retaining URL, deadline, status and byte-limit precedence. Media selection grants no source authority. |
| DEP1 | Reconstruct missing published G1/H2 custody over HTTP | `managed_amx_sources_refuse_partial_removed_and_substituted_custody_without_http_repair` | A visible private generation reopens only its original complete pair; removal/partial/substituted custody is terminal and never triggers replacement reads or signing. |
| DEP2 | Accept identical bytes from a substituted file inode | `managed_amx_sources_bind_original_file_identity_and_exact_capsule_inventory` | The original retained descriptors, private directory and exact three-file capsule remain binding before and after every source read. Content equality cannot substitute for original physical custody. |
| DEP3 | Admit retained sources after authentication crosses original release expiry | `managed_amx_sources_recheck_release_after_retained_authentication_without_refetch` | Reopen rechecks the exact selected parent's original live release/deadline after authentication, without HTTP repair or replacement. |
| DEP4 | Publish a fresh pair after acquisition crosses original release expiry | `managed_amx_sources_refuse_wrong_parent_height_and_expired_reads_before_publication` | Genuine source acquisition/authentication must finish under the original selected release and deadline before atomic publication; a late refusal cannot leave a newly admitted capsule. |
| DEP5 | Omit original local snapshot comparison when reopening G1/H2 | `managed_amx_sources_reopen_refuses_identical_g1_h2_replacement_without_http_repair` | A complete capsule records its native directory identity and source file snapshots (host kind, volume/object, extent, change/modified timestamps and custody metadata) before create-only publication. Reopen compares the actual originals with that unchanged private record without HTTP repair or a fresh deadline. These local values stay out of signed genesis; they are consistency evidence under native filesystem/clock and private-directory trust, not cryptographic authority, non-reusable identifiers, or defense against same-owner rewriting of all anchors. |
| DEP6 | Accept a substituted original child or administrative signer | `original_amx_administrator_child_fees_time_and_checkpoint_survive_reopen_and_refuse_substitution` | The explicit administrative action binds the retained child, selected parent, public signer, original fees/UTC interval and authenticated pre-dispatch checkpoint before signing. Recovery uses the same transaction and certified carrier; neither SNS ownership nor a later permission grant replaces the original operation. Native CanSetParameters admission remains mandatory. |
| DEP7 | Reconstruct completed authenticated genesis metadata during retained signed-profile validation | `localnet::private_root::tests::private_root_preparation_executes_signed_genesis_and_retains_owner_on_reopen` | Every private caller lends the Copy scalar from canonical authentication of the same original block. Profile/output/network/account/material validation preserves its existing order and original error mapping. The genuine independently signed private-root control executes and reopens the retained generation, then validates that exact original profile under zero additional decoder quota. No cached result, replacement source or new authority graph substitutes for the original signed block. |

Torii canonical-outcome custody uses its own `--torii` unit-test family
(`SUMERAGI_TORII_MUTATION`, `sumeragi_torii_mutation`). Its empty test-only
`mutation-testing` feature is rejected in every non-test library and never forwarded
to Core or another dependency. The test-profile baseline and mutant retain the
original 1200/900/3600-second deadlines, exact discovered terminal accounting and
strict named-control failures; an incidental substring-selected failure is not a kill.
The cached original entry remains unchanged on refusal. Cache-only local rejection,
expiry and pending hints do not manufacture a committed outcome.

| Mutation | Fault | Named deterministic test | Rule exercised |
|---|---|---|---|
| TOR1 | Accept cached block outcomes without their original canonical transaction binding | `tests_runtime_handlers::pipeline_status_cached_applied_refuses_removed_original_membership`, `tests_runtime_handlers::prepared_submit_outcome_cached_applied_refuses_removed_original_membership` | Both actual status and prepared-submit adapters authenticate genuine Applied first, then refuse the same retained cached outcome after its original State membership is removed. Applied and Committed require binding even without height metadata; block-associated Rejected/Expired also require binding. Local no-height rejection/expiry and pending hints remain available. The mutant bypasses only this absent-canonical guard, preserving State-present authentication and the original wire/cache. This local control is not whole-network finality qualification. |
| TOR2 | Refresh pending blocks from the execution pool before original query admission | `tests_runtime_handlers::pipeline_status_pending_refresh_retains_original_query_refusal_and_pending_source` | The actual status caller must retain its admitted query pool and typed Capacity refusal, original pending kind/hash/observation/deferral, exact native carrier and cumulative decoder owner. Only a successfully authenticated exact target may retire its matching pending block after canonical recheck; it projects the same immutable carrier without another read or unrelated pending drain. The mutant restores only the old pre-admission bulk refresh, so execution capacity cannot populate the cache before the original query refusal. Block-event processing remains separate; this local control does not establish whole-network timing or finality qualification. |
| TOR3 | Retire original finite-finality query credit before the unpolled HTTP stop control | `finality_interval::tests::failed_and_timed_out_workers_keep_original_credit_until_unpolled_stop_control_retires` | Both actual missing-height refusal and original expired-deadline 408 retain the exact original query-memory owner while the physical worker and its CPU/TLS admission have already retired. A test-owned completion wake observes the actual JoinHandle without repolling the HTTP future; the charged stop flag remains live before result observation, and all credit/control storage refunds after it. The mutant omits only the same-owner stop-guard field and clone. No replacement pool, second reservation or deadline extension is used; native baseline and causal kill remain required. |
| TOR4 | Discard the original push replay carrier attempt on a late allocation refusal | `push::tests::push_replay_late_capacity_retains_original_frame_and_waits_for_external_release`, `push::tests::push_replay_verification_slot_capacity_preserves_original_wait_and_resumes` | Push replay retains its current native frame, shared shell, prefix and verification result slots under the original pool while the same target waits. Controls separately refuse the shell, prefix, committed frame and result destinations. The exact Capacity release remains pending while unrelated capacity is held; releasing that blocker permits the same target to finish without moving its cursor early, and retiring the attempt refunds its retained storage. The mutant drops only the retained attempt on Deferred and preserves the original refusal, reproducing the self-release wake. Deeper nested decoder custody and whole-node qualification remain separate requirements. |
| TOR5 | Treat ordinary genesis-only Push bootstrap as fatal before its certified successor exists | `push::tests::push_worker_genesis_bootstrap_waits_for_authenticated_successor_and_shutdown`, `push::tests::push_worker_genesis_bootstrap_rejects_corrupt_history_and_nonzero_cursor` | An applied genesis-only chain with an origin cursor waits for real State publication of H2 and remains responsive to shutdown. The wait grants no execution authority, dispatches no queued notification and publishes no cursor. Fresh and restored State then pass the unchanged native history verification before effects; corrupt history and nonzero or malformed bootstrap cursors remain rejected. The mutant skips only this bootstrap wait and restores the old native read before H2, causing the critical worker to exit. This component control does not qualify whole-node restart. |

Norito canonical decode-origin rules use the owning `--norito` libtest family
(`SUMERAGI_NORITO_MUTATION`, `sumeragi_norito_mutation`). Its empty test-only
`mutation-testing` feature is refused in non-test libraries and dependencies.
Baseline and mutant use the test profile, the existing 1200/900/3600-second
step deadlines and the same exact discovered-terminal accounting. No dependency
cfg, replacement pool, counter reset or reconstructed error supplies provenance.

| Mutation | Fault | Named deterministic test | Rule exercised |
|---|---|---|---|
| NC1 | Omit original active-counter family capture for direct JSON operations | `core::decode_attempt::tests::direct_json_refusal_keeps_original_context_and_retry` | The canonical direct parser and checked writer retain their genuine enclosing refusal and same-source retry under the original owned context. Malformed JSON remains Invalid and all original pool credit refunds. |
| NC2 | Accept a saved refusal without its observer root and boundary | `core::decode_attempt::tests::direct_attempt_replay_under_same_counter_owner_is_invalid`, `core::decode_attempt::tests::direct_attempt_cross_thread_replay_with_original_shared_context_is_invalid`, `core::decode_attempt::tests::direct_nested_attempts_preserve_parent_origin_and_refuse_old_sibling`, `core::decode_attempt::tests::already_active_direct_attempt_rejects_later_foreign_thread_root` | Same-context later attempts, old siblings and independent thread roots cannot inherit saved provenance even after a genuine fresh local refusal is swallowed. The receiver-first cross-thread control separately requires root identity when the foreign boundary ordinal is newer. Immediate child propagation remains valid; counters and original physical owner are unchanged. |
| NC3 | Wrap the exhausted process-wide observer identity sequence | `core::decode_attempt::tests::observer_boundary_sequence_exhaustion_never_wraps` | The original scalar owner emits its final distinct identity once, then refuses every later mint without changing or wrapping the exhausted counter. No allocation or replacement counter is introduced. |
| NC4 | Discard original unscoped JSON decoder resource fields | `json::tests::core_resource_errors_roundtrip_exact_fields_without_fresh_scope`, `json::tests::direct_json_parser_retains_unscoped_fields_and_same_input_retry` | Every recorded resource field survives binary/JSON conversion and direct parser refusal. Copying fields never creates observer provenance; same-input retry and original pool refunds remain required. |
| NC5 | Convert malformed core input to a JSON allocator refusal | `json::tests::non_resource_core_errors_cannot_become_json_allocator_refusals` | Invalid magic and length mismatch retain terminal diagnostics and remain Invalid, never becoming retryable allocation pressure. |

The consensus signing-suite integration additionally owns this Core mutation:

| Mutation | Fault | Named deterministic test | Rule exercised |
|---|---|---|---|
| SC4 | Restore generic w3f signing in the production consensus signer | `sumeragi::crypto::tests::consensus_signature_matches_dst_sig_fixture`, `sumeragi::crypto::tests::production_consensus_suite_refuses_generic_and_nonallowlisted_signatures` | The actual signer must match the dedicated `DST_SIG` signature of the original allowlisted Commit preimage. Generic signatures fail both single and aggregate consensus verification; consensus signatures fail the generic verifier. Kind `0x06`, truncated and unscoped preimages cannot sign or enter any aggregate group. This implements planned SCCP case SC4 without changing any protocol preimage layout. |

The Core rules above are replay and committee-retention prerequisites. They do not qualify production lane
offence admission, original-stake monetary dispatch or the complete H3 allocation graph.

**SCCP and certified-time application rules** (`specs/sccp.md` §4.3–§4.10,
§11.6; Core gate `--core`). SC1–SC25 retain their original rule labels;
the exact source controls below use the active HC IDs, except the dedicated
SC4 signing-suite control. Every fault has a registered hook and named test.
These entries use real crypto and cannot change a consensus signing-preimage
layout (§1 item 6). Source coverage is distinct from qualification: the current
baseline and each declared causal failure must pass with `--strict`; compiler
errors and resource failures never count as mutation kills. Cross-owner
Parliament eligibility, due scheduling and casting-open authority remain
external inputs, not synthetic fixture success.

| Rule and active controls | Core fault | Named deterministic tests | Oracle |
|---|---|---|---|
| SC1 (HC308) | Ordinary result hashing omits the original finality header | `published_execution_result_binds_the_original_header_and_body_digest` | Raw SHA-256 binds original X and the original tagged body digest |
| SC2 (HC226, HC325) | The header's `committee_root` is taken from `C_{h+1}` at a boundary | `native_heartbeat_certificate_keeps_outgoing_generation_then_uses_successor`, `key_change_before_heartbeat_requires_rotation_at_the_original_boundary` | A boundary header names the outgoing committee |
| SC3 (HC309) | `ROTATION` is not set at a key change | `key_change_before_heartbeat_requires_rotation_at_the_original_boundary` | A key change names the successor root and validity |
| SC4 (implemented) | `KeyPairSigner` signs through the generic (w3f) API | `consensus_signature_matches_dst_sig_fixture`, `production_consensus_suite_refuses_generic_and_nonallowlisted_signatures` | Consensus signatures match the dedicated `DST_SIG` suite and generic/unscoped signatures are refused (§1 item 6) |
| SC5 (HC257) | CT1 disabled | `prepare_withheld_while_block_time_ahead` | Full State execution defers beyond the committed allowance; routing-lane effective time and pinned allowance are covered by HC268 (§4.5) |
| SC6 (HC259, HC260, HC264) | CT3 builder pacing disabled | `proposer_clock_selection_retains_future_signed_inputs_until_the_exact_time`, `lane_proposer_clock_selection_preserves_future_inputs_and_resumes_after_advance`, `proposer_clock_retains_final_input_and_canonical_output_until_due`, `proposer_clock_retains_certified_lane_floor_and_completed_original`, `future_only_lane_work_retries_without_an_empty_answer_or_new_traffic` | The leader never proposes a block timed ahead of its clock |
| SC7 (HC312) | The keepalive due predicate ignores the heartbeat time | `heartbeat_due_rejects_early_progress_and_includes_the_exact_deadline` | A keepalive before the heartbeat is refused |
| SC8 (HC313) | The keepalive due predicate ignores governance work | `governance_due_keeps_the_original_fast_pause_leg_when_heartbeat_is_disabled` | The original parent fast-pause conclusion remains due even with heartbeat disabled; the Parliament producer remains external |
| SC9 (HC277) | Keepalive quota K1 disabled | `keepalive_k1_counts_carriers_independently_of_outcomes` | A block with two keepalives is `Invalid` |
| SC10 (HC310) | Missing SCCP inputs return `Invalid` | `degraded_block_without_leaves_keeps_history_and_records_failure` | Missing inputs give an inactive header, never `Invalid` |
| SC11 (HC311) | The heartbeat trigger `BEAT` disabled | `native_heartbeat_certificate_keeps_outgoing_generation_then_uses_successor` | An idle chain creates a heartbeat generation |
| SC12 (HC281, HC334, HC337) | CT5 disabled | `keepalive_ct5_stale_due_work_is_a_local_refusal`, `sccp_ct5_completion_resamples_clock_and_retains_original_for_certified_retry`, `sccp_ct5_prepare_signing_resamples_original_after_valid_and_binds_every_coordinate` | No Prepare vote on a stale uncertified due-work block |
| SC13 (HC315) | Forgery rule E4 ignores `D_body` | `signed_body_digest_only_forgery_is_e4_against_original_anchor` | A genuine header with a forged body digest is evidence |
| SC14 (HC316) | Forgery rule E0 ignores `liable(g)` | `generation_lookup_and_inclusive_liability_use_captured_values_only` | Evidence outside the liability window is refused |
| SC15 (HC320, HC321) | An unbond is finalized while its stake is liable or a forgery record is pending | `sccp_liable_unbond_keeps_exact_pending_request_and_both_balances`, `pending_exact_offence_survives_liability_expiry_and_only_applied_releases_it` | Stake stays in custody while slashable |
| SC16 (HC314) | Keepalive rule K2 disabled | `keepalive_admission_requires_established_due_work_before_assigning_exemption` | Unavailable or absent due work grants no Keepalive exemption |
| SC17 (HC258, HC282) | The executor ignores `Execute.certified` | `certified_execution_flag_reaches_the_application_without_inference`, `keepalive_ct5_certified_execution_ignores_the_local_wall_clock` | Actual certified execution preserves the deterministic result while skipping CT1 and CT5 local wall-clock refusal |
| SC18 (HC317) | Forgery rule E3 compares against Iroha's `state.block_hashes` | `genuine_native_certificate_uses_core_anchor_instead_of_outer_block_hash` | A genuine certificate is never evidence |
| SC19 (HC229) | The liability clock follows block time without the step cap | `begin_block_clamps_halt_time_using_original_native_parent` | A halt followed by a time jump consumes no liability window |
| SC20 (HC322) | The destination-progress gate L5 is ignored | `current_generation_and_parent_clearance_cannot_be_shortened_by_block_writes` | A generation stays liable until destinations progress past its deadline |
| SC21 (HC318, HC319) | The SCCP penalty uses the certificate height as the offence height, or resolves offenders by peer key | `sccp_penalty_uses_captured_tuple_start_and_record_delay_without_generation_or_peer_map`, `sccp_penalty_ignores_late_peer_mapping_and_keeps_original_g6_custody` | Offenders are the recorded registrations at the generation start |
| SC22 (HC278) | The SCCP due predicate ignores the degraded run | `keepalive_k2_uses_parent_heartbeat_and_degraded_run` | A persistent defect produces at most two keepalive blocks |
| SC23 (HC227, HC324) | The resync rule G7 disabled | `resync_uses_real_native_parent_time_then_boundary_rotates_again` | A missed committee change creates a resync generation using the actual native parent time |
| SC24 (HC292, HC293) | Pruning ignores pending forgery records | `pruning_keeps_pending_exact_generation_until_penalty_is_applied`, `pruning_anchor_boundary_uses_minimum_retained_start_and_is_strict` | A generation named by a pending record is retained |
| SC25 (HC323) | The forgery hold ignores the revision's `forgery_floor` | `forgery_floor_is_inclusive_and_u64_max_is_not_a_release_sentinel` | Evidence for a passed generation holds no revision |

The continuation implements these additional SCCP source hooks and exact causal
controls. Registry membership is distinct from a passing mutation report; current
candidate results are recorded by `scripts/sumeragi_mutation_gate.py`.

| Id | Changed rule | Named deterministic control | Oracle |
|---|---|---|---|
| MS67 | A durable Prepare reservation grants a certified clock exemption | `machine::tests::signing::det_prepare_context_restart_reservation_alone_is_uncertified` | Only original certified protocol state may grant the exemption after restart |
| MS68 | An honest clock-enabled builder publishes before its canonical time floor | `sim::world::clock_guard::tests::clock_guard_committed_parent_wait_retains_work_until_clock_recovery` | Original work remains queued until both the committed parent cadence and transaction creation floors are admissible |
| MS69 | An honest clock-enabled builder skips the completed-payload clock recheck | `sim::world::clock_guard::tests::clock_guard_completed_payload_waits_after_build_latency_backstep` | The original completed payload remains retained after a build-latency clock backstep until its canonical time is admissible |
| MS70 | An honest clock-enabled builder skips the final fresh-proposal clock recheck | `sim::world::clock_guard::tests::clock_guard_fresh_proposal_waits_after_authored_queue_backstep` | The original authored proposal waits after a queue-time clock backstep before Core may sign or publish it |
| HC276 | EVM registration omits the locked CREATE2 address binding | `evm_address_binds_original_identity_network_pin_revision_and_cap` | The destination binds the original identity, network, pin, revision and cap |
| HC277 | A block accepts a second Keepalive carrier | `keepalive_k1_counts_carriers_independently_of_outcomes` | K1 counts every carrier independently of its execution outcome |
| HC278 | Heartbeat continues after two degraded parent heights | `keepalive_k2_uses_parent_heartbeat_and_degraded_run` | K2 reads the original parent and stops repeated degradation |
| HC279 | Keepalive ignores standalone Ed25519 and empty fee intent | `keepalive_k3_k5_require_standalone_ed25519_due_time_and_empty_fee` | K3 and K5 require the exact signed shape and due time |
| HC280 | The builder retains a Keepalive older than half the agreed lag | `keepalive_k4_refreshes_after_half_lag_and_preserves_boundary` | K4 preserves the equality boundary and replaces older carriers |
| HC281 | CT5 accepts stale uncertified due work | `keepalive_ct5_stale_due_work_is_a_local_refusal` | Staleness defers the local attempt without declaring the block invalid |
| HC282 | CT5 applies local wall-clock refusal to certified execution | `keepalive_ct5_certified_execution_ignores_the_local_wall_clock` | Genuine certified execution retains its exemption |
| HC283 | Native registration omits the retained forgery generation floor | `native_forgery_publication_requires_a_strictly_newer_pin` | A new pin must be strictly newer than every retained forged generation |
| HC284 | Proposer permission bypasses the Parliament ballot gate | `sccp_route_governance_proposal_requires_permission_or_bond` | Permission cannot create interim ballot authority |
| HC285 | Deployment attestation lowers the retained forgery floor | `native_offence_release_and_later_attestation_never_lower_the_floor` | Attestation and offence release preserve the monotone floor |
| HC286 | Replays replace a quarantine's original permanent cause | `quarantine_retains_its_original_cause_across_replays_and_progress` | Quarantine retains its first cause across later progress |
| HC287 | Forged-mint evidence omits authenticated payload binding | `forged_mint_requires_exact_registered_event_and_payload_binding` | Another payload's id cannot increase forged supply |
| HC288 | A quarantined revision retires before reconciliation completes | `quarantined_retirement_requires_the_single_completed_reconciliation_window` | Retirement waits for the single completed reconciliation window |
| HC289 | Reconciliation claims spend backing reserved for refunds | `reconciliation_reserves_refunds_and_later_claims_exhaust_only_priced_backing` | Priced claims preserve pending refund backing |
| HC290 | A refused reconciled credit advances settled face | `reconciliation_pending_credit_retry_recomputes_rounding_without_spending_face` | Refusal spends no face and retry recomputes rounding against current backing |
| HC292 | Generation pruning drops a pending penalty's generation | `pruning_keeps_pending_exact_generation_until_penalty_is_applied` | Exact pending attribution retains its original generation |
| HC293 | Anchor pruning erases the retained boundary | `pruning_anchor_boundary_uses_minimum_retained_start_and_is_strict` | Only chunks strictly below the minimum retained start may be pruned |
| HC295 | Reserve seats replace originals early | `sccp_pause_seats_replace_only_unaccepted_in_primary_then_backup_order_at_deadline` | No replacement before the exact acceptance deadline; eligible reserves remain disjoint |
| HC296 | Revoked endorsements count toward quorum | `sccp_pause_certification_rechecks_revoked_members_and_exact_close_after_halt` | Current eligible seat holders alone satisfy quorum |
| HC297 | An expired endorsement window certifies | `sccp_pause_certification_rechecks_revoked_members_and_exact_close_after_halt` | Equality at the closing time is expired even after a halt |
| HC298 | Lift ignores original casting-open position | `sccp_pause_lift_compares_original_height_position_and_removes_only_the_matching_part` | Resume can clear only a strictly earlier pause and its matching part |
| HC299 | Suspension clears an active pause | `sccp_pause_suspension_never_clears_active_parts_and_zero_removes_only_suspension` | Suspension changes only the suspension deadline |
| HC300 | A consumed direct instruction is rearmed | `pause_direct_source_binds_each_signed_slot_and_cannot_be_rearmed_or_substituted` | Each exact signed slot is consumed once; callbacks and substitution grant no authority |
| HC301 | Fast-pause controls ignore occupied block leaves | `sccp_pause_controls_preflight_capacity_nonce_and_every_live_part_before_effects` | Every live destination part fits before the first hold, nonce or leaf write |
| HC302 | Keepalive reads the new overlay's pause work | `keepalive_pause_conclusion_stays_due_through_expiry_and_reads_original_parent` | Admission retains the original parent's due-work observation |
| HC303 | G0 requires the later committee boundary instead of the pulse carrier | `sccp_panel_draw_reads_the_original_pulse_at_its_actual_carrying_height` | A genuine verified pulse is available at its original pre-boundary carrying height |
| HC304 | Genesis accepts a budget that only recertifies pauses | `sccp_executed_genesis_rejects_work_budgets_that_starve_pause_enactment` | At least six conclusions and one enactment fit in the committed budget |

| HC305 | Genesis accepts an unbound committee signer | `sccp_genesis_requires_every_original_signer_to_have_one_staking_binding` | Missing original global stake refuses before parameters, generation or events |
| HC306 | Bundled admission skips a signed advance's state expectation | `signed_bundle_uses_original_overlay_and_checks_each_advance_cas` | Every advance binds its original overlay state before effects |
| HC307 | Local allocation refusal becomes protocol rejection | `exhausted_bundle_admission_preserves_original_deferral_and_retry` | The original deferred attempt remains retryable after custody is released |
| HC308 | SC1 SCCP result: omit the original fixed header from ordinary voting | `sumeragi::executor::publication_tests::published_execution_result_binds_the_original_header_and_body_digest` | Exact original-source assertion; current strict baseline and named causal kill required |
| HC309 | SC3 SCCP key change: omit native boundary rotation | `smartcontracts::isi::sccp::generations::tests::key_change_before_heartbeat_requires_rotation_at_the_original_boundary` | Exact original-source assertion; current strict baseline and named causal kill required |
| HC310 | SC10 SCCP unavailable inputs: invalidate ordinary execution instead of degrading | `smartcontracts::isi::sccp::hook::tests::degraded_block_without_leaves_keeps_history_and_records_failure` | Exact original-source assertion; current strict baseline and named causal kill required |
| HC311 | SC11 SCCP unchanged committee: disable due heartbeat rotation | `smartcontracts::isi::sccp::hook::tests::native_heartbeat_certificate_keeps_outgoing_generation_then_uses_successor` | Exact original-source assertion; current strict baseline and named causal kill required |
| HC312 | SC7 SCCP heartbeat: ignore the original due timestamp | `smartcontracts::isi::sccp::keepalive::tests::heartbeat_due_rejects_early_progress_and_includes_the_exact_deadline` | Exact original-source assertion; current strict baseline and named causal kill required |
| HC313 | SC8 SCCP due work: omit the original fast-pause conclusion leg | `smartcontracts::isi::sccp::keepalive::tests::governance_due_keeps_the_original_fast_pause_leg_when_heartbeat_is_disabled` | Exact original-source assertion; current strict baseline and named causal kill required |
| HC314 | SC16 SCCP Keepalive: admit a carrier without established due work | `smartcontracts::isi::sccp::keepalive::tests::keepalive_admission_requires_established_due_work_before_assigning_exemption` | Exact original-source assertion; current strict baseline and named causal kill required |
| HC315 | SC13 SCCP forgery: ignore the signed result-body digest | `smartcontracts::isi::sccp::forgery::tests::signed_body_digest_only_forgery_is_e4_against_original_anchor` | Exact original-source assertion; current strict baseline and named causal kill required |
| HC316 | SC14 SCCP forgery: accept evidence outside original generation liability | `smartcontracts::isi::sccp::forgery::tests::generation_lookup_and_inclusive_liability_use_captured_values_only` | Exact original-source assertion; current strict baseline and named causal kill required |
| HC317 | SC18 SCCP forgery: replace original core anchor with outer Iroha block hash | `smartcontracts::isi::sccp::forgery::tests::genuine_native_certificate_uses_core_anchor_instead_of_outer_block_hash` | A genuine native certificate remains not evidence under the original core anchor |
| HC318 | SC21 SCCP penalty: use attacker-selected certificate height for liability | `sumeragi::penalties::tests::sccp_penalty_uses_captured_tuple_start_and_record_delay_without_generation_or_peer_map` | Exact original-source assertion; current strict baseline and named causal kill required |
| HC319 | SC21 SCCP penalty: replace captured registration with current peer-key mapping | `sumeragi::penalties::tests::sccp_penalty_ignores_late_peer_mapping_and_keeps_original_g6_custody` | Exact original-source assertion; current strict baseline and named causal kill required |
| HC320 | SC15 SCCP unbond: omit the original generation liability barrier | `smartcontracts::isi::staking::tests::sccp_liable_unbond_keeps_exact_pending_request_and_both_balances` | Exact original-source assertion; current strict baseline and named causal kill required |
| HC321 | SC15 SCCP unbond: omit the exact pending offence barrier | `smartcontracts::isi::sccp::liability::tests::pending_exact_offence_survives_liability_expiry_and_only_applied_releases_it` | Exact original-source assertion; current strict baseline and named causal kill required |
| HC322 | SC20 SCCP liability: omit original destination-progress clearance | `smartcontracts::isi::sccp::liability::tests::current_generation_and_parent_clearance_cannot_be_shortened_by_block_writes` | Exact original-source assertion; current strict baseline and named causal kill required |
| HC323 | SC25 SCCP holds: ignore the retained maximum forgery generation | `smartcontracts::isi::sccp::hold::forgery_tests::forgery_floor_is_inclusive_and_u64_max_is_not_a_release_sentinel` | Exact original-source assertion; current strict baseline and named causal kill required |
| HC324 | SC23 SCCP generation: disable missed-boundary resynchronization | `smartcontracts::isi::sccp::generations::tests::resync_uses_real_native_parent_time_then_boundary_rotates_again` | Exact original-source assertion; current strict baseline and named causal kill required |
| HC325 | SC2 SCCP rotation: substitute the successor for the outgoing committee root | `smartcontracts::isi::sccp::generations::tests::key_change_before_heartbeat_requires_rotation_at_the_original_boundary` | Exact original-source assertion; current strict baseline and named causal kill required |
| HC326 | SCCP TON registration accepts caller-substituted contract code | `smartcontracts::isi::sccp::governance::registration::tests::ton_deployment_refuses_substituted_code_at_its_matching_state_init_address` | All minter, wallet and bucket code hashes and depths must match the compiled artifact lock even when the supplied address matches the substituted StateInit |

| HC343 | Private-root scope omits canonical role deletion | `sumeragi::amx::native::tests::paid_borrowed_custody::read_roles::native_private_read_role_removal_preserves_debit_and_survives_certified_restart` | Genuine paid management deletes the dedicated read role; debit consent and another root remain intact through certified restart |

These consumer and source-binding controls do not qualify missing Parliament
eligibility, draw, shared-pass or Policy Jury opening producers. No component
fixture supplies production authority for those external interfaces.

Also required: golden vectors for every preimage (including `echo_preimage`, §3.3), `block_hash`, `att_digest`, `committee_digest`,
the permutation, `D_h`, slot substitution (order and leaders for `|D| ∈ {0, 1, f}`, with demoted
slots at the anchor, between views and adjacent to each other) at views 0, 1, 2, and the stage
hint; TC
verification vectors; Norito round-trips of every wire and record type; fuzzing of the decoder and
of `handle` with arbitrary events (no panic, O-MEM holds).

### 13.5 Driver conformance and soak (the runtime, not only the reducer)

- The production driver in `iroha_core` is generic over `Net`, `RecordStore`, `BodyStore`,
  `BlockStore`, `Clock` and `Executor` traits, so the **same driver code** runs in the simulator with
  fake backends (F9, F13, F14, F27, F29, F32 at minimum).
- Conformance oracles on the real driver: O2 (kill the process image at every I/O completion and
  check that nothing externally visible preceded durability), O3 (commit and `BlockApplied` order;
  the applied header in every `BlockApplied`, and its `block_hash` equal to that of the height's
  `CommitBlock` block — the core halts with `DriverAnomaly` otherwise, §6.13, checked with a
  driver fault that reports another block of the same height; `ApplyDiverged` on a forced mismatch, and none when
  the cached post-state was evicted before `CommitBlock`; one execution, not two, when
  `CommitBlock` arrives while that block's execution is in flight), O4 (every `Execute` answered exactly once, `Cancelled` included;
  an `Execute` whose certified parent post-state was evicted is answered with the correct `Valid`,
  never `Failed`), O5/O8 (Tick lateness and control-class latency under bulk and CPU floods), O9
  (a stalled DS instance does not delay global-instance events).
- **Host seam.** The simulator runs each replica's node program behind `sim::host::Host`: the
  ingress queues with the O5 priorities and the O6/O8 bounds and classes, the core, and the O1/O2
  persist-before-effect barrier. The world supplies everything else as fake backends: network,
  clocks, the write device and record store with the installation log, the body store, the block
  store with O3 apply, the O4 executor, the payload builder and the `Init` a restart assembles from
  the durable stores. The default host is the fake driver (`sim::host::FakeHost`); Byzantine
  machines always run it. A host may also *own its driver scheduling* (`Host::owns_io`): the
  world then performs only its device operations (`sim::host::Op`) — writes that may fail (the
  host retries), executions on the post-state cache, the three apply steps (prepare the
  certified post-state, durably append to the block store, commit), builds, network effects and
  serving — and reports their completions (`sim::host::Done`); the core's actions are observed
  by the oracles but not interpreted. The production driver's kernel
  (`iroha_core::sumeragi::driver::Kernel`: ingress, core, O2 barrier, ordered persistence with
  retries, execution/apply/build scheduling) runs every honest replica this way (scenario field
  `host`), in F9, F13, F14, F27, F29 and F32 and in the O2 run that kills a replica at each
  of its write completions (scenario field `io_kill`), under every oracle and an O4 answer check.
  The world holds the host's prepared post-state as a single live overlay: any other executor
  operation between a prepare and its commit drops it, and a commit without it fails the run.
  A replica whose disk fails every write for 20 s runs under the O-MEM bounds of its queues.
  Its proposal/manifest/row messages use the canonical wire owner (§12.8) under the world's
  network faults. Actual author/acquisition jobs issue opaque bodies; receiving metadata alone
  cannot substitute for reconstruction. Component conformance must keep this same custody path.
  O3 in-flight reuse, O4 exactly-once answers and parking are also tested on the kernel's
  scheduler with the fake executor, and O9 with two threaded driver instances in one process.
  `Init` assembly and serving stay with the world in the simulator; the driver's versions are
  tested over in-memory backends.
- Deployment policy is owned by on-chain governance for Taira and production. Multi-process
  fault runs, including loss/delay, crashes, restarts and disk exhaustion, are optional
  engineering diagnostics, as are full regression suites; their duration, topology and verdict
  do not authorize or block a cutover. There is no mandatory 24-hour fault test for any network,
  and elapsed off-chain runtime or a missing soak verdict is not a Sumeragi protocol or
  node-admission rule.
  Operators still enforce signed native control authority, authenticated genesis and committee,
  safety-record provenance and custody, and report actual service readiness. Write, restart,
  pulse-crossing and epoch-boundary exercises are optional diagnostics, never signing or
  deployment prerequisites. Optional diagnostics compute O-AGR, O-SIGN, O-LIVE and O-PERF
  from node logs.

---

## 14. Out of scope for the core (tracked as goals) and future optimisations

1. Node integration: driver in `iroha_core` wiring P2P (routing by instance id, traffic classes),
   Kura (blocks + CommitQCs), body store, State (speculative execution chained on certified
   parents, apply, height-config schedule, `R` definition), Queue (payload builder, `PayloadReady`,
   quarantine), safety-record files per key, status endpoint, config surface, §13.5 conformance.
2. Deleting the v2 runtime, its specs, formal models, configs and tests; no "v2" naming remains.
3. Qualifying dataspace/lane hosting: independent signed roots in separate daemons and several
   lane cores per node, with exact instance identities, committees and O9 isolation.
4. AMX 2PC (§11): the global chain's side (Begin, relay, decision by the deadline, trackers with
   handoffs), native participant escrow and complete archived write sets run in each root's
   executor. Production bootstrap assembly, complete outbound proof custody, durable validator
   relaying and whole-network qualification remain (Appendix E, E58).
5. Taira reset: fresh genesis with the new parameters and an operator runbook: key generation
   on the node, the installation log, store id and initial records (§7.4 record provenance), the
   per-instance "never signed" assertion for imported keys at genesis, backups that exclude record
   files and the store id (a restored key store makes its keys imported), retired records kept for
   good, and single-height key rotation (§10.3).
6. Evidence → penalties; NPoS election and epoch scheduling of committees; forensics for
   conflicting certificates (cross-view, and same-view ones at an uncommitted height).
7. Payload dissemination beyond §12.8: the current candidate sends all original rows to its
   requested peers. Holder forwarding, per-committee-size parity tuning and relay ordering
   remain possible optimisations; none is claimed implemented or measured here.
8. Weak-subjectivity checkpoints for long-range sync.
9. Push delivery of committed blocks to observers (RPC/indexer nodes) by subscription; `Status`
   pull stays the backstop.
10. Governance-certified committee handover for an instance that lost its quorum (§10.8).
11. **Future optimisations** removed from the first release by the revision-3 simplicity pass
    (Appendix B). None is needed for safety or for P1–P6; each may come back only with its own
    mutation test and independent qualification:
    a. optimistic (batch) vote verification at the aggregator;
    b. re-chaining of silent set-A members and proxy tails (absence records in headers, with
       attribution to `f + 1` distinct proxy tails), which would remove the recurring P3 cost of a
       silent proxy tail (§8.2);
    c. several outstanding `SyncRequest`s for consecutive ranges (faster catch-up when the
       round trip, not apply, dominates).

---

## 15. Open questions

1. **Boundary application latency.** Ordinary parameters retain lag two. Authority changes use
   the applied certified boundary (§10); qualify the resulting boundary latency on real networks.
2. **Crashed-leader cost and durable availability.** `payload_retry_interval` is 5 s and never
   creates a block. Queue-independent view-0 grace still costs 7.2 s at the defaults before
   replacing a crashed leader. Durable bodies are retained through their height's apply;
   reclaiming earlier under prolonged uncommitted view churn needs a reviewed availability
   proof, because a withheld PrepareQC can later require an older body.
3. **Predictable schedule.** Leaders and proxy tails are a round-robin over a per-committee
   permutation, so they are known ahead of time. This removes seed grinding and gives slot
   fairness (§2.1), but lets an attacker aim a DoS at upcoming leaders; the cost of that is bounded by
   view change and demotion. An unpredictable alternative (seed = unique BLS signature of the
   previous leader, carried in the header) is possible. Accept predictability?
4. **Demotion parameters.** Only leaders of failed views are demoted, for `W = 128` heights,
   `|D| ≤ f`, with slot substitution. Silent set-A members and proxy tails are not demoted (their
   cost is in §8.2 P2/P3). Confirm.
5. **Block time semantics.** Timestamps are application payload; the core never checks clocks.
   The application defines time monotonicity without local-clock comparisons, and bounds
   certified time through the liveness-only Prepare-vote guard of §4.5, which never makes a
   verdict depend on a local clock. Qualifying that guard on real networks (clock skew,
   re-proposals after long hidden PrepareQCs) remains open.
6. **Divergence recovery.** `ApplyDiverged` halts the instance; recovery needs a state-snapshot
   path (not in scope here).
7. **Payload size and layout.** The current worker sends each canonical row to its requested
   peers (§12.8). Measure complete egress, acquisition and verification before choosing any
   holder-forwarding strategy or larger-committee parity tuning. The recommended `d = 4, p = 2`
   describes erasure geometry; it alone is not a validator-fault bandwidth guarantee.
8. **Epoch length** of AMX-participating instances (handoff cadence for light clients, §11.7).

## 16. Keyed State commitment (application layer)

**Status: specified by ZK delivery plan task G.1, built by G.3; until then row E51 of Appendix E
is the as-built behaviour**, and nothing in this section is consensus behaviour. The section
defines what the single State-owned keyed commitment commits, what its witnesses establish, how
its roots enter `R` and who publishes them. It selects no tree, arity, hash or witness encoding:
G.2 measures candidates against this section and G.3 selects and builds one.

Machine-checked companions:

- `specs/state_table_inventory.json` lists every field of `State`, `World`, the trigger set and
  the canonical runtime with the roots it affects today, every commitment over State content
  that exists in the tree with its owner and disposition, and the open defects. It is generated
  from the authority registry and the source, and compared with both by
  `crates/iroha_core/src/state/state_table_inventory_tests.rs`. The same tests pin the as-built
  premises of §16.5 and §16.6 and the rule identifiers of this section.
- `crates/iroha_core/src/state/authority_registry/keyed_commitment.rs` is the typed interface
  (`KeyedStateCommitment`, `StateSchema`, `KeyRange`, `Witness`, `KeyedStateRoot`) with its
  conformance suite (`conformance::check_contract`) and a test-only reference oracle.
- `specs/state_commitment_candidates.json` is the G.2 comparison of four development-only
  candidate constructions, each passing the conformance suite: measured natively under five hash
  profiles and, for the three tree candidates under the Poseidon2 and Rescue-Prime sponge
  profiles, in-circuit with the uncommitted B.1 reference (no committed proof exists until B.2).
  It carries the benchmark identity, every number classified (measured, accounting model,
  projection), and the decision criteria proposed for G.3. It records no selection.
  `scripts/check_state_commitment_candidates.py` checks it against the prototype sources, which
  it binds by digest.

### 16.1 Committed object, canonical order and schema descriptor

The keyed State at one cut is a finite map `(table, key) ↦ value`.

- `table` is the registry identity of a canonical table or cell, for example `world.accounts`,
  `triggers.data`, `state.transactions.current` or `runtime.lanes`. Nested owners are flattened.
  The committed set is exactly the tables and cells that the exhaustive authority registry
  (`crates/iroha_core/src/state/authority_registry.rs`, `STATE_FIELDS`) declares canonical
  (`StateSchema::from_registry`). World and State-level fields are one schema.
- A **cell** is the single entry of its table at the empty key (K8).
- **Derived** fields are not entries. Each is rebuilt from its registered sources and checked by
  its registered procedure; the root binds it only through those sources. The inventory lists a
  derived field whose sources include an uncommitted or historical field with `unbound_bases`.
- **History** fields are authenticated by the header chain and the certified results (§16.7).
  **Local** fields are authenticated by nothing. Neither is an entry, and a local field never
  influences a root.

**Canonical order.** Tables are ordered by the ascending bytes of their identity. Entries are
ordered by table position, then by key bytes. This is the only order: of the schema descriptor,
of every range and of any layout derived from the root.

**Schema descriptor.** Every construction binds these bytes into its root (K1):

```text
"iroha:state-keyed-commitment:schema:v1\0" ‖ le32(count) ‖ for each table in canonical order:
    shape ‖ le32(len(id)) ‖ id ‖ le32(len(key codec)) ‖ key codec ‖ le32(len(value codec)) ‖ value codec
shape        = 0x00 table | 0x01 cell
codec        = "norito:<nominal name>@<major>.<minor>.<flags>"      declared Norito type
             | "semantic:<identity>@<major>.<minor>.<flags>"        registered semantic projection
key codec    = "" for a cell
```

The schema is part of the protocol: adding, removing, renaming or re-typing a canonical field
changes the descriptor and therefore every root. Under the first-release rules that is a coherent
replacement with a fresh genesis.

### 16.2 Key and value encodings

- **Key bytes** are the bare Norito payload of the declared key type under the fixed V1 layout
  (compact lengths; `norito::codec::encode_adaptive`), with no header and no added length prefix.
  The Rust type's nominal Norito identity must equal the registry's.
- **Value bytes** are the bare V1 Norito payload of the declared value type, or of the registered
  semantic projection for a semantic field (the projection excludes runtime caches; the registry
  names its encoder). Where a projection exists today only as a digest function (trigger actions,
  the executor), G.3 names the byte string that function hashes as the committed value.
- An empty value is **present** (K5). Absence is the lack of an entry.
- **Key order is byte order**, not the `Ord` of the Rust key. Norito integers are little-endian,
  so numeric order is not a byte range; a consumer that needs a numeric range proof needs a table
  whose declared key codec is order-preserving, which is a schema change.
- A tuple or record key encodes every component as `[len][payload]` (Norito's field framing).
  "Every key whose leading components are `c`" is therefore the byte interval
  `[p, prefix_upper_bound(p))`, where `p` is the exact leading bytes the key encoding emits for
  those components, framing included. The bare encoding of a component alone is not that prefix.
- A construction may commit a digest of the value bytes in its leaves. The statement a witness
  proves is still over the full value bytes, and the digest must bind the value codec identity and
  the byte length.

### 16.3 Statements and witnesses

A witness is an opaque canonical byte string carried by the consumer. Each kind establishes one
statement against one keyed State root:

| Kind | Statement |
|---|---|
| Inclusion | `root` commits `(table, key) ↦ value`. |
| Absence | `root` commits no entry at `(table, key)`. |
| Complete range | The ascending list `entries` is exactly every entry of `table` that `root` commits with `lower ≤ key < upper`. |

A range is a half-open interval of key bytes inside one table; `upper = None` is unbounded and
`[ε, None)` is the complete table. An interval with `upper ≤ lower` is ill-formed, and so is a
claimed entry outside the interval. An empty result is a valid statement.

Verification is a pure function of the schema, the root, the statement and the witness bytes. It
reads no State, cache, Kura, clock or node configuration. Its outcomes are acceptance and
deterministic rejection; it has no local-failure outcome. Proving and updating may fail locally
(`LocalFailure`); a local failure is never a verdict.

### 16.4 Rules every construction satisfies

`conformance::check_contract` checks each rule and reports the first violation. The reference
oracle passes, and each deliberately faulty variant of it, at least one per rule, is reported
under the rule it breaks.

| Rule | Requirement |
|---|---|
| K1 | **Schema binding.** The root binds the schema descriptor bytes: a different table set, shape or codec identity gives a different root, also for the empty State. |
| K2 | **Content function.** The root is a function of the schema and the committed entries alone, independent of the order, batching and history of updates. |
| K3 | **Binding.** Different contents have different roots, including contents that differ in one value, one table, one empty-valued entry or only in how the same bytes split into key and value. |
| K4 | **Inclusion.** A committed entry has a witness; verification accepts its exact value bytes and no other value, key or table. |
| K5 | **Absence.** An absent key has a witness; a present key has none, also when its value is empty. |
| K6 | **Complete range.** The honest list verifies; omission, substitution, addition, reordering, duplication and a claimed entry outside the interval are rejected, the last also when that entry is committed. `lower` is inclusive and `upper` exclusive. |
| K7 | **Table isolation.** A statement names one declared table. An undeclared table is ill-formed. An entry of one table never satisfies a statement about another, including identities that are prefixes of each other. |
| K8 | **Cells.** A cell has only the empty key; any other key is ill-formed in updates, proofs and verification. |
| K9 | **Canonical witness encoding.** Verification consumes the complete canonical encoding: a truncated encoding and an encoding followed by further bytes are rejected, and every carried byte is charged against the committed byte and work caps. A changed witness never establishes a false statement. Proofs need not be non-malleable: an independently valid alternative witness of the same true statement may verify. |
| K10 | **Atomic update.** One block's net change set names each `(table, key)` at most once and is applied completely or not at all. Removing an absent key and rewriting an equal value do not change the root. |
| K11 | **Incremental equals cold.** After any sequence of change sets the root equals a cold build of the same content. |
| K12 | **Root binding.** A statement that a later State falsifies is rejected at the later root with the earlier witness; verification at the earlier root is unaffected. |

Further requirements that the suite cannot observe:

- **Determinism.** Root, witnesses and verdicts are identical on every platform; an accelerated
  path is bit-identical to the scalar one.
- **Bounded verification.** Verification work is bounded by a function of the witness length and
  the claimed entry count. G.4 caps both from committed State before verification.
- **Cross-witness consistency.** For one root it is infeasible to produce an inclusion and an
  absence witness for the same position, two inclusion witnesses with different values, or a range
  witness that omits a position for which an inclusion witness exists. A construction built from
  more than one tree (for example a hashed lookup tree paired with an ordered tree) must prove
  this from its root, not assume it.
- **In-circuit form.** Each witness kind has an AIR relation over the same statement and bytes;
  G.2 measures both forms.

### 16.5 One owner, atomic publication and recovery

The commitment is owned by the existing State publication owner
(`crates/iroha_core/src/state/publication.rs`), which today advances the World state accumulator
once per block, after `world_commit::PreparedWorldCommit::prepare_overlay_mutations`.

- **P1. One owner, one scheme.** Only the State publication owner advances the authoritative
  complete-State commitment. Exactly one such commitment scheme exists, including its historical
  roots; independently authoritative per-table State roots are forbidden. Inventoried per-block
  witness roots retain their specified roles. Application accumulators may retain
  application-statement proofs under §16.8, but a commitment that independently authenticates
  canonical State entries is a per-table State root regardless of its carrier. A protocol
  fingerprint may remain only as an inventoried comparison value that every consuming validator
  recomputes from committed canonical entries at the specified State cut, using only its
  inventoried block-header context and registered historical inputs authenticated under §§16.1
  and 16.7, or from canonical entries staged from the signed genesis. It has no State-witness
  form and never substitutes for a keyed State witness. A derived State field takes its
  authority only from its registered sources; a protocol-carried copy may be installed only
  after equality with an independent derivation from those sources at the specified State cut,
  and remains a comparison value under the protocol-fingerprint rule. Node-local binding
  commitments may remain only with an inventoried owner and reason; they may authenticate
  local artifacts, including snapshot file bytes through chunk proofs, but never authenticate
  State reads, determine transaction validity, or enter protocol-authenticated roots or State
  witnesses. They may compose into inventoried local binding identifiers. Local binding
  failures require recovery or deferral.
- **P2. One change set.** The update consumes the frozen journals of the same publication cut as
  the State view: every canonical World and State-level field, from each journal's own undo
  entries. The cost is proportional to the change set.
- **P3. Two cuts per height.** `X_h` is the State after block `h`'s execution is sealed; `P_h` is
  the State after its deterministic apply-time tail writes. `R_h` binds `X_h`; `R_{h+1}` binds
  `P_h` (§16.6).
- **P4. Atomic publication.** The State view generation of height `h` and the commitment version
  of `P_h` become visible in one step. A reader, a prover and a witness server never observe one
  without the other. A failed, refused or replaced publication leaves the commitment at `P_{h−1}`.
- **P5. Recovery.** Persisted nodes of a construction are a cache. Restart replays the certified
  chain and requires each recomputed root to equal the certified one, and the incremental root to
  equal a cold build (K11). The three outcomes are distinct: a certified-root mismatch while
  applying a block is `ApplyDiverged`; a block that does not replay at restart is
  `NodeError::Replay`; lost or corrupt local publication is `PublicationRecoveryRequired`. None of
  them changes transaction validity.
- **P6. Local independence.** Cache size, serving retention, worker count, acceleration and
  available memory change no root and no verdict. A node that cannot serve or build a witness
  defers; it does not reject.

### 16.6 Result layout and non-circular binding

`ExecutionCommitment` keeps its field order. Two fields are replaced in place:

```text
ExecutionCommitment {
    parent_state_root,              // witnessed pre-values: a per-block witness root, unchanged
    post_state_root,                // witnessed writes, unchanged
    ordinary_writes_root,           // unchanged
    parent_keyed_state_root,        // replaces parent_world_state_root: root(P_{h−1})
    keyed_state_root,               // replaces world_state_root: root(X_h)
    event_commitment,               // unchanged
    executed_block_wire_len,        // unchanged
    executed_block_wire_hash,       // unchanged
    transaction_input_commitment,   // unchanged
    transaction_output_commitment,  // unchanged
}
```

- `parent_keyed_state_root` of block `h` is the root of `P_{h−1}`: the complete keyed State the
  block executes on. For genesis it is the root of the empty State under the schema, so genesis
  absorbs everything the State holds.
- `keyed_state_root` is the root of `X_h`. Both cover the whole schema of §16.1, not only World.
- **Wire type.** Both fields have the type `KeyedStateRoot([u8; 32])`. Its Norito payload is
  exactly 32 raw bytes, preserving all 256 bits, with no `iroha_crypto::Hash` marker and no
  alternate representation; the enclosing record framing remains. The codec is explicit, because
  ordinary array serialization frames each element. G.3 defines the one shared type beside
  `ExecutionCommitment`, replacing the prototype type of the interface. G.2 measures and G.3
  freezes the canonical encoding of a construction's native root and any normalisation hash, with
  its domain and its raw 256-bit output; a marker-setting `Hash` conversion is never used. The
  codec is tested with both values of the marker bit and rejects every alternate framing.
- `R` keeps the form of §4.1.1, `SHA-256(RESULT_TAG ‖ F ‖ H(RESULT_BODY_TAG ‖
  norito(ExecutionResultCommitment)))` (E51); G.3 changes only the body. There is one layout and
  one tag. `F` is the finality header of §4.1.1, not the State `X_h` of this section.

```text
P_{h−1}
header_h   = (…, parent_hash = bh_{h−1}, parent_result = R_{h−1}, payload_hash, …)
bh_h       = H(TAG_BLOCK ‖ header_h)
X_h        = exec(P_{h−1}, body_h)
R_h        = SHA-256(RESULT_TAG ‖ F_h ‖ H(RESULT_BODY_TAG ‖ norito({h, execution{root(P_{h−1}), root(X_h), …}, schedule, beacon, native_lanes})))
CommitQC_h = q_h votes over (I, E, h, v, bh_h, R_h)
P_h        = tail(X_h, body_h, R_h)
header_{h+1}.parent_result = R_h,   R_{h+1} binds root(P_h)
```

- **N1.** A block's own result is not in its header (§3.2). `header_h` binds `R_{h−1}` only.
- **N2.** Nothing in `X_h` depends on `R_h`, on a vote or on a certificate of height `h`.
  Execution reads `P_{h−1}`, the header and the body.
- **N3.** No State cut depends on certificate bytes at any height. Different exact-quorum signer
  sets certify the same `(bh, R)` (§3.4), so signer bitmaps and aggregate signatures
  are not replicated State. `P_h` may depend on `R_h`, which is unique.
- **N4.** A root is never an input of the root that commits it. In particular the commitment's own
  nodes, counters and roots are not entries of the schema (the derived `world.state_accumulator`
  cell has no successor).
- **N5.** The CommitQC authenticates `R_h`, and through it `root(P_{h−1})` and `root(X_h)`.
  Neither root depends on that certificate.

### 16.7 Root history

Carried witnesses name an anchor root. Validators check the anchor against replicated State
alone, so recent roots are committed entries:

- A canonical table (working identity `state.keyed_root_history`) maps a height `j` to
  `root(P_j)`.
- The entry for `j` is written while block `j + 1` executes or later. A row written at height `h`
  names only heights below `h` (N4). `root(P_{h−1})` needs no row at height `h`: it is
  `parent_keyed_state_root`.
- Retention and anchor ages come from committed State (G.4). Rows are pruned deterministically in
  the block that makes them inadmissible.
- The table holds no result, certificate or post-execution root. `root(X_h)` is available to
  external verifiers from `R_h` and its CommitQC.
- The table authenticates published State roots only. It does not authenticate a result: a
  consumer that opens `R_j` (for example `ordinary_writes_root` or a transaction outcome of height
  `j`) authenticates that opening against replicated execution authority (G.4, A.1).

G.3 freezes the table identity and codec; G.4 defines ages, caps and the admission checks.

### 16.8 One root and cutover

- The cutover replaces the two LtHash16 fields; it does not add fields beside them. The same
  change deletes `WorldStateAccumulator`, the `world.state_accumulator` cell, the World-element
  snapshot format and their `world_state_*_v1` helpers.
- No binary computes both roots for consensus, and none selects a layout by height,
  configuration, feature or environment. A chain built on the LtHash16 layout is not replayed by
  the keyed binary: the cutover is a fresh genesis. A second calculation is permitted only under
  `#[cfg(test)]` as a differential.
- No per-table root is added to the result. Per-table and per-key proofs are witnesses against
  the one keyed root; contract-state value proofs use `world.smart_contract_state` in it.
- Every existing commitment over State content is enumerated under `roots` or, where the
  application-accumulator exclusion applies, under `application_accumulator`. Each entry of
  `roots` has one class, one owner task and one disposition. The classes are: certified State
  roots (the World state root, replaced in place, and any per-table State root, removed under
  its open defect); per-block witness roots and their witnessed values (kept in their E51 roles;
  a witnessed value that digests State content is retained as a certified per-block witness
  value, not as State-read authority, and consumers requiring State reads use keyed State
  witnesses); protocol fingerprints, flat digests or composite summaries of State content
  carried for comparison in a header, the block result, signed genesis or peer handshake (made
  a function of committed canonical entries or removed under their open defects; none
  authenticates a State read); consensus bindings (kept: see below); uncertified drafts
  (deleted, or kept only as an internal component of the selected construction without an
  independently authoritative root); and node-local binding commitments (kept under P1).
- The protocol fingerprints that exist today are the execution-policy digest (signed genesis
  and the peer handshake, which also carries the Nexus policy digest on its own), the Nexus/AMX
  context hash (signed genesis), the DA proof-policy bundle hash (every block header; the bundle
  is in the block) and the confidential feature digest (every block header and the peer
  handshake: the effective verifying-key projection, the selected parameter identifiers with
  their registry-effectiveness checks, and the ZK policy). Block or genesis validation
  recomputes each from State and rejects on a difference. Open defects G1-D3 and G1-D10 of the
  inventory track them. The block result also carries the AXT policy snapshot, tracked by
  G1-D11. It is the AXT policy projection of the derived table `world.axt_policies` with a
  64-bit version, a truncated hash of its entries; validation compares the whole record with
  the projection it reads from State after execution, and the apply path installs the carried
  rows into the derived table without rebuilding them from the table's registered sources.
  The other State-compared content of the block payload and result is classified field by
  field in the inventory (`protocol_carriers`): per-input routing contexts, proposal inputs,
  references to certified lane blocks and execution results commit no State table, and the
  roots of a FASTPQ transfer transcript concern transcript-local balances.
- Consensus bindings are digests or embedded records that bind consensus authority, scheduling
  and finalized beacon inputs in their specified roles under §§3, 4.1 and 10; they authenticate
  no State read, and their canonical State source entries are also committed by the keyed State
  root. They are the epoch context identity `EpochId.context` in every header, vote and
  certificate, and the `schedule` and `beacon` fields of `R`; `native_lanes` keeps its
  classification as a certified per-block witness value. A lane instance has the same binding
  for its own authority: the pinned committee digest and parameters in every lane result, and
  the genesis hash and genesis result of the lane incarnation, whose source is the lane cell
  (`specs/sumeragi_lanes.md`). Authority follows signed genesis and
  authenticated predecessor transitions; it does not depend on a State opening authenticated by
  the certificate being verified.
- Local bindings cover the tiered backend's separate key and value hashes, the projection
  rowset hash and compressed archive/blob hash, and both private-settlement evidence
  commitments: seven-table ledger evidence and replicated staged-lock evidence. They
  authenticate only local artifacts or test observations, never State reads or transaction
  validity. Shipping builds do not compile the two private-settlement commitments, and the
  projection producer is still pending. The other local bindings are listed in the inventory
  with their owners.
- An application accumulator is maintained by deterministic execution over application records;
  its authoritative root and canonical persisted data are committed as State values by the keyed
  State root, and its proofs establish application statements without substituting for keyed
  State inclusion, absence or complete-range witnesses.
- The drift test discovers hash-domain literals independently of ROOTS across both crates and
  rejects every unclassified literal use, commitment-construction use and hash-bearing
  execution-witness field; exemptions identify exact reviewed uses and never match an open
  prefix. The drift test walks the listed consensus-carried types and their declared nested
  types, rejecting unclassified hash-bearing fields or unclassified nested types. It
  independently enumerates `iroha_core` functions and methods with a State/World receiver or
  reader argument and a hash-bearing return value under documented type rules, rejecting
  unclassified matches. Generated JSON pins each listed domain literal's source paths and
  occurrence counts. These checks detect carrier, signature and literal drift; they do not
  establish arbitrary State-dataflow completeness.
- The test is `crates/iroha_core/src/state/state_table_inventory_tests.rs`. The literal and
  construction scan reads every non-test source of `iroha_core` and `iroha_data_model`; the
  signature scan reads every non-test source of `iroha_core`; the carrier walk reads the
  declarations of the block header, the block payload and block result, the signed genesis
  consensus parameters, `R`, the lane batch and the lane result with their nested records, and
  also those of every Sumeragi wire message (`crates/iroha_sumeragi`, from its `WireMessage`
  enumeration), of the peer handshake (`crates/iroha_p2p`: the hello record that peers
  exchange with its consensus, confidential, crypto and trust metadata and its wire digest, the
  identity binding that the hello signature covers, and the consensus, confidential and crypto
  capabilities that a node compares them with) and of the node's network envelope
  (`iroha_core::NetworkMessage`, whose every variant is classified), and the inventory cites
  the hashing of the Nexus/AMX context in `crates/iroha_config`. In the types listed under
  `protocol_carriers[*].every_field_classified` every field is classified, so a new field
  fails the check whatever its type. They are the block, its payload and its result, the
  header with its confidential feature digest, the native `CertifiedResultV1`, all twelve
  fixed X fields, the two body records of `R`, the walked committee-member, authorization,
  beacon-binding and frozen-election-policy records, the lane batch and the lane result, the
  genesis context parameters, the epoch identity, every walked record of the peer handshake,
  the network envelope with its Sumeragi frame, and the DA commitment bundle with its storage
  variants, canonical parts and commitment records. In the other walked types a new field
  fails only when its type is hash-bearing or names an unclassified nested type.
  The signature scan reads the whole header of an `impl` or `trait` block, also of a literal
  block in a macro body; it does not expand macros. It also matches a function that reads
  State and returns a walked record of the peer handshake or of a lane block
  (`source_scan.carried_records`), whatever the name of the record; it does not read the node
  binary, which fills the handshake capabilities. Its reader types
  (`source_scan.state_reader_types`) are `State`, `World` and
  the owners of the other registry fields (the transaction storage, the block-hash journal, the
  trigger set and the canonical runtime) with their handles and reader traits, and the table
  and cell handles. The inventory states the form of literal that it
  discovers (`source_scan.domain_literal_rule`), the construction identifiers that it counts,
  the signature rules (`source_scan.state_reader_rule`, `source_scan.hash_return_rule`), the
  carriers with every classified field (`protocol_carriers`), the detectors that report each
  commitment (`roots[*].detected_by`), the commitments that only a review found
  (`source_scan.found_by_review`), the carried values that only a review found because the
  hash rules do not match their type, for example an integer
  (`protocol_carriers[*].found_by_review`), and what the checks do not detect
  (`source_scan.not_detected`). The per-table mapping of the witnessed roots
  (`witness_families[*].fields`) is read from the World accessors of the listed deriving
  functions; a helper that such a function calls is listed by hand.
- Consumers: G.2 implements each candidate behind `KeyedStateCommitment`, passes
  `conformance::check_contract` and then measures it. G.3 selects and freezes the construction,
  commits the State-level fields, binds it to the publication owner, replaces E51 and closes the
  open defects of the inventory. G.4 defines carried witnesses, anchor ages and caps against
  §16.3, §16.4 and §16.7. G.5 ships the witness-assertion operation over the three statement
  kinds. For A.1 a State witness verifies against a §16.7 anchor, a carried result opening is
  authenticated against replicated execution authority and not by a published root, and
  `new_root` of ordinary effects stays `ordinary_writes_root`.

---

## Appendix E. As-built reconciliation

This appendix reconciles revision 4.1 with the implementation in `crates/iroha_sumeragi` and its
simulator. Every `// SPEC:` marker in the crate refers to one row below. Rows E1–E8, E36, E40,
E41, E43, E44, E47, E53, E60 and E64 changed the normative text above (minimal edits, marked by their section;
E43, E44, E47, E53, E60 and E64 are the node-integration additions); rows E9–E30, E37, E38, E45, E49, E51, E52,
E54, E57 and E58 record code-level choices where the text leaves room or adds a defensive check, without changing
the protocol (E51, E52, E54, E57 and E58 record the node's application and backend choices);
E31–E35, E39, E42, E46, E59, E61, E62 and E63 record simulator and verification deviations. This file,
`specs/sumeragi.md`, is the normative specification that the crate's `§`
references and `// SPEC:` markers resolve against (checked by `crates/iroha_sumeragi/tests/spec.rs`).

### E.1 Rules amended in place

| # | Found by | Rule and change | Where | Code site |
|---|---|---|---|---|
| E1 | simulator, F3 seed 12 (build report bug 1) | `Status` rate limit: a `Status` over the per-peer limit is still used for its `committed_qc` alone if that is at height `≥ h` and above every `committed_qc` height processed from the peer (the §6.1 rule-3 reply carrying the CommitQC a lagging voter lacks often follows the peer's periodic `Status` inside the window; at most two extra verifications per peer and height). Not covered by 4.1, which exempts only echoes and proposal requests. | §6.11 on-`Status` step 3 | `machine::intake::on_status` |
| E2 | simulator, F24 forged record, seed 11 (bug 2) | R4 requires the record's `parent_commit_qc` to be a valid CommitQC of the tip `t` for `(tip.block_hash, tip.result)` (absent only at `g + 1`); otherwise `Halt(SafetyRecordInconsistent)`. A checksum-valid record that contradicts the block store would otherwise make a restarted leader re-send a different proposal (its `parent_qc` comes from the record). 4.1 checks only R5's parent CommitQC. The check runs for the record of every key (configured or retired, signing or not) when the node reaches the record's height (R4 at the restart, R6 later), as step 4 says ("if a key has an R4 record"); the first implementation checked the signing key's record only (found by review). | §7.4 step 4 | `machine::restart::record_matches_tip` (from `machine::round::take_restore`) |
| E3 | simulator, F17 seed 106 (bug 3) | Sync: before a request, buffered entries above a gap in the heights from `h` on are dropped and fetched again (a dropped invalid entry otherwise left a gap that `from_height = max(h, highest buffered + 1)` never requested again, and a full buffer blocked all requests). A request unanswered by `sync_retry` counts as an empty response for dropping an unverified target (a silent source would keep a bogus hint and its requests alive). | §6.9 rule 2 | `machine::sync::keep_buffer_contiguous`, `sync_tick` |
| E4 | simulator, F2 seed 115 (bug 4) | Heartbeat: a `PayloadReady{req}` that reaches the core before the `EMPTY` answer to `BuildPayload{req}` (the builder answered, then a transaction arrived) is kept, and the `EMPTY` answer then requests again at once instead of idling until `payload_retry_interval`. Revision 4's request ids narrow the case but do not order the two events. | §6.10 rule 1 | `machine::propose::on_payload_ready` |
| E5 | simulator, F3 seed 4 (this reconciliation) | Unsettled also at stage 2 of the current round. A withholding proxy tail can deliver its PrepareQC to some honest members only; at stage 2 those no longer re-send their Prepare (its phase QC is held), so the others cannot form the PrepareQC from broadcast votes and learn the lock only from `Status` — at the keepalive cadence after revision 4 removed "no commit in `2·rebroadcast_interval`", which broke P3. | §6.11 Status | `machine::timers::unsettled` |
| E6 | simulator, F24 seed 10 (this reconciliation) | R2: anchoring is also checked when `BlockApplied` makes `C_{tip.height+2}` known. At a height entry that configuration is normally not known yet, and later echoes report higher heights (they never lower an entry, so they trigger no check): a node whose lowest replies were recorded while it was behind stayed unanchored forever. | §7.4 R2 | `machine::round::on_block_applied` |
| E7 | test `det_s31e_echo_signature` (this reconciliation) | Probe-table pruning at height entry happens only while `C_{tip.height+2}` is known; otherwise the entries are kept (a lowest reported height stays valid as the tip rises). Pruning against an unknown configuration discarded valid replies. | §6.8 step 5 | `machine::round::prune_probe` |
| E8 | simulator, F9 seeds 34, 274, 284 | P1's per-gap bound is `G_norm + 2·rebroadcast_interval + Δ`: a proposal copy lost to two members the quorum needs is recovered by their proposal request once they see evidence (at worst the stage-2 votes, about `2·t_retx` later) or by the re-push. P1's p99 is taken after a 20-height warm-up (`qc_lat_ewma` starts at 250 ms). O6 SHOULD serve peers round-robin within a class (a flooding peer otherwise starves honest control traffic when the CPU is saturated). | §8.2 P1, §12.3 O6 | `sim::oracle::check_gap`, `sim::driver::Lane` |
| E36 | review (sync buffer poisoning) | Sync responses are bound to requests: a response answers one unanswered request of this node to its source and starts at that request's `from_height` (an empty one answers the source's latest request); other responses, including a second one for the same request, are dropped; buffered entries above a gap are dropped before a response is checked; `Status` candidates are members only (as rule 2 already said). 4.1 processed every response of a source that was ever asked and never replaced a buffered entry, so a Byzantine source asked once could fill the buffer with well-formed entries carrying forged CommitQCs for heights above `h`; they never reached their turn, every honest answer found the buffer full, and a lagging node never caught up. Now a forged entry reaches its turn and is dropped there, at most once per request sent to its source. | §6.9 rules 2–3 | `machine::sync::on_sync_response`, `SyncState::take_request`, `maybe_request_sync` |
| E40 | simulator, final 500-seed sweep: F5 seed 279 (`n = 22`, churn; successive equivocating leaders held every honest node at start levels 3–4 and one height took 26.4 s, failing the post-heal progress check) | (a) §9.2 raise: the start level rises iff `pm.last_exec_ms > T(start)/2` (unchanged) or the committing view was slow here, `t_commit(h) − anchor(h, v_c) > T(start)/2` with `v_c` the committing CommitQC's view, measured only when this node is in `v_c`; the rule "a view timed out on its deadline or by a join while this node held its proposal" (`failed_with_proposal`) and the timeout causes that existed only for it are deleted. That rule let every faulty leader raise the level at each of its turns (equivocate, or send a valid proposal to only `2f` honest members); now a failed view never raises. The rule as first drafted measured from `t_enter(h, v_c)`; the anchor is used instead because at view 0 the entry is followed by the pace or heartbeat wait (`payload_retry_interval` = 5 s > `T(0)/2`): measured from the entry, a healthy idle chain in the simulator sat at `start_cap` = 4 and a loaded `n = 4` chain at level 1 (both stay at 0 from the anchor); for `v_c > 0` the two differ by at most `build_timeout`. (b) Early timeout on proven leader equivocation: two different proposals for the current `(h, view)`, both validly signed by `L(h, view)`, make the node sign its timeout at once (not only report evidence), so the view ends one join and one TC later instead of at its deadline. Safe (timeouts are always safe under the fence) and unframeable (the evidence needs two signatures of the leader over different preimages). Tests `det_l25`, `det_l26`; mutations ML25, ML26. | §6.2 step 2, §6.6, §6.8 step 4, §7.1 SR35, §7.5, §8.2 L2–L3, §8.3, §9.2, §13.4 | `pacemaker::Pacemaker::on_commit`, `machine::round::commit_height`, `machine::proposal::check_held`, `machine::timeout::sign_timeout` |
| E41 | adversarial review of E40: (1) every executor 3.0–3.9 s for non-empty blocks at `n = 4` defaults, with an executor that aborts discarded work (O4) — every height committed `EMPTY` at view 2 and the start level stayed 0; (2) a leader whose valid proposal arrives `T(start)/2 + ε` after `t_enter + P(0)` — the view commits, the leader is never demoted, and every honest node rose to `start_cap`, because faulty members lead every `n/f` heights and `decay_after` = 8 never catches up | (a) `pm.last_exec_ms` is the maximum over the height (it was the last value), and an execution still `Pending` when `discard_exec` removes it, or when its block commits, counts with `now − since`, a lower bound that never exceeds what the execution clause counts once the execution finishes. With the failed-view raise gone (E40), nothing else saw an execution that outlasted every payload view; the simulator's non-preemptive executor had hidden it (the next view's execution queued behind the cancelled job, so the committing view looked slow). (b) `d_c = t_commit − t_body`, where `t_body` is when this node first held the committing view's proposal together with its body; `d_c` is defined only if this node holds that view's proposal of the committed block. E40 measured from the anchor, which a late proposal stretches; measuring from `t_prop`, as the review proposed, would still count a body served late and the other twin's commit. §9.2 item (2) corrected: faulty members stretch `d_c` only through certificate delays that the stage ladder bounds, and decay cannot outpace a lever used at every faulty turn. Tests `det_l27`, `det_l28`, `det_l29` and `det_l26` (h), which now executes view 1's block before the commit; mutations ML27–ML30; scenarios F15 variant 5 and F36. | §6.0, §6.2 steps 8–9 and `discard_exec`, §6.3 step 1, §6.8 steps 4–5, §6.12, §8.3, §9.2, §13.3, §13.4 | `pacemaker::Pacemaker::record_exec`, `machine::proposal::{discard_exec, record_pending_exec, maybe_execute}`, `machine::round::commit_height` |
| E44 | first-release transport | One canonical wire tag table classifies both decoded and raw Norito frames: Proposal and PayloadManifest are Proposal class; PayloadChunk and SyncResponse are Bulk; the remaining tags are Control. Classification never depends on node height or optional payload presence. | §3.5, §12.3 O8 | `message::{TrafficClass, traffic_class_of_frame, PROTOCOL_VERSION}`, `sim::net::class_of` |
| E53 | crash matrix of the file record store (node integration) | Store-id check: the "every key imported" marks of a mismatch are one event — all appended with one fresh id, the id file written and synced after them. Written one by one, each with its own id written first, a crash after the first mark left a matching id and the other keys' stale "generated" entries, so a later instance start (records lost with a replaced record store, key store rolled back) could write an initial record for a key that had signed there. | §7.4 rule 3 | `iroha_core::sumeragi::driver::persist::reconcile_store_id` |
| E60 | mandatory first-release signed RS16 integration | Sumeragi owns signed layout, complete original signature table and source-bound custody. ProposalMessage and SyncEntry require availability evidence; actual rows use the same Norito WireMessage owner. Typed author/acquisition/restoration jobs retain original funded owners through refusal. AvailableBody binds full independent authority; metadata alone grants no custody. Reconstruction/restoration checks complete codeword and padding. Publication retains original frame and never re-signs or falls back to raw bodies. Current all-row dissemination has no holder-bandwidth claim; live qualification remains open. | §12.8, §3.2, §3.3, §3.5, §12.1–§12.3 | `iroha_sumeragi::{availability, message, api}`, `iroha_core::sumeragi::driver::{payload_worker, payload_jobs, acquisition}` |

### E.2 Code-level choices (no protocol change)

| # | Topic | As-built choice | Code site |
|---|---|---|---|
| E9 | Signature length | Every signature and aggregate is 96 bytes (BLS12-381 min-pk; the fake scheme uses the same): `tc_digest` places `agg_sig` before a variable-length `opt(..)`, so variable-length aggregates could make two TCs share a digest and a cached verdict. | `types::SIGNATURE_LEN` |
| E10 | Decode bounds | At most 1024 committee members (bitmaps, TC entries, `skipped_leaders`) and 1024 entries per `SyncResponse`; `sync_batch` is validated against the latter. | `types::MAX_COMMITTEE_SIZE`, `message::MAX_SYNC_ENTRIES` |
| E11 | Bitmap bit order | Bit `i` is `(bytes[i / 8] >> (i % 8)) & 1` (least significant bit first). | `types::Bitmap` |
| E12 | Default `epoch_length` | 3 600 heights (one hour at 1 s). | `types::ChainParams::default` |
| E13 | Instance in digests | `qc_digest` / `tc_digest` take `I` from the certificate's own `instance` field (equal to `I` for every verified certificate). | `preimage::qc_digest_preimage` |
| E14 | Local defaults by size | The §9.3 `n = 4` column below 10 members, the `n ≈ 20` column from 10 on. | `api::LocalParams::for_committee_size` |
| E15 | `Init.instance` | `Init` carries the instance id: the core needs `I` before any record, header or certificate exists (a genesis start). | `api::Init` |
| E16 | `Init` validation | One `RecordState` per configured or retired key; a missing state, a signer for a retired key, a configured key without signer or a key listed twice is a `ConfigError`, not a guess. | `machine::restart::local_keys` |
| E17 | R1 consistency | A record that decodes but contradicts itself (certificates of other heights, instances or kinds; a timeout carrying a QC above its view; a `justify` not for `view − 1`) is corrupt (`Halt(SafetyRecordCorrupt)`). | `safety::SafetyRecord::check_consistency` |
| E18 | Key conflict | "Two configured keys in `C_h` sign with neither" applies whether or not a key abstains or is unanchored (a conflict never resolves to signing). Retired keys never count. | `safety::select_signer` |
| E19 | Abstaining members | A member whose key abstains or is unanchored keeps its routing roles (it aggregates votes sent to it as proxy tail and broadcasts the QCs it forms); only signing is suppressed. | `machine::Me` |
| E20 | Oversize payload | Superseded: an oversized build now waits for bounded retry and never creates a block. | `machine::propose::payload_ready` |
| E21 | `T_max_eff` bound | `T_max_eff` is clamped to 2^40 ms, up to which `T(L)` and `level_cap` are exact in integer arithmetic. | `pacemaker::MAX_VIEW_TIMEOUT` |
| E22 | Config validation | Also rejected: zero `t_base`, `rebroadcast_interval`, `status_keepalive`, `fetch_retry`, `sync_retry` (they would busy-loop the timer), zero `build_timeout` (the build deadline would answer every build with `EMPTY` before the builder, O5, so the leader would never propose a transaction) and `sync_batch` above the decode bound. | `pacemaker::validate_local` |
| E23 | `t_retx` clamp | When `φ·T/2 < 50 ms` the clamp bounds cross; the lower bound wins. | `pacemaker::Pacemaker::t_retx` |
| E24 | Initial `latency_ewma` | None: the first sample initialises it, and `pace = block_time` until then. | `pacemaker::Pacemaker::pace` |
| E25 | Start-level "otherwise" | "Otherwise unchanged" keeps both `start` and `fast_streak`; the per-height `last_exec_ms` resets at every commit. | `pacemaker::Pacemaker::on_commit` |
| E26 | Sync buffer size | An entry counts its payload plus 256 + 2048 bytes per header and 64 per skipped leader (no re-encoding). | `machine::sync::entry_bytes` |
| E27 | Want sources | The peer that relayed a proposal without its body is also a fetch source (bodies are self-verifying). | `machine::proposal::accept_proposal` |
| E28 | Evidence dedup | `reported` has one key per `(kind, view, signer)` for votes and timeouts and per `(kind, view)` for proposal evidence (equivocation and signed defect: `3n + 2` per view); it is capped at `3·(3n + 1)` keys and at 15 keys per accused signer (the leader of the view for proposal evidence: three pool-window views times five kinds), and evidence beyond either cap is dropped (evidence is best effort). The per-signer cap keeps one Byzantine member, which can sign defective proposals for any number of future views (no TC is needed for a signed defect) and timeouts for any future view, from filling the whole cap with keys that are never pruned within the height (found by review); `f` signers hold at most `15f < 3·(3n + 1)` keys. | `machine::Core::report` |
| E29 | Restored own messages | The authenticated persisted Prepare signature and deterministically rebuilt timeout re-enter the own pools through `pool_insert` / `timeout_insert`, last in `restore`, followed by `try_commit()`; formation may then commit. An unsigned Prepare reservation awaits original execution admission. | `machine::restart::restore_round` |
| E30 | Probe answers | Answered at most once per peer per `rebroadcast_interval`, with a stamp separate from the §6.1 reply limit. | `machine::intake::answer_probe` |
| E37 | `Init.configs` | Only the heights `t` to `t + 2` are accepted, each at most once (a `ConfigError::InvalidInit` otherwise). A configuration above `t + 2` let commits run more than two heights ahead of apply (§10.2), and the next in-order `BlockApplied` then halted the core as a driver anomaly. | `machine::restart::check_init` |
| E38 | Chain parameters | Historical rule, superseded by the no-empty-block design: `Core::new` also applies the transport-independent §9.4 chain-parameter rules to the initial configurations (`block_time ≤ payload_retry_interval`, `empty_after_views ≥ 1`), and the leader applies the voters' fresh-block rule (§6.2 step 6) to every fresh payload, at view 0 too: with `empty_after_views = 0` from a committed configuration it proposes `EMPTY` instead of a payload every voter reports as a signed defect. | `machine::restart::Core::new`, `machine::propose::propose_fresh` |
| E45 | `CoreStatus` | Also reports the leader and the proxy tail of `(h, view)` (`None` while awaiting: the next round's committee is not known yet) and the view of the lock (`high_pqc`), for the node's status endpoint, which replaces the v2 leader and QC endpoints. | `machine::Core::status` |
| E49 | Driver bounds and failure handling (§12.2, §12.3, §12.5) | The `iroha_core` driver bounds every queue the core's peers or a failing device can grow. Serving: the node's own `FetchPayload`s go first (one per body), then peers round-robin with at most one pending `ServeBlocks` and one `ServePayload` each (a newer one replaces it) within a per-peer token bucket of response bytes; the rest is dropped (O6). The O2 barrier holds at most 1 024 effects and 32 MiB of block payload, dropping the oldest `Send`, `Broadcast`, `ServeBlocks` or `ServePayload` beyond (the core rebroadcasts; `CommitBlock`, evidence and `Halt` are never dropped; a newer `FetchPayload` of a body replaces a held one); a record still queued is superseded by a newer one of the same key, and what waited for it waits for the newer; queued bodies of applied heights are dropped. Released effects leave in batches of 64 with a due `Tick` in between (O5). A prepared commit runs alone on the executor (nothing between its prepare and its commit, also while a step backs off), and a retryable refusal re-prepares the same original owner without a second append. Consuming publication failure or prepare/commit unwind halts for recovery; ordinary idempotent write failures and missing reads remain retryable; a thread that stops anyway, or an unreachable worker, stops the instance and is reported. Frames are decoded within the transport limit (O10). | `driver::{serve::ServeSched, barrier::Barrier, persist::PersistQueue, exec::ExecSched, Kernel, Driver}` |
| E51 | Application `R` (node integration, §4.1) | Current candidate: §4.1.1 `R = SHA-256(RESULT_TAG ‖ F ‖ H(RESULT_BODY_TAG ‖ body))`, preimage `F ‖ body`; complete producer/replay/reader qualification remains open (WP-C2). The body is `ExecutionResultCommitment` with `ExecutionResultCommitment{height, execution, schedule, beacon, native_lanes}`. `execution` (`ExecutionCommitment`) binds: (1) the **complete World state**: `parent_world_state_root`, the World the block executed on (every canonical World entry after the parent block's publication, including the parent's apply-time deterministic writes; for genesis the empty World, so genesis absorbs everything the World holds, including state seeded before it executes), and `world_state_root`, the World after the execution; (2) the **event root** `event_commitment`: the Merkle root (`iroha_crypto::MerkleTree`, leaves the hashes of the canonical Norito events) and count of the events the execution emitted, in emission order, `None` without events (pipeline status notifications are delivery, not results); (3) the witnessed pre- and post-state roots and the ordinary-write root (sparse Merkle roots over the execution witness; the ordinary-write root carries the per-key write proofs of §11 records and KAGEMUSHA receipts) and the KAGEMUSHA top-up root and count; (4) the length and hash of the result-bearing block wire (every transaction result and output) and the network-input and typed-output Merkle commitments. `schedule` retains the complete current epoch context and the lag-2 successor schedule with every ordered key and verified BLS proof of possession, `beacon` the finalized pulse the execution consumed and `native_lanes` the complete lane-context proof against the ordinary-write root. The canonical preimage is stored as `CommitCertificate.result_preimage` in the block's Kura frame. **World state root.** The root of an incremental homomorphic multiset hash (LtHash16). Each canonical World entry, a table row `(k, v)` or the value `v` of a cell `f` that the exhaustive World authority registry declares canonical (derived indexes and local buffers excluded; the trigger owner's authoritative stores included), expands to `e = BLAKE3-XOF(derive_key("iroha 2026-09-30 world-state lthash16 element v1"), P_f ‖ presence ‖ H(k) ‖ H(v))` read as 1 024 little-endian `u16` lanes, where `P_f` binds the field identity and kind and `H` is the bare-Norito value hash or the registry's declared semantic projection. The accumulator is the lane-wise sum of all elements modulo 2^16 with the entry count modulo 2^64 (order independent; removal is the exact inverse of addition), and the root is `H("iroha:world-state:root:v1\0" ‖ S ‖ entries ‖ lanes)` (little-endian count and lanes) with `S` the digest of the registry's canonical field identities, kinds and key/value schemas. A block subtracts `e(before)` and adds `e(after)` for every entry of every canonical World storage and cell that its overlay touched, read from the overlay's own undo journal, so the per-block cost is proportional to the change set and never to the World; every pass must visit exactly the registry's canonical fields (the registry destructures `WorldData` without `..`). The accumulator is the derived World cell `state_accumulator`: the node stores it after the block's last deterministic World write at publication, and it is the next block's parent root, so the apply-time writes of block `h` enter `R_{h+1}`. Chosen over a persistent sparse Merkle tree over the World: no consumer needs per-key membership proofs against the complete state (§11 and the §12.7 readers prove writes against the ordinary-write root), and the accumulator needs 2 KiB of state and no per-entry tree nodes. Replay re-executes every certified block and so recomputes and checks both World roots and the event root; after replay, startup also requires the accumulator to equal a cold capture of the rebuilt World. Each sparse Merkle tree is built once per block. **Specified replacement (prospective: specified by ZK delivery plan G.1 in §16, not built).** G.3 replaces the "World state root" part of this row by the following text in one fresh-genesis cutover that deletes the accumulator; until then this row is the as-built rule and no second State root is published. *Keyed State roots.* `execution` binds the complete keyed State: `parent_keyed_state_root`, the State the block executed on (every canonical State and World entry after the parent block's publication, including the parent's deterministic apply-time writes; for genesis the empty State), and `keyed_state_root`, the State after the execution. Both have the type `KeyedStateRoot` (a Norito payload of exactly 32 raw bytes without a `Hash` marker, §16.6) and are roots of the one State-owned keyed commitment of §16 over the canonical tables and cells of the exhaustive authority registry, in ascending identity order, with keys and values in their registered bare Norito V1 or semantic encodings. The construction is the one G.3 selects. Inclusion, absence and complete-range witnesses verify against either root from the witness bytes alone. A block updates the commitment from its complete change set, read from the overlay's own undo journal; the State publication owner advances it once, after the block's last deterministic write, and that root is the next block's parent root. Replay recomputes and checks both roots at every certified block and requires the incremental root to equal a cold build. Exactly one complete-State commitment scheme exists and no per-table State root is independently authoritative; the witnessed roots of (3) keep their roles, `schedule`, `beacon` and the epoch context identity keep their roles as consensus bindings (§16.8), application accumulators keep their application-statement proofs, a protocol fingerprint remains only as a comparison value recomputed from committed canonical entries (§16.5 P1), and node-local binding commitments remain only under §16.5 P1. The result, header and certificate order is unchanged: a header binds only its parent's `R`, `R` binds the State before and after execution, and no State cut depends on the certificate that authenticates it (§16.6). | `iroha_core::sumeragi::commitment::{execution_result, WorldStateTransition}`, `iroha_core::state::world_projection::WorldStateAccumulator` |
| E52 | Application schedule (node integration, §10.1, §9.4) | World retains the authenticated current native epoch and bounded three-slot schedule. Parameters retain lag two; membership beyond a boundary is Pending until original certified boundary application atomically installs its exact next epoch. Genesis uses its signed context. Parameter validation consumes the exported `FRAME_OVERHEAD`, including bounded epoch witnesses and control bytes, against the protocol transport bound. | `iroha_core::sumeragi::schedule` |
| E54 | Production driver backends (§7.4, §12.2, §12.3 O2, O8, O10) | `iroha_core::sumeragi`: `crypto` — `H = iroha_crypto::Hash`; BLS-normal signatures (48-byte keys, 96-byte signatures); a committee key's proof of possession is verified once when the height schedule admits it and every aggregate naming a key not admitted fails (fail closed); a TC verifies with one multi-pairing over its `hq` groups (`iroha_crypto::bls_normal_verify_preaggregated_multi_message`); the signer is the node's key pair (BLS signatures are unique, so deterministic). `records` — one file per `(I, K)` under `records_dir/<I hex>/<H(K) hex>.record` and the store id beside them, each replaced by temp file, fsync, rename and directory fsync; the installation log is an append-only file of length-prefixed Norito entries outside `records_dir`, fsynced per entry; a torn or corrupt tail ends the log (cut before the next append), which the store-id check then sees as a mismatch (safe). The operator's assertion is a one-shot boot flag, never a configuration key. `bodies` — `<root>/bodies/<I hex>/<h>/<bh hex>`, written like records, never replaced, verified against `(h, bh)` when read, pruned through the applied height, and bounded by a byte cap that fails a write like a full disk (retried; never an eviction). `net` — `NetworkMessage::Sumeragi` carries the exact frame and `I`; one classifier (`traffic_class_of_frame`) serves the raw and the decoded P2P paths; Control → `ConsensusSafety` (the reserved safety FIFO), Proposal → `ConsensusPayload`, Bulk → `BlockSync`; one `post_recoverable` per recipient; payload streams retain the exact returned post and admission ticket under backpressure until admission succeeds; the driver owns its three FIFOs on `SubscriberRoute::Sumeragi`; relayed frames (origin ≠ authenticated connection) are not accepted, so ingress stays keyed by authenticated peers. | `sumeragi::{crypto, records, bodies, net}` |
| E55 | Driver builds (§6.10 rule 1, §12.1 `PayloadReady`); found by the node's n = 4 in-process test with `payload_retry_interval` = 600 s | Two lost wakeups at a view-0 leader. (a) A transaction arriving while `BuildPayload{req}` runs (the builder may have read the queue before it) is remembered, and an `EMPTY` answer to `req` is followed by `PayloadReady{req}` at once. (b) A builder that first waits for the parent's apply can answer after `t_propose + build_timeout`: the core has then used `EMPTY` and waits for the heartbeat, and ignores the late answer (its `req` is no longer in `build`). The driver sends `PayloadReady{req}` after every non-empty answer too; in `Requested{req}` the answer is proposed first and the readiness is ignored, in `IdleWait{req}` it requests again at once. Without either, a transaction waited up to `payload_retry_interval`. The core is unchanged. | `driver::exec::ExecSched::{transactions_available, done}` |
| E56 | Node cutover (§12.1, §12.3, §7.4; node integration) | `irohad` starts only Sumeragi. Startup order: Kura; a new empty State (nonempty local snapshot exports are not restored: `R` commits the complete World state (E51), but restoring a snapshot against the certified parent World root of its successor block is not implemented yet, goal S9) with the node's runtime configuration installed; `node::prepare` applies (fresh chain) or re-executes (restart) the signed genesis, replays every Kura block against its certificate and requires the World state accumulator to equal a cold capture of the rebuilt World, before the queue, the handshake and the network are built from the rebuilt state; then `Prepared::start_on_network` installs the records of the node's key, subscribes the driver's three FIFOs and spawns the driver over `P2pNet`. The handshake binds `proto = PROTOCOL_VERSION` and `consensus_fingerprint = I`. The operator's assertion is the one-shot CLI flag `--sumeragi-assert-fresh-key` (test-network peers pass it only on their original launch, with both the configured records directory and installation log absent; a restart never reasserts it after history loss. `kagami localnet` currently selects it when the peer's records directory is absent). The v2 relay is replaced by one subscriber per semantic class for gossip, streaming and time only. Signed local snapshot export and budget maintenance start only after original replay and successful driver startup. The gate is revoked on halt, worker failure or unwind; normal shutdown retains readiness for the final write. A local signature authenticates export bytes and never substitutes for full-World execution provenance. Emergency Fast starts no driver. The configured SoraFS provider-ingest and reputation finalized archives are bound to the native executor (`sumeragi::executor::FinalizedArchives`), which captures each committed height from the exact committed State before apply completes; a failed capture keeps the commit pending. | `iroha_core::sumeragi::node::{prepare, Prepared, NetworkedNode, NodeHandle}`, `irohad::{network_relay, supervise_sumeragi, sumeragi_node_config}` |
| E57 | Certified-chain reader (§12.7; node integration) | `iroha_core::sumeragi::certified_chain` replaces the v2 finality sidecar for application readers. `committed_block` derives a per-height receipt from the Kura frame's header and result preimage only (certified block id `H("iroha/sumeragi/certified-block/v1" ‖ block_hash ‖ R)`, which signer floors pin as `context_id`); `CertifiedChain` adds the local `CommitQC` check under the committee authenticated by `R_{height−2}` (exact BLS quorum verification) and iteratively authenticates the complete historical prefix with a lag-2 authority ring; rotated-away committees remain independently verifiable and missing authority fails closed. The role-11 Check instruction uses only the committed read (certificates are per node); signer finality, native Check histories and provider-admission readers use the certified read. | `iroha_core::sumeragi::certified_chain` |
| E58 | AMX on the global chain (§11; node application) | (a) A record is a World write of the block that creates it under the reserved execution-witness key `0xD9 ‖ kind ‖ x` (one key per kind and transaction on an instance), proven by the sparse-Merkle path in `R`'s ordinary-write root; E51's layout is unchanged, and building a path needs the block's complete write set (the mandatory lane-state write included). (b) `G` admits a `Begin` only if every participant is registered and `b < d ≤ b + 7 200`, so escrow is bounded in global heights; it keeps at most 4 096 pending transactions and 256 registered dataspaces. Relayed proofs of unknown or decided transactions are ignored without touching the state. The deadline step runs after the block's transactions, so a `Yes` relayed in block `d + 1` is recorded but cannot commit; all deadline records must be accepted before pending entries are pruned, and any local record refusal preserves the original pending source and typed cause for retry; a transaction leaves the state in the first block above `d`, and since `x` binds `d` it can never begin again. (c) A participant rejects a `Prepare` once it has verified a `G` block above `d`, and on that condition drops its prepared entries except an unsettled `Yes` escrow (which only its decision proof closes); it drops held decisions 7 200 heights after their decision height. No valid `Prepare` of a dropped transaction can follow, and its decision proof is then only held. (d) The tracker checks a certificate with `Verifier::verify_qc` under the tracked epoch's proof-of-possession-verified BLS keys, as the portable finality proofs do; its epoch window also requires the header's epoch to contain the height, so a committee never certifies a height of a later epoch. (e) `RegisterAmxDataspaceV1` is accepted in genesis or from an authority holding `CanSetParameters`, anchored at a canonical `ValidatorEpochContextV1` within the result-preimage bounds. (f) A native participant is installed exactly once by its signed private genesis, binding its signed parent network and complete global chain label to the canonical signed global genesis plus its genuine H2 carrier. The sole native prefix verifier reconstructs authority, validates Global root ownership and the exact instance, and authenticates genesis `R` from H2's exact quorum. The participant's original State pool retains both full canonical source frames, complete current/previous authority and every exact monetary escrow. Allocation admission of a decoded snapshot grants no execution capability; original genesis/journal replay remains required. (g) The native transfer host accepts a positive same-dataspace ordinary non-retail numeric leg owned by the signed transaction authority. Enrolled-wallet legs and registered retail monetary assets record `Prepared No` before any principal, maintenance or payment effect; local decoder/allocation refusal is an unfinished attempt and never `No`. Supporting retail AMX requires the original signed customer assessment and exact frozen fee/payment obligations in the funded escrow; a permissionless settlement relayer cannot supply them. A `Yes` uses dedicated non-signing custody and only an authenticated global Commit or Abort closes it. Each daemon supervises its independently signed root State and mandatory native context archive. Managed bootstrap retains the original authenticated G1/H2 source. Explicit administrative parent registration preserves its original signer, fees, deadline and signed wire; only independently verified original Global execution supplies a terminal success or rejection. Remaining S6 work (`TODO(S6)` in `iroha_core::sumeragi::amx`): current-source managed lifecycle qualification, complete outbound proof custody, durable validator relaying of pending proofs (§11 item 4), authenticated complete-State restoration and whole-network native monetary qualification. Each root executor persists complete write sets in its mandatory native context archive; `iroha_core::sumeragi::amx::amx_record_proof` authenticates a historical carrier and its full write root before constructing record proofs. Portable proof graphs and tree scratch retain their original finite pool; the same authenticated carrier/archive job can detach from its State view without rebuilding acquired fields. Complete historical-prefix, decoder and outbound transport custody remain open. | `iroha_data_model::sumeragi_amx`, `iroha_data_model::isi::sumeragi_amx`, `iroha_core::sumeragi::amx` |

### E.3 Simulator and verification

| # | Topic | As-built | Site |
|---|---|---|---|
| E31 | F33 | As literally described F33 needs the network to also delay the lock holder's votes: stage-2 broadcast voting otherwise re-forms the hidden PrepareQC among the honest members. The scenario does so. | `sim::byz::adv_net` |
| E32 | F4, F34 slow executors | A slow executor delays only its Prepare (a Commit needs no execution), so P2's "one gap per `n` heights" is not claimed for it; F4 and F34's pending-execution variant check progress, not P2. | `sim::scenarios::f34` |
| E33 | O3 in-flight reuse | The fake driver reuses a cached post-state whose commitment equals the certified result and otherwise re-executes at once; reusing an execution still in flight is a performance property checked only by the §13.5 production-driver conformance (`iroha_core` driver tests `commit_during_execution_executes_once`, `commit_answers_a_queued_execution`). | `sim::world::apply_block` |
| E34 | O-LIVE accounting | The precondition "`≥ q` honest, running members able to sign" (an unanchored member counts as faulty until it anchors, an abstaining one at its heights) is evaluated every 50 virtual ms; O-LIVE windows restart when it holds again. | `sim::oracle::check_live` |
| E35 | §13.4 meta-check | Every registered MS/ML, MA, ME, MR and MX mutation has a current-source `cfg(sumeragi_mutation = "<ID>")` switch. `build.rs` enables it only with the `mutation-testing` crate feature; production builds cannot be mutated. `scripts/sumeragi_mutation_gate.py` runs the unmutated baseline, each mutation's named deterministic tests and its listed randomized scenarios at 200 seeds. `--strict` requires a named test to kill every mutation; a scenario-only kill does not satisfy §13.4. Every named filter must execute, and a kill requires a normally completed test harness reporting an actual failed test; missing or ignored tests, process crashes and timeouts are gate errors. `.github/workflows/nightly_sumeragi.yml` runs the strict gate and, separately, every simulator fault scenario at 10 000 seeds, retaining the gate report and logs. `pytests/scripts/test_sumeragi_mutation_gate.py` checks that registered switches and named tests still exist, and verifies owner selection, strict result classification and the Core test-build guard. A separate nightly Core job uses `--core --strict --fast` for HC rules; Core selectors cannot enable protocol mutations. These implemented controls define the qualification requirement; only completed reports for the current candidate establish its result. | `build.rs`, `scripts/sumeragi_mutation_gate.py`, `.github/workflows/nightly_sumeragi.yml` |
| E42 | Executor and adversary models of E41 | The fake executor optionally aborts a discarded running job and answers `Cancelled` at once (`Profile::abort_discarded`; O4 allows either), and non-empty payloads may carry extra latency that the builder's `exec_budget` estimate does not foresee (`Profile::exec_nonempty`), both used by F15 variant 5 (F15 seeds now cycle over six variants). `Strategy::LateLeader` delivers view-0 proposals, or their bodies, as late as the view still commits, timed from the attacker's `t_enter` (a simulator-only observation, `Core::round_entered_at`) and the lowest honest start level (F36). | `sim::driver::Executor::discard`, `sim::scenarios::{f15, f36}`, `sim::byz::Strategy::LateLeader` |
| E39 | specification traceability and quorum consistency | `tests/spec.rs` checks that every `§` reference, Appendix E citation and `// SPEC:` marker in the crate resolves in this file, and that the specification's quorum examples match the implementation. Protocol behavior remains covered by deterministic simulator scenarios and the §13.4 mutation gate. | `tests/spec.rs` |
| E46 | Host seam (§13.5) | The world drives each replica through `sim::host::Host` (ingress lanes, core, O2 barrier); `FakeHost` is the former in-world fake driver, moved behind the trait without behavioural change (the `Io` write device lost its barrier to `sim::driver::Barrier`). A scenario chooses its host with `Scenario::host`; `sim::tests::host_seam_runs_a_wrapped_host` runs a delegating wrapper through F9 and F13 (crash churn) and checks identical results. | `sim::host`, `sim::world::World::process` |
| E48 | Hosts that own their scheduling (§13.5) | `Host::owns_io`, `poll` and `complete` let a host run its own persistence queue, barrier, execution scheduler and apply sequencing over the world's devices (`sim::host::{Op, Done}`); a write of such a host fails with probability `Profile::write_fail_ppm` and is reported failed (the fake driver retries the original FIFO head through scheduled attempts; failed writes retain the O2 barrier, stale completion events cannot skip the head, and even permanent failure yields virtual time for faults and recovery), apply is split into prepare, durable append and commit (the `InsideApply` crash point lies between append and commit), and churn crash points apply to its device operations. Byzantine machines run the fake driver whatever the scenario's host. `Scenario::io_kill` kills one machine at its `n`-th write completion, before or after durability (`sim::tests::io_kill_at_each_write_completion` with the fake driver; the production driver in `iroha_core`). Tick lateness and the "Tick did not consume its deadline" check use the core's deadline (`Core::next_wakeup`), not the host's own timers. | `sim::host`, `sim::world::{perform_op, poll_host, io_kill_at}` |
| E50 | Driver queues and apply sequencing in the simulator (§13.5) | O-MEM also bounds the queues of a host that owns its scheduling (`Host::backlog`, `sim::host::BacklogBound`: 4 096 held effects and 64 MiB of their payload, one queued record per key, queued bodies only at unapplied heights and within the §8.4 per-height payload, 128 executor operations other than `Execute`s, two serving requests per peer plus eight). The world keeps the post-state a `Prepare` made ready (`sim::driver::Executor::prepared`) as a single live overlay: any other executor operation drops it and a `Commit` without it fails the run, so a driver that interleaves work between prepare and commit is caught. The `iroha_core` conformance adds a replica whose writes all fail for 20 s. | `sim::host::{Backlog, BacklogBound}`, `sim::oracle::observe_core`, `sim::world::perform_op` |
| E59 | Toy AMX application (F31, O-AMX, §11) | Instance 0 is `G`, every other instance a dataspace. The application runs inside each block's execution over the parent's application state (memoised by `(instance, R)`), and an AMX world certifies `R = H(TAG ‖ R_base ‖ H(records))` with `R_base` the plain simulator result, so a record proof is the header, the `CommitQC` and `(R_base, records)`; worlds without the application keep `R = R_base`. The last block of each epoch (a committee-schedule entry) records the next epoch's context, which is the handoff proof; trackers are anchored at each instance's genesis context. Inputs are workload-format transactions naming an entry of an input registry (proofs are not serialized). Relayers run on chosen machines, resubmit every second until the effect is committed at their own replica of the target, lose their jobs when down or crashed and rebuild them from the committed chain, and delay each prepare relay by up to 4 s and each settlement relay by up to 6 s (per transaction, from its id: `G` sometimes decides before a participant prepares, which then holds the decision, and a participant sometimes verifies `G` blocks above `d` while its `Yes` escrow still waits for the decision); a forging relayer also submits every vote and decision with the record flipped. O-AMX runs every 100 virtual ms over the reference chains and once at the end. | `sim::amx`, `sim::scenarios::f31` |
| E61 | Host frames (§13.5, §12.8) | A host that owns its scheduling sends opaque frames (`sim::host::Op::Frame` with a `HostFrame`, received through `Host::receive_frame`); the world carries them like messages of their class (NIC bandwidth, delay, loss, duplication, partitions) without reading them, and the network adversary does not rewrite them. The production kernel's availability frames travel so in the §13.5 conformance runs; the fake driver sends none. | `sim::host::{Op, HostFrame}`, `sim::world` |
| E62 | F35 sparse local work (§8.1, §13.3) | The 100-seed sweep failed F35 seeds 6, 31, 78 and 87 (all `n = 22`): the progress check kept from the heartbeat era (8 heights in 120 s) and O-TXP's sanity check (half of the transactions older than 20 s committed) are not implied once leaders propose only nonempty work (§6.10). With the `f + 1` holders placed at random, up to `2f` workless leaders precede the first holder in a height's rotation and each failed view's timer grows ×1.5 up to `T_max` (§9.1): at `n = 22` one height may take 310 s (seed 6: views 0–7 of height 1, 129 s, had no holder leader; the other seeds lost views the same way, and no view `≥ 1` led by a holder failed). F35 checks the leader-turn bound (`Perf::LeaderTurns`) instead, from §6.10, §8.2 L1, L2, L4 and §9.1: with `v*(h)` the first view `≥ 1` whose leader (ground-truth topology) is a running holder, no honest replica passes `v*(h)` at an uncommitted height, and each commits `h` within `Σ_{v ≤ v*(h)} (P(v) + T(min(level_cap, s + v)) + σ + Δ)` of entering it (+3 % for drift), `s` the highest start level reported at `h`. A holder has work in any view `≥ 1`: the next transaction reaches it within the workload interval (`≤ 9 s`) of the parent's build, before view 1 ends (`P(0) + T(0) + P(1) + T(1) ≥ 10.4 s`, asserted by the scenario). O-TXP then requires each transaction in a block of the second height first committed after its submission (that block is built after the submission by a holder from its whole queue) instead of the 20-s check. The run lasts until heights 1 and 2 are due by the bound (no demotions yet, §2.1; start levels 0 and at most 1), at least 120 s, and requires both. `sim::tests::leader_turns_flags_holders_without_work` shows that the bound catches holders whose builders never return work. | `sim::scenarios::f35`, `sim::oracle::check_turns` |
| E63 | F4 slow executors (§9.1, E32) | The 1000-seed sweep failed F4 seeds 163, 455, 675 and 799 (all `n = 22`, 6–7 heights in 40 s against 8): the fake builder prices a payload at its own machine's execution cost, so F4's slow executor (`exec_base` 1.5 s, above `exec_budget` = 750 ms at `n = 22` and 500 ms at `n ≤ 7`) fitted no transaction and, since leaders propose only nonempty work (§6.10), led like a silent member besides F4's silent ones (seed 163: views 0 and 1 of height 6, 12.9 s, led by its two slow executors). `exec_budget` is a calibrated estimate (§9.1) and E32 models F4's slow members as delaying only their Prepare, so their builders no longer price that slowness into payloads (`exec_per_kib: 0`, as for F15's and F34's slow executors). | `sim::scenarios::f04` |

### Native control-witness qualification boundary

`ControlWitness` is a fixed inline byte value; its sole canonical codec emits the occupied
byte sequence and rejects advertised lengths above 2048 before copying. Norito still applies
its cumulative element/allocation accounting to those bytes. `FRAME_OVERHEAD` includes the
generic committee key/TC metadata, 2048 control bytes and explicit framing allowance. The maximal structural frame regression checks
the actual canonical encoding against that declared bound. In-memory sync
and held-effect bounds count the full inline capacity even for an empty witness.

Native beacon control is the exact canonical finalized-pulse frame, separate from transaction
payload and DA body acquisition. Its threshold preimage binds instance, scheduling epoch,
complete epoch-context identity, parent consensus hash and parent result in addition to the
network/session/transcript/height/finalized-chain anchor. Historical readers require header/R
byte equality and those exact context joins; the current exact QC authenticates execution's
full session verification. They do not claim to independently reconstruct a DKG session from
only the transcript binding. Empty control does not establish no demand: State execution checks
required and unsolicited pulses against the same pristine parent. Demand is consensus-native
only; governance state is not consulted.

The generic core/driver tests use an explicit no-demand application. They are not threshold
beacon or production finality qualification. Maintained native-network, message-loss, saturation,
all-seat restart and final-transaction gates must run on the connected implementation.
