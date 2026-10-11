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
   validity rule depends on a local clock.
6. **Cryptography.** EUF-CMA signatures with aggregation. Production: BLS12-381 in the min-pk
   setting, `iroha_crypto::Algorithm::BlsNormal` (public key = compressed G1 point, 48 bytes;
   signature and aggregate = compressed G2 point, 96 bytes). Proof-of-possession is checked by the
   application when a key enters a committee, so rogue-key attacks are excluded. Collision-resistant
   `H`. The simulator uses a fake scheme with identical interfaces and provenance tracking (§13).
7. **Execution.** `exec(S_{h−1}, B) → Valid(R, S_h) | Invalid` is a deterministic pure function of
   the committed parent state and the block; it terminates within a chain-parameter budget
   (`E_max`, enforced by gas/size limits). `R` is a 32-byte execution commitment (§4.1). A local
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
KIND_PROPOSAL = 0x01, KIND_PREPARE = 0x02, KIND_COMMIT = 0x03, KIND_TIMEOUT = 0x04, KIND_ECHO = 0x05,
KIND_ATTEST = 0x06; availability signatures use the separate domain of §12.8
Hash32 = [u8; 32]; ValidatorIndex = u32 (canonical index into C_h)

kb(pk)    = be16(len(raw)) ‖ raw    // raw: 48-byte compressed G1 point (production); 32 bytes (simulator)
keys(l)   = be32(len(l)) ‖ kb(l[0]) ‖ … ‖ kb(l[len(l)−1])
enc(None) = 0x00 ; enc(Some(w)) = 0x01 ‖ be64(w)     // optional view
opt(None) = 0x00 ; opt(Some(x)) = 0x01 ‖ x           // optional digest
bit(false) = 0x00 ; bit(true) = 0x01                  // flag byte
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
    attest: bool,                     // application payload/control flag (§3.7 A1);
                                      // checked by deterministic execution at every view
}
// AvailableBody is an opaque local custody owner (§12.8), not a wire-decoded struct.
// Its read-only accessors expose source(), header(), availability(), payload().
```

```text
block_hash = H(TAG_BLOCK ‖ I ‖ E ‖ be64(h) ‖ be64(origin_view) ‖ parent_hash ‖ parent_result ‖
               payload_hash ‖ availability_digest ‖ be32(payload_len) ‖ be32(proposer) ‖ keys(skipped_leaders) ‖ be32(control_len) ‖ control_witness ‖ bit(attest))
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
with no transaction entrypoints. Genesis is applied through its separate startup path. The flag `attest` belongs to the application (§3.7): the leader combines the payload and
control builders' flags, adds none of its own (not even at an epoch boundary), and execution
checks the application's exact rule (§4.2).

### 3.3 Signed messages and preimages

`E = be64(epoch) ‖ epoch_context_id` binds the scheduling epoch and the hash of its complete
canonical application context. The context commits to network, consensus mode, epoch bounds and
authorization, immutable authority generation, complete ordered BLS roster with verified proofs
of possession, and fresh authenticated leader randomness (§10). It contains no local certificate
or signer subset. Every header, vote, QC, timeout, TC and probe echo carries this identity;
verification requires equality with the authenticated context installed for that height.

```text
prop_preimage(h, v, bh, ad)      = TAG_SIG ‖ 0x01 ‖ I ‖ E ‖ be64(h) ‖ be64(v) ‖ bh ‖ ad
vote_preimage(kind, h, v, bh, R, a) = TAG_SIG ‖ kind ‖ I ‖ E ‖ be64(h) ‖ be64(v) ‖ bh ‖ R ‖ bit(a)
                                                         (kind ∈ {0x02, 0x03}; a = the block's `attest`)
tmo_preimage(h, v, hq)           = TAG_SIG ‖ 0x04 ‖ I ‖ E ‖ be64(h) ‖ be64(v) ‖ enc(hq)       (hq = view of the carried PrepareQC)
echo_preimage(nonce, height)     = TAG_SIG ‖ 0x05 ‖ I ‖ E ‖ be64(nonce) ‖ be64(height)        (probe echo, §3.5, §7.4 R2)
att_preimage(h, bh, R)           = TAG_SIG ‖ 0x06 ‖ I ‖ E ‖ be64(h) ‖ bh ‖ R                   (commit statement, §3.7; no view)

ad = att_digest(justify, parent_qc)
   = H(TAG_ATT ‖ opt(justify.map(tc_digest)) ‖ opt(parent_qc.map(qc_digest)))
qc_digest(c) = H(TAG_QC ‖ c.kind ‖ I ‖ E ‖ be64(c.height) ‖ be64(c.view) ‖ c.block_hash ‖ c.result ‖
                 be32(len(c.signers)) ‖ c.signers ‖ c.agg_sig ‖ bit(c.attest) ‖ witness(c.attestation_witness) ‖ blobs(c.attestations))
tc_digest(t) = H(TAG_TC ‖ I ‖ E ‖ be64(t.height) ‖ be64(t.view) ‖ be32(len(t.entries)) ‖
                 [be32(idx) ‖ enc(hq)] for each entry ‖ t.agg_sig ‖ opt(t.high_pqc.map(qc_digest)))
```

Domain separation: tag, kind, instance, scheduling epoch/context, height and view are in every consensus preimage; block
hash, result and the block's `attest` flag in every vote. There is no other consensus voting
object. The probe echo (kind `0x05`) binds the prober's nonce
and the replier's reported height, carries no sign-once obligation (a node signs one per probe it
answers), is never recorded, and cannot verify as a vote, proposal or timeout because of its kind
byte. The commit statement `att_preimage` (kind `0x06`) is not signed by consensus keys: the
application's attestor signs it (§3.7); its kind byte keeps it apart from every consensus object.
The original author's manifest and per-row authorizations use separate availability domains
(§12.8), signed by the original header proposer under the complete authenticated height source.
They are retained unchanged across re-proposals, publication and serving; later leaders do not
re-sign them. A proposal signature binds its complete header and QC/TC attachments. A
`ProposalMessage` additionally carries the mandatory original availability table. Corrupting
that carrier or an actual row cannot frame the leader for a different signed proposal.

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
    attest: bool,                  // the block's header flag (Prepare) or the lock's (Commit), signed
    signer: ValidatorIndex, sig: Signature,   // over vote_preimage(kind, h, v, bh, R, attest)
    attestation: Option<CommitAttestation>,  // Some iff kind == Commit ∧ attest: the signer's attestation of
                                   //   att_preimage(h, bh, R) (§3.7); not covered by `sig`
}
struct TimeoutVote {
    epoch: EpochId, // authenticated scheduling epoch and complete context
    instance: Hash32, height: u64, view: u64,
    high_pqc: Option<Qc>,          // the signer's lock at signing time; view ≤ self.view
    signer: ValidatorIndex, sig: Signature,   // over tmo_preimage(height, view, high_pqc.map(|q| q.view))
}
```

`witness(None) = 0x00`; `witness(Some(w)) = 0x01 ‖ be32(len(w)) ‖ w`.

### 3.4 Certificates

```rust
struct Qc {
    epoch: EpochId, // authenticated scheduling epoch and complete context                        // PrepareQC if kind == Prepare, CommitQC if kind == Commit
    kind: VoteKind, instance: Hash32, height: u64, view: u64,
    block_hash: Hash32, result: Hash32,
    attest: bool,                  // the certified block's flag (signed by every signer)
    signers: Bitmap,               // exactly ceil(n_h/8) bytes, bit i = canonical index i, spare bits 0
    agg_sig: AggregateSignature,
    attestation_witness: Option<ResultWitness>, // exactly one shared source iff flagged CommitQC
    attestations: Vec<AttestationSignature>,    // CommitQC with attest: one per signer, ascending index (§3.7);
                                   //   empty otherwise
}
struct TimeoutCert {
    epoch: EpochId, // authenticated scheduling epoch and complete context
    instance: Hash32, height: u64, view: u64,
    entries: Vec<(ValidatorIndex, Option<u64>)>, // strictly increasing index; hq view per signer
    agg_sig: AggregateSignature,                 // aggregate of the individual timeout signatures
    high_pqc: Option<Qc>,                        // the PrepareQC with view == max(entries.hq)
}
```

**verify_qc(qc, C_h)**: `qc.instance == I`; bitmap length exact and spare bits zero;
`popcount == q_h`; `AggVerify({pk_i : bit i set}, vote_preimage(kind, h, v, bh, R, a), agg_sig)`
with `a = qc.attest`; and the attestation rule A4 (§3.7): a CommitQC with `attest` carries
one attestation per signer that verifies, any other certificate carries none. Every PrepareQC
and CommitQC has exactly `q_h` equal validator votes, regardless of its attestation flag;
otherwise valid signer supersets are rejected. Different exact-quorum signer subsets remain
valid for the same authenticated value. The committee used is always
`C_{qc.height}`; a certificate for a height whose committee is not known is buffered (bounded,
§8.4) or dropped, never verified against another committee.

**verify_tc(tc, C_h)**: `tc.instance == I`; `len(entries) == q_h`; indices strictly increasing and
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
`(kind, h, v, block_hash, R, attest)`, using exactly those `q_h` (a CommitQC with `attest` carries
their attestations in signer order, §3.7). The QC formation API rejects larger input lists;
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
    VoteEquivocation(Vote, Vote),               // same (kind,I,h,v,signer), different (bh, R, attest)
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

Message sizes include complete authenticated epoch context and the declared Norito framing.
A proposal or manifest additionally carries the exact availability table of §12.8
(`4 + 96 + N·(32 + 96)` inner bytes, before its Norito envelope). Earlier estimates excluding
this mandatory table do not describe the wire size. A
Commit vote of a flagged block adds its attestation, and a CommitQC of one (also inside a
`Status`, a proposal's `parent_qc` or a sync entry) adds `q` attestations (§3.7); each is at most
`MAX_ATTESTATION_SIGNATURE_BYTES = 256` occupied bytes. Each vote carries its bounded
`ResultWitness` and compact signature. Each flagged CommitQC carries exactly one shared
`ResultWitness` of at most 64 KiB plus the ordered compact signatures. The only decoded witness
state is explicitly untrusted; admission copies or shares it into the original State resource
pool before native ingress retains it. Immutable clones retain the same actual backing/control
charges. The frame allowance includes the witness, compact signatures and bounded header/TC
metadata through the generic core committee bound.

The canonical execution-result witness carries each complete authorized epoch context once:
the current context, the optional boundary's next context, and its optional frozen preparation.
Each ready successor slot carries only its exact height and lag-two parameters, deriving its
epoch from the boundary's next context when present and otherwise from the current context.
Pending-boundary slots retain their explicit predecessor identity and boundary height. Encoding
rejects an owned ready slot that differs from its derivable context; decoding reconstructs and
validates the complete graph while charging the additional owned credentials to the inherited
decode allocation budget. This keeps supported 31-member boundary/preparation graphs within
the same 64 KiB witness limit, with no alternate or repeated-context result decoder.

### 3.7 Commit attestation (application extension)

Some blocks need more than consensus finality: KAGEMUSHA mint finality requires that `q`
validators' separately provisioned application authorities (paired Pasta keys, verified by a
recursive mint circuit without BLS) attest the committed block and result. The core supports this
generically and key-agnostically, as opaque bytes carried by Commit votes and CommitQCs, produced
and checked by two driver-supplied traits:

```rust
pub enum AttestOutcome { Attested(CommitAttestation), Pending, NoAuthority }
pub trait Attestor {             // the node's application authority (KAGEMUSHA in production)
    fn attest(&self, height: u64, key: &PublicKey, statement: &[u8]) -> AttestOutcome;
}
pub trait AttestationVerifier {  // every node
    fn verify(&self, height: u64, signer: ValidatorIndex, key: &PublicKey, statement: &[u8],
              witness: &ResultWitness, attestation: &[u8]) -> bool;
}
```

`attest` runs inside `handle`, like `Signer::sign`: local, non-blocking and deterministic (the same
inputs give the same `Attested` bytes). It answers `NoAuthority` iff the node holds no authority
for member `key` at `height`, and `Pending` while it lacks application data that the attestation
binds and only the node's own execution of `bh` provides (in KAGEMUSHA, `R`'s preimage; the
attestor learns it from the executor, never from the core). `verify` is a pure function of its
arguments and of committed application state known wherever `C_height` is known (the application
installs its complete committee and authority only through an applied certified epoch boundary, §10.1), never of local
execution: sync, `Status` and `parent_qc` verify certificates of blocks the node has not executed
(§6.8, §6.9). It MUST accept only an attestation that the authority of member `key` of `C_height`
produced over exactly `statement` (EUF-CMA). The statement is `att_preimage(h, bh, R)` (§3.3): it
binds `I`, `h`, `bh` and `R` but not the view, so an attestation stays valid in every view of its
block (re-proposals, restarts).

**Unique message.** An application MAY bind more than the statement (its network, its key
generation, the content of `R`'s preimage): the attestation then signs an application *message*.
That message MUST be determined by the statement and the committed state alone, and `verify` MUST
check it: every attestation it accepts for one statement at one height binds the same message. An
attestation that needs a preimage of a digest in the statement carries it, and `verify` re-hashes
it (`R`'s preimage → `R`). Then the attestations of every valid flagged CommitQC are `q` signatures
over one message, one application bundle, whichever members signed, and a Byzantine member cannot
get an attestation over another message counted (it is a different, unverifiable claim about the
same statement).

Rules (safety rules SR39–SR42 of §7.1, argument in §7.7):

- **A1 Flag.** The payload and control builders supply the block’s attestation requirement.
  Every fresh header uses `attest = payload_requires_attestation || control_requires_attestation`.
  The core adds no requirement of its own: an epoch boundary (`h == epoch.last_height`) is
  flagged exactly when its builders flag it, and an unflagged boundary block and its
  certificates are valid on every path (header checks, cached QCs, a TC’s carried PrepareQC,
  sync, R5, the restart tip and `BlockApplied`). `EMPTY` is a
  builder response only and has no block header or votes; every zero-length proposal is a
  signed defect at every view (§6.2 step 6). Execution checks the application's exact
  deterministic rule. Every vote signs the header flag (Prepare) or lock flag (Commit); every
  certificate retains that common flag.
- **A2 Attested Commit.** `try_commit` on a lock `Q` with `Q.attest` first asks the node's
  `Attestor` for `attest(h, key, att_preimage(h, Q.block_hash, Q.result))` and checks an
  `Attested` answer with its own verifier. `Attested` and accepted → the Commit vote carries the
  attestation. `Pending` → no Commit vote yet (no `persist()`, nothing signed) and no fault;
  `try_commit` runs again when the node's execution of the current proposal's block completes
  `Valid` with a flagged lock (§6.3 step 4), and at every stage raise. `NoAuthority`, or an
  attestation its verifier rejects (a misconfigured authority), → no Commit vote and
  `LocalFault(AttestationUnavailable{height, view})` once per view. The own vote is pooled
  without further checks (§6.0), so this check keeps every certificate a node forms valid (SR38).
  Prepare votes, timeouts, aggregation and every other rule are unaffected.
- **A3 Counting.** A vote is well formed only if `attestation` is present exactly when
  `kind == Commit ∧ attest`. A Commit vote with `attest` enters a pool (§6.4 step 4) only if
  `verify(h, signer, C_h[signer], att_preimage(h, bh, R), witness, signature)` holds. A malformed vote,
  or one whose attestation does not verify, is dropped with no state change and no evidence: a
  relay can strip or corrupt the unsigned attestation, and the signer's retransmission still
  counts. Votes aggregate only with identical `(bh, R, attest)`; two votes of one signer at
  `(kind, h, v)` that differ in `attest` are equivocation (§3.6).
- **A4 Certificate.** A PrepareQC and a CommitQC without `attest` carry no attestations. A
  CommitQC with `attest` has exactly `q_h` signers (`popcount(signers) == q_h`) and carries `q_h`
  attestations in ascending signer order, the `i`-th verifying for the `i`-th signer under
  `C_{qc.height}` over `att_preimage(qc.height, qc.block_hash, qc.result)`; formation (§3.4) uses
  exactly `q_h` pooled votes, rejects differing witness bytes, retains one witness owner and
  copies their compact signatures. Only a Byzantine aggregator forms a
  larger one, which is rejected like a withheld one: the application's bundle (one message, `q_h`
  seals, as the KAGEMUSHA mint verifier requires) is then the certificate's attestations, with no
  choice of subset. `verify_qc` checks this on every path that verifies a certificate, and
  `qc_digest` covers the flag, exact optional shared witness bytes and the compact attestations, so the verified-certificate cache (§6.1 rule 5) cannot admit a
  stripped copy. Only the safety monitor (§7.6) checks the Commit signatures alone. A caller that
  holds the certified header also checks `qc.attest == header.attest` (sync entries, §6.9 rule 3;
  light clients, §11).
- **A5 Liveness.** A member that cannot attest at `h` counts as faulty at `h` for flagged blocks
  (§8.1): a flagged block commits only if at least `q` members of `C_h` are honest, running and
  able to attest. A `Pending` member is not faulty: its attestation follows its own execution,
  which after GST ends within `E_max` (§8.2 L4); a member that never receives the proposal of the
  lock's view attests the re-proposal of a later view. A locked flagged block is re-proposed by
  the TC rule, so a height whose flagged block was locked commits nothing else. The application MUST therefore provision attestation
  authority for every member it schedules into a committee, and flag nothing while fewer than `q`
  could attest. An application without attestation authority (`NoAttestation`) flags nothing;
  every height, epoch boundaries included, then commits without attestations.

Why the flag is signed and not only in the header: a member Commit-votes on a PrepareQC alone
(§6.5) and a node commits on a CommitQC alone (§6.8), often before either holds the header. With
the flag in every vote preimage, every valid certificate carries the true flag of its block (it has
an honest signer, §7.7), so each node knows whether attestations are required without the header.
With a header-only flag, a Byzantine aggregator could present a flagged block's CommitQC, stripped
of its attestations, as unflagged to every node that lacks the header.

*KAGEMUSHA mapping (informative).* The `Attestor` is the validator's
`KagemushaMintFinalityLocalAuthorityV1`. The seal message binds the network, the authority
generation and epoch authorization, the height, the digests of `bh` and of the execution
commitment, and the top-up root and count. The last three come from `R`'s preimage, the node's
`ExecutionResultCommitment` (`R = H("iroha/sumeragi/result/v1" ‖ preimage)`, §4.1), which travels as a bounded opaque immutable core witness. Hence:

- A vote carries `(ResultWitness, compact paired seal)`; a QC stores the witness once.
  The seal is 132 bytes: big-endian seat index, then Eq nonce/response and Ep nonce/response.
  The witness codec has one canonical byte-sequence layout; ownership state is never on wire.
- The attestor takes the preimage from its node's own execution of `bh` and uses it only if it
  hashes to the statement's `R`; it answers `Pending` until then (A2), and forever on a divergent
  executor (which reports `ExecutionMismatch`, §4.2).
- The verifier decodes canonically and re-hashes the preimage to the statement's `R`. From the
  preimage, `bh`, `h` and the authority generation scheduled for `h` it derives the one expected
  seal message, requires the carried seal to be over exactly it, and verifies the seal under the
  validator's Pasta keys from that generation (keyed by the consensus key). No local execution
  is needed, so sync and `Status` verify flagged certificates of unexecuted blocks.

The node's builder flags every payload containing a top-up and, as its own application rule
(the core does not require it, A1), every NPoS epoch boundary. Every
proposal carries nonempty work; an empty builder response is never proposed. A rejected top-up still needs a real source-complete seal: its canonical empty tree and
zero leaf count authorize no mint. Genesis bootstrap stays unsigned and cannot be an ordinary
zero-leaf finality receipt. Every native seal binds the domain-separated complete core statement
(instance, scheduling epoch/context, height, block hash and R), the exact authorization and
immutable Pasta generation carried in R, the leaf projection and optional next authorization.

The process-lived native worker is the sole publisher of local signing receipts. It checks the
retained original result, exact canonical preimage and separately admitted witness against the
same pool, then retains its actual signed receipt across mailbox contention. Only publication
permits `Valid`, Prepare/certificate publication and application. Discard clears the receipt
before releasing the source. The mailbox and its lock-release control are prepaid together
from the original State pool. Contention carries that mailbox's pre-probe release observation;
an unrelated lock cannot release it, and every actual mailbox guard signals only after unlocking.
Native mutex storage, pending waiter registration and release-driven scheduling remain separate
qualification obligations. A stateless `NativePastaVerifier` independently reconstructs this
message; no node-local execution cache supplies historical verification authority.

---

## 4. Execute-before-vote

### 4.1 What is executed and what is bound

- A committee member executes a proposed block `B` at height `h` against `S_{h−1}`: the applied
  state (after `BlockApplied(h−1)`, §12) or, earlier, the executor's cached post-state of the
  committed parent block. The core allows the latter only when this node executed that parent and
  obtained exactly the certified result (`tip.exec_ok`, §6.8), so durable apply of the parent is
  not on the vote path. If the driver no longer holds that post-state (evicted, lost on restart)
  it recomputes it; a missing cache entry is never a verdict (§12.3 O4). Execution is requested by
  `Action::Execute { block, req }` and answered exactly once by
  `Event::Executed { block_hash, req, outcome }`,
  `outcome ∈ {Valid(R), Invalid, Failed, Cancelled}`; `req` is a per-core request counter, so an
  answer to a request the core has since discarded never matches a live entry (§6.3).
- `R` is the application's 32-byte execution commitment. It MUST commit to everything the chain
  must agree on for that block: at least the post-state root, the root of per-transaction outcomes
  (accepted/rejected + reason), the event root, and the height configuration scheduled by this
  block (`C_{h+2}` and chain parameters, §10). The core treats `R` as opaque. After G.3, `R` binds
  `parent_keyed_state_root = root(P_{h−1})` and the post-execution
  `keyed_state_root = root(X_h)`, as specified in §16; until then E51 describes the as-built
  behaviour.
- The Prepare vote, the PrepareQC, the Commit vote and the CommitQC all sign
  `(I, h, v, block_hash, R)`. A CommitQC therefore finalizes order **and** result. The next
  block's header repeats the certified `R` as `parent_result`.

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
  apply, the apply path detects the divergence and halts that instance (§12.5).
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
- **Application flag.** `exec(S_{h−1}, B)` is `Invalid` when `B.header.attest` differs from the
  application's deterministic flag rule (§3.7 A1).
  Zero-length payloads are invalid at every height. A flagged block is otherwise executed like any other; the attestations are
  checked by the vote and certificate rules, never by `exec`.

### 4.3 The complete Prepare-vote predicate (no local refusal reasons)

An honest committee member of `C_h` signs `Prepare(h, v, bh, R)` (with `attest` = the proposal
header's flag, §3.7) iff **all** hold:
1. it is in round `(h, v)`, has a signing key at `h` (§7.4), and `timeout_view < v` (it has not
   timed out view `v` or later);
2. it has not signed a Prepare at `(h, v)` (sign-once record);
3. it holds a Proposal for `(h, v)` that passed §6.2 (signature, leader, attachments, header, TC
   rule), whose body it holds (`body_ok`) and has handed to `StoreBody`;
4. `Executed(bh) = Valid(R)`, and if `bh` is certified, `R == Q.result`;
5. it is in set A of `(h, v)`, or its stage for `(h, v)` is ≥ 1 (§5.2).

Nothing else may gate a vote: not load, queue state, mempool contents, recovery state, peer
connectivity, disk pressure, clock readings, other instances, or a local lock (there is no
voter-side lock check; §7.3 explains why the TC rule makes it unnecessary for safety and why it
would harm liveness). Slowness only delays conditions 3–4; the vote is still sent when they become
true, as long as condition 1 holds.

### 4.4 Why this does not reintroduce the v2 common-mode stall

The v2 root cause was that votes depended on each node's local conditions, so one bug or one
slow resource stopped every honest node at once. Here:
1. **Value dependence is deterministic.** The only data-dependent input is `exec`, a pure function
   of committed data. A deterministic "Invalid" verdict is shared by all honest nodes and costs
   one view (early timeout, next leader; the leader of that view is recorded as skipped), and
   `PayloadRejected` lets builders drop the culprit transactions. Progress requires available
   valid work and a functioning deterministic executor; empty blocks never conceal an executor
   defect or missing attestation authority.
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
    attestation: Attestation,            // the node's attestor and the attestation verifier (§3.7)
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
     `payload_len > 0` at every view, including certified re-proposals (§3.7 A1).
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
`Execute{block: blocks[bh], req}`.

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
4. `try_prepare()`; then, after `Valid` and with a flagged lock (`high_pqc.attest`), `try_commit()`:
   an attestor that answered `Pending` may need exactly this execution (§3.7 A2).

`try_prepare()`: if the §4.3 predicate holds for `proposal` (condition 3 includes
`proposal.view == view`; condition 2 is `safety.prepare` having no entry at `view`):
```text
a = proposal.header.attest
safety.prepare = Some((view, bh, R, a)); persist()
vote = sign(Prepare, h, view, bh, R, a); mine.prepare = vote
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
   `(bh, R, attest)` → drop; different → `ReportEvidence(VoteEquivocation)` (deduplicated), drop.
   Then §3.7 A3: a malformed vote, or a Commit vote with `attest` whose attestation does not
   verify, is dropped.
4. `pool_insert(x)`: insert (only votes verified in step 3, or the node's own, ever enter a pool).
   If `x.view == view`, `me ≠ P` and the pools of view `view` now hold votes from ≥ `f+1` distinct
   signers other than `me`: enter stage 2 (§5.2 contagion). If the pool now holds `q` votes with
   identical `(kind, view, bh, R, attest)` and no QC of that kind and view is held: form the Qc from
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
if Q.attest:                                                // §3.7 A2
    s = att_preimage(h, Q.bh, Q.R)
    match attestor.attest(h, keys[signer], s):
        Pending: return                                     // again after §6.3 step 4 or a stage raise
        Attested(att) if verifier.verify(h, idx(me), keys[signer], s, att): pass
        otherwise: LocalFault(AttestationUnavailable{h, view}) (once per view); return
persist()                                                   // writes lock = Q (SR25)
vote = sign(Commit, h, view, Q.bh, Q.R, Q.attest) with attestation att; mine.commit = vote
route(vote); pool_insert(vote); t_lastvote = now
```
A Commit vote does not require local execution of the block, nor its header: the flag comes from
the lock. (An attestor may: a KAGEMUSHA authority answers `Pending` until the node's execution
gives it `R`'s preimage, §3.7 A2, so at a flagged height a slow executor also delays its Commit.) There is no separate "commit"
entry in the record: a Commit at `(h, v)` is always for the lock of view `v` (unique per view by
Lemma 1 and never replaced within a view, §6.5 2a), and that lock is durable before the vote
leaves (SR25). After a restart, `try_commit()` may sign it again; the preimage and, with
deterministic signatures, the bytes are identical, and so is a deterministic attestation (§3.7).

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
   always continues the contiguous buffered prefix. A request unanswered by its deadline counts
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
   `block_hash(manifest.header) == c.block_hash`, `c.attest == manifest.header.attest` (§3.7 A4),
   mandatory structurally valid availability table, consecutive heights. The entry
   for the current `h` additionally needs `C_h` known, `verify_qc(c, C_h)`,
   `header.parent_hash == tip.block_hash`, `header.parent_result == tip.result` and the exact
   scheduled epoch. Without body custody the entry
   remains buffered, creates a want and starts source-bound acquisition; it cannot advance sync
   merely from the signature table. Once custody is held it runs §6.8 (commit, enter the next
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
   `min(2^(attempt+1), |sources|)` peers cyclically. The driver first starts or resumes a typed
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
   nonempty payload, exact control witness, proposer, skipped leaders and the combined
   payload/control attestation flag from §3.7 A1. Core emits `AuthorPayload` with
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
  1. Re-send `mine.timeout` by broadcast if `timeout_view == Some(view)`.
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
  whichever of them a peer's rate limit admits is answered.

On `Status s` from peer `p` (`p` is the authenticated sender, §1.4), in this order:
1. **Echo** (exempt from the rate limit). If `s.echo = Some(e)`, `e.nonce == nonce`, some key is
   unanchored, `C_{tip.height+2}` is known, `e.key` is a member of it and not one of this node's
   keys, and `probe` holds no entry for `e.key` at or below `s.height`: verify `e.sig` under
   `e.key` over `echo_preimage(nonce, s.height)` (§3.3); on success `probe[e.key] = s.height` and
   check anchoring (§7.4 R2). The reply is fresh (it echoes a nonce drawn at this `Init`) and the
   signature, not the channel, identifies the member, so a relayed copy counts for its signer.
   Nothing else in `s` is exempt from the rate limit.
2. **Proposal request** (exempt from the rate limit). If `s.want_proposal`, `(s.height, s.view)
   == (h, view)` and this node leads `(h, view)`: apply the late-entrant re-push (capped at once
   per member per view).
3. **Rate limit.** The rest of a `Status` is processed for at most one `Status` per peer per
   `rebroadcast_interval / 2`; for any other `Status`, stop here — except that its
   `committed_qc` alone is still used (§6.8 for height `h`, §6.9 above it) if its height is
   `≥ h` and above every `committed_qc` height processed from that peer (at most two extra
   verifications per peer and height): the §6.1 rule-3 reply that carries the CommitQC a
   lagging voter lacks often follows the peer's periodic `Status` within the window.
4. Record `(p, s.height, s.view, s.proposal_hash)` in `peers`. If `s.probe = Some(x)`, the node
   has a configured key, and none of its keys (retired ones included) is unanchored or abstaining
   at the current height (R2, R6): `Send(p, our Status with echo: Some(Echo{nonce: x, key, sig}))`
   (at most once per peer per `rebroadcast_interval`), where `key` is its signing key at `h`
   (`keys[signer]`), else its first configured key, and `sig = sign(echo_preimage(x, height))`
   over the `height` of that `Status` (across a key rotation a reply may name a key that is not
   in the prober's `C_{t'+2}`; it then does not count, and replies after the change height do).
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
  Its certified header carries only its application's flag (§3.7 A1). `next` starts at `B+1`, has epoch number incremented
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
| SR39 | Attestation flag: every vote signs its block's `attest` (Prepare: the header's; Commit: the lock's), a fresh header carries exactly the payload/control builders' combined flag (the core adds none, SR46), every proposed payload is nonempty at every view, and a restored Prepare carries its recorded flag | §3.7 A1, §6.2, §6.10, R4 | MA6, MA7, MA8, MA9 |
| SR40 | Attested Commit: a Commit vote on a flagged lock is signed only with the node's attestation, checked by its own verifier; a node that cannot attest does not Commit-vote there, and one whose attestor is `Pending` asks again after its execution of the block | §3.7 A2, §6.3, §6.5 | MA5, MA10, MA12 |
| SR41 | Attestation counting: a Commit vote with `attest` is pooled only with an attestation that verifies for its signer | §3.7 A3, §6.4 | MA1 |
| SR42 | Attested certificate: a flagged CommitQC is valid only with exactly `q` signers and one verifying attestation per signer over `att_preimage(h, bh, R)`, which binds `I`, `h`, `bh` and `R` | §3.3, §3.7 A4 | MA2, MA3, MA4, MA11 |
| SR43 | An original publication that cannot safely retry halts the local instance without new execution or signing; reversible refusal retains its original owner | §12.3 O3, §12.5 | MS42 |
| MS43 | `put_epoch` — omits scheduling epoch and complete context from all domains | `det_s43_every_signature_binds_epoch_and_complete_context` | — | O-SIGN |
| MS44 | `applied_config_updates` — accepts an early next-epoch lag-2 config | `det_s44_lag_two_cannot_install_next_epoch_early` | — | O-CERT |
| MS45 | `request_authoring` — imposes a mandatory flag at `h == epoch.last_height` (the retired boundary rule) | `det_s45_unflagged_boundary_commits_without_attestation`: n=4, the core under `NoAttestation`, boundary at height 1 → the boundary leader proposes the builders' unset flag, Commit-votes without `AttestationUnavailable` and commits; a remote leader's unflagged boundary proposal is Prepared with no evidence; sync crosses the unflagged boundary; a restart from its unflagged tip `CommitQC` resumes; each case enters the next epoch. `det_s45_boundary_proposal_carries_only_the_builders_flag`: at views 0 and 2 an empty boundary build never becomes a block and the nonempty proposal carries exactly the builder's flag | — | O-ATT |
| MS46 | header hash omits control bytes | `det_s46_control_witness_is_bound_by_header_hash_and_proposal_signature` | — | O-SIGN |
| MS47 | real work invents an absent authenticated control response | `det_s47_nonempty_work_waits_for_independent_control_and_preserves_attestation` | — | O-LIVE |
| MS48 | control completion accepts another exact source | `det_s48_control_response_requires_exact_request_epoch_view_and_parent_source` | — | O-SIGN |
| SR44 | All signatures and certificate/header hashes bind the installed scheduling epoch and complete context | §3.3, §10 | MS43 |
| SR45 | Authority activation is atomic only after its certified predecessor boundary is applied | §6.13, §10 | MS44 |
| SR46 | The core adds no attestation requirement: an epoch boundary carries only its builders' flag, and an unflagged boundary block and its certificates are accepted on every path (header checks, certificate cache, TC, sync, R5, restart tip, `BlockApplied`) | §3.7 A1, §6.13, §10 | MS45 |

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
    key: PublicKey,                                  // the consensus key this record belongs to
    height: u64,                                     // round height the record describes
    parent_commit_qc: Option<Qc>,                    // CommitQC of height − 1 (None at g + 1)
    proposal: Option<(u64, Hash32, Option<TimeoutCert>)>, // (view, bh, justify) of the last proposal signed
    prepare: Option<(u64, Hash32, Hash32, bool)>,    // (view, bh, R, attest) of the last Prepare signed
    timeout: Option<(u64, Option<Qc>)>,              // (view, exact PrepareQC carried) of the last timeout signed
    lock: Option<Qc>,                                // high_pqc at write time; also the record of every Commit (§6.5)
    high_tc: Option<TimeoutCert>,                    // high_tc at write time (the certificate that justified the view)
}
```
Norito-encoded, followed by `H(encoding)`; the driver keeps one file per `(instance, key)` and
writes it atomically (temp file, fsync, rename, fsync dir). Size ≤ ~3 KB at n = 31. Nothing else is
persisted by the core; the block bodies it relies on are written by the driver on `StoreBody`.
Votes, pools, pacemaker level and routing stage are re-derived or re-fetched.

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
1. **R1** For every key: `Present` but checksum/decode fails, or `instance`/`key` mismatch →
   `Halt(SafetyRecordCorrupt)`.
2. **R5** If some `Present` record has `height == t + 2` (the block store lost the last commit: a
   crash after entering `t+2`, before the apply of `t+1` was durable): verify its
   `parent_commit_qc` under `C_{t+1}` as a CommitQC for `t + 1`; failure →
   `Halt(SafetyRecordInconsistent)`. On success commit it (§6.8 steps 2–3: `tip` becomes `t + 1`;
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
   re-sent proposal). Otherwise restore from it: `proposal`, `prepare`, `timeout`, `lock`, `high_tc` into `safety`;
   `high_pqc = lock`; `high_tc = record.high_tc`; `timeout_view = timeout.view`; `mine.timeout` =
   the timeout rebuilt from the recorded `(view, carried QC)` (re-signing an identical preimage
   gives identical bytes, §12.1); `view` = the maximum of `proposal.view`, `prepare.view`,
   `timeout.view`, `lock.view` and `high_tc.view + 1` over the entries present (0 if none; the
   views of `parent_commit_qc` and of certificates nested inside entries are not used); timers
   start at `now`. The recorded timeout is re-sent at the first rebroadcast and a recorded Prepare
   of the current view on the retransmit schedule with `t_vote = now`; `try_commit()` is called
   (it re-signs the identical Commit if the lock is of the current view; for a flagged lock whose
   attestor answers `Pending` after the restart, once the node has executed the block again, §3.7 A2); a recorded proposal is
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
  only on a mismatch, and it checks the Commit signatures alone, not the attestations (§3.7 A4):
  `q` Commit signatures on another value already prove the violation. CommitQCs for older heights
  are dropped (§10.7).
- Nothing else is monitored. Conflicting certificates of the current, uncommitted height are
  never even verified (a second PrepareQC of a view already locked is cheap-rejected, §6.1 rule
  5); forensics for them are the application's (§14.6).

### 7.7 Commit attestation: safety argument

The extension of §3.7 changes no rule that §7.5 relies on. It adds data (attestations) that no
safety rule reads, one signed byte (the flag), and one more reason not to Commit-vote.

1. *Agreement is unchanged.* The flag is part of the signed value, and `bh` binds the header, so
   every honest vote on a block carries that block's true flag, and two votes of one value agree
   on it. Lemma 1 and the theorem of §7.5 therefore hold with the value `(bh, R)` exactly as
   before: a Byzantine vote with a wrong flag is a different preimage, which never aggregates with
   honest votes (§3.4, A3) and is evidence if its signer also signed the true one. A2 only withholds
   Commit votes, which is indistinguishable from a crashed voter; SR25's lock durability, the
   timeout fence and the TC rule are untouched. The attestation is not in the safety record, and
   a restart re-creates the identical Commit (A2 with a deterministic `Attestor`); a
   non-deterministic one yields a vote that differs only in unsigned bytes, never an equivocation.
2. *Certificates carry the true flag.* Let `c` be a valid CommitQC for a block `B`. It has an honest
   signer `s` (`q − f ≥ 1`), which Commit-voted with the flag of its lock `Q`, a valid PrepareQC of
   `c.view` for `(B, c.result)`, so `c.attest == Q.attest` (they are one signed byte). `Q` has an
   honest signer `p`, which Prepared the proposal it held, whose header hashes to `B`, with that
   header's flag. Hence `c.attest == B.header.attest`, whatever the aggregator did: a Byzantine
   aggregator cannot present a flagged block's CommitQC as unflagged, nor the reverse.
3. *No flagged commit without `q` attestations.* An honest node accepts a CommitQC `c` only through
   `verify_qc` (every path of SR21 and sync, A4) or by forming it (SR38). By (2), if `B` is flagged
   then `c.attest` holds, so `verify_qc` requires exactly `q` signers with one attestation each,
   verifying for its signer over `att_preimage(h, bh, R)`. A formed `c` takes its attestations
   from pooled votes, which A3 admitted only with verifying attestations, and from the node's
   own vote, whose attestation its verifier accepted before the vote was signed (A2). By the
   verifier's EUF-CMA property (§3.7) these are `q` attestations produced by the authorities of
   `q` distinct members of `C_h` over exactly `(I, h, bh, R)`, at least `q − f` of them honest.
   A Byzantine aggregator can strip, reorder, forge, replay or add attestations only to make its
   certificate invalid (an over-aggregated one has more than `q` signers). An attestation from
   another instance, height, block or result does not verify, because the statement binds all
   four; one made in another view does verify, and it attests the same fact.
   By the unique-message rule (§3.7) the `q` attestations sign one application message, so the
   certificate is one application bundle; a Byzantine attestation over another message (another
   top-up root under the same `R`) does not verify and is not counted (A3).
4. *Honest nodes never count an unattested Commit vote for a flagged block.* By A3 such a vote is
   dropped before it can enter a pool, and only pooled votes are counted, trigger contagion or form
   certificates. Relays can therefore not front-run an honest vote with a stripped copy either:
   the copy leaves no state behind.
5. *Liveness* is the only cost: a flagged block needs `q` honest, running members that can attest
   (A5, §8.1), and an attestor that needs `R`'s preimage waits for its node's execution (A2).
   The core adds no flag of its own (A1), so an application that flags nothing, epoch
   boundaries included, never pays it; an unflagged boundary is certified like any other block,
   and SR45's activation barrier, not an attestation, orders the successor epoch. A
   Byzantine member can withhold or forge its attestation, which removes one attestor, exactly as
   withholding its Commit vote would. `Pending` withholds a Commit vote only until the execution
   ends, and never signs anything, so it changes no safety argument above.

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
counts as faulty at `h`, and a member that cannot attest at `h` counts as faulty at `h` for a
flagged block (§3.7 A5); honest-to-honest delay `≤ Δ` for every
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
  `σ + build_timeout + 3Δ + F + A_max + E_max ≤ φ·T`; at a flagged height a `Pending` attestor is
  asked again at that `Executed` (§6.3 step 4), so every honest attesting member Commit-votes within
  the same bound after the PrepareQC reaches it. If every set-A
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
| Member that cannot attest (no authority, forged or withheld attestations) | its Commit vote on a flagged block is not sent or not pooled (§3.7 A2, A3); set B and stage 1 supply the missing Commit votes, as for a silent set-A member; a slow executor whose attestor is `Pending` Commit-votes when its execution ends (§6.3 step 4) | as a silent set-A member, at flagged heights only; below `q` attestors a flagged height halts (A5) |
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
| `max_block_bytes` | chain | 4 MiB | 4 MiB |
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
| `sync_max_bytes` (≥ `max_block_bytes` + `FRAME_OVERHEAD`) | local | 16 MiB | 16 MiB |
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
`block_time > payload_retry_interval`, `payload_retry_interval == 0`, or `max_block_bytes` above the
transport limit (§12.3 O10). `Δ_nom` must cover manifest and complete encoded-row delivery for
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
   certified by the current authority's exact-quorum CommitQC; the core requires no
   attestation there (§3.7 A1). Only the
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
   or slashing obligations before authenticated replacement. Current and pending credentials
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
   old keys does not confer forward security. This rule is not a committee override.
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
height `h` when `(h + 1) % epoch_length_blocks == 0`, or when committed Parliament state
requests that slot. A pulse is bound to the exact network, active public DKG session, scheduled
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
   `e` it has verified with `C_{J,e}`, and also `C_{J,e−1}`. It accepts a foreign CommitQC for height
   `x` only if `epoch(x) ∈ {e − 1, e}` and `verify_commit_qc(I_J, C_{J,epoch(x)}, qc)` holds. To
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
`verify_commit_qc(verifier, instance, &Committee, &Qc, Option<&BlockHeader>) -> bool` for
foreign-instance light verification (the attestation verifier and the certified header, when the
caller holds it, serve §3.7 A4).

**As built.** The global chain's side runs in the node; the dataspace side is a tested component
that no node hosts yet (§14, item 3). Choices beyond the rules above are Appendix E, E58 (node)
and E59 (simulator).

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
  The mandatory native context archive retains the global executor's complete original write
  sets. `iroha_core::sumeragi::amx::amx_record_proof` authenticates the exact historical carrier
  and archive root before serving records, including after deadline pruning and certified
  replay. Dataspace executor archive integration and complete proof-graph resource qualification
  remain open.
- *Tracker* (`AmxForeignInstanceV1`, item 7): the complete authenticated contexts `C_{J,e}` and
  `C_{J,e−1}`. A certified block verifies only if its header's epoch is one of them and contains
  its height, exactly `q` members of that epoch's committee signed the `CommitQC` (the core's
  `verify_qc_signatures`), and the result preimage hashes to the certified `R` and names that
  height and context. A handoff proof is the certified last block of `e`: the boundary decision in
  its result preimage, validated against `C_{J,e}`, names `C_{J,e+1}`.
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
  The same proof can retry against the original escrow. Native participant graph funding,
  daemon hosting of independent State owners and production escrow installation remain open.
  Root startup derives its Kura and configured chain identity from the original State; callers
  cannot supply a second store or chain identity. Component tests run separate signed
  Permissioned/Bootstrap dataspace roots through the production driver, with full-width IDs,
  independent pools/stores, scoped PipelineGas payments and certified replay. These do not
  qualify daemon multi-root hosting, parent-Nexus fee settlement, or queue/transport owner
  affinity. Foreign network inputs still require original-root validation before execution.
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
               attestation: Attestation, body_budget: AllocationBudget, now: Millis)
               -> Result<(Core, Vec<Action>), ConfigError>;  // applies R1–R6 (§7.4)
    pub fn handle(&mut self, now: Millis, event: Event) -> Vec<Action>;
    pub fn next_wakeup(&self) -> Millis;                   // earliest deadline; driver sends Tick
    pub fn status(&self) -> CoreStatus;                    // read-only diagnostics (height, view, level, stage, t_retx,
                                                           //   leader and proxy tail of (h, view), high PrepareQC view, footprint)
}
pub struct Attestation { attestor: Box<dyn Attestor>, verifier: Box<dyn AttestationVerifier> } // §3.7
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
        attest: bool,
    },
    PayloadAuthored {
        req: u64,
        body: AvailableBody,
    },
    ControlWitnessBuilt {
        req: u64,
        context: ControlWitnessContext,
        witness: crate::types::ControlWitness,
        attest: bool,
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
pub trait Signer: Send + Sync { fn public_key(&self) -> &PublicKey; fn sign(&self, preimage: &[u8]) -> Signature; } // deterministic
pub trait Crypto {                                  // pure; BLS in production, fake in the simulator
    fn hash_chunks(&self, chunks: &[&[u8]]) -> Hash32; // required; exact concatenation without bulk copy
    fn hash(&self, bytes: &[u8]) -> Hash32 { self.hash_chunks(&[bytes]) }
    fn verify(&self, pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool;
    fn aggregate(&self, sigs: &[Signature]) -> AggregateSignature;
    fn verify_aggregate(&self, pks: &[&PublicKey], msg: &[u8], agg: &AggregateSignature) -> bool;
    fn verify_aggregate_multi(&self, groups: &[(Vec<&PublicKey>, Vec<u8>)], agg: &AggregateSignature) -> bool;
}
// Attestor (answers AttestOutcome: Attested(CommitAttestation) | Pending | NoAuthority) and AttestationVerifier: §3.7.
```
`Signer::sign` runs inside `handle` and MUST be local and non-blocking (an in-memory key or a
local device with bounded latency); a remote signer would block the core and its timers. It MUST
be deterministic (same key and preimage → same bytes; BLS signatures are): the core re-creates
recorded messages after a restart by signing their recorded preimages again (§6.10 rule 0, §7.4).
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
as `Failed`, the applied header in `BlockApplied`, the application side of commit attestation
(§3.7): the builder's flag, the executor's flag check, the node's `Attestor` and the
`AttestationVerifier`, and signed RS16 payload availability (§12.8): proposals include mandatory original availability metadata, actual bytes travel as signed
rows, and Core receives only opaque `BodyAvailable`/`PayloadAuthored` custody. Core emits
`StoreBody`; O2 makes durability a prerequisite for later signature effects, not an attribute
asserted by a decoded manifest. One core instance per consensus instance; instances share nothing inside the core and
are isolated by the driver (O9).

A new request may borrow the exact completed nonempty global payload while its original
State-funded backing and selected-input table remain live. This requires the same applied
native parent, State publication generation, height, view, byte limit and execution budget;
every request first reads and authenticates the physical canonical parent. The actual Queue
mutation fence captures the original ownership generation before selection and binds every
selected signed input to that same admission boundary, checks
that every input is still pending and unexpired, and refuses reuse after any insertion or
removal. The earliest actual selected-input expiry bounds physical retention; the Worker
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

A retained partial global builder must pass those fresh parent and current-scope checks
before returning its first completed output. Its signed lane merge section must equal the
current proposal from the actual lane journals, including its time floor; newly mandatory
lane work withdraws the old plan. Every selected Queue input, including in a mixed payload,
retains its original admission receipt before encoding. Queue mutation, actual expiry or
completed State publication withdraws that receipt, so a later request rebuilds from current
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
  `sync_max_bytes`; the driver checks this at startup against the committed chain parameters.
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
1. a corrupt local safety record, a recorded parent CommitQC that does not verify (R1, R5), or a
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
   `CommitQC`, which must be a Commit certificate of this height, block hash, `R`, `attest` flag
   and instance `I`, and verify under `C_height`. The complete ordered keys and BLS proofs of
   possession of `C_height` are retained in `next_committee` in the preimage of `R_{height−2}`.
   Verification starts from the signed genesis registrations and iteratively authenticates each
   preceding certificate, result preimage, executed-wire identity and both parent links. A
   scheduling result cannot authenticate itself with the authority it proposes. The reader
   retains only its current parent and two upcoming authorities, so rotated-away committees
   need neither a live World registration nor an unbounded historical key cache. Verification is
   pluggable: by default full source-complete native Pasta verification. A caller can explicitly
   pass an application `AttestationVerifier` (§3.7); no absent-verifier signature-only fallback
   authenticates a flagged certificate. `walk` also checks that each block extends the previous one (core
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
incumbent mint-finality authority from the signed genesis metadata in World
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
| O-ATT | (F37) Commit attestation (§3.7): every CommitQC with which an honest node commits a flagged block carries the flag, exactly `q` signers and one attestation per signer, each produced by that signer's authority (ground truth) over `att_preimage(h, bh, R)`; no honest node sends a Commit vote for a flagged block without its attestation. |
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
commit attestation (§3.7): a share of the transactions requires mint finality, so the builder
flags their blocks; every authority attests only blocks its node executed (`Pending` before, as a
KAGEMUSHA authority needs `R`'s preimage); up to `f` Byzantine members forge or withhold their
attestations, a Byzantine proxy tail strips the attestations of the CommitQCs it forms and clears
their flag, and it over-aggregates the genuine attested votes it receives into `q + 1`-signer
CommitQCs; one honest member has no attestation authority (or a misconfigured one) while `q`
members still attest; on every other seed one attesting honest member executes non-empty blocks
slowly (the PrepareQC often reaches it before its execution ends) → O-ATT, O-LIVE · F38 a lane
instance next to the global one (`specs/sumeragi_lanes.md` §4.1): the lane's pinned committee is
four of the global validators, every other machine follows the lane as an observer (a node runs
every instance), the lane stalls while the global instance keeps finalizing, and a global validator
that only observes the lane crashes and restarts → every replica of both instances, observers
included, commits after the lane recovers (O-LIVE, O-AGR).

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
| MS33c | `restore` — keys processed one by one in configuration order, each R4/R5 overwriting the round (no composition) | `det_s33_key_rotation_restart` (b): store tip t, K2 (listed first) with a record at t+2, K1 with a record at t+1 → start in round t+2 from K2's record, exactly one `CommitBlock` for t+1, the tip never moves back | F28 with R4/R5 splits | O-AGR, O-SIGN |
| MS33d | fake driver record store — the store-id comparison deleted (a rolled-back log is trusted: a key it lists as generated on this node gets an initial record for every instance the log lacks) | `det_s33d_installation_log_rollback`: key K generated on X; dataspace instance I created later (initial record, `(I, K)` entry, new store id); X Prepares B at (t+1, 0) for I, block store at t; X's key store is restored from a snapshot taken before I existed and X's record for I is deleted; restart → the driver marks K imported, `Init` carries `Absent` for (I, K), and X does not Prepare the twin B′ at (t+1, 0); variant: the same old key store onto a new, empty record store → `Absent` likewise | F24 (key store restored from an older backup) | O-SIGN, O-AGR, direct assertion on `Init` |
| MS34 | fake driver apply — the commitment comparison skipped | `det_s34_apply_divergence_halts`: X's executor diverges deterministically (cached and re-executed commitments differ from `commit_qc.result`) → `ApplyDiverged` → `Halt` | F21 | O-VAL, O-HALT |
| MS35 | `on_manifest_rejected`: an unsigned availability-carrier rejection early-times-out the held current-view proposal | `det_s35_relay_tamper_no_evidence`: altered or stripped carrier bytes cannot accuse or time out the original author; the genuine carrier still executes and Prepares | F25 | O-EVID, O-PERF |
| MS36a | `on_executed` step 3 — the certified branch (`Invalid` for a certified block, or `Valid(R ≠ expected_R)`) handled like uncertified `Invalid` | `det_s36_certified_mismatch_is_local` (a): re-proposal of certified B; X's executor returns `Invalid` → `LocalFault(ExecutionMismatch)`, no early timeout, no `PayloadRejected`; X still Commit-votes on PQC | F21 | O-FAULT, O-LIVE |
| MS36b | `on_executed` step 2 — `Failed` handled like `Invalid` | `det_s36_certified_mismatch_is_local` (b): uncertified block, executor returns `Failed` → `LocalFault(ExecutorFailed)`, retry, no early timeout, no `PayloadRejected` | F15 with injected `Failed` | O-FAULT, O-LIVE |
| MS37 | `on_qc` step 1 — the §7.6 monitor branch deleted | `det_s37_conflicting_commitqc_halts` (harness keys): conflicting CommitQC for `tip.height` → `Halt(SafetyViolation)` | — | expects `Halt` |
| MS38 | `on_vote` — `pool_insert` before the signature check | `det_s38_forged_votes_never_pooled`: n=4, `q − 1` forged Commit votes under honest signer indices plus one genuine one reach `P` → no CommitQC, no commit, no stage change; the genuine votes still form a QC later | F18 with forged-signature votes at every node | O-CERT, O-AGR |
| MS39 | `verify_qc_signatures` — accepts more than `q` genuine signers | `det_s39_qc_exact_signer_count`: exact `q` subsets verify for Prepare/Commit with either flag; `q + 1` genuine signers are rejected | — | O-CERT |
| MS40 | `verify_tc_inner` — accepts more than `q` genuine timeout entries | `det_s40_tc_exact_signer_count`: both full and cached-high-QC paths reject under/over counts while accepting differing exact-quorum subsets; TC formation from a larger pool projects exactly `q` | — | O-CERT |
| MS41 | `form_qc` — emits a QC from more than `q` votes | `det_s41_form_qc_exact_signer_count`: every vote kind/flag accepts exactly `q` and rejects `q - 1` / `q + 1` inputs; preserved signer order and attestations | — | O-CERT |
| MS42 | `PublicationRecoveryRequired` handler — ignores the irreversible local failure | `det_s42_original_publication_recovery_halts`: the original publication cannot retry, so halt immediately, sign/schedule nothing and retain serving | — | O-HALT, O-SIGN |
| MS49 | Native codec converts scoped resource refusals to malformed-frame text | `scoped_decode_refusal_is_not_malformed_native_evidence`, `codec_resource_errors_survive_lossless_norito_conversion`: preserve exact typed refusals, retry identical bytes outside the refused scope, and continue rejecting corrupt frames | — | typed refusal and exact retry |
| MS50 | Static byte-domain length violations become retryable local resource refusals | `protocol_byte_lengths_are_terminal_codec_errors`: reject empty or oversized result witnesses and oversized attestation signatures as malformed bytes; valid witnesses still retry after local decode limits are removed | — | permanent wire bounds versus local limits |

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

**Commit attestation rules (§3.7, SR39–SR42).** Harness keys and the fake attestor of
`testing.rs` (a keyed MAC per member key and height, so a forged, stripped or replayed attestation
is distinguishable from a genuine one; its execution-gated form answers `Pending` for a block its
node has not executed, as the simulator's authorities do).

| Id | Site — change | Named deterministic test (setup → expected) | Randomized scenario | Oracle |
|---|---|---|---|---|
| MA1 | `on_vote` (`attested`) — a Commit vote with `attest` is pooled whether or not its attestation is present and verifies | `det_a2_unattested_commit_votes_not_counted`: n=4, X = P of view 0, flagged block B; X holds PQC(B) and its own attested Commit; W's Commit arrives with a forged attestation, Y's with its attestation stripped, Z's with W's attestation → none is pooled, no stage change, no evidence; Y's genuine retransmission → still no CommitQC; W's genuine one → a CommitQC carrying exactly the attestations of X, Y and W, which verifies | F37 | O-ATT |
| MA2 | `verify_qc` — the attestation check (A4) skipped | `det_a4_commitqc_attestations_checked`: flagged CommitQC(h) with no attestations, one missing, one forged, two swapped, or one made at another height → rejected by `verify_qc` and `verify_commit_qc`, and no commit when it arrives as a `Qc`, in a `Status` or as a proposal's `parent_qc`; with the genuine attestations → commit | F37 | O-ATT |
| MA3 | `att_preimage` omits `R` | `det_a3_attestation_binds_result`: the genuine members' attestations of `(h, bh, R′)` attached to a flagged CommitQC for `(h, bh, R)`, and to a Commit vote for `(h, bh, R)` → rejected, not counted | — (no scenario varies `R` under one block) | — |
| MA4 | `att_preimage` omits `h` | `golden_attestation_preimage` (the §3.3 layout, which an application verifier may parse) | — | — |
| MA5 | `try_commit` — a node whose `Attestor` answers `NoAuthority` Commit-votes anyway (without an attestation) | `det_a5_no_authority_abstains_from_commit_only` (a): X without authority Prepares flagged B, sends no Commit vote for it and reports `AttestationUnavailable` once per view; for an unflagged block it Commit-votes normally | F37 | O-ATT |
| MA6 | `vote_preimage` omits the flag | `det_a6_flag_is_signed`: a Byzantine P strips the attestations of a genuine flagged CommitQC and clears its flag → an honest node without B's header rejects it as a `Qc`, in a `Status` and as `parent_qc` | F37 (stripping proxy tail) | O-ATT |
| MA7 | `propose_fresh` — the builder's flag is dropped (every fresh block unflagged) | `det_a1_flagged_block_commits_with_attestations`: n=4, the builder flags B → B's header carries the flag, every Commit vote an attestation, and the CommitQC q attestations | F37 | O-ATT |
| MA8 | Omit rejection of zero-payload proposals | `det_a7_empty_proposals_are_rejected_at_every_view`: flagged and unflagged zero payloads are rejected at every view | — | direct assertion |
| MA9 | `restore_round` — the recorded Prepare is rebuilt unflagged | `det_a8_restart_resends_identical_attested_votes`: X Prepares and Commits flagged B, its record is durable, it crashes and restarts (R4) → the re-sent Prepare and Commit (with its attestation) are byte-identical to the originals | — (F37 has no restarts; F13 has no flagged blocks) | O-SIGN |
| MA10 | `try_commit` — an attestation that the node's own verifier rejects is used anyway | `det_a5_no_authority_abstains_from_commit_only` (b): the proxy tail's authority is misconfigured (its attestations never verify) → no Commit vote, `AttestationUnavailable`; the others' attested votes form a `CommitQC` that verifies | F37 (an honest member with a broken authority) | O-ATT, O-CERT |
| MA11 | `verify_attestations` — a flagged CommitQC with more than `q` signers accepted (one attestation each) | `det_a4_flagged_commitqc_has_exactly_q_signers`: `q + 1` genuine signatures and attestations → `AttestationShape` from `verify_attestations`, `TooManySigners` from `verify_qc_signatures` / `verify_qc`, and rejection from `verify_commit_qc`; unflagged CommitQCs and PrepareQCs also reject the superset; `det_a4_commitqc_attestations_checked_core`: that certificate commits nothing as a `Qc`, in a `Status` or as `parent_qc` | F37 (over-aggregating proxy tail) | O-ATT (counts the signers itself) |
| MA12 | `on_outcome` — no `try_commit()` after the execution of the current proposal's block (a `Pending` attestor is asked again only at a stage raise) | `det_a9_pending_attestor_commits_after_execution`: n=4, X in set A with an execution-gated authority, flagged B executing; PQC(B) arrives first → no Commit vote, no `PersistSafety`, no `AttestationUnavailable`; `Executed{Valid(R)}` → X Commit-votes at once with a verifying attestation; `Valid(R′ ≠ R)` → `ExecutionMismatch`, still no Commit | — (F37's slow executors then commit later, at stage raises: start levels rise, no oracle fails) | — |
| MA13 | QC aggregation accepts different shared result witnesses | `form_qc_carries_attestations` | — | O-ATT |

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
`cfg(test)`. Baseline and mutant use the same profile, release by default. The explicit
`--core-profile test` option supports a warm local test target; the report records that choice
and does not establish release-profile qualification. The protocol gate's release profile and
strict named-test, normal-exit and complete-harness requirements are unchanged.

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
| HC9 | `evidence::witness_custody::decode` — skip original-pool result-witness custody | `retained_native_evidence_witnesses_belong_to_original_preparation_pool` | Genuine signed evidence retains every witness backing/control under the original State preparation pool; exact control refusal refunds a failed capture and the same source retries. Initial decoding and the remaining proof graph remain unfunded obligations |
| HC10 | `state_certificate::query_scratch_admission` — skip original query scratch admission | `state_certificate_signed_availability_scratch_uses_original_query_allowance` | Genuine signed RS16 availability refuses its exact scratch-minus-one allowance without losing original source/pool owners, retries at its exact allowance, and still rejects changed payload bytes. This gate covers the query scratch callback only; the remaining cryptographic/decoded ownership graph stays a separate qualification obligation |
| HC11 | `certified_chain::read_durable_pinned_block` — accept Kura's decoded cache instead of the current durable certificate | `durable_certificate_read_rejects_checksum_valid_corruption_after_cache_warm` | State-backed and pinned restoration readers reject checksum-valid wrong-height and forged-signature QCs after cache warming, then accept the restored original frame |
| HC12 | Beacon session construction omits the complete original prepaid remainder check | `beacon_verification_reserves_exact_buffers_and_refuses_before_unfunded_work` | One byte below the exact graph, control and scratch demand refuses before any physical allocation and preserves the original reservation unchanged. The same authentic source with exact funding succeeds; no parallel logical callback or unbudgeted session constructor exists. |
| HC13 | Core executed-successor query constructs aggregate pairing scratch without charging the inherited request allowance | `state_certificate_pairing_constructor_refusal_preserves_original_source_for_retry` requires exact typed refusal before verification, preserves the original certified source/parent, and retries under the original request model | Core test-only constructor callback; no node fault control |
| HC14 | `certified_chain::OriginalResultVerifier` — borrow the original decoded result for different witness bytes | `original_result_witness_rejects_foreign_canonical_bytes_before_borrowing_graph` | A genuine foreign canonical witness cannot replace the exact original receipt preimage; rejection refunds the original partial owners and the unchanged source retries. The private borrow shares native seal predicates and does not independently grant finality authority |
| HC15 | `StoredBodyRead::poll_with_qc` — deep-copy the original decoded quorum certificate at body handoff | `committed_read_returns_original_qc_backing_after_projection_refusal_and_retry` | Genuine attested restoration returns the original bitmap, signature vector and funded witness across refusal/retry; the body-only adapter drops unused proof owners before returning. Initial metadata allocation remains a separate accounting obligation |
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
| HC32 | Current reward-credit readers erase original outer Norito decode refusal | `original_fee_credit_alias_decode_refusal_preserves_balance_and_retries`, `original_fee_credit_owner_decode_refusal_preserves_exact_binding_and_retries` | The authenticated current claim prefix succeeds before the immutable beneficiary alias or owner-revision decoder refuses. Exact credit bytes/backing, reserved state and network-XOR custody balance survive; the same signed plan retries unchanged, and connected claim preparation retains nonserializable deferral through actual transaction rollback. Malformed records and intrinsic format limits remain terminal; complete decoded-graph funding remains separate |
| HC33 | Core decode refusal classifier borrows an unrelated active scope | `norito_global_archive_cap_is_terminal_inside_an_outer_decode_scope`, `norito_inner_format_limits_are_terminal_under_a_wider_outer_scope` | Actual global archive and stricter inner field/sequence/cumulative limits remain deterministic rejections under a wider outer scope. Local retry requires the original error dimension and ceiling to match a surviving scope; genuine inherited credit allocation refusal still defers. No allocation-pool owner or release notification is invented |
| HC35 | SNS permission projection publishes an original local refusal as a completed rejection | `original_sns_alias_domain_permission_refusal_retries_without_a_rejection`, `original_sns_domain_transfer_permission_refusal_retries_without_a_rejection` | The active outer decode budget can defer authoritative SNS reads without changing original NameRecord bytes or permanently denying domain authority; the same bytes succeed after budget release |
| HC36 | Claim fee exemption publishes original metadata or SNS refusal as a paid fee verdict | `original_claim_metadata_refusal_defers_fee_quote_and_retries_exact_payload`, `original_claim_alias_refusal_after_metadata_defers_fee_quote_and_retries` | Both original metadata reads and authoritative SNS records preserve local deferral through quotes, queue admission and the execution latch. Refusal cannot debit or publish; exact signed payloads retry after relief. Malformed/empty metadata remains completed; complete allocation funding remains separate |
| HC37 | Canonical account or NPoS currency pin refusal becomes selector absence | `original_canonical_account_refusal_does_not_fall_through_to_alias_absence`, `original_network_xor_pin_refusal_defers_quote_and_retries_same_parameter` | Typed canonical address and original committed currency reads preserve local deferral instead of falling through to alias absence or invalid fee configuration. Exact canonical literals and parameter bytes succeed after relief; foreign, malformed and intrinsically invalid selectors remain completed |

| HC34 | Native maintenance omits applied native source accounting | `native_authorization_has_no_entry_until_an_applied_transcript_and_drops_atomically`, `native_pool_overflow_cannot_borrow_ordinary_or_governance_reservations` | Applied native maintenance transcripts own one exact native permit. No entry exists before Apply, dropping the permit releases its entry atomically, and native-pool overflow cannot consume ordinary or governance reservations. Original SNS decode refusal still defers before debit or publication; complete decoded-graph funding and accelerated whole-State restoration remain open |
| HC40 | Account target or matcher turns an unfinished original SNS/canonical account read into a completed route | `original_account_target_refusal_never_selects_the_default_route`, `original_canonical_account_matcher_preserves_decode_refusal_and_retry`, `original_signed_account_matcher_refusal_is_not_a_mismatch_or_panic`, `original_native_policy_account_matcher_retains_refusal_before_route_selection` | Original account targets and exact, wildcard, instruction and query matchers propagate local refusal through configured and native route selection. Canonical matching uses the typed account parser without formatting panic. Ordered first-match evaluation and authoritative maintained directories remain unchanged; complete decoded-graph funding remains open |
| HC42 | SNS auto-renew rejects current-owner replacement after authenticated multisig rekey | `signed_rekey_current_owner_can_replace_stale_auto_renew_configuration`, `signed_rekey_same_configuration_requires_owner_replacement_cas`, `signed_rekey_disabled_clean_record_requires_exact_owner_revision` | The current authenticated lease owner may replace or disable stale owner-pinned configuration only at the exact persisted revision. Identical stale configuration still requires Apply. The actual Time sweep authenticates the exact persisted record and admits any payment under its separate committed native-maintenance quota; intrinsic refusal advances deterministic retry state without moving balances, renewing the lease, or retaining a source entry. Prior/unrelated owners and stale revisions stay rejected; rekey never transfers debit authority implicitly |
| HC44 | Execution worker discards original validation or prepared-certificate read refusal | `original_post_merge_validation_refusal_retains_worker_owner_and_exact_available_retry`, `original_prepared_certificate_read_refusal_retains_worker_owner_and_funded_execution` | The exact local carrier survives diagnostics with the original available source or funded execution. The same source retries without quarantine, negative verdict, publication, or replacement of an already executed overlay. Decoder counters do not invent pool release notifications |
| HC45 | Payload worker drops the original typed local decoder refusal | `original_available_payload_local_decode_refusal_keeps_typed_worker_reason_and_retry` | Original signed available custody, source and bytes remain unchanged; the worker retains the exact local reason before a diagnostic, publishes no verdict, and retries the same body after the field/allocation limit is removed. Scoped counters invent no allocation-pool release owner. |
| HC46 | Decode classifier treats a surviving narrower caller depth as invalid | `original_surviving_narrow_decode_depth_refusal_retries_identical_bytes`, `original_available_payload_narrow_depth_refusal_keeps_typed_worker_reason_and_retry` | Actual canonical bytes under a matching surviving decode-budget depth defer with their typed worker owner; exact bytes execute after scope removal. Dropped inner depth, global archive and canonical nesting ceilings remain terminal. |
| HC49 | Staking payload converts original preparation refusal into a diagnostic string | `original_staking_payload_refusal_retains_evidence_pool_and_exact_assembly_retry`, `original_staking_payload_worker_retains_pool_refusal_and_exact_queued_retry` | Payload assembly and its worker retain the exact evidence or State admission owner before diagnostics. Releasing the original occupied pool retries the same parent, evidence and queued transaction without dequeue, publication or a deterministic rejection. This boundary does not establish complete staking graph funding |

| HC38 | Routing turns an original SNS read refusal into a completed route error | `original_dataspace_alias_read_refusal_keeps_routing_retryable`, `original_physical_policy_read_refusal_never_enters_captured_row`, `original_private_instruction_routing_refusal_latches_before_scope_verdict` | The original SNS bytes retain a typed local refusal through queue/native routing and physical capture; private execution latches it before effects. Semantic absent/inactive routes remain completed outcomes; real-network qualification and complete allocation funding remain separate |
| HC39 | Native routing erases original root or lane-policy decode refusal | `original_root_scope_read_refusal_does_not_publish_invalid_native_context`, `original_lane_policy_read_refusal_after_root_keeps_exact_capture_retryable` | The root read and a policy read after its exact measured root prefix retain local deferral through Snapshot and pristine capture. No invalid carrier row is published, original metadata bytes remain unchanged and fresh owners retry the exact source; absence or completed malformed metadata stays distinct from local refusal |
| HC41 | Parameter control follows a private account rule in physical policy | `parameter_control_preserves_global_physical_route_before_private_account_rule`, `alias_registry_routing_paid_post_genesis_dataspace_domain_and_renewal`, `alias_registry_routing_cold_replay_with_expanded_catalog_preserves_paid_bootstrap` | Genuine signed parameter batches keep universal physical and native scope before account routing, while the same owner’s ordinary application retains its private route. Paid catalog/bootstrap, immutable genesis and certified cold replay remain mandatory; no physical dataspace mismatch guard is bypassed |


| HC47 | Runtime availability converts local historical refusal to corruption, or drops the original append/metadata retry owner | `original_availability_history_refusal_is_pending_without_corruption`, `original_availability_constructor_refusal_retries_without_installing_authority`, `append_refusal_keeps_original_commit_and_release_owner_until_durable`, `refused_metadata_owner_cannot_be_replaced_by_another_peer_during_backoff` | Non-wire local attempts retain the original State/source, capacity owner and queued work through storage and driver retry. The sole refused metadata slot cannot be replaced during backoff; payload work still progresses. Malformed artifacts remain terminal. Historical lane-prefix cause retention and full graph funding remain separately open |
| HC87 | Stake-index magnitude charges drop before the retained quantities | `stake_index_quantities_prepaid_and_borrowed_from_original_pool` | The complete exact account, descriptor and four aggregate layouts are admitted atomically before retained allocation. One-byte refusal preserves the original World and pool for retry. Repeated exposure reads borrow the same originally funded magnitude through move and drop; released charges cannot qualify a live physical aggregate. Bounded stack arithmetic preserves the original bonded-plus-complete-pending grouping. Evidence/history and penalty-action graphs remain separate resource obligations. |
| HC94 | Retired replay completion accepts replacement source configuration | `replay_completion_retirement_keeps_exact_source_and_original_pool_retry` | Only the same worker's successful historical execution and archive completion issue fixed process-local evidence. The large Published frame is retired. Every retry still admits its original body and witness, compares complete epoch, parameters and ordered committee, binds the current opaque State tip, and funds exact canonical header, QC and availability encoding from the same finite pool. Altered certificates, even another valid quorum, and replacement parameters are refused without duplicate events. Original capacity refusal preserves that evidence until the same bytes can retry after release. No decoded or persisted completion grants execution authority. |
| HC53 | Node time omits host suspension from admission timestamps, probe expiry or RTT | `suspend_inclusive_clock_advances_admission_and_expires_retained_probes`, `suspend_inclusive_clock_counts_entire_probe_round_trip` | One Unix anchor advances with the actual process-bound native suspend-inclusive elapsed clock. The same elapsed timeline owns probe deadlines, sample retention and RTT; no wall-clock reconsult or larger admission drift masks sleep. Clock refusal, regression or overflow retains the last representable floor and reports unhealthy fallback, never healthy peer samples. This is node-local time accounting and does not authenticate a Unix timestamp or change consensus timers. |
| HC51 | Lane history erases the original archive, certificate-prefix, evidence handoff or proposal policy refusal | `original_archive_read_refusal_preserves_pool_release_and_same_lane_prefix`, `original_certificate_projection_refusal_preserves_pool_release_and_exact_carrier`, `original_lane_evidence_handoff_preserves_actual_decode_refusal_and_exact_cut`, `original_native_lane_authority_refusal_reaches_merge_and_original_pool_retry`, `original_lane_history_refusal_reaches_evidence_without_recovery_or_rejection`, `original_lane_policy_proposal_refusal_retains_worker_owner_and_exact_queued_retry` | Original finite-pool release evidence and surviving caller decode refusal remain local through the retained history, merge, evidence and actual proposal Worker consumers. Retry preserves the exact selected archive descriptor, carrier, State cut and original ceiling. Decoder scopes invent no pool release. Typed Kura acquisition and full decoded/crypto graph funding remain separate obligations. |
| HC48 | Incumbent history or a signed committee/lifecycle decoder converts local refusal into a completed instruction failure | `original_incumbent_history_refusal_keeps_authority_and_same_source_retry`, `original_candidate_authority_refusal_keeps_command_and_same_source_retry`, `original_candidate_command_decode_refusal_has_no_publication_and_retries`, `original_beacon_public_state_decode_refusal_defers_before_installation`, `original_tle_public_state_decode_refusal_defers_before_installation`, `original_staking_authority_refusal_keeps_exit_overlay_and_same_signed_retry` | The original non-wire attempt reaches State before any candidate/key installation or validator exit; the same signed source retries. Signed malformed public state remains terminal. General NPoS parameter-read propagation has the separate HC50 control; complete decoded-graph funding remains open |
| HC50 | Original signed NPoS policy read turns a local decoder refusal into missing authority | `original_npos_parameter_refusal_does_not_become_missing_staking_policy`, `original_npos_exit_policy_refusal_keeps_stake_and_same_signed_retry`, `original_npos_reserve_validation_refuses_without_changing_current_or_undo`, `original_npos_policy_refusal_preserves_host_seed_projection_and_retries`, `original_npos_policy_refusal_cannot_prune_retained_evidence`, `late_original_npos_activation_read_refusal_rolls_back_and_same_signed_retry`, `original_lane_observer_late_policy_refusal_retains_observation_and_retries` | The same original policy remains available for retry through staking preparation and signed Exit, current and undo reserve validation, host seed projection and charged evidence pruning, including cumulative refusal after completed earlier activation or lane-observer policy reads. Refusal cannot publish a deterministic rejection, clear a completed projection or release retained proof bytes. Malformed policy remains terminal; complete graph funding and whole-State restoration remain separate obligations. |
| HC52 | Original checkpoint binary decoding becomes completed invalidity | `original_checkpoint_binary_refusal_is_local_and_retries_exact_original_source` | Exact original decoder fields survive portable checkpoint import. Core applies the shared surviving-caller-limit classifier before any rejection diagnostic; a live caller refusal retains retry while a dropped inner format ceiling remains terminal. The independently selected original checkpoint remains byte-identical and retries. This does not fund the complete decoded graph or authenticate a remotely supplied checkpoint. |
| HC54 | Bootstrap or restored beacon custody ignores the DKG transcript's authority generation | `committee_bootstrap_rejects_genuine_dkg_from_another_generation`, `committee_restore_rejects_genuine_dkg_from_another_generation` | Genuine signed DKG transcripts for the same ordered roster and network require the exact authenticated generation. Bootstrap and installed retention restore reject foreign generations; matching-generation transcripts remain accepted. This component check does not qualify whole-node restart or committee transitions. |
| HC95 | Native AMX accepts a certified Begin for a different signed debit source | `native_amx_paid_commit_survives_certified_restart_and_rejects_bypass` | The authenticated Global Begin binds the exact transfer digest, signed source authority and dataspace custody. A genuine foreign certificate cannot authorize another signed debit. The original paid commit/restart control rejects the substituted source before escrow; local resource refusal retains the original owner for retry. This component rule does not qualify daemon supervision or validator relayers. |
| HC55 | A fee reward claim ignores its signed custody, entitlement or beneficiary preconditions | `signed_fee_reward_claim_rejects_every_changed_binding_before_mutation` | Execution reproduces the exact lifecycle, recovered beneficiary revision, scoped XOR transfer, full accrued credit and next receipt sequence before releasing reserves. Explicit absence of a fee claim authorizes no additional payout. This component control does not qualify fee enactment or the complete monetary network lifecycle. |
| HC56 | Shared custody omits fee obligations from the combined staking and reward reserve floor | `shared_fee_stake_reward_custody_is_additive` | A source holding fee proceeds or fee rewards plus public-lane stake and rewards protects their sum. Individually backed obligations cannot authorize a debit that underfunds their combined liability. Network conservation and full restoration qualification remain separate gates. |
| HC57 | Startup replay acknowledges a changed certificate or source as an exact retry | `completed_replay_rejects_altered_certificate_and_source_without_losing_exact_retry` | The serialized worker retains only its original completed tip and exact certificate, availability, payload and source identity after releasing the heavy execution owner. Changed retries reject; original-pool scratch refusal preserves the exact retry and a subsequent forward commit invalidates the receipt. This component control does not qualify all-seat recovery. |
| HC58 | Shared network currency accepts a substitute asset, scoped balance policy or wrong precision | `canonical_network_xor_is_required_before_fee_reward_state_changes`, `network_xor_rejects_wrong_definition_scope_and_precision`, `staking_registration_rejects_wrong_xor_shape_with_transaction_rollback`, `reward_claim_rejects_wrong_xor_shape_with_transaction_rollback` | `state/network_xor.rs` supplies the shared exact network identity and global scale-nine guard. Governance admission, active and restored policy, staking deposits, conversion and claim preparation enforce it before reserving or paying funds; restored stake/reward custody also rejects incompatible definition and exact asset scope. The enacted fee asset remains distinct. Original execution and connected network conservation remain qualification gates. |
| HC59 | The bounded beacon reducer retains an unverified partial signature | `threshold_beacon_inline_reducer_rejects_invalid_share_without_losing_original_slots` | Every share is verified against the exact public transcript and pulse before occupying an inline seat slot. Rebound or forged proofs cannot replace an original verified share. Fixed 31-seat storage and canonical subset order preserve the unique output; remaining transcript and cryptographic allocation funding is a separate release obligation. |
| HC60 | Publication preparation drops the original local resource source at the scheduler handoff | `certificate_capacity_refusal_reaches_scheduler_with_original_release_and_execution` | Actual exhaustion of the original State pool at QC encoding, availability encoding and original shared-control admission retains the same execution, preimage and queued commit. The exact release observation survives the worker boundary and backoff; foreign-pool release grants no retry credit, while release of the actual occupied owner permits the unchanged prepare, append and apply. This source-retention control does not establish release-driven scheduling or complete graph funding. |
| HC61 | Lane admission converts an original anchor-history capacity refusal into an invalid anchor verdict | `anchor_read_refusal_retains_original_lane_body_until_capacity_returns`, `anchor_history_refusal_retains_exact_source_through_lane_evidence_retry` | Admission, evidence verification and publication preserve the original anchor pool refusal without caching Invalid or changing the signed lane body. A foreign pool release grants no retry credit; releasing the actual occupied owner permits the unchanged body to reproduce its certified result. Component coverage does not qualify network scheduling. |
| HC62 | Prepared publication accepts an independently allocated control containing identical certified bytes | `prepared_block_moves_original_graph_and_rejects_replaced_shared_control` | The original executed entrypoint graph moves without cloning into one fallibly prepaid immutable block control. Committed execution, staged publication and Kura retain the same pointer and original State pool; substituting a fully funded same-pool control with identical bytes requires recovery before State visibility. Nested graph allocation and whole-network qualification remain separate open work. |
| HC63 | State publication replaces an original pool or physical-lock refusal with a retry string | `state_publication_lock_refusals_reach_scheduler_with_original_execution_and_release`; `state_execution_and_membership_refusals_preserve_actual_release_owners` | The worker and scheduler retain the exact original State allocation, hash writer, publication participant or membership writer release observation. Unrelated releases cannot wake it, locks carry no invented allocation demand, and retry preserves the original queued execution, overlay, shared certified block and durable append before one successful application. Timer-based dispatch remains; retaining a release observation alone does not establish release-driven scheduling. |
| HC64 | Committed archive capture replaces original authenticated-history or index contention with a retry string | `committed_archive_index_refusal_retains_original_release_and_exact_publication`; `committed_archive_cold_history_refusal_retains_original_pool_and_exact_publication` | After State is visible, the worker retains its exact pending decision, original precharged context bytes and actual history-pool or archive-index release source. An unrelated release grants no retry credit. Unchanged retry completes immutable archives and emits original events once without reapplying State; invalid certificates remain distinct failures. Native context publication performs I/O over already admitted bytes and invents no allocation source. Complete archive graph funding and release-driven network scheduling remain separate obligations. |
| HC65 | Cold publication preparation replaces the original unfinished execution refusal with a retry string | `cold_prepare_refusal_retains_original_finishing_owner_and_exact_release`; `cold_prepare_validation_refusals_retain_original_storage_owners` | World, hash-history and membership writers, context-proof scratch, original context archive and result encoding refusals preserve the exact original pool and release observation through cold Prepare and the scheduler. Retry retains the original overlay, witness allocations and queued decision; unrelated releases and changed certificates cannot acquire its retry source. Exact validation wrapper errors retain pool demand, lock role, predecessor observation and decoder counters. Impossible layout, poisoned storage and custody-identity failures require recovery; a pool ceiling has no invented release source. Execution and attestation failures stay typed until the terminal execution report. Mailbox contention preserves its actual lock release without invented allocation demand; physical wait registration and complete nested graph funding remain separate obligations. |
| HC66 | Opaque host output or supplied proved replay derives unsigned staking monetary authority | `raw_ivm_staking_trigger_requires_signed_monetary_plan`; `supplied_proved_staking_effects_require_signed_monetary_plan` | The common consumption check recursively rejects monetary plans before the first queued effect, including raw VM trigger registration and resolved multisig approval. Actual transaction rollback preserves exact XOR balances, reserves and accruals; direct signed monetary instructions and ordinary nonmonetary raw output remain allowed. Supplied replay coverage tests the consumption boundary; production proof acceptance remains closed until the complete native STARK execution relation exists. |
| HC67 | Live multisig proposal reads turn an original bounded-decoder refusal into malformed authority | `live_multisig_proposal_decode_refusal_retries_original_signed_xor_claim` | Opaque traversal and native approval retain the actual local decoder refusal before any approval or monetary write. Discarding the refused overlay and retrying the unchanged signed approval pays its exact retained XOR claim. Missing, malformed and differently bound proposal rows remain deterministic outcomes. A cumulative Norito ceiling has no invented allocation pool or release notification. |
| HC68 | A retained multisig proposal changes its body or physical source while preserving an approved hash | `live_multisig_proposal_body_binding_rolls_back_original_signed_xor_claim`; `proposal_migration_validates_original_physical_key_and_body_before_writes`; `persisted_multisig_body_binding_and_local_refusal_reach_signed_queue_admission`; `restored_multisig_proposals_require_exact_body_and_preserve_local_read_refusal` | Native execution, queue admission, account migration and restoration share exact account/key/content validation. The existing V1 typed hash streams into its hash owner and retains original serializer refusal. Rejected operations roll back their actual transaction; unchanged signed claims and serialized state retry. Migration preserves original body, approvals and terminal history, and cannot overwrite a destination proposal. Valid depth chains and repeated sibling approvals retain traversal coverage. |
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
| HC81 | Native beacon readiness admission loses its original resource owner at worker or node startup | `beacon_startup_retains_original_capacity_through_worker_channel_and_node` | The fixed readiness control is admitted by the original State pool. Capacity refusal preserves its exact release source through the serialized executor and typed node error; no producer is attached or existing execution replaced. Actual release permits the same attachment, while duplicate attachment remains terminal. Attestation-mailbox and driver startup errors retain their concrete owners; allocator failures carry their actual error without inventing a release. Beacon transcript and cryptographic scratch funding remain separate work. |
| HC82 | Cold World-root verification stringifies an original storage refusal | `world_root_verification_preserves_original_writer_refusal_and_exact_retry`, `world_root_verification_preserves_original_capacity_refusal_and_exact_retry` | The complete cold World capture keeps actual writer Busy and original-pool Capacity distinct from canonical capture errors and stored-root mismatch, including through startup replay errors. Unrelated refunds cannot authorize retry. Releasing the original writer or occupied original pool permits verification of the unchanged certified World; a stale accumulator remains a typed mismatch. |
| HC83 | Scheduler destruction refunds retained original controls before cancelling every linked waiter | `cancelling_and_dropping_scheduler_unlinks_all_waiters_before_original_refunds` | Cancellation retires all same-pool registrations before dropping original bodies, input owners, refusal carriers or registration backing. The real capacity callback remains silent during context cancellation, recovery and scheduler destruction; an earlier refunded control must never wake a later still-linked registration. |
| HC84 | Startup assembly converts original committed-history refusal into invalid configuration | `startup_history_retains_original_cold_kura_refusal_and_exact_retry` | Actual cold Kura admission keeps the original State pool and release observation through `assemble_init` and the typed node error. A failed read creates no missing entry or partial startup input; the same signed tip and complete header window retry after actual release. Global and lane callers preserve local deferral, while missing history and completed I/O or corruption errors retain their exact height and category. This boundary does not claim complete cold decoder or startup graph funding. |
| HC85 | An authenticated shared beacon session is reused under a substituted current context | `shared_authenticated_session_rechecks_every_current_external_binding` | Network, session, ordered-roster and transcript bindings are checked against the immutable sealed graph on every borrowed use. Sharing its original charged owner grants no new epoch or authority. Separate graph controls prove exact aggregate admission, preconstruction refusal, same-pool release, zero-allocation clones, last-reader credit retention and canonical lifecycle encoding; this does not claim complete DKG construction, snapshot decode or credential registry funding. |
| HC86 | An original local execution custody invariant is treated as retryable resource pressure | `original_local_custody_invariant_halts_worker_without_fee_result_or_quarantine` | The sticky host-local invariant abandons the original transaction without fees and requires native recovery before publishing a result. Clearing a local fault cannot authorize worker retry, quarantine, or a deterministic invalid-transaction verdict. Real capacity refusals retain their distinct original release source. |
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
| HC130 | Discard an original completed decoded proposal and reenter canonical decoding on retry | `completed_decoded_retry_borrows_original_graph_without_canonical_reentry` | The existing original-source attempt retains the completed canonical graph and its prepared leaves until an explicit retirement or actual validator transfer. Same-pool/address/whole-wire identity remains mandatory. Every retry reruns current parent, schedule, height/view, attestation and lane/source checks before production validation; retained decoding is no execution or finality authority. A local validator error returns the actual block and only its exact canonical resultless projection may rejoin the original attempt. Projection refusal or source mismatch retains that graph and fails closed. Full transaction/DA/result funding, post-validation refusals and consuming-panic ownership remain open. |
| HC131 | Accept an independently prepared signature collection with equal canonical wire in the same source pool | `same_source_same_pool_distinct_prepared_signature_owner_is_refused_at_both_boundaries` | At both completed-decoding reuse and validator-return recovery, the block must retain the exact original prepared signature control. Same source bytes, canonical proposal, pool and signature values do not substitute an independently admitted owner. The allocation-free Model observation checks the decoder's unchanged original input and compares the physical collection control. This Core mutant bypasses only the two physical-control requirements; Model equality and all source, pool, wire, height/view, current schedule/authority and attestation checks remain unchanged. The named unmutated control covers both boundaries; its completed-boundary refusal assertion kills the mutant. This rule qualifies only signature-control identity, not transaction/DA/result graph funding, consuming-unwind custody or full H1/H2 integration. |
| HC132 | Omit the native top-up seal outside an epoch boundary | `native_top_up_proposal_requires_attestation_before_an_epoch_boundary` | One node predicate inspects original proposal work and the authenticated epoch's last height for both construction and validation. Rejected native top-up work still requires a source-complete empty mint tree seal; ordinary nonboundary work does not. The independent executed-count guard remains fail-closed. The named control checks a genuine signed, structurally valid SDK fixture and does not establish successful monetary execution or network liveness. |

The Core rules above are replay and committee-retention prerequisites. They do not qualify production lane
offence admission, original-stake monetary dispatch or the complete H3 allocation graph.

Also required: golden vectors for every preimage (including `echo_preimage` and `att_preimage`, §3.3), `block_hash`, `att_digest`, `committee_digest`,
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
  `host`), in F9, F13, F14, F27, F29, F32 and F37 and in the O2 run that kills a replica at each
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
3. Hosting dataspace/lane instances (several cores per node, instance-id derivation, committees,
   O9 isolation).
4. AMX 2PC (§11): the global chain's side (Begin, relay, decision by the deadline, trackers with
   handoffs) runs in the node's executor and the participant side is a component over an escrow
   interface; hosting a dataspace instance with its own state (item 3), retaining each block's
   write set so that relayers can build record proofs, and payload builders that relay pending
   proofs remain (Appendix E, E58).
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
   The application must define time monotonicity without local-clock comparisons.
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
    post_state_root,                // witnessed writes with top-ups, unchanged
    ordinary_writes_root,           // unchanged
    kagemusha_top_up_root,          // unchanged
    kagemusha_top_up_count,         // unchanged
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
- `R = H("iroha/sumeragi/result/v1" ‖ norito(ExecutionResultCommitment))` is unchanged in form.
  There is one layout and one tag.

```text
P_{h−1}
header_h   = (…, parent_hash = bh_{h−1}, parent_result = R_{h−1}, payload_hash, …)
bh_h       = H(TAG_BLOCK ‖ header_h)
X_h        = exec(P_{h−1}, body_h)
R_h        = H(RESULT_TAG ‖ norito({h, execution{root(P_{h−1}), root(X_h), …}, schedule, beacon, native_lanes}))
CommitQC_h = q_h votes over (I, E, h, v, bh_h, R_h)
P_h        = tail(X_h, body_h, R_h)
header_{h+1}.parent_result = R_h,   R_{h+1} binds root(P_h)
```

- **N1.** A block's own result is not in its header (§3.2). `header_h` binds `R_{h−1}` only.
- **N2.** Nothing in `X_h` depends on `R_h`, on a vote or on a certificate of height `h`.
  Execution reads `P_{h−1}`, the header and the body.
- **N3.** No State cut depends on certificate bytes at any height. Different exact-quorum signer
  sets certify the same `(bh, R)` (§3.4), so signer bitmaps, aggregate signatures and attestations
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
  header with its confidential feature digest, the two records of `R`, the lane batch and the
  lane result, the genesis context parameters, the epoch identity, every walked record of the
  peer handshake, and the network envelope with its Sumeragi frame. In the other walked types
  a new field fails only when its type is hash-bearing or names an unclassified nested type.
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
| E43 | owner decision (node integration, KAGEMUSHA mint finality) | Commit attestation, a generic application extension (§3.7): a header flag `attest` bound in `block_hash`; every vote signs its block's flag (one byte appended to `vote_preimage`); a Commit vote on a flagged block carries an attestation of `att_preimage(h, bh, R)` (new kind `0x06`) from a driver-supplied `Attestor`, and a node that cannot attest does not Commit-vote there (`LocalFault(AttestationUnavailable)`); aggregators pool only Commit votes whose attestation verifies under a driver-supplied `AttestationVerifier`; a flagged CommitQC carries the attestations of exactly its signers and `verify_qc` checks them on every path (`qc_digest` covers them); the recorded Prepare keeps its flag; epoch boundaries require attestation; the current no-empty-block rule never proposes `EMPTY`. The v2 runtime sealed KAGEMUSHA top-ups inside Commit votes; this keeps that model without making the core aware of Pasta keys. Safety argument §7.7; liveness condition §3.7 A5, §8.1. Tests `det_a1`–`det_a8`, `golden_attestation_preimage`; mutations MA1–MA10; scenario F37 and oracle O-ATT. Amended by E47 and E64 (no mandatory boundary attestation). | §3.1–§3.7, §4.2–§4.4, §6.2–§6.5, §6.9, §6.10, §7.1, §7.4, §7.6, §7.7, §8.1, §12.1, §13.2–§13.4 | `crypto::{Attestor, AttestationVerifier, verify_qc, verify_attestations}`, `preimage::{att_preimage, vote_preimage}`, `machine::votes::{attested, try_commit}`, `machine::propose::propose_fresh`, `machine::proposal::check_header`, `machine::sync::on_sync_response` |
| E44 | first-release transport | One canonical wire tag table classifies both decoded and raw Norito frames: Proposal and PayloadManifest are Proposal class; PayloadChunk and SyncResponse are Bulk; the remaining tags are Control. Classification never depends on node height or optional payload presence. | §3.5, §12.3 O8 | `message::{TrafficClass, traffic_class_of_frame, PROTOCOL_VERSION}`, `sim::net::class_of` |
| E47 | adversarial review of E43 (KAGEMUSHA mapping) | (a) A KAGEMUSHA seal message binds the top-up root and count and the execution-commitment digest, i.e. `R`'s preimage, which the core carries as an opaque bounded witness and which a node that Commit-votes on the lock alone may not have executed yet. `Attestor::attest` now answers `AttestOutcome::{Attested, Pending, NoAuthority}`: `Pending` (the authority still needs its own execution) is no fault, and `try_commit()` runs again after every `Valid` execution of the current proposal's block with a flagged lock (§6.3 step 4) as well as at stage raises; before, a slow executor's authority could only answer "no authority" and its Commit waited for a stage raise. (b) The verifier contract gains the unique-message rule: whatever an attestation binds beyond the statement is determined by the statement and committed state and checked by `verify`, so an attestation carries the preimages it needs (KAGEMUSHA: `R`'s preimage, re-hashed to `R`) and never depends on local execution (sync, `Status`, `parent_qc`); a Byzantine seal over another top-up root under the same `R` is not counted. (c) A flagged CommitQC has exactly `q` signers (formation always uses `q`): a Byzantine aggregator's over-aggregated certificate would otherwise commit a block whose attestations are not an exact-quorum KAGEMUSHA bundle, leaving its top-ups unmintable. Tests `det_a4_flagged_commitqc_has_exactly_q_signers`, `det_a4_commitqc_attestations_checked_core` (over-aggregated case), `det_a9_pending_attestor_commits_after_execution`, `execution_gated_attestor_waits_for_execution`, `o_att_requires_exactly_q_attested_signers`; mutations MA11, MA12; F37 gains execution-gated authorities, slow executors and an over-aggregating proxy tail (`Strategy::OverAggregate`), and O-ATT counts exactly `q`. | §3.4, §3.7 A2, A4, A5, §6.3, §6.5, §7.1, §7.7, §8.2, §8.3, §12.1, §13.2–§13.4 | `crypto::{AttestOutcome, Attestor, AttestationVerifier, verify_attestations}`, `machine::votes::try_commit`, `machine::proposal::on_outcome` |
| E53 | crash matrix of the file record store (node integration) | Store-id check: the "every key imported" marks of a mismatch are one event — all appended with one fresh id, the id file written and synced after them. Written one by one, each with its own id written first, a crash after the first mark left a matching id and the other keys' stale "generated" entries, so a later instance start (records lost with a replaced record store, key store rolled back) could write an initial record for a key that had signed there. | §7.4 rule 3 | `iroha_core::sumeragi::driver::persist::reconcile_store_id` |
| E60 | mandatory first-release signed RS16 integration | Sumeragi owns signed layout, complete original signature table and source-bound custody. ProposalMessage and SyncEntry require availability evidence; actual rows use the same Norito WireMessage owner. Typed author/acquisition/restoration jobs retain original funded owners through refusal. AvailableBody binds full independent authority; metadata alone grants no custody. Reconstruction/restoration checks complete codeword and padding. Publication retains original frame and never re-signs or falls back to raw bodies. Current all-row dissemination has no holder-bandwidth claim; live qualification remains open. | §12.8, §3.2, §3.3, §3.5, §12.1–§12.3 | `iroha_sumeragi::{availability, message, api}`, `iroha_core::sumeragi::driver::{payload_worker, payload_jobs, acquisition}` |
| E64 | owner decision (first release, KAGEMUSHA removal) | The core no longer mandates attestation at epoch boundaries: the fresh flag of §3.7 A1 is exactly the payload/control builders' flag, and header checks (`Defect::BoundaryAttestation` is removed), the certificate cache, a TC's carried PrepareQC, sync, R5, the restart tip and `BlockApplied` accept an unflagged boundary. An application without attestation authority (`NoAttestation`) therefore commits every boundary; before, every boundary stalled under it. The node application still flags its NPoS boundaries by its own rule until its boundary seal is removed. SR46 and MS45 are restated; tests `det_s45_unflagged_boundary_commits_without_attestation`, `det_s45_boundary_proposal_carries_only_the_builders_flag`, `epoch_boundary_flag_is_no_signed_defect`, `boundary_certificates_keep_context_checks_before_cache_hits`. | §3.2, §3.7 A1, A5, §4.2, §6.9, §6.10, §6.13, §7.1, §7.7, §10, §11 | `machine::propose::request_authoring`, `message::Proposal::header_defect`, `machine::{verify_qc_cached, verify_tc_cached}`, `machine::sync::process_sync_buffer`, `machine::restart::check_init`, `machine::round::applied_config_updates`, `safety::check_recommit` |

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
| E29 | Restored own messages | The Prepare and timeout rebuilt by R4 re-enter the own pools through `pool_insert` / `timeout_insert` (they are re-signed, identical bytes), last in `restore`, followed by `try_commit()`; formation may then commit. | `machine::restart::restore_round` |
| E30 | Probe answers | Answered at most once per peer per `rebroadcast_interval`, with a stamp separate from the §6.1 reply limit. | `machine::intake::answer_probe` |
| E37 | `Init.configs` | Only the heights `t` to `t + 2` are accepted, each at most once (a `ConfigError::InvalidInit` otherwise). A configuration above `t + 2` let commits run more than two heights ahead of apply (§10.2), and the next in-order `BlockApplied` then halted the core as a driver anomaly. | `machine::restart::check_init` |
| E38 | Chain parameters | Historical rule, superseded by the no-empty-block design: `Core::new` also applies the transport-independent §9.4 chain-parameter rules to the initial configurations (`block_time ≤ payload_retry_interval`, `empty_after_views ≥ 1`), and the leader applies the voters' fresh-block rule (§6.2 step 6) to every fresh payload, at view 0 too: with `empty_after_views = 0` from a committed configuration it proposes `EMPTY` instead of a payload every voter reports as a signed defect. | `machine::restart::Core::new`, `machine::propose::propose_fresh` |
| E45 | `CoreStatus` | Also reports the leader and the proxy tail of `(h, view)` (`None` while awaiting: the next round's committee is not known yet) and the view of the lock (`high_pqc`), for the node's status endpoint, which replaces the v2 leader and QC endpoints. | `machine::Core::status` |
| E49 | Driver bounds and failure handling (§12.2, §12.3, §12.5) | The `iroha_core` driver bounds every queue the core's peers or a failing device can grow. Serving: the node's own `FetchPayload`s go first (one per body), then peers round-robin with at most one pending `ServeBlocks` and one `ServePayload` each (a newer one replaces it) within a per-peer token bucket of response bytes; the rest is dropped (O6). The O2 barrier holds at most 1 024 effects and 32 MiB of block payload, dropping the oldest `Send`, `Broadcast`, `ServeBlocks` or `ServePayload` beyond (the core rebroadcasts; `CommitBlock`, evidence and `Halt` are never dropped; a newer `FetchPayload` of a body replaces a held one); a record still queued is superseded by a newer one of the same key, and what waited for it waits for the newer; queued bodies of applied heights are dropped. Released effects leave in batches of 64 with a due `Tick` in between (O5). A prepared commit runs alone on the executor (nothing between its prepare and its commit, also while a step backs off), and a retryable refusal re-prepares the same original owner without a second append. Consuming publication failure or prepare/commit unwind halts for recovery; ordinary idempotent write failures and missing reads remain retryable; a thread that stops anyway, or an unreachable worker, stops the instance and is reported. Frames are decoded within the transport limit (O10). | `driver::{serve::ServeSched, barrier::Barrier, persist::PersistQueue, exec::ExecSched, Kernel, Driver}` |
| E51 | Application `R` (node integration, §4.1) | `R = H("iroha/sumeragi/result/v1" ‖ norito(ExecutionResultCommitment))` with `ExecutionResultCommitment{height, execution, schedule, beacon, native_lanes}`. `execution` (`ExecutionCommitment`) binds: (1) the **complete World state**: `parent_world_state_root`, the World the block executed on (every canonical World entry after the parent block's publication, including the parent's apply-time deterministic writes; for genesis the empty World, so genesis absorbs everything the World holds, including state seeded before it executes), and `world_state_root`, the World after the execution; (2) the **event root** `event_commitment`: the Merkle root (`iroha_crypto::MerkleTree`, leaves the hashes of the canonical Norito events) and count of the events the execution emitted, in emission order, `None` without events (pipeline status notifications are delivery, not results); (3) the witnessed pre- and post-state roots and the ordinary-write root (sparse Merkle roots over the execution witness; the ordinary-write root carries the per-key write proofs of §11 records and KAGEMUSHA receipts) and the KAGEMUSHA top-up root and count; (4) the length and hash of the result-bearing block wire (every transaction result and output) and the network-input and typed-output Merkle commitments. `schedule` retains the complete current epoch context and the lag-2 successor schedule with every ordered key and verified BLS proof of possession, `beacon` the finalized pulse the execution consumed and `native_lanes` the complete lane-context proof against the ordinary-write root. The canonical preimage is stored as `CommitCertificate.result_preimage` in the block's Kura frame. **World state root.** The root of an incremental homomorphic multiset hash (LtHash16). Each canonical World entry, a table row `(k, v)` or the value `v` of a cell `f` that the exhaustive World authority registry declares canonical (derived indexes and local buffers excluded; the trigger owner's authoritative stores included), expands to `e = BLAKE3-XOF(derive_key("iroha 2026-09-30 world-state lthash16 element v1"), P_f ‖ presence ‖ H(k) ‖ H(v))` read as 1 024 little-endian `u16` lanes, where `P_f` binds the field identity and kind and `H` is the bare-Norito value hash or the registry's declared semantic projection. The accumulator is the lane-wise sum of all elements modulo 2^16 with the entry count modulo 2^64 (order independent; removal is the exact inverse of addition), and the root is `H("iroha:world-state:root:v1\0" ‖ S ‖ entries ‖ lanes)` (little-endian count and lanes) with `S` the digest of the registry's canonical field identities, kinds and key/value schemas. A block subtracts `e(before)` and adds `e(after)` for every entry of every canonical World storage and cell that its overlay touched, read from the overlay's own undo journal, so the per-block cost is proportional to the change set and never to the World; every pass must visit exactly the registry's canonical fields (the registry destructures `WorldData` without `..`). The accumulator is the derived World cell `state_accumulator`: the node stores it after the block's last deterministic World write at publication, and it is the next block's parent root, so the apply-time writes of block `h` enter `R_{h+1}`. Chosen over a persistent sparse Merkle tree over the World: no consumer needs per-key membership proofs against the complete state (§11 and the §12.7 readers prove writes against the ordinary-write root), and the accumulator needs 2 KiB of state and no per-entry tree nodes. Replay re-executes every certified block and so recomputes and checks both World roots and the event root; after replay, startup also requires the accumulator to equal a cold capture of the rebuilt World. Each sparse Merkle tree is built once per block. **Specified replacement (prospective: specified by ZK delivery plan G.1 in §16, not built).** G.3 replaces the "World state root" part of this row by the following text in one fresh-genesis cutover that deletes the accumulator; until then this row is the as-built rule and no second State root is published. *Keyed State roots.* `execution` binds the complete keyed State: `parent_keyed_state_root`, the State the block executed on (every canonical State and World entry after the parent block's publication, including the parent's deterministic apply-time writes; for genesis the empty State), and `keyed_state_root`, the State after the execution. Both have the type `KeyedStateRoot` (a Norito payload of exactly 32 raw bytes without a `Hash` marker, §16.6) and are roots of the one State-owned keyed commitment of §16 over the canonical tables and cells of the exhaustive authority registry, in ascending identity order, with keys and values in their registered bare Norito V1 or semantic encodings. The construction is the one G.3 selects. Inclusion, absence and complete-range witnesses verify against either root from the witness bytes alone. A block updates the commitment from its complete change set, read from the overlay's own undo journal; the State publication owner advances it once, after the block's last deterministic write, and that root is the next block's parent root. Replay recomputes and checks both roots at every certified block and requires the incremental root to equal a cold build. Exactly one complete-State commitment scheme exists and no per-table State root is independently authoritative; the witnessed roots of (3) keep their roles, `schedule`, `beacon` and the epoch context identity keep their roles as consensus bindings (§16.8), application accumulators keep their application-statement proofs, a protocol fingerprint remains only as a comparison value recomputed from committed canonical entries (§16.5 P1), and node-local binding commitments remain only under §16.5 P1. The result, header and certificate order is unchanged: a header binds only its parent's `R`, `R` binds the State before and after execution, and no State cut depends on the certificate that authenticates it (§16.6). | `iroha_core::sumeragi::commitment::{execution_result, WorldStateTransition}`, `iroha_core::state::world_projection::WorldStateAccumulator` |
| E52 | Application schedule (node integration, §10.1, §9.4) | World retains the authenticated current native epoch and bounded three-slot schedule. Parameters retain lag two; membership beyond a boundary is Pending until original certified boundary application atomically installs its exact next epoch. Genesis uses its signed context. Parameter validation consumes the exported `FRAME_OVERHEAD`, including source-complete Pasta witnesses and control bytes, against the protocol transport bound. | `iroha_core::sumeragi::schedule` |
| E54 | Production driver backends (§7.4, §12.2, §12.3 O2, O8, O10) | `iroha_core::sumeragi`: `crypto` — `H = iroha_crypto::Hash`; BLS-normal signatures (48-byte keys, 96-byte signatures); a committee key's proof of possession is verified once when the height schedule admits it and every aggregate naming a key not admitted fails (fail closed); a TC verifies with one multi-pairing over its `hq` groups (`iroha_crypto::bls_normal_verify_preaggregated_multi_message`); the signer is the node's key pair (BLS signatures are unique, so deterministic). `records` — one file per `(I, K)` under `records_dir/<I hex>/<H(K) hex>.record` and the store id beside them, each replaced by temp file, fsync, rename and directory fsync; the installation log is an append-only file of length-prefixed Norito entries outside `records_dir`, fsynced per entry; a torn or corrupt tail ends the log (cut before the next append), which the store-id check then sees as a mismatch (safe). The operator's assertion is a one-shot boot flag, never a configuration key. `bodies` — `<root>/bodies/<I hex>/<h>/<bh hex>`, written like records, never replaced, verified against `(h, bh)` when read, pruned through the applied height, and bounded by a byte cap that fails a write like a full disk (retried; never an eviction). `net` — `NetworkMessage::Sumeragi` carries the exact frame and `I`; one classifier (`traffic_class_of_frame`) serves the raw and the decoded P2P paths; Control → `ConsensusSafety` (the reserved safety FIFO), Proposal → `ConsensusPayload`, Bulk → `BlockSync`; one `post_recoverable` per recipient; payload streams retain the exact returned post and admission ticket under backpressure until admission succeeds; the driver owns its three FIFOs on `SubscriberRoute::Sumeragi`; relayed frames (origin ≠ authenticated connection) are not accepted, so ingress stays keyed by authenticated peers. | `sumeragi::{crypto, records, bodies, net}` |
| E55 | Driver builds (§6.10 rule 1, §12.1 `PayloadReady`); found by the node's n = 4 in-process test with `payload_retry_interval` = 600 s | Two lost wakeups at a view-0 leader. (a) A transaction arriving while `BuildPayload{req}` runs (the builder may have read the queue before it) is remembered, and an `EMPTY` answer to `req` is followed by `PayloadReady{req}` at once. (b) A builder that first waits for the parent's apply can answer after `t_propose + build_timeout`: the core has then used `EMPTY` and waits for the heartbeat, and ignores the late answer (its `req` is no longer in `build`). The driver sends `PayloadReady{req}` after every non-empty answer too; in `Requested{req}` the answer is proposed first and the readiness is ignored, in `IdleWait{req}` it requests again at once. Without either, a transaction waited up to `payload_retry_interval`. The core is unchanged. | `driver::exec::ExecSched::{transactions_available, done}` |
| E56 | Node cutover (§12.1, §12.3, §7.4; node integration) | `irohad` starts only Sumeragi. Startup order: Kura; a new empty State (nonempty local snapshot exports are not restored: `R` commits the complete World state (E51), but restoring a snapshot against the certified parent World root of its successor block is not implemented yet, goal S9) with the node's runtime configuration installed; `node::prepare` applies (fresh chain) or re-executes (restart) the signed genesis, replays every Kura block against its certificate and requires the World state accumulator to equal a cold capture of the rebuilt World, before the queue, the handshake and the network are built from the rebuilt state; then `Prepared::start_on_network` installs the records of the node's key, subscribes the driver's three FIFOs and spawns the driver over `P2pNet`. The handshake binds `proto = PROTOCOL_VERSION` and `consensus_fingerprint = I`. The operator's assertion is the one-shot CLI flag `--sumeragi-assert-fresh-key` (test-network peers pass it only on their original launch, with both the configured records directory and installation log absent; a restart never reasserts it after history loss. `kagami localnet` currently selects it when the peer's records directory is absent). The v2 relay is replaced by one subscriber per semantic class for gossip, streaming and time only. Signed local snapshot export and budget maintenance start only after original replay and successful driver startup. The gate is revoked on halt, worker failure or unwind; normal shutdown retains readiness for the final write. A local signature authenticates export bytes and never substitutes for full-World execution provenance. Emergency Fast starts no driver. The configured SoraFS provider-ingest and reputation finalized archives are bound to the native executor (`sumeragi::executor::FinalizedArchives`), which captures each committed height from the exact committed State before apply completes; a failed capture keeps the commit pending. | `iroha_core::sumeragi::node::{prepare, Prepared, NetworkedNode, NodeHandle}`, `irohad::{network_relay, supervise_sumeragi, sumeragi_node_config}` |
| E57 | Certified-chain reader (§12.7; node integration) | `iroha_core::sumeragi::certified_chain` replaces the v2 finality sidecar for application readers. `committed_block` derives a per-height receipt from the Kura frame's header and result preimage only (certified block id `H("iroha/sumeragi/certified-block/v1" ‖ block_hash ‖ R)`, which signer floors pin as `context_id`); `CertifiedChain` adds the local `CommitQC` check under the committee authenticated by `R_{height−2}` (full native Pasta by default, or an explicit application `AttestationVerifier`) and iteratively authenticates the complete historical prefix with a lag-2 authority ring; rotated-away committees remain independently verifiable and missing authority fails closed. The role-11 Check instruction uses only the committed read (certificates are per node); signer finality, native Check histories and provider-admission readers use the certified read. | `iroha_core::sumeragi::certified_chain` |
| E58 | AMX on the global chain (§11; node application) | (a) A record is a World write of the block that creates it under the reserved execution-witness key `0xD9 ‖ kind ‖ x` (one key per kind and transaction on an instance), proven by the sparse-Merkle path in `R`'s ordinary-write root; E51's layout is unchanged, and building a path needs the block's complete write set (the mandatory lane-state write included). (b) `G` admits a `Begin` only if every participant is registered and `b < d ≤ b + 7 200`, so escrow is bounded in global heights; it keeps at most 4 096 pending transactions and 256 registered dataspaces. Relayed proofs of unknown or decided transactions are ignored without touching the state. The deadline step runs after the block's transactions, so a `Yes` relayed in block `d + 1` is recorded but cannot commit; a transaction leaves the state in the first block above `d`, and since `x` binds `d` it can never begin again. (c) A participant rejects a `Prepare` once it has verified a `G` block above `d`, and on that condition drops its prepared entries except an unsettled `Yes` escrow (which only its decision proof closes); it drops held decisions 7 200 heights after their decision height. No valid `Prepare` of a dropped transaction can follow, and its decision proof is then only held. (d) The tracker checks a certificate with `Verifier::verify_qc_signatures` under the tracked epoch's proof-of-possession-verified BLS keys, as the portable finality proofs do, and a flagged certificate's attestations only for shape (they are application evidence, §3.7); its epoch window also requires the header's epoch to contain the height, so a committee never certifies a height of a later epoch. (e) `RegisterAmxDataspaceV1` is accepted in genesis or from an authority holding `CanSetParameters`, anchored at a canonical `ValidatorEpochContextV1` within the result-preimage bounds. (f) A native participant is installed exactly once by its signed private genesis, binding its signed parent network and complete global chain label to the canonical signed global genesis plus its genuine H2 carrier. The sole native prefix verifier reconstructs authority, validates Global root ownership and the exact instance, and authenticates genesis `R` from H2's exact quorum. The participant's original State pool retains both full canonical source frames, complete current/previous authority and every exact monetary escrow. Allocation admission of a decoded snapshot grants no execution capability; original genesis/journal replay remains required. (g) The native transfer host accepts a positive same-dataspace ordinary non-retail numeric leg owned by the signed transaction authority. Enrolled-wallet legs and registered retail monetary assets record `Prepared No` before any principal, maintenance or payment effect; local decoder/allocation refusal is an unfinished attempt and never `No`. Supporting retail AMX requires the original signed customer assessment and exact frozen fee/payment obligations in the funded escrow; a permissionless settlement relayer cannot supply them. A `Yes` uses dedicated non-signing custody and only an authenticated global Commit or Abort closes it. Remaining S6 work (`TODO(S6)` in `iroha_core::sumeragi::amx`): whole-network native monetary qualification, daemon supervision of independent State/archive owners, authenticated complete-State restoration and validator payload builders that include pending proofs (§11 item 4). The global executor already persists complete write sets in its mandatory native context archive; `iroha_core::sumeragi::amx::amx_record_proof` authenticates a historical carrier and its full write root before constructing record proofs. Portable proof graphs and tree scratch retain the native receipt reader's resource-qualification gap. | `iroha_data_model::sumeragi_amx`, `iroha_data_model::isi::sumeragi_amx`, `iroha_core::sumeragi::amx` |

### E.3 Simulator and verification

| # | Topic | As-built | Site |
|---|---|---|---|
| E31 | F33 | As literally described F33 needs the network to also delay the lock holder's votes: stage-2 broadcast voting otherwise re-forms the hidden PrepareQC among the honest members. The scenario does so. | `sim::byz::adv_net` |
| E32 | F4, F34 slow executors | A slow executor delays only its Prepare (a Commit needs no execution), so P2's "one gap per `n` heights" is not claimed for it; F4 and F34's pending-execution variant check progress, not P2. At a flagged height an attestor that needs `R`'s preimage (§3.7 A2, E47) delays the slow executor's Commit too; F37's slow-executor seeds check progress and O-ATT. | `sim::scenarios::f34` |
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
64 KiB shared result witness, bounded compact signatures, generic committee key/TC metadata,
2048 control bytes and explicit framing allowance. The maximal structural frame regression checks
the actual canonical encoding against that declared bound. In-memory sync
and held-effect bounds count the full inline capacity even for an empty witness.

Native beacon control is the exact canonical finalized-pulse frame, separate from transaction
payload and DA body acquisition. Its threshold preimage binds instance, scheduling epoch,
complete epoch-context identity, parent consensus hash and parent result in addition to the
network/session/transcript/height/finalized-chain anchor. Historical readers require header/R
byte equality and those exact context joins; the current exact QC authenticates execution's
full session verification. They do not claim to independently reconstruct a DKG session from
only the transcript binding. Empty control does not establish no demand: State execution checks
required and unsolicited pulses against the same pristine parent, including Parliament demand.

The generic core/driver tests use an explicit no-demand application. They are not threshold
beacon or production Pasta qualification. Maintained native-network, message-loss, saturation,
all-seat restart and final-transaction gates must run on the connected implementation.
