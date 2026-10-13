# SCCP v1: SORA Cross-Chain Protocol (first release)

Status: normative design, first release, revision 5 (2026-10-05). Destinations
verify Taira's own Sumeragi `CommitQC`: a fixed-layout finality header `X` is
bound into every certified result, and there is no bridge key, attestation
transaction or attestor. Validators of a network with SCCP stay bonded and
slashable while any destination may still trust a committee generation that
contained them. Governance belongs to the SORA Parliament: binding juries use
anonymous on-chain ballots per `specs/parliament_private_ballot_design.md`,
there is no Parliament key or custodian, and destinations need no Parliament
key. A pause-only fast pause track complements it. SCCP registers no route
until the Parliament's qualified post-quantum ballot exists (§10.2). Section 12
records the implemented source, remaining integration and qualification work,
and external gates; §14 records the binding decisions. SCCP does not change generic
Sumeragi bridge finality (`specs/bridge_finality.md`) beyond the
certified-result layout of `specs/sumeragi.md` §4.1.1 and the consensus
signature suite of `specs/sumeragi.md` §1 item 6.

SCCP moves Taira XOR between the Taira Iroha network and three external
mainnets. The first release admits exactly these profiles:

| Profile | Tag | SCCP domain | Native identity |
|---|---|---|---|
| `sora-taira` | `0x40` | 0 | runtime `NetworkId` (genesis header hash) |
| `ethereum-mainnet` | `0x41` | 1 | EVM chain id 1 |
| `bsc-mainnet` | `0x42` | 2 | EVM chain id 56 |
| `ton-mainnet` | `0x44` | 4 | TON global id −239 |

Tag `0x43` and SCCP domain 5, which belonged to the removed TRON profile, are
unassigned, and every decoder rejects them. There are no testnet profiles, no
alias profiles and no compatibility layouts.

## 0. Conventions

- MUST, MUST NOT, SHOULD and MAY are used in the RFC 2119 sense.
- `‖` is byte concatenation. `u8`, `u16`, `u32`, `u64`, `u128` are unsigned
  integers encoded **big-endian** with exactly that width; `be32(x)` and
  `be64(x)` are the same encodings. `bytes32` is 32 raw bytes.
- `word(x)` is the 32-byte ABI word of one static value: an unsigned integer or
  `address` is left-zero-padded big-endian to 32 bytes, a `bytes32` is taken
  verbatim, and a `bool` is 0 or 1.
- `keccak256` is Ethereum Keccak-256 (not SHA3-256). `SHA-256` is FIPS 180-4.
  `H_iroha` is `iroha_crypto::Hash`: Blake2b-256 with the low bit of the last
  byte forced to 1. Taira-internal identifiers use `H_iroha`; contract-visible
  hashes use `keccak256` or `SHA-256` as stated. `ASCII("…")` is the literal
  byte string without terminator or length prefix.
- **BLS12-381** constants (golden tests MUST pin them against `blst`):

  ```
  p      = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
  HALF_P = (p − 1) / 2
         = 0x0d0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd555
  g1.x   = 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
  g1.y   = 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
  −g1.y  = 0x114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca
  ```

- **Compressed points** use the ZCash serialization: G1 is 48 bytes and G2 is
  96 bytes, stored `x.c1 ‖ x.c0`. The top three bits of byte 0 are flags:
  `0x80` compressed, `0x40` infinity, `0x20` sign. The sign bit is 1 iff `y >
  HALF_P`; for G2 the comparison uses `c1`, or `c0` when `c1 = 0`.
- "Taira-internal" structures are Norito types (`norito::{Encode, Decode}`,
  `norito::json`) and are only ever interpreted by Taira nodes and Rust tools.
  Whenever a Taira-internal value is hashed, the input is the headered Norito
  frame (`norito::to_bytes`), which advertises its layout flags.
  "Contract-visible" structures have the explicit byte layouts in §3 and MUST
  NOT depend on Norito, Rust enum discriminants or JSON spelling.
- Heights, epochs and timestamps refer to Taira unless qualified. `t(h)` is the
  canonical `creation_time_ms` of block `h`, and `h_exec` is the height of the
  block that executes the rule being described. On destinations `now_ms` is
  `block.timestamp × 1000` (EVM) or `now() × 1000` (TON).
- A Taira height `h` is **durably final** on a node when Kura holds the
  certified `SignedBlockWire` frame of `h` (the Sumeragi core's commit
  certificate over the block, `specs/sumeragi.md`) and the node's state has
  applied `h`. The Sumeragi core applies only certified blocks, so a committed
  height never reverts. Everywhere in this spec, "committed" means durably
  final.
- **Epochs** are the fixed-length epochs of the Sumeragi core
  (`specs/sumeragi.md` §11.7): with genesis height `g` and the scheduled
  `epoch_length_blocks`, the genesis block and the first `epoch_length` heights
  after it form epoch 0, and each following run of `epoch_length` heights is
  the next epoch (`sumeragi_epoch(h, g, epoch_length)`). A height is an epoch
  **boundary** iff it is the last height of its epoch. Committees change only
  at certified boundaries (`specs/sumeragi.md` §10). SCCP committee
  generations (§4.2) change at those key changes and also at heartbeats (same
  keys) and resyncs.
- **Taira** is the global Sumeragi instance, kind 0 index 0, with instance id
  `I = H_iroha("sumeragi/instance" ‖ genesis_hash ‖ chain_id ‖ 0x00 ‖ be32(0))`
  (`specs/sumeragi.md` §1 item 8).
- `C_h` is the scheduled committee of height `h`: `n = 3f + 1` BLS-normal keys
  with `4 ≤ n ≤ 31`, in canonical order (strictly ascending by `kb(pk)`, every
  key with the same length prefix), and `q = n − f`.
- A committee generation `g` (§4.2) is **retained** while its record exists and
  **liable** while `liable(g)` holds (§4.8). `lc(h)` is the liability clock of
  block `h` (§4.8).
- **Amounts.** Taira XOR amounts are `Numeric` values of the XOR definition
  (scale ≤ 9). `taira_units(q) = mantissa(q) × 10^(9 − scale(q))`; it MUST be
  an exact integer with `0 < taira_units(q) < 2^128`. Every destination token
  has 9 decimals, so one token unit equals one Taira unit on every chain and no
  scaling happens anywhere.

## 1. Design summary

### 1.1 Trust model

**Taira finality authorizes outbound value.** After block `h` executes, every
voter computes the 221-byte finality header `X_h`: the block's SCCP commitment
root and message count, the history accumulator, the committee generation that
certifies `h` and, at a rotation, the successor's committee root and validity.
Every voter binds it into the result it signs, `R_h = SHA-256(RESULT_TAG ‖ X_h
‖ D_body)` (§3.6). `CommitQC(h)`, exactly `q = n − f` BLS signatures of `C_h`
over `SHA-256` of the 165-byte Commit preimage, therefore certifies `X_h` with
exactly the strength of the block. A destination keeps only the current
generation `{root, generation, start, high, untilMs}`. It verifies one
aggregate signature with one pairing check (Ethereum and BSC through EIP-2537,
TON through `BLS_FASTAGGREGATEVERIFY`), verifies a keccak Merkle path to the
leaf, consumes the message nonce in an on-chain set, and mints under an
immutable supply cap before the message's deadline. Each generation's trust
deadline is fixed when the destination installs it, and only a genuine handoff
signed by the current generation installs a successor: identical, stale and
future-dated certificates never extend trust (§5.1.2). A message that is not
minted by its deadline is **voided** on the destination with the same nonce
bit, and Taira refunds it once the void is proven.

External→Taira transfers are proven natively by every Taira node against
permissionless on-chain light clients of the source chain. A proven message is
recorded and then settled, immediately or later, without re-proving. There is
no trusted setup, prover, relayer, archive, hosted service or bridge key: every
step is a permissionless transaction that a wallet builds from Taira Torii and
public RPC. Validator nodes run an in-node keeper by default that advances the
light clients, submits due keepalives and watches destinations (§4.13.4). It
adds liveness, never trust.

**Accountability.** Departed validators keep their keys. Validators of a
network with SCCP therefore stay bonded and slashable while any destination may
still trust a generation that contained them (§4.8). The unbonding delay covers
the validity window plus a grace period; a liability clock that a Taira halt
cannot consume measures it; and a destination-progress gate keeps a generation
liable until every destination network's light client has finalized past its
deadline. Any `CommitQC`-valid certificate of a generation for a Taira commit
preimage whose block or result is not Taira's at that height is slashing
evidence against every signer (`SubmitSccpForgeryEvidenceV1`, §4.9), applied
through the consensus penalty pipeline. It also holds every route revision that
may be at that generation until the Parliament attests the deployment's
progress or quarantines it (§4.10).

**The Parliament decides; destinations need no Parliament key.** Every SCCP
governance decision is taken by the SORA Parliament through
`ProposeSccpRouteGovernance` and enacted deterministically at block start
(§4.14). Binding juries use anonymous on-chain ballots
(`specs/parliament_private_ballot_design.md`); there is no Parliament key or
custodian of any kind. A pause-only fast pause track, decided by a standing
citizen panel through public account-signed endorsements, can pause a network
for a bounded time (§4.14.7). Every decision that affects a destination becomes
a control leaf of the enacting block's commitment tree, and any `CommitQC`
covering that block proves it (§4.14.6).

Safety of Taira→external rests on Taira consensus plus historical-key
accountability (§9.1). Safety of external→Taira equals each source chain's own
finality assumption plus Taira consensus. Both trust the Parliament for what it
enacts, and the fast pause panel for pauses only.

### 1.2 Settled sub-decisions

| Question | Decision | Why |
|---|---|---|
| Outbound finality | A `CommitQC` of exactly `q = n − f` signers of the destination's current generation, over a result that binds the 221-byte header `X` (§3.6–§3.8). The vote preimage, the QC and the core wire are unchanged | The proof exists when `h` commits. No second signature round, no application key family and no attestor liveness. Rejected: a new vote-preimage field (it changes every core layout and is no stronger); certifying `X_h` through the header of `h + 1` (idle chains make no `h + 1`); a commit-attestation extension (it needs an application key family); a post-commit signing round (an attestation transport under another name) |
| Consensus signature suite | Only Sumeragi kinds `0x01`–`0x05` and RS16 availability statements sign `SHA-256(P)` of an allowlisted preimage `P` under the IETF min-pk PoP ciphersuite `DST_SIG`, through a dedicated consensus API. Every other BLS signature keeps the existing w3f transcript, and the w3f proof of possession stays the rogue-key defence (§3.8) | Destinations hash to G2 under a standard DST with audited code. A 32-byte message fits TON's message slice and fixes the EVM cost. Reserving `DST_SIG` keeps every other signing context from ever producing a vote. Unifying all BLS signatures is later work |
| Committee generations | A generation changes at a key-set change at an epoch boundary, at a heartbeat once it is `committee_heartbeat_ms` old (same keys), and at a resync after a missed boundary. Each generation has an immutable deadline anchored at its certified start (§4.2) | Deadlines that only a genuine handoff renews bound how long departed keys stay usable; heartbeats renew maintained destinations |
| Destination state | The current generation only, an `equivocated` latch, checkpoint ids and the pause state; no record of past generations (§5.1) | Constant TON state; a retired quorum cannot touch an up-to-date deployment |
| Trust model | Exit delay plus slashing: liability windows, a liability clock, a destination-progress gate, forgery evidence and per-revision holds (§4.8–§4.10) | Validators exit freely, but their stake is released only after no destination can still trust them |
| Certified time | A liveness-only executor guard withholds Prepare votes on blocks timed ahead of the local clock, and on stale blocks that apply due work; certified re-proposals are exempt. No validity rule reads a clock (§4.3; `specs/sumeragi.md` §4.5) | Bounds Byzantine-chosen block times, which anchor deadlines, without a local-clock verdict |
| Idle chains | No empty blocks. A permissionless, fee-exempt, due-gated `Keepalive` produces exactly the blocks that heartbeats and governance work need (§4.7) | Iroha produces no block without a transaction |
| Fees and permissions | Keepalives, forgery evidence, keeper light-client advances and recipient self-claims are fee-exempt only when eligible. Eligible advances and self-claims are exempt on success and charged the ordinary fee on failure; a keepalive that applies no due work or forgery evidence that fails at execution makes its block `Invalid` (K2, R-EX), so those two never fail inside a valid block. Eligibility is one predicate per kind over the committed parent state, the authority and the payload, shared by admission, fee quoting, the per-block quotas and execution, plus pre-verification and deduplication (§4.19). A transaction of an exempt shape that is not eligible pays the ordinary fee and is never refused for its shape. The only SCCP permission token is `CanProposeSccpRouteGovernance`, which only allows proposing and is granted and revoked only in genesis | A fee-exempt root is safe only when admission rejects invalid and duplicate eligible payloads before the queue; relayers, third-party settles and paid advances must stay admissible |
| Storage and pruning | Messages, control messages, inbound records, consumed sets, history leaves, per-block commitments and SCCP governance revisions are permanent. Generation records and anchor chunk roots are pruned once no longer liable (§4.11). Light-client checkpoints keep one permanent entry per stride (§4.13.1) | Old messages stay provable through the history root under any newer certificate; old burns stay provable through retained checkpoints |
| Long-range attacks, weak subjectivity | Trust deadlines anchored at certified generation starts (14 d default, 30 d immutable maximum), heartbeat renewal, and exit delay plus slashing. A destination that is not rotated in time freezes, and its in-flight value is refunded through voids (§5.1.2, §9.9) | Validators exit freely, so departed keys are bounded by time and made accountable by stake; voids make a freeze lossless |
| Old messages | Append-only **history accumulator** over SCCP-bearing blocks; every `X` carries its root, so any later certificate proves any older message (§3.5) | Destinations need only a current certificate |
| Failed transfers | Outbound: each message carries a destination-time `deadline_ms`. After it, or once the destination is frozen, anyone voids the nonce on the destination, and Taira refunds on proof of the void (§4.16, §5.1.8). Inbound: prove, then settle; a proof is recorded whenever the revision is not `Staged`, and settlement retries without a proof (§4.12). Undecodable or uncreditable recipients bounce | No value is stranded by a paused, held, retired or frozen destination, or by a temporarily unsettleable claim |
| New-user claims | Settlement registers a missing recipient account. A recipient with no XOR self-claims fee-exempt, and the fee is deducted from the proceeds (§4.12.4) | No faucet, sponsor program or hosted onboarding |
| Light-client liveness | Permissionless proof-carrying advances; the in-node keeper, enabled by default, with compiled default public RPC lists; Parliament re-initialization and trusted checkpoints as a last resort (§4.13.4) | Light clients have weak-subjectivity bounds that idle lanes would otherwise exceed. The keeper adds liveness, never trust |
| Escrow | One core-created escrow account per route, derived without the revision, created at genesis. Core rejects every non-SCCP debit, credit, registration or unregistration of it. `balance(escrow(route)) = Σ_r liability(r) + stranded(route)` (§4.15) | Registration cannot be front-run, and upgradable executor code cannot drain escrow |
| Governance | SORA Parliament only: `ProposeSccpRouteGovernance` (bonded citizen or `CanProposeSccpRouteGovernance`) → Parliament bodies with a binding jury → certificate → block-start enactment. The expected head is scoped per SCCP subject. `RegisterRoute` pins a retained committee generation; Taira recomputes the TON and EVM deployment addresses. SCCP attempts and their progress transitions are permissionless and core-derived. No route can be registered before the binding ballot and reconciliation exist (§4.14, §10.2) | Governance belongs to citizens, not to validators or keys. Per-subject heads keep independent proposals from superseding each other |
| Destination pause | Two tracks reach destinations as control leaves that carry the revision's complete pause state: track 1 (Parliament) and track 2 (fast pause). The effective pause is the Parliament pause or an unexpired fast pause; fast pauses expire on the destination by time alone. Burns, checkpoints, rotations, voids and controls are never paused (§3.4, §5.1.6) | One authority per track, no privileged key on the destination, and lapses need no relay |
| Fast pause | Pause-only. A standing panel, a disjoint backup and a reserve are drawn from the epoch-boundary beacon pulse outside the Parliament attempt reducer. Either panel decides by public, account-signed endorsements; pauses lapse automatically and can be renewed; the Parliament can lift, confirm or suspend (§4.14.7) | A brake whose latency is minutes rather than a full Parliament round, that cannot do anything but delay |
| Destination replay protection | Dense per-(network, revision) outbound nonce assigned by Taira. EVM uses a bitmap `mapping(uint256 ⇒ uint256)`; TON uses sequentially activated bucket child contracts of 512 flags that only the minter activates, once per bucket (§5.3.4) | One storage word per 256 messages. The TON account-state cap (65 536 cells) forbids an in-contract dictionary |
| Token and bridge shape | One contract per destination: an ERC-20 with the bridge built in (EVM), deployed through deterministic CREATE2; or one Jetton master with the bridge built in plus standard wallets and consumption buckets (TON). 9 decimals everywhere | No cross-contract minting, no code-hash rechecks, no unit scaling, and Taira can recompute every deployment address |
| Taira resets | Taira identity is the runtime `NetworkId`. Genesis carries a random reset nonce, so every reset has a fresh identity. Nothing Taira-specific is compiled into Rust or contracts. Old deployments freeze when their last generation's deadline passes (§4.18) | A compiled Taira identity would make every reset and devnet unusable |
| Contract toolchains | Solidity 0.8.31 (`solc` +commit.fd3a2265), legacy pipeline, `evmVersion: cancun`, for Ethereum and BSC; Acton 1.2.0 / Tolk 1.4.2 for TON. All ship native macOS arm64 binaries (§5.5) | Every contract builds natively on macOS arm64 |

### 1.3 End-to-end shape

```mermaid
sequenceDiagram
    participant P as Parliament / fast pause panel
    participant U as Wallet / relayer / watcher
    participant T as Taira (validators, Torii, Kura)
    participant D as Destination contract
    U->>T: RecordSccpMessage{network, expected_revision, amount, recipient} (signed tx)
    Note over T: voters: CT1/CT5 guard Prepare, execute, X_h, R_h = SHA-256(RESULT_TAG ‖ X_h ‖ D_body)
    Note over T: CommitQC(h) = q BLS signatures on SHA-256(Commit preimage(…, R_h, …)) under DST_SIG
    U->>T: GET /v1/sccp/messages/{id}/proof
    U->>D: submitCheckpoints([rotations…, latest]) when D lags
    U->>D: finalizeFromCheckpoint(X, proof) or finalizeFromTaira(certificate, proof) before the deadline
    Note over U,D: after the deadline: voidExpired(...) on D, then SubmitSccpOutboundVoidV1 on Taira refunds
    U->>D: transferToTaira(recipient, amount, nonce)  (reverse direction)
    U->>T: [Register<Account>(self)?, AdvanceSccpLightClientV1…, SubmitSccpInboundMessageV1] (signed tx)
    T->>T: native light-client proof check, inbound record, settlement (release or bounce)
    P->>T: certificate or panel quorum → enacted at block start → control leaf (track 1 or 2, full pause state)
    U->>D: applyControl(...)
    U->>T: Keepalive when a heartbeat or governance work is due on an idle chain
    U->>T: SubmitSccpForgeryEvidenceV1(certificate) when a destination shows a certificate Taira never made
    Note over T: slash every signer through the penalty pipeline; hold every revision that may be at that generation
```

## 2. Networks, identities and lanes

### 2.1 Identity words

Each profile has a 1-byte tag and a 32-byte identity word:

| Profile | `tag` | `identity_word` |
|---|---|---|
| `sora-taira` | `0x40` | the 32 bytes of Taira's `NetworkId` (hash of the genesis block header), read from world state at runtime |
| `ethereum-mainnet` | `0x41` | `word(1)` |
| `bsc-mainnet` | `0x42` | `word(56)` |
| `ton-mainnet` | `0x44` | two's-complement `int256(−239)`, i.e. `0xFF…FF11` |

`network_bytes(p) = tag(p) ‖ identity_word(p)` (33 bytes).

SCCP reads Taira's identity only from world state: no SCCP hash or check uses
the Taira `ChainId` label or a compiled Taira chain id, genesis hash or network
id. The I105 discriminant is not part of any SCCP hash. In the finality header,
`network_id` is this identity word (§3.6).

### 2.2 Lanes

A lane is a directed pair with exactly one Taira endpoint:

```
lane_bytes(source, target) = network_bytes(source) ‖ network_bytes(target)   // 66 bytes
```

Taira→X lanes carry outbound messages (minted on X). X→Taira lanes carry
inbound messages (burned on X, released on Taira).

### 2.3 Routes

One route per external profile, identified by `route_id` text:

| Profile | `route_id` | Destination token | Decimals |
|---|---|---|---|
| ETH | `taira_eth_xor` | ERC-20 bridge contract | 9 |
| BSC | `taira_bsc_xor` | BEP-20 bridge contract | 9 |
| TON | `taira_ton_xor` | Jetton master (bridge) | 9 |

Taira XOR has scale 9 (existing Taira genesis asset definition, Global policy),
so every amount in this spec is in Taira units (§0). A route has numbered
**revisions** (`u32`, from 1). Each revision binds exactly one deployed
destination contract (§4.14). `asset_id` text is `xor`.

## 3. Canonical contract-visible encodings

### 3.1 Account codecs

| Codec | Name | Bytes | Validity |
|---|---|---|---|
| 1 | `canonical_text` | 1..=256 | printable ASCII `0x21..=0x7e`; used for `asset_id` and `route_id` only |
| 2 | `evm_address20` | 20 | nonzero |
| 3 | `taira_account` | 1..=1024 | canonical Iroha `AccountAddress` payload bytes (header ‖ controller; the I105 payload without discriminant or checksum). Contracts check only the length; Taira decodes (§4.12.3) |
| 7 | `ton_account36` | 36 | `i32` workchain (big-endian) = 0, then a nonzero 32-byte account id |

Codecs 4, 5 and 6 are unassigned; codec 5 belonged to the removed TRON profile
and every decoder rejects it. The 1024-byte bound admits Taira multisig
controllers with many members. A Taira authority whose `AccountAddress` exceeds
it cannot send (§4.4), and wallets refuse such recipients before burning
(§7.2).

### 3.2 Transfer payload

```
payload =
  u8   kind            = 0x02            // Transfer
  u8   version         = 0x01
  u32  source_domain
  u32  dest_domain
  u64  nonce
  u32  route_revision                    // nonzero
  u64  deadline_ms                       // Taira→X: destination-time mint deadline; X→Taira: 0
  u32  asset_home_domain = 0             // SORA
  u8   asset_id_codec    = 1
  u16  asset_id_len ‖ asset_id           // "xor"
  u128 amount                            // Taira units = token units, nonzero
  u8   sender_codec    ‖ u16 sender_len    ‖ sender
  u8   recipient_codec ‖ u16 recipient_len ‖ recipient
  u8   route_id_codec  = 1
  u16  route_id_len ‖ route_id           // e.g. "taira_eth_xor"
```

Rules (decoders MUST enforce all of them and MUST reject trailing bytes):

- Each variable field has the length range of its codec (§3.1). Total payload ≤
  4 096 bytes.
- `source_domain ≠ dest_domain`, exactly one of them is 0, and the other is 1,
  2 or 4.
- `deadline_ms ≠ 0` iff `source_domain = 0`. A destination mints only while
  `now_ms ≤ deadline_ms` and voids only after it (§5.1.5, §5.1.8).
- `amount ≠ 0`; `amount < 2^96` when either endpoint is TON.
- Sender and recipient codecs are determined by the domains:

| Direction | `sender_codec` | `recipient_codec` |
|---|---|---|
| Taira → ETH/BSC | 3 | 2 |
| Taira → TON | 3 | 7 |
| ETH/BSC → Taira | 2 | 3 |
| TON → Taira | 7 | 3 |

- `route_id` MUST equal the route of the external endpoint; `route_revision`
  MUST name a registered revision of that route.

Integers are big-endian and length prefixes are `u16`, so contracts parse
without byte swaps.

### 3.3 Payload hash and message id

```
payload_hash = keccak256(ASCII("SCCP/PAYLOAD/V1") ‖ payload)
message_id   = keccak256(ASCII("SCCP/MESSAGE/V1") ‖ lane_bytes(source, target) ‖ payload_hash)
```

`message_id` is the global identity of a message in both directions. It binds
the Taira network identity, so it differs across Taira resets.

### 3.4 Block commitment tree

Leaves are the **SCCP messages** recorded by one Taira block, in
`commitment_index` order (0-based execution order, dense; §4.5). An SCCP
message is either a **transfer** (an outbound payload, §3.2) or a **control**
(the complete pause state of one route revision after a Parliament or
fast-pause change, §4.14.6):

```
destination_word = word(address20)                  // EVM: the contract address
                 | ton_account_id32                 // TON: account id of the Jetton master (workchain 0)
transfer_leaf = keccak256(ASCII("SCCP/LEAF/V1") ‖ message_id ‖ destination_word)
control_leaf  = keccak256(
      ASCII("SCCP/CONTROL/V1")            //  15 bytes
    ‖ lane_bytes(sora-taira, target)      //  66 bytes: 0x40 ‖ Taira NetworkId ‖ tag(target) ‖ identity_word(target)
    ‖ destination_word                    //  32 bytes
    ‖ u32 route_revision                  //   4 bytes, nonzero
    ‖ u64 control_nonce                   //   8 bytes, ≥ 1, strictly increasing per (network, revision)
    ‖ u8  track                           //   1 byte: 1 PARLIAMENT, 2 FAST_PAUSE
    ‖ u8  parliament_paused               //   1 byte: the revision's Parliament pause flag after this change
    ‖ u64 fast_pause_until_ms             //   8 bytes: expiry of the revision's active fast pause, or 0
    ‖ certificate_id                      //  32 bytes
    ‖ effect_hash)                        //  32 bytes; the preimage is 199 bytes
node(l, r) = keccak256(ASCII("SCCP/NODE/V1") ‖ l ‖ r)
```

**Control semantics.** A control leaf carries the **complete pause state** of
`(network, revision)` after the change, plus the authority that made it. A
destination that applies the newest leaf therefore holds both pause states
exactly, whatever was lost or reordered before it (§5.1.6).

- Track 1 (Parliament): `certificate_id = GovernanceCertificateId::derive_v1`
  of the enacted certificate, and `effect_hash` is that certificate's
  `effect_preimage_hash`.
- Track 2 (fast pause): `certificate_id =
  SccpFastPauseCertificateId::derive_v1` and `effect_hash` is that
  certificate's `effect_preimage_hash` (§4.14.7).
- Constraints, checked by Taira and by destinations (`BadControl`): `track ∈
  {1, 2}`; `parliament_paused ∈ {0, 1}`; `track = 2 ⇒ fast_pause_until_ms ≠ 0`;
  `certificate_id ≠ 0`; `effect_hash ≠ 0`. A destination takes
  `parliament_paused` through a typed field (`bool parliamentPaused` on EVM,
  where the ABI decoder refuses a dirty word before any contract check, and
  `Bool` on TON), so a value other than 0 or 1 never reaches its check: that
  constraint is observable on Taira and in the references only.
- Recording rules, checked by Taira before the constraints (§4.14.6): the
  target is a first-release external network, `route_revision ≥ 1` and
  `control_nonce ≥ 1`. The Rust and Python references label their refusals
  `TargetNotExternal`, `ZeroRevision` and `ZeroControlNonce`
  (`control_v1.json`, `rejected[].error`). These are reference labels, not
  contract errors: a destination is never asked to record a control.
- There is no lapse leaf: destinations expire a fast pause from the
  authenticated `fast_pause_until_ms` by their own clock.

The preimages differ in prefix and length (transfer 76 bytes, node 76 bytes
with a different prefix, control 199 bytes), and verifiers always compute the
leaf they check from its fields, so no leaf kind can pass as another or as an
internal node. `leaf` without qualification means either kind.

On TON, 199 bytes exceed one cell, so the contract hashes two byte-aligned
builders with `HASHEXT` id 3: `b1` = tag ‖ lane ‖ destination word ‖ revision ‖
nonce (125 bytes) and `b2` = track ‖ `parliament_paused` ‖
`fast_pause_until_ms` ‖ `certificate_id` ‖ `effect_hash` (74 bytes).

Example control leaves (pinned in `fixtures/sccp/control_v1.json`, §11), for
Taira `NetworkId = 0x11…11` (32 bytes of `0x11`), target `ethereum-mainnet`,
`destination_word = 0x00…00 ‖ 20 bytes of 0x22`, `route_revision = 1`:

| nonce | track | `parliament_paused` | `fast_pause_until_ms` | `certificate_id` | `effect_hash` | leaf |
|---|---|---|---|---|---|---|
| 1 | 1 | 1 | 0 | `0x33^32` | `0x44^32` | `0xd9be284f6412d8e310b35afa921f8244f8d56cc64fbfc795d58701c11dce4d77` |
| 2 | 2 | 0 | 1 700 604 800 000 | `0x55^32` | `0x66^32` | `0xfbdf5c5743292897ecf43c3d74fe0a3d3946aa73219bdab2f0a3e33bc0b988e0` |
| 3 | 1 | 1 | 1 700 604 800 000 | `0x77^32` | `0x88^32` | `0x8afcebc533342cb86836b0195edc6a55e8e998d8e52d85f1fbf2c2707193c518` |
| 4 | 1 | 0 | 0 | `0x99^32` | `0xaa^32` | `0xb52aafb5bd2fcc77db32e1dfb8a92890b97adc2b9e81dd30f63dba3c059c8df3` |

The preimage of nonce 2 is `534343502f434f4e54524f4c2f5631 40 11…11 41 00…01
00…00 22…22 00000001 0000000000000002 02 00 0000018bf3f1ec00 55…55 66…66`.

Tree rule ("promote-odd"): level 0 is the leaf list. Each next level pairs
elements left to right, and an unpaired last element is promoted unchanged. The
root of a single-leaf tree is that leaf. A block has 1..=512 leaves of both
kinds together (`SCCP_MESSAGES_MAX_PER_BLOCK_V1`), so paths have at most 9
siblings.

Verification is positional and binds the leaf index and count:

```
fn merkle_root(leaf, index, count, siblings) -> bytes32:
    require count ≥ 1 and index < count
    h, k = leaf, 0
    while count > 1:
        if index is odd:              h = node(siblings[k], h); k += 1
        elif index + 1 < count:       h = node(h, siblings[k]); k += 1
        # else: promoted, no sibling at this level
        index = index >> 1
        count = (count + 1) >> 1
    require k == len(siblings)
    return h
```

### 3.5 History accumulator

Taira keeps an append-only list of every SCCP-bearing block (message count > 0,
counting transfer and control leaves), in height order:

```
history_leaf(height, sccp_root, message_count) =
    keccak256(ASCII("SCCP/HISTORY/V1") ‖ u64 height ‖ sccp_root ‖ u32 message_count)
history_root(size) = promote-odd root (§3.4 node rule) over the first `size` history leaves
```

`history_root(0) = 0x00…00`. The promote-odd tree equals a right-bagged Merkle
mountain range: with the perfect-subtree roots `P_a, P_b, …, P_z` of the binary
decomposition of `size` (largest first), `root = node(P_a, node(P_b, …
node(P_y, P_z)))`. Taira therefore maintains it in O(log size) state (the
peaks), and verifiers use the same `merkle_root` function with `(leaf_index,
history_size)`. History paths have at most 32 siblings (`history_size ≤ 2^32`
is enforced). Every active finality header carries the accumulator after its
block (§3.6), so a certificate of any later block proves any older message
(§5.1.5).

### 3.6 Finality header `X` and the certified result `R`

**Layout.** `X` (`SccpFinalityHeaderV1`) is exactly 221 bytes:

| Offset | Size | Field | Encoding |
|---|---|---|---|
| 0 | 16 | `magic` | `ASCII("SCCP/FINALITY/V1")` |
| 16 | 32 | `network_id` | the instance's genesis-derived `NetworkId` (for Taira, the §2.1 identity word) |
| 48 | 8 | `height` | `u64 h` |
| 56 | 8 | `timestamp_ms` | `u64 t(h)` |
| 64 | 1 | `flags` | bit 0 `ACTIVE`, bit 1 `ROTATION`, bits 2–7 zero |
| 65 | 4 | `message_count` | `u32` |
| 69 | 32 | `sccp_root` | bytes32 |
| 101 | 8 | `history_size` | `u64` |
| 109 | 32 | `history_root` | bytes32 |
| 141 | 8 | `generation` | `u64`: the generation that certifies `h` (§4.2 G5) |
| 149 | 32 | `committee_root` | `committee_root(C_h)` (§3.7) |
| 181 | 8 | `validity_ms` | `u64`: with `ROTATION`, the validity granted to the successor generation; otherwise 0 |
| 189 | 32 | `next_committee_root` | with `ROTATION`, `committee_root(C_{h+1})` (equal to `committee_root` at a heartbeat); otherwise zero |

TON splits `X` at offset 109: `XHead = X[0..109)` (872 bits) and `XTail =
X[109..221)` (896 bits).

**When `ACTIVE` is set.** `ACTIVE` is set iff SCCP exists (`sccp_parameters` is
present), the executing instance is Taira (global kind 0, index 0), and the
authenticated inputs of `h` are present and consistent (§4.2 G4, G7). With
`ACTIVE`:

- `message_count` and `sccp_root` are the `sccp_block_commitments[h]` entry, or
  0 and zero when there is none;
- `history_size` and `history_root` describe the accumulator after `h`,
  including `h`'s own leaf;
- `ROTATION` is set iff rule G2 ends the current generation at `h`, at a key
  change or at a heartbeat. A resync (G7) never sets it.

**Invariants.** Every producer and every parser MUST enforce X1–X7 through one
function, `SccpFinalityHeaderV1::parse`:

| # | Invariant |
|---|---|
| X1 | `magic` is exact, and `flags & 0xFC = 0` |
| X2 | `ACTIVE` unset ⇒ bytes `[65..221)` are zero and `ROTATION` is unset |
| X3 | `ACTIVE` set ⇒ `generation ≥ 1` and `committee_root ≠ 0` |
| X4 | `message_count = 0 ⇔ sccp_root = 0`, and `message_count ≤ 512` |
| X5 | `history_size = 0 ⇔ history_root = 0`, and `history_size ≤ 2^32` |
| X6 | `ROTATION` set ⇒ `next_committee_root ≠ 0`, `1 ≤ validity_ms ≤ MAX_VALIDITY_MS`, `height ≤ 2^64 − 2` and `generation ≤ 2^64 − 2` (the successor's start, `height + 1`, and its generation, `generation + 1`, are `u64` values). `ROTATION` unset ⇒ `next_committee_root = 0` and `validity_ms = 0`. `next_committee_root = committee_root` is allowed (heartbeat) |
| X7 | `height ≥ 1` |

`parse` first requires exactly 221 bytes (`Length`). It then evaluates the
invariants in the order X1, X2 (`ACTIVE` unset) or X3 (`ACTIVE` set), X4, X5,
X6, X7, and reports the first one violated. A destination reports every one of
them, and a wrong length, as `BadHeader` (§5.1.3).

**Inactive form.** `X = magic ‖ network_id ‖ be64(h) ‖ be64(t(h)) ‖ 0x00 ‖
0^156`. It is used by every non-global root that uses
`ExecutionResultCommitment` (dataspace roots, private developer anchors), by
Taira before SCCP is initialized, and by Taira blocks whose inputs are missing
(§4.6). Lane instances keep their own `LANE_RESULT_TAG` result and carry no
`X`. Destinations reject an inactive `X`.

**Certified result.** For every instance that uses `ExecutionResultCommitment`:

```
body   = norito::encode_canonical(ExecutionResultCommitment)     // ≤ MAX_RESULT_BODY_BYTES = 65 315
D_body = H_iroha(RESULT_BODY_TAG ‖ body)                           // 32 bytes, opaque to destinations
R      = SHA-256(RESULT_TAG ‖ X ‖ D_body)                          // 277-byte input, raw 32 bytes
```

- `RESULT_TAG = ASCII("iroha/sumeragi/result/v1")` (24 bytes) and
  `RESULT_BODY_TAG = ASCII("iroha/sumeragi/result-body/v1")` (29 bytes).
- `R` is not an `H_iroha` value: code MUST NOT pass it through
  `Hash::prehashed`, `HashOf` or any type that checks or sets the marker bit.
- The stored result preimage (`CommitCertificate.result_preimage`) is
  `X ‖ body`, at most `MAX_RESULT_PREIMAGE_BYTES = 65 536` bytes in total
  (`specs/sumeragi.md` §3.6, §4.1.1). It is local publication and certified-read
  evidence, never a vote or QC sidecar.
- `result_of_preimage(p)` is the only `R` function, for voters and readers
  alike. It returns nothing if `len(p) < 222`, if `len(p) > 65 536`, or if
  `SccpFinalityHeaderV1::parse(p[0..221])` fails; otherwise it returns
  `SHA-256(RESULT_TAG ‖ p[0..221] ‖ H_iroha(RESULT_BODY_TAG ‖ p[221..]))`.
  Callers MUST treat nothing as a mismatch, never as a local fault.
- SHA-256 is native on TON (`HASHEXT` id 0) and on EVM (precompile `0x02`), and
  it is already inside the BLS suite.

**Readers.** Every Rust reader that holds `X ‖ body` without executing it MUST
decode it through `CertifiedResultV1::decode(p, scope)`, with `scope ∈
{TairaGlobal, NonGlobal}`. `decode` performs C1–C4 and the scope rule. A reader
that also holds the block MUST then call
`CertifiedResultV1::check_block(height, timestamp_ms)` with the block's height
and canonical time; it performs C5.

- **C1.** X1–X7 hold, and `X.height = body.height`.
- **C2.** `X.network_id` equals the network of the epoch context that the
  certified schedule assigns to `X.height`: the body's own `schedule.current`.
- **C3.** With `ACTIVE`: `X.committee_root` equals the `committee_root` of that
  context's committee keys.
- **C4.** With `ACTIVE`: if the body carries a boundary decision
  (`schedule.boundary`) whose successor committee (`boundary.next`) has a root
  that differs from `X.committee_root`, then `ROTATION` is set and
  `X.next_committee_root` equals that root; if `ROTATION` is set with
  `X.next_committee_root ≠ X.committee_root`, the body MUST carry that boundary
  decision.
- **C5** (`check_block`). `X.height` equals the block height, and
  `X.timestamp_ms = t(X.height)`.
- **Scope** (`decode`). `NonGlobal` requires `ACTIVE` unset.

`decode` runs its checks in this order and reports the first failure: the
preimage length (`222 ≤ len(p) ≤ 65 536`); the parse of `X` (X1–X7); the scope
rule; the decode of the body and the body's own validation; then the height
equality of C1, C2, C3 and C4.

The SCCP fields (`sccp_root`, `message_count`, `history_*`, `generation`,
`validity_ms` and heartbeat rotations) cannot be derived from the body. Their
only authority is the quorum signature, and Taira's forgery evidence (§4.9)
holds signers to them.

### 3.7 Committee root and certificate encodings

**Committee root.**

```
committee_root(C) = keccak256(ASCII("SCCP/COMMITTEE/V1") ‖ u8 n ‖ PK_0 ‖ … ‖ PK_{n−1})   // 18 + 48n bytes
```

Keys are compressed and in canonical order, and bitmap index `i` is `PK_i`.
Compressed keys suit TON's BLS opcodes, and EVM takes each signer's `y` from
calldata, which avoids a square root per key. Example (synthetic, not points):
keys `0x01^48, 0x02^48, 0x03^48, 0x04^48` give
`0xfe8902a93a6592a748b8528a9f49312e9cbc5d1abcccb1ff7431b0acba92b2b9`.

The root is defined for `1 ≤ n ≤ 255` keys only, the counts the `u8` names. A
list with no key, or with more than 255, has no root: the function returns
nothing for it, and no value (the zero root included) stands in for a missing
root. Committees are further restricted to `n ∈ {4, 7, …, 31}` (§3.8).

**`QC_FIXED` (116 bytes)** carries the fields of a `CommitQC` that a
destination needs:

| Offset | Size | Field | Source |
|---|---|---|---|
| 0 | 8 | `epoch` | `qc.epoch.epoch` |
| 8 | 32 | `epoch_context` | `qc.epoch.context` |
| 40 | 8 | `view` | `qc.view` |
| 48 | 32 | `block_hash` | `qc.block_hash` (the Sumeragi core block hash) |
| 80 | 32 | `result_body` | `D_body` |
| 112 | 4 | `signers` | `be32(Σ_j bitmap[j] << 8j)` |

`signers` is derived from the Sumeragi bitmap, in which bit `i` is canonical
index `i`, LSB-first within each byte. Example: `n = 31`, indices {0, 9, 30}:
bitmap bytes `01 02 00 40`, `signers = 0x40000201`, encoded `40 00 02 01`.
Copying the bitmap bytes raw would give `0x01020040`, which is wrong (a
negative vector).

**Commit preimage and message.**

```
P = ASCII("sumeragi/sig") ‖ 0x03 ‖ I ‖ be64(epoch) ‖ epoch_context ‖ be64(X.height) ‖ be64(view)
    ‖ block_hash ‖ R                                    // 165 bytes (specs/sumeragi.md §3.3)
m = SHA-256(P)
checkpoint_id(X) = keccak256(X)
```

**Signatures and committee on the wire.** On TON and Taira the aggregate
signature is the 96-byte compressed `qc.agg_sig`. On EVM it is the same point
uncompressed, as four 48-byte big-endian limbs in the order `x.c0 ‖ x.c1 ‖
y.c0 ‖ y.c1`: 192 bytes of calldata (ZCash compression stores `c1` first). The
192 bytes are not a precompile input: the contract zero-extends each limb to 64
bytes (16 zero bytes, then the limb) to form the 256-byte G2 input of EIP-2537.
On EVM the committee is supplied as `48n` bytes of compressed keys and
`signerYs`, `48q` bytes holding each signer's `y` in ascending index order; a
signer's `x` and `y` are zero-extended the same way to the 128-byte G1 input.
TON reads the keys from storage.

### 3.8 Consensus signatures and the destination verification relation

**Suite.** Sumeragi signatures of kinds `0x01`–`0x05` and the RS16 availability
statements sign `m = SHA-256(P)` for an allowlisted preimage `P` only, as `σ =
sk · hash_to_G2(m, DST_SIG)` with `DST_SIG =
ASCII("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")` (43 bytes), the IETF
min-pk proof-of-possession ciphersuite. The allowlist, the consensus API and
the registry of every other BLS signing context are normative in
`specs/sumeragi.md` §1 item 6. Every other BLS signature, including the
consensus-key proof of possession, keeps the existing w3f transcript (`TODO:`
unify every BLS signature on RFC 9380 suites in a later release). Only the
consensus API ever hashes under `DST_SIG`, so no signature obtained in another
context (Torii's chosen-challenge node attestation, P2P relay digests,
lifecycle certificates) can verify as a vote or a `CommitQC` share.

**Signing relation** (the Rust reference
`iroha_sccp::v1::finality::verify_certificate` applies `KeyValidate` to every
signer key; it equals the destination relation on every committee whose keys
pass `KeyValidate`, which is every committee under a root Taira admitted):

- `KeyValidate(PK)`: the encoding is canonical, not the identity, and in the
  subgroup. It is an admission invariant on Taira, and no destination
  re-checks it key by key: an EVM destination observes the aggregate key only
  (`verify_certificate_by_aggregate` is that form), and a TON destination has
  the verdict of its aggregate opcode (§5.1.3 steps 10–11, §5.3.4).
- `FastAggregateVerify(PK_1..k, m, σ)`: `k ≥ 1`; every key is w3f-PoP-admitted
  or comes from an authenticated committee root; `apk = Σ PK_i ≠ O`; `σ` is
  canonical, in the subgroup and not O; `e(apk, H(m)) = e(g1, σ)`.

**Destination verification relation** (normative; Taira's forgery evidence uses
it too, §4.9). Inputs: `QC_FIXED`, `X`, `σ` and the keys `PK_0..PK_{n−1}` of
the current generation.

1. `n ∈ {4, 7, …, 31}`, `f = (n − 1)/3`, `q = n − f`.
2. `signers >> n = 0` and `popcount(signers) = q` exactly.
3. `QC_FIXED` has exactly the canonical 116-byte layout; extension fields and
   trailing bytes are rejected.
4. `R = SHA-256(RESULT_TAG ‖ X ‖ result_body)`.
5. `P` per §3.7 with the pinned `I`; `epoch`, `epoch_context`, `view` and
   `block_hash` come unverified from `QC_FIXED`. Kind `0x03` is mandatory: a
   PrepareQC is never accepted.
6. `m = SHA-256(P)`.
7. `apk = Σ_{bit i set} PK_i ≠ O`, a point of the G1 subgroup. The keys of a
   root Taira admitted are in G1, so their sum is. A destination presented
   with other key bytes (a pin or a forged rotation that commits to them)
   answers as §5.1.3 steps 10–11 state.
8. `Q = hash_to_curve_G2(m, DST_SIG)` per RFC 9380: `expand_message_xmd(m,
   DST_SIG, 256)` with `Z_pad = 0^64`, `l_i_b_str = 0x0100` and `DST_prime =
   DST_SIG ‖ 0x2b`; `u0 = (OS2IP(b[0..64]) mod p, OS2IP(b[64..128]) mod p)`,
   `u1 = (OS2IP(b[128..192]) mod p, OS2IP(b[192..256]) mod p)`; `Q = map(u0) +
   map(u1)` with `map` = EIP-2537 `MAP_FP2_TO_G2` (which includes cofactor
   clearing).
9. Accept iff `σ` is in G2's subgroup, `σ ≠ O`, and `e(apk, Q) · e(−g1, σ) =
   1`.

**Rogue keys and root admission.** The w3f proof of possession with
`KeyValidate` makes `FastAggregateVerify` rogue-key secure for every key Taira
admits; its hash domain differs from `DST_SIG`, so a proof of possession is
never a consensus signature and the reverse. A destination root enters in only
two ways: the Parliament-pinned generation, whose keys Taira validated (§4.14.3
P1), or `X.next_committee_root` of a rotation certified by the current
generation, whose `f + 1` honest signers computed it from a validated successor
context or from the unchanged keys at a heartbeat. Taira's strict key ordering
excludes duplicates; TON re-checks ordering when it installs keys. The residual
risk, a generation signing a forged rotation while a destination still trusts
it, is the slashable case of §4.9.

**Frozen external verification surface.** The Commit preimage layout, the `I`
derivation, LSB-first bitmap order, `n ≤ 31`, `q = n − f`, the
`DST_SIG`-plus-SHA-256 rule, `RESULT_TAG` and the `X` layout are pinned by
`specs/sumeragi.md` §3.3.1 and its golden test. Changing any of them requires a
new route revision with new contracts, activated by the Parliament (§4.14.3),
not only a node release.

### 3.9 Constant summary

| Name | Value |
|---|---|
| Event `SccpTransferToTaira(bytes32,address,uint64,bytes)` topic0 | `0x79ac1cc63262b80bfbf96e55b2d49d96bd82f018ce0192f7002168724c7d264b` |
| Event `SccpFinalized(bytes32,uint64,address,uint256)` topic0 | `0x8ab0eb669cb9abcdf0e37e9ce8443162d317d10c2b059296e40aebbd3fa23748` |
| Event `SccpVoided(bytes32,uint64)` topic0 | `0xfc0fe8523e61c1e6bcbb957a8b692dd0b08e1774c4c4bd897fbc68c047c82fcf` |
| Committee, control and certificate events | §5.2.2 |
| Leaf, node and history tags | `SCCP/LEAF/V1` (12 B), `SCCP/CONTROL/V1` (15 B), `SCCP/NODE/V1` (12 B), `SCCP/HISTORY/V1` (15 B) |
| `X` magic, `X_LEN`, committee tag | `SCCP/FINALITY/V1` (16 B), 221 bytes, `SCCP/COMMITTEE/V1` (17 B) |
| `QC_FIXED_LEN` / Commit `P` length / control-leaf preimage | 116 / 165 / 199 bytes |
| `RESULT_TAG` / `RESULT_BODY_TAG` | `iroha/sumeragi/result/v1` (24 B) / `iroha/sumeragi/result-body/v1` (29 B) |
| `MAX_RESULT_PREIMAGE_BYTES` / `MAX_RESULT_BODY_BYTES` | 65 536 / 65 315 |
| `DST_SIG` | `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` (43 B) |
| `MAX_VALIDITY_MS` (destination immutable; Taira parameter cap) | 2 592 000 000 (30 d) |
| `MAX_FAST_PAUSE_MS` (destination immutable clamp) | 2 592 000 000 (30 d) |
| `MAX_INIT_SLACK_MS` (slack of the destination constructor and init bound) | 3 600 000 (1 h) |
| `SCCP_MIN_EPOCH_MS` / `SCCP_MIN_HEARTBEAT_MS` | 3 600 000 / 3 600 000 |
| `SCCP_PIN_MARGIN_MS` (added to `committee_heartbeat_ms`, §4.14.3 P2) | 86 400 000 |
| `SCCP_LC_SLACK_MS` (liability-clock step slack, §4.8) | 3 600 000 |
| `MAX_CLOCK_DRIFT_BOUND_MS` (cap of `max_clock_drift_ms`) | 60 000 |
| `MAX_CERTIFICATES_PER_CALL` (EVM) / TON checkpoint slots | 16 / 3 |
| `MAX_VOID_FROZEN_RANGE_EVM` / `_TON` | 256 / 512 (one bucket) |
| `SCCP_ANCHOR_CHUNK` (heights per anchor chunk; path length 12) | 4 096 |
| Anchor leaf / anchor node | `H_iroha("sccp/anchor-leaf/v1" ‖ be64(h) ‖ core_hash ‖ R)` / `H_iroha("sccp/anchor-node/v1" ‖ left ‖ right)` |
| Forgery evidence id | `H_iroha("sccp/forgery-evidence/v1" ‖ be64(g) ‖ m ‖ be32(signers))` |
| `SCCP_EVM_DEPLOYER` (keyless deterministic-deployment proxy, same address on Ethereum and BSC) | `0x4e59b44847b379578588920ca78fbf26c0b4956c`; CREATE2 salt `0^32` |
| Max block leaves (transfers + controls) / block path / history path | 512 / 9 / 32 |
| Exempt-class block quotas | `Keepalive` 1, `ForgeryEvidence` 1, `KeeperAdvance` 1 per external network, `SelfClaim` the rest (§4.19) |

Implementations MUST pin all constants in golden tests (§11). Every selector
and event topic in this document was computed with an independent Keccak-256
over the canonical signature strings, with tuple types expanded as the Solidity
ABI does; the same implementation reproduces the unchanged
`SccpTransferToTaira` topic.

## 4. Taira side

### 4.1 On-chain parameters and activation

SCCP consensus parameters are one Taira-internal value `SccpParametersV1`. It
lives in dedicated world state (`sccp_parameters`), not in the generic
`Parameter` set. It is written only by the genesis-only instruction
`InitializeSccpV1` and by the Parliament-enacted action `SetParameters`
(§4.14.3), so no executor upgrade, no `SetParameter` path and no validator can
alter it.

```
InitializeSccpV1 {
    parameters: SccpParametersV1,
    reset_nonce: [u8; 32],      // fresh randomness per Taira genesis, nonzero (§4.18)
}
```

`InitializeSccpV1` is valid only inside the independently authenticated Global
genesis block, and only under NPoS consensus parameters whose committees satisfy
`n = 3f + 1`, `4 ≤ n ≤ 31`. The root role comes from the original signed genesis,
never from a supplied finality header. It
checks every rule of the table below, the epoch-duration guard (§4.2) and the
staking floor L1 against the genesis-pinned staking policy (§4.8), so a genesis
that fails any of them is invalid. It stores the parameters, creates the three
route escrow accounts (§4.15) and an empty registry. The same genesis execution's
post-execution finalizer installs committee generation 1 (§4.2 G1) from the
reconciled authenticated height inputs before sealing the result; no later block
or supplied certificate can initialize it. It creates **no route**: routes are registered only by the Parliament after
the launch gate opens (§10.2). SCCP exists on a network iff `sccp_parameters`
is present; no compiled chain id gates it.

| Field | Default (Taira genesis value) | Rule |
|---|---|---|
| `enabled` | `true` | When false, only value-moving effects stop: `RecordSccpMessage` fails, and inbound settlement and outbound refunds stay `Pending`. Generations, finality headers, anchors, keepalives, forgery evidence, light-client advances, inbound and void proof recording, Parliament enactment, fast pauses and control messages keep running, so re-enabling needs no recovery and destinations keep receiving rotations and controls. Per-route stops use `Paused` (§4.14.2) |
| `committee_validity_ms` | 1 209 600 000 (14 d) | `fast_pause_hold_ms + 2·committee_heartbeat_ms + 86 400 000 ≤ v ≤ MAX_VALIDITY_MS`, and `v + forgery_evidence_grace_ms ≤ unbonding_delay_ms` of the pinned staking policy (§4.8 L1) |
| `committee_heartbeat_ms` | 86 400 000 (1 d) | `≥ SCCP_MIN_HEARTBEAT_MS` (1 h) |
| `forgery_evidence_grace_ms` | 604 800 000 (7 d) | `86 400 000 ..= 2 592 000 000` |
| `destination_progress_cap_ms` | 2 592 000 000 (30 d) | `0 ..= 2 592 000 000` (§4.8 L5) |
| `outbound_ttl_ms` | 604 800 000 (7 d) | 1 d..=90 d; `deadline_ms = creation_time_ms(record block) + outbound_ttl_ms` |
| `min_outbound_amount` | 10^9 (1 XOR) | Floor per outbound message; bounds permanent dust records. `1 ≤ min_outbound_amount ≤ 10^15` (1 000 000 XOR) |
| `inbound_self_claim_fee` | 10^7 (0.01 XOR) | Deducted from the proceeds of a fee-exempt self-claim (§4.12.4). `inbound_self_claim_fee ≤ 10^10` (10 XOR) |
| `max_exempt_transactions_per_block` | 32 | `8..=1 024`, and at least the sum of the fixed per-class quotas of §4.19 plus 1 (those quotas sum to 5, so every allowed value leaves room for self-claims) |
| `fast_pause_panel_seats` | 9 | `∈ {5, 7, 9}`; quorum `parliament_quorum_seats_v1`: 4, 5 and 6. The draw also takes up to `k` reserve members (§4.14.7) |
| `fast_pause_panel_term_ms` | 604 800 000 (7 d) | `≥ SCCP_MIN_EPOCH_MS`. A value equal to the epoch duration draws at every epoch boundary. The 7 d default awaits owner confirmation (§13 item 1) |
| `fast_pause_seat_accept_window_ms` | 43 200 000 (12 h) | `600 000 ..= fast_pause_panel_term_ms / 2` |
| `fast_pause_endorse_window_ms` | 1 800 000 (30 min) | `300 000 ..= 21 600 000` |
| `fast_pause_renew_lead_ms` | 86 400 000 (1 d) | `2·fast_pause_endorse_window_ms ..= fast_pause_hold_ms / 2` |
| `fast_pause_hold_ms` | 864 000 000 (10 d) | `≥ parliament_sccp_attempt_latency_ms()` and `≤ MAX_FAST_PAUSE_MS − 86 400 000` |

`InitializeSccpV1` and `SetParameters` check every rule, including the joint
ones, against the complete new value. The defaults satisfy every rule: the
validity rule gives 10 d + 2·1 d + 1 d = 13 d ≤ 14 d, and the unbonding rule
gives 14 d + 7 d = 21 d, which the SCCP staking profile meets (§4.8 L1).
Windows are in milliseconds of Taira block time, not in blocks, because Iroha
produces no empty blocks and block counts have no wall-clock bound.

- **Who changes the parameters.** After genesis only the Parliament's SCCP
  action `SetParameters` writes `SccpParametersV1`, and that action is refused
  while the launch gate is closed (§10.2): until the Parliament's binding
  ballot exists, the genesis values hold and there is no interim governance.
  Core rejects every generic `SetParameter` that targets SCCP state, whatever
  the executor.
- **Parliament coupling.** `parliament_sccp_attempt_latency_ms()` is provided
  by the Parliament pipeline (§10.1; ballot spec §11): the latency of one
  full-track SCCP attempt, including a single sortition-retry generation,
  derived from the committed windows. The ballot has no ballot retries, so the
  hold covers one attempt; a longer outage, such as a rejected attempt followed
  by a retry attempt, is covered by renewing the fast pause before it lapses,
  which has no cooldown (§4.14.7). The Parliament's own parameter path MUST
  re-check the `fast_pause_hold_ms` rule whenever a window that the function
  derives from changes. `TODO:` pin `fast_pause_hold_ms` once the post-quantum
  ballot's windows are fixed; if one attempt takes more than about 27 d, SCCP
  cannot be configured and the ballot timings must change.
- **Related chain parameters.** The Sumeragi parameter `max_clock_drift_ms`
  (default 1 000) is capped at `MAX_CLOCK_DRIFT_BOUND_MS` (60 000) by genesis
  validation and by `validate_parameter_change`; the governance parameter
  `gov.due_work_max_lag_ms` (default 60 000) MUST be at least
  `2·max_clock_drift_ms + 4·block_cadence_ms` (§4.3). The staking floor
  (`nexus.staking.unbonding_delay_ms`, `nexus.staking.max_slash_bps`) is node
  configuration pinned by the genesis Nexus consensus-policy digest (§4.8 L1).
- **Deleted fields.** `roster_max_age_ms` and `roster_validity_ms` are replaced
  by `committee_heartbeat_ms` and `committee_validity_ms`;
  `attestation_retention_ms`, `attestation_stall_ms` and
  `max_attestation_entries_per_instruction` are deleted with the attestation
  transport.

Node-local behavior (keeper key directory, keepalive stagger, watch and
light-client endpoints) lives in `iroha_config` `[sccp.keeper]` and
`[sccp.light_client_keeper]` (§4.13.4), with defaults that need no operator
input. Native verifier work limits are the `sccp` section of the committed
`zk_validity_policy_v1` chain parameter (protocol defaults when absent),
bound into the consensus policy hash. Each category has a per-transaction
and a per-block limit: proofs, proof bytes (plus a per-frame bound), native
headers and header bytes, Ethereum light-client updates, BSC vote
attestations and Ed25519 signature checks (TON). Defaults admit one full
advance of every chain in a transaction and four in a block.

### 4.2 Committee generations and consensus anchors

A **committee generation** is the unit of destination trust. It names a
committee key set (§3.7) and an immutable trust deadline.

#### 4.2.1 State

```
sccp_committee_generations: u64 → SccpCommitteeGenerationV1 {
    generation: u64,
    committee_root: [u8; 32],
    keys: Vec<[u8; 48]>,                              // canonical order; bitmap index i = keys[i]
    members: Vec<Option<SccpGenerationMemberV1>>,     // same order: { lane_id, validator: AccountId, activation_height: u64 } (G6)
    cause: SccpGenerationCauseV1,                      // Genesis | KeyChange | Heartbeat | Resync
    start_height: u64,
    start_timestamp_ms: u64,                           // t of the handoff block (Genesis: t(genesis); Resync: t(h))
    start_lc: u64,                                     // lc of the same block (§4.8)
    validity_ms: u64,                                  // committee_validity_ms in effect at creation
    deadline_ms: u64,                                  // start_timestamp_ms + validity_ms (destination-facing)
    grace_ms: u64,                                     // forgery_evidence_grace_ms in effect at creation
    progress_cap_ms: u64,                              // destination_progress_cap_ms in effect at creation
    liable_until_lc: u64,                              // start_lc + validity_ms + grace_ms
    dest_cleared_lc: Option<u64>,                      // §4.8 L5
    end: Option<SccpGenerationEndV1 {
        end_height: u64, end_timestamp_ms: u64,
        next_committee_root: [u8; 32], successor_validity_ms: u64 }>,
}
sccp_committee_current: u64
sccp_liability_clock: u64                              // lc of the latest block (§4.8)
sccp_degraded_run: u32                                 // consecutive degraded blocks ending at the tip (§4.6)
sccp_anchor_open: Vec<SccpAnchorV1 { core_hash: [u8; 32], result: [u8; 32] }>   // anchors of the open chunk, by position
sccp_anchor_chunks: u64 (chunk index) → [u8; 32]       // Merkle roots of completed chunks
```

**Consensus anchors.** The anchor of height `a` is `(core_hash_a, R_a)`: the
Sumeragi core block hash (`header.hash` over the core `BlockHeader`; for
genesis the core hash of the genesis block) and the certified result. This is
what a `CommitQC` signs as `block_hash` and `R`. It is not Iroha's
`HashOf<BlockHeader>` in `state.block_hashes`. The native execution tip holds
exactly `(core_hash, result)` for the latest applied block, authenticated
against its commit certificate.

- **Recording.** Rule A1 appends the anchor of `h − 1` in the post-execution
  hook of block `h`, reading it from the parent's native execution tip, which
  is still the parent's at that point. Appending at the end of the block means
  that every lookup during block `h` sees exactly the parent state's anchors,
  so admission against the committed tip sees the same anchors as execution,
  even when the append completes a chunk.
- **Chunks.** Height `a` has chunk `c = ⌊(a − 1) / 4 096⌋` and position `p = (a
  − 1) mod 4 096`. When position 4 095 is appended, Core computes the chunk
  root, a complete binary Merkle tree over `anchor_leaf(a) =
  H_iroha("sccp/anchor-leaf/v1" ‖ be64(a) ‖ core_hash ‖ R)` with nodes
  `H_iroha("sccp/anchor-node/v1" ‖ left ‖ right)`, stores it in
  `sccp_anchor_chunks[c]` and clears `sccp_anchor_open`. The open chunk holds
  at most 4 096 × 64 B = 256 KiB.
- **Lookup.** `anchor(a)` during the execution of block `h_exec` (or at
  admission against the tip `h_exec − 1`) reads the parent state: for `a =
  h_exec − 1` it is the parent's native execution tip record; for `a` in the
  parent's open chunk it is `sccp_anchor_open[(a − 1) mod 4 096]`; otherwise it
  needs a witness `{core_hash, result, path}` that hashes to
  `sccp_anchor_chunks[c]` through its 12-hash bottom-up path with leaf index
  `(a − 1) mod 4 096`. If that root was pruned, the lookup fails with
  `EvidenceExpired` (§4.9).
- Anchors are recorded for every height while SCCP exists, whatever `X` was; A1
  needs no SCCP inputs and runs in degraded blocks too.
- **Why chunks.** A per-height map over the retained window would hold about
  116 MB at a 1 s cadence with the defaults (64 B × 86 400 × 21 d). Chunk roots
  cost 32 B per 4 096 heights, and completed chunks never change, so a witness
  never goes stale.

#### 4.2.2 Rules

The rules use the authenticated height inputs (`SccpHeightInputsV1` from the
Sumeragi core's lag-2 `consensus_schedule` in world state; its committee fields
are key lists), never Kura or a parent finality artifact. S0 runs at block
start; G1–G7 and A1 run in the post-execution hook (§4.5).

| # | Rule |
|---|---|
| S0 | **Begin-block step** (`sccp::hook::begin_block`). It runs before the governance block-start pass (§4.7) and before any transaction, sets `lc(h)` (§4.8) and never invalidates the block; a local storage or resource refusal defers execution as a local failure; missing authenticated SCCP inputs produce the inactive header. |
| A1 | **Anchor append.** Append the anchor of `h − 1` from the parent's native execution tip and close the chunk when it is full. It runs in every block while SCCP exists. |
| G1 | **Genesis.** In the same atomic execution as `InitializeSccpV1`, the post-execution finalizer creates generation 1 after reconciling the original authenticated Global genesis height inputs and before sealing its active `X`. It uses the keys of `C_genesis`, `cause = Genesis`, `start_height` = the genesis height, `start_timestamp_ms = start_lc = t(genesis)`, and `validity_ms`, `deadline_ms`, `grace_ms`, `progress_cap_ms` and `liable_until_lc` from the initial parameters. The instruction cannot substitute an offered committee for those original inputs. |
| G2 | **Generation change at `h`.** Let `KEY := h is the last height of its epoch ∧ committee_root(C_{h+1}) ≠ current.committee_root` and `BEAT := t(h) ≥ current.start_timestamp_ms + committee_heartbeat_ms`. If G4 passes and `KEY ∨ BEAT`: (1) set `current.end = {h, t(h), committee_root(C_{h+1}), committee_validity_ms}`; (2) insert `g + 1` with `keys(C_{h+1})`, members (G6), `cause = KeyChange` if `KEY` else `Heartbeat`, `start_height = h + 1`, `start_timestamp_ms = t(h)`, `start_lc = lc(h)`, `validity_ms = committee_validity_ms`, `deadline_ms = t(h) + validity_ms`, the current `grace_ms` and `progress_cap_ms`, `liable_until_lc = lc(h) + validity_ms + grace_ms` and `dest_cleared_lc = None`; (3) set `sccp_committee_current = g + 1`; (4) emit `SccpCommitteeGenerationCreated { generation, cause, committee_root, start_height, deadline_ms }`. At a non-boundary height `C_{h+1} = C_h`, so a heartbeat keeps the keys. |
| G3 | **No other trigger** besides G7: no forced rotation, no fault rotation and no inertness. |
| G4 | **Inputs (fail-closed in SCCP only).** Every block checks that the authenticated inputs of `h` are present. On failure, §4.6 applies: inactive `X`, `sccp_degraded_run` incremented, an event, and no G2 or G7. Otherwise `sccp_degraded_run` is reset to 0. It is never `Invalid`. |
| G5 | **`X` fields.** `X.generation` is the generation current before G2 runs at `h`, after any G7 at `h`; at a rotation that is the outgoing generation. `X.committee_root = committee_root(C_h)` from the authenticated inputs. `ROTATION` is set iff G2 fired at `h`; then `X.next_committee_root = committee_root(C_{h+1})` and `X.validity_ms = (g + 1).validity_ms`, otherwise both are zero. |
| G6 | **Member resolution.** For each key of a new generation, Core reads the original NPoS registrations at executing height `h`, restricts them to the canonical global election owner (`LaneId::SINGLE`), then resolves `(lane_id, validator, activation_height)` by immutable consensus-peer binding and tenure. Fresh mutable consensus-key registrations cannot replace that original binding. Duplicate qualifying registrations within that owner are unresolved; participant-dataspace registrations cannot shadow a global signer. Tenure is checked at `start_height(g)`: inclusive activation and exclusive deactivation at `h + 1` for G2, at `h` for G7, and at the genesis height for G1. Thus a newly elected member activating at `h + 1` backs the handoff generation, while a member deactivated at that height does not. The stored binding, not a later lookup, is what liability and penalties use (§4.9). A key cannot be rebound after activation. An unresolvable key is stored as `None` and emits `SccpGenerationMemberUnslashable { generation, index }`; under NPoS every elected member has a record, so `None` signals a misconfiguration. Genesis initialization refuses unless every original signer resolves to exactly one global staking binding before generation 1 is published. |
| G7 | **Resync.** It applies when G4 passes but `committee_root(current) ≠ committee_root(C_h)`, which happens only when a key change was missed at a degraded boundary. Before G5: (1) set `current.end = {h − 1, t(h − 1), committee_root(C_h), committee_validity_ms}`, taking `t(h − 1)` from the parent tip; (2) insert `g + 1` with `keys(C_h)`, members (G6), `cause = Resync`, `start_height = h`, `start_timestamp_ms = t(h)`, `start_lc = lc(h)` and the other fields as in G2; (3) set the current generation; (4) emit `SccpCommitteeResync { generation, committee_root, start_height }`. `X_h` is then certified by `g + 1`, and G2 runs normally afterwards. No certificate of `g` names `g + 1`, so destinations still at `g` freeze at `deadline_ms(g)` and new deployments pin `g + 1` or later. |

**Rate.** G2 fires at most once per block. `KEY` needs an epoch boundary, and
boundaries are at least `SCCP_MIN_EPOCH_MS` apart (below); `BEAT` needs
`committee_heartbeat_ms ≥ 1 h` since the last start of any cause. A heartbeat
can fire just before a key-change boundary, so `KEY` and `BEAT` can fire on
consecutive blocks. At the 1 h minima of both that gives at most 48 rotations a
day; with the defaults (1 h epochs, 1 d heartbeat) at most 24 key changes and
one heartbeat a day, because a key change resets the heartbeat timer. A resync
needs a bug (§4.6).

**Idle chains.** `BEAT` needs a block at or after the heartbeat time, and the
keepalive is due exactly then (§4.7), so an idle Taira produces one block per
`committee_heartbeat_ms` and no other SCCP block.

**Epoch-duration guard.** While SCCP exists, `epoch_length_blocks ×
block_cadence_ms ≥ SCCP_MIN_EPOCH_MS` MUST hold, and this product MUST fit the
`u64` millisecond clock. `InitializeSccpV1` and
`validate_parameter_change` for `EpochLengthBlocks` check it. Canonical time
advances by at least the cadence per block, so key changes happen at most 24
times a day, and each change and each heartbeat costs every destination one
rotation (§5.4).

#### 4.2.3 Trust deadlines on destinations

- A destination installs generation `g + 1` from a rotation certificate `X_B`
  signed by `g`, with `untilMs = min(X_B.timestamp_ms, now_ms) +
  X_B.validity_ms`, saturating at `2^64 − 1` (§5.1.2). Because
  `X_B.timestamp_ms = start_timestamp_ms(g + 1)` and
  `X_B.validity_ms = validity_ms(g + 1)`, this is at most `deadline_ms(g + 1)`.
  For the pinned generation, `untilMs = deadline_ms(g)` (§4.14.3 P1).
- No destination therefore accepts any certificate of `g` after
  `deadline_ms(g)` by its own clock, whatever is submitted in whatever order.
  No certificate other than a genuine handoff (a rotation certificate of the
  current generation) ever renews trust. The deadline bounds the first
  admission of a forgery while the destination's trust is genuinely anchored.
  It does not bound the later use of a forged handoff that installed `cur`, or
  the completion of effects already admitted (§5.1.2 properties 3 and 4).
- "By its own clock" matters: a destination's block time can lag real time
  after a destination halt, so Taira's liability waits for authenticated
  destination progress (§4.8 L5).
- A generation lives about `committee_heartbeat_ms` plus the keepalive latency,
  so a maintained destination has about `committee_validity_ms −
  committee_heartbeat_ms` (13 d with the defaults) to apply each rotation.
- Lowering `committee_validity_ms` shortens only the deadlines of later
  generations, so a successor can expire before its predecessor. A destination
  that lags by more than the new value freezes. Value drains through voids, so
  this is safe, but it should be announced; pins check every generation on the
  catch-up path (§4.14.3 P2).

### 4.3 Certified time

Canonical block time is `max(parent + cadence, lane time floor, max
tx.creation_time + 1)`, and only genesis is checked against a wall clock. One
Byzantine leader could therefore move Taira's clock arbitrarily far forward
with a post-dated transaction, or include an old due transaction and anchor due
work at a stale time. SCCP and the governance clock anchor deadlines at
certified block times (generation starts, fast-pause expiries, Parliament
anchors), so both directions need a bound. The rules are application-level
executor rules, specified normatively in `specs/sumeragi.md` §4.5; no validity
rule depends on a clock:

| # | Rule (summary) |
|---|---|
| CT1 | **Clock ahead.** For every non-genesis block of every Sumeragi instance of the network executed with `certified = false`, the executor answers `Failed(ClockAhead)`, never `Invalid`, while `t(block) > local_wall_ms + max_clock_drift_ms`. No `Valid` is recorded meanwhile, so the node withholds its Prepare vote. Commit votes are not guarded directly; the bound reaches every `CommitQC` through its PrepareQC. |
| CT2 | **Scope.** The apply and replay path of certified blocks never consults the clock. Genesis keeps its existing check. |
| CT3 | **Builder pacing.** The payload builder includes no transaction with `creation_time_ms > local_wall_ms`, and does not propose while the block's canonical time would exceed `local_wall_ms`; it waits instead. |
| CT4 | **Bound.** `max_clock_drift_ms ≤ MAX_CLOCK_DRIFT_BOUND_MS` at genesis and in `validate_parameter_change`. |
| CT5 | **Stale due work.** The global executor answers `Failed(StaleDueWork)` for a block executed with `certified = false` that satisfies the keepalive validity predicate of K2 (§4.7), while `local_wall_ms − t(block) > gov.due_work_max_lag_ms`. Panel draws, seat replacement, lapse cleanup, resyncs and key-change rotations alone never trigger it. |

`certified` is set by the Sumeragi core on `Action::Execute` iff the node holds
a PrepareQC for the block (a re-proposal or its own lock). A re-proposal keeps
the certified block's original time, and nodes that discarded the execution,
sat behind a hidden PrepareQC or restarted must execute it again: without the
exemption, a due-work block whose PrepareQC was hidden for longer than
`gov.due_work_max_lag_ms` could never gather Prepare votes again. The exemption
is sound because the PrepareQC's honest signers passed CT1 and CT5 when they
first voted. The verdict never depends on `certified`.

**Properties used by SCCP** (`specs/sumeragi.md` §4.5 proves them; every honest
wall clock is within `ε` of real time, with `2ε ≤ max_clock_drift_ms`):

- **Upper bound.** For a committee with at most `f` Byzantine members, a
  certified block time is at most `W_j + 2·max_clock_drift_ms` for any
  individual honest clock `W_j` at any later moment. A deadline anchored at
  certified time can therefore fire up to `2·max_clock_drift_ms` early relative
  to an individual honest clock. Wallet and relayer margins are
  `2·max_clock_drift_ms` plus inclusion latency.
- **Lower bound for anchors.** Every block that anchors governance work or a
  heartbeat has `t(h) ≥ W_i − gov.due_work_max_lag_ms` for some honest first
  Prepare voter, at the moment of that first Prepare.
- **Commit lag.** Between the first honest Prepare and the commit, view
  changes, a hidden PrepareQC or a halt can add unbounded delay, so an anchor
  can be older than wall time at commit. Recovery for SCCP anchors is
  deterministic: a heartbeat or key change with a stale start gives the
  successor a shorter trust window, and if `BEAT` then holds again the next
  block makes a fresh heartbeat; a fast pause with a stale enactment time holds
  for less time and can be renewed (§4.14.7); liability uses the liability
  clock and destination progress, not anchors (§4.8). Parliament anchors have
  the same lag; the ballot spec anchors a ballot's closure to the block after
  its opening, so a stale opening never shortens voting (§4.7.2 G2b;
  `specs/parliament_private_ballot_design.md` §3.4).
- **Liveness.** An honest leader's fresh block satisfies CT1 at every honest
  voter whose clock is within `max_clock_drift_ms` of the leader's; CT5 is
  satisfied by including a fresh keepalive (§4.7 K4); certified re-proposals
  are exempt; larger skew only delays votes.

### 4.4 Outbound: `RecordSccpMessage`

```
RecordSccpMessage {
    network: SccpNetworkV1,     // external target
    expected_revision: u32,     // the revision the wallet verified (§7.1)
    amount: Numeric,            // XOR (§0)
    recipient: Vec<u8>,         // bytes for the target's recipient codec (§3.1)
}
```

This is a plain signed instruction, not a contract call. The authority is the
sender. Execution runs these steps in order:

1. SCCP is enabled. The route for `network` has exactly one revision `r` in
   `Bidirectional` (§4.14.2), `r = expected_revision`, the effective Taira hold
   `hold(r, t)` is false (Parliament pause, fast pause, forgery hold and
   quarantine, §4.14.2), `r` was never quarantined (a quarantined revision
   never records again, including after reconciliation, §4.10), and the
   destination of `r` is not paused: `destination_paused(r)` is false and `r`
   has no unexpired fast-pause part (§4.14.7).
2. Finality liveness: the parent's `sccp_degraded_run = 0`, else
   `SccpFinalityDegraded` (§4.6). This prevents locking funds that no active
   `X` would cover.
3. `a = taira_units(amount)` is exact (§0), `a ≥ min_outbound_amount`, and `a <
   2^96` for TON.
4. The authority's `AccountAddress` bytes are at most 1024 bytes.
5. `recipient` is valid for the target codec (§3.1) and passes every recipient
   rule the destination enforces (§5.1.5): EVM, nonzero and not the revision's
   contract address; TON, workchain 0, nonzero account id and not the minter
   account.
6. `liability(r) + a ≤ max_wrapped_supply(r)`.
7. The block has fewer than 512 leaves (transfers and controls, §3.4).
8. Transfer `a` XOR from the authority to the route escrow (§4.15), and set
   `liability(r) += a`.
9. `nonce = next_outbound_nonce(r)`, then `next_outbound_nonce(r) += 1`. Nonces
   are dense per revision, starting at 0.
10. `deadline_ms = creation_time_ms(block) + outbound_ttl_ms`.
11. Build the payload (§3.2) with `source_domain 0`, `dest_domain` of
    `network`, and `sender_codec 3` = the authority's `AccountAddress` bytes.
    Compute `payload_hash`, `message_id` and the transfer `leaf` (with `r`'s
    destination word).
12. Allocate `commitment_index` = the number of leaves already recorded in this
    block. A failed transaction releases its indices by state rollback.
13. Insert `sccp_outbound_messages[message_id] = SccpOutboundMessageRecordV1 {
    network, revision, nonce, height, commitment_index, deadline_ms, sender:
    AccountId, amount: a, payload, leaf, status: Recorded }`,
    `sccp_block_leaves[(height, commitment_index)] = Transfer(message_id)` and
    `sccp_outbound_by_nonce[(network, revision, nonce)] = message_id`.
14. Emit `SccpMessageRecorded { message_id, network, revision, nonce, height,
    commitment_index, deadline_ms }`.

Ordinary fees apply. Taira cannot observe mints; the destination's consumed set
is authoritative (§5). A record leaves `Recorded` only through a proven void
(§4.16); a minted record stays `Recorded`.

**Where it executes.** `RecordSccpMessage` executes only as an instruction of a
signed transaction (an `Instructions` executable or an instruction item of a
`Batch`) or as an instruction of a multisig proposal whose quorum is reached by
signed `MultisigApprove` transactions; it then records from the multisig
account. Every opaque deferred executable is refused before its first effect
with `NotPermitted`: a trigger body (user- or contract-registered), the queued
effects of an IVM program or contract call, an `IvmProved` overlay, and a
multisig proposal or approval that one of these derives. Trigger registration
(as an invalid parameter) and the IVM `CREATE_TRIGGER` syscall (with
`PermissionDenied`) refuse an action that contains the record directly, in a
batch or overlay, in a nested trigger registration or in a multisig proposal;
execution re-checks every derived group, including live multisig approvals. The
other SCCP instructions keep their own rules.

Contract-originated SCCP sends (Kotodama) are not part of v1: Kotodama has no
SCCP builtin, and the ABI v1 syscall `0xA0` defines the single operation tag
`1=SubmitBallot`. The IVM hosts reject every other tag, and every instruction
other than `SubmitBallot`, with `PermissionDenied`, so an encoded
`RecordSccpMessage` fails under any tag (§11). The post-execution commitment
(§4.5) would support contract-originated sends safely later.

### 4.5 Block commitment, history and finality header (post-execution)

The block header carries no SCCP root: a block's commitment root exists in its
post-execution world state and in its finality header `X`, which the certified
result binds (§3.6).

All SCCP instructions are routed to the universal dataspace and execute
serially in one execution context, so nonce assignment and `commitment_index`
allocation are deterministic. The governance block-start pass (§4.7), including
Parliament and fast-pause enactments, runs before the block's transactions, so
the control leaves of a block precede its transfer leaves.

```
sccp_block_leaves: (u64 height, u32 commitment_index) → SccpLeafRefV1 =
    | Transfer(message_id)                              // §4.4
    | Control { network, revision, control_nonce }       // §4.14.6
```

In `ValidBlock::finalize_owned_execution_metadata`
(`crates/iroha_core/src/block/post_execution_tail.rs`), after all transactions
of block `h` have executed and before the output seal, the SCCP hook runs in
this order:

1. **Commitment and history.** Read the applied leaf outbox
   `sccp_block_leaves[(h, ·)]` and assert that its indices are exactly `0..m`;
   a gap is an execution invariant violation and fails the block. If `m > 0`,
   compute `root` per §3.4 over the stored leaves of the referenced transfer
   and control records, append `history_leaf(h, root, m)` to the accumulator
   (§3.5), and write `sccp_block_commitments[h] = { root, message_count: m,
   history_index }`.
2. **Generation step.** G4, then G7 if it applies, then G2 (§4.2.2).
3. **Anchor append** (A1).
4. **Pruning** (§4.11), then the destination-progress gate L5 (§4.8).
5. **Finality header.** Produce `X_h` per §3.6 and G5 (§4.6).

These writes are part of the post-state covered by the execution commitment,
and `X_h` is part of the certified result itself, so a `CommitQC` of `h`
authenticates them with no vote-wire change.

### 4.6 Finality header production and failure semantics

**Producer and plumbing.**

1. `sccp::hook::finalize_block` returns `SccpFinalityHeaderV1`. It is a pure
   read of the post-execution World (after steps 1–4 of §4.5), `t(h)`, the
   `NetworkId` and the authenticated `SccpHeightInputsV1`. It reads no clock,
   configuration, Kura or hash-map iteration order. It returns `SccpLocalFault`
   only for a node-local resource or storage failure, which the executor maps
   to `Failed` (retry), never to `Invalid`; inconsistent SCCP state yields an
   inactive `X` or a resync, never an error.
2. `ExecutionOutputSealMetadata` gains `sccp_finality_header:
   SccpFinalityHeaderV1`, and the executor passes it to
   `sumeragi::commitment::execution_result`, which returns
   `RetainedPayload<CertifiedResultV1>`. The added field is a fixed-size inline
   `[u8; 221]` with no owned allocation, and the `unsafe map_payload` SAFETY
   note says so.
3. `encode_result_preimage` writes `X`, then the canonical body, into one
   buffer charged for `221 + len(body)`, and refuses a body over 65 315 bytes
   with `ResultPreimageError::PreimageLength`.
   `ExecutionResultCommitment::result()` is deleted, because `R` cannot be
   computed without `X`.
4. `X` travels with the original execution owner and is never recomputed from
   another state view.
5. **Voting.** There is no separate pre-vote check. Each voter's own `X` and
   `R` go into its vote. A divergent `X` gives a divergent `R` and so
   `LocalFault(ExecutionMismatch)`; replay re-executes, and the apply path
   halts on divergence (`specs/sumeragi.md` §12.5).

The finality header, generation and anchor bookkeeping never make a block
`Invalid`; only the content rules K1, K2 and R-EX do (§4.7, §4.9).

**Missing inputs (degraded).** If SCCP exists on Taira and the authenticated
inputs of `h` are missing (G4): `X_h` is produced in inactive form;
`sccp_degraded_run` is incremented (it counts consecutive degraded blocks
ending at the tip, and the next non-degraded block resets it to 0);
`SccpFinalityDegraded { height, reason }` is emitted; and G2 and G7 do not run
at `h`. While `sccp_degraded_run > 0`, `RecordSccpMessage` is refused with
`SccpFinalityDegraded`. While `sccp_degraded_run ≥ 2`, no heartbeat is due and
a keepalive is not valid on SCCP grounds (§4.7), so a persistent defect
produces at most two fee-free blocks, while a transient defect still gets one
keepalive retry on an idle chain.

**Missed boundary (resync).** If the inputs are present but the current
generation's root differs from `committee_root(C_h)`, a key change was missed
at a degraded boundary. G7 creates a resync generation, and `X_h` is produced
normally. Destinations still at the old generation cannot follow a resync,
because no certificate of that generation names the successor; they freeze at
their deadline.

**Recovery.** The condition is evaluated per block and is not sticky. Messages
already recorded stay in the history and become provable under any later active
`X`. If the defect persists, destinations freeze at their deadline, and value
drains through `voidFrozen` and inbound void settlement. Under consensus both
paths are unreachable without a bug: the inputs of `h + 1` exist once boundary
`h` is applied. Unauthenticated component executions
(`SccpHeightSourceV1::Unauthenticated`) produce an inactive `X`; fixtures that
need an active `X` MUST supply authenticated inputs.

**Evidence never reads the degraded state.** An `ACTIVE` certificate at a
degraded height has an `R` that differs from the recorded anchor, so it is
forgery evidence under E4 (§4.9).

### 4.7 Keepalive and the governance clock

SCCP owns the governance clock's due predicate and the shared keepalive (§14
D17); the Parliament workstream owns the ballot items that the pass runs.

#### 4.7.1 Clock rules

- **Millisecond deadlines.** A due item is applied by the block-start pass of
  the first block `B` with `t(B) ≥ due_ms`. Deadlines are canonical block times
  in milliseconds, never block counts. Height-indexed values stay height-based:
  beacon pulse slots, recorded `*_at_height` fields and the validation-fee
  activation offset.
- **Intents in transactions, transitions at block start.** Transactions record
  facts and intents only (responses, endorsements, ballots, phase-advance
  intents, proposals). Lifecycle transitions, including early closes, panel
  conclusions, ballot openings and closures, certification and enactment, are
  applied by Core's block-start pass. A transaction that satisfies an
  early-close condition sets a pending flag with `due_ms = t(B)`.
- **Anchors.** Only transitions applied by the pass take a time anchor, and
  each takes `t(B)` of the block whose pass applies it: body draws, entry into
  Reflection, ballot casting openings (`s0`), certifications and fast-pause
  enactments. Every other deadline is a fixed offset from an anchor, computed
  when the anchor is applied, and never moves.
- Converting the remaining height-based Parliament windows (invitation and
  deliberation) to this clock is part of this work (§12, coordinated with the
  Parliament workstream).

#### 4.7.2 Block-start pass

S0 (§4.2) runs first and is not part of the pass. The pass runs, on the global
chain's ordinary carrier only, in this order under the shared budget
`gov.governance_block_start_work_units` (default 64, minimum 10):
The committed minimum funds all six possible cost-one SCCP conclusions and one
cost-four enactment in a pass, preventing recertification alone from starving
every enactment. Genesis and parameter updates enforce the same minimum.

- **G0** pause-panel draw (§4.14.7), at the native pre-boundary pulse
  carrying height, one block before the committee boundary. Outside the budget;
  not due work.
- **G1** Parliament sortition, at the exact pulse slot, in the request order of
  the Parliament pipeline.
- **G2** transitions with `due_ms ≤ t(B)`, in three segments:
  - **G2a**, ranks 0–3, in `(due_ms, kind_rank, item key)` order. Ranks 0–2
    are Parliament lifecycle transitions (phase-advance intents, invitation
    closes, public-finding conclusions), whose keys and costs the Parliament
    workstream fixes. Rank 3 is the SCCP rank: the pause-panel conclusion,
    and the end of a reconciliation window (§4.10). Their common item key is
    `(network tag, SCCP kind, subkey)`: pause conclusions have kind 0 and
    subkey primary 0 or backup 1; reconciliation ends have kind 1 and subkey
    revision. A pause conclusion is due at `t(B)`; a reconciliation keeps its
    original `closes_at_ms`. Thus overdue windows precede newly due conclusions,
    and equal-time items have one total order.
  - **G2b**, rank 4: binding-ballot closures whose closing time
    `t(h_open + 1) + casting_window_ms` has been reached, in `(closing time,
    governance_attempt_id, body_role)` order. `h_open = s0.height` is the
    opening block; closure is anchored to the first block executed after it,
    not to `s0`, so an opening that is already stale when it commits never
    shortens voting (`specs/parliament_private_ballot_design.md` §3.4, §3.7).
    The closing time is fixed when block `h_open + 1` executes and never
    moves.
  - **G2c**, rank 5: binding-ballot openings with `opening_at ≤ t(B)`,
    previously deferred ones included, in `(opening_at,
    governance_attempt_id, body_role)` order, each only while fewer than `K`
    casting windows are open. A window counts as open until its closure is
    processed. The first opening that finds no free slot ends G2c; it is not
    processed, keeps its place, and its deferral consumes no retry
    (`specs/parliament_private_ballot_design.md` §3.6, §8).
  - Ranks 6–8 are reserved and have no item kind. Adding one changes this
    section and the ballot spec together.

  Each segment reads the state that the earlier steps of the pass left, so a
  closure in G2b frees its slot for an opening in G2c of the same pass, and a
  Reflection entry in G2a whose `opening_at` has already been reached opens
  its ballot in G2c of the same pass. An item that a transition makes due in
  its own segment or an earlier one waits for the next pass.
- **G3** enactments: Parliament certificates first, in `(enact_not_before_ms,
  governance_attempt_id)` order, then fast pauses, in `(network tag, panel
  role)` order, each in its own rollback-isolated transaction.
- **G4** fast-pause lapse cleanup (§4.14.7), in network-tag order. Not due
  work, outside the budget and not positioned; at most one record per external
  network.

**Budget.** Each G1–G3 item has a fixed cost set by its owner (an enactment
costs 4, a pause-panel conclusion or reconciliation end 1). The first item of a
pass is always processed; after that, processing stops at the first item whose
cost exceeds the remaining budget, order is never skipped, and leftover items
stay due. A ballot closure that the budget defers changes no corpus, because
block validation checks each ballot against its own block's timestamp (ballot
spec §3.6); a deferred opening takes its `s0` at the pass that opens it.

A fast pause certified in G2 but deferred in G3 keeps its original round and
`certify_due` flag. The next pass certifies it again from that pass's current
state and time before attempting enactment. No certificate survives its pass,
no extra window is granted, and an expired round ends `NoResult`.

**Positions.** Every processed G1–G3 item gets a position: its 0-based index
among the items processed in that block's pass, in processing order. Ballot
openings record theirs in `s0`, and fast-pause enactments record theirs in
`enacted_at`; the lift rule compares them (§4.14.7). Because G2c precedes G3, a
ballot that opens in the block of a fast-pause enactment always has the
smaller position. S0, G0 and G4 are not positioned.
`governance_due_applied` is true iff at least one G1, G2 or G3 item was
processed.

#### 4.7.3 Due predicate

```
keepalive_due(parent, h, t) := sccp_due(parent, t) ∨ governance_due(parent, h, t)

sccp_due(parent, t) := SCCP exists
                     ∧ parent.sccp_degraded_run < 2
                     ∧ t ≥ current.start_timestamp_ms + committee_heartbeat_ms   // G2 BEAT would fire

governance_due(parent, h, t) :=
     ∃ unconsumed Parliament pulse request with pulse_height = h          // the exact slot only
  ∨ ∃ G2a or G2b item with due_ms ≤ t                                   // deadlines, pending early-close flags, reconciliation ends, ballot closures
  ∨ ∃ ballot opening with opening_at ≤ t while fewer than K casting windows are open   // G2c
  ∨ ∃ certified attempt with enact_not_before_ms ≤ t                     // G3
  ∨ ∃ fast-pause round with certify_due                                  // §4.14.7
  ∨ ∃ item carried over by the block-start budget
```

- **Admission** evaluates the predicate on the committed tip, with `h = tip +
  1` and `t = c + 1`, where `c` is the keepalive's `creation_time_ms`.
  Execution validity is K2.
- A pulse request is due only at its exact slot. A slot that passes without its
  pulse leaves the request waiting for that exact pulse
  (`specs/parliament_private_ballot_design.md` §9); it is not due work, so a
  missing beacon never manufactures blocks. `TODO:` (WP-S3, with the
  Parliament availability-isolation step, ballot spec §12.2): the due leg for a
  late pulse; under the progress invariant below it may make a request due only
  in a pass that consumes it. Fast-pause lapses and panel draws are not due,
  because they act by time alone or wait for a boundary pulse.
- **Progress invariant** (normative for every present and future term). An item
  may appear in `governance_due` only if the block-start pass that finds it due
  consumes or terminalizes it. An item that waits for external material is not
  due. So every keepalive block strictly shrinks the due set or creates a
  generation, and an idle chain makes at most one block per due item.

#### 4.7.4 `Keepalive` and block rules

`Keepalive {}` (wire id `iroha.chain.keepalive.v1`) is one shared chain-level
instruction with no fields, and its execution is a no-op. A transaction that
carries it carries nothing else.

| # | Rule |
|---|---|
| K1 | **At most one** `Keepalive` per block. A block with two is `Invalid` (`DuplicateKeepalive`). |
| K2 | **Must apply due work.** A block that contains a `Keepalive` is valid only if `governance_due_applied` holds, or SCCP exists, `BEAT` (§4.2.2) holds at that block and the parent's `sccp_degraded_run < 2`. Otherwise it is `Invalid` (`KeepaliveNotDue`). The verdict is deterministic, from content, parent state and block time. It is keyed on `BEAT`, not on G2 actually running, so a block that degrades at its own height cannot make an honest heartbeat keepalive invalid. CT5 triggers on exactly this predicate. |
| K3 | **Fees.** Exempt, from any Ed25519 authority, registered or not, with no fee field (§4.19). |
| K4 | **Honest proposer.** It includes a keepalive only if its candidate block `B` will satisfy K2, which it decides without executing, because the pass depends only on the parent state, `t(B)` and the pulses `B` carries; in particular a keepalive due only because of a pulse request at slot `h` is included only if `B` carries that pulse. It includes at most one: the due one with the latest `creation_time` not above its clock plus drift. If its candidate would satisfy K2 with `local_now − t(B) > gov.due_work_max_lag_ms / 2`, it replaces any keepalive with a fresh one of its own, which satisfies CT5. It drops keepalives that are no longer due. |
| K5 | **Admission** (Torii and P2P ingress): the exact shape; `c ≤ local_wall_ms + max_clock_drift_ms`; and `keepalive_due(tip, tip + 1, c + 1)`. The pulse leg counts a request at slot `tip + 1`; whether the block carries the pulse is the builder's decision (K4). The queue drops a pending keepalive when a newer tip makes it not due. Peers MAY deduplicate locally. |

**Guarantees.** Through CT1 a keepalive cannot advance Taira time: its block
waits until honest clocks reach `c − max_clock_drift_ms`. Through CT5 and K4,
due work and heartbeats are anchored within `gov.due_work_max_lag_ms` of honest
time. Through K2 and the progress invariant, no block exists without due work,
and an idle chain produces one block per `committee_heartbeat_ms` plus one per
governance item; a persistent degraded run produces at most two keepalive
blocks. Through `Execute.certified`, a re-proposed due-work block is never
blocked by CT5.

**Who submits.** Anyone. Validators run the keeper (§4.13.4), which signs with
its node-local Ed25519 `keeper_key`. Committee members stagger: each submits
when `local_wall_ms ≥ due_time + rank · keepalive_stagger_ms` and nothing is
pending, where `rank` is its canonical index and `due_time` is
`current.start_timestamp_ms + committee_heartbeat_ms` for a heartbeat, or the
item's due time for governance work (with a `rank · 1 000 ms` stagger). Juror
and panel wallets MAY submit.

**Deleted.** `heartbeat_start_work_pending`, `apply_block_start` and
`sccp_heartbeat_marker` (`hook.rs`), and the SCCP part of
`State::deterministic_start_work_pending` (with the function itself unless
another caller exists).

### 4.8 Validator liability: exit delay, liability clock and destination progress

**Liability clock.**

```
lc(genesis) = t(genesis)
lc(h)       = lc(h − 1) + min(t(h) − t(h − 1), committee_heartbeat_ms + SCCP_LC_SLACK_MS)
```

S0 stores `lc(h)` in `sccp_liability_clock` before any transaction of `h`. On a
running chain consecutive blocks are at most `committee_heartbeat_ms` plus
keepalive latency apart (§4.7), so `lc` follows `t`. After a halt, the first
block advances `lc` by at most one step, so neither the outage nor that block's
time jump consumes a liability window. Always `lc ≤ t`, so a window measured in
`lc` never ends earlier, in `t`, than the same window measured in `t`.

**Liable predicate.** One inclusive predicate serves evidence admission (E0),
the stake release gate (L3) and pruning:

```
liable(g) at block h :=
      g = sccp_committee_current
   ∨ lc(h) ≤ rec.liable_until_lc                                              // time leg
   ∨ (rec.dest_cleared_lc = None    ∧ lc(h) ≤ rec.liable_until_lc + rec.progress_cap_ms)
   ∨ (rec.dest_cleared_lc = Some(c) ∧ lc(h) ≤ c + rec.grace_ms)              // destination-progress leg
```

All transactions of one block see the same `lc(h)` and the same parent-state
`dest_cleared_lc`, so evidence and an unbond in one block get one answer,
whatever their order.

| # | Rule |
|---|---|
| L1 | **Delay and slash rate.** While SCCP exists, `nexus.staking.unbonding_delay_ms ≥ committee_validity_ms + forgery_evidence_grace_ms` for the current parameters and for every retained generation's `validity_ms + grace_ms`, and `nexus.staking.max_slash_bps ≥ 1`. Both values are node configuration pinned by the genesis Nexus consensus-policy digest (`NexusConsensusStakingV1`), not chain parameters. They are enforced (a) by `InitializeSccpV1` against the genesis-pinned policy, so a genesis that fails them is invalid; (b) by `irohad`, which refuses to start when SCCP exists in state and the configured policy fails them (the digest already refuses any other change); and (c) by the Parliament's `SetParameters`, which checks the parameter side against the pinned policy. Kagami's SCCP-enabled profiles set `unbonding_delay_ms = 1 814 400 000` (21 d) and `max_slash_bps = 10 000`; the global default unbonding delay of 0 stays for chains without SCCP. |
| L2 | **Liability anchor.** A forgery against generation `g` is a root-consensus offence at offence height `start_height(g)`: the penalty uses `ConsensusSlashLiability::Root(start_height(g))`. The liable exposure is bonded stake plus every pending unbond whose `slashable_through_height ≥ start_height(g)`, which is exactly the stake that backed `g`. |
| L3 | **Release gate.** `FinalizePublicLaneUnbond` of a pending unbond of validator `v` with `slashable_through_height = H` is refused with `SccpLiabilityActive` while some retained `g` with `v ∈ members(g)` and `start_height(g) ≤ H` is `liable(g)`, and with `SccpPenaltyPending` while a `Pending` SCCP forgery record names `v`, until its penalty is `Applied`. The same two conditions refuse the pruning of an exited zero-custody validator and a `RegisterPublicLaneValidator` that replaces `v`'s exited record (a re-registration would otherwise give `v` a registration that G6 never named). The gate adds to the existing `unbond_liability_release_height` check and scans at most the retained generations. |
| L4 | **Exit is never blocked.** `ExitPublicLaneValidator` is unchanged. A validator leaves the committee at the next election; only the release of its stake waits. |
| L5 | **Destination-progress gate.** In the post-execution hook, after pruning, Core visits at most 64 retained, ended generations with `dest_cleared_lc = None`, in ascending order through the committed pending-generation index (so previously cleared history is not traversed), and sets `dest_cleared_lc = lc(h)` iff, for every network that has a non-`Retired` route revision, the network's active inbound light client has a finalized checkpoint with `source_time_ms > deadline_ms(g)`; it then emits `SccpGenerationDestinationCleared { generation, lc }`. A network with such a revision but no active light client blocks the clearance. With no such network, as before launch, clearance is immediate. |

The index is derived from generation records, updated in the same transaction when a generation ends or clears, and rebuilt from both current and exact predecessor records on snapshot restore. It has no independent authority.

**Why L5.** A destination accepts `g` while its own block time is at most
`deadline_ms(g)`, and that time is chosen by the destination's proposers. After
a multi-day BSC or TON halt, the first blocks can carry old timestamps, and one
malicious proposer could include a forged rotation of an expired generation
after Taira had released the collateral. Destination timestamps strictly
increase, so once a finalized header with a time above the deadline exists, no
later block of that chain accepts `g`, and every earlier block is final and
public. L5 waits until Taira's light client sees such a header, then leaves
`grace_ms` of liability clock for evidence. Like the deadline itself (§4.2.3),
this bounds the first admission of a forgery of `g` on a destination whose
trust is genuinely anchored. It does not bound the later use of a forged
handoff that installed `cur`, or the completion of effects already admitted
(§5.1.2 properties 3 and 4); the forgery hold and quarantine answer those
(§4.10). The time leg keeps the bound while
light clients are current, and the cap bounds the stake lock when a destination
halts or nobody advances its light client.

**Guarantee: the exit delay keeps every signer bonded.** Let `v` be a member of
`g`, and consider the stake that backed `g`. It is either still bonded, or a
pending unbond with `slashable_through_height ≥ start_height(g)` (the
validator's next scheduled deactivation height minus one, so stake keeps
backing every generation that starts before that boundary, heartbeat
generations of the same epoch included). L3 keeps such an unbond in custody
while `g` is liable, and E0 admits evidence against `g` exactly while `g` is
liable. Once evidence is recorded, L3 holds the stake until the penalty
applies, and the record carries everything the penalty needs (§4.9). So
whenever forgery evidence is admissible against `v`, the stake that backed `g`
has not left custody. L1 makes the ordinary unbonding wait cover the time leg,
so L3 binds only in edge cases (stake unbonding mid-epoch that still backs a
later heartbeat generation, parameter changes, halts in which `lc` lags `t`,
slow destination progress); L3 is what makes the guarantee unconditional.
Liability follows the registration that G6 resolved at generation creation, not
the key: a key cannot be rebound after activation, and L3 refuses a replacing
re-registration while liability lasts.

**Residual assumptions** (§9.1): relay, watch and Taira inclusion latency
together stay below `grace_ms` (7 d by default); a destination chain's
finalized time does not stay at or below a generation's deadline for longer
than `grace_ms + progress_cap_ms` past it (37 d by default) and then resume
with backdated blocks, and its light client is not left unadvanced that long;
and the inbound light clients are safe, which inbound SCCP already assumes.

### 4.9 Forgery evidence and slashing: `SubmitSccpForgeryEvidenceV1`

```
SubmitSccpForgeryEvidenceV1 {
    qc: [u8; 116],                          // QC_FIXED (§3.7)
    header: [u8; 221],                      // X
    aggregate_signature: [u8; 96],          // compressed σ
    anchor: Option<SccpAnchorWitnessV1>,    // required only when X.height lies in a completed anchor chunk
}
SccpAnchorWitnessV1 { core_hash: [u8; 32], result: [u8; 32], path: [[u8; 32]; 12] }
```

A transaction that carries it carries nothing else. Anyone can build the
witness from Kura (§6). The steps are identical at admission and at execution:
at admission they run against the committed tip, with `h_exec = tip + 1`, `t =
tx.creation_time_ms` and `lc = lc(tip) + min(t − t(tip), committee_heartbeat_ms +
SCCP_LC_SLACK_MS)`; at execution they run against the parent state with
`lc(h_exec)`. Steps run in order, and the first failure is the result.

1. SCCP exists, `X` parses (X1–X7), `ACTIVE` is set, and `X.network_id` is the
   live `NetworkId`. Otherwise `NotEvidence`: an inactive or foreign `X` makes
   no SCCP claim.
2. Let `g = X.generation` and `rec = sccp_committee_generations[g]`. A missing
   record gives `EvidenceExpired` when `g ≤ current`, else
   `EvidenceUnknownGeneration`. If `X.committee_root ≠ rec.committee_root`, the
   result is `NotEvidence`: keys that Taira never certified are not validators.
3. **E0 (window).** `liable(g)` (§4.8), else `EvidenceExpired`.
4. **Signature.** The §3.8 destination relation holds with `rec.keys`, Taira's
   `I` and `q(n)`, verified with
   `iroha_crypto::bls::consensus::verify_fast_aggregate_committed`; else
   `BadSignature`.
5. **Mismatch.** The first matching rule applies; if none matches, the result
   is `NotEvidence`:

   | # | Predicate | Meaning |
   |---|---|---|
   | E1 | `X.height < rec.start_height`, or `rec.end = Some(e) ∧ X.height > e.end_height` | Signed outside the generation's tenure. No anchor is needed. |
   | E2 | `X.height ≥ h_exec` | A height Taira has not committed. Through parent hashes, any genuine certificate at such a height would depend on the payload of block `h_exec`, which contains this evidence. |
   | E3 | `X.height < h_exec ∧ qc.block_hash ≠ anchor(X.height).core_hash` | Not Taira's block at that height. |
   | E4 | `X.height < h_exec`, the block hash equals the anchor's, and `SHA-256(RESULT_TAG ‖ X ‖ qc.result_body) ≠ anchor(X.height).result` | Taira's block with a result Taira never certified: a false `X`, a false `D_body`, or both. |

   `anchor(a)` follows §4.2.1. Its errors are `WitnessRequired` (a witness is
   needed and absent), `BadWitness` (the path does not reach
   `sccp_anchor_chunks[c]`) and `EvidenceExpired` (the chunk root was pruned).
   A certificate that fails E1–E4 is genuine, its block hash and result being
   Taira's, including a genuine certificate with a different valid signer set;
   it is never evidence, whoever submits it. Admission is only a pre-check: a
   node whose tip lags can admit a genuine certificate under E2, and the
   builder's recheck against the parent state then finds it `NotEvidence` and
   drops it. E2 is sound at execution, where the hash-chain argument applies.

   **Why honest signers are not slashed.** If `g` has at most `f` Byzantine
   members, an honest Prepare voter signs only an `R` it computed from a valid
   proposal, and an honest Commit voter signs only a PrepareQC'd value of its
   current view. The one gap is up to `f` honest Commit votes on a block that
   never committed (§9.12); a certificate built on them needs `f + 1` further
   keys of `g`, which exceeds `g`'s BFT bound. Strict liability then slashes
   those honest stray signers too (§9.12).
6. **Offenders.** For each set bit `i`, the offender is `rec.members[i]`, the
   G6 binding `(lane, validator, activation_height)`. A `None` member is
   recorded as unslashable and emits `SccpForgeryOffenderUnslashable`.
7. **Deduplication.** The new offenders are those with no
   `sccp_forgery_offences[(g, lane, validator)]` entry. If there are none, the
   result is `EvidenceDuplicate`. Each validator is penalized at most once per
   generation; a second certificate with other signers penalizes only them
   (certificates are per node, `specs/bridge_finality.md`).
8. **Record.** Inside the transaction:
   - `evidence_id = H_iroha("sccp/forgery-evidence/v1" ‖ be64(g) ‖ m ‖
     be32(signers))`;
   - append a consensus `EvidenceRecord` whose `evidence` field is the closed
     enum `RecordedEvidenceV1 { Native(Evidence),
     SccpForgery(Box<SccpForgeryRecordV1>) }`, with `SccpForgeryRecordV1 { evidence:
     SubmitSccpForgeryEvidenceV1, rule: E1..E4, generation: g, start_height:
     rec.start_height, offenders: Vec<SccpForgeryOffenderV1 { signer: u32,
     lane_id, validator, activation_height }> }`;
     the Box's exact allocation and ledger slot are prepaid and retained with the
     record. Its canonical v1 binary field includes the owned-value length prefix
     inside the variant-field prefix; JSON keeps the direct record in `value`;
   - attribution: `scope: EvidenceScope::SccpGeneration { generation: g }` and
     `instance: I`; `height: rec.start_height`, the offence height (L2), not
     `X.height`; `epoch` and `context_id` as signed in `QC_FIXED` (unverified);
     `authority_generation: rec.committee_root`; `offenders`: the new offenders
     as signer index, the key's peer id and `lane_stake: None`;
     `safety_violation: true`;
   - `penalty_status: Pending`; insert `sccp_forgery_offences` for each new
     offender; set `sccp_forgery_max_generation = max(·, g)` (§4.10);
   - emit `SccpForgeryEvidenceRecorded { evidence_id, generation, height:
     X.height, rule, offenders }`.
9. **Penalty.** The consensus penalty pipeline
   (`crates/iroha_core/src/sumeragi/penalties.rs`) applies the record after the
   immutable `slashing_delay_blocks`, counted from `recorded_at_height`. For
   `SccpForgery` records it uses neither the peer-key validator map nor the
   locator tenure filter, which would test an attacker-chosen height. For each
   offender it loads the `(lane, validator)` record and requires an equal
   `activation_height` (the same registration; L3 refuses replacement while
   liable), slashes `max_slash_amount(exposure, max_slash_bps)` with
   `ConsensusSlashLiability::Root(record.start_height)` (L2; the tenure check
   holds because G6 resolved the member for that generation's start), credits
   `slash_sink_account_id`, and marks the record `Applied`. The native evidence
   horizon of at most three epochs does not apply. Nothing in the penalty reads
   the generation record, so pruning cannot strand it; pruning also skips
   generations that pending records name (§4.11). On an idle chain the penalty
   waits for the next block, and L3 holds the stake meanwhile.

**Fees, admission and validity.**

- Exempt class `ForgeryEvidence`, quota 1 per block (§4.19). Any authority,
  registered or not, may submit.
- **Ingress** (Torii and P2P) checks, in this order: exact lengths and parsing
  (step 1); the record lookup and E0 (steps 2–3); step 5 without the signature
  (the E1/E2 classification or the anchor lookup and witness path);
  deduplication against state (step 7); an LRU of the last 4 096 `(g, m,
  signers)` triples seen, accepted or refused, which drops repeats; a node-wide
  token bucket of 8 pairings per second with a burst of 32; and only then the
  pairing (step 4). Refused submissions never reach the queue. Per-peer rate
  limits stay.
- **R-EX.** A block that contains a `ForgeryEvidence` transaction that fails at
  execution is `Invalid`. The verdict is deterministic, from the signed content
  and the parent state. An honest builder runs steps 1–7 against the certified
  parent state and the candidate block's canonical time before including one,
  and includes at most one per block, so honest blocks never trip R-EX, and a
  Byzantine leader cannot use failing evidence to make a free block.
- **Bounded cost.** The payload is `116 + 221 + 96 + 64 + 384` bytes plus
  framing. Execution costs one hash-to-curve, at most 31 point additions, one
  pairing check, at most 13 `H_iroha` for the path and O(1) map reads.

### 4.10 Forgery hold, quarantine and reconciliation

```
sccp_forgery_max_generation: Option<u64>    // the highest generation named by any recorded SCCP forgery evidence
SccpRouteRevisionV1 gains:
    forgery_floor: u64                       // the lowest generation the deployment may still be at; initially pin.generation
    quarantine: Option<SccpQuarantineV1 { certificate_id: [u8; 32], since_height: u64 }>
```

- **Held.** `forgery_held(r) := sccp_forgery_max_generation ≥
  Some(r.forgery_floor)`. A deployment can be at generation `g` only if `g ≥
  forgery_floor(r)`, because destinations move only forward (§5.1.2), so
  evidence for a lower generation cannot affect `r`.
- **Effect.** While `forgery_held(r) ∨ r.quarantine.is_some()`, and until `r`
  is reconciled (R3), `r` is held on Taira whatever its activation (§4.14.2):
  `RecordSccpMessage` to `r` is refused with `SccpForgeryHold`, and inbound
  settlement and outbound refunds of `r` stay `Pending`. This covers
  `InboundOnly` revisions, which `SetTairaPaused` cannot pause. Proofs, inbound
  proving, light clients, destination voids and governance continue.
- **Release by attestation.** The Parliament action
  `AttestSccpDeploymentProgress { network, revision, at }` (subject
  `ForgeryHold(network)`) takes `at ∈ { Generation { generation, committee_root
  }, Frozen }` and raises `forgery_floor(r)` to `generation`, or to `u64::MAX`
  for `Frozen`. Preconditions: `generation ≤ current`, and `committee_root`
  equals the record of `generation` while that record is retained. The revision
  is released as soon as `forgery_floor(r) > sccp_forgery_max_generation`. The
  attestation states destination facts that reviewers check with `iroha sccp
  monitor`. The deployment's `committeeState()` names that genuine generation
  and root, or the deployment is frozen (expired or latched) at a genuine
  generation. If the deployment has rotated (`cur.generation >
  initial_committee.generation`), the handoff that installed `cur`, at height
  `cur.start − 1`, is Taira's: its checkpoint id equals `keccak256` of Taira's
  canonical header of that height. The id is read from
  `checkpointHeader(cur.start − 1)` on EVM. On TON it is read from
  `get_sccp_checkpoints()` while the entry is retained, and otherwise from the
  `sccp_checkpointed` or `sccp_certificate` external message of the installing
  rotation (TON evicts the entry after three higher checkpoints, §5.1.3). A
  deployment still at its pin has no installing handoff: its `cur` root,
  generation and start equal the registered `initial_committee` (§4.14.3 P1).
  And no forged certificate took effect on the deployment since its last clean
  attestation, pending TON mints included. A deployment that fails one of
  these is not attested: the revision is quarantined (below).
  Destinations never move backwards, so the generation fact stays true.
- **Ordering.** Attestation and evidence commute. Evidence recorded later for a
  generation `≥ forgery_floor(r)` holds `r` again, which is correct, because
  the deployment may be at that generation.
- **Griefing.** Evidence for a generation that every deployment has passed
  holds nothing, so an already-slashed quorum that keeps signing with keys
  reused across heartbeat generations cannot re-arm a hold. Evidence changes no
  governance head, so it never supersedes a pending attestation.
- **Quarantine.** `QuarantineSccpRevision { network, revision }` (subject
  `ForgeryHold(network)`) sets `r.quarantine = { certificate_id, since_height
  }` from the enacting certificate, for a deployment that the Parliament finds
  captured: its `committeeState()` root is not a genuine Taira root, its
  installing handoff is not Taira's header of that height, or `monitor` shows
  that a forged certificate took effect (a forged mint, pending TON mints
  included, or a forged control). The quarantine record is permanent: no
  attestation, lapse, Parliament resume or reconciliation removes it, and a
  quarantined revision never records outbound again (§4.4 step 1). What ends
  is the quarantine's hold on settlement: it ends at the end of the
  reconciliation window (R3), after which later claims settle at the
  reconciled rate (R4) and `r` can eventually retire (R5). A proposal that
  quarantines a `Bidirectional` or `Paused` revision normally also carries
  `DeactivateOutbound`, because a `Paused` revision keeps its claims held
  (§4.12.3).
- **Events** (§4.17). Recording evidence emits `SccpRevisionForgeryHeld` for
  each revision it newly holds; an attestation that releases a revision emits
  `SccpRevisionForgeryReleased`; quarantine emits `SccpRevisionQuarantined`;
  reconciliation emits `SccpReconciliationOpened`, `SccpForgedMintProven` per
  proven id, `SccpReconciliationSettled` at the window end and
  `SccpReconciledClaimSettled` per claim settled afterwards.
- **Why.** A captured deployment accepts only its attacker generation, so
  neither Taira controls nor fast pauses reach it (§5.1.2). Holding the
  revision on Taira is the only automatic protection of its escrow, and
  quarantine keeps that protection after the rest of the network resumes.
  Triggering a hold costs at least `f + 1` signers their stake (§9.11), and no
  single party can trigger it.

**Reconciliation of a quarantined revision (launch blocker).** `RegisterRoute`
is refused until this mechanism is implemented (§10.2); releasing a captured
revision without it would let attacker-minted burns drain its remaining
backing. Its state is:

```
sccp_reconciliations: (SccpNetworkV1, u32) → SccpReconciliationStateV1 {
    opened_at_ms: u64, closes_at_ms: u64,   // t(B); + positive window_ms, checked
    forged_supply: u128,                    // F: checked sum of distinct proven amounts
    rho: Option<SccpReconciliationRatioV1 { backing: u128, denominator: u128 }>,
    settled_face: u128,                     // S: face amount settled under rho
}
sccp_reconciliation_proven: (SccpNetworkV1, u32, [u8; 32]) → u128
sccp_pending_refund_amount: (SccpNetworkV1, u32) → u128
```

The accounting record is fixed-size. Permanent proof ids and their authenticated
amounts occupy a separate admitted map, so adding one proof or settling one claim
never clones the revision's proof history. An ordered deadline index is derived
from the exact current and undo records. Restore checks each cut's proof sum,
pending-refund sum, quarantine binding and open-window supply bound before
publishing any field. The read API returns the scalar accounting record.

`SccpForgedMintProofV1` carries both the source light-client proof and the canonical
outbound payload preimage (1–4096 bytes). Verification binds the registered
emitter, network, revision, nonce and message id; an EVM event's amount must also
match. TON's finalized event has no amount, so its authenticated id binds the
payload from which the amount is obtained. A caller-supplied amount is never
independent evidence.

A quarantined revision is in exactly one phase, derived from this record:
**Held** (no record), **Reconciling** (a record with `rho = None`) or
**Reconciled** (`rho = Some`). `refunds_pending(r)` is the sum of the amounts
of `r`'s `Voided` outbound records whose refund is still pending, kept as a
counter. `⊖` is saturating subtraction.

| # | Requirement |
|---|---|
| R1 | **Held and Reconciling.** Quarantine holds every pending and future inbound claim and outbound refund of `r` (`Pending{Held}`). Inbound proving and void proofs continue, so claims and refunds are recorded and wait. |
| R2 | **Window.** `OpenSccpReconciliation { network, revision, window_ms }` (Parliament, subject `ForgeryHold(network)`) requires `r` quarantined and no reconciliation record for `r`, so each revision has one window. It writes the record with `opened_at_ms = t(B)` of the enacting block and `closes_at_ms = t(B) + window_ms` (checked; an overflow fails the action at enactment). While the executing block's `t < closes_at_ms`, anyone may submit `ProveSccpForgedMintV1 { network, revision, proof }`: an inbound light-client proof of a destination `SccpFinalized` event of `r` for a message id that Taira never recorded for `r` (the id binds the payload hash, §3.3, so a forged payload under a genuine nonce is such an id). Each proven id adds its amount once to `F` and emits `SccpForgedMintProven`; a proof that would make `liability(r) + F` exceed `u128::MAX` is refused, so `B + F` (R3) always fits. `liability(r)` does not change while `r` is Held or Reconciling, because nothing records to or bounces into it and its claims and refunds are held. From `closes_at_ms` the instruction is refused, so a forged mint proven late prices nothing in. |
| R3 | **Window end: the quarantine's hold ends.** The first block-start pass with `t(B) ≥ closes_at_ms` runs the reconciliation end (G2a rank 3, due work, cost 1, §4.7.2). It does constant work: with `B = liability(r) ⊖ refunds_pending(r)`, it fixes `rho = (B, B + F)`, or `(0, 1)` when `B + F = 0`, and emits `SccpReconciliationSettled { network, revision, backing: B, forged_supply: F }`. From then on `r` is Reconciled: the quarantine leg and the forgery-hold leg of `hold(r, t)` no longer apply to it (§4.14.2), while its other legs (`Paused`, an unexpired fast pause, `¬enabled`) still do. `rho` never changes again. |
| R4 | **Later claims.** Every inbound claim of a Reconciled `r`, whether it was held across the window end or proven later, settles through the ordinary settlement and retry path (§4.12.3, `SettleSccpV1::Inbound`), in canonical execution order, with step 1 replaced by this payout. For claim amount `a`, `payout = min(liability(r) ⊖ refunds_pending(r), ⌊(S + a)·B / (B + F)⌋ − ⌊S·B / (B + F)⌋)`, computed exactly with 256-bit intermediates. Steps 2–7 run on `payout` instead of `a` (fee, bounce and credit included); step 1 never holds the record, because the cap replaces it. When the record leaves `Pending` (released, bounced or stranded), and only then, `S += a` (stored saturating at `u128::MAX`), step 7 or the bounce sets `liability(r) −= payout`, the final status records `payout`, the rest `a − payout` is void, and `SccpReconciledClaimSettled { network, revision, message_id, amount: a, payout }` is emitted. A refusal that keeps the record `Pending` (steps 4 and 6, or `BlockLeavesFull`) changes neither `S` nor `liability(r)`, and its retry recomputes the payout from the `S` of that moment. A zero payout releases the record with nothing credited, charged or bounced. While no void of `r` is proven after the window end, the cap never binds before `S` reaches `B + F`, and claims of exactly `B + F` face value receive exactly `B` in total, whatever their order; order changes only per-claim rounding and who bears a shortfall. Claims beyond `B + F` (forged mints not proven in the window, or minted after it, since a captured deployment keeps accepting its attacker generation) receive only the liability that remains, so later claimants carry the risk of unpriced forgery. Outbound refunds of `r` settle in full under §4.16; claims never take liability that backs a pending refund, and a refund that `liability(r)` no longer covers stays `Pending{LiabilityShortfall}`. |
| R5 | **Retirement.** A quarantined revision retires only when Reconciled, under the ordinary `RetireRevision` precondition (`liability(r) = 0` and no inbound record or refund of `r` `Pending`, §4.14.3). Until then it stays Reconciled indefinitely and keeps settling later claims under R4. Its quarantine record and its outbound refusal never end. |
| R6 | Deterministic, with bounded work per block: the window end is constant work, and each claim or refund is one ordinary settlement. Every step is evented. |

R1–R6 are the implemented pro-rata rule. Liability backing genuine messages
that a captured deployment never minted and that no void proof can reach may
prevent `liability(r) = 0`, so R5 deliberately permits indefinite retention.
The Norito records, events, scalar hold/reconciliation route and
`iroha sccp reconcile` status/proof commands are implemented. The original
Parliament G1/G2 prefix, shared positions and carried work budget remain the
external inputs required to close windows; combined qualification remains open.

### 4.11 Storage and pruning

| Map | Retention |
|---|---|
| `sccp_outbound_messages`, `sccp_block_leaves`, `sccp_outbound_by_nonce` | permanent (one record per value transfer, ≤ 4 KiB payload) |
| `sccp_control_messages` | permanent (one record per recorded control, §4.14.6) |
| `sccp_block_commitments`, history leaves and peaks | permanent (~48 B per SCCP block) |
| `sccp_inbound_messages` | permanent (one record per inbound message) |
| `sccp_committee_generations` | pruned (below) |
| `sccp_anchor_open` / `sccp_anchor_chunks` | the open chunk (≤ 256 KiB) / pruned chunk roots (below) |
| `sccp_forgery_offences`, SCCP forgery evidence records | permanent |
| fast-pause panel, rounds, pauses and suspensions | current values only (§4.14.7) |
| `sccp_reconciliations` | permanent (one per reconciled revision) |
| light-client sets and checkpoints | §4.13.1 |
| `sccp_governance_revisions` | permanent (one counter per SCCP governance subject, §4.14.3) |
| Parliament proposals, attempts and certificates | owned by the Parliament pipeline |

**Pruning** runs in the post-execution hook, after G2 and G7 (§4.5), and reads
pending penalties from the original permanent forgery-evidence owner. An absent
or unavailable owner is never an empty pending set.

- **Generation records.** Scan in ascending order and delete at most 8 records
  `g` with `g < sccp_committee_current`, `¬liable(g)` and no `Pending` SCCP
  forgery record naming `g`. Gaps are allowed; nothing assumes that a successor
  outlives its predecessor.
- **Anchor chunk roots.** Delete at most 8 chunk roots whose last height is
  below the smallest `start_height` of the retained generations. The open chunk
  is never deleted.

**Size.** A generation record is about 4 KB at `n = 31`. With the defaults,
generations are created at most 25 times a day and the retained window is about
21 days, so about 525 records are retained. The longest window the parameter
caps allow is 90 days (30 d validity, 30 d grace and the 30 d progress cap,
which applies only while a destination light client stalls), at most 4 320
records or about 17 MB at 48 rotations a day. Anchor chunk roots add about 21
entries a day at a 1 s cadence.

**Node-local.** The rotation archive and anchor witnesses are node-local (§6).
Old messages remain finalizable through the history root of any later
certificate (§3.5).

### 4.12 Inbound: prove, then settle

Inbound messages are proven once and settled separately, so a burn that is
proven never becomes unprovable. Settlement may be retried later without a
proof.

#### 4.12.1 `SubmitSccpInboundMessageV1` (prove)

```
SubmitSccpInboundMessageV1 {
    network: SccpNetworkV1,          // external source
    revision: u32,
    payload: Vec<u8>,                // §3.2
    proof: SccpSourceProofV1,        // per-chain enum, §4.13
}
```

Validation:

1. SCCP exists. Revision `r` of the route exists and is not `Staged`:
   `Bidirectional`, `Paused`, `InboundOnly` and `Retired` accept proofs.
   `enabled`, holds and quarantine do not affect proving.
2. The payload decodes (§3.2) with `source_domain` = the network's domain,
   `dest_domain = 0`, `route_revision = r`, `route_id` of the route and
   `deadline_ms = 0`.
3. `message_id`, recomputed per §3.3, is not in `sccp_inbound_messages`.
4. `proof` verifies against the network's light client (§4.13) and yields a
   normalized source event `{ kind: TransferToTaira, emitter, message_id,
   sender, nonce, payload_hash }`. Its `emitter` equals revision `r`'s
   deployment address, and its fields equal those recomputed from `payload`.
5. Verifier work is estimated from the frame alone (`SccpVerifierWorkV1`)
   and reserved under the committed `sccp` transaction and block limits before any
   cryptography runs; advances and equivocation evidence are reserved the same
   way. A reservation reaches the block only when its transaction commits. A
   transaction carries at most one inbound or void proof, preceded by any
   number of `AdvanceSccpLightClientV1` instructions within the work limits.

Effect: insert `sccp_inbound_messages[message_id] = SccpInboundRecordV1 {
network, revision, payload, source_locator, proven_at_height, fee_due, status:
Pending }` and emit `SccpInboundProven`. Then attempt settlement (§4.12.3). If
settlement cannot complete, the record stays `Pending` with the reason of
§4.12.3 and the instruction still succeeds: every deterministic settlement
refusal is checked before any settlement effect runs, so only an execution
invariant violation fails the proof.

`SettleSccpV1 { target: Inbound(message_id) | Refund { network, revision, nonce
} }` retries a `Pending` inbound settlement or outbound refund (§4.16) without
a proof. Anyone may submit it, and it pays the ordinary fee, except a
recipient's settle that is an eligible self-claim (§4.12.4). It fails if it
changes nothing, so retry spam pays: a failed exempt settle is charged too
(§4.19).

#### 4.12.2 Source event binding per chain

| Source | Evidence of the burn | Normalized fields come from |
|---|---|---|
| ETH, BSC | Receipt log with `status = 1`, `address` = deployment, `topics = [0x79ac1cc6…, message_id, word(sender)]`, `data = abi.encode(uint64 nonce, bytes payload)` | log topics and data |
| TON | A transaction of the deployment (minter) account with successful compute and action phases and an external-out message whose body is `sccp_transfer_to_taira` (§5.3.3). The body's `amount`, `nonce` and `sender` (codec 7) MUST equal the payload's; the minter builds the payload from them, so a disagreement is refused | out-message body |

#### 4.12.3 Settlement

Settlement proceeds only when SCCP is enabled, revision `r` is `Bidirectional`
or `InboundOnly`, and `hold(r, t)` is false (§4.14.2). Otherwise the record
stays `Pending` with reason `Disabled`, `RevisionNotSettleable` or `Held`.
`Paused` holds it; `Retired` cannot hold one (§4.14.2). A quarantined revision
settles only once reconciled, with step 1 replaced by the payout of §4.10 R4
and steps 2–7 run on that payout. The steps run in this order,
and each refusal is checked without mutating state before the effects that
follow it:

1. If `liability(r) < amount`, the record stays `Pending{LiabilityShortfall}`
   and core emits `SccpInboundLiabilityShortfall`. A shortfall means the
   external side released more than Taira locked, which indicates a destination
   forgery, a source-chain compromise or a verifier compromise. The responses
   are forgery evidence (§4.9) and quarantine (§4.10) where a forged
   certificate exists, `ReportSccpLightClientEquivocationV1` where equivocation
   evidence exists, and otherwise a Parliament-enacted `FreezeLightClient`.
2. Decode `recipient` (codec 3) as `AccountAddress` and derive the `AccountId`.
   If decoding fails, bounce (§4.12.5) with `UndecodableRecipient`.
3. Bounce if the recipient can never be credited. These are permanent identity
   refusals:
   - it is an SCCP escrow account (`EscrowRecipient`);
   - its controller uses a signing algorithm or curve that account admission
     does not allow (`InadmissibleController`); or
   - it does not exist and `Register<Account>(Account::new(recipient))` refuses
     its identity (`UnregistrableRecipient`), for example a retired rekey
     identity or a reserved protocol escrow identity. Core decides this with
     the identity precheck that `Register<Account>` itself runs first, so the
     two cannot drift.
4. Let `fee = min(fee_due, amount)`. If `fee > 0` and the fee sink of the Nexus
   fee policy does not resolve to an existing account, the record stays
   `Pending{FeeSinkUnavailable}`.
5. If the account does not exist and `amount − fee > 0`, core registers
   `Account::new(recipient)`, with the same effect and validation-fee DS
   classification as `Register<Account>`, and emits `SccpRecipientRegistered`.
6. Core prechecks each credit of step 7 against every guard of the escrow
   release movement (transfer control, holding limit, custody, the XOR
   definition's transfer, usage and privacy policy). A refused recipient credit
   keeps the record `Pending{CreditRefused}`; a refused fee credit keeps it
   `Pending{FeeSinkUnavailable}`. These refusals can lift (the recipient raises
   its holding limit, say), so they hold rather than bounce. A registration
   made in step 5 stays.
7. Transfer `amount − fee` XOR from the route escrow to the recipient and `fee`
   to the fee sink (one combined credit when the sink is the recipient; a zero
   credit is skipped). Set `liability(r) −= amount` and `status = Released {
   height }`. Emit `SccpInboundReleased`.

A retry by `SettleSccpV1::Inbound` reruns these steps; it changes something
when the reason changes, a registration happens, or the message settles.

#### 4.12.4 Authority, fees and self-claim

Anyone may submit a proof or a settle and pay the ordinary fee. The recipient
is fixed by the payload, so relaying cannot redirect funds, and a relayed proof
or a third-party settle owes no self-claim fee.

**Self-claim.** A recipient that holds no XOR can claim alone, with no faucet
or sponsor. A transaction is an eligible self-claim when all of the following
hold against the committed parent state (the state the block executes on,
§4.19):

- its instructions are exactly `[Register<Account>(Account::new(authority))?,
  SubmitSccpInboundMessageV1]` or `[SettleSccpV1::Inbound]`; the optional
  self-registration is bare (no metadata, label, UAID or opaque identifiers),
  so an exempt claim carries no other registration effect;
- its authority equals the payload's recipient `AccountId` (the submitted
  payload of a proof, the stored record's payload of a settle);
- the payload amount exceeds `inbound_self_claim_fee`;
- for a settle, the record is `Pending` and settlement can progress: SCCP is
  enabled, the revision settles, it is not held, and `liability(r) ≥ amount`
  (for a reconciled revision, the payout of §4.10 R4 is positive instead).
  Holds that only the release decides (`CreditRefused`, `FeeSinkUnavailable`,
  `BlockLeavesFull`) are not predicted; a settle that meets one and changes
  nothing fails and is charged.

`[Register<Account>(authority)?, AdvanceSccpLightClientV1+,
SubmitSccpInboundMessageV1]` is a self-claim shape too. Admission verifies its
proof against the same-network light client with the bundled advances applied
in order to an original-pool overlay. Each signed expected state hash and the
original allocation and verifier-work limits are enforced before eligibility.

A transaction that is not eligible is never refused for its shape: it pays the
ordinary fee. This covers relayers, third-party settles, amounts at or below
the fee, settles that cannot progress, and claims for a multisig recipient. An
eligible self-claim is fee-exempt on success and charged on failure (§4.19).
Admission pre-verifies it against committed state and rejects it only when it
is invalid: for a proof, the revision accepts proofs, the message is not yet
proven and the proof verifies within the `[zk.sccp]` limits; for a settle, the
record is `Pending`. The queue holds at most one pending exempt self-claim per
authority and per `message_id`, and eligible self-claims count toward the
`SelfClaim` class of the per-block quota.

Only an exempt self-claim makes the self-claim fee due. Execution sets `fee_due
= min(inbound_self_claim_fee, amount − 1)` on the record it proves, or raises
the `fee_due` of the `Pending` record it settles to that value. The fee is
charged once, at release (§4.12.3). A recipient that pays the ordinary fee is
not charged the self-claim fee as well. The existing
`allows_unregistered_authority` rule already admits `Register<Account>(self)`
from an absent authority. A multisig recipient cannot self-claim, but any
funded account can claim for it.

#### 4.12.5 Bounce

If settlement step 2 or 3 bounces, the value returns to the source-chain
sender. A bounce requires `liability(r) ≥ amount` (settlement step 1) and a
free commitment leaf in the executing block; when the block already holds its
512 SCCP leaves the record stays `Pending{BlockLeavesFull}` and a later
`SettleSccpV1::Inbound` bounces it. The target revision `r'` is the route's
`Bidirectional` revision if one exists, was never quarantined, `hold(r', t)` is
false and `liability(r') + amount ≤ max_wrapped_supply(r')`; otherwise `r' =
r`. A quarantined revision is never a bounce target, in any phase (§4.10): if
`r'` would be quarantined, the bounce strands instead (`liability(r) −=
amount`, `stranded(route) += amount`, the record becomes `Stranded`, and
`SccpInboundStranded` is emitted), and only a Parliament `ReleaseStranded`
moves that value. Otherwise set `liability(r) −= amount` and `liability(r') +=
amount`. Record an outbound
message per §4.4 steps 9–14 on `r'` with `amount` = the inbound amount,
`sender` = the escrow account's `AccountAddress` and `recipient` = the inbound
`sender`. The activation, pause, liveness, minimum-amount and cap checks of
§4.4 steps 1–6 are skipped (the cap of `r'` was checked above). The inbound
record becomes `Bounced { bounce_message_id }`. Emit `SccpInboundBounced`. A
bounce that is later voided moves its amount to `stranded(route)` (§4.16).

### 4.13 Inbound light clients

Inbound finality is permissionless light-client state. World state stores
**authenticated validator sets** of each source chain with validity ranges,
plus finalized checkpoints. Each inbound or void proof carries its own finality
evidence, verified against a stored set. The Parliament only initializes,
re-initializes, freezes, installs trusted checkpoints and activates compiled
profile versions (§4.14.3); every advance is permissionless. The finalized
source time of each light client also feeds the destination-progress gate (§4.8
L5).

#### 4.13.1 State

```
sccp_light_clients: SccpNetworkV1 → SccpLightClientV1 {
    params: SccpLightClientParamsV1,   // profile, thresholds, ws_bound_ms, set retention,
                                       // checkpoint stride, per-ISI bounds (no fork bound, §4.13.2)
    head: { latest_set_id: u64, latest_finalized: SccpLcPointV1, last_progress_taira_ms: u64 },
    frozen: Option<SccpLcFreezeReasonV1>,
    state_hash: [u8; 32],              // keccak of canonical state bytes; CAS handle for wallets
}
sccp_light_client_sets:        (SccpNetworkV1, u64 set_id) → SccpLcConsensusSetV1 {
    …, superseded_at_source_ms: Option<u64> }
sccp_light_client_checkpoints: (SccpNetworkV1, u64 source_height) → SccpLcCheckpointV1 {
    block_hash, state_root: Option, receipts_or_tx_root, source_time_ms,
    recorded_at_taira_ms, origin: Advance | Proof | Backfill | Parliament }
sccp_light_client_profiles:    (SccpNetworkV1, u32 version) → SccpLcProfileActivationV1 {
    profile_hash: [u8; 32], activation_height: u64, proposal_id: [u8; 32] }
                                       // append-only; absent = version 1 (§4.13.2)
```

- **Sets** are retained until 180 days after they are superseded.
- **Checkpoints** are written idempotently by every accepted advance, proof and
  backfill.
- **Checkpoint retention.** A checkpoint at source height `s` is kept
  permanently if it is the lowest checkpoint recorded in its stride bucket `⌊s
  / stride⌋` (stride: ETH 8 192, BSC 8 192 blocks; TON keeps none, because
  `OldMcBlocksInfo` covers old blocks), or if it was installed by the
  Parliament. Other checkpoints are pruned 30 days after recording. Permanent
  checkpoints cost a few MB per year per chain at most.

#### 4.13.2 Instructions and weak subjectivity

| Instruction | Permission | Effect |
|---|---|---|
| `InitializeLightClient` | Parliament-enacted action only (§4.14.3) | Installs params and a bootstrap set (weak-subjectivity checkpoint). Used when a route is first registered, after a freeze, after staleness and after every Taira reset |
| `AdvanceSccpLightClientV1 { network, expected_state_hash: Option<[u8;32]>, advance: SccpLcAdvanceV1 }` | anyone; ordinary fee. Eligible for exemption on success (charged on failure) as a `KeeperAdvance` from any authority, unless it is a `Backfill`; admission rejects an eligible advance that does not verify or does not move the head (§4.13.4, §4.19) | Stores the next set(s) and checkpoints. Idempotent: re-proving stored data is `Ok` with no change, so concurrent wallets do not fail |
| `AdvanceSccpLightClientV1` with `advance = Backfill { segment }` | anyone; ordinary fee, never exempt | Proof-carrying backwards ancestry: ≤ 256 parent-linked headers ending at a stored checkpoint. Records the segment's first header as a checkpoint (`origin: Backfill`) |
| `ReportSccpLightClientEquivocationV1 { network, a, b }` | anyone; ordinary fee | Two quorum-valid conflicting records (same period/epoch/key block/height, different content) set `frozen`. An advance that conflicts with stored data is rejected with a pointer to this instruction |
| `InstallTrustedCheckpoint` | Parliament-enacted action only (§4.14.3) | Installs a checkpoint at any source height, exempt from the weak-subjectivity bound. It recovers burns that are too old for §4.13.5 (`origin: Parliament`). Refused for TON, whose light client reads no checkpoints (`OldMcBlocksInfo` reaches old blocks) |
| `FreezeLightClient` | Parliament-enacted action only (§4.14.3) | Sets `frozen` without equivocation evidence, for example on a suspected source-chain or verifier compromise |
| `ActivateLightClientProfile` | Parliament-enacted action only (§4.14.3) | Makes a compiled chain-profile version the network's active version from the block after enactment (below). The light client's params, sets and checkpoints are untouched |

**Weak subjectivity.** An advance or a proof is accepted only if its signing
set is fresh: the set is current, or was superseded (by source time) less than
`params.ws_bound_ms` before the Taira block time. Old events are proven by
ancestry from a fresh finality point or from a stored checkpoint, never by
stale keys. A light client whose newest set has aged beyond `ws_bound_ms`
cannot advance and needs re-initialization (§4.13.4).

**Fork bound and profile versions.** The source-chain fork schedule and its
`supported_until` (the last epoch or time the verifier supports) belong to a
compiled chain profile (`iroha_sccp::light_client::profile`), never to
`params`. Each network's profiles are versioned and append-only: version `v` is
the `v`-th compiled profile, a release only ever appends a version, and the
profile hash of a version is the keccak of its canonical policy bytes (every
profile field and the verifier's fixed bounds). Version 1 is active from
genesis. A later version (a new fork, or a later `supported_until`) becomes
active only through a Parliament-enacted `ActivateLightClientProfile { network,
version, profile_hash }` (§4.14.3), which records
`sccp_light_client_profiles[(network, version)]` with `activation_height =
enacting block + 1`; the enacting block itself still runs the previous version.
At Taira height `h` a network's active version is its highest recorded version
with `activation_height ≤ h`, else version 1. Every advance, proof,
equivocation report, bootstrap and usability check executing at `h` runs under
the versions active at `h`. Any advance or proof signed beyond the active
version's `supported_until` fails closed; once an extending version is
activated, the same light client continues with no freeze or re-initialization.

Every block's confidential feature digest binds the active version and profile
hash of every network at its height (version 1's compiled hash when none is
recorded), not the compiled profiles themselves. A release that only appends a
version not yet activated therefore computes the same digest, accepts the same
blocks and replays historical blocks unchanged; mixed releases agree until an
activation. The profile hash covers profile fields and fixed bounds, not
verifier code, so a release that changes what an already-numbered version
accepts must append a new version instead of editing the verifier under the old
number. Height-independent identities (the p2p handshake, genesis signing and
snapshot identities) bind the version-1 hashes rather than the active ones, so
peers at different heights still connect across an activation. Activation is a
release obligation: every validator must run a release that compiles the
version, with exactly the recorded hash, before the enactment height. A release
that does not compile it (or compiles other content under that number) fails
closed and never diverges: enacting the activation, and any later verification
under it, defers the block with `VerifierArtifactsUnavailable`, so that node
applies no further block until it is upgraded, and a snapshot whose state
activates such a version is refused. A version that no release compiles would
therefore stall the chain at its enactment; proposers build the action with
`iroha sccp lc-profile --network N --version V` from a release that compiles
`V`, and reviewers rebuild it with their own release before the vote. Torii
reports each network's active version, hash, activation height and
`supported_until` in `GET /v1/sccp/capabilities` (§6).

#### 4.13.3 Per chain

| Chain | Stored set | Advance | Inbound / void proof | `ws_bound_ms` |
|---|---|---|---|---|
| Ethereum | Sync committee per period (current and next), learned **only** from finalized updates. The fork schedule is compiled into the chain profile with `supported_until` (last supported fork epoch), not stored (§4.13.2) | ≤ 16 `LightClientUpdate`s. Each MUST carry a finality branch and satisfy `3·popcount(sync_committee_bits) ≥ 2·512` (≥ 342 participants) and `signature_slot > attested.slot ≥ finalized.slot`. It is verified against the stored committee of `period(signature_slot)`, with the domain fork version of `compute_epoch_at_slot(max(signature_slot, 1) − 1)`, by fast-aggregate BLS. A `next_sync_committee` branch is accepted only when the attested and finalized headers share a period | A finality update under exactly the same rules gives finalized execution block `E`. Ancestry from the event block `B`: `SameBlock` \| `HeaderChain` (≤ 256 parent-linked execution header RLPs from `B` to `E` or to a stored checkpoint) \| `HistoryContract` (EIP-2935 account and storage proof under `E`'s state root, `1 ≤ E−B ≤ 8191`; needs state at `E`). Then the event header RLP (keccak = hash, fields read by index) and the receipt MPT | 14 d |
| BSC | Parlia validator set (address, BLS key) with the epoch-checkpoint height where it took effect, and turn length | **Skipping:** only the set-transition epoch-checkpoint headers. Each carries the new set in `extraData` and is finalized by a fast-finality vote attestation (in a descendant within ≤ 256 headers) signed by at least `⌈2n/3⌉` of the previous stored set. If the set is unchanged, a step from a later epoch checkpoint (which re-announces it) to a header with such a vote advances `latest_finalized` to that checkpoint. Cost is O(set changes) plus one refresh per keeper interval, not O(epochs) | Event header `B` plus a vote attestation finalizing `B` (in a descendant within ≤ 256 headers) signed by the stored set covering `B`, which must be fresh; then the receipt MPT | 5 d (BSC unbonding is 7 d) |
| TON | Validator epoch per key block (config 34, 28, 15) | ≤ 16 key-block hops, each signed by the current subset, with `prev_key_block_seqno` = stored latest key block | Any masterchain block signed by the epoch named by its `prev_key_block_seqno`, or an `OldMcBlocksInfo` back-link from a fresh block. Then the shard registration, a ≤ 32 shard-block `prev_ref` walk (both predecessors after a merge; `before_split` allowed), and the account transaction and out-message | `utime_until + stake_held_for − margin` |

**BSC details.** A stored set is keyed by the height of the epoch checkpoint
that announced it and records the set that finalized that checkpoint. It covers
vote targets from `checkpoint + (n_prev / 2 + 1) · turn_prev` (Parlia switches
after `minerHistoryCheckLen` blocks of the previous set, and checks the votes
on a target against the set of the target's parent). A finality proof is one
attestation `(S → S + 1)`: it names the covering set, and the set's successor
when it is not the newest set, so the target must precede the successor's first
covered height. A superseded set stays fresh until `ws_bound_ms` after its
successor's checkpoint time. The newest set stays fresh until `ws_bound_ms`
after the newest finalized epoch checkpoint that (re-)announces it, which is
`head.latest_finalized`: an advance step moves the head only to such a
checkpoint (a transition's announcing checkpoint, or a later one announcing the
newest set), and finalized blocks without one record checkpoints but never
extend the newest set's freshness. A set the chain no longer announces thus
ages out like a superseded set instead of extending its own freshness with its
own votes, and the keeper's unchanged-set advances start at the latest
finalized epoch checkpoint. A roster's BLS keys are validated once, when its
set is learned (bootstrap or transition); stored sets and the announcements
compared with them are only checked structurally, so no verification spends
unmetered key validation. A transition step starts at the announcing checkpoint
and must be attested by the newest set before the new set takes over. Any other
epoch checkpoint above the newest set's checkpoint, in an advance, proof or
evidence record, must announce the newest set, so every transition is learned
in order. The bootstrap carries the trusted checkpoint and the checkpoint one
epoch earlier, whose set size and turn length fix the new set's first covered
height. Proofs name sets from `GET /v1/sccp/light-clients/{network}/sets`.

**TON details.** A stored epoch is keyed by its key block's seqno and holds
config 34 (with the config-28 shuffle flag) and config 15 `stake_held_for`,
read from a proof of the key block's state rooted at its `state_update` new
hash. A masterchain block is verified under the stored epoch its
`prev_key_block_seqno` names: the masterchain subset for the block's catchain
session (the first `main` validators, shuffled when config 28 says so) must
carry the block's `validator_list_hash_short`, and signatures of more than two
thirds of the subset weight must verify (ordinary or Simplex transcripts). An
epoch is fresh until `(utime_until + stake_held_for) · 1000 − 1 h` (TON light
clients store `ws_bound_ms = 0`). A hop's key block must name the newest epoch;
re-proving a stored hop is a no-op. A proof walks from the shard block the
anchoring masterchain block registers for the minter's shard down to the event
block (`TON_MAX_SHARD_LINKS = 32`), and the event block's proof must reach the
minter's transaction, whose cell may be pruned there and is then supplied in
full. Header, shard-link and transaction proofs may prune the block's
`state_update` (as liteservers serve them); only bootstraps, key-block hops and
back-links open it. A liteserver shard-link proof is rooted at the block before
the link, so builders take a shard block's header proof from the next link and
the event block's from its transaction proof. The normalized sender is codec 7
(`int32 0 ‖ account`), and a transfer's payload must carry the event's amount,
nonce and sender. A Simplex transcript signs the `session_id` it carries; the
candidate data binds the block id and the header fixes the subset, so another
session's votes could only finalize the same block. Current v1 verifies the
signed session id, block id, selected validator subset and strict weighted
quorum. Deriving that session id independently from the epoch is optional
future strengthening (WP13), not an additional v1 acceptance rule: it would
require the config-29 options hash and the vertical seqno of the epoch's
state, which the stored epoch does not retain. TON records no
checkpoints and refuses `InstallTrustedCheckpoint`. Recorded mainnet answers
(`fixtures/sccp/rpc/ton/transport`) replay through the verifier: the config-28
shuffle reproduces the subset hash of real headers, Simplex signatures of a
block and of a key-block hop verify, and the pruned proofs open. The keeper
looks for a new key block once the head is an hour old, backing off while there
is none (§4.13.4).

Approximate advance traffic to stay fresh: Ethereum, one update per sync period
(~27 h, ~25 KB). BSC, one skipping advance per validator-set change (about
daily, ~3 KB) and one re-announcement step per keeper interval (a few headers).
TON, one key-block hop per validator round (~18 h, ~20–60 KB).

**Builders.** The `iroha_sccp_rpc` builders (§8) that the keeper, the CLI and
wallets share step every advance to the light client's
`max_updates_per_advance` and the submitter's byte budget (the keeper's
`max_advance_bytes`, §4.13.4): they keep the longest prefix of updates, steps
or hops that fits, so a light client that is far behind catches up over several
advances. For example, Ethereum updates carrying a committee are about 25 KB,
so about nine fit in 256 KiB. Evidence anchors are chosen as §4.13.5 states. A
burn that is older than a fresh anchor allows is proven from the nearest
retained checkpoint at or above it, with `Backfill` advances submitted first
when that checkpoint is beyond one proof's ancestry bound.

The per-chain checks are stateless functions in `iroha_sccp`: Ethereum in
`ethereum_native.rs` and `ethereum_source.rs`, TON in `ton_native.rs`, and the
Parlia header, roster and vote-attestation primitives in `light_client/bsc.rs`.

Deployment code identity is not proven per transfer: Taira recomputes the EVM
CREATE2 and TON deployment addresses at registration (§4.14.3), and reviewers
verify the deployment before the vote (§4.14.4).

#### 4.13.4 Liveness, keeper and recovery

- **Wallets.** Anyone may advance, and wallets advance as part of a claim.
- **In-node keeper.** An irohad component (`crates/irohad/src/sccp_keeper.rs`;
  config `[sccp.keeper]` and `[sccp.light_client_keeper]`) runs on validator
  nodes and is enabled by default. It signs with a node-local Ed25519
  `keeper_key`, generated on first start in an owner-only directory, with no
  registration and no funding: every transaction it submits is fee-exempt on
  success (§4.19). It has three duties, each polled independently:
  - **Light-client advances.** It reads each light client from local state.
    When `now − head.last_progress_taira_ms ≥ advance_after_ms` (default
    `ws_bound_ms / 4`), or when the light client's finalized source time lags
    the deadline of a retained, ended generation that L5 has not cleared
    (§4.8), it builds proof-carrying advances from its public RPC endpoints
    with the same `iroha_sccp_rpc` builders that wallets use (§8) and submits
    them as exempt `KeeperAdvance` transactions. Admission keeps at most one
    pending exempt advance per `(authority, network)`, and the proposer
    includes at most one exempt advance per network per block. It steps each
    advance to `max_advance_bytes` and drops, with a warning, an advance that
    still does not fit. Its submissions are verified like anyone's, so a lying
    endpoint can only cause rejected advances.
  - **Keepalives.** It submits a due `Keepalive` with the stagger of §4.7.4
    (`keepalive = true`).
  - **Watch.** It polls each registered destination's `SccpCertificate` events
    and `sccp_certificate` external messages, and its `SccpCommitteeRotated`,
    `SccpCheckpointed` and `SccpLatched` events. It compares each certificate's
    `X`, block hash and `R` with Taira's anchors and generation records. On a
    mismatch it builds `SubmitSccpForgeryEvidenceV1` straight from the
    published certificate (recompressing EVM's 192-byte `σ`), adds an anchor
    witness from local Kura, and submits it. It alerts at `untilMs − 3 d`.
    Watching is node-local duty, not a consensus rule.

  The keeper is its own supervised task and polls each network independently,
  so a slow, firewalled or hostile endpoint of one chain delays neither block
  production nor the other chains. A poll copies the light client and whether
  it is aged (its newest signing set beyond the weak-subjectivity bound at the
  latest committed block time, the time admission checks advances against) out
  of one short-lived committed state view, and drops the view before any
  network I/O. A frozen or aged light client cannot be advanced, so the keeper
  spends no RPC on it and reports it once (`sccp_keeper_needs_recovery`) until
  a Parliament `InitializeLightClient` re-seeds it (below). A stale light
  client's advance is built on a blocking worker under a wall-clock budget
  (`poll_budget_ms`) shared by all of its requests; a build still running after
  1.25 × that budget counts as a failed poll, and the network starts no other
  poll until it returns. A build that fails on the data it was served
  (malformed, inconsistent or incomplete) moves that network's clients to their
  next endpoints. A network is polled again `poll_interval_ms` later plus up to
  25 % jitter seeded per node and network; each consecutive failed poll (an
  endpoint or build failure, an over-budget build, an oversized advance or a
  refused submission) doubles that wait, up to 64 × `poll_interval_ms`, and a
  poll that needs no RPC or submits an advance resets it.

  The existing telemetry registry exports `sccp_keeper_unconfigured` for a
  local keeper-key failure, `sccp_keeper_needs_recovery{network}` for a frozen
  or aged inbound light client, and `sccp_keeper_poll_success{network,duty}`
  for the latest remote attempt (`1` success, `0` refusal). The duty labels
  are `advance` and `watch`; no poll sample exists before the first attempt.
  Labels never include endpoints or revision identifiers. These node-local
  observations do not authorize recovery or protocol effects.

  A hostile or broken endpoint can cost a node bounded time and memory only
  (§8, `iroha_sccp_rpc` RPC hygiene): every attempt has one wall-clock deadline
  (`request_timeout_ms`) for connecting, sending and reading the whole answer;
  every answer is bounded by its route's byte cap and parsed under JSON value,
  depth and allocation limits derived from that cap (a TON answer by its
  query's cap), and an answer over a limit fails over to the next endpoint. The
  keeper's lists start at an index seeded per node, so validators sharing the
  compiled lists spread over them, and an endpoint that answers a request with
  HTTP 404, an error object or malformed data has its answer returned while the
  next request starts at the next endpoint. Default lists of free public RPC
  endpoints per chain are compiled into the `iroha_config` defaults; an
  operator MAY override them and MAY add per-endpoint secret headers read from
  owner-only files.

  Configuration (user → actual → defaults, file-only, no environment variables;
  every default works without editing):

  ```toml
  [sccp.keeper]
  enabled = true                  # default true for validators
  key_dir = ""                    # default "<kura.store_dir>/sccp/keeper-key" (0700 directory, 0600 file, symlinks refused)
  keepalive = true                # submit due keepalives (§4.7.4)
  keepalive_stagger_ms = 15000    # per canonical committee index
  watch = true                    # watch registered destinations; endpoints as for the light-client keeper

  [sccp.light_client_keeper]
  enabled = true                  # default true
  advance_after_ms = 0            # 0 = ws_bound_ms / 4 of each light client
  poll_interval_ms = 60000        # per-network cadence (+ up to 25 % jitter; doubles per failed poll up to 64 ×)
  request_timeout_ms = 10000      # total per RPC attempt (connect, send, whole answer), then failover
  poll_budget_ms = 120000         # wall-clock budget of one network's poll
  max_advance_bytes = 262144      # advances are stepped to fit; ≤ the on-chain per-ISI bounds

  [sccp.light_client_keeper.endpoints]
  ethereum_execution = []         # empty = the compiled default list
  ethereum_beacon = []            # empty = the compiled default list
  bsc = []                        # empty = the compiled default list
  ton_liteservers = []            # empty = the compiled default liteserver list

  # optional, repeatable: a secret header for one endpoint, read from an owner-only file
  # [[sccp.light_client_keeper.secret_headers]]
  # endpoint = "https://…"
  # header = "x-api-key"
  # value_file = "/path/to/owner-only/file"
  ```

- **Recovery.** If a light client exceeds its bound or is frozen, a
  Parliament-enacted `InitializeLightClient` re-seeds it. The proposal carries
  the complete bootstrap; reviewers and anyone else rebuild and check it
  independently with `iroha sccp light-client bootstrap build|verify` against
  their own endpoints before the Parliament decides. `InstallTrustedCheckpoint`
  recovers burns older than §4.13.5 allows. A Parliament round takes the
  full-track latency (§4.14.5), which fits inside the ETH and BSC `ws_bound_ms`
  but not always inside a TON bootstrap's freshness, so a TON initialization is
  proposed on its own (§4.14.5). Recovery is never immediate; the keeper exists
  so that recovery is rarely needed.
- **Wallet guard.** Torii reports freshness, the weak-subjectivity deadline,
  `supported_until` and claim windows (§6). Wallets refuse to burn on a lane
  whose light client is frozen, has less than 25 % of its weak-subjectivity
  bound left, or is within 7 days of `supported_until` (§7.2).

#### 4.13.5 Claim windows

A proof is recorded permanently once accepted (§4.12.1), so these windows bind
only the **prove** step. Wallets journal raw evidence and submit the proof as
soon as the source block is final.

The table states what the shipped builders (`iroha_sccp_rpc`, used by `iroha
sccp claim` and wallets, §8) build. Each builder tries its anchors in order and
takes the first that works. It anchors at a signing set only while that set
stays fresh for one more hour (`FRESHNESS_MARGIN_MS`), because the submission
lands after the build. `C` is the lowest retained checkpoint at or above the
event block `B` (`GET
/v1/sccp/light-clients/{network}/checkpoints?covering=B`). Checkpoints are
recorded by advances (Ethereum: the finalized block of every period's update;
BSC: each step's first and last header and its newest epoch checkpoint
announcing the newest set, including the epoch checkpoints of set transitions),
by accepted proofs and by backfills. A `Backfill` segment holds 256 headers and
moves a checkpoint 255 blocks down. The builders carry at most 64 of them, and
the claim submits each in its own transaction before the proof.

| Chain | Window of the shipped builders | Beyond it |
|---|---|---|
| Ethereum | 1. Latest finality update `E`, when Taira stores the committee of its signature period: `SameBlock`; `HeaderChain` for `E − B ≤ 8`; `HistoryContract` for `E − B ≤ 8 191` when the endpoint serves the state of `E` (≈ 27 h); `HeaderChain` for `E − B ≤ 256` otherwise. 2. Stored checkpoint `C`, under the same rules (`HistoryContract` at `C` needs an endpoint that serves the state of `C`, usually an archive node). 3. Backfill from `C` down to `C − B ≤ 256`, then `HeaderChain`. In all: `C − B ≤ 16 576`. Advances record a checkpoint in every sync period, so `C − B` stays below about two periods (16 384 blocks) while the light client is advanced through every period | `InstallTrustedCheckpoint` within 16 576 blocks above `B` |
| BSC | 1. A vote attestation within 256 headers of `B`, under the stored set covering it: until 5 d after the set's successor checkpoint (the newest set: 5 d after the newest finalized epoch checkpoint that re-announces it, `head.latest_finalized`). 2. Headers `B ..= C` for `C − B ≤ 255`. 3. Backfill from `C`. In all: `C − B ≤ 16 575` | `InstallTrustedCheckpoint` within 16 575 blocks above `B` |
| TON | 1. The masterchain block `T` that registers the burn's shard block, signed by the epoch its `prev_key_block_seqno` names: while Taira stores that epoch and it is fresh (until `(utime_until + stake_held_for) · 1000 − 1 h`), across later key-block hops. 2. An `OldMcBlocksInfo` back link to `T` from the first block after the newest stored key block. With the light client kept fresh, the window is unlimited while liteservers serve the blocks (archive liteservers for old blocks) | Advance the light client first when `T`'s epoch is newer than the newest stored key block |

### 4.14 Route registry and governance

#### 4.14.1 Registry state

```
SccpRouteV1 {
    network: SccpNetworkV1, route_id, escrow: AccountId,       // §4.15
    stranded: u128,                                            // §4.16
    revisions: BTreeMap<u32, SccpRouteRevisionV1>,
}
SccpRouteRevisionV1 {
    revision: u32,
    deployment: SccpDeploymentV1,
    destination_word: [u8; 32],
    initial_committee: SccpCommitteePinV1 {           // pinned at registration (§4.14.3 P1)
        generation: u64, committee_root: [u8; 32], start_height: u64, until_ms: u64 },
    activation: SccpRouteActivationV1,
    destination_frozen: bool,          // set by a proven frozen void (§4.16)
    destination_paused: bool,          // Parliament pause flag of the destination (§4.14.6)
    next_control_nonce: u64,           // starts at 1
    max_wrapped_supply: u128,          // Taira units = token units; equals the contract cap
    liability: u128,
    next_outbound_nonce: u64,
    registered_at_height: u64,
    forgery_floor: u64,                // §4.10; initially initial_committee.generation
    quarantine: Option<SccpQuarantineV1>,   // §4.10
}
SccpDeploymentV1 =
  | Evm  { address: [u8; 20], runtime_code_hash: [u8; 32] }      // ETH, BSC; address checked by CREATE2 recomputation
  | Ton  { master_account: [u8; 32], minter_code: SccpTonCodeRefV1,
           wallet_code: SccpTonCodeRefV1, bucket_code: SccpTonCodeRefV1 }
SccpTonCodeRefV1 { hash: [u8; 32], depth: u16 }   // cell representation hash and depth
sccp_destination_words: [u8; 32] → (SccpNetworkV1, u32)   // unique across all routes and revisions, never freed
sccp_governance_revisions: SccpGovernanceSubjectV1 → u64  // §4.14.3; absent = 0
```

#### 4.14.2 Activation states and the effective hold

`Staged` → `Bidirectional` ⇄ `Paused`; `Bidirectional`/`Paused` → `InboundOnly`
→ `Retired`. Every transition except the automatic frozen-void transition is a
Parliament-enacted action (§4.14.3).

**Effective Taira hold** of revision `r` of `network` at block time `t`, with
`fp` the network's active fast pause (§4.14.7):

```
hold(r, t) = activation(r) = Paused
           ∨ (fp.taira ∧ t < fp.until_ms)
           ∨ (¬reconciled(r) ∧ (forgery_held(r) ∨ r.quarantine.is_some()))   // §4.10 R1, R3
           ∨ ¬enabled
```

`reconciled(r)` holds once the reconciliation window of a quarantined `r` has
ended (§4.10 R3). Recording to a quarantined revision stays refused in every
phase (§4.4 step 1).

| State | Record | Inbound proof | Inbound settlement | Void proof | Refund |
|---|---|---|---|---|---|
| `Staged` | no | no | no | no | no |
| `Bidirectional` | yes, unless held | yes | yes, unless held | yes | yes, unless held |
| `Paused` | no | yes | held `Pending` | yes | held `Pending` |
| `InboundOnly` | no | yes | yes, unless held | yes | yes, unless held |
| `Retired` | no | yes (cannot occur, see below) | no | yes (cannot occur) | no |

- At most one revision per route is `Bidirectional` or `Paused`.
  `SwitchRevision` atomically moves the old revision to `InboundOnly` and a
  `Staged` successor to `Bidirectional`.
- `Retired` requires `liability(r) = 0` and no `Pending` inbound record or
  refund for `r`. Zero liability means every recorded message was either burned
  back and released, or voided and refunded, so the destination supply is zero
  (§4.15) and no burn on a retired deployment can exist. Minted messages keep
  status `Recorded` forever, because Taira never observes mints.
- A proven frozen void (§4.16) sets `destination_frozen` and moves `r` from
  `Bidirectional` or `Paused` to `InboundOnly` automatically.
- The hold never writes `activation`. Proofs, voids, inbound proving and
  governance continue while a revision is held.
- The Taira side and the destination side are independent: `Paused` and the
  other legs of `hold` stop Taira from recording and releasing, while
  `destination_paused` and an unexpired fast-pause part stop the destination
  from minting (§4.14.6). A Parliament pause proposal normally carries both
  `SetTairaPaused` and `SetDestinationPaused`; a fast pause sets both parts at
  once (§4.14.7). `RecordSccpMessage` requires both sides to be clear (§4.4).

#### 4.14.3 Governance: the Parliament pipeline

SCCP has exactly one governance authority: the SORA Parliament, with the
pause-only fast pause track of §4.14.7 beside it. Validators and their keys
take no part in any decision. SCCP uses the Parliament pipeline
(`ProposeSccpRouteGovernance`, the SCCP body list of
`parliament_attempt_policy_v1`, the certificate and deterministic block-start
enactment) with its own action payload and a per-subject expected head. Binding
juries use anonymous on-chain ballots per
`specs/parliament_private_ballot_design.md`; there is no Parliament key or
custodian, and SCCP reads no ballot internals.

**Payload.**

```
ProposeSccpRouteGovernance { proposal: SccpGovernanceProposalV1 }
ProposalKind::SccpRouteGovernance(SccpRouteGovernanceProposal { proposal: Box<SccpGovernanceProposalV1> })

SccpGovernanceProposalV1 {
    network_id: NetworkId,                    // MUST equal the live NetworkId
    base_revisions: Vec<(SccpGovernanceSubjectV1, u64)>,   // exactly S(P), sorted: the rev(s) the proposer saw
    actions: Vec<SccpGovernanceActionV1>,     // 1..=16, applied atomically in this order
}

SccpGovernanceActionV1 =
  // subject Route { network }
  | RegisterRoute      { network, revision, deployment, max_wrapped_supply, initial_committee: SccpCommitteePinV1 }
  | ActivateRevision   { network, revision }                  // Staged → Bidirectional
  | SwitchRevision     { network, from, to }                  // from → InboundOnly, to: Staged → Bidirectional
  | DeactivateOutbound { network, revision }                  // Bidirectional | Paused → InboundOnly
  | RetireRevision     { network, revision }                  // InboundOnly → Retired
  | RemoveStaged       { network, revision }                  // never activated, liability 0
  | ReleaseStranded    { network, amount: u128, recipient: AccountId, memo: String /* ≤ 256 B */ }
  | SetTairaPaused     { network, paused: bool }              // ensure: Bidirectional ⇄ Paused; lift rule (§4.14.7)
  // subject RouteControl { network }
  | SetDestinationPaused { network, revision, paused: bool }  // records a track-1 control (§4.14.6); lift rule
  // subject LightClient { network }
  | InitializeLightClient    { network, expected: Absent | Unusable, params, bootstrap }
  | InstallTrustedCheckpoint { network, checkpoint }
  | FreezeLightClient        { network }
  | ActivateLightClientProfile { network, version: u32, profile_hash: [u8; 32] }
  // subject Parameters
  | SetParameters      { next: SccpParametersV1 }
  // subject FastPauseControl { network }
  | SetFastPauseSuspended { network, duration_ms: u64 }       // §4.14.7
  // subject ForgeryHold { network }
  | AttestSccpDeploymentProgress { network, revision, at: Generation { generation, committee_root } | Frozen }   // §4.10
  | QuarantineSccpRevision       { network, revision }        // §4.10
  | OpenSccpReconciliation       { network, revision, window_ms: u64 }   // §4.10

SccpGovernanceSubjectV1 =
  | Route { network } | RouteControl { network } | LightClient { network } | Parameters
  | FastHold { network } | FastPauseControl { network } | ForgeryHold { network }
```

`network` is always an external profile. Route registration, the Taira pause
and the destination pause on the full track, light-client recovery and profile
activation, parameters, stranded releases, fast-pause suspension, forgery-hold
releases, quarantine and reconciliation are therefore all Parliament decisions,
and there is no other path to any of them. `FastHold{network}` has no action:
its revision changes only automatically, on fast-pause enactment, renewal and
lift clears (§4.14.7). The light-client lane subject `LightClient{network}`
covers the light client's stored state and its active profile version, so an
activation and a re-initialization of the same light client supersede each
other in enactment order, while activations on different networks never do.

Every action that reads or writes a revision's `activation` is under
`Route{network}`, including `SetTairaPaused`, so the Route head covers every
state the route lifecycle depends on. `RouteControl{network}` covers only
`destination_paused` and `next_control_nonce`, which only
`SetDestinationPaused` and fast-pause enactment write.

Light-client chain data whose native integers can exceed 2^53 − 1 (TON
validator weights, which sum to 2^60, and the TON config and key-block data in
general) is carried in `params`, `bootstrap` and `checkpoint` as opaque bytes
(BoC), never as integer fields, because every Parliament proposal must pass
`first_release_exact_json_u64_invariant_error` (below).

**Pipeline.**

1. **Propose.** `ProposeSccpRouteGovernance` has one proposer rule
   (`ensure_sccp_route_governance_proposer`): the authority is a citizen whose
   bond is at least `gov.citizenship_bond_amount`, or holds
   `CanProposeSccpRouteGovernance`. It is refused with
   `ParliamentBallotUnavailable` while the launch gate's ballot leg is closed
   (§10.2). `network_id` MUST equal the live `NetworkId`, the action count is
   1..=16, every action passes static validation (external network, nonzero
   revision, amount and cap bounds, memo length, bounded bootstrap and
   checkpoint sizes, no `InstallTrustedCheckpoint` for TON, a profile version
   of at least 2 with a nonzero profile hash, a nonzero `window_ms`,
   `duration_ms ≤ 3·MAX_FAST_PAUSE_MS`, and every `RegisterRoute` destination
   word unused in `sccp_destination_words`), every `u64` in the payload (base
   revisions, generations, the parameters, windows and durations, and the
   integer fields of light-client params, bootstraps and checkpoints) is at
   most 2^53 − 1 (the SCCP arm of
   `first_release_exact_json_u64_invariant_error`, which the pipeline applies
   at proposal and at attempt creation), and `base_revisions` lists exactly the
   subjects `S(P)` (below) with their current `rev(s)`. The proposal id is
   `ProposalKind::SccpRouteGovernance(..).fingerprint()` and the record is
   stored as `Proposed`; an identical re-proposal while it is `Proposed` is
   idempotent, and one after it left `Proposed` is refused (the id already
   exists). The full proposal body is in state, so every reviewer can fetch it
   from any Torii (§6). Ordinary fee.
2. **Attempt.** Any account creates the attempt with
   `CreateParliamentGovernanceAttemptV1`: for this kind it is permissionless
   and core-derived (§4.14.5 item 3). It additionally fails unless every
   `rev(s)` still equals `base_revisions` and every `RegisterRoute` destination
   word is still unused (checked next to the payout preflight of attempt
   creation); a proposal that fails this check is stale and can never get
   another attempt, so a new proposal against the current state is needed.
   `parliament_attempt_policy_v1` gives risk tier `Constitutional` and the SCCP
   body list: Rules Committee, Agenda Council, Interest Panel, Review Panel,
   Coordination Council, FMA Committee and Oversight Committee (public
   findings) and the Policy Jury (a binding jury voting by anonymous on-chain
   ballot), plus a Confirmation Jury when a Policy approval is narrow
   (`specs/parliament_private_ballot_design.md` §7–§8). The expected head
   (below) is frozen into the attempt.
3. **Lifecycle.** Future-beacon sortition, invitations (binding-jury members
   register their one-time ballot credentials at seat acceptance),
   deliberation, public findings, the binding ballot (credential root frozen at
   seal, casting opened at block start at the anchor `s0`, signerless
   fee-exempt ballots with public vote, nullifier and post-quantum membership
   proof, public counts, closure) and certification run as for every other
   proposal kind, except that the manager-only transitions are permissionless
   for this kind (§4.14.5 item 3). Lifecycle transitions are applied by the
   block-start pass (§4.7), and the shared keepalive produces their blocks on
   an idle chain.
4. **Enactment.** At the first block start with `t ≥ enact_not_before_ms` (G3,
   §4.7.2), Core recomputes the head. A changed head marks the proposal
   `Superseded`. Otherwise Core calls `sccp::governance::enact(certificate_id,
   effect_hash, s0, proposal)` in the isolated effect transaction of that
   certificate: `certificate_id` is the 32-byte
   `GovernanceCertificateId::derive_v1`, `effect_hash` is the certificate's
   `effect_preimage_hash`, and `s0: GovernanceAnchorV1 { height, position,
   timestamp_ms }` is the casting-open anchor of the approving Policy Jury
   ballot behind the certificate (the height, the opening transition's position
   in that block's pass, and the block's time). A Confirmation Jury ballot,
   outcome evidence and enactment never move it, and a retry attempt has its
   own. SCCP parses no other certificate internals.
   `enact` applies every action in order and increments
   `sccp_governance_revisions[s]` by one for each subject `s` of the proposal,
   inside the same effect transaction. If any action's precondition fails at
   enactment, the effect transaction is dropped, no SCCP state changes, and the
   attempt is recorded `ExecutionFailed`. Core emits `SccpGovernanceEnacted {
   proposal_id, subjects }`.

**After a failed attempt.** A `Rejected` attempt (including one whose binding
ballot ended `NoQuorum`) or an `ExecutionFailed` attempt leaves the proposal
eligible for a retry attempt (sequence + 1, at most 16) on the same id, which
anyone may create while `base_revisions` still match. The same content can
never be proposed again under a new id, because the fingerprint already exists.
A retry repeats the same actions, so after an `ExecutionFailed` caused by
content that has gone stale (for example a bootstrap that is no longer fresh),
the retry fails the same way and a new proposal with new content is needed.
After `Superseded`, or whenever any `rev(s)` has changed, a retry attempt
always fails the `base_revisions` check, and only a new proposal with the
current base revisions (a new id) can proceed.

There is no direct path: no instruction applies an SCCP governance action
outside Parliament enactment, and core rejects every `SetParameter` that
targets SCCP state (SCCP parameters are not in the generic `Parameter` set,
§4.1), whatever the executor.

**Expected head, scoped per subject.** Each action has exactly one subject (the
comment above it). For a proposal `P`, let `S(P)` be the sorted, deduplicated
list of its actions' subjects and `rev(s) = sccp_governance_revisions[s]` (0
when absent). The attempt's expected head, which equals the head implied by
`base_revisions` because attempt creation checks them, is:

```
subject_id = GOVERNANCE_SUBJECT_ID_V1 hash of GovernanceSubjectPreimageV1::Sccp(S(P))
version    = 1 + Σ_{s ∈ S(P)} rev(s)                         // checked u64
head_root  = parliament_governance_head_root_v1(&[(s, rev(s)) for s in S(P)])
expected   = GovernanceExpectedHeadV1::Present { subject_id, version, head_root }
```

Only the enactment of an SCCP proposal changes the `rev(s)` of a full-track
subject; the only automatic head change is `rev(FastHold{n})` (§4.14.7). Other
automatic SCCP state changes (records, releases, liability, nonces, frozen
voids, light-client advances, generations, forgery evidence, fast-pause leaves)
never touch a head; each action re-checks its own preconditions at enactment
instead, and the actions that such automatic changes can race have "ensure"
semantics or name the exact state they act on (`SetTairaPaused`,
`SetDestinationPaused`, below). Consequences:

- Proposals whose subject sets are disjoint never supersede each other:
  registering the TON route, re-initializing the Ethereum light client and
  changing parameters can all be in flight at once. Disjoint proposals can
  still interact only through automatic state changes and through the global
  destination-word index, which attempt creation and enactment re-check.
- Two proposals that share a subject are ordered by enactment; the later one
  becomes `Superseded` (or its attempt cannot be created) and must be proposed
  again against the new state. Proposers therefore batch related actions on one
  subject into one proposal.
- A proposal MAY span subjects (for example `RegisterRoute`,
  `InitializeLightClient` and `ActivateRevision` for one network, or a pause of
  every route before a Taira reset); it then competes with every proposal
  touching any of them. A pause (`SetTairaPaused` plus `SetDestinationPaused`)
  spans `Route{n}` and `RouteControl{n}`, so it and a concurrent lifecycle
  proposal on the same route supersede each other in enactment order, which is
  intended because both change the route's activation; neither can end
  `ExecutionFailed` because of the other.
- A captured fast pause panel changes only `rev(FastHold{n})`, never
  `rev(Route{n})`, `rev(RouteControl{n})`, `rev(LightClient{n})` or
  `rev(ForgeryHold{n})`, so it cannot supersede a full-track proposal,
  including a profile activation or a quarantine. Fast-pause leaves consume
  `next_control_nonce(r)`, an automatic change that the "ensure" semantics
  already tolerate.

**Implementation notes:**

- The SCCP arm of `governed_subject_id_v1` and of `GovernanceSubjectPreimageV1`
  (`crates/iroha_data_model/src/governance/types.rs`) is
  `Sccp(Vec<SccpGovernanceSubjectV1>)`, and the SCCP arm of
  `parliament_expected_head_v1`
  (`crates/iroha_core/src/smartcontracts/isi/world.rs`) computes the head
  above. The reducer checks only subject-id equality and head validity, and
  there is no global per-subject lock. A `version ≥ 1` with a nonzero
  `head_root` satisfies the head validity check.
- `sccp_governance_revisions` is incremented inside the effect transaction: the
  failure path re-checks that the head is unchanged before recording
  `ExecutionFailed`.
- State snapshots persist `sccp_governance_revisions`,
  `sccp_light_client_profiles` and every SCCP map of this revision.
- The `base_revisions` and destination-word checks run next to the payout
  preflight of `CreateParliamentGovernanceAttemptV1`.
- Certificates due in the same pass execute in a deterministic order (§4.7.2),
  so overlapping subjects supersede deterministically.

**Action rules** (all checked on Taira at enactment, at the enacting block's
time `T`):

- `RegisterRoute` → `Staged`:
  - **P0.** The launch gate of §10.2 is open, which includes reconciliation
    (§4.10).
  - **P1.** `initial_committee.generation` is retained; `committee_root` and
    `start_height` match its record; `until_ms = deadline_ms(generation)`; and
    every member of every generation from it to the current one resolved (no
    `None`, G6).
  - **P2.** For every generation `g` with `initial_committee.generation ≤ g ≤
    current`: `deadline_ms(g) ≥ T + committee_heartbeat_ms +
    SCCP_PIN_MARGIN_MS`. A destination installs each of these generations in
    turn and freezes if any has expired, so after a validity reduction checking
    only the pin is not enough. The parameter rule `committee_validity_ms ≥
    fast_pause_hold_ms + 2·committee_heartbeat_ms + 1 d` (§4.1) keeps P2
    satisfiable for a proposal that pins the generation current when it is
    made.
  - **P3 (TON).** `master_account` equals the address Taira computes from
    `StateInit{code: minter_code, data: canonical_initial_data}`, with the
    canonical initial data built per §5.3.1 from the generation's keys, the
    pin, the live `NetworkId`, `I`, the revision, the cap and the wallet and
    bucket code refs, using `iroha_sccp::v1::ton_cell` (`minter_account_id`
    over `state_init`, code cells as `CellRef::opaque`; only code hashes and
    depths are needed). All three code references MUST equal
    `ton_cell::locked_code_refs()`, the compiled minter, wallet and bucket
    hashes and depths pinned by `fixtures/sccp/ton_stateinit_v1.json`; a
    matching address for substituted code is refused.
  - **P4 (EVM).** `address` equals `keccak256(0xff ‖ SCCP_EVM_DEPLOYER ‖ 0^32 ‖
    keccak256(SCCP_EVM_CREATION_CODE ‖ abi.encode(ctor)))[12..32]` with `ctor =
    (TAIRA_NETWORK_ID, I, networkTag(network), revision, max_wrapped_supply,
    pin.generation, pin.committee_root, pin.start_height, pin.until_ms)`
    (§5.2.1). `SCCP_EVM_CREATION_CODE` is the exact creation bytecode pinned by
    `scripts/contract_tooling/artifact-lock.json` and embedded in
    `iroha_sccp::v1::evm_abi`; its drift tests fail if the two differ.
  - **P5.** `sccp_forgery_max_generation < initial_committee.generation`, or no
    forgery evidence has been recorded; otherwise the revision would start held
    (§4.10).
  - `revision = latest + 1` for the route; `destination_word` is unused in
    `sccp_destination_words`; `0 < max_wrapped_supply < 2^128`, and for TON `<
    2^96`. `forgery_floor` starts at the pinned generation and `quarantine` at
    `None`.
  - **Why the pin need not be current.** A deployment pinned to a past
    generation `g` is reachable only through genuine handoffs from `g`, and P2
    keeps that path open. A handoff that `g` forges before registration is
    slashable while `g` is liable, and the reviewers' live check (§4.14.4)
    detects it before activation.
- `ActivateRevision`: `r` is `Staged`, no other revision of the route is
  `Bidirectional` or `Paused`, and the network's light client is installed and
  not frozen, so burns on the new deployment are provable.
- `SwitchRevision`: `from` is `Bidirectional` or `Paused`, `to` is `Staged`;
  `from` becomes `InboundOnly` and `to` `Bidirectional` atomically.
- `DeactivateOutbound`: `r` is `Bidirectional` or `Paused`; it becomes
  `InboundOnly`.
- `RetireRevision`: `r` is `InboundOnly`, `liability(r) = 0`, no inbound record
  or refund of `r` is `Pending`, and a quarantined `r` is reconciled (§4.10
  R5).
- `RemoveStaged`: `r` is `Staged` and was never activated; its destination word
  stays reserved.
- `ReleaseStranded`: `amount ≤ stranded(route)`; the recipient is creditable
  under §4.12.3 step 3 and is registered if absent, and the release movement
  accepts the credit; `stranded −= amount`.
- `SetTairaPaused` ("ensure" semantics, addressed by network because at most
  one revision per route is `Bidirectional` or `Paused`): with `paused = true`,
  a `Bidirectional` revision becomes `Paused`, and if the route has a `Paused`
  revision or none that is `Bidirectional` or `Paused` (for example after a
  frozen void), nothing changes. With `paused = false`, a `Paused` revision
  becomes `Bidirectional`, otherwise nothing changes, and the lift rule
  (§4.14.7) is applied to the Taira part of the network's active fast pause. It
  never fails at enactment.
- `SetDestinationPaused`: if `r` exists and is not `Retired`, it sets
  `destination_paused(r) = paused`, applies the lift rule (§4.14.7) to `r`'s
  fast-pause part when `paused = false`, and then records a track-1 control
  with the revision's complete pause state (§4.14.6). The nonce is always
  consumed, also when nothing changed. If `r` has been retired or removed since
  the proposal, it is a successful no-op: a retired revision has zero liability
  and a removed one was never activated, so neither can have anything left to
  mint.
- `InitializeLightClient`: with `expected = Absent`, no light client is
  installed; with `expected = Unusable`, the installed one is frozen or has
  aged beyond its `ws_bound_ms`. The bootstrap's signing set MUST be fresh at
  the enactment block time (§4.13.2), so a slow round cannot install a stale
  checkpoint. A healthy light client is never replaced: to change its stored
  parameters, the Parliament freezes it and re-initializes it. A source-chain
  hard fork needs a release that appends a profile version and an
  `ActivateLightClientProfile`, never a re-initialization.
- `InstallTrustedCheckpoint`: the network is not TON (refused statically and at
  enactment); the light client is installed; the checkpoint is written with
  `origin: Parliament` and MUST NOT conflict with a stored checkpoint at the
  same height (a conflict fails the action; equivocation is reported with
  `ReportSccpLightClientEquivocationV1`).
- `FreezeLightClient`: sets `frozen`.
- `ActivateLightClientProfile`: `version` exceeds the network's newest recorded
  version (1 when none is), so activations are monotone and a version is never
  re-activated or rolled back; the enacting release compiles `version` with
  exactly `profile_hash`, else the action fails (a different hash) or, when the
  release does not compile `version` at all, the node defers the block instead
  of recording what it cannot verify (§4.13.2). It writes
  `sccp_light_client_profiles[(network, version)]` with `activation_height =
  enacting height + 1` and the proposal id. The light client need not be
  installed; frozen or aged light clients keep their state.
- `SetParameters`: `next` satisfies every rule of §4.1, including L1 against
  the node's genesis-pinned staking policy (§4.8). Parameters change only
  through this action, so `base_revisions` already guarantees that they are the
  ones the proposer saw; Torii shows the diff (§6).
- `SetFastPauseSuspended`, the lift rule and confirmation: §4.14.7.
- `AttestSccpDeploymentProgress`, `QuarantineSccpRevision` (which records
  `SccpQuarantineV1 { certificate_id, since_height }` from the enacting
  certificate) and `OpenSccpReconciliation` (which requires `r` quarantined and
  without a reconciliation record, one window per revision): §4.10.

**Replay.** The pipeline enacts a proposal at most once. A retry attempt
(sequence ≤ 16) on the same id is allowed only after a `Rejected`, `Superseded`
or `ExecutionFailed` predecessor, and for SCCP it succeeds only while
`base_revisions` still match (see "After a failed attempt" above), so after
`Superseded` it never does. An `Enacted` proposal can never be proposed or
attempted again. Because `base_revisions` is part of the content, a proposal id
names one decision about one state of its subjects, and a later decision with
the same actions (pause, resume, pause again) has different base revisions and
a new id. Nonces, expiry heights and executed-action sets are not needed.

#### 4.14.4 Deployment verification

Taira itself recomputes every deployment address at enactment (P3, P4), so a
registered address can only hold the locked code with the registered pin.
Before the bodies endorse and the binding jury votes on a `RegisterRoute`, and
again before an `ActivateRevision` is proposed, reviewers (the Review Panel and
FMA Committee members first, and anyone else) run locally:

```
iroha sccp deployment verify <original-authority flags> --network <p> --revision <r> --actions <actions.json>
```

The tool authenticates generations and compiled profiles against the selected
original native World cut. `--actions` reviews a proposed action file;
`--proposal-id` selects the exact stored proposal body. These flags are mutually
exclusive. Omitting both reviews the authenticated registered revision. It reads
the destination from the reviewer's configured RPC at one fixed finalized EVM
block or TON masterchain block. Initial `until_ms` must equal the original
native generation deadline; later installed generations follow the protocol
bounds. An initial committee at `high = start − 1` has no checkpoint yet.
EVM checks sample the highest accepted checkpoint and at most sixteen explicit
`--checkpoint-height` values; TON checks every occupied one of its three slots. It MUST confirm:

- **EVM.** The address equals the P4 recomputation, and the runtime code
  (`eth_getCode`) equals the runtime that `SCCP_EVM_CREATION_CODE` deploys with
  those constructor arguments; its keccak equals `runtime_code_hash`. The views
  return `opCount() = 0`, `totalSupply() = 0`, `controlNonce() = 0`,
  `pauseState() = (false, 0, 0, false)` and `equivocated() = false`, and
  `committeeState()` names generation `G` or a later genuine Taira generation
  (`cur.generation ≥ G`, `cur.root` equal to Taira's record of that
  generation), and every sampled `checkpointHeader` equals `keccak256` of
  Taira's genuine `X` at that height.
- **TON.** The account is active with the minter code, and `get_sccp_state`
  reports `initialized`, not `equivocated`, a zero op count, zero supply, a
  zero control nonce and a committee at `G` or a later genuine generation.

The proposal's Torii view (§6) shows the recomputed checks that Taira will
repeat at enactment. With a genuine pin, nothing can be minted, voided or
burned before registration without genuine certificates, and genuine
certificates never carry leaves for an unregistered destination. Anyone can
deploy a destination contract; only the registered deployment matters.

#### 4.14.5 Seating the Parliament on Taira

Without a seated Parliament whose binding ballot is qualified, no route can be
registered (§10.2), and nothing can be activated, paused on the full track or
recovered. `InitializeSccpV1` cannot check this, so the Taira reset tooling and
`scripts/taira_devnet.py` MUST provision all of the following in genesis, the
shared configuration or the reset ceremony, MUST refuse to produce a network
that lacks any of them, and `iroha taira doctor` MUST report each one. Items 3
and 4 are SCCP changes to how SCCP attempts are driven; the rest are not
SCCP-specific, and the recommended `[gov]` profile applies to every Parliament
proposal kind on Taira.

1. **Citizens.** Sortition candidates are exactly the citizens whose recorded
   bond is at least `gov.citizenship_bond_amount`
   (`canonical_parliament_eligible_candidates_v1`, at most 65 536 citizens).
   Genesis MUST, for each of `C` citizens: register the citizen's account
   (`Register<Account>`; `RegisterCitizen` needs an existing account), mint the
   bond plus a fee float, and register the citizen with `RegisterCitizen {
   owner, amount ≥ citizenship_bond_amount }` (registering another owner is
   allowed only in the initial genesis). Invitation responses, endorsements and
   fast-pause actions pay ordinary fees; anonymous ballots are signerless and
   fee-exempt (ballot spec §3.6). Each citizen is a distinct account whose key
   is a runtime secret generated by the reset tooling and handed to a distinct
   live participant; keys are never committed. Anyone can join later with
   `RegisterCitizen`. Citizenship bonds are independent of validator staking:
   SCCP's exit delay and slashing live entirely in the staking module.

   **Sybil cost on Taira.** The Taira faucet pays 25 000 XOR per claim at a
   4-bit proof of work (`[torii.faucet]`) against a 10 000 XOR bond, so today
   anyone can create funded citizens at almost no cost. Such citizens could
   capture bodies or fast pause panels (bounded as in §9.13), or stall
   full-track rounds by accepting seats and staying silent. Taira MUST set
   `citizenship_bond_amount` far beyond faucet reach (recommended 1 000 000
   XOR, that is 40 faucet claims) and MUST enable adaptive faucet difficulty
   (`pow_adaptive_claims_per_extra_bit > 0` and `pow_adaptive_max_extra_bits >
   0`), and the doctor checks both. Even then, Taira citizenship is only as
   scarce as test XOR.
2. **Body sizes and body liveness.** Each required body seats `s_b =
   min(size_b, C)` members; a citizen may sit on several bodies.
   - **Public findings.** The seven public-finding bodies run one after
     another. Each needs about six phase advances and `⌈2o/3⌉` endorsements of
     the same result root (`parliament_quorum_seats_v1`), where `o` is the
     number of seats accepted when the body's roster was sealed.
   - **Binding juries** (`specs/parliament_private_ballot_design.md` §3,
     §7–§8). The Policy Jury seals only with at least 3 accepted seats, each
     with a registered credential; fewer is an objective `NoRoster` with a
     sortition retry. It has exactly one ballot: turnout below `max(3, Q)` at
     closure is `NoQuorum`, and a lost credential counts as an absent vote. A
     narrow Policy approval needs a Confirmation Jury drawn from citizens
     outside the sealed Policy Jury.
   - **Config constraints.** `policy_jury_size ≥ 3`;
     `coordination_council_size` set explicitly (its default is 150); the
     ballot parameters `vote_notice_ms`, `casting_window_ms`, the per-block
     ballot budget, the concurrency bound and the admission-stamp difficulty
     are genesis or committed governance policy (ballot spec §3.10).
     `[gov.parliament_timed_ovn]` and `[gov.parliament_tle_key_lifecycle]` are
     retired. The `[gov]` values are part of the consensus execution policy, so
     every validator uses the same ones.

   Taira's current values (Rules 7, Agenda 9, Interest 11, Review 13, Oversight
   7, FMA 5, Policy Jury 25, Coordination and Confirmation unset) with its
   single genesis citizen cannot seat a binding jury. The recommended Taira
   profile:

   | Setting | Taira today | Recommended |
   |---|---|---|
   | genesis citizens `C` | 1 | 16 |
   | `citizenship_bond_amount` | 10 000 | 1 000 000 |
   | `rules_committee_size`, `agenda_council_size`, `interest_panel_size`, `review_panel_size`, `coordination_council_size`, `fma_committee_size`, `oversight_committee_size` | 7, 9, 11, 13, unset (150), 5, 7 | 5 each |
   | `policy_jury_size` | 25 | 9 |
   | `confirmation_jury_size` | unset (1 000) | 7 |
   | `parliament_alternate_size` | 21 | 3 |
   | invitation and public-finding windows | unset (3 600 blocks each) | 300 and 900 blocks today; milliseconds once the governance clock converts them (§4.7.1) |
   | `min_enactment_delay` | 600 | 50 blocks today; `enact_not_before_ms` under the governance clock |
   | binding-ballot windows and budgets | — | set with the ballot's qualification (`TODO:`, §12) |

3. **No clerk for SCCP.** `CreateParliamentGovernanceAttemptV1` and the
   manager-only transitions (`CompleteQualification`,
   `RegisterInitialSortition`, `RegisterSortitionRequest`, `AdvanceBodyPhase`,
   `EscalateRisk`) require `CanManageParliament` for other proposal kinds,
   which for SCCP would let one account outside the Parliament decide which
   proposals ever reach the bodies. For `ProposalKind::SccpRouteGovernance`
   they are permissionless and core-derived:
   `parliament_transition_requires_manager_v1` takes the proposal kind and
   returns false for SCCP, and each transition is valid only with the canonical
   content core derives from state. An attempt exists for exactly the
   `Proposed` SCCP proposal it names, whose `base_revisions` are current;
   `AdvanceBodyPhase` targets only the next phase once its precondition holds;
   `EscalateRisk` targets only the policy-derived tier; sortition registration
   uses only consensus-derived inputs. Where a manager transition carries a
   parameter that core does not derive today, the SCCP variant fixes it to that
   canonical value (`TODO:` enumerate each such field in the
   `SubmitParliamentLifecycleTransitionV1` executor). Ballot casting opens and
   closes at block start with no transition at all. Nobody chooses the SCCP
   agenda, and genesis grants `CanManageParliament` to nobody for SCCP. Other
   proposal kinds keep their manager rule.
4. **Parliament driver (optional).** Due transitions run at block start and the
   shared keepalive (§4.7) produces their blocks on an idle chain, so no driver
   ticks, relays ballots or lands transactions at exact heights. `iroha sccp
   governance drive` remains a convenience from any funded account: it creates
   attempts for `Proposed` SCCP proposals whose `base_revisions` are current,
   oldest first, and submits the permissionless manager-intent transitions as
   soon as they are valid. It reads `GET /v1/sccp/governance/proposals` and,
   per active attempt, `GET /v1/gov/parliament/attempts/{id}/plan`, which Core
   computes over one committed view by trial-applying every permissionless
   transition at the next candidate height; this is advice, not a reservation.
   Anyone may run a driver, several drivers are harmless (a duplicate
   transition fails and pays its fee), and a driver has no discretion: attempt
   creation is permissionless, so a flood of junk proposals cannot hold a
   genuine one back. The doctor MUST report every active SCCP attempt with its
   next due item and the height of its last progress transition, and fail when
   an attempt has due work and the tip is not growing.
5. **Global threshold beacon.** Sortition consumes a finalized beacon pulse at
   an exact future slot, and the fast pause panel draw consumes the NPoS
   epoch-boundary pulse that consensus already requires (§4.14.7). A
   global-beacon key session MUST be installed (`InstallGlobalBeaconKey`, an
   exact `2f + 1` validator-roster lifecycle certificate; the Taira
   public-reset beacon bootstrap), and every validator MUST run its beacon
   partial signer. Every validator-set change needs a new beacon DKG and
   `InstallGlobalBeaconKey` before the next pulse, a consensus prerequisite of
   free validator churn on Taira whether or not SCCP exists; it MUST be
   automated in-node (§12). A missing Parliament pulse is governance-local
   waiting, never a reason to halt block production (ballot spec §9).
6. **No ballot custody.** Validators provide no secret custody, opening or
   tally service for ballots: ordinary block execution verifies ballots and
   derives the counts. There are no Parliament TLE sessions, no TLE custody and
   no release shares, and the daemon's TLE preflight is deleted with them
   (ballot spec §9, §12).
7. **Node-generated credentials.** Item 5 MUST NOT add an operator step to the
   validator path. The beacon partial signer, including its FD200 credential,
   MUST default to key material that the node generates on first start under
   its store directory, owner-only as for the keeper key (§4.13.4), and MUST be
   overridable in `iroha_config`; no environment variables. Until this lands,
   joining a Taira validator requires configuring the beacon credential; that
   is a consensus requirement, not an SCCP one.

Validators provide item 5 as infrastructure. A threshold of them can withhold
or delay pulses (liveness, and with the parent proposer a choice among panel
draws, §4.14.7), but cannot choose members, proposals or outcomes, and cannot
open, read or alter ballots (§9.13).

**Tooling.** Binding-jury members register their credential when they accept a
seat and cast anonymous ballots through the account-free submission path of the
Parliament wallet (ballot spec §6), submitting at least `2·max_clock_drift_ms`
plus inclusion latency before a deadline (§4.3). `scripts/taira_devnet.py`
generates the `C` citizen keys in its owner-only workspace and runs the
citizens' invitation responses, endorsements and ballots itself. Disposable
devnets MAY build irohad with the `test-network-parliament-signers` feature for
the beacon signers; public Taira never does.

**Bring-up.** Once the launch gate is open (§10.2), first install the three
source light clients (§4.18): one proposal may initialize ETH and BSC, while
a separate proposal initializes TON. After each initialization is authenticated
at the operator's selected cut, deploy and prove the destination under that light
client (§7.4). Subsequent proposals register and activate those proven
deployments: ETH and BSC may share a proposal, while TON may proceed separately.
Initialization requires no registered route. A combined initialization and
registration proposal is usable only when a prior authenticated light client
already established deployment finality. The TON light client is proposed alone
because a TON bootstrap stays fresh only until `utime_until + stake_held_for −
margin`, 9.1 to 27.3 hours after capture with mainnet values (65 536 s rounds,
32 768 s stake hold), and actions are atomic: a stale TON bootstrap at
enactment would otherwise take its route's registration down with it. A failed
TON initialization is re-proposed with a fresh bootstrap. A bootstrap rule that
accepts a set that was fresh when proposed and then catches up is not adopted,
because it reopens a long-range window of up to the proposal's age.

**Latency.** A full-track round takes the invitation window, the public-finding
bodies one after another (each bounded by its window), the vote notice and
casting window of the binding ballot, a Confirmation Jury ballot when the
approval is narrow, and the enactment delay, plus a sortition retry after a
`NoRoster`. `parliament_sccp_attempt_latency_ms()` reports the configured total
of one such attempt and bounds `fast_pause_hold_ms` (§4.1). Wall-clock time no longer depends on
traffic, because due transitions run at block start and the keepalive produces
their blocks. This is the latency of every full-track decision, including a
Parliament pause; the fast pause track (§4.14.7) covers emergencies.

#### 4.14.6 Destination control messages

```
sccp_control_messages: (SccpNetworkV1, u32 revision, u64 control_nonce) → SccpControlRecordV1 {
    track: u8, parliament_paused: bool, fast_pause_until_ms: u64,
    certificate_id: [u8; 32], effect_hash: [u8; 32],
    height: u64, commitment_index: u32, leaf: [u8; 32],
}
```

`record_control(stx, network, revision, cause: ControlCauseV1 { track,
certificate_id, effect_hash }) -> Result<u64, Error>` records one control in
block `h`. It never writes pause state: the caller writes its own state first
(the Parliament flag, or the fast-pause record), and the leaf captures the
resulting complete state.

1. `control_nonce = next_control_nonce(r)`, then `next_control_nonce(r) += 1`.
2. The leaf (§3.4) has `target = network`, `r`'s destination word,
   `route_revision = r`, `control_nonce`, the cause's `track`, `certificate_id`
   and `effect_hash`, `parliament_paused = destination_paused(r)`, and
   `fast_pause_until_ms = fp.until_ms` if `r ∈ fp.revisions ∧ t(h) <
   fp.until_ms`, else 0.
3. The block MUST have fewer than 512 leaves (otherwise the action fails).
   Allocate `commitment_index` = the number of leaves already recorded in `h`,
   insert `sccp_block_leaves[(h, commitment_index)] = Control { network, r,
   control_nonce }` and the control record, and emit `SccpControlRecorded {
   network, revision, control_nonce, track, parliament_paused,
   fast_pause_until_ms, certificate_id, height, commitment_index }`.

Track-1 controls are recorded by `SetDestinationPaused` (§4.14.3), track-2
controls by fast-pause enactment, one per destination part (§4.14.7). Lapses
and Taira-only changes record nothing. The post-execution hook commits the
control leaf with the block's transfers (§4.5), so the block's `X` covers it.
Anyone then fetches the proof bundle (§6) and calls `applyControl` on the
destination (§5.1.6), which accepts a control only with a nonce above the last
applied one. Only the newest control matters: applying it makes every older one
stale, and it carries the complete state. Controls are recorded whether or not
`enabled` is set, for any non-`Retired` revision, and are never pruned. Taira
cannot observe whether a control was applied; wallets read the destination's
`pauseState()` and apply the newest control themselves before finalizing
(§7.1).

#### 4.14.7 Fast pause track

The fast pause track can only pause. A standing citizen panel, a disjoint
backup panel and a reserve are drawn outside the Parliament attempt reducer;
either panel decides by public, account-signed endorsements; an enacted fast
pause holds the network's Taira part and the destination parts of its live
revisions until it lapses by time.

**State.**

```
sccp_fast_pauses: SccpNetworkV1 → SccpFastPauseV1 {
    certificate_id: [u8; 32], effect_hash: [u8; 32], panel_id: [u8; 32],
    enacted_at: SccpPassPositionV1 { height: u64, position: u32 },   // block-start position (§4.7.2)
    enacted_at_ms: u64 /* e */, until_ms: u64 /* e + fast_pause_hold_ms */,
    taira: bool,                     // Taira part still held; set at every enactment
    revisions: Vec<u32>,             // destination parts still held (sorted)
}
sccp_fast_pause_suspended_until_ms: SccpNetworkV1 → u64
sccp_fast_pause_rounds: (SccpNetworkV1, SccpPanelRoleV1 /* Primary | Backup */) → SccpFastPauseRoundV1
sccp_pause_panel: Option<SccpPausePanelV1>
```

**Effect on Taira.** While `fp.taira ∧ t < fp.until_ms`, every revision of the
network is held (`hold(r, t)`, §4.14.2): a `Bidirectional` revision refuses
`RecordSccpMessage`, and inbound settlement and refunds of every settling
revision, `InboundOnly` included, stay `Pending`. Enactment sets `fp.taira =
true` whatever the activations are at that moment, so the Taira part is
independent of activation: if a Parliament pause is followed by a resume ballot
opening, a fast pause enactment and then the older resume's enactment, the
resume restores `Bidirectional` but cannot release the Taira part, because the
lift rule retains it. `activation` itself is never written; proofs, voids and
inbound proving continue.

**Effect on destinations.** For revision `r`, the destination state that its
leaves carry is `parliament_paused = destination_paused(r)` and
`fast_pause_until_ms = fp.until_ms` if `r ∈ fp.revisions ∧ t < fp.until_ms`,
else 0. The destination's effective pause is `parliamentPaused ∨ now_ms <
fastPauseUntilMs` (§5.1.6).

**Separation.** A fast pause never writes `activation`, `destination_paused`, a
forgery floor or a quarantine. A Parliament action writes fast-pause state only
through the lift rule. A lapse removes only fast-pause state.

**Standing panel.**

```
SccpPausePanelV1 { panel_seq: u64, pulse_id: [u8; 32], seated_height: u64, seated_at_ms: u64,
                   accept_until_ms: u64, term_ends_at_ms: u64,
                   drawn: Vec<AccountId> /* ≤ 3k, draw order: k primary seats, k backup seats, reserve */,
                   accepted: BTreeSet<AccountId>,
                   primary_id: [u8; 32], backup_id: [u8; 32] }
```

- **One panel per chain** serves every network; `k = fast_pause_panel_seats`.
- **When.** A draw happens in step G0 of the block-start pass (§4.7.2) of a
  block `B` that carries the NPoS pre-boundary global beacon pulse (the pulse
  consensus already requires at `h + 1 = current.authorization.last_height`,
  `specs/sumeragi.md` "Governed NPoS reconfiguration"), if no panel is seated
  or `t(B) ≥ term_ends_at_ms`. The draw reads that pulse as captured before
  execution, or, where an implementation cannot read it at block start, the
  same pulse as recorded in state for that boundary. It happens only in `B` and
  is never deferred, so a proposer cannot choose a more favourable candidate
  snapshot. It registers no Parliament pulse request and adds no
  consensus-mandatory pulse slot.
- **Term.** Draws use only the epoch-boundary pulse, at the first boundary at
  or after `term_ends_at_ms`. The literal reading of "drawn per epoch", a draw
  at every boundary, is the parameter value `fast_pause_panel_term_ms` = the
  epoch duration. The 7 d default exists because SCCP epochs can be as short as
  1 h and each draw is a fresh chance to seat a captured panel: with the
  default 9/6 panel and an attacker share of 0.2, either panel is captured with
  probability 0.0061 per draw, which is about 53 expected captures a year with
  hourly draws and about 0.32 with weekly draws. The owner-selected default is
  7 d; implementations support both values, and changing the term is a
  parameter change.
- **Who.** The candidate snapshot is every eligible citizen at the parent
  state, in canonical order: a bond of at least `gov.citizenship_bond_amount`,
  no slash or suspension in force, and an active account. Core draws up to `3k`
  members without replacement with the existing governance draw, seeded with
  `H_iroha("sccp/pause-panel/v1" ‖ network_id ‖ pulse_id ‖ be64(panel_seq))`.
  The first `k` hold the primary seats, the next `k` the backup seats, and the
  rest form the reserve, so the panels are disjoint. `panel_id =
  H_iroha("sccp/pause-panel-id/v1" ‖ be64(panel_seq) ‖ pulse_id ‖ u8 role)`,
  with role 0 for the primary and 1 for the backup. Seating sets
  `accept_until_ms = t(B) + fast_pause_seat_accept_window_ms` and
  `term_ends_at_ms = t(B) + fast_pause_panel_term_ms` and emits
  `SccpPausePanelSeated`. The draw is outside the Parliament attempt reducer,
  so it consumes no sortition sequence, redraw unit or proposal-wide entropy
  budget. Seating freezes and retains no bond: a seat holder whose bond falls
  below the floor, or who is slashed or suspended, only stops counting at the
  next eligibility recheck.
- **Seats and acceptance.** `AcceptSccpPausePanelSeatV1 { panel_seq }` is an
  account-signed transaction from a drawn member, paying the ordinary fee; it
  records acceptance (`SccpPausePanelSeatAccepted`), and an endorsement by a
  seat holder also counts as acceptance. Seat holders are a pure function of
  state and time. Before `accept_until_ms`, primary seat `i` is held by
  `drawn[i]` and backup seat `i` by `drawn[k + i]`. From `accept_until_ms`,
  walk the primary seats, then the backup seats, in order: a seat whose drawn
  holder has not accepted passes to the next reserve member (`drawn[2k..]`, in
  order) who has accepted and is eligible; each reserve member is used once; if
  none is left, the drawn holder keeps the seat. Replacement is lazy and never
  due work. A reserve member's endorsement counts only once that member holds a
  seat.
- **Failure modes.** With fewer than `2k` candidates no new panel is seated,
  the seated one (if any) stays, and `SccpPausePanelUnavailable` is emitted;
  with between `2k` and `3k` the reserve is shorter. If the canonical snapshot
  payload would exceed 8 MiB (the citizen registry is capped at 65 536
  entries), no draw happens, the seated panel stays, and
  `SccpPausePanelUnavailable { reason: SnapshotTooLarge }` is emitted. A
  missing pulse (no boundary reached, or the beacon unavailable) leaves the
  seated panel in place and extends its term; this is a governance-local wait,
  never a block-production halt and never due work.
- **Budget.** The draw is not charged to the shared pass budget (§4.7.2), so it
  can never defer due work and break K2. Its own bound is the snapshot ceiling,
  at most one draw per boundary block, never carried over.

**Endorsements and rounds.**

```
EndorseSccpFastPauseV1 { network_id: NetworkId, network: SccpNetworkV1, panel_id: [u8; 32], head: u64, incident_digest: [u8; 32] }
SccpFastPauseEndorsementV1 { incident_digest: [u8; 32], recorded_at_height: u64 /* committed height, not timestamp */ }
SccpFastPauseRoundV1 { panel_id, panel_seq, head, opened_at_ms, closes_at_ms,
                       endorsers: BTreeMap<AccountId, SccpFastPauseEndorsementV1>, certify_due: bool }
```

An endorsement is a public, account-signed transaction from a seat holder,
paying the ordinary fee. `head = rev(FastHold{network})` is the endorsement
nonce: it binds the current head, so an endorsement can never be replayed
against a later state. Preconditions, checked at admission and at execution:

1. `network_id` is live, and `network` has a route with at least one revision
   in `{Bidirectional, Paused, InboundOnly}`.
2. `panel_id` names the primary or the backup of the seated panel, and the
   authority holds a seat of that panel and is eligible now.
3. `t ≥ sccp_fast_pause_suspended_until_ms[network]`.
4. There is no active fast pause, or its renewal window is open: the record is
   absent, or `t ≥ fp.until_ms − fast_pause_renew_lead_ms`.
5. `head = rev(FastHold{network})`.
6. `incident_digest ≠ 0`.
7. The authority has not already endorsed that panel's open round.

- **Rounds.** The primary and the backup each keep their own round per network,
  with an immutable `closes_at_ms = opened_at_ms +
  fast_pause_endorse_window_ms`. An endorsement joins the panel's open round if
  that round has the same `panel_id` and `head` and `t < closes_at_ms`;
  otherwise it replaces the round with a fresh one opened at `t`. Expiry is
  lazy and not due work. When the round's endorsers who still hold a seat and
  are eligible reach `quorum(k)`, `certify_due` is set; that is a G2 rank-3
  item due at `t(B)`, so the keepalive becomes due (§4.7.3).
- **Both panels decide.** The first round to reach quorum certifies, and the
  other round of the network ends when the head changes at enactment. Failover
  to the backup is therefore automatic and unconditional: the backup can
  certify whenever the primary has not, with no eligibility or timeout
  condition, and a decline, a blocking minority or a `NoResult` in one panel
  never blocks the other. To disable the brake, a blocking minority (or absent members) must
  exist in both panels. If both rounds of a network certify in one pass, the
  primary's enacts first (G3 order, §4.7.2) and the backup's ends `NoResult` at
  its head recheck.
- **Renewal.** A round that opens while a fast pause is active, within its
  renewal window, is a renewal. Its enactment replaces the record before the
  lapse, so protection has no gap. It adds no power beyond the absence of a
  cooldown, because a panel could re-pause right after the lapse anyway.
- **Event.** `SccpFastPauseEndorsed { network, panel_id, endorser,
  incident_digest, count }`. Every endorsement is public.

**Certification** happens at the next block-start pass as the G2 rank-3
"pause-panel conclusion". It rechecks every condition: `t(B) < closes_at_ms`
(approvals never outlive their window, even across a halt); the round's
`panel_seq` is the seated panel's and `panel_id` names its primary or backup;
the endorsers who still hold a seat and are eligible number at least
`quorum(k)`; `head = rev(FastHold{network})`; the network is not suspended, and
there is no active fast pause unless its renewal window is open; and
precondition 1 still holds. A failed recheck deletes the round and emits
`SccpFastPauseNoResult { reason }`. Otherwise Core builds:

```
SccpFastPauseCertificateV1 { network_id, network, panel_id, panel_role: Primary | Backup, panel_seq, head,
    endorsement_root /* H_iroha over sorted (account, incident_digest, height) of eligible seat-holding endorsers */,
    endorsement_count, quorum, incident_root, effect_preimage_hash, certified_at_height, certified_at_ms }
effect_preimage_hash = fingerprint(SCCP_FAST_PAUSE_EFFECT_V1, (network_id, network, head))
certificate id       = SccpFastPauseCertificateId::derive_v1   // fingerprint domain SCCP_FAST_PAUSE_CERTIFICATE_ID_V1
```

Both roots use the eligible current seat-holding endorsers in canonical
`AccountId` order, with `n = endorsement_count`. Their exact preimages are:

```
endorsement_root = H_iroha("sccp/pause-endorsements/v1" ‖ be32(n) ‖
    concat(be64(len(account_payload)) ‖ account_payload ‖ incident_digest ‖ be64(recorded_at_height)))
incident_root = H_iroha("sccp/pause-incidents/v1" ‖ be32(n) ‖ concat(incident_digest))
```

`account_payload` is the canonical fixed-layout v1 Norito bare `AccountId`
payload. Incident digests retain the same account order and repetitions; they
are not deduplicated or independently sorted. A round may retain up to `3k`
endorsers across lazy seat replacements, but only its current eligible seat
holders count toward quorum.

It is not a `GovernanceCertificateV1`, so that type's Policy Jury requirement
does not apply.

**Enactment** happens in G3 of the same pass, after every Parliament
certificate due in that pass, in its own rollback-isolated transaction. It
rechecks the whole certification list again, because Parliament enactments
earlier in the pass can suspend the network, lift a pause, or slash or suspend
citizens; a failed recheck ends `NoResult`. Then:

- `e = t(B)`, `until_ms = e + fast_pause_hold_ms`, and `enacted_at = (h,
  position of this item in the pass)`;
- `taira = true`;
- the destination parts are every revision whose activation is `Bidirectional`,
  `Paused` or `InboundOnly` (`Staged` revisions have no transfer leaves;
  `Retired` revisions are excluded); for each part, Core writes the record
  first and then records a track-2 control with the complete state (§4.14.6);
- write `sccp_fast_pauses[network]`, replacing an active record on a renewal
  (which replaces `enacted_at`, so the lift rule compares against the newest
  pause);
- bump `rev(FastHold{network})`, delete both rounds of the network, and emit
  `SccpFastPauseEnacted { network, certificate_id, until_ms, renewal }`.

Block-start leaves are few and the cap is 512 leaves per block, so enactment
cannot run out of leaves in a fresh block; if it ever did, it would roll back
and the round would end `NoResult`.

**Lapse.** A fast pause stops holding on Taira as soon as `t ≥ until_ms`, and
on a destination as soon as `now_ms ≥ fastPauseUntilMs`. No transaction, leaf
or block is needed. The first block-start pass with `t ≥ until_ms` deletes the
record and emits `SccpFastPauseLapsed` (step G4); this is neither due work nor
a head change. A lapse never touches Parliament state, forgery holds or
quarantines, so a Parliament pause enacted before, during or after a fast pause
stays in force. A renewal enacted before `until_ms` leaves no gap; relayers
deliver its leaves before the old `until_ms`. A track-2 leaf delivered after
its expiry only consumes its nonce.

**Parliament interaction.**

- **Lift rule** (`specs/parliament_private_ballot_design.md` §11). A Parliament
  resume (`SetDestinationPaused{…, false}` for a destination part,
  `SetTairaPaused{…, false}` for the Taira part) clears the matching part of
  the network's active fast pause `fp` iff `(fp.enacted_at.height,
  fp.enacted_at.position) < (s0.height, s0.position)` lexicographically, where
  `s0` is the casting-open anchor of the approving Policy Jury ballot (§4.14.3
  item 4). The active record is by construction the current head of
  `FastHold(network)`, because every enactment, renewal and clear bumps that
  head, which satisfies the ballot spec's condition that the pause instance is
  the current head.
  Timestamps are not compared: two transitions in one block share a time, but
  not a position. Otherwise the part is retained and `SccpFastPauseRetained` is
  emitted, so a resume decided before an emergency never undoes a later pause.
  A clear bumps `rev(FastHold{network})` and emits `SccpFastPauseCleared {
  reason: Lifted }`; when the last part is cleared, the record is deleted.
- **Confirmation** is simply a Parliament pause (`SetDestinationPaused{…,
  true}` or `SetTairaPaused{…, true}`). It sets the Parliament state and leaves
  the fast part to lapse; because the effective pause is an OR, the target
  stays paused after the lapse. Relayers MUST deliver the confirming track-1
  leaf before `fp.until_ms`, otherwise the destination can mint between the
  lapse and the delivery; that is the only dependence on timely control
  relaying.
- **Suspension.** `SetFastPauseSuspended { network, duration_ms }` (subject
  `FastPauseControl{network}`) writes `sccp_fast_pause_suspended_until_ms =
  t(B) + duration_ms`, where `B` is the enacting block; `0` clears it, and
  `duration_ms ≤ 3·MAX_FAST_PAUSE_MS`. It takes a duration because the
  enactment time is unknown when the ballot is drafted. While `t <
  suspended_until`, endorsements are refused, and certification and enactment,
  renewals included, end `NoResult`. It does not clear an active fast pause; a
  lift does.
- **Responding to a captured panel.** Suspend first, then resume: a resume
  ballot that opens after the suspension's enactment has an `s0` later than
  every pause the panel could still enact.

**Abuse bounds and parameter choice.**

- **Power.** A panel can only pause. A captured panel can hold a network's
  Taira part and live revisions for `fast_pause_hold_ms` per enactment and
  renew continuously while it is seated, because there is no cooldown (a
  cooldown would let an attacker who forces a lapse disable the honest brake).
  The Parliament bounds this with suspension and a lift. A panel can never
  resume, mint, rotate, release, attest, quarantine or change any other state.
  Value is delayed, never lost.
- **Capture per draw** (at least `q` attacker seats in a panel; `a` is the
  attacker's share of the eligible snapshot, binomial approximation of a large
  snapshot; "either" is the relevant figure because either panel decides):

  | Panel `k`/`q` | `a` = 0.10: one / either | `a` = 0.20: one / either | `a` = 1/3: one / either |
  |---|---|---|---|
  | 5/4 | 0.00046 / 0.00092 | 0.0067 / 0.0134 | 0.045 / 0.088 |
  | 7/5 | 0.00018 / 0.00035 | 0.0047 / 0.0093 | 0.045 / 0.088 |
  | **9/6 (default)** | 0.00006 / 0.00013 | 0.0031 / 0.0061 | 0.042 / 0.083 |

- **Blocking per term.** A panel is blocked when at least `k − q + 1` seat
  holders do not endorse; the non-endorsing rate is `a + (1 − a)·u`, where `u`
  is the unavailability of honest seat holders after acceptance. "One" is a
  single deciding panel; "both" is this design, where the brake fails only if
  both panels are blocked:

  | Panel | `a`=0.1, `u`=0 | `a`=0.1, `u`=0.1 | `a`=0.2, `u`=0 | `a`=0.2, `u`=0.1 | `a`=1/3, `u`=0 | `a`=1/3, `u`=0.1 |
  |---|---|---|---|---|---|---|
  | 5/4 one / both | 0.082 / 0.007 | 0.242 / 0.059 | 0.263 / 0.069 | 0.430 / 0.185 | 0.539 / 0.291 | 0.663 / 0.440 |
  | 7/5 one / both | 0.026 / 0.001 | 0.131 / 0.017 | 0.148 / 0.022 | 0.308 / 0.095 | 0.429 / 0.184 | 0.580 / 0.337 |
  | **9/6** one / both | 0.008 / 0.000 | 0.073 / 0.005 | 0.086 / 0.007 | 0.226 / 0.051 | 0.350 / 0.122 | 0.517 / 0.268 |

  9/6 is better than 7/5 on both tables, so it is the default.
- **The cost of acceptance.** Replacement draws from members who accept, so an
  attacker who always accepts raises its effective share to `a / (a + (1 −
  a)·p_acc)`, where `p_acc` is the honest acceptance rate: 0.24 at `a = 0.2`
  and `p_acc = 0.8`. That is the price of a brake whose seats are actually
  staffed.
- **Over a year.** At `a = 0.2` with 9/6, weekly draws give a probability of
  about 0.27 of at least one capture a year (about 0.32 expected captures);
  hourly draws make capture near-certain (about 53 expected), which is why the
  default term is 7 d.
- **Grinding.** The epoch-boundary pulse is a unique threshold signature, but
  an `f + 1` beacon coalition that includes the parent proposer can withhold or
  delay boundary pulses and so choose among draws, which is beyond the BFT
  bound. A captured standing panel lasts a full term; the mitigation is
  Parliament suspension.
- **Taira caveat.** On Taira a citizen bond costs CPU-hours of faucet work, so
  these bounds are CPU-hour bounds there. Mainnet MUST price citizenship bonds
  against a `fast_pause_hold_ms` minting delay.
- **Hold lifetime.** `fast_pause_hold_ms ≥ parliament_sccp_attempt_latency_ms()`,
  the latency of one full-track attempt (§4.1; ballot spec §11). It cannot
  guarantee that the full track finishes before expiry, because unbounded
  exact-pulse waits are excluded (ballot spec §9) and a rejected attempt needs
  a retry attempt; renewal before the lapse, which has no cooldown, covers the
  gap while the panel is honest.
- **Rejected alternatives:** per-attempt panels drawn inside the attempt
  reducer (the standing panel avoids every reducer constraint); a re-pause
  cooldown; slashing panelists for unconfirmed pauses, which punishes honest
  panels when the Parliament is merely slow; timeout-based failover during an
  incident, which favours an always-online attacker more than seat acceptance
  does; and draws at every 1 h epoch by default.

### 4.15 Escrow and liability invariants

- **One escrow per route.** It is `sccp_route_escrow_account_id_v1(network_id,
  route_id, "xor")`, derived without the revision and non-signable.
  `InitializeSccpV1` creates it in genesis for all three routes, so it cannot
  be front-run. Core rejects every ordinary `Register<Account>` and
  `Unregister<Account>` of an escrow id, whatever the executor.
- **Core custody guards.** `ensure_not_sccp_escrow_source` and
  `ensure_not_sccp_escrow_destination` in
  `crates/iroha_core/src/smartcontracts/isi/asset.rs` reject every transfer,
  burn, mint or other balance change that touches an escrow, except the SCCP
  effects: credit by `RecordSccpMessage`, and debit by inbound release,
  outbound refund, a Parliament-enacted `ReleaseStranded` and reconciliation
  settlement (§4.10). The guards hold for every escrow in every revision state
  and are enforced in core, not in the upgradable executor. Neither the XOR
  definition owner (burn) nor holders of `CanTransferAssetWithDefinition` can
  move escrow funds.
- **Invariants after every transaction:**
  - `balance(escrow(route)) = Σ_r liability(r) + stranded(route)`;
  - `liability(r) ≤ max_wrapped_supply(r)` (a bounce checks the cap of its
    target revision);
  - on the destination, `supply(r) ≤ liability(r)` while the generations the
    deployment trusts produce no forged certificate. Every mintable message was
    counted into liability when recorded, burns decrease supply before Taira
    releases, and a void and a mint consume the same nonce bit. The destination
    cap (§5.1.4) is defence in depth and never binds under honest operation; a
    forgery is answered by slashing, holds and reconciliation (§4.9–§4.10).
- Tests assert all invariants, including negative tests for a definition-owner
  burn and a permissioned transfer against an escrow. The settlement tests
  (`crates/iroha_core/src/smartcontracts/isi/sccp/settle/tests.rs`) assert the
  balance invariant after every step of release (with and without a self-claim
  fee), bounce (including a full target cap), each hold reason, liability
  shortfall, refund versus strand, `ReleaseStranded`, a frozen void of a full
  512-nonce TON bucket, a void that leaves a multisig sender's refund pending,
  and pseudo-random operation sequences from fixed seeds.
- **Release precheck.** Every escrow release (inbound release, refund,
  `ReleaseStranded`, reconciliation settlement) runs through the same core
  movement path, and settlement first runs a read-only precheck of that path
  that shares its policy gate (`precheck_sccp_escrow_release` in `asset.rs`),
  so a refused credit holds a record instead of failing the proof or void that
  triggered it (§4.12.3).

### 4.16 Outbound voids and refunds

A recorded outbound message that is never minted is recovered by voiding its
nonce on the destination and proving the void to Taira. No refund depends on
Taira observing an absence.

- **On the destination** (§5.1.8), a nonce is voided in one of two ways, and
  either one emits the void event: `voidExpired`, after `deadline_ms`, with the
  same certificate proof as finalization; or `voidFrozen`, over a range of
  nonces, once the destination is frozen (expired or latched). A void sets the
  nonce bit without minting. Mint and void consume the same bit, so exactly one
  of them can ever happen.
- **`SubmitSccpOutboundVoidV1 { network, revision, proof: SccpSourceProofV1
  }`**: anyone may submit it (ordinary fee). The proof uses the network's light
  client (§4.13) and yields a normalized void event `{ emitter = r's
  deployment, first_nonce, count, message_id or zero, kind: Expired | Frozen
  }`: `SccpVoided` logs on ETH and BSC, and `sccp_voided` external-out messages
  on TON.

  The range is bounded per destination before any effect: an `Expired` void
  names exactly one nonce, and a `Frozen` range is `1..=256` nonces on ETH and
  BSC and `1..=512` (one bucket) on TON
  (`iroha_sccp::v1::network::max_void_frozen_range`). For each nonce whose
  record is `Recorded`: if `message_id ≠ 0`, it MUST equal the record's; the
  record becomes `Voided`; a refund is attempted; and `SccpOutboundVoided {
  refund_pending }` reports whether it still waits after that attempt.

  Every escrow release is one FASTPQ transfer transcript, and a transaction
  that exceeds its per-entry FASTPQ source limits is rejected as a whole. A
  void therefore releases value inline for at most `max(1,
  ⌊min(max_transcripts, max_deltas) / 2⌋)` senders of the intrinsic limits
  frozen at block start (8 under the bootstrap profile), in nonce order; the
  half left over covers the transaction's other movements. Only single-key
  senders are released inline: a transcript's bytes grow with the credited
  identity, and the intrinsic byte limits cover sixteen transfers between
  single-key accounts but only one transfer of a large multisig identity, so a
  few multisig senders could push the void past its source capacity, and a
  frozen destination cannot void those nonces again. A multisig sender's
  refund, and every further creditable refund of the range, stays pending for
  `SettleSccpV1::Refund`, which anyone may submit, several per transaction
  within the same limits. Strands and holds move no value and are not limited,
  so a full 512-nonce frozen void still completes in one transaction.

  A `Frozen` void also sets `destination_frozen` and moves `r` to
  `InboundOnly`. A void that changes nothing (every named nonce already left
  `Recorded`, and for `Frozen` the revision is already frozen and drained)
  fails, so a replay is never a silent success.
- **Refund.** A refund proceeds when SCCP is enabled and `hold(r, t)` is false
  (§4.14.2); otherwise it waits in `Pending` for `SettleSccpV1::Refund`. A
  quarantined revision's refunds are Taira-side records and settle in full once
  it is reconciled, while its liability covers them (§4.10 R3–R4). It credits
  the record's `sender` under the rules of §4.12.3 steps 3, 5 and 6,
  registering the account if it is absent:
  - if the sender is the escrow (a bounce) or can never be credited (a
    permanent identity refusal of §4.12.3 step 3), the amount moves to
    `stranded(route)` and the status becomes `Stranded`;
  - if the release movement refuses the credit now (§4.12.3 step 6), the record
    stays `Voided` with its refund pending for `SettleSccpV1::Refund`;
  - otherwise the sender is credited and the status becomes `Refunded`.

  A refund or strand sets `liability(r) −= amount`. No refusal of one nonce
  aborts the other nonces of a void range or the frozen transition. A
  Parliament-enacted `ReleaseStranded` (§4.14.3) is the only way out of
  `stranded`.
- A paused destination keeps `voidExpired` open, so messages that cannot be
  minted while it is paused are refunded after their deadlines.
- **Wallets** refuse to record when the destination's `untilMs` comes before
  the message could be finalized and no later rotation is available, or when
  the newest control for the revision leaves the destination paused (§7.1).

### 4.17 Events

`SccpEvent` (Taira data events):

- **Messages and settlement:** `MessageRecorded`, `BlockCommitted { height,
  root, count, history_size }`, `InboundProven`, `RecipientRegistered`,
  `InboundReleased`, `InboundBounced`, `InboundStranded`,
  `InboundLiabilityShortfall`, `OutboundVoided { refund_pending }`,
  `OutboundRefunded`, `OutboundStranded`, `StrandedReleased`.
- **Finality and generations:** `FinalityDegraded { height, reason }`,
  `CommitteeGenerationCreated { generation, cause, committee_root,
  start_height, deadline_ms }`, `CommitteeResync { generation, committee_root,
  start_height }`, `GenerationMemberUnslashable { generation, index }`,
  `GenerationDestinationCleared { generation, lc }`.
- **Evidence, holds and reconciliation:** `ForgeryEvidenceRecorded {
  evidence_id, generation, height, rule, offenders }`,
  `ForgeryOffenderUnslashable`, `RevisionForgeryHeld`,
  `RevisionForgeryReleased`, `RevisionQuarantined`, `ReconciliationOpened`,
  `ForgedMintProven`, `ReconciliationSettled { network, revision, backing,
  forged_supply }`, `ReconciledClaimSettled { network, revision, message_id,
  amount, payout }`.
- **Fast pause:** `PausePanelSeated`, `PausePanelSeatAccepted`,
  `PausePanelUnavailable { reason }`, `FastPauseEndorsed`, `FastPauseNoResult {
  reason }`, `FastPauseEnacted`, `FastPauseCleared { reason }`,
  `FastPauseRetained`, `FastPauseLapsed`.
- **Light clients:** `LightClientAdvanced`, `LightClientFrozen`,
  `LightClientInitialized`, `TrustedCheckpointInstalled`.
- **Governance and controls:** `RevisionActivationChanged { network, revision,
  from, to }`, `ControlRecorded { network, revision, control_nonce, track,
  parliament_paused, fast_pause_until_ms, certificate_id, height,
  commitment_index }`, `GovernanceEnacted { proposal_id, subjects }`.

Proposal submission, attempts, certificates and enactment outcomes
(`Superseded`, `ExecutionFailed`) are reported by the existing Parliament
governance events; SCCP adds only `GovernanceEnacted` with the subjects it
changed. Deleted: `SubjectCreated`, `AttestationSigned`, `BlockAttested`,
`RosterGenerationCreated`, `RosterDerivationFailed`, `HandoffStalled`,
`BridgeKeySet` and `AttestationFault`.

### 4.18 Taira resets and devnets

- **Identity.** The Taira identity is the `NetworkId` read from state. SCCP
  hashes, `X.network_id`, the instance id `I` and escrow account derivation all
  use it. Nothing about Taira is compiled into Rust or contracts, so
  `scripts/taira_devnet.py` devnets work with the same binaries.
- **Fresh identity per reset.** Genesis `InitializeSccpV1` carries a fresh
  random 32-byte `reset_nonce`, so every reset has a new `NetworkId` (and
  therefore a new `I`). The reset tooling refuses a `NetworkId` or
  `reset_nonce` it has recorded before. A reset that reused a genesis would let
  old certificates verify, so it is forbidden.
- **Before a reset**, the Parliament SHOULD enact one proposal that sets
  `SetDestinationPaused(true)` (and `SetTairaPaused(true)`) for every live
  revision, and anyone applies the controls on the destinations; a fast pause
  can bridge the time until it is enacted. If it is not done, the old
  deployments keep minting what certificates of their current generation cover
  until that generation's deadline (at most `committee_validity_ms`), and then
  freeze. The old deployments are bound to the old identity: their wrapped
  supply is stranded, and their burns are not accepted by the new Taira.
  Validator stake on the old network stays liable under its own rules until
  that network stops. This is accepted for a test network and MUST be stated in
  token metadata and the wallet UI ("Taira test XOR; redeemable only on Taira
  network `<NetworkId>`").
- **Genesis and the reset configuration MUST seed** `InitializeSccpV1`
  (creating generation 1 and the three escrows, and no route) and everything
  the Parliament needs (§4.14.5):
  - in genesis: each citizen's account, bond, fee float and `RegisterCitizen`,
    and optionally a `CanProposeSccpRouteGovernance` grant for the reset
    operator's proposing account (§4.19); no `CanManageParliament` is needed
    for SCCP; validator staking that satisfies L1 (§4.8) through the SCCP
    Kagami profile;
  - in the shared configuration: the recommended `[gov]` profile, the raised
    `citizenship_bond_amount` and the adaptive `[torii.faucet]` difficulty;
  - in the reset ceremony: the global-beacon bootstrap, installed by the
    in-node automation (§4.14.5 items 5 and 7).
- **After a reset:**
  1. Generation 1 is a genuine generation from genesis; the keeper and
     keepalives keep generations current from the first block.
  2. Once the launch gate is open (§10.2), anyone deploys fresh destination
     contracts pinned to a retained generation that satisfies P2 (EVM through
     `SCCP_EVM_DEPLOYER`, TON with its canonical initial data).
  3. A citizen (or the holder of `CanProposeSccpRouteGovernance`) makes the
     bring-up proposals of §4.14.5. Reviewers verify the deployments and
     bootstraps (§4.14.4) while the Parliament deliberates.
  4. The Parliament enacts the proposals and the routes activate.
- **Wallets** pin deployments per `NetworkId` in `[sccp]` client config and
  refuse a destination whose `tairaNetworkId()` or `consensusInstance()`
  differs from Torii's capabilities.

### 4.19 Permissions and fees

| Instruction | Authority | Fee |
|---|---|---|
| `InitializeSccpV1` | genesis block only | — |
| `Keepalive` | any Ed25519 authority, which may be unregistered | exempt when eligible (§4.7.4 K5); a block with a non-due keepalive is `Invalid` (K2) |
| `SubmitSccpForgeryEvidenceV1` | any, which may be unregistered | exempt when eligible (ingress pre-verified and deduplicated, §4.9); a block whose evidence fails at execution is `Invalid` (R-EX) |
| `RecordSccpMessage` | the sender | ordinary |
| `SubmitSccpInboundMessageV1` | any | ordinary; exempt on success as an eligible self-claim (§4.12.4) |
| `SettleSccpV1` | any | ordinary; exempt on success as an eligible inbound self-claim that can progress (§4.12.4) |
| `SubmitSccpOutboundVoidV1` | any | ordinary |
| `AdvanceSccpLightClientV1` | any, which may be unregistered for an exempt advance | ordinary; exempt on success as a `KeeperAdvance` unless it is a `Backfill`, admission-verified to move the head (at most one pending per authority and network, and one per network per block) |
| `ReportSccpLightClientEquivocationV1` | any | ordinary |
| `AcceptSccpPausePanelSeatV1`, `EndorseSccpFastPauseV1` | a drawn panel member or seat holder (§4.14.7) | ordinary |
| `ProveSccpForgedMintV1` | any (§4.10) | ordinary |
| `ProposeSccpRouteGovernance` | a citizen bonded at ≥ `gov.citizenship_bond_amount`, or a holder of `CanProposeSccpRouteGovernance` | ordinary |
| `CreateParliamentGovernanceAttemptV1` and manager-only lifecycle transitions, for SCCP proposals | any; core-derived content only (§4.14.5 item 3) | ordinary |
| Other Parliament lifecycle transitions and ballots | per the Parliament pipeline and the ballot spec | per the Parliament pipeline (anonymous ballots are signerless and fee-exempt) |

**Exempt classes.** `SccpExemptClassV1 = { Keepalive, ForgeryEvidence,
KeeperAdvance { network }, SelfClaim }`. Each block includes at most
`max_exempt_transactions_per_block` exempt SCCP transactions, with the
deterministic quotas `Keepalive` 1, `ForgeryEvidence` 1, `KeeperAdvance` 1 per
external network, and `SelfClaim` the rest. The quotas count included
transactions by content, whatever their outcome. Besides the generic
`Register<Account>(self)` rule that an unregistered self-claim uses (§4.12.4),
unregistered authorities are admitted only for `Keepalive`, `ForgeryEvidence`
and `KeeperAdvance`.

**Eligibility.** Whether a transaction is SCCP fee-exempt is one predicate per
exempt kind: a pure function of the committed parent state (the state the next
block executes on), the authority and the signed payload. Queue admission, fee
quoting, the per-block quotas and execution all evaluate this predicate against
the same parent state, never against writes of the executing block. So a
transaction is admitted, quoted, counted and executed as exempt exactly when it
is eligible. A transaction of an exempt shape that is not eligible is never
refused for its shape: it pays the ordinary fee and does not count toward the
quotas. Admission pre-verifies every eligible transaction and rejects only an
eligible transaction that is invalid.

Fee exemption is "exempt on success, charged on failure": a failed eligible
transaction is charged the ordinary Nexus fee within its signed fee intent,
when that intent covers the fee and the payer can pay it. Otherwise it fails
uncharged and keeps its own rejection reason, because a Nexus fee receipt never
exceeds the signed limits. The failure charge is the Nexus fee only, with no
PipelineGas transfer. Two classes never fail inside a valid block: a non-due
keepalive and failing forgery evidence make their block `Invalid` (K2, R-EX),
so a Byzantine leader cannot use them for free blocks. Pending limits
are per exempt kind, never across kinds: one keepalive per authority (the queue
also drops keepalives that a newer tip makes not due), forgery evidence
deduplicated by `(g, m, signers)` and against recorded offences (§4.9), one
keeper advance per authority and network, and one self-claim per authority and
per `message_id` (§4.12.4). Ingress MUST rate-limit unverifiable advances per
peer connection. Every SCCP instruction routes to the universal dataspace.

The only SCCP permission token is `CanProposeSccpRouteGovernance`, which only
allows proposing. Its grant and revoke rule is `OnlyGenesis`
(`INITIAL_GENESIS_ONLY_PERMISSION_NAMES` in
`crates/iroha_core/src/executor.rs`): genesis MAY grant it (for example to the
reset operator's proposing account), and after genesis nobody can grant or
revoke it. No manager role grants or revokes it. A holder can only put
proposals before the Parliament and pay their fees; bonded citizens can always
propose. The default executor gets allow-visitors for the SCCP instructions;
core enforces every SCCP rule. Implicit account registrations (a recipient at
settlement, refund or stranded release, §4.12.3) have the effect and
validation-fee DS classification of `Register<Account>`.

## 5. Destination contracts

### 5.1 Common semantics (all three chains)

#### 5.1.1 State

- **Immutable:** `tairaNetworkId`; `consensusInstance` (Taira's `I`); network
  tag, domain and identity word; `routeRevision`; `maxWrappedSupply` (token
  units = Taira units); route id; the initial pin `(generation, committee_root,
  start_height, until_ms)`. Constants: `MAX_VALIDITY_MS`, `MAX_FAST_PAUSE_MS`
  and `MAX_INIT_SLACK_MS` (§3.9).
- **Committee state:** `cur = { root: bytes32, generation: u64, start: u64,
  high: u64, untilMs: u64 }`. TON also stores the current keys. There are **no
  records of past generations**, so TON state size is constant in the number of
  rotations.
- **Checkpoints:** `checkpoint[h] → checkpoint_id = keccak256(X)`: every height
  on EVM, three slots on TON (§5.1.3).
- **Latch:** `equivocated: bool`.
- **Pause state:** `parliamentPaused: bool`, `fastPauseUntilMs: u64`,
  `controlNonce: u64` (the nonce of the last applied control, 0 initially).
- **Counters:** the consumed set over outbound nonces; outbound source nonces,
  which are `0 ..= 2^64 − 2` (§5.1.7); token supply; and `opCount`, which is
  monotone and counts finalizations, voids, burns and applied controls, but not
  checkpoints or rotations. `opCount` saturates at `2^64 − 1`: it never wraps,
  and the operation that reaches the bound, like every one after it, still
  succeeds.
- **Initial values** from the pin: `cur = {root, generation, start =
  pin.start_height, high = pin.start_height − 1, untilMs = pin.until_ms}`, no
  checkpoints, `equivocated = false`, pause state `{false, 0, 0}`.
- There is no owner, guardian, admin key or privileged control key. The only
  inputs that change the pause state are Taira control leaves under a genuine
  certificate (§5.1.6).

#### 5.1.2 Committee state machine

**Definitions.**

- `Live ⇔ ¬equivocated ∧ now_ms ≤ cur.untilMs`; `Frozen ⇔ ¬Live`. Frozen is
  permanent: nothing extends an expired `untilMs`, and the latch never clears.
- `t_eff(X) = min(X.timestamp_ms, now_ms)`.
- **CUR** ⇔ `X.generation = cur.generation ∧ X.committee_root = cur.root`.
  Every other certificate is refused with `CommitteeNotAccepted` before any
  signature check; it never changes state and never latches, whether genuine or
  not.

**Violation predicates.** They are evaluated only on a CUR certificate that
passed `VerifyCertificate` (§5.1.3): its signature verified in this call, or
its `X` is already stored and the mandatory cheap path applied, so the
signature verified when `X` was stored. A `ROTATION` header that an inline
call stored, which installs nothing, can therefore latch through V3 in a later
`submitCheckpoints` without a second signature check. Each predicate is a
conflict signed by `cur` itself:

| # | Predicate | Meaning |
|---|---|---|
| V1 | `checkpoint[X.height]` exists and `≠ keccak256(X)` | Two different `X` certified at one height |
| V2 | `X.height < cur.start` | Signed before its own tenure |
| V3 | `ROTATION ∧ X.height < cur.high` | A handoff below a height the same generation already certified |

**Latching:** set `equivocated = true` and `cur.untilMs = 0`, emit
`SccpLatched(reason, X.generation, X.height, a, b)`, persist, and stop
processing. Reason codes: V1 → 1 (`a` = stored id, `b` = new id); V2 → 2; V3 →
3 (for codes 2 and 3, `a = X.committee_root` and `b = keccak256(X)`). Latching
MUST NOT revert. When `cur` is a genuine Taira generation that a genuine
handoff installed (or is the pin), every V1–V3 trigger involves a certificate
Taira never made, and its signers are slashable on Taira (§4.9): V2 through
E1; V1 and V3 through E1, E3 or E4, for whichever of the two conflicting
certificates is not genuine. After a forged handoff that names the genuine
successor root, a genuine certificate can trip V2 (property 4): the evidence
is then the published forged handoff, not the certificate that latched.

**Updates** (`submitCheckpoints`; CUR only; requires `Live`; no violation):

1. Record `checkpoint[X.height] = keccak256(X)` if absent, and emit
   `SccpCheckpointed(height, id)`.
2. `cur.high = max(cur.high, X.height)`.
3. **Rotation** (`X.ROTATION`): set `cur = { X.next_committee_root,
   cur.generation + 1, X.height + 1, X.height, min(t_eff(X) + X.validity_ms,
   2^64 − 1) }`. On TON, `next_keys` is required iff `X.next_committee_root ≠
   cur.root`; it MUST hold a valid `n` of strictly ascending keys whose
   committee root is the new root (else `BadCommittee`); at a heartbeat the
   stored keys are kept. Emit `SccpCommitteeRotated(generation, root, untilMs,
   start)`. If the destination is no longer `Live` after the rotation (it
   lagged past the successor's deadline), the state persists and processing
   stops without reverting.
4. Nothing else changes `cur.untilMs`: a non-rotation certificate, or the same
   certificate replayed, never extends trust.

**Arithmetic.** No destination call aborts for arithmetic, and no value wraps:

- The clock is `now_ms = min(block.timestamp × 1000, 2^64 − 1)`, computed in
  256 bits on EVM, so it saturates instead of reverting or truncating for
  `block.timestamp ≥ 18 446 744 073 709 552`. TON's `now()` is a 32-bit
  unixtime, so `now_ms < 2^42` there and no TON time sum can reach `2^64`.
- `X.height + 1` and `cur.generation + 1` are `u64` values. X6 bounds a
  rotation's height and generation by `2^64 − 2`, and a CUR header has
  `X.generation = cur.generation`. The eligibility rule U2 (§5.1.3) adds 1 to
  the height and generation of a `ROTATION` header only.
- The two time sums saturate at `2^64 − 1`: a rotation sets `cur.untilMs =
  min(t_eff(X) + X.validity_ms, 2^64 − 1)`, and a control sets
  `fastPauseUntilMs = min(leaf.fast_pause_until_ms, min(now_ms +
  MAX_FAST_PAUSE_MS, 2^64 − 1))` (§5.1.6).
- The deployment bound `now_ms < initialUntilMs ≤ now_ms + MAX_VALIDITY_MS +
  MAX_INIT_SLACK_MS` of the constructor and `sccp_init` (§5.2.1, §5.3.1) is
  compared as `initialUntilMs − now_ms ≤ MAX_VALIDITY_MS + MAX_INIT_SLACK_MS`
  after `now_ms < initialUntilMs`, so its sum is never formed. A failure is
  `BadConfig`; `committee_transitions_v1.json` lists the bound under
  `init_bounds`.
- A range or a cap is compared without forming a value above its width.
  `voidFrozen(firstNonce, count)` accepts `firstNonce + count = 2^64` and
  refuses any range beyond it (§5.1.8). A mint compares `amount` with
  `maxWrappedSupply − totalSupply`, and answers `SupplyCapExceeded` when it is
  larger (§5.1.5).
- The two counters have a top. `opCount` saturates at `2^64 − 1` (§5.1.1). A
  source nonce is at most `2^64 − 2`: a stored next nonce of `2^64 − 1` is
  exhausted, and a burn of that sender is refused with `BadNonce` before any
  state change, so no source nonce is used twice (§5.1.7). The TON minter
  applies both bounds to its `op_count` and `outbound_nonce`, where the one
  `outbound_nonce` serves every sender, and its Acton harness pins them.

**Which entry points may do what.**

| Entry point | Classes accepted | Records checkpoint / raises `high` | Installs successor | On V1–V3 |
|---|---|---|---|---|
| `submitCheckpoints` / `sccp_checkpoint` | CUR, `Live` | yes | yes | latch |
| inline `finalizeFromTaira`, `applyControl`, `voidExpired` (and TON equivalents) | CUR, `Live` | yes | no | revert `LatchRequired`; the relayer resubmits through `submitCheckpoints` |
| `*FromCheckpoint` | a stored id whose header is CUR or the handoff that installed `cur` (§5.1.3), `Live` | no | no | — |

**Check order and errors.** After the chain-identity check:

- `submitCheckpoints` checks `TooManyCertificates`, then an empty batch
  (`NothingToDo`), then `Live`, then each certificate.
- The inline entry points obtain `X` first, through `VerifyCertificate` with
  V1–V3, where a violation gives `LatchRequired`. They check `Live` after it,
  in the step order of §5.1.5. On a destination that is not `Live`, an inline
  call therefore answers for its certificate first: one that does not verify
  is `BadSignature`, and a verified CUR certificate without a violation gets
  the `Live` answer below. Neither stores a checkpoint, because the call
  reverts.
- **TON finalize and void:** the minter checks the payload and its recipient
  (`BadPayload`, `BadRecipient`) before it obtains `X`, on the inline and the
  checkpoint form alike, because the value it requires depends on the payload
  nonce (§5.3.4). EVM checks them where §5.1.5 step 4 puts them, after `X`,
  `Live`, the pause and the block reference. On both flavours the deadline is
  checked before the leaf path.
- The checkpoint entry points obtain `X` through the checkpoint use check of
  §5.1.3: the length of `X` (`BadHeader`), the stored id (`UnknownCheckpoint`),
  X1–X7 with `ACTIVE` (`BadHeader`), `Live`, then eligibility
  (`CommitteeNotAccepted`).
- `voidFrozen` checks its range before `Frozen` (§5.1.8).
- A failed `Live` check answers `Equivocated` when the latch is set, and
  `CommitteeNotAccepted` when only `cur.untilMs` has passed.

**Properties.**

1. **No false latch.** Genuine certificates of `g` carry `X.generation = g` and
   heights in `[start_g, end_g]`; Taira certifies one `X` per height, so
   genuine checkpoints never conflict; `ROTATION` occurs exactly at `end_g`,
   and `high` only grows from CUR certificates at or below `end_g`. So V1–V3
   never fire in honest operation, and genuine certificates of other
   generations (including K→K′→K returns and heartbeats with identical keys)
   are refused without effect.
2. **Anchored expiry.** `cur.untilMs` changes only when a CUR rotation installs
   a successor (and at a latch, which zeroes it). The rotation sets it to
   `min(t_eff(X_rot) + X_rot.validity_ms, 2^64 − 1)`, which is at most
   `deadline_ms(successor)` and, because `t_eff ≤ now_ms`, at most `now_ms +
   X_rot.validity_ms`: a future-dated rotation installs its successor, but
   never with more than `validity_ms` from the destination's own clock.
   Non-rotation certificates, and identical or replayed certificates of any
   kind, leave `untilMs` unchanged. Trust in any generation ends by its
   deadline, at most `MAX_VALIDITY_MS` after its certified start.
3. **Retired quorums: no new authorizations.** Once a destination installs `g +
   1`, it accepts no certificate of `g`: none records a checkpoint, raises
   `high`, rotates or latches there. A departed quorum of `g` can therefore
   present certificates only to a destination still at `g`, only until
   `deadline_ms(g)` by that destination's clock, and only certificates that are
   slashable on Taira while `g` is liable (§4.8). The checkpoints of `g` give
   no new authorization either, with one exception: the handoff that installed
   `g + 1` stays usable until the next rotation (§5.1.3, U2). Effects already
   applied survive a rotation: mints, consumed nonces, applied controls
   (including a forged control with a maximal nonce, after which no genuine
   control applies) and, on TON, the mints already admitted (§5.3.4). The
   property is "no new authorizations from a retired generation", not "nothing
   signed by `g` has any effect".
4. **Departed-quorum attacks on a destination still at `g`:**
   - forged certificates of `g` at `H > end_g` (E1) are accepted and
     checkpointed and raise `high`; the genuine handoff `X_{end_g}` then trips
     V3 and latches;
   - a forged `X` at an in-tenure height that is not a handoff (E3 or E4): V1
     fires when the genuine `X` of that height is already stored, or is
     submitted while `g` is still current. Otherwise the forged checkpoint is
     usable while `g` is current (U1), and stops being usable when the genuine
     handoff of `g` is installed, which anyone can submit, or at
     `deadline_ms(g)`. A forged `X` commits to a tree of the forger's choosing,
     so the message deadlines and the control leaves proven under it are the
     forger's own: until it stops being usable, the supply cap and a freeze or
     latch of the destination bound what it authorizes, and Taira answers with
     the slashing of its signers and the forgery hold (§4.9–§4.10);
   - a forged handoff (E1, E3 or E4) is the capture case. Submitted through
     `submitCheckpoints` while `g` is current, it installs `cur`, also when it
     names the genuine successor root with forged message or history roots. It
     stays eligible under U2 until the next rotation, and the genuine handoff
     is then refused as not CUR, without latching. With the genuine successor
     root, genuine certificates of `g + 1` are CUR from the forged start
     `H_f + 1`: one at a height in `(end_g, H_f]` trips V2 and latches, and
     the successor's `untilMs` is the one the forged handoff granted. With an
     attacker root the
     destination no longer accepts Taira's genuine certificates, so neither
     controls nor voids reach it. Detection is the published `SccpCertificate`
     (§5.1.3 step 12), which the keeper watch and `iroha sccp monitor` read.
     The response is slashing of every signer, the per-revision forgery hold,
     and quarantine with reconciliation (§4.9–§4.10). Damage is bounded by the
     cap, and Taira-side release of every revision that can be at the forged
     generation stops once the evidence is recorded.
5. **No skipping.** One rotation per generation, in order: at most 16 per EVM
   call and one per TON message.
6. `voidFrozen` is allowed iff `Frozen`, which includes the latch.

#### 5.1.3 Certificate verification and checkpoints

`VerifyCertificate(cert)` runs these checks in order, cheapest first, and the
first failure is the call's error:

1. Exact lengths: `QC_FIXED` 116 (else `BadCertificate`), `X` 221 (else
   `BadHeader`), signature 192 on EVM or 96 on TON (else `BadCertificate`). EVM
   also checks `committee = 48n` with `n ∈ {4, 7, …, 31}` (else
   `BadCommittee`) and `signerYs = 48q` (else `BadCertificate`).
2. Parse `X` (X1–X7, §3.6), and require `X.network_id = tairaNetworkId` and
   `ACTIVE` set; any failure gives `BadHeader`. There is no skew check.
3. Classify (§5.1.2): anything other than CUR gives `CommitteeNotAccepted`.
4. EVM: `keccak256("SCCP/COMMITTEE/V1" ‖ u8 n ‖ committee) = cur.root`, else
   `BadCommittee`.
5. `signers >> n = 0` and `popcount(signers) = q(n)`, else `BadCertificate`.
6. Encodings, in this order, before the cheap path and before any curve
   operation:
   1. **Both flavours** reject the identity signature (`σ = O`) with
      `BadSignature`: on EVM the 192 bytes are all zero; on TON, as on Taira,
      the compressed form is `0xc0` followed by 95 zero bytes. The check sits
      here so that EVM and TON agree on a certificate whose `X` is already
      stored.
   2. **EVM:** every signer `y` is `< p` (else `BadCommittee`).
   3. **EVM:** every `σ` limb is `< p` (else `BadSignature`).
   4. **EVM:** for every signer key, with `x` = the key with `byte0 & 0x1f`:
      byte 0 satisfies `& 0xc0 = 0x80` and `(byte0 & 0x20 ≠ 0) = (y >
      HALF_P)`, `x < p`, and `(x, y) ≠ (0, 0)` (else `BadCommittee`). No
      precompile runs before these checks: `G1ADD` reads `(0, 0)` as the
      point at infinity, which would drop the signer from the aggregate, and
      on `x ≥ p` it fails and burns the gas forwarded to it.
7. `id = keccak256(X)`.
8. **Cheap path (MUST):** if `checkpoint[X.height] = id`, skip steps 9–12. Only
   `X` is ever used, and it is already certified. The path is mandatory, with
   no deployment or build option, because it is observable: a certificate
   whose `X` is stored is not checked against its signature and is not
   published again, and the shared outcome table pins both (§11.4). Steps 1–6
   have run, so the lengths, the classification as CUR, the signer set and the
   encodings of step 6 are enforced on this path too.
9. `R = SHA-256(RESULT_TAG ‖ X ‖ result_body)` (§3.6) and `m = SHA-256(P)`
   (§3.7). `R` enters nothing but `P`, so it is computed here, on the full
   path only.
10. Aggregate. **EVM** uses `G1ADD` over `(x, y)`, each coordinate
    zero-extended to 64 bytes (§3.7); a signer point off the curve, then `apk =
    O`, give `BadCommittee`, before `σ` is read as a point. **TON** pushes the
    key slices and has no aggregate step of its own.
11. Pairing check (§3.8). **EVM** zero-extends the four `σ` limbs to the
    256-byte G2 input (§3.7). `BadSignature` answers a `σ` that is not the
    canonical encoding of a point of the G2 subgroup, an aggregate key outside
    the G1 subgroup (`PAIRING_CHECK` refuses either input) and a failed
    pairing; the identity signature was refused at step 6. `G1ADD` adds any
    points of the curve, so the contract observes the aggregate key and never
    a single signer key: signer keys outside G1 whose components outside the
    subgroup cancel are accepted when the pairing holds. **TON** has one
    verdict for steps 10 and 11, the result of `BLS_FASTAGGREGATEVERIFY`, and
    `false` throws `BadSignature` (§5.3.4 item 5): a stored signer key that is
    no canonical point, is the identity or lies outside G1, an identity
    aggregate, a `σ` that is no point of the G2 subgroup, and a failed
    pairing. None of these inputs exists under a root Taira admitted (§3.8),
    so the two flavours differ on no certificate of a genuine committee.
12. **Publish the certificate.** EVM emits `SccpCertificate(X.height,
    X.generation, qc, header, signature)`; TON sends the external message
    `sccp_certificate`. This happens after every successful full-path
    verification, whatever follows (a checkpoint, a rotation, a latch or a
    use). A call that later reverts discards the event with every other effect,
    so a forged certificate that took effect is always published.
13. Evaluate V1–V3, then the entry point's action (§5.1.2).

Step 12 exists because forged certificates can arrive through internal calls
(there is no direct-caller rule), and their bytes would otherwise be reachable
only through tracing APIs that public RPC usually lacks. Other events carry
only `keccak256(X)`, and only the first forged rotation, which a Taira
generation signs, is slashable (later attacker generations give
`EvidenceUnknownGeneration`), so that certificate must be recoverable. The
keeper watch builds evidence straight from these events (§4.13.4). The cost is
about 8k gas per full-path certificate on EVM.

**Checkpoints.**

- **EVM:** `mapping(uint64 ⇒ bytes32) checkpointHeader`, never evicted.
- **TON:** at most 3 entries `(height, id)`. Insert only if the height is
  absent and either `count < 3` or `height > min stored`; the minimum is
  evicted. A height already present with an equal id is a no-op. Conflict
  detection covers retained entries only.
- **Using a checkpoint** (`CheckpointRefV1 = {header: X}`): a `*FromCheckpoint`
  entry point requires, in this order:
  1. `X` of 221 bytes (else `BadHeader`);
  2. `checkpoint[X.height] = keccak256(X) ≠ 0` (else `UnknownCheckpoint`);
  3. X1–X7 with `ACTIVE` (else `BadHeader`);
  4. `Live` (else `Equivocated` when latched and `CommitteeNotAccepted` when
     expired, §5.1.2);
  5. the stored header is eligible (else `CommitteeNotAccepted`):
     - **U1.** `X.generation = cur.generation` and `X.committee_root =
       cur.root`; or
     - **U2.** `X` is the handoff that installed `cur`: `ROTATION` is set,
       `X.generation + 1 = cur.generation`, `X.height + 1 = cur.start` and
       `X.next_committee_root = cur.root`.

  The messages and controls of a retired generation are proven under the
  handoff that installed `cur`, or under a newer certificate of the current
  generation, with a history proof (§5.1.5). Nothing else about checkpoints
  depends on eligibility: storage, the TON slots, V1 conflict detection over
  the stored ids, and the cheap path of step 8, which still requires the CUR
  classification of step 3 first. U2 applies to checkpoint-reference entry
  points only. It never makes a certificate CUR, so an old certificate cannot
  rotate, latch or skip classification through it. §5.1.2 properties 3 and 4
  state what this leaves to a forged checkpoint.
- **TON eviction race.** A `*_checkpoint` message whose checkpoint was evicted
  throws `UnknownCheckpoint` and bounces with its value. The inline form is the
  fallback only for a certificate of the current generation. A header of an
  earlier generation is not CUR and cannot be presented inline: its messages
  and controls are proven under a newer certificate of the current generation,
  with a history proof (§5.1.5).

**`submitCheckpoints(certs[1..16])`** (TON: one `sccp_checkpoint` per message)
is permissionless, works while paused and does not count toward `opCount`. Like
every entry point, it first checks chain identity (EVM `block.chainid` of the
profile; TON `GLOBALID = −239`). It then checks `TooManyCertificates` (more
than 16 certificates), an empty batch (`NothingToDo`) and `Live`, in this
order, and processes the certificates in order (§5.1.2 updates). A latch, or a
rotation that leaves the destination not `Live`, persists and stops processing.
Any other failure reverts the whole call: the batch is atomic. A call that
changed no state reverts `NothingToDo`.

#### 5.1.4 Supply cap

`maxWrappedSupply` is immutable and is set at construction to Taira's
`max_wrapped_supply` (same units). Mint reverts if it would be exceeded.

#### 5.1.5 Block and message proofs, and finalization

`BlockRefV1 = {height, sccpRoot, messageCount, historyIndex, historyPath}` is
checked against a verified `X`, and a reference that fails is `BadProof`:

- If `height = X.height`: require `sccpRoot = X.sccp_root ≠ 0`, `messageCount =
  X.message_count`, `historyIndex = 0` and an empty path. The certified block
  itself takes no history proof.
- Otherwise: require `height < X.height`, `1 ≤ messageCount ≤ 512`, `sccpRoot ≠
  0` and `len(historyPath) ≤ 32`, and `merkle_root(history_leaf(height,
  sccpRoot, messageCount), historyIndex, X.history_size, historyPath) =
  X.history_root` (§3.5). `X.history_size ≤ 2^32` is part of X5, so a
  one-sibling path for leaf `2^32` can never verify.

Leaves are checked with `merkle_root(leaf, leafIndex, messageCount, path) =
sccpRoot` (path ≤ 9 siblings). Any certificate of the current generation, or
any usable stored checkpoint (§5.1.3), therefore proves any older message or
control.

**`finalizeFromTaira(cert, proof)` / `finalizeFromCheckpoint(ref, proof)`:**

1. Chain identity: EVM `block.chainid` of the profile; TON `GLOBALID = −239`.
2. Obtain `X`: inline, `VerifyCertificate` as CUR (which records the checkpoint
   and raises `high`); otherwise the checkpoint use check (§5.1.3).
3. Require `Live` and no effective pause (`MintingIsPaused`, §5.1.6).
4. The block reference, as above. The payload is valid per §3.2 with
   `source_domain 0`; `dest_domain`, `route_revision` and `route_id` equal to
   this contract's own; `asset_id = "xor"`; a recipient valid for the own codec
   (EVM: nonzero and not this contract; TON: `addr_std` workchain 0, not the
   minter); and `now_ms ≤ deadline_ms`.
5. The transfer `leaf` per §3.4 with the own destination word verifies against
   the block reference.
6. The payload's `nonce` is not consumed; mark it consumed.
7. `totalSupply (+ pending) + amount ≤ maxWrappedSupply`, compared as `amount ≤
   maxWrappedSupply − totalSupply (− pending)` so that no sum exceeds its
   width; else `SupplyCapExceeded`.
8. Mint `amount` to the recipient; `opCount += 1`; emit `SccpFinalized`. Return
   the message id.

Finalization is permissionless; the recipient is fixed by the payload.

#### 5.1.6 Parliament and fast-pause controls (`applyControl`)

The pause state of a destination is set only by Taira control leaves (§3.4,
§4.14.6). `ControlProofV1` carries `{controlNonce, track, parliamentPaused,
fastPauseUntilMs, certificateId, effectHash, leafIndex, path, block}`.

1. Chain identity, as in §5.1.5.
2. Obtain `X` (inline as CUR, or from a checkpoint) and require `Live`.
3. The leaf is the §3.4 control leaf computed from the contract's own
   immutables (`lane_bytes(sora-taira, own network)` with the own
   `tairaNetworkId`, the own destination word, the own `routeRevision`) and the
   supplied fields; it verifies against the block reference. The §3.4
   constraints hold, else `BadControl`.
4. `controlNonce > stored`, else `StaleControl`. Gaps are allowed: only the
   newest control needs to be applied.
5. Set `parliamentPaused = leaf.parliament_paused` and `fastPauseUntilMs =
   min(leaf.fast_pause_until_ms, min(now_ms + MAX_FAST_PAUSE_MS, 2^64 − 1))`:
   the bound saturates, so the step never aborts for arithmetic. Store the
   nonce, `opCount += 1`, and emit `SccpControlApplied(controlNonce, track,
   parliamentPaused, fastPauseUntilMs, certificateId)`.

The **effective pause** is `parliamentPaused ∨ now_ms < fastPauseUntilMs`. It
blocks minting only: burns, voids, checkpoints, rotations and controls are
never paused. The clamp is defence in depth against a Byzantine Taira time,
which CT1 already bounds (§4.3). A track-2 leaf applied after its expiry only
consumes its nonce. `applyControl` is permissionless and not blocked by the
pause. It needs `Live`, so a frozen destination cannot apply controls, which is
harmless because it can never mint again. The destination holds no privileged
key at all: the Parliament or the fast pause panel decides, Taira's committee
certifies the block that carries the decision, and any relayer delivers it.

#### 5.1.7 `transferToTaira`

Burns wrapped XOR from the caller and emits the source event:

- **Canonical calldata** (EVM): the contract reverts with
  `NonCanonicalCalldata()` unless `msg.data.length = 4 + 0x80 + ceil32(len)`,
  the offset word of `tairaRecipient` is `0x60`, `len` is in 1..=1024, and the
  padding after the recipient bytes is zero. Solidity's own decoder accepts
  other encodings; this rule keeps exactly one accepted encoding, which the
  shared `calldata_conformance` table pins together with the Rust decoder
  (§5.2.2). A dirty `expectedNonce` word already reverts in Solidity's ABI
  decoder.
- recipient: `taira_account` bytes, 1..=1024.
- `tokenAmount > 0` and `tokenAmount < 2^128` (units are Taira units).
- **EVM:** `nonce = transferNonces[msg.sender]` MUST equal the caller-supplied
  `expectedNonce`, else `BadNonce(nonce)`; it then increments. Per-sender
  nonces make the payload derivable from the call.
- **Nonce range.** A source nonce is in `0 ..= 2^64 − 2`, so the stored next
  nonce is at most `2^64 − 1`, and that value means the nonces are exhausted.
  On EVM, when `transferNonces[msg.sender] = 2^64 − 1`, every call of that
  sender that passes the checks above reverts `BadNonce(2^64 − 1)`, whatever
  `expectedNonce` it supplies, before any state change. The nonce `2^64 − 1`
  is never used, and no nonce is reused or wrapped. Other senders are not
  affected.
- **TON:** the owner MUST be `addr_std` in workchain 0 without anycast.
  Otherwise the minter throws, and the standard bounce restores the wallet
  balance. `nonce = outbound_nonce++` (the Jetton master serializes all
  burns), in the same range: at `outbound_nonce = 2^64 − 1` the minter throws
  `BadNonce` before any state change, for every owner, and the bounce restores
  the wallet balance (§5.1.2 "Arithmetic").
- Build the payload per §3.2 (`dest_domain 0`, `deadline_ms 0`, sender =
  caller, route constants) and `message_id` per §3.3 with lane `(own, Taira)`.
  Burn, `opCount += 1`, emit.

Burns are allowed while paused, after expiry and after a latch.

#### 5.1.8 Voids

- **`voidExpired(nonce, cert, proof)` / `voidExpiredFromCheckpoint(nonce, ref,
  proof)`** run the steps of §5.1.5 except the pause check (step 3's pause
  part) and the cap check (step 7), and require `now_ms > deadline_ms` instead
  of `≤`. They require `Live`. The `nonce` argument MUST equal the payload
  nonce, else `BadNonce`; it is checked after the leaf path and before the
  consumed set, so a wrong argument for a consumed payload is `BadNonce`. They
  mark the nonce consumed, set `opCount += 1` and emit
  `SccpVoided(messageId, nonce)`. Nothing is minted.
- **`voidFrozen(firstNonce, count)`** checks its range first: `1 ≤ count ≤ 256`
  and `firstNonce + count ≤ 2^64`, compared without forming a value above
  `u64` (`firstNonce + count = 2^64` is valid, since the last nonce is `2^64 −
  1`); on TON `count ≤ 512` within one bucket. A range failure gives
  `BadAmount` on EVM and `BadRange` on TON. It then requires `Frozen` (expired or latched), else
  `NotFrozen`, and every nonce in the range unconsumed, else revert. It marks
  them all consumed, sets `opCount += 1`, and emits `SccpVoided(0, nonce)` per
  nonce (TON: one external-out message for the range). It is permissionless: a
  frozen destination can never mint again, so voiding any nonce is safe. A mint
  already in flight on TON when the latch fires is not minted (§5.3.4).
- **Canonical calldata** (EVM): `voidFrozen` reverts with
  `NonCanonicalCalldata()` unless `msg.data.length = 0x44`. Voids are proven to
  Taira from the `SccpVoided` logs (§4.16), so the dynamic `voidExpired*`
  arguments need no calldata rule.

### 5.2 EVM: Ethereum and BSC (`contracts/evm/sccp/SccpTairaXor.sol`)

One contract source and the one library it imports
(`contracts/evm/sccp/lib/BLS12_381.sol`, §5.2.4) are compiled by `solc` 0.8.31
for Ethereum and BSC. The contract is the ERC-20/BEP-20 token itself. It makes no external calls other than
precompiles (so it needs no reentrancy guard), and has no owner, no upgrade
path and no setters. Token metadata: name `Taira XOR`, symbol `tXOR`, decimals
9, initial supply 0.

#### 5.2.1 Constructor and deployment

```solidity
constructor(bytes32 tairaNetworkId, bytes32 consensusInstance, uint8 networkTag /*0x41|0x42*/,
            uint32 routeRevision /*≠0*/, uint256 maxWrappedSupply /*≠0, <2^128*/,
            uint64 initialGeneration /*≥1*/, bytes32 initialCommitteeRoot /*≠0*/,
            uint64 initialStartHeight /*≥1*/,
            uint64 initialUntilMs /*now < u ≤ now + MAX_VALIDITY_MS + MAX_INIT_SLACK_MS*/)
```

- The constructor derives the domain, identity word and route id text from
  `networkTag`, requires `block.chainid` to equal the identity word, sets `cur
  = {root, generation, start, high = start − 1, untilMs}` and the pause state
  `{false, 0, 0}`, and stores every argument as an immutable.
  `MAX_VALIDITY_MS` and `MAX_FAST_PAUSE_MS` are compile-time constants of the
  source, not arguments, so they are part of `SCCP_EVM_CREATION_CODE`.
- **Constructor errors.** A `networkTag` other than `0x41` or `0x42`, or a
  `block.chainid` that differs from the tag's identity word, reverts
  `WrongChain()`; this is checked first. Every other violated bound reverts
  `BadConfig()`: a zero `tairaNetworkId` or `consensusInstance`, the bounds
  written in the signature above, and the `init_bounds` rows of
  `committee_transitions_v1.json`. The contract is initialized by its
  constructor only, so the EVM ABI does not declare `NotInitialized` or
  `AlreadyInitialized`.
- **The slack on `initialUntilMs`.** `until_ms = deadline_ms(g)` is anchored at
  Taira's certified time, which can be ahead of a destination's clock by up to
  `2·max_clock_drift_ms` plus the destination's own lag. Without the slack, a
  pin with `validity = MAX_VALIDITY_MS` could fail the bound. The bound is
  defence in depth: Taira checks `until_ms` exactly (§4.14.3 P1).
- **Deterministic deployment.** The contract is created only through
  `SCCP_EVM_DEPLOYER` (the keyless deterministic-deployment proxy at
  `0x4e59b448…956c`, at the same address on Ethereum and BSC), with salt `0^32`
  and init code `SCCP_EVM_CREATION_CODE ‖ abi.encode(constructor arguments)`.
  The address is then a function of the arguments, and Taira recomputes it
  (§4.14.3 P4). `iroha sccp deployment deploy` refuses any other path. A
  front-runner that deploys the same arguments first produces the identical
  contract at the same address. Before signing, the deploy CLI requires the
  exact 69-byte `SCCP_EVM_DEPLOYER_RUNTIME` from `iroha_sccp::v1::constants`
  on either chain; its Keccak-256 is `SCCP_EVM_DEPLOYER_RUNTIME_HASH`
  (`2fa86add0aed31f33a762c9d88e807c475bd51d0f52bd0955754b2608f7e4989`).
  Rust and the independent EVM model check that pin. Local chain-id 1 and 56
  tests exercise the same proxy runtime; they do not attest the current code
  at a public endpoint. Live deployment performs the exact-code inspection
  against the selected chain before preparing its transaction.

#### 5.2.2 ABI

```solidity
struct TairaCertificateV1 { bytes qc; bytes header; bytes signature; bytes committee; bytes signerYs; }
struct CheckpointRefV1 { bytes header; }
struct BlockRefV1 { uint64 height; bytes32 sccpRoot; uint32 messageCount; uint64 historyIndex; bytes32[] historyPath; }
struct MessageProofV1 { bytes payload; uint32 leafIndex; bytes32[] path; BlockRefV1 block; }
struct ControlProofV1 { uint64 controlNonce; uint8 track; bool parliamentPaused; uint64 fastPauseUntilMs;
                        bytes32 certificateId; bytes32 effectHash; uint32 leafIndex; bytes32[] path; BlockRefV1 block; }
```

`parliamentPaused` is a Solidity `bool`. A calldata word above 1 in that
position is refused by Solidity's ABI decoder with empty revert data, not with
`BadControl()`: `applyControl` and `applyControlFromCheckpoint` read the member
as their first statement, so the refusal precedes every check of the contract,
including the chain check. This is the one row of `control_v1.json`
(`parliament_paused_2`) whose EVM outcome differs from the reference's.

| Selector | Function | Notes |
|---|---|---|
| `0x07a5e706` | `submitCheckpoints(TairaCertificateV1[])` | §5.1.3; at most 16 |
| `0x10efea88` | `finalizeFromTaira(TairaCertificateV1,MessageProofV1) returns (bytes32)` | §5.1.5 |
| `0x55c39595` | `finalizeFromCheckpoint(CheckpointRefV1,MessageProofV1) returns (bytes32)` | §5.1.5 |
| `0x32118e92` | `applyControl(TairaCertificateV1,ControlProofV1)` | §5.1.6 |
| `0x53899b1e` | `applyControlFromCheckpoint(CheckpointRefV1,ControlProofV1)` | §5.1.6 |
| `0x997fcd99` | `voidExpired(uint64,TairaCertificateV1,MessageProofV1)` | §5.1.8 |
| `0xfbeb670e` | `voidExpiredFromCheckpoint(uint64,CheckpointRefV1,MessageProofV1)` | §5.1.8 |
| `0x5b094c00` | `voidFrozen(uint64 firstNonce,uint64 count)` | §5.1.8 |
| `0xebfc6ca8` | `transferToTaira(bytes tairaRecipient,uint256 tokenAmount,uint64 expectedNonce) returns (bytes32 messageId)` | §5.1.7 |
| `0x620ae238` | `committeeState() view returns (bytes32 root, uint64 untilMs, uint64 start, uint64 high, uint64 generation)` | |
| `0x405cf530` | `checkpointHeader(uint64) view returns (bytes32)` | `keccak256(X)` or 0 |
| `0xd7118351` | `pauseState() view returns (bool parliamentPaused, uint64 fastPauseUntilMs, uint64 controlNonce, bool effective)` | the compiled ABI names the third output `controlNonce_` (below) |
| `0xe1a283d6` | `mintingPaused() view returns (bool)` | the effective pause at `block.timestamp` |
| `0x1682dae6` | `consensusInstance() view returns (bytes32)` | |
| `0x86645f61` | `initialCommittee() view returns (uint64 generation, bytes32 root, uint64 start, uint64 untilMs)` | |
| `0x78048149` | `equivocated() view returns (bool)` | |
| `0x5cffa161` | `maxValidityMs() pure returns (uint64)` | the constant `MAX_VALIDITY_MS` |
| `0x95b67034` | `isConsumed(uint64 nonce) view returns (bool)` | |
| `0x4faac8ca` | `controlNonce() view returns (uint64)` | nonce of the last applied control |
| `0xcb58065f` | `opCount() view returns (uint64)` | |

Unchanged views: `transferNonces(address)` (`0xf6f0e8a6`), `tairaNetworkId()`
(`0x6b91d731`), `routeRevision()` (`0x1818891a`) and `maxWrappedSupply()`
(`0xd8bc4dcd`), plus the standard ERC-20 surface (`name`, `symbol`, `decimals`,
`totalSupply`, `balanceOf`, `transfer`, `transferFrom`, `approve`, `allowance`,
`Transfer`, `Approval`). Calldata is the standard Solidity ABI encoding of
these signatures. Selectors are the first four bytes of Keccak-256 over the
canonical signature with tuples expanded, for example
`submitCheckpoints((bytes,bytes,bytes,bytes,bytes)[])` → `0x07a5e706`. None
collides with an ERC-20 selector or with another listed one. Two details of
the compiled ABI JSON change no selector and no encoding: `maxValidityMs()` is
`pure`, because its bound is a compile-time constant (§5.2.1), and the third
output of `pauseState()` is named `controlNonce_`, because Solidity cannot
declare an output named like the `controlNonce()` getter without a warning,
and the artifact corridor fails a build that warns. Removed with the
attestation transport: `finalizeFromTairaHistorical`, `rotateRosters`,
`applyControlHistorical`, `voidExpiredHistorical`, `rosterState`,
`domainSeparator`, `initialRosterDigest`, `initialRosterGeneration` and
`maxRosterValidityMs`, the roster and signature errors (`RosterNotAccepted`,
`BadRoster`, `BadRosterValidity`, `BadSignatures`, `TooFewSignatures`,
`BadRotation`), and, with TRON, the direct-caller rule
(`REQUIRE_DIRECT_CALLER`, `DirectCallerRequired()`).

**Canonical calldata.** `transferToTaira` and `voidFrozen` accept exactly the
encoding Solidity's own encoder produces and revert with
`NonCanonicalCalldata()` (or in Solidity's ABI decoder, with empty revert data)
on every other one: every dynamic offset equals the position where the
canonical encoder puts that value's tail (`0x60` for `tairaRecipient`); every
integer word fits its declared width; the padding after every `bytes` value is
zero; and `msg.data.length` equals the canonical length exactly (`0x44` for
`voidFrozen`). `iroha_sccp::v1::evm_abi` decodes the same set
(`TransferToTairaCallV1`, and `VoidCallV1` restricted to `voidFrozen`, which
also bounds a range to 1..=256 nonces ending at most at `2^64 − 1`), and the
conformance table `calldata_conformance` in
`fixtures/sccp/evm_calldata_v1.json` pins that the contract and the decoder
accept exactly the same entries (§11).

**Events:**

| Event | topic0 |
|---|---|
| `SccpTransferToTaira(bytes32 indexed messageId, address indexed sender, uint64 nonce, bytes payload)` | `0x79ac1cc63262b80bfbf96e55b2d49d96bd82f018ce0192f7002168724c7d264b` |
| `SccpFinalized(bytes32 indexed messageId, uint64 indexed nonce, address indexed recipient, uint256 tokenAmount)` | `0x8ab0eb669cb9abcdf0e37e9ce8443162d317d10c2b059296e40aebbd3fa23748` |
| `SccpVoided(bytes32 indexed messageId, uint64 indexed nonce)` (`messageId = 0` for `voidFrozen`) | `0xfc0fe8523e61c1e6bcbb957a8b692dd0b08e1774c4c4bd897fbc68c047c82fcf` |
| `SccpCommitteeRotated(uint64 indexed generation, bytes32 root, uint64 untilMs, uint64 startHeight)` | `0x6244ff84b5945581521adb818f0b307122dfde790299fb252046603a974d3d3d` |
| `SccpCheckpointed(uint64 indexed height, bytes32 header)` (the value is `keccak256(X)`) | `0xfe0aa9a242fa773b609fa05dac2bc7034ac693373de95b042f61db6c8d218853` |
| `SccpLatched(uint8 indexed reason, uint64 generation, uint64 height, bytes32 a, bytes32 b)` | `0x0567b58957c8b229342697465e6c4c3c6f0f63efb05b97d09469929c47a331f7` |
| `SccpControlApplied(uint64 indexed controlNonce, uint8 track, bool parliamentPaused, uint64 fastPauseUntilMs, bytes32 certificateId)` | `0xb069397cc6f8fa22bf7c0216c554253ab0fc92a3178d10969760b028dd174238` |
| `SccpCertificate(uint64 indexed height, uint64 indexed generation, bytes qc, bytes header, bytes signature)` (every full-path verification, §5.1.3 step 12; `signature` is the 192-byte calldata form of §3.7) | `0xa89e234faf229fd8a8a7add0e9aec37a1986183e842549427a65eb2fb88c116e` |

`SccpTransferToTaira` is the inbound source event consumed by Taira (§4.12.2):
`data = abi.encode(uint64 nonce, bytes payload)` and `topics[2] =
word(sender)`. `SccpVoided` is the void event (§4.16). Mint and burn also emit
ERC-20 `Transfer` from/to `address(0)`. `SccpRosterRotated` is removed.

**Errors.** One shared table maps EVM names to TON exit codes, and the
cross-check harness keys on the names:

| EVM error | TON code | EVM error | TON code |
|---|---|---|---|
| `WrongChain` | 400 | `DeadlinePassed` | 414 |
| `MintingIsPaused` | 401 | `DeadlineNotReached` | 415 |
| `CommitteeNotAccepted` | 402 | `NotFrozen` | 416 |
| `BadCommittee` | 403 | `StaleControl` | 417 |
| `BadCertificate` | 404 | `NotInitialized` / `AlreadyInitialized` | 418 / 419 |
| `BadSignature` | 405 | `BadControl` | 420 |
| `BadHeader` | 406 | `BadNonce(uint64 expected)` (a nonce argument that differs from the payload's or the sender's next nonce; a sender whose source nonces are exhausted, §5.1.7) | 425 (unchanged) |
| `BadProof` / `BadPayload` | 407 / 408 | `NothingToDo` | 428 |
| `SupplyCapExceeded` | 410 | `BadConfig` | 429 |
| `UnknownCheckpoint` | 411 | `Equivocated` | 433 |
| `BadRecipient` / `BadAmount` | 412 / 413 | `LatchRequired` | 434 |
| `TooManyCertificates`, `NonCanonicalCalldata`, `AlreadyConsumed(uint64 nonce)` | EVM only | TEP-74 codes 47–74, 333 | unchanged |

**Reverts with empty data.** Two kinds of EVM revert carry no error of the
table. One is a refusal by Solidity itself: a typed calldata word above its
width, calldata that is too short, an unknown selector, or value sent with a
call (no function is payable). The other is a failed precompile call inside
the commit message or hash-to-G2 (`SHA256`, `MODEXP`, `MAP_FP2_TO_G2`,
`G2ADD`, §5.2.4), which is possible only when the call runs out of gas or on a
chain without the precompile. It is not a verdict on the certificate, and
neither is the answer of a `G1ADD` or `PAIRING_CHECK` call that ran out of
gas, which is the one a refused input gets (`BadCommittee`, `BadSignature`).
A relayer simulates with ample gas before it treats any of these as a
rejection.

`NotInitialized` and `AlreadyInitialized` are TON codes only; the EVM ABI does
not declare them (§5.2.1). TON-only codes keep their current values
(`contracts/ton/sccp/contracts/sccp-errors.tolk`): `BadSnake` 421,
`BucketNotDeployed` 422, `NotMinter` 423, `NotBucket` 424, `BadRange` 426,
`BadBurnPayload` 427, `BucketNotActive` 430 and `NothingToRetry` 431. Code 432
stays unassigned. TON reports an already consumed nonce through the bucket's
`sccp_already_consumed` reply (§5.3.4), not an exit code, so
`AlreadyConsumed` has no TON code.

#### 5.2.3 Storage

```
slot A: bytes32 committeeRoot
slot B: uint64 untilMs | uint64 start | uint64 high | uint64 generation
slot C: uint64 controlNonce | uint64 opCount | uint64 fastPauseUntilMs | bool parliamentPaused | bool equivocated   // 26 bytes
mapping(uint64 ⇒ bytes32) checkpointHeader
mapping(uint256 ⇒ uint256) consumedBitmap;   // word = nonce >> 8, bit = nonce & 255
mapping(address ⇒ uint64) transferNonces
ERC-20: totalSupply, balances, allowances
immutable: TAIRA_NETWORK_ID, CONSENSUS_INSTANCE, NETWORK_TAG, ROUTE_REVISION, MAX_WRAPPED_SUPPLY, the initial pin
```

Slots follow this order from slot 0: A, B and C are slots 0, 1 and 2, the
three mappings are slots 3, 4 and 5, `totalSupply` is slot 6, and the balances
and allowances are slots 7 and 8. Within a packed slot the first-named field
is the low-order one (Solidity declaration order): in slot B `untilMs` is bits
0..63 and `generation` bits 192..255, and in slot C `controlNonce` is bits
0..63, `opCount` 64..127, `fastPauseUntilMs` 128..191, `parliamentPaused` bit
192 and `equivocated` bit 200. The initial pin is the four immutables
`INITIAL_GENERATION`, `INITIAL_COMMITTEE_ROOT`, `INITIAL_START_HEIGHT` and
`INITIAL_UNTIL_MS`, so the runtime code has exactly nine immutables.

#### 5.2.4 BLS implementation (EIP-2537)

Ethereum provides EIP-2537 since Pectra and BSC since BEP-439; both price the
precompiles identically.

- **Precompiles:** `G1ADD 0x0b`, `G2ADD 0x0d`, `PAIRING_CHECK 0x0f`,
  `MAP_FP2_TO_G2 0x11`, `SHA256 0x02`, `MODEXP 0x05`.
- **Gas.** Every precompile call MUST forward `gas()`; hard-coded stipends are
  forbidden, because the contract is immutable and repricings happen. Every
  call checks `success`, the return length and the value.
- **Fail fast.** Precompile errors consume all forwarded gas, so step 6 of
  §5.1.3 MUST run before any precompile: every coordinate and limb is below
  `p`, no signer has the coordinates `(0, 0)`, which the precompiles read as
  the point at infinity, and `σ` is not `0^192`.
- **Hash to G2.** `contracts/evm/sccp/lib/BLS12_381.sol` is written for this
  repository from RFC 9380 and EIP-2537; it is not a copy of a third-party
  file. `hashToG2(bytes32)` is `expand_message_xmd` with SHA-256 and `DST_SIG`
  (§3.8) to four 64-byte values, each reduced mod `p` by `MODEXP` with
  exponent 1, then `MAP_FP2_TO_G2` twice and one `G2ADD`. `Z_pad` and every
  16-byte field padding are written explicitly, so no result depends on prior
  memory contents. A failed or wrong-length precompile call inside it reverts
  with empty data. The library has only internal functions and is compiled
  into the contract. Its audit is part of the EIP-2537 glue audit gate.
- **Point encodings.** Every field element of a precompile input is a 64-byte
  big-endian word whose top 16 bytes are zero: a G1 point is 128 bytes (`x ‖
  y`) and a G2 point is 256 bytes (`x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1`). The contract
  builds them by zero-extending the 48-byte values it holds: each signer's `x`
  and `y`, and the four limbs of the 192-byte calldata signature (§3.7).
- **Pairing input** is 768 bytes, `apk ‖ Q ‖ (−g1) ‖ σ`, and must return 32
  bytes equal to 1.
- **Not used:** BSC's precompile `0x66`. It returns empty on failure, does not
  check key uniqueness, is BSC-specific and removable, and would be a second
  verifier to audit.

#### 5.2.5 Build

The same creation code serves Ethereum and BSC; runtime code differs only in
immutables. Compile with `evmVersion: cancun` (`mcopy`). The build is
reproducible from `scripts/contract_tooling/compiler-lock.json`, and its exact
creation bytes are `SCCP_EVM_CREATION_CODE` (§4.14.3 P4). The EDR suites run
under both the Prague and the Osaka rules (BSC: Pascal or later). Payload parsing reads calldata slices, with
no memory copies of the payload; `transferToTaira` builds the payload in memory
and hashes it once for `payload_hash` and once for `message_id`.

### 5.3 TON (Tolk)

Three contracts: `SccpTairaXorMinter` (TEP-74 Jetton master with the bridge
built in), `SccpTairaXorWallet` (TEP-74 wallet) and `SccpConsumedBucket`
(replay flags). All are in workchain 0.

#### 5.3.1 Minter storage (TL-B) and canonical initial data

```
minter_data#_ initialized:Bool equivocated:Bool total_supply:Coins pending_supply:Coins outbound_nonce:uint64
  op_count:uint64 control_nonce:uint64 parliament_paused:Bool fast_pause_until_ms:uint64 deployed_buckets:uint64
  config:^MinterConfig committee:^CommitteeState checkpoints:^Checkpoints
  recovery:^RecoveryBook = MinterData;                                                     // ≤ 571 data bits, 4 refs
minter_config#_ taira_network_id:bits256 consensus_instance:bits256 route_revision:uint32 max_supply:Coins
  initial:^InitialPin wallet_code:^Cell bucket_code:^Cell = MinterConfig;
initial_pin#_ generation:uint64 root:bits256 start:uint64 until_ms:uint64 = InitialPin;
committee_state#_ root:bits256 until_ms:uint64 start:uint64 high:uint64 generation:uint64 n:uint8 keys:^KeyChunk = CommitteeState;
checkpoints#_ count:uint2 entries:(count × (height:uint64 id:bits256)) = Checkpoints;          // ≤ 962 bits
key_chunk#_ keys:(k × bits384) next:(Maybe ^KeyChunk) = KeyChunk;                             // k = 2, last chunk 1..2
```

- `RecoveryBook` has `next_id:uint64`, `count:uint10`,
  `activated_buckets:uint64` and `operations:(HashmapE 64 ^RecoveryOperation)`.
  Its canonical empty cell is exactly 139 bits with no references: next id 1,
  count 0, activated prefix 0 and an empty dictionary.
- `RecoveryOperation` retains, in order, `stage:uint3 phase:uint2 attempt:uint64
  nonce:uint64 amount:uint96 count:uint10 next_id:uint64 query_id:uint64
  result:uint2 tail:^ConsumeTail`. The dictionary holds at most 512 rows.
  A complete activation batch reserves its rows before the first dispatch.
  Operation ids increase monotonically and never repeat after capacity is freed;
  exhausted operation or attempt counters reject before wrapping.
- `get_jetton_data` builds the TEP-64 content (on-chain name `Taira XOR`,
  symbol `tXOR`, decimals `9`) at run time from constants, so no content cell
  is stored.
- **State size is constant.** There is no tenure dictionary. A rotation
  replaces the `KeyChunk` chain (at most 16 cells), or keeps it at a heartbeat;
  recovery custody has a fixed capacity of 512 operations and no evictable history.

**Canonical initial data** for a deployment pinned to Taira generation `G`:
`initialized = false`, `equivocated = false`, every counter and supply zero,
`parliament_paused = false`, `fast_pause_until_ms = 0`, `deployed_buckets = 0`,
`checkpoints.count = 0` and the exact empty `RecoveryBook`; `config` holds the live
`NetworkId`, `I`, the revision, the cap, the pin and the wallet and bucket
code; `committee` holds the pin with the generation's keys and `high = start −
1`. Taira recomputes the minter address from exactly this data at
`RegisterRoute` (§4.14.3 P3), so the stored committee is bound to the pin by
construction.

**`sccp_init`** (permissionless, once) completes deployment. It requires
`initialized = false`, `GLOBALID = −239`, a valid `n` with keys strictly
ascending (`SDLEXCMP`), the keccak committee root of the stored keys equal to
`committee.root = initial.root`, the remaining committee fields equal to
`initial`, and `now_ms < until_ms ≤ now_ms + MAX_VALIDITY_MS +
MAX_INIT_SLACK_MS` (§5.2.1 explains the slack). It then sets `initialized =
true`. Every other operation throws until then.

#### 5.3.2 Cell formats

```
taira_cert#_ signature:bits768 signers:uint32 qc:^QcFixed x:^XHead = TairaCert;
qc_fixed#_ epoch:uint64 epoch_context:bits256 view:uint64 block_hash:bits256 result_body:bits256 = QcFixed;
x_head#_ bytes:bits872 tail:^XTail = XHead;      x_tail#_ bytes:bits896 = XTail;
checkpoint_ref#_ x:^XHead = CheckpointRef;
block_ref#_ height:uint64 sccp_root:bits256 message_count:uint32 history_index:uint64 path_len:uint8 path:(Maybe ^HashChunk) = BlockRef;
message_proof#_ leaf_index:uint32 path_len:uint8 payload:^SnakeBytes path:(Maybe ^HashChunk) block:^BlockRef = MessageProof;
control_proof#_ control_nonce:uint64 track:uint8 parliament_paused:Bool fast_pause_until_ms:uint64
                certificate_id:bits256 effect_hash:bits256
                leaf_index:uint32 path_len:uint8 path:(Maybe ^HashChunk) block:^BlockRef = ControlProof;   // 690 data bits, ≤ 2 refs
hash_chunk#_ hashes:(k × uint256) next:(Maybe ^HashChunk) = HashChunk;   // k = 3 except the last chunk
```

- Every cell taken from a message MUST be an ordinary cell with the exact bit
  and ref counts above; exotic cells are rejected with `BadSnake`. `XHead.bytes
  ‖ XTail.bytes = X`.
- **`SnakeBytes`** is a standard snake cell. All data bits are bytes, and the
  continuation is the single reference when present. A chunk with a
  continuation holds exactly 127 bytes; the last chunk holds 1..=127 bytes;
  there are no empty chunks and no other references. Contracts reject any other
  shape, and golden BoCs pin it (§11).
- **Chunked lists** (`KeyChunk`, `HashChunk`) are maximally packed except the
  last chunk.

#### 5.3.3 Messages

To the minter (`query_id:uint64 response:MsgAddressInt` follow the op unless
shown otherwise):

| Op | TL-B | Sender |
|---|---|---|
| `0x53434930` | `sccp_init query_id:uint64` | anyone, once |
| `0x53434b31` | `sccp_checkpoint cert:^TairaCert next_keys:(Maybe ^KeyChunk)` | anyone; value ≥ `checkpoint_required_value()`. `next_keys` is required iff a rotation applies with `X.next_committee_root ≠ cur.root` and is hashed against that root (else `BadCommittee`); it is ignored otherwise |
| `0x53434631` / `0x53434632` | `sccp_finalize cert:^TairaCert message:^MessageProof` / `sccp_finalize_checkpoint ref:^CheckpointRef message:^MessageProof` | anyone; value ≥ `finalize_required_value(nonce)` (§5.3.5) |
| `0x53435631` / `0x53435632` | `sccp_void_expired nonce:uint64 cert:^TairaCert message:^MessageProof` / `sccp_void_expired_checkpoint nonce:uint64 ref:^CheckpointRef message:^MessageProof` | anyone; value ≥ `void_required_value(nonce)` |
| `0x53435633` | `sccp_void_frozen first_nonce:uint64 count:uint16` | anyone; value ≥ `void_frozen_required_value(first_nonce)` |
| `0x53434d31` / `0x53434d32` | `sccp_apply_control cert:^TairaCert control:^ControlProof` / `sccp_apply_control_checkpoint ref:^CheckpointRef control:^ControlProof` | anyone (§5.1.6); value ≥ `apply_control_required_value()` |
| `0x53434431` | `sccp_deploy_buckets count:uint8` | anyone; value ≥ `deploy_buckets_required_value(count)` |
| `0x53435931` | `sccp_retry operation_id:uint64` | anyone; value ≥ `retry_required_value()`; throws `NothingToRetry` (431) when no operation is retained |
| `0x7bdd97de` | `burn_notification query_id:uint64 amount:Coins sender:MsgAddress response_destination:MsgAddress sccp:^SccpBurnToTaira` | own wallet |
| `0xd372158c` | `top_up query_id:uint64` | anyone |
| standard | `provide_wallet_address` / TEP-89 | anyone |

`0x53434531` (`sccp_evidence`), `0x53435231` (`sccp_rotate`) and the historical
finalize, void and control ops are deleted.

Internal recovery messages (bounceable; IHR disabled):

| Op | TL-B fields after op | Sender and destination |
|---|---|---|
| `0x53435241` | `operation_id:uint64 stage:uint8 attempt:uint64 nonce:uint64 count:uint16 amount:uint96 query_id:uint64 response:MsgAddressInt` | minter → canonical bucket or wallet |
| `0x53435242` | `operation_id:uint64 stage:uint8 attempt:uint64 query_id:uint64 response:MsgAddressInt` | minter → destination; confirm the retained receipt |
| `0x53435243` | same fields as confirmation | minter → destination; delete the exact receipt |
| `0x53435244` | `operation_id:uint64 stage:uint8 attempt:uint64 result:uint8 query_id:uint64 response:MsgAddressInt` | canonical destination → minter; authenticated ACK |

Stages are activation 1, consume 2, mint 3, unconsume 4 and range 5. Results
are missing 0, applied 1, rejected 2 and deletion confirmed 3. A bucket accepts
activation only for its own index, and the other bucket stages only after
activation. A wallet accepts only mint dispatches from its minter. Ordinary
TEP-74 wallet-to-wallet transfers require the authenticated peer wallet address.
Anyone may top up either child.

```
consume_tail#_ kind:uint1 recipient:MsgAddress response:MsgAddressInt message_id:uint256 = ConsumeTail;
recovery_receipts#_ count:uint10 receipts:(HashmapE 72 RecoveryReceipt) = RecoveryReceipts;
recovery_receipt#_ attempt:uint64 result:uint2 = RecoveryReceipt;
bucket_data#_ minter:MsgAddressInt index:uint64 activated:Bool bits:uint512 recovery:^RecoveryReceipts = BucketData;
wallet_data#_ jetton_balance:Coins owner:MsgAddressInt minter:MsgAddressInt recovery:^RecoveryReceipts = WalletData;
sccp_burn_to_taira#53434254 recipient:^SnakeBytes = SccpBurnToTaira;
```

Each child's receipt key is `(operation_id << 8) | stage`; each retains at most
512 receipts. Canonical child StateInit has an exact empty 11-bit receipt cell
(count 0, empty dictionary); a missing reference is invalid. Bucket StateInit
also has `activated = false` and zero bits. The minter's immutable tail retains
the original response and message id; each in-flight recovery exchange echoes
its own query id and response, so a concurrent caller cannot redirect another
caller's excess by starting a retry.

External-out messages from the minter:

```
sccp_finalized#5343464e message_id:uint256 nonce:uint64 = ExtOut;
sccp_voided#5343564f message_id:uint256 first_nonce:uint64 count:uint16 = ExtOut;   // message_id = 0 for frozen voids
sccp_transfer_to_taira#53435454 message_id:uint256 nonce:uint64 sender:MsgAddressInt
    amount:Coins payload:^SnakeBytes = ExtOut;
sccp_committee_rotated#53435252 generation:uint64 root:bits256 until_ms:uint64 start:uint64 = ExtOut;
sccp_checkpointed#53434b4e height:uint64 id:bits256 = ExtOut;
sccp_latched#53434c54 reason:uint8 generation:uint64 height:uint64 a:bits256 b:bits256 = ExtOut;
sccp_control_applied#5343434e control_nonce:uint64 track:uint8 parliament_paused:Bool fast_pause_until_ms:uint64
    certificate_id:bits256 = ExtOut;
sccp_certificate#53434346 height:uint64 generation:uint64 cert:^TairaCert = ExtOut;   // §5.1.3 step 12
```

`sccp_roster_rotated` is deleted. The new tags collide with no existing op or
event tag. Every external-out message is sent with bounce on action failure
(send mode `+16`): an event that cannot be sent aborts its step's transaction
and bounces the inbound message, so no step completes without its event.

#### 5.3.4 Flows

**Verification binding (pinned).**

1. **Order:** parse, then check the required value (it uses the payload nonce
   and bucket count), then verify, so an underfunded call fails cheaply before
   any signature work.
2. **`m`:** `HASHEXTA` id 0 over byte-aligned builders into an empty builder,
   then `ENDC`, `CTOS`: a slice of exactly 256 bits and no refs.
   `BLS_FASTAGGREGATEVERIFY` hashes the whole message slice. `R` is built the
   same way; the 165-byte `P` spans two builders.
3. **`id`:** `HASHEXT` id 3 (keccak) over the `XHead.bytes` and `XTail.bytes`
   slices (`2 PUSHINT 3 HASHEXT`).
4. **Keys:** `loadBits(384)` slices of exactly 384 bits from the `KeyChunk`s,
   selected by ascending set bits. The signature slice is exactly 768 bits.
   384-bit keys MUST NOT be loaded as integers.
5. **Call:** the minter MUST reject the compressed identity signature, `0xc0`
   followed by 95 zero bytes, with `BadSignature` at §5.1.3 step 6, before the
   checkpoint lookup of the cheap path: `BLS_FASTAGGREGATEVERIFY` does not
   enforce `σ ≠ O`, which §3.8 requires, and the cheap path never calls it. On
   the full path the minter then builds the tuple `t = [k_1 … k_q, q, m, σ]`
   (length `q + 3 ≤ 24`) and runs `asm "DUP" "TLEN" "UNTUPLEVAR"
   "BLS_FASTAGGREGATEVERIFY"` (`TLEN` `0x6F88`, `UNTUPLEVAR` `0x6F82`,
   `BLS_FASTAGGREGATEVERIFY` `0xF93002`).
   `UNTUPLEVAR` consumes `t n`, and `TLEN` supplies `n = q + 3`; an
   implementation MAY push `q + 3` explicitly instead. The resulting stack `k_1
   … k_q q m σ` (σ on top) is exactly the opcode's pop order. Gas is 58 000 + 3
   000·q. The opcode applies `DST_SIG`, and its result is the minter's only
   verdict on the keys, the aggregate and the signature: `false` throws
   `BadSignature`, including for an identity aggregate, which EVM reports as
   `BadCommittee` (§5.1.3 steps 10–11). The minter runs no aggregate step of
   its own. The opcode refuses a signer key that is no canonical point, is the
   identity or lies outside G1, as the reference models read it; a root Taira
   admitted holds no such key (§3.8). The Acton harness
   (`tests/unit/sccp-bls.test.tolk`) pins that the opcode answers `false`, and
   the minter `BadSignature` after the opcode's gas, for a stored signer key
   with the infinity flag (`0xc0…`), without the compression flag, with `x ≥
   p`, with the coordinates `(0, 0)`, on the curve outside G1 (one key with the
   genuine signature, and two keys shifted by `T` and `−T` whose sum is the
   genuine aggregate), and for keys that sum to the identity; the opcode also
   answers `false` for the identity key alone under the identity signature.
   Both reference generators record `BadSignature` as `expected.ton` for
   those shared negative and flavour-specific certificate rows. The harness
   also pins the stack shape and the opcode gas at n = 4, 7 and 31.
6. **Latch:** commit state, emit `sccp_latched`, and return the excess value to
   `response` with no throw. A mint in flight whose consume completion
   arrives after the latch is not minted: the minter dispatches a retained
   unconsume operation and releases `pending_supply`, and the nonce stays voidable
   through `voidFrozen`. Expiry alone does not cancel an in-flight mint.
   Exit codes: an `sccp_checkpoint` that finds V1–V3 persists the latch and
   throws nothing, neither 433 nor 434. An inline entry point that finds V1–V3
   throws `LatchRequired` (434) and changes nothing. Once the latch is set,
   every entry point that requires `Live` (`sccp_checkpoint`, `sccp_finalize*`,
   `sccp_void_expired*` and `sccp_apply_control*`) throws `Equivocated` (433)
   at its `Live` check (§5.1.2); an expired minter without a latch throws
   `CommitteeNotAccepted` (402) there, and so does a `*_checkpoint` message on
   a `Live` minter whose stored header is neither U1 nor U2 (§5.1.3). No other
   message throws 433: the bucket replies of a mint in flight follow the
   unconsume flow above.
7. **Sends:** event sends use `SEND_MODE_REGULAR |
   SEND_MODE_BOUNCE_ON_ACTION_FAIL`; burns never pay toward the floor (§5.3.5).
   Failing messages throw and bounce their value.

**Finalize (Taira→TON).**

1. **Admission.** Require initialization and TON mainnet. Parse the payload,
   recipient and amount (`amount < 2^96`); determine the bounded deployment
   count and require an active bucket or a new contiguous activation batch.
   Admit capacity for every activation plus the consume before verification or
   storage mutation. Check attached value including the floor deficit before
   signatures, then authenticate `X`, `Live`, pause, block reference, deadline
   and leaf path in the specified order. Check `total_supply + pending_supply
   + amount ≤ max_supply`, reserve pending supply and retain the immutable row.
2. **Activation.** A finalize/void can reserve up to four new buckets; an
   explicit `sccp_deploy_buckets` call can reserve 1..16. `deployed_buckets`
   advances when the whole chain is reserved. `activated_buckets` advances
   only after each successful activation's receipt deletion is acknowledged.
   Dispatch one activation at a time, then the consume. Active buckets remain
   usable while a chain is in flight; further extension waits for that chain.
   Only activation carries bucket StateInit. A deleted bucket recreated from
   StateInit is inactive and cannot replay a formerly consumed nonce.
3. **Destination effect.** Authenticate the minter and the exact operation,
   stage and attempt. Before a new effect, require receipt capacity and the
   funded maximum-state floor. Atomically apply the effect and retain its
   result receipt. A consumed bit produces `rejected`, without changing the
   bit. An identical already-receipted dispatch only repeats its ACK.
4. **Receipt completion.** The minter authenticates the canonical destination
   and exact operation/stage/attempt. An applied/rejected ACK changes its row
   from `WAIT` to `DROP`, retaining the result, and sends receipt deletion.
   Only authenticated deletion confirmation advances or releases the row.
   A consume rejection releases its pending amount. An applied mint consume
   releases pending supply, reserves the amount in total supply, and changes
   the same reserved row to wallet mint.
   If equivocation latched before this point, change it to unconsume instead.
   Only authenticated wallet receipt deletion completion increments `op_count`,
   emits `sccp_finalized` and releases the slot. Thus Finalized proofs attest an
   actual wallet credit, never a tentative dispatch that can still bounce.
   Expiry alone does not
   cancel an already admitted operation.
5. **Authenticated original failure.** The first 168 body bits bind a bounced
   dispatch to operation id, stage and attempt. Exact sender and `WAIT` phase
   are mandatory. A consume/range failure frees its row (and mint pending
   supply). A failed wallet mint removes its unminted total supply and changes
   the existing row to `FAILED` unconsume. Activation/unconsume failure keeps
   that row `FAILED`. These handlers send no new messages and allocate no new
   rows, so a low-value bounce cannot lose the recovery instruction.
   `op_count` stays monotone and saturates at `2^64 − 1`.

**Retry.** Anyone can fund `sccp_retry{operation_id}`. A `FAILED` row alone may
advance its attempt and dispatch the original action again. A `WAIT` row sends
confirmation; a `DROP` row repeats exact receipt deletion. A queued activation
cannot be retried before its predecessor. Prepared/Drop ACK loss never clears
a bit, releases pending supply or blindly repeats a mint. Destination deletion
is idempotent, and stale operation/stage/attempt messages cannot touch a newer
receipt or a reused capacity slot. Missing receipt is observational only: it
cannot prove original failure after possible destination deletion/recreation,
so it retains the row without reminting or clearing a replay flag.

TON validates same-source/destination order with IHR disabled (whitepaper
§§2.2.9–2.2.11; `ValidateQuery::check_message_processing_order`, including
emitted logical times and deferred queues). The pinned compiler's message
header is tested with `ihr_disabled = true`. Monetary safety also holds for
confirmation before a delayed original: absence never authorizes replay, and
stages advance only on positive authenticated completion or original failure.

**Void (TON).** Expired voids use the same retained consume flow with kind void,
no pause/cap/pending-supply check and `now_ms > deadline_ms`; the supplied nonce
must equal the payload nonce. Frozen voids require `Frozen` and 1..512 nonces
inside one bucket, use the same activation reservation and dispatch range.
The bucket sets the whole range iff all its bits are clear. After receipt
deletion confirmation an applied result emits one `sccp_voided(0, first,
count)` and increments `op_count`; a rejection changes neither. ACK loss keeps
the flags and result available for permissionless recovery.

**Burn (TON→Taira).**

1. The owner sends TEP-74 `burn#595f07bc query_id amount response_destination
   custom_payload` to its wallet with `custom_payload = sccp_burn_to_taira`.
2. Before debiting or forwarding, the wallet requires the custom payload and
   opens it as an ordinary cell containing exactly 32 bits (opcode
   `0x53434254`) and one reference. A missing payload or wrong opcode is
   `BadBurnPayload`; an exotic wrapper or any extra/missing bits or references
   is `BadSnake`. It traverses the **entire** referenced recipient as ordinary
   canonical `SnakeBytes` (§5.3.2): 127 bytes in every nonterminal chunk,
   1..=127 bytes in the final chunk, exactly one continuation reference when
   present and no extra bits or references. The total MUST be 1..=1024 bytes;
   an oversized recipient is `BadRecipient`, and an empty, noncanonical or
   exotic snake is `BadSnake`. Only after these checks and the required-value
   check does the wallet debit and send the extended `burn_notification`.
   This admission bound makes the maximal notification size priced by
   `burn_required_value()` a real upper bound on the forwarded body.
3. The minter verifies the wallet address; requires the owner to be `addr_std`
   in workchain 0 without anycast; repeats the same ordinary, exact wrapper
   and full canonical 1..=1024-byte recipient checks;
   applies `total_supply −= amount` and `nonce = outbound_nonce++`; builds the
   payload (`sender_codec 7` = owner) and computes `message_id`; sets `op_count
   += 1`; reserves only its prior balance (a burn never pays toward
   `MINTER_FLOOR`, §5.3.5); emits `sccp_transfer_to_taira`; and returns the
   excess to `response_destination`.

Any failure, including an event that cannot be sent, aborts the minter's
transaction, and the standard bounce of `burn_notification` restores the wallet
balance.

**Checkpoint and apply control.** These follow §5.1.2–§5.1.3 and §5.1.6 with
keys read from storage, after the entry value check of §5.3.5. A key-changing
rotation hashes `next_keys` against `X.next_committee_root` and replaces the
`KeyChunk` chain; a heartbeat keeps it. The control leaf uses
`lane_bytes(sora-taira, ton-mainnet)` with the stored `taira_network_id`
(target tag `0x44`, identity word `int256(−239)`), `destination_word` = the
minter account id, and the own `route_revision`, hashed in the two builders of
§3.4. An applied control sets `parliament_paused`, `fast_pause_until_ms` and
`control_nonce`, increments `op_count` and emits `sccp_control_applied`. Excess
value returns to `response`.

#### 5.3.5 Value, fees and storage rent

- **Step values.** The required value of each minter entry (checkpoint,
  finalize, void, `void_frozen`, `deploy_buckets`, `apply_control`, `retry`) is
  computed at entry with `GETGASFEE` (per-step gas limits pinned from measured
  maxima), `GETFORWARDFEE` (per-message sizes, including the bucket and wallet
  StateInit and the `sccp_certificate` message) and `GETSTORAGEFEE` (the bucket
  floor and wallet storage). There is no fixed TON constant. A price increase
  between asynchronous steps can fail a delivery; retained custody permits a
  newly funded retry without repeating an effect whose outcome is unknown.
- **Minter floor.** `MINTER_FLOOR` = `GETSTORAGEFEE` for the minter's maximal
  cells and bits over 100 years. Every entry requires `msg_value ≥ step +
  max(0, MINTER_FLOOR − stored)`, where `stored` is the balance before the
  transaction's storage phase (`BALANCE − msg_value + STORAGEFEES`), checked
  before any signature. It then reserves (`raw_reserve`, mode 2)
  `min(max(MINTER_FLOOR, before), before + msg_value − step)`, where `before`
  is the balance after the storage phase: the floor is topped up from the
  caller's value, but never from the part the step needs. Storage the caller
  did not pay for stays a deficit for the next caller. Anyone may add to the
  floor with `top_up`.
- **Burns and replies.** Burns and recovery ACKs reserve the minter's prior
  balance rather than charging its floor deficit. Original-bounce handlers
  update existing custody without sending or allocating. Their bounded gas is
  paid from the minter balance when the bounce carries little value.
- **Quotes.** The `*_required_value` get methods return `step + max(0,
  MINTER_FLOOR − balance) + grace`, where a get method's balance is exactly
  `stored`, so a quote does not go stale as time passes. `grace` is
  `GETSTORAGEFEE` of the maximal minter for 7 days. It covers storage that
  other minter transactions collect between the quote and the send; beyond it,
  the call fails `NotEnoughValue` before any signature and bounces. Every
  unused nanoton returns to `response`. Clients add a margin on top.
- **Child custody floors.** Before dispatch, attached value covers 100 years
  of each destination's maximum 512-receipt state at current prices; activation,
  consume and minted-wallet delivery require and reserve that floor. Ordinary
  peer wallet deployment retains the separate five-year minimum. The maximum
  minter (512 operations) is bounded by 2,380 cells/790,000 bits; each bucket
  by 1,080 cells/83,000 bits and wallet by 1,080 cells/86,000 bits. Native maximum
  fixtures cover those graphs with at most 5% headroom. No eviction discards
  recovery. Repeated lost responses consume capacity until funded recovery
  completes; full capacity rejects before another irreversible dispatch.
- **Buckets are never reset.** A bucket deleted for unpaid rent (practically
  excluded by the floor) makes its nonces unfinalizable and unvoidable until
  someone unfreezes it with its exact public state. Anyone can redeploy its
  canonical `StateInit`, but that bucket is not activated and accepts nothing
  (§5.3.4 step 2), so already-minted nonces never become voidable.
- **Duplicate finalizes.** Parallel duplicate finalizes of one message each
  reserve `pending_supply` until the bucket rejects them. Near the cap this can
  delay honest mints by one round trip; this is accepted.

#### 5.3.6 Get methods

- `get_jetton_data` and `get_wallet_address(owner)` (TEP-74).
- `get_sccp_state()` returns `(initialized, equivocated, taira_network_id,
  consensus_instance, route_revision, initial pin…, root, until_ms, start,
  high, generation, outbound_nonce, op_count, parliament_paused,
  fast_pause_until_ms, effective_paused, control_nonce, total_supply,
  pending_supply, max_supply, deployed_buckets)`.
- `get_sccp_committee()`, `get_sccp_checkpoints()` and
  `get_bucket_address(index)`.
- Quotes (§5.3.5): `checkpoint_required_value()`,
  `finalize_required_value(nonce)`, `void_required_value(nonce)`,
  `void_frozen_required_value(first_nonce)` (the nonce selects how many buckets
  the call activates), `deploy_buckets_required_value(count)`,
  `apply_control_required_value()` and `retry_required_value()`;
  `minter_floor()` returns `MINTER_FLOOR` at current prices;
  `get_sccp_recovery(operation_id)` returns the retained operation cell or null;
  `get_sccp_recovery_state()` returns `(count, next_id, activated_buckets)`.
- Buckets: `get_bucket_data() → (minter, index, activated, bits_hi, bits_lo)`,
  `get_bits()`, `is_consumed(nonce)` and `is_activated()`.

Consumption of a nonce is read from the bucket's account state (`bits`) or its
`get_bits` method. A bucket index ≥ `deployed_buckets` means nothing in it is
consumed. `get_sccp_members`, `get_sccp_tenure` and `rotate_required_value` are
deleted.

#### 5.3.7 Tolk notes

Tolk 1.4.2 has no BLS or keccak builtins, so the contracts declare asm wrappers
for `BLS_FASTAGGREGATEVERIFY` (with the `DUP TLEN UNTUPLEVAR` prefix of
§5.3.4), `HASHEXT` id 0 (SHA-256) and id 3 (keccak256) over builders and
slices, and `GETGASFEE`, `GETFORWARDFEE` and `GETSTORAGEFEE`. TON's BLS opcodes
have been live on mainnet since 2023. The `ECRECOVER` helpers
(`sccp-crypto.tolk`) and roster verification (`sccp-verify.tolk`) are deleted.

### 5.4 Cost estimates

`n = 4` is Taira today and `n = 31` is the protocol maximum. The EVM and the
TON values are measurements. Tests MUST record measured values (§11). The TON
baseline is `contracts/ton/sccp/gas-baseline.json`: the builder
(`scripts/ton_sccp_builder.py test`) fails when a step exceeds its gas limit
or 1.1 × its baseline row, and when a row is missing from the baseline or
from a complete run. The EVM baseline is
`contracts/evm/sccp/test/gas_baseline_v1.json` (hardfork → row → profile, with
`n = 7` as well), and the EVM table below lists its values. The gas suite
(`contracts/evm/sccp/test/sccp_gas.test.js`) measures every row under two
hardforks, Prague and Osaka, and fails when a measurement is outside
0.9..1.1 × its baseline: above 1.1 × is a regression, and below 0.9 × is a
stale baseline that would hide a later one. A row that is missing from the
baseline or from the run fails too.

**EVM (measured on the locked EDR runtime under the Prague and the Osaka
rules; BSC prices the precompiles identically).** A cell reads Prague / Osaka,
or one value when both agree. Values are the gas used by the whole transaction
under the Ethereum profile; the BSC profile differs by at most 70 gas, from
calldata bytes. The certificate core is hash-to-G2 (54 036 / 55 236), the
pairing (103 124) and one `G1ADD` per signer (591 each with its call
overhead), plus encoding checks, parsing, hashing and memory. The `MODEXP`
repricing of EIP-7883 (Osaka) raises each of the four field reductions of
hash-to-G2 from 200 to 500 gas, so every full-path certificate costs exactly
1 200 gas more under Osaka and nothing else differs. The `submitCheckpoints`
calldata of one certificate is 1 316 bytes at `n = 4` (35 096 intrinsic gas)
and 3 492 bytes at `n = 31` (69 696). The EIP-7623 floor binds on one measured
row only: an inline `finalizeFromTaira` on the cheap path at `n = 31` (155 110).

| Operation | n = 4 | n = 31 |
|---|---|---|
| `submitCheckpoints`, 1 certificate (checkpoint SSTORE, `high`) | 253 265 / 254 465 | 316 706 / 317 906 |
| … with rotation (root and slot B) | heartbeat (slot B) 256 908 / 258 108; key change (root and slot B) 259 660 / 260 860 | heartbeat 320 337 / 321 537; key change 323 149 / 324 349 |
| … each extra certificate | 221 999 / 223 199 (16 = 3 583 256 / 3 602 456) | 285 735 / 286 935 (16 = 4 602 731 / 4 621 931, below the EIP-7825 cap of 2^24) |
| `finalizeFromCheckpoint` / `voidExpiredFromCheckpoint` / `applyControlFromCheckpoint` | 71 400–148 843 / 58 374–118 642 / 51 196–94 377 | same |
| `finalizeFromTaira` inline | 288 866–356 192 / 290 066–357 392; cheap path 92 578 | 352 284–419 646 / 353 484–420 846; cheap path 155 110 |
| `applyControl` inline | 267 508 / 268 708 | 330 986 / 332 186 |
| `voidFrozen`, 256 nonces | 450 206 in one bitmap word, 472 836 across two (1 nonce: 54 458; ≈ 1.55k per further nonce) | same |
| `transferToTaira` | 51 558–75 829 | same |

- The ranges are the measured cases of each row. `*FromCheckpoint`: the low
  end is a 1-leaf block, and the high end a 512-leaf block proved through a
  32-sibling history path; for a finalization the low end also has an
  existing balance and a used bitmap word (139 788 as the destination's first
  operation, which also initializes the balance, the bitmap word and slot C).
  `finalizeFromTaira` inline: an existing balance and a used bitmap word, up to
  the first operation. `transferToTaira`: a later burn with a 34-byte
  recipient (68 646 for a sender's first burn), up to a 1 024-byte recipient.
- An inline `voidExpired` costs 274 694 / 275 894 at `n = 4` and 338 172 /
  339 372 at `n = 31`. Sixteen key-changing rotations in one call cost
  3 641 232 / 3 660 432 at `n = 4` and 4 660 695 / 4 679 895 at `n = 31`.
  Deployment through `SCCP_EVM_DEPLOYER` costs 3 811 293.
- One checkpoint serves every proof at or below its height while the
  destination is `Live` and the checkpoint is usable (§5.1.3, U1 and U2).
  After a rotation, the handoff that installed the current generation serves
  the proofs of every earlier height.
- Upkeep is one rotation per heartbeat (default once a day, 256 908 / 258 108
  gas at `n = 4`) plus one per key-set change (at most 24 a day with the
  defaults; at most 48 rotations a day at the 1 h minima, §4.2.2).
- `SccpCertificate` costs 7 388 gas on every full-path verification (LOG3 with
  736 bytes of ABI data at every `n`); the cheap path emits nothing.
- `voidFrozen` costs more per nonce than a bitmap update alone because every
  nonce emits its own `SccpVoided(0, nonce)`.
- Under the scheduled Glamsterdam repricing (EIP-7976: a 64 gas per calldata
  byte floor; EIP-8037: ≈ 98k per new slot), calldata-heavy inline calls become
  floor-bound; the checkpoint path and the bitmap consumed set keep
  finalization robust to it.

**TON (Acton 1.2.0 emulator).** `contracts/ton/sccp/gas-baseline.json` pins
named gas measurements for committees of 4, 7 and 31, maximal certificate and
payload paths, ordinary wallet operations and each recovery stage. The native
suite separately measures inserts and acknowledgements with all 512 retained
rows/receipts. Every measurement is checked against the corresponding limit
used by the current-price required-value calculation. Recovery transitions
have an 80,000-gas bound, including the 63-fork dictionary path; deployment admission for 16 buckets has an 800,000-gas
bound. Certificate-step bounds are 250,000/550,000/535,000/260,000 for
checkpoint/finalize/void/control. These are compute bounds, not fixed TON fees.

The minter graph includes 31 keys, all three checkpoint slots, full-width
scalars, 512 distinct operation rows and immutable tails; destination fixtures
include 512 distinct receipts. The fixed admission caps turn those measured
maximum graphs into enforceable custody bounds. Ten thousand rotations retain
the same layout. StateInit hashes and Rust/Python cell mirrors change in lockstep
with compiled code and the mandatory empty recovery references.

A certificate is 4 cells; a key-changing rotation adds at most 16. Stack depth
is at most `q + 3`. The `sccp_certificate` external message re-references the
certificate cells and adds one forward fee.

### 5.5 Toolchains and reproducible artifacts

| Target | Compiler | Settings |
|---|---|---|
| ETH, BSC | solc `0.8.31+commit.fd3a2265` (universal macOS arm64/x86-64, linux-amd64, linux-arm64) | `evmVersion: "cancun"`, `optimizer: {enabled: true, runs: 200}`, `viaIR: false`, `metadata.bytecodeHash: "none"`, `metadata.appendCBOR: false` |
| TON | Acton 1.2.0 bundling Tolk 1.4.2 (`acton-aarch64-apple-darwin`, linux builds) | fixed optimization; code cell hashes and depths locked |

- `scripts/contract_tooling/compiler-lock.json` pins the URLs and sha256 of
  the solc binaries. `contract_artifact_corridor.py` builds, locks and verifies
  artifacts, including each contract's creation code
  (`SCCP_EVM_CREATION_CODE`), runtime template and `immutableReferences`. No
  Rosetta or Docker is needed on macOS arm64.
- `evmVersion: cancun` must be explicit because the compiler defaults to
  `osaka`. The legacy pipeline avoids the via-IR-only 0.8.31 bugs. The source
  MUST NOT `delete` memory `bytes` elements or use custom storage layouts
  (0.8.31 legacy-pipeline bug patterns).
- The EVM lock lists exactly two sources, `SccpTairaXor.sol` and
  `lib/BLS12_381.sol`, and `scripts/contract_tooling/artifact-lock.json`
  records the creation code built from them. The EDR suites run that locked
  build under both the Prague and the Osaka rules
  (`scripts/sccp_evm_contract_smoke.sh`).
- The TON toolchain is pinned outside `compiler-lock.json`:
  `contracts/ton/sccp/Acton.toml` pins `acton = "1.2.0"` (PascalCase wrapper
  names), and `scripts/ton_sccp_builder.py` pins the Acton version
  (`ACTON_VERSION`, with the exact reported version line), the SHA-256 of the
  release archive of each host (`ACTON_ARCHIVES`) and the bundled Tolk version
  (`TOLK_VERSION`), which it checks against the project stdlib after a build.
  `fixtures/sccp/ton_stateinit_v1.json` locks the code cell hashes and depths
  and records both versions; `scripts/sccp_ton_contract_build.sh` fails on any
  drift. `acton simulator` provides local end-to-end emulation.

## 6. Torii read API (served by every Taira peer from state)

All routes are public GETs (`public_sccp_get` descriptors), JSON or Norito by
`Accept`, and derived only from committed state and the node's own Kura. Every
honest peer therefore returns identical bytes for state-derived content, and
wallets may cross-check peers. Wallets never trust these bytes: certificates,
proofs and digests are verified locally (§7).

Errors are `{code, message}` JSON: `400 sccp_invalid_query`, `404
sccp_not_found`, `410 sccp_pruned` (the data existed but retention removed it,
§4.11, §4.13.1) and `410 sccp_rotation_pruned` (below). A node that cannot acquire or verify its
original native certificate custody returns `503 sccp_unavailable`; it never
substitutes an attestation or reports a local resource refusal as a bad query.
A message or control
proof is available as soon as its record height commits; there is no
attestation wait. Immutable responses (proof bundles of an explicit height,
history paths of an explicit `size`, certificates of an explicit height, and
final message states: refunded, stranded, released, bounced) carry a strong
`ETag` over the negotiated representation with `Cache-Control: public,
no-cache`, and a matching `If-None-Match` answers `304`. Paged routes return
the cursor of the next page (`next_from_nonce`, `next_after_nonce`,
`next_before`). The wire types are `iroha_sccp::api` and
`iroha_data_model::sccp::finality` (§8).

**Types** (Taira-internal Norito types; their contract-visible parts are the
fixed byte layouts of §3):

```
SccpCertificateV1 { height: u64, qc: [u8; 116], aggregate_signature: [u8; 96], header: [u8; 221], committee: Vec<[u8; 48]> }
SccpGenerationV1  { generation, committee_root, cause, start_height, start_timestamp_ms, start_lc, validity_ms, deadline_ms,
                    grace_ms, progress_cap_ms, liable_until_lc, dest_cleared_lc, liable: bool,
                    end: Option<{ end_height, end_timestamp_ms, next_committee_root, successor_validity_ms }>,
                    keys: Vec<[u8; 48]>, members: Vec<Option<{ lane_id, validator, activation_height }>> }
SccpBlockRefV1 { height, sccp_root, message_count, history_index, history_path: Vec<[u8; 32]> }
SccpMessageProofBundleV1 { message_id, payload, deadline_ms, leaf_index, path, block: SccpBlockRefV1, certificate: SccpCertificateV1 }
SccpControlProofBundleV1 { network, revision, control_nonce, track, parliament_paused, fast_pause_until_ms,
                           certificate_id, effect_hash, leaf_index, path, block, certificate }
SccpRotationV1 { certificate: SccpCertificateV1 /* ROTATION */, next_committee: Vec<[u8; 48]> }
SccpAnchorWitnessBundleV1 { height, chunk, witness: Option<SccpAnchorWitnessV1> /* None in the open chunk or at the tip */ }
SccpForgeryEvidenceStatusV1 { evidence_id, generation, height, rule, offenders, penalty_status, recorded_at_height }
SccpForgeryHoldViewV1 { max_generation: Option<u64>,
                        revisions: Vec<{ network, revision, forgery_floor, held: bool, quarantine: Option<SccpQuarantineV1>,
                                         reconciliation: Option<SccpReconciliationStateV1> /* scalar phase/accounting per §4.10; no proof-id history */ }>,
                        next: Option<{ network, revision }> /* exclusive cursor; at most 64 rows */ }
SccpFastPauseViewV1 { panel: Option<SccpPausePanelV1>,
                      seats: Option<{ primary: Vec<AccountId>, backup: Vec<AccountId> }>, eligibility_available: bool,
                      rounds: Vec<{ network, role, round: SccpFastPauseRoundV1 }>,
                      active: Vec<{ network, pause: SccpFastPauseV1 }>, suspended: Vec<{ network, until_ms: u64 }> }
```

The fast-pause view retains the original draw and records even when Parliament
eligibility is unavailable. In that case `seats` is null and
`eligibility_available` is false. It returns at most six rounds, three pause
records and three suspension deadlines; expired records remain distinguishable
by their deadlines. Anchor witnesses reconstruct a closed chunk from the
original Kura certificate custody and check its retained root. Both routes use
the admitted request allocation budget and deadline through encoding, reject
query parameters and return `Cache-Control: no-store`.

Registry, governance, message and light-client metadata use the same admitted
request owner. Response row backing is reserved from that request's pool before
allocation; nested account, proposal and payload graphs are borrowed from the
captured view, and retained validator-set bytes share their original charged
owner. Source scans check the request deadline and cancellation flag. Encoding
retains both source custody and the response reservation, and publication
retains the admitted transport owner. Insufficient local capacity is a retryable
service refusal, never an empty list or a claim that source data was pruned.

| Route | Path | Content |
|---|---|---|
| `sccp.capabilities` | `GET /v1/sccp/capabilities` | `{network_id, chain_id, consensus_instance, finality constants (X layout id, DST_SIG, RESULT_TAG, RESULT_BODY_TAG), parameters, committed_height, current_generation (with its deadline), liability_clock, coalition_slashable_floor (§9.11), the forgery-hold summary, the seated panel ids, the launch-gate state (§10.2), profiles (the newest compiled light-client profile of each network with supported_until_ms), profiles_policy_hash (commitment to the versions active at the next block, the SCCP input of the confidential policy digest, §4.13.2), light_client_profiles[{network, version, profile_hash, activation_height, proposal_id, supported_until_ms}] (active at the next block), path templates, limits (page sizes)}` |
| `sccp.registry` | `GET /v1/sccp/registry` | routes, escrow, `stranded`, revisions, deployments, initial committee pin, activation, `destination_frozen`, `destination_paused`, `next_control_nonce`, liability, cap, `next_outbound_nonce`, `forgery_floor`, quarantine, and each network's active fast pause |
| `sccp.messages.recent` | `GET /v1/sccp/messages/recent?direction=outbound\|inbound&network&before&limit≤50` | records of one direction (default outbound), newest first: outbound by `(height, commitment_index)` with their state, inbound by `(proven_at_height, message_id)`; `next_before` is `<height>:<index>` or `<height>:<message id hex>`. The inbound listing scans every inbound record until state indexes them by height |
| `sccp.message.status` | `GET /v1/sccp/messages/{message_id}` | `SccpMessageStatusV1`: `outbound{record, state}` with state `recorded{deadline_ms, provable}\|voided\|refunded\|stranded` (`provable` once the record height is committed), `inbound{record}` whose status is `pending{reason}\|released\|bounced{bounce_message_id}`, or `unknown` (no record: a burn not proven yet) |
| `sccp.message.proof` | `GET /v1/sccp/messages/{message_id}/proof?at=record\|latest\|<H>` | `SccpMessageProofBundleV1`: payload, `deadline_ms`, leaf index, path, the block reference (with a history path when `H` is above the record height) and the certificate of `H`. `at=record` uses the record height; `latest` the durable tip. Immutable per explicit `H` (ETag) |
| `sccp.outbound.by_nonce` | `GET /v1/sccp/outbound/{network}/{revision}?from_nonce&limit≤256` | `next_outbound_nonce` and the records from `from_nonce`, ascending, with state and deadline (finding a just-recorded transfer, void and refund planning) |
| `sccp.controls` | `GET /v1/sccp/controls/{network}/{revision}?after_nonce&limit≤64` | `next_control_nonce` and the control records (§4.14.6) above `after_nonce`: nonce, track, full pause state, certificate id, effect hash, height, commitment index and `provable` from the original committed native tip |
| `sccp.control.proof` | `GET /v1/sccp/controls/{network}/{revision}/{control_nonce}/proof?at=record\|latest\|<H>` | `SccpControlProofBundleV1`, ready for one `applyControl*` or `sccp_apply_control*`. Immutable per explicit `H` (ETag) |
| `sccp.history.proof` | `GET /v1/sccp/history/{height}?size=S` | the block's history leaf index, `history_root(S)` and the path within it (`S` defaults to the current size; an explicit `S` is immutable, ETag). Served in `O(log n)`: Torii caches the roots of complete perfect subtrees, validated against the stored peaks before each use, and hashes only subtrees below 32 leaves |
| `sccp.finality` | `GET /v1/sccp/finality/{height}`, `/latest` | `SccpCertificateV1` of that height |
| `sccp.committees` | `GET /v1/sccp/committees/current`, `/{generation}` | `SccpGenerationV1`, including `liable` |
| `sccp.committees.rotations` | `GET /v1/sccp/committees/rotations?after_generation=G&limit≤16` | the ordered `[SccpRotationV1]` catch-up chain, ready for one `submitCheckpoints` call; `410 sccp_rotation_pruned` beyond retention |
| `sccp.evidence` | `GET /v1/sccp/evidence?after=&limit=`, `/evidence/{evidence_id}` | `SccpForgeryEvidencePageV1` (default/max 64, exclusive raw evidence-id cursor) or exact `SccpForgeryEvidenceStatusV1`: original id, generation, claimed height, E1–E4 rule, retained offenders, penalty status and recorded height. Pages borrow the original evidence graph and reserve row backing from the admitted request before allocation; encoding retains that charge and observes cancellation/deadline. Both routes are `no-store`. |
| `sccp.evidence.anchor` | `GET /v1/sccp/evidence/anchor/{height}` | `SccpAnchorWitnessBundleV1`, built from the node's Kura (below) |
| `sccp.forgery_hold` | `GET /v1/sccp/forgery-hold?network=&revision=&after_network=&after_revision=&limit=` | `SccpForgeryHoldViewV1`: lexicographic `(network, revision)` pages, default/max 64 rows. `revision` requires `network`; both exclusive cursor fields are required together. The original admitted request funds row backing and encoding, retains the authenticated committed source and observes its deadline/cancellation. |
| `sccp.fast_pause` | `GET /v1/sccp/fast-pause` | `SccpFastPauseViewV1` |
| `sccp.light_clients` | `GET /v1/sccp/light-clients`, `/{network}`, `/{network}/sets`, `/{network}/checkpoints?covering=N` | the stored light clients; per network the record (params, head, freeze, `state_hash`), `usable` at the committed block time, weak-subjectivity deadline, `supported_until` of the active profile version (§4.13.2), the latest finalized source time (the L5 input, §4.8) and set/checkpoint summaries; the stored sets; for `covering=N` the nearest retained checkpoint ≥ N (the ancestry anchor) and the nearest permanent one, 404 while the head is below N and 410 when the head covers N but no checkpoint ≥ N is retained. Target: claim windows (§4.13.5) |
| `sccp.governance` | `GET /v1/sccp/governance`, `/proposals?status&after`, `/proposals/{proposal_id}`, `/readiness` | Revisions per subject; open proposals oldest first with full body, subjects, base revisions, current preflight and newest attempt; detail in every phase with each retained attempt's original frozen expected head, stage/status and terminal outcome. `parameters_before` and the ordered proposal actions expose exact parameter comparisons. `activation_diff` lists requested activation changes against current committed state, resolving pause targets through preceding intents without predicting enactment success. Readiness exposes `[gov]` body sizes, the original active beacon session and exact ordered current-roster match, both launch legs (§10.2), qualified latency and every active/certified SCCP attempt. Until the Parliament owner supplies eligibility and next-due observations, `eligible_citizens` and due coordinates are null and `due_available` is false; unavailable never means zero or no work. |

Removed with the attestation transport: `/v1/sccp/rosters/*`,
`/v1/sccp/attestations/*` and `/v1/sccp/bridge-keys`. `/v1/bridge/finality/*`
(`specs/bridge_finality.md`) is unchanged, and its proofs carry `X ‖ body` as
the result preimage.

**Building bundles.**

1. Read the certified `SignedBlockWire` of height `H`. Its `CommitCertificate`
   gives the core header, the `CommitQC` and `X ‖ body`; anyone gets the same
   bytes from `GET /v1/bridge/finality/{H}`.
2. Build `qc` per §3.7, and take `header = result_preimage[0..221]`.
   `committee` is the keys of `sccp_committee_generations[X.generation]`, which
   equal the keys of the committee that the certified schedule assigns to `H`.
3. Leaf paths come from the `SccpMessageRecorded` and `SccpControlRecorded`
   events, in `commitment_index` order. History leaves come from
   `SccpBlockCommitted`.
4. A checkpoint reference is the 221-byte `X` alone.
5. Torii MUST verify every bundle it serves with
   `iroha_sccp::v1::finality::verify_certificate` and the §5.1.5 checks.
   Wallets MUST re-verify locally against the target's live `committeeState()`
   before submitting.
6. The wallet or CLI builds EVM calldata locally, decompressing `σ` and the
   signer `y`s with `blst`. Torii serves no calldata and no BoCs.

**Retention.**

- **Original rotation history.** Nodes retain the original canonical
  `SignedBlockWire` Kura history. For every ended generation whose
  `deadline_ms(g) ≥ t_tip`, the rotation endpoint projects `SccpRotationV1`
  from the State-pinned original end block and retained generation, verifies
  the outgoing quorum, certified result and successor, and returns that
  projection. A separately imported rotation file is never certificate
  authority. First-release startup replays original Kura history and rejects
  a snapshot as a substitute for missing historical blocks
  (`specs/sumeragi.md`, E56); there is no snapshot-only SCCP backfill path.
  Missing original source data fails unavailable. Beyond the generation's
  retention window, Torii returns `410 sccp_rotation_pruned`; destinations
  still at that generation are frozen.
- **Anchor witnesses.** The anchor `(core_hash, R)` of height `a` is the
  `(parent_hash, parent_result)` of block `a + 1`'s core header. The original
  Kura blocks of a completed chunk supply its 12-hash path. Nodes MAY cache
  derived chunk leaves, but verify them against the original committed
  chunk root. Missing source data fails unavailable; a cache or imported
  snapshot does not replace the authenticated history.

Writes use the generic `POST /v1/pipeline/transactions`, `GET
/v1/pipeline/transactions/{hash}/status` and `POST /v1/fees/quote`. There are
no SCCP-specific submit endpoints. The Parliament draft route `POST
/v1/gov/proposals/sccp-route-governance`
(`handle_gov_propose_sccp_route_governance`) takes the
`SccpGovernanceProposalV1` payload; Parliament participation uses the generic
Parliament routes, and anonymous ballots use the Parliament's account-free
submission path (ballot spec §6).

## 7. Wallet flows (no hosted services)

Wallets run the native Rust library (§8) against any Taira peer's Torii and the
public RPC endpoints in the user's `[sccp]` client config. These are
third-party endpoints; nothing is operated by the project. Every flow verifies
before paying: certificates against the destination's on-chain committee root,
Merkle paths, and inbound and void proofs through the same `iroha_sccp`
verifier Taira runs. Every flow journals its raw evidence and state transitions
through `iroha_operation_journal`, keyed by `NetworkId`, before submitting
anything, so it resumes after a crash. A resumed command uses the retained
original intent and signed bytes. `--rebroadcast` first reconciles the original
operation, then may resend only those identical bytes; `--retry` cannot replace
an unknown outcome. Confirmation derives the control nonce, checkpoint target,
recovery baseline and deployment pin from the exact locked journal step selected
by the driver. A cached deployment outcome must match that retained pin before
printing its address or registration action. Concurrent selection cannot refresh
the original authority or replace signed bytes. TON discovery retains a bounded, non-authoritative history
cursor. Expiry or absence alone never proves execution or failure. Even after
a destination effect is observed, native TON finality must authenticate a higher
sequence in the exact original basechain wallet's state before the journal
permits another action. The proof binds the signed masterchain anchor, registered
shard block, state-update root, exact account dictionary key, immutable standard
v5r1 code hash, wallet id and data sequence. A getter response, expiry or missing
proof cannot retire that envelope. Missing evidence leaves the original pending
and permits only exact-byte rebroadcast. Control, checkpoint, deployment and
recovery progress require the same native account proof of the locked minter's
storage; getters cannot complete a step. Recovery-row absence follows a complete
bounded dictionary traversal and the monotonic operation-id frontier. A retry
retains the authenticated minter cut with its original row and accepts progress
only at a strictly later target masterchain cut with a changed registered shard
block and a permitted forward recovery transition; an older authentic row cannot
become progress merely because the payer's wallet sequence has advanced. Source
proofs bind the exact discovered transaction root and the authenticated event's
emitter, type, message, nonce and payload. All consumed native light-client,
validator-set and retained-checkpoint records authenticate to the selected World
cut; weak-subjectivity freshness uses the later of that cut's time and the
current local time, so retaining an old cut cannot preserve an expired set.
The journal retains the original light-client, validator-set and consumed
checkpoint records, their source identifiers, selected cut identity and verification
time alongside the proof, so offline replay does not depend on current RPC state.
EVM terminal outcomes likewise require
native-light-client-authenticated block ancestry and both the original signed
transaction and receipt at one identical trie index; finalized mint completion
also authenticates the consumed bitmap under that block's state root. The journal
retains these proof bytes within its finite reopenable record bound. Taira terminal
outcomes require native certified execution inclusion of the exact original signed
envelope at or below the explicitly selected original cut. RPC `Applied`,
`Rejected` or `Expired` status alone never completes a journal step. A final message
also requires its exact authenticated World record, including the original route
when deriving stranded state. A transaction beyond the selected cut remains
pending; resume the same flow with a newer authenticated `--at-height` or
`--world-snapshot`. `settle` therefore requires the original-authority arguments
too. All network requests in each confirmation loop share one absolute deadline.
Deadlines anchored at certified Taira
time can fire up to `2·max_clock_drift_ms` early relative to an individual
clock (§4.3), so wallets submit at least that plus inclusion latency before a
deadline.

### 7.1 Taira → external

1. `GET /v1/sccp/capabilities` and check `network_id` and `consensus_instance`
   against the pinned deployment set. `GET /v1/sccp/registry` returns the
   `Bidirectional` revision `r`; refuse if it is held (forgery hold,
   quarantine, Parliament pause or fast pause).
2. Read the destination: EVM `eth_call` of `committeeState()`, `pauseState()`,
   `equivocated()`, `tairaNetworkId()` and `consensusInstance()`, and the
   `eth_getCode` hash; TON `liteServer.runSmcMethod get_sccp_state`. Refuse on
   any mismatch. Also refuse if:
   - the newest control for `r` leaves the destination paused. The newest
     control is the one with the higher nonce among the destination's
     `pauseState()` and Taira's newest control for `r` (`GET
     /v1/sccp/controls/{network}/{r}`). A pause that Taira recorded but nobody
     has applied yet therefore refuses, and a resume that Taira recorded but
     nobody has applied yet does not: step 5 applies it before finalizing;
   - the destination is not `Live`, or its `committeeState()` root is not
     Taira's record of that generation;
   - no rotation chain from the destination's generation to Taira's current
     generation is available (`/v1/sccp/committees/rotations`), or a generation
     on that chain, or the destination's own `untilMs`, ends before the message
     could be finalized (`outbound_ttl_ms` plus the margin above).
3. `POST /v1/fees/quote`, then sign and `POST /v1/pipeline/transactions` with
   `RecordSccpMessage{network, expected_revision: r, amount, recipient}`. Poll
   the status. Read `message_id` and `deadline_ms` from the
   `SccpMessageRecorded` event, or find the record (sender, amount, recipient)
   in `GET /v1/sccp/outbound/{network}/{r}?from_nonce=<next_outbound_nonce read
   before submitting>` as `iroha sccp send` does, and show the deadline. Discovery
   scans at most sixteen pages per poll and retains its next-page cursor under
   the original signed step, so competing records cannot force every restart
   back to the first page. The retained route and original nonce floor are
   checked on every page; a missing, foreign or corrupt hint restarts discovery
   without changing the signed submission or its outcome.
4. The message is provable as soon as its block commits (`GET
   /v1/sccp/messages/{id}` reports `provable`).
5. If the destination's generation is behind Taira's current one, `GET
   /v1/sccp/committees/rotations?after_generation=<dest>` and submit one
   `submitCheckpoints([rotations…, latest])` (EVM) or `sccp_checkpoint`
   messages batched in one wallet-v5 external message (TON). If Taira's newest
   control for `r` has a nonce above the destination's `controlNonce`, apply it
   first with `applyControl*` (§5.1.6). A pending resume is thereby applied
   before the finalization; a pending pause stops the finalization, which is
   the intended effect, and the message is refunded through a void after its
   deadline (§7.3).
6. `GET /v1/sccp/messages/{id}/proof?at=record` (or `latest`, or a height whose
   checkpoint the destination stores and may still use, §5.1.3: a header of
   the current generation, or the handoff that installed it). Verify locally
   against the destination's live `committeeState()`.
7. Submit before `deadline_ms`: EVM `eth_sendRawTransaction` (EIP-1559 type 2)
   of `finalizeFromCheckpoint` when a usable covering checkpoint is stored
   (a stored checkpoint of a retired generation answers
   `CommitteeNotAccepted`), else `finalizeFromTaira`; TON `liteServer.sendMessage` of a wallet-v5 external
   message carrying `sccp_finalize_checkpoint` or `sccp_finalize`. With
   `--emit`, the wallet instead exports the next required unsigned request:
   an EIP-1559 transaction with `--payer`, or a wallet-v5r1 signing-request BoC
   with `--ton-wallet`, including its signing hash. Export requires no key file
   and submits nothing. If committee or control progress is needed, that request
   is exported first; rerun after it is confirmed to export finalization.
   QR rendering, WalletConnect and TON Connect are optional adapters.
8. Confirm with `isConsumed(nonce)` or the bucket bits, and the `SccpFinalized`
   log.

Anyone may perform steps 5–7 for the recipient. Wallet software MUST NOT skip
the control step of step 5.

### 7.2 External → Taira

1. **Pre-burn guard.** The revision is `Bidirectional` or `InboundOnly` and
   neither forgery-held nor quarantined (claims on a held revision wait, and a
   quarantined revision's claims settle pro rata once reconciled, with later
   claims bearing any unpriced forgery, §4.10 R4). The lane's light
   client is not frozen, has at least 25 % of its weak-subjectivity bound left,
   and is not within 7 days of `supported_until` (`GET
   /v1/sccp/light-clients/{network}`). The recipient literal decodes (checksum
   verified) to `AccountAddress` bytes of at most 1024 bytes whose controller
   account admission allows. The account need not exist. Refuse otherwise.
   Retain the original route, light-client and controller-admission observations
   with the signed burn before dispatch. Recovery reuses that original envelope
   and its evidence; it does not replace a still-unknown burn after rechecking
   newer state.
2. **Burn.** EVM: read `transferNonces(sender)`, then call
   `transferToTaira(recipient, amount, expectedNonce)` with canonical ABI
   encoding. TON: jetton `burn` with `sccp_burn_to_taira`.
3. **Collect and journal evidence** from public RPC as soon as the source block
   is final:
   - **ETH:** `eth_getTransactionReceipt`, `eth_getBlockReceipts(B)` (rebuild
     the receipt trie), `eth_getBlockByNumber(B)` (re-encode the header and
     check the hash), beacon `/eth/v1/beacon/light_client/finality_update`. For
     ancestry, either `eth_getBlockByNumber(B+1..E)` for `HeaderChain`, or
     `eth_getProof(0x0000F90827F1C53a10cb7A02335B175320002935, [B mod 8191],
     E)` for `HistoryContract` (state at `E` must still be available).
   - **BSC:** the same receipt and header calls, and `eth_getBlockByNumber` of
     descendants for the vote attestation in `extraData`.
   - **Older ETH and BSC burns:** `GET
     /v1/sccp/light-clients/{network}/checkpoints?covering=B` and the headers
     from `B` to that checkpoint (§4.13.5).
   - **TON:** liteserver ADNL (`ton.org/global-config.json` peers):
     `getMasterchainInfo`, `lookupBlock`, `getBlockHeader`, `getBlockProof`
     (forward from the epoch's key block for the signatures of the burn's own
     masterchain block, or backward to it from the first block after the newest
     stored key block), `getShardBlockProof`, `getTransactions`,
     `getOneTransaction`.
4. `GET /v1/sccp/light-clients/{network}` and `/sets`. If the light client does
   not cover the evidence, build `AdvanceSccpLightClientV1` updates with
   `expected_state_hash`: ETH `/eth/v1/beacon/light_client/updates`; BSC set
   transitions; TON key-block `getBlockProof` links. Each advance is stepped to
   the light client's bounds; repeat until it covers the evidence. The builders
   pick the proof's anchor as §4.13.5 states. When the anchor is a checkpoint
   beyond one proof's ancestry bound, the evidence also carries `Backfill`
   advances (`expected_state_hash: None`).
5. Run the verifier locally against the light client, sets and checkpoints read
   in step 4, with the backfills applied in order, then submit **promptly**
   (§4.13.5). In the ordinary funded mode, backfills go first, each in its own
   journaled transaction. `iroha sccp claim --self-claim` instead builds and
   locally verifies one bounded recipient bundle, including its ordered
   advances and backfills. `--register-self` adds only the recipient's bare
   account registration when needed. Then:
   - A user without XOR submits a self-claim `[Register<Account>(self)?,
     AdvanceSccpLightClientV1…, SubmitSccpInboundMessageV1]` signed by the
     recipient key (§4.12.4). Admission verifies the ordered bundled advances
     and proof under the original allocation and work budgets; a qualifying
     bundle is fee-exempt on success. Separate keeper advances remain useful
     when catch-up exceeds one transaction's limits.
   - Otherwise the user submits the same instructions from any funded account.
6. If the record is `Pending` (revision paused or held, SCCP disabled), retry
   later with `SettleSccpV1::Inbound(message_id)`.

### 7.3 Refunds (outbound that did not mint)

1. After `deadline_ms`, check `isConsumed(nonce)` or the bucket bits. If the
   nonce is unconsumed:
   - if the destination is `Live`, submit `voidExpired*` with the same kind of
     proof as finalization;
   - if the destination is frozen (expired or latched), submit
     `voidFrozen(first, count)` over the unconsumed range (`GET
     /v1/sccp/outbound/{network}/{revision}`).
2. Collect the void evidence exactly as in §7.2 steps 3–5 (the `SccpVoided` log
   or the TON `sccp_voided` external-out), and submit
   `SubmitSccpOutboundVoidV1`. The same builders and anchors apply, so void
   evidence ages like a burn: the §4.13.5 windows hold, and an older void is
   proven from a checkpoint with backfills. If the refund is left `Pending`
   (the revision is held), retry with `SettleSccpV1::Refund`.

### 7.4 Destination upkeep, deployment and registration

- **Committee sync.** Anyone runs `iroha sccp committee-sync --network
  <profile>`, which reads `committeeState()`, walks
  `/v1/sccp/committees/rotations`, submits one `submitCheckpoints` and applies
  the newest pending control. It must run at least once per
  `committee_validity_ms − committee_heartbeat_ms` (13 d with the defaults,
  §4.2.3) per destination; every finalizing wallet also does it as a side
  effect. Route operators run it as a funded relayer duty, and the deployment
  runbook names the owner. Validator nodes do not rotate destinations, because
  they hold no external-chain funds.
- **Control relay.** After the Parliament enacts `SetDestinationPaused`, or the
  fast pause track enacts a pause, anyone (normally the proposer or a panel
  member) runs `iroha sccp control apply --network <profile>`, which fetches
  `/v1/sccp/controls/{network}/{revision}/{nonce}/proof` for the newest control
  and submits `applyControl*` (`sccp_apply_control*` on TON). `iroha sccp
  control status` compares Taira's newest control with the destination's
  `pauseState()`. A confirming Parliament pause MUST be delivered before the
  fast pause it confirms lapses (§4.14.7).
- **Watch and evidence.** `iroha sccp monitor` compares each destination's
  `committeeState()`, `checkpointHeader` and `pauseState()` against Taira,
  alerts at `untilMs − 3 d`, and builds forgery evidence on divergence (`iroha
  sccp evidence build|submit`, with `evidence anchor` for the witness). For
  every held revision it prints the `AttestSccpDeploymentProgress` or
  `QuarantineSccpRevision` proposal it needs (§4.10). The CLI makes one bounded
  read-only pass over at most 64 configured pinned deployments, using the
  independently selected original native cut and configured RPC transports.
  EVM discovery covers at most 2,048 blocks and consumes 16 certificates per
  pass; its printed exclusive `BLOCK:LOG_INDEX` cursor resumes without
  dropping additional events. TON discovery consumes one linked page of
  16 transactions and prints the next older `LT:HASH` cursor. An observation
  or unsigned suggested action never establishes Parliament authority.
  Only a signature verified against the original generation plus an E1–E4
  mismatch becomes a candidate accepted by `evidence submit`, which uses the
  durable transaction journal and recovers its exact original envelope first.
  Validator nodes do the
  same through the keeper watch (§4.13.4).
- **Light-client keeper.** This runs in validator nodes by default (§4.13.4).
  Anyone may also run `iroha sccp light-client advance --network <p>`.
- **Fast pause.** Panel members run `iroha sccp fast-pause
  panel|accept|endorse|status` (§4.14.7).
- **Source trust before deployment.** For a network without a usable native light
  client, first obtain genuine Parliament enactment of `InitializeLightClient`,
  using `iroha sccp light-client bootstrap build|verify`. Initialization does not
  require a registered route. Select a cut containing that initialization before
  deployment; no endpoint observation or bootstrap fallback substitutes for this
  authenticated source-chain authority.
- **Deployment.** `iroha sccp deploy --network <profile>` deploys from locked
  artifacts with the deployer's key: EVM only through `SCCP_EVM_DEPLOYER`
  (§5.2.1), TON with its canonical initial data followed by `sccp_init`. It
  pins a retained generation that satisfies P2 at the expected enactment time,
  read from the operator's own node or cross-checked across the configured
  peers, proves deployment finality under the already authenticated source light
  client, and prints the `RegisterRoute` action. Ethereum and BSC deployments of
  one revision get different addresses because their constructor arguments
  differ, so destination words stay unique (§4.14.3).
- **Registration and every other decision.** Once the launch gate is open
  (§10.2), a bonded citizen (or a holder of `CanProposeSccpRouteGovernance`)
  runs `iroha sccp governance propose --actions <file>`, which builds and
  checks an `SccpGovernanceProposalV1` (for a newly proven deployment:
  `RegisterRoute` and `ActivateRevision`) and submits
  `ProposeSccpRouteGovernance`. Reviewers run `iroha sccp deployment verify --network <p> --revision <r>
  --actions <file>` before proposal, or select the stored `--proposal-id`,
  and `iroha sccp light-client bootstrap verify` (§4.14.4) against the body
  shown by `iroha sccp governance show`. Anyone MAY run `iroha sccp governance
  drive` (§4.14.5 item 4). Seated members act with the `iroha gov parliament`
  commands and the Parliament wallet, and enactment is automatic (§4.14.3).
  A combined initialization and registration proposal remains legal only when
  deployment was independently proven under a prior authenticated light client.
  Both launch gates currently remain false (§10.2); this sequence introduces no
  substitute authority or bypass.

## 8. Off-chain Rust

- **`crates/iroha_sccp`** is network-free and linked into `iroha_core`. It
  holds:
  - the v1 payload codec and amount rules, hashes, transfer and control leaves,
    Merkle and history functions;
  - `v1::finality`: `X`, `QC_FIXED`, `R`, the Commit preimage `P`, `m`,
    `checkpoint_id`, `verify_certificate` (with `KeyValidate` on every signer
    key) and `verify_certificate_by_aggregate` (the form an EVM destination
    evaluates, §5.1.3 steps 10–11);
  - `v1::committee`: the committee root and the §5.1.2 destination state
    machine as the reference for both contracts;
  - `v1::control`: the 199-byte control leaf of §3.4, its constraints and the
    fast-pause clamp of §5.1.6;
  - `v1::destination` and `v1::destination_abi`: the executable model of both
    destination contracts (§5.1: every entry point, the check order, events
    and state), which writes the shared outcome tables, and the error, event
    and selector tables of §5.2.2;
  - `v1::evidence`: the §4.9 E1–E4 reference, anchor leaves, chunk roots and
    paths, used by Torii, the CLI and the keeper for pre-checks;
  - `v1::constants`; `v1::evm_abi`, including `SCCP_EVM_DEPLOYER`,
    `SCCP_EVM_CREATION_CODE`, constructor encoding and CREATE2 derivation;
    `v1::evm_abi` and `v1::ton_cell` encoders for every §5 entry point;
  - the `SccpGovernanceProposalV1` static validation and subject mapping;
  - the per-chain inbound and void verifiers and light-client logic (Ethereum,
    BSC, TON);
  - TON cell hashing and StateInit address derivation;
  - Torii DTOs (`api.rs`).
- **`crates/iroha_crypto`** gains the consensus signing API `bls::consensus`
  (`DST_SIG`, `ConsensusDigest::from_preimage` over the allowlist, `sign`,
  `verify`, `verify_fast_aggregate`, `verify_aggregate_multi` and
  `verify_fast_aggregate_committed`; `specs/sumeragi.md` §1 item 6). The w3f
  transcript and proof of possession are unchanged.
- **`crates/iroha_sccp_rpc`** (std; network I/O) is used by the irohad keeper,
  the CLI and the wallet. It holds:
  - endpoint lists with failover, and per-endpoint secret headers read from
    owner-only files;
  - blocking `reqwest` (rustls, no `json` feature) with `norito::json` parsing;
  - RPC hygiene, because every endpoint is untrusted and validators share the
    compiled lists:
    - one wall-clock deadline per attempt for connecting, sending and reading
      the whole answer (a body that trickles in is cut off at the deadline, not
      merely between reads), and an optional per-poll budget (`PollBudget`)
      past which no attempt starts and no backoff sleeps;
    - a byte cap per route sized to its real answers (beacon light-client
      updates scale with the requested count; `eth_getBlockReceipts` uses the
      64 MiB transport ceiling), and per TON query kind, checked against the
      announced size before reading;
    - JSON admitted by an allocation-free lexical preflight (at most one value
      per 8 bytes of the cap, nesting depth 32) and then built under a Norito
      decode budget of 6 × the cap. All limits derive from the cap alone, so
      every node applies the same bounds to the same route. Bodies over a cap
      or a limit fail over; they never panic or allocate without bound;
    - typed decoding inside the attempt. A non-failover answer about the
      request (HTTP 404 or another client status, a JSON-RPC or API error,
      malformed data, a non-failover `liteServer.error`) is returned, and the
      next request starts at the next endpoint. Callers whose build fails on
      served data, or whose verification rejects it, rotate explicitly
      (`rotate_preferred`, or a builder's `rotate_endpoints`, which the keeper
      calls after such a failed build);
    - start indices seeded per caller (`endpoint_seed` derives a seed from
      bytes such as the peer id), so the keepers of different validators start
      at different endpoints. Explicit CLI and wallet lists keep their order;
  - EVM JSON-RPC, the beacon API (JSON light-client and header routes), and a
    TON ADNL-TCP liteclient with its ADNL handshake crypto built from workspace
    crypto crates;
  - destination readers for the keeper watch and `monitor` (`SccpCertificate`
    and committee events, `sccp_certificate` external messages,
    `committeeState()`, `pauseState()`);
  - the compiled default public endpoint lists that `iroha_config` exposes as
    defaults;
  - builders for advances, backfills, inbound proofs, void proofs and
    light-client bootstraps, behind the `builders::SourceChainBuilder` entry
    points that the keeper, the CLI and wallets share. Advances are stepped to
    a byte budget, evidence anchors are chosen as §4.13.5 states, and
    `LightClientReplayV1` verifies evidence against a local replay of Taira's
    light client before anything is submitted.
- **`crates/iroha_sccp_wallet`** (std; never in the `irohad` graph, enforced by
  the `sccp_wallet` layer in `ci/dependency_budget.json`) holds:
  - `pure/`: bundle verification (BLS through `blst`), the §5.1.2 committee
    state machine for planning `submitCheckpoints`, EVM ABI encoding and
    EIP-1559 signing, TON cell/BoC builders and wallet-v5 messages. These are
    FFI-exportable for SDK bridges;
  - `journal.rs` and `flow.rs`: the resumable journal keyed by `NetworkId`
    and typed outbound, inbound, refund, deployment, evidence and destination
    maintenance state machines, built on `iroha_operation_journal`. The CLI
    adapters retain the exact signed public bytes and verified source evidence
    before dispatch. Restart observes the original operation first; explicit
    rebroadcast reuses its identical bytes, and a new attempt requires an
    authenticated terminal outcome. Tests cover crashes on both sides of the
    dispatch marker, altered intent, recovery without a second signature,
    bounded discovery hints and private-directory custody. This component
    qualification does not replace live route and external-chain qualification;
  - `config.rs`: the client-config `[sccp]` table (file-only): endpoint lists,
    timeouts and pinned deployments per `NetworkId`.
- **`crates/irohad`** has the SCCP keeper `sccp_keeper.rs` (§4.13.4:
  keepalives, light-client advances and the watch), a supervised task with one
  schedule per network and short-lived state views, configured through
  `[sccp.keeper]` and `[sccp.light_client_keeper]` (user → actual → defaults;
  no environment variables), and the start-up refusal of a staking policy that
  fails L1 while SCCP exists (§4.8).
- **CLI** `iroha sccp {info, routes, recent, send, status, proof, finalize,
  committee, rotations, committee-sync, control status|apply, burn, claim, settle,
  void, refund, light-client status|advance|backfill|bootstrap build|bootstrap
  verify, lc-profile, deploy, deployment verify, governance propose|show|drive,
  evidence build|submit|status|anchor, fast-pause panel|accept|endorse|status,
  monitor, ton-retry, reconcile prove-mint|status}`.
  - `reconcile status [--network <profile> --revision <n>] [--limit <1..64>]
    [--after-network <profile> --after-revision <n>]` reads one bounded page of effective
    holds and scalar reconciliation window, forged supply and payout rate from
    `/v1/sccp/forgery-hold`. The default page has at most 64 rows and reports the
    next exclusive cursor. It does not copy the permanent proof-id history.
    `reconcile prove-mint --network <profile> --revision <n> --proof <file>`
    submits a bounded Norito JSON `SccpForgedMintProofV1`: the authenticated
    source proof and the canonical outbound payload preimage. The node verifies
    the event, deployment and message-id binding; TON's event has no amount,
    so the amount comes only from that bound payload.
  - `governance propose` builds, statically validates and submits
    `ProposeSccpRouteGovernance`; Parliament participation uses the `iroha gov
    parliament` commands and the Parliament wallet. There is no governance
    signing command, because no key approves anything.
  - `governance drive` is the optional driver of §4.14.5 item 4.
  - Taira keys come from `account.private_key_file`. External keys come only
    from owner-only key files or `iroha_wallet` named wallets. `--emit` exports
    unsigned transactions for external signers. No keys on argv or in
    environment variables.
- **SDKs (phase 2):** read models, `RecordSccpMessage` building, bundle
  verification and destination encoding, via `connect_norito_bridge` (Swift,
  Kotlin, C#) and `iroha_js_host` (JS). Python only verifies. Java has no SCCP
  surface.

## 9. Security analysis

### 9.1 Trust assumptions and operational dependencies

| Direction | Safety holds if | Liveness needs |
|---|---|---|
| Taira → X | (1) **Taira consensus:** at most `f` Byzantine members per committee, for Taira's own safety. (2) **Historical-key accountability:** every generation `g` that a destination may still trust either has at most `f` Byzantine members, or its forging coalition is economically accountable: every member stays bonded while `g` is liable (§4.8), and every destination-valid certificate of `g` whose block or result is not Taira's is slashable on Taira (§4.9). (3) **Destination progress:** a destination chain's finalized time passes each generation's deadline within `grace_ms + progress_cap_ms` of it (37 d by default), the inbound light clients are safe, and relay plus inclusion latency stays below `grace_ms` (§4.8). (4) The deployment was pinned to a genuine generation and registered by the Parliament (§9.7). (5) Correct destination code | `q` running honest members per committee; one keepalive submitter on an idle chain; one honest submitter on X before the deadline; a committee sync within the validity window, done by any finalizer or relayer. Otherwise a void and refund recovers the value |
| X → Taira | the source chain's finality assumption (ETH ≥ 2/3 sync committee; BSC ≥ 2/3 Parlia BLS votes; TON > 2/3 validator weight) within the weak-subjectivity bound, **and** Taira BFT, **and** a genuine Parliament-enacted light-client bootstrap | one submitter within the claim window (§4.13.5); a light client kept within `ws_bound` by wallets or keepers, or re-initialized by the Parliament |
| Governance | the SORA Parliament enacts only what its seated citizens approve: honest sortition (beacon uniqueness), a sound binding ballot (anonymous on-chain ballots, `specs/parliament_private_ballot_design.md`) and a citizen majority in each body; the fast pause panel is trusted for pauses only (§9.13) | a seated Parliament with a qualified ballot; the global beacon; keepalives on an idle chain; for the fast pause, a non-blocked panel (§4.14.7) |

The current committee's BFT assumption alone is not sufficient, because
departed members keep their keys. This design makes no forward-security claim
for departed keys before their deadline: it makes their misuse slashable and
bounds it in time. For liveness, honest clocks are within `max_clock_drift_ms /
2` of real time; certified time is then at most `2·max_clock_drift_ms` ahead of
any individual honest clock (§4.3).

**Removed assumptions:** honest bridge keys, attestor liveness and bridge-key
fault economics. **Consensus keys are now bridge keys.** They are hot,
in-process keys; external custody of vote keys is out of scope (§13). An
operator is liable for every signature of its consensus key while any
generation that contained it is liable, so operators MUST keep a retired key
secret until then and SHOULD destroy it afterwards; by then every destination
network's finalized time has passed the deadline, or the cap has expired, and
no destination accepts it.

Taira today runs 4 validators on one host under one custody owner, and its
genesis citizens are provisioned by the same reset tooling, so the effective
trust in every direction is that operator. The protocol is correct for any `n ≤
31` and any citizen count; decentralization is a deployment property.

**Operational dependencies.** None of these is a hosted service, and none adds
trust, but each needs someone to act:

- after each Taira reset, and once the launch gate is open, someone redeploys
  three mainnet contracts, a citizen makes the bring-up proposals (§4.14.5),
  and the Parliament enacts them;
- the Parliament must stay seated: citizens respond within the windows and cast
  their ballots, and validators run the beacon signers;
- validators need do nothing for SCCP itself: their nodes produce finality
  headers as part of execution, and the keeper submits keepalives, advances
  light clients and watches destinations by default, from a key that needs no
  funds because those transactions are fee-exempt (§4.13.4). Validators must
  accept the SCCP staking floor (§4.8 L1): their stake is released only after
  their generations stop being liable;
- someone keeps each destination's committee current and applies controls (any
  finalizing wallet does both as a side effect, §7.1);
- keeper and wallet traffic uses third-party public RPC endpoints, which may
  rate-limit or require API keys (supported through secret header files);
- WalletConnect needs a project id, which is why raw-transaction and QR export
  are the default hand-off;
- every public Taira Torii hostname currently resolves to one host
  (`configs/soranexus/taira/dns_records.json`), so cross-checking peers gives
  no independence today. Wallets rely on local verification, not on peer
  agreement.

### 9.2 Replay

- **Destination:** each (revision, nonce) is consumed at most once, by either a
  mint or a void (bitmap or bucket). Nonces are dense and unique per revision,
  because Taira assigns them in deterministic serial execution. The leaf binds
  the destination contract, the payload binds the revision and domains, and the
  message id binds both network identities, so a message cannot be minted
  twice, or on another contract, chain, revision or Taira network. A TON bucket
  accepts flags only after the minter's one-time activation, so a bucket
  redeployed by anyone stays inactive and its bits cannot be reset.
- **Taira:** `sccp_inbound_messages[message_id]` is permanent. Message ids are
  unique because source nonces are per-sender (EVM) or serialized (TON), and
  the payload includes the sender, nonce and revision. Void proofs act only on
  records in status `Recorded`.
- **Certificates:** `P` binds `I` (chain, reset, instance), the height and kind
  `0x03`; `X` binds the network. Checkpoints are idempotent per `keccak256(X)`.
  Rotations are generation-locked, and a replayed or stale certificate never
  extends trust (§5.1.2).
- **Controls:** a destination applies a control only with a nonce above the
  last applied one, so a stale control can never be replayed after a newer one,
  and each leaf carries the complete state. The control leaf binds the Taira
  network, the target network, the destination word and the revision, so a
  control cannot be applied to another deployment, chain, revision or Taira
  network.
- **Governance:** each Parliament decision is enacted at most once, and its
  per-subject expected head supersedes it if another decision changed the same
  subject first (§4.14.3). Fast-pause endorsements bind the panel, the network
  and the current `FastHold` head. No signed governance statement exists to
  replay.
- **Evidence:** forgery records are deduplicated per `(generation, validator)`;
  anchors bind their height.

### 9.3 Rogue keys and key admission

Consensus keys enter a committee only with the w3f proof of possession, checked
at genesis, in every epoch context and at admission, together with
`KeyValidate`. That makes `FastAggregateVerify` rogue-key secure for every
admitted key, and the PoP's hash domain differs from `DST_SIG`, so a PoP is
never a consensus signature. Destinations aggregate only keys committed by a
root they accepted (the Parliament-pinned generation, or a successor certified
by the current generation), so they inherit Taira's checks. Taira's strict key
ordering excludes duplicates, and TON re-checks ordering when it installs keys.
There is no peer key-consent signature in this release; `RegisterPeerWithPop`
is unchanged.

### 9.4 Signature counting and malleability

Contracts and Taira enforce: exactly `q = n − f` signers (`popcount(signers) =
q`; signer supersets are rejected), bits `≥ n` zero, LSB-first bitmap order,
canonical compressed keys with the right flags and sign bit, every `y` and `σ`
limb below `p`, `σ ≠ O` and in the subgroup, and `apk ≠ O`. Different
exact-quorum subsets are valid for the same block and result (certificates are
per node), so evidence deduplicates per validator, not per certificate.
Consumption is keyed by nonce, never by signature bytes.

### 9.5 Domain separation

- `DST_SIG` is reserved to the allowlisted consensus API (kinds `0x01`–`0x05`
  and RS16 statements, exact preimage lengths). Every other BLS context keeps
  the w3f transcript, and the PoP binds its own key under the w3f DST (§3.8).
- ASCII role tags separate the payload, message, transfer leaf, control leaf,
  node, history, committee, finality header, result, result body, anchor and
  evidence hashes. Leaf and node preimages differ in prefix and length, and
  verifiers compute leaves themselves, so an internal node cannot pass as a
  leaf and a transfer cannot pass as a control or the reverse.
- Proofs are positional and bind the leaf index and count against an
  authenticated `message_count` or `history_size`.
- The keeper key signs only the node's own Taira transactions (keepalives,
  advances and evidence); no key signs caller-supplied bytes.

### 9.6 Cross-chain and cross-route confusion

The same certificate is valid on every destination by design. Each destination
accepts only leaves with its own destination word, domains, revision and route
id. Control leaves carry the Taira and target network bytes, the destination
word and the revision. Destination words are unique across all registered
routes and revisions. A contract deployed on the wrong chain is rejected by the
`block.chainid` / `GLOBALID` check and could mint only unregistered,
unredeemable tokens; CREATE2 addresses depend on the network tag, so the
Ethereum and BSC deployments of a revision differ.

### 9.7 Deployment integrity

**Threat.** An attacker deploys a contract with a fake initial committee. It
mints to itself, burns back to zero supply, rotates to the real generation and
gets the deployment registered. That would pre-consume honest nonces and leave
provable burns that drain escrow.

**Defense.** The initial pin is part of the deployment's identity: Taira
recomputes the EVM CREATE2 address from the locked creation code and the pin,
and the TON address from canonical initial data built from its own generation
record (§4.14.3 P3, P4), and `RegisterRoute` checks the pin against that record
(P1). Reviewers additionally verify live state (zero op count and supply, a
genuine committee chain, genuine checkpoints) before the decision and before
activation (§4.14.4). With a genuine pin, no mint, void or burn is possible
before registration without a genuine certificate; a forged handoff by the
pinned generation is slashable while it is liable.

### 9.8 Taira reset

A reset gives a new `NetworkId` (enforced by the genesis reset nonce), which
means a new `I`, a new `X.network_id`, new lane bytes and new committee
generations. No old certificate, message or burn is valid across the reset. The
Parliament should pause old deployments before the reset (§4.18); either way
they freeze when their last generation's deadline passes. Their burns are not
accepted by the new Taira. The stranded value is the documented cost (§4.18).

### 9.9 Long-range attacks and weak subjectivity

| Case | Bound |
|---|---|
| Departed key set; destination maintained | Rotated past at the next heartbeat or key change; afterwards no certificate it signs is accepted there, and no checkpoint of its generation gives a new authorization except the handoff that installed the next generation, until the rotation after it (§5.1.2 property 3, §5.1.3) |
| Destination nobody maintains | Trusted until `deadline_ms(cur)` ≤ certified start + validity (14 d by default, 30 d at most), then frozen and drained through voids |
| Replay of a certified `X`; future-dated `X` | No extension; `t_eff` caps a rotation's start at `now_ms` (§5.1.2) |
| A departed quorum forges within its deadline | Out-of-tenure checkpoints lead to a V3 latch on the genuine handoff; an in-tenure false `X` that is not a handoff leads to V1 if the genuine one is stored or is submitted while `g` is current, and otherwise stops being usable when the genuine handoff of `g` is installed or at `deadline_ms(g)`; a forged handoff captures the destination and stays usable until the next rotation (§5.1.2 property 4). In every case the signers are slashable while `g` is liable, and every revision that can be at `g` is held (§4.9–§4.10) |
| Destination halts, then resumes with backdated blocks | `g` stays liable until the destination's light client finalizes a header past `deadline_ms(g)`, plus `grace_ms`, up to `progress_cap_ms` (§4.8 L5) |
| Taira halts, then resumes with a time jump | The liability clock advances by at most one step across the halt, so no liability window is consumed (§4.8) |
| Keys compromised after `g` stops being liable | Every destination's finalized time is past the deadline, or the cap has expired; no destination accepts them, stake may be released, and nothing needs slashing |
| Idle Taira | Heartbeat keepalive (§4.7) |
| Halted Taira | Destinations freeze at the deadline, then voids |
| Network reset reusing a genesis | Forbidden: resets MUST change the genesis hash, hence `I` and the network id |

Inbound light clients enforce per-chain `ws_bound_ms` against Taira block time
and freeze on proven equivocation. Keeping destinations synced is the operative
defence on the outbound side, and every finalizing wallet syncs as a side
effect.

### 9.10 Liveness, censorship and failure recovery

- **Censorship.** Censoring `RecordSccpMessage`, proofs, voids, keepalives or
  evidence on Taira requires control of proposers across leader rotation.
  Destination-side censorship affects only timing, because every destination
  call is permissionless and idempotent. A quorum of the current generation can
  halt Taira and censor evidence; that is outside the model, like any
  compromise of Taira's consensus (§9.12).
- **Finality liveness.** The proof of every SCCP block exists when the block
  commits, so there is no attestor or handoff to stall. Idle chains produce
  exactly the blocks heartbeats and governance work need (§4.7). A missed key
  change degrades into a resync, and destinations at the old generation freeze
  safely (§4.6).
- **Destination freeze, pause, hold or retirement never strands value.**
  Unminted outbound messages are voided and refunded (§4.16), including on a
  paused destination, where `voidExpired` stays open. Revision states admit
  proofs everywhere except `Staged`. `Retired` requires zero liability. Held
  settlement waits; quarantined settlement is reconciled (§4.10).
- **Pause latency.** A fast pause takes one endorsement window of a standing
  panel plus one block and a control delivery (§4.14.7); a full-track pause
  takes a full Parliament round (§4.14.5). Until a control is applied, the
  destination keeps minting what certificates cover. What bounds the damage
  meanwhile: the immutable destination cap; Taira's liability accounting;
  honest wallets, which apply a recorded control before finalizing (§7.1); and,
  for forgeries, slashing and per-revision holds.
- **Inbound.** A proof, once accepted, never expires (§4.12). Claim windows
  bind only the prove step (§4.13.5), and wallets prove promptly. Light clients
  are kept fresh by claims and by the in-node keeper. A source-chain hard fork
  beyond `supported_until` is recovered by a release that appends an extending
  profile version and its Parliament activation (§4.13.2). A stale or frozen
  light client, or a burn older than its window, is recovered by Parliament
  re-initialization or a trusted checkpoint, with bootstraps built and checked
  from public RPC by reviewers. Wallets refuse to burn when a lane is at risk
  (§7.2).
- **Governance liveness.** Without a seated Parliament with a qualified ballot,
  no route can be registered (§10.2); once routes exist, value keeps flowing
  and voids and refunds stay available even if the Parliament stalls, and the
  fast pause track still works. A binding ballot whose turnout misses quorum
  ends `NoQuorum` (§4.14.5 item 2), and cheap citizenship lets an attacker seat
  silent members, so the Taira bond must be out of faucet reach (§4.14.5 item
  1).
- **`enabled = false`** stops only value movement. Proofs, generations,
  controls, evidence and Parliament enactment keep running (§4.1).

### 9.11 Economic safety

- Destination supply ≤ the immutable cap. Taira never records a message that
  would exceed it (§4.15), so no certified message is unmintable because of the
  cap.
- Taira releases, bounces and refunds only up to the revision's liability. A
  compromised source-chain verification can drain at most the route's escrow,
  and a forged bounce is bounded the same way. A forged Taira certificate can
  mint at most the destination cap minus supply on the destinations that accept
  it: those at the forged generation when it is presented. After such a
  destination rotates, only a forged handoff that installed its current
  generation still authorizes mints there (§5.1.2 property 4).
- **The slashable floor.** Torii publishes `coalition_slashable_floor(g)` for
  the current generation: calculate each original member's currently seizable
  amount from bonded and generation-height-eligible pending-unbond custody,
  multiply by `max_slash_bps / 10 000` and round toward zero at that exposure's
  canonical decimal scale, exactly as the native penalty does; then sum the
  `f + 1` smallest rounded amounts. Rounding occurs before summing: two integer
  exposures of one unit at 50 % contribute zero, not one. Missing or inconsistent
  original member provenance makes the read unavailable; a known zero exposure
  contributes zero. Before initialization the field is null. The cheapest forging coalition
  has `f + 1` members, because up to `f` honest stray Commit votes can complete
  a certificate (§9.12). The floor is **seizable collateral**, not a guaranteed
  attacker loss: exposure includes nominators' delegated stake, so operators
  may lose less and nominators bear part of it. Slashed stake goes to
  `slash_sink_account_id`; it does not compensate holders of a captured
  deployment, whom reconciliation (§4.10) pays from that revision's escrow.
  Each `(g, validator)` is penalized once: its permanent recorded offence makes
  that member contribute zero further seizable amount for `g`, including while
  the already-recorded penalty awaits application. A 100 % slash leaves nothing
  for a later generation that reuses the key. `max_slash_bps ≥ 1` while SCCP exists
  (L1), and the Kagami profiles use 10 000.
- **Damage and race window.** Damage is bounded by the sum of the caps of the
  destinations that can be at the forged generation, or whose current
  generation a forged handoff of it installed (§5.1.2 property 4). Taira-side
  release of every revision that can be at that generation stops when the
  evidence is recorded. An attacker can forge, mint, burn and claim inbound settlement
  before that, within the time from the forged destination transaction to
  evidence recording, measured against the source chain's finality for the
  burn proof: seconds to minutes on TON and BSC, about 13 minutes on Ethereum.
  The keeper watch and `monitor` shrink it, using the published certificates
  (§5.1.3). An inbound settlement delay is open (§13).
- **Coverage is not promised.** The Parliament SHOULD keep the sum of
  `max_wrapped_supply` at or below `coalition_slashable_floor`. This is not
  enforced on chain, because stake moves continuously (§13).
- Recipient problems cannot lose value: an absent account is registered at
  settlement; an undecodable or uncreditable recipient bounces (§4.12.5); a
  voided bounce lands in `stranded`, which only the Parliament can release.
- Dust: `min_outbound_amount` bounds the permanent records a sender can create
  per fee. Self-claims pay `inbound_self_claim_fee` from their proceeds, and
  the per-class quotas and pending limits bound fee-exempt load.

### 9.12 Key compromise

- **At most `f` keys of every generation a destination trusts:** no forgery,
  even with `f` honest stray Commit votes.
- **`f + 1` to `q − 1` keys of a generation `g`:** they can complete the stray
  Commit votes of one block that never committed into a certificate for that
  block. Up to `f` honest members may have Commit-voted a block that never
  committed (a hidden PrepareQC followed by a commit of another block in a
  later view; any timeout certificate intersects at least `f + 1` honest Commit
  voters, which would force the re-proposal, so at most `f` such stray votes
  exist for any block). That certificate is E3 evidence: the forgery is
  slashable and every revision at `g` is held. Strict liability then also
  slashes the honest stray signers; this needs `f + 1` colluding or stolen keys
  of `g`, beyond `g`'s BFT bound, so it is accepted, and finer attribution is
  open (§13). With more than `f` Byzantine members, honest members can also be
  led to sign conflicting Commits across views (`specs/sumeragi.md` §3.6), and
  strict liability may slash them; that happens only after `g`'s BFT assumption
  has failed.
- **`q` keys of a departed generation, within its deadline:** the holders can
  present certificates only to destinations still at that generation. A
  checkpoint they forge there gives no new authorization once the genuine
  handoff is installed; a handoff they forge captures the destination (§5.1.2
  properties 3 and 4). It is slashable while `g` is liable, and those
  revisions are held.
- **`q` keys of the current generation:** the holders control Taira's
  consensus. They can halt it and censor evidence, so the Taira response does
  not apply. This is outside the model, like any compromise of Taira's
  consensus.
- **After liability ends:** no effect.
- **A keeper key:** it can only submit keepalives, advances and evidence, each
  verified like anyone's. Its holder gains no authority; the operator deletes
  the key and the node generates a new one.

### 9.13 Governance: the Parliament and the fast pause panel

- **Trust.** The Parliament is part of the trusted base for what it enacts. A
  captured Parliament could register a malicious deployment and let users send
  value into it (bounded by that revision's liability), re-initialize a light
  client from a fake bootstrap or install a fake checkpoint and release that
  route's escrow against forged burns (bounded by the route's liabilities),
  release `stranded` value, attest false deployment progress to release a
  forgery hold (bounded by the held revision's liability), pause or resume
  destinations, or change parameters within their rules. It cannot mint on a
  destination, forge a certificate, move escrow of another route, or change a
  deployment's cap, committee or consumed nonces. **Destinations need no
  Parliament key:** a valid control proof shows that `q` members of the
  destination's current generation signed Commit for the enacting block, so
  "the Parliament enacted this at `h`" holds exactly when Taira is safe
  (§10.3).
- **The fast pause panel** is trusted for pauses only. A captured panel can
  delay minting, recording and settlement on one network for
  `fast_pause_hold_ms` per enactment, renewable while seated, and nothing else;
  the Parliament bounds it with suspension and a lift (§4.14.7). Blocking needs
  a blocking minority in both panels.
- **Citizenship cost.** The Parliament and the panels are only as
  Sybil-resistant as the citizen bond. On Taira, XOR comes from a faucet, so
  the bond MUST be far beyond faucet reach and the faucet MUST use adaptive
  difficulty (§4.14.5 item 1). Cheap citizens could otherwise capture bodies or
  panels within the powers above, or stall full-track rounds.
- **What validators contribute.** Validators produce blocks and run the global
  beacon. Under the beacon's uniqueness a threshold of them can withhold or
  delay pulses (liveness; with the parent proposer, a choice among panel
  draws), but cannot choose members, findings, proposals or outcomes. They hold
  no ballot custody and cannot open, read or alter ballots; ordinary block
  execution verifies ballots and derives the counts
  (`specs/parliament_private_ballot_design.md` §1).
- **No clerk.** SCCP attempts and their progress transitions are permissionless
  and core-derived (§4.14.5 item 3), so no account outside the Parliament
  chooses which SCCP proposals reach the bodies or when.
- **Review.** Every enacted body is public before the vote (§6), and reviewers
  can check deployments and bootstraps with local tools against their own
  endpoints (§4.14.4, §4.13.4). Enactment re-checks every on-Taira
  precondition, including the deployment addresses, the pin and the bootstrap's
  freshness.
- **Latency** is a governance property (§4.14.5); the fast pause track covers
  emergencies.

## 10. Parliament dependency and launch gate

### 10.1 What SCCP consumes

The Parliament's ballot and certificates are owned by the Parliament workstream
(`specs/parliament_private_ballot_design.md`). SCCP needs only:

- the 32-byte `GovernanceCertificateId` (`derive_v1`) and the certificate's
  32-byte `effect_preimage_hash`;
- `s0: GovernanceAnchorV1 { height, position, timestamp_ms }`, the casting-open
  anchor of the approving Policy Jury ballot behind the certificate (ballot
  spec §3.4, §11);
- deterministic block-start enactment: one rollback-isolated transaction per
  certificate, calling `sccp::governance::enact(certificate_id, effect_hash,
  s0, proposal)`;
- the block-start position of each processed item (§4.7.2), recorded for ballot
  openings;
- `parliament_sccp_attempt_latency_ms()`, the latency of one full-track SCCP
  attempt including a single sortition-retry generation, for the hold rule
  (§4.1), with the Parliament's parameter path re-checking that rule;
- reuse of the citizen-eligibility predicate and of the governance draw by the
  pause panel;
- a read-only iterator over due G1–G3 items for `governance_due`, whose
  predicate SCCP owns (§4.7.3);
- `parliament_binding_ballot_available() -> bool` (§10.2).

SCCP parses no other certificate internals, so ballot-binding fields can change
without touching SCCP.

**Interface items with the Parliament workstream.** Confirmed on 2026-10-05:
(1) `enact` takes the full `s0` anchor, which the lift rule needs (§4.14.7;
ballot spec §11); (2) the two `governance_due` corrections: pulse requests are
due only at their exact slot, and fast-pause lapses are not due (§4.7.3); (4)
both panels decide, with seat acceptance and a reserve, so a decline, a
blocking minority or a `NoResult` in one panel never blocks the other, and the
capture figures use the union of the two panels (§4.14.7); (5) the clock
residual is `2·max_clock_drift_ms` relative to an individual honest clock
(§4.3; ballot spec §3.4), and because anchors, `s0` included, can be stale by
the prepare-to-commit lag, a ballot's closure is anchored to the block after
its opening (§4.7.2 G2b; ballot spec §3.4). The hold rule uses
`parliament_sccp_attempt_latency_ms()` (§4.1; ballot spec §11). Still open
(`TODO:`, tracked in §13): (6) the G2 segments that place ballot closures
(rank 4) and openings (rank 5) after the other transitions, the capacity rule
of G2c and the positions they give `s0` (§4.7.2), which the ballot spec
delegates to this revision (ballot spec §8).
Item (3) is settled: draws use the epoch-boundary pulse once per term, with a
7 d default (§4.14.7).

### 10.2 Launch gate

`RegisterRoute` requires both of the following. Each is a stub that returns
`false` until its owner lands it (`TODO:`):

- `parliament_binding_ballot_available()`, provided by the Parliament
  workstream: true once the qualified post-quantum ballot construction is
  active on the chain (ballot spec §5);
- `sccp_reconciliation_available()`, provided by SCCP: true once the implemented
  accounting of quarantined revisions (§4.10) is qualified with the original
  Parliament shared-pass producer, positions and carried remaining work budget.

While `parliament_binding_ballot_available()` is false:

- `ProposeSccpRouteGovernance` is refused for every SCCP action with
  `ParliamentBallotUnavailable`. There is no interim governance, and the SCCP
  parameters keep their genesis values (§4.1).
- `RegisterRoute` cannot be enacted (§4.14.3 P0).
- Genesis and Kagami create no routes: `InitializeSccpV1` creates only the
  parameters, the per-network escrows and generation 1.
- SCCP machinery that needs no route still runs: generations, heartbeats,
  finality headers, keepalives, anchors, the liability clock, forgery evidence
  and panel draws. Endorsements are refused anyway while no route exists
  (§4.14.7 precondition 1).

### 10.3 Trust statement

Binding juries use anonymous on-chain ballots: one-time hash credentials
registered at seat acceptance, a frozen roster Merkle root, and a public vote
with a nullifier and a post-quantum zero-knowledge membership proof; counts are
public (`specs/parliament_private_ballot_design.md`). There is no Parliament
key and no custodian of any kind. **Destinations need no Parliament key.** A
valid control proof shows that `q = n − f` members of the destination's current
generation signed Commit for `(h, R_h)`. At least `f + 1` honest validators
therefore executed block `h`, whose block-start pass validated the certificate,
compared and set the head, applied the effect and wrote the leaf. "The
Parliament enacted this at `h`" holds exactly when Taira is safe.

### 10.4 Profiles and the frozen surface

- **Inbound:** light-client source profiles become active only through
  Parliament enactment (`ActivateLightClientProfile`, §4.13.2).
- **Outbound:** any change to the frozen external verification surface (`X`
  layout, consensus suite, Commit preimage; §3.8) requires a new route revision
  with new contracts, activated by the Parliament. Old revisions drain through
  voids.

## 11. Tests and fixtures

Shared vectors live in `fixtures/sccp/`. Contract, node and SDK tests consume
them, and every file has a generator with a drift check:

- **Reference files.** `finality_v1.json`, `committee_transitions_v1.json` and
  `control_v1.json` are written by two independent generators, whose outputs
  MUST be byte-identical: the Python reference
  (`scripts/sccp_reference/generate.py`, dependency-free) and the Rust
  reference (the `crates/iroha_sccp` integration tests `v1_reference_finality`,
  `v1_reference_transitions` and `v1_reference_control`, built on
  `iroha_sccp::v1` and `iroha_crypto::bls::consensus`). `generate.py --check`
  is the Python drift check. On the Rust side each file has a drift test
  `reference_<file-stem>_matches_committed_fixture` and an ignored `regenerate`
  test.
- **`bls_consensus_v1.json`** is written by the Python reference alone, and the
  `iroha_crypto::bls::consensus` tests reproduce it row by row.
- **Rust-only files.** `finality_rust_v1.json` and
  `bls_consensus_rust_v1.json` carry the vectors that need the w3f transcript
  of `iroha_crypto`, which the Python reference does not implement. Rust
  generates and drift-checks them. `pytests/scripts/test_sccp_reference.py`
  checks with the Python reference every row of `finality_rust_v1.json`
  (rejected, and its signature is the w3f aggregate of its signers), and of
  `bls_consensus_rust_v1.json` the standard sign, verify and aggregate
  vectors, the allowlist rows and rejections, and the key and consensus-API
  negatives. Two things in that file are verdicts of the w3f transcript and
  stay Rust-only: the proofs of possession (`keys[].w3f_pop`) and the
  generic-API negative (`dst_sig_signature_presented_to_generic_api`), of
  which Python confirms only that the signature is a consensus signature. The
  pytest fails on a missing file and on a row shape it does not know.
- **Other files.** The remaining Rust-generated files come from the
  `crates/iroha_sccp` vector tests, and the Python reference re-derives the
  payload, commitment-tree and history vectors among them. The TON StateInit
  vectors come from the contracts themselves.

The Rust drift tests run in CI with the crate tests of `iroha_sccp` and
`iroha_crypto` (`scripts/rust_ci.py`). `.github/workflows/sccp.yml` also runs
the independent Python reference suite, including in-memory regeneration and
byte-for-byte comparison of every Python-owned fixture, and retains its test
record alongside the Rust and destination-contract qualification artifacts.
To regenerate after a reviewed change:

```
python3 scripts/sccp_reference/generate.py --write
cargo test -p iroha_sccp --test v1_reference_finality \
    --test v1_reference_transitions --test v1_reference_control \
    -- --ignored regenerate
```

### 11.1 Fixtures

| Fixture | Content |
|---|---|
| `payload_v1.json` | payloads for all 6 directions (with `deadline_ms`), payload hashes, message ids, amount-scale conversions, rejected encodings (including the retired TRON domain and codec 5) |
| `commitment_tree_v1.json` | transfer and control leaves, mixed trees, roots and every path for counts 1..=17 and 512, including promoted nodes; a transfer/control/node confusion negative |
| `control_v1.json` | the §3.4 control-leaf vectors for every target network, both tracks and both pause values; constraint negatives (`track` 0 or 3, `parliament_paused` 2, `track = 2` with expiry 0, a zero id or a zero effect) and the recording-rule refusals under their reference labels (§3.4; `parliament_paused` 2 cannot reach a contract through its typed interface, so no contract harness replays that row); the `SccpControlApplied` topic; `applyControl` scenarios (§5.1.6) in the row shape of `committee_transitions_v1.json`, including the `MAX_FAST_PAUSE_MS` clamp and a fast-pause expiry ending in 001 ms probed at the whole seconds on both sides |
| `history_v1.json` | history leaves, roots and paths for sizes 1..=40; peak-bagging equivalence |
| `governance_v1.json` | `SccpGovernanceProposalV1` frames with `base_revisions`, subject sets (including `FastHold`, `FastPauseControl` and `ForgeryHold`), proposal ids, expected heads (`subject_id`, `version`, `head_root`) for fixed revision maps |
| `finality_v1.json` | `X` encodings (rotation, heartbeat, non-rotation, inactive), `R`, `checkpoint_id`, `P`, `m`, `QC_FIXED`, committee roots, anchor leaves, nodes and chunk roots, the forgery evidence id (§11.2); valid headers, and invalid headers each with the first violated check of §3.6 (`Length`, X1–X7), including one row with two violations for every adjacent pair of that order, so that the order itself is pinned; `result_of_preimage` bounds; full certificates (§11.3) |
| `finality_rust_v1.json` | schema `iroha.sccp.finality.rust.v1`: the §11.3 negative certificate whose aggregate is a w3f-transcript signature, with its expected rejection. Rust-generated by `v1_reference_finality`; the Python reference verifies that it rejects the row |
| `committee_transitions_v1.json` | the §5.1.2 state machine as `(state, input, now) → (state', outcome, event)` rows (below); the error names and the check order of §5.1.2, §5.1.3 and §5.1.8 under `error_choices` |
| `fast_pause_v1.json` | panel draws, seat replacement, endorsement rounds, certification, enactment, renewal, lift, suspension and lapse rows (below) |
| `forgery_evidence_v1.json`, `liability_v1.json` | the §4.8–§4.9 rows (below) |
| `evm_calldata_v1.json` | golden calldata of every §5.2.2 entry point, every selector and event topic, the view returns, `SccpTransferToTaira`, `SccpVoided` and `SccpCertificate` logs, the P4 CREATE2 address of a sample pin, and `calldata_conformance`: the shared table of `transferToTaira` and `voidFrozen` encodings (canonical, trailing byte and word, truncation, a dirty high bit in every integer field, every dynamic offset moved past an inserted word, nonzero padding of every `bytes`, recipient length and amount bounds, `voidFrozen` counts 0/1/256/257 and the `2^64` end) with the Rust decoder's and the contract's verdicts, which accept exactly the same entries |
| `ton_boc_v1.json`, `ton_stateinit_v1.json` | BoCs of every §5.3.3 op, including `sccp_checkpoint` with and without `next_keys` and `sccp_retry`; snake-cell negatives; canonical minter initial data with an empty `retries` and the minter address for a fixed pin, `NetworkId`, `I`, revision, cap and code refs |
| `native_transfer_event_v1.json` | inbound transfer and void vectors per source with the normalized event: `SccpTransferToTaira`/`SccpVoided` logs (ETH, BSC) and the `sccp_transfer_to_taira` external-out body (TON); the Rust light clients verify the ETH and TON vectors |
| `rpc/{eth,bsc,ton}/` | captured public-RPC responses for real mainnet blocks, driving the proof builders and verifiers: finality, ancestry and inclusion. The recorded TON liteserver answers (`rpc/ton/transport`) also replay through the TON light client: a key-block bootstrap, the config-28 shuffle against real headers' subset hashes, Simplex signatures of a block and of a key-block hop, and header, shard and transaction proofs that prune `state_update` |
| `bls_consensus_v1.json` | `Sign`, `Verify`, `FastAggregateVerify` and `AggregateVerify` under `DST_SIG` over SHA-256 digests; imported Ethereum `bls12-381-tests`; each allowlist row positive, plus off-by-one lengths and wrong kinds; negatives: the identity key, non-canonical and non-subgroup points. Written by the Python reference; `iroha_crypto::bls::consensus` reproduces it row by row |
| `bls_consensus_rust_v1.json` | the vectors that need the w3f transcript: pinned w3f PoP vectors (algorithm unchanged); negatives: a w3f-transcript signature over a consensus digest, a `DST_SIG` signature presented to the generic API, a PoP used as a signature. Rust-generated by `iroha_crypto`; the Python reference checks every row it can decide without the w3f transcript (above) |

`eip712_v1.json` and `roster_v1.json` are deleted with the attestation
transport.

**Scenario time.** A destination's clock has one-second resolution: `now_ms` is
`block.timestamp × 1000` on EVM and `now() × 1000` on TON (§0). Every `now_ms`
of a scenario step, in `committee_transitions_v1.json` and in the
`applyControl` scenarios of `control_v1.json`, is therefore a multiple of 1000
and never decreases within a scenario; equal values are allowed.
`X.timestamp_ms`, `until_ms`, message deadlines and fast-pause expiries may be
sub-second.

**Required `committee_transitions_v1.json` rows:** the initial pin; a
checkpoint that raises `high` and leaves `untilMs` unchanged; a rotation at a
key change; a heartbeat rotation with an identical root (TON without
`next_keys`); a rotation with a lowered `validity_ms`; a rotation whose
successor deadline has already passed (applied, then `Frozen`, processing
stops); 16 batched rotations; K→K′→K; one future-dated certificate replayed
across several validity periods (no extension); freshly forged in-generation
heights after the genuine end (accepted, bounded), then the genuine handoff
latching through V3; after every genuine rotation is applied, certificates of
an old generation refused with `CommitteeNotAccepted` and no state change; a
CUR certificate at `height ≤ high`; V1, V2 and V3, each positive and with its
nearest non-violating neighbour (V1's neighbour is the same `X` with a
different `result_body`, which records nothing and does not latch); expiry,
then refusal of `submitCheckpoints`, then `voidFrozen`; a latch inside a batch;
an inline V3 giving `LatchRequired`, then `submitCheckpoints` latching; a
future-dated rotation `X` (`t_eff` caps the start at `now_ms`); TON checkpoint
eviction ordering; a rotation `X` with a sub-second timestamp, whose
sub-second `untilMs` is probed at the whole seconds on both sides; the cheap
path on both flavours: a certificate of a stored `X` under a signature that
does not verify is not refused with `BadSignature` (its signature is not
checked and nothing is published; the call answers `NothingToDo` because it
changes nothing), and the same `X` under the identity signature is refused
with `BadSignature`; the step 6 encodings on the cheap path (EVM): a stored
`X` under a signer `y ≥ p`, a signer `y` of the other sign and a `σ` limb `≥
p` is refused; message deadlines: a finalization accepted at exactly `now_ms
= deadline_ms` and refused one second later, with the void outcomes the
other way round, and the same pairs for a `deadline_ms` ending in 999 ms at
the whole seconds on both sides; checkpoint use after a rotation (§5.1.3 U1
and U2) on both flavours: a non-handoff checkpoint of `g` refused with
`CommitteeNotAccepted` once the handoff of `g` is installed, the installing
handoff usable, and a checkpoint two generations old refused, for finalize,
control and void on EVM; on TON, where a successful mint needs the bucket
round trip that the models do not cover (§5.3.4), the refusals for finalize
and control and the installing handoff usable for control; `voidFrozen` on a
`Live` destination of each flavour: every range failure (`BadAmount` on EVM;
`BadRange` on TON, including a range that crosses a bucket) and then a valid
range answering `NotFrozen`, which pins the range check before `Frozen`; two
faults in one call on each flavour: a payload of another revision, and one
that pays the contract, under a checkpoint that is not stored
(`UnknownCheckpoint` on EVM; `BadPayload` and `BadRecipient` on TON, §5.1.2
"Check order and errors"), and a finalization after the deadline with a wrong
leaf path (`DeadlinePassed` on both); the orders a single fault cannot show
(EVM): a control leaf that violates a §3.4 constraint with a nonce below the
stored one (`BadControl`), a consumed nonce at a full supply cap
(`AlreadyConsumed`), and `voidExpired` of a consumed payload with a wrong
nonce argument (`BadNonce`); a reference to the certified block itself that
carries a history proof (§5.1.5), on both flavours: with `historyIndex = 1`,
or with a `historyPath` of one sibling, it is `BadProof` for an inline
finalization and, under the stored checkpoint, for a control, a finalization
and a void, next to the unchanged proofs, which are accepted (on TON the
control only); the inline entry points on a destination whose generation has
expired (§5.1.2 "Check order and errors"), on both flavours: for a
finalization, a control and a void, a certificate that does not verify is
`BadSignature` and the genuine certificate of the current generation is
`CommitteeNotAccepted`, and neither stores a checkpoint; and the deployment
bound on the pinned `untilMs` around both ends (`init_bounds`).

**Flavour and profile.** A TON row runs on `ton-mainnet`: Taira's leaves use
`lane_bytes(sora-taira, ton-mainnet)`, recipients are 36-byte accounts of
workchain 0, the destination word is a placeholder minter account id
(`0x35…35`), and every step names the TON message of §5.3.2. An EVM row runs
on `ethereum-mainnet`. Both models refuse any other pair of flavour and
profile, because a contract computes its lane and its destination word from
its own chain and address. The refusals of the TON rows do not depend on the
minter address; the applied controls of `ton_checkpoint_use_after_rotation`
and `ton_same_height_block_ref_with_history` do. The Acton harness installs
its minter at `0:35…35`, matching those rows. An `SccpCertificate` event of a
row names the pooled certificate whose
`QC_FIXED`, header and signature the destination published, among the
certificates of its own step.

**Required `fast_pause_v1.json` rows:** a Parliament pause, then a fast pause,
then the lapse (destination and Taira stay paused); a fast round certified
before a Parliament pause and enacted after it (the lapse leaves the Parliament
pause in force); a track-2 leaf delivered after its expiry (no pause); a
Parliament lift with `s0` after `enacted_at` (cleared) and before it
(retained); a ballot opened at position 2 and a fast pause enacted at position
5 of the same block (retained); a Parliament pause, a resume ballot opening, a
fast pause enactment, then the older resume's enactment (Taira part retained,
settlement held); an `InboundOnly` revision whose settlement and refunds a fast
pause holds; a renewal round opened at `until_ms − fast_pause_renew_lead_ms`
and enacted before the lapse, with a lift whose `s0` lies between the two
enactments (renewed pause retained); three primary members silent and the
backup deciding, with the other round deleted at enactment; seat replacement at
`accept_until_ms` from the reserve, reserve exhaustion, and a reserve member's
premature endorsement not counting; quorum reached but the next block after
`closes_at_ms` (`NoResult`); a citizen endorser suspended by a Parliament
enactment earlier in the same pass (`NoResult`); `SetFastPauseSuspended`
enacted earlier in the same pass (`NoResult`), with its duration counted from
its own enactment; a stale nonce; the `MAX_FAST_PAUSE_MS` clamp; an endorsement
by a non-member; a second endorsement by one member; a new draw between quorum
and certification (`NoResult`).

**Required `forgery_evidence_v1.json` rows:** E0–E4 positives, including a
genuine `X` with a different `D_body` (E4) and a certificate completing stray
Commit votes on a block that never committed (E3); `NotEvidence` neighbours: a
genuine certificate, and a genuine certificate with a different valid signer
set; anchors from the tip, the open chunk, and a completed chunk with a path,
with negatives for a missing witness, a wrong path and a pruned chunk;
deduplication with the same and with different signer sets; a pruned
generation, an inactive `X`, and an `ACTIVE` `X` at a degraded height (E4); a
self-contained record whose offence height is `start_height` and whose
offenders carry G6 bindings.

**Required `liability_v1.json` rows:** the liability clock across a halt;
`liable(g)` across the time leg, the destination-progress leg and the cap; L5
with a stalled light client; evidence and an unbond in one block at `lc =
liable_until_lc`, in both orders; pruning that skips a generation named by a
pending record; P2 across a validity reduction.

### 11.2 Hash-only worked examples

Common fields: network `0x11^32`, message count 2, root `0x22^32`, history size
5, history root `0x33^32`, generation 3, committee root `0x44^32`, `D_body =
0x66^32`.

| Case | Distinct fields | `R` | `checkpoint_id = keccak256(X)` |
|---|---|---|---|
| Rotation (key change) | h = 7200, t = 1 790 000 000 000, flags `0x03`, validity 1 209 600 000, next `0x55^32` | `0x3fcdcdfce761808f1a1f633fd209c197738d93032a0c5496ff20fb9bbcd783d7` | `0xb0a93737e03cec3ff52c920efa7db18859883ecb598ff7bdd2bf19f67c1086f6` |
| Heartbeat | as above, next `0x44^32` (= committee) | `0xec15d2c034f21de8f6a6192bd246d5ee7acf99ae452c7a70f7c6003b567b1ed4` | `0x0ae4bff13d50fc7129b3fcd5926df55d5da6afc8a33445abed1a1a7e650537a4` |
| Non-rotation | h = 7199, t = 1 789 999 999 000, flags `0x01`, validity 0, next 0 | `0x93d642e5cd5e489a395a937a88c63834fceaa8db9ef267e600f70ba58027c9ac` | `0x2d519a8ba8b000583ee3d0e6ec06843d95c3f7de32bf5ff9a76e6fad0fbbda6c` |
| Inactive | h = 9, t = 1 790 000 000 000 | `0x541b29c5e6058adb34edef96855cb321fdcdc635fc92e4ac25777d1b3ea07b1a` | — |

- Rotation `X` bytes: `534343502f46494e414c4954592f5631 11…11 0000000000001c20
  000001a0c4506c00 03 00000002 22…22 0000000000000005 33…33 0000000000000003
  44…44 0000000048190800 55…55`.
- Non-rotation `X` bytes: `534343502f46494e414c4954592f5631 11…11
  0000000000001c1f 000001a0c4506818 01 00000002 22…22 0000000000000005 33…33
  0000000000000003 44…44 0000000000000000 00…00`.
- `QC_FIXED` with epoch 2, context `0x88^32`, view 1, `bh = 0x99^32`,
  `result_body = 0x66^32`, signers {0, 9, 30}: `0000000000000002 88…88
  0000000000000001 99…99 66…66 40000201`.
- With `I = 0x77^32` and the rotation `R`: `m = SHA-256(P) =
  0x85c684fac5aab78b197a5e2d40329ec518bc038abd99974a37064ea26e4943e0`.
- Forgery evidence id for `g = 3`, that `m` and signers `0x40000201`:
  `0x5fe24c413eba8a5e1d7727f630f9bf0c005286c75662061a8216b0292a454f35`.
- Anchors, with core hash `0x99^32`; heights 7199 and 7200 are positions 3102
  and 3103 of chunk 1, so they are siblings: `anchor_leaf(7199, 0x99^32,
  R_non-rotation) =
  0xa22346dda5d3ec12cd1308908cbbcb509f68f3b860377153ca4bae4a5f13df65`;
  `anchor_leaf(7200, 0x99^32, R_rotation) =
  0x0422761979d4e89d78edd5dcfbd719b1f6e10f339603a53da14e4b1587202ed7`; their
  node is `0x1d1e5d3ee82efa64b0c2703e18202b34c29bed398a688bb1626f873c2d36d1a3`;
  the root of chunk 0 with every anchor `(0x99^32, 0x66^32)` is
  `0x2367ae00d979ce576c55f1be87c6971c22921aae16c939eb9ff85b820d2e235f`.
- Event topics: §5.2.2. Committee root: §3.7. Control leaves: §3.4.

### 11.3 Full certificates

Keys are `sk_i = KeyGen(IKM = SHA-256("sccp-finality-test-ikm" ‖ u8 i))`,
committees `n = 4, 7, 31`, and signer sets the lowest `q`, the highest `q` and
scattered sets including {0, 9, 30} at `n = 31`. The file also carries a
key-change rotation certificate, a heartbeat rotation certificate (`next =
committee root`), a non-rotation certificate, and an inactive `X`. Negatives,
each mapped to its §5.2.2 error: kind `0x02`; popcount `q ± 1`; spare bits;
noncanonical `QC_FIXED` lengths; wrong `I`; wrong network; each of X1–X7
violated (including `ROTATION` with `validity_ms = 0`, and non-`ROTATION` with
a nonzero `validity_ms` or `next_committee_root`); root mismatch; a certificate
of a past generation (`CommitteeNotAccepted`); flag `0xc0`; wrong sign bit; `y
≥ p`; off-curve `y`; `σ` outside the subgroup; `σ = O` (`0^192` on EVM, the
compressed identity on TON); any `σ` limb `≥ p`; `c0`/`c1` swapped; raw-bitmap
`signers`; `X.height ≠` the signed height; and the EVM signer coordinates of
§5.1.3 step 6, `x ≥ p` and `(x, y) = (0, 0)`, each pinned under a committee
root that commits to that key. Keys that are points of the curve but no valid
keys, each pinned under the root of its exact key bytes (§5.1.3 steps 10–11):
`signer_key_outside_g1`, one signer key shifted by a point outside G1 with the
genuine signature, so that the pairing equation holds and the aggregate key is
outside G1 (`BadSignature` on both flavours); `aggregate_key_identity`, three
valid signer keys that sum to the identity (`BadCommittee` on EVM,
`BadSignature` on TON), and the same with an EVM `σ` off the curve
(`BadCommittee`: `apk = O` is reported first). `flavor_specific_certificates`
holds `signer_keys_outside_g1_cancelling`: two signer keys shifted by `T` and
`−T`, which an EVM destination accepts because it observes the aggregate only;
its TON outcome is `null` until the Acton harness confirms the per-key checks
of the opcode (§5.3.4 item 5). The invalid headers of the file add
`rotation_at_max_height` and `rotation_at_max_generation`: `ROTATION` at
height or at generation `2^64 − 1`, which X6 refuses, and the rows named
`<a>_and_<b>`, which violate two checks each and report the earlier one. A
certificate row carries `forgery_evidence_id` only when the message that was
signed is the `m` a verifier derives from the row's wire fields (§4.9). The
w3f-transcript signature negative is the row of `finality_rust_v1.json`,
because only `iroha_crypto` produces that transcript.

### 11.4 Conformance

1. Rust `iroha_sccp::v1::{finality, committee, control, evidence, destination,
   destination_abi}` and `iroha_crypto::bls::consensus` are the reference.
2. `scripts/sccp_reference/*.py` is an independent, dependency-free Python
   reference: its own Keccak-256, BLS12-381 arithmetic and pairing, RFC 9380
   hash-to-G2 under `DST_SIG`, and an executable model of §5.1. It derives
   every contract-visible vector and the anchor vectors, writes the three
   reference files byte for byte as the Rust reference does, and verifies the
   rows of the Rust-only files (§11).
3. **The Solidity EDR harness** (Prague and Osaka) runs every calldata vector,
   certificate and scenario, including dirty-memory runs (memory pre-filled
   before verification) for `n ∈ {4, 7, 31}` and 16-certificate batches. It
   checks that `SccpCertificate` is emitted exactly on the full path, and
   records gas per §5.4 row and hardfork.
4. **The Tolk Acton harness** runs every BoC, certificate and scenario. It pins
   the `DUP TLEN UNTUPLEVAR BLS_FASTAGGREGATEVERIFY` stack shape and gas at `n
   = 4, 7, 31`; the value-before-verify ordering and latch refunds; a bounced
   mint whose unconsume also bounces, recorded in `retries` and recovered by
   `sccp_retry`; and a 10 000-rotation run whose account cell count stays
   constant.
5. One shared table (certificate, scenario → expected outcome name) drives
   Rust, EDR and Acton.
6. `BlsCrypto` and `ProofCrypto` parity: one shared certificate verifies
   identically through both.
7. **`integration_tests/tests/sccp_lanes`** runs 4 peers through: an epoch
   boundary with a key change; an idle period crossing a heartbeat, with a
   keepalive; a fast pause on an idle chain (seat acceptance, endorsements,
   keepalive, certification and enactment, then the lapse with no block); a
   forged certificate signed by a test quorum of an earlier generation,
   submitted as evidence with an anchor witness (record, per-revision hold, and
   the penalty after the slashing delay); and a Parliament attestation that
   releases the hold. It extracts bundles from Torii, verifies them with the
   reference, and replays them into EDR and Acton: finalize, rotation,
   heartbeat, control, void and latch.

### 11.5 Required tests

- **Rust unit tests** for every new or modified function: codecs and amount
  conversion, digests, transfer and control leaves, Merkle and history, `X`
  parsing and `result_of_preimage`, committee roots, generation rules S0, A1
  and G1–G7 (including a degraded boundary followed by a resync), anchors and
  chunk paths, the liability clock and `liable(g)`, E0–E4, every rule of the
  §4.1 parameter table including the joint ones and each boundary value, the
  governance subject mapping and expected head, the SCCP arm of the exact-JSON
  `u64` invariant, and every validation branch of each ISI and governance
  action, including `ActivateLightClientProfile`: its binary and JSON roundtrip
  and fixed layout; enactment recording a compiled version from the next block,
  and refusing a version that does not exceed the newest recorded one or a hash
  that differs from the compiled profile; deferral (not refusal) when the
  release does not compile the version; the digest unchanged when a release
  appends a version that is not activated; verification switching profiles at
  the activation height; blocks before the activation resolving the same
  profiles under the new release as under the old one; and the p2p handshake
  policy unchanged by an activation. The light clients additionally test BSC
  roster keys validated once per learned set and the newest set's freshness
  moving only at re-announcing epoch checkpoints; a TON transfer event whose
  amount, nonce or sender disagrees with its payload; and
  `InstallTrustedCheckpoint` refused for TON.
- **Node (irohad) tests:** keeper-key generation into an empty `key_dir`
  (modes, atomic write, refusal of symlinks); `[sccp.keeper]` and
  `[sccp.light_client_keeper]` defaults parsing with an empty config and the
  compiled endpoint lists; a keeper whose endpoint hangs does not delay the
  other networks or keepalives; per-network cadence, backoff and the skipping
  of frozen or aged light clients; keepalive stagger; the watch building
  evidence from a published certificate alone; the L1 start-up refusal.
- **Review-driven tests:** a future-dated certificate replayed across several
  validity periods, then freshly forged heights (no extension, V3 latch); every
  genuine rotation applied, then an old quorum compromised (its certificates
  refused, Taira's evidence slashes it); both Parliament/fast-pause enactment
  orders, suspension races and delayed pause delivery after the lapse; the TON
  wrapper at `n = 4, 7, 31` plus the rotation-count run; the Rust/EVM/TON
  cross-check (exact quorum, bitmap order, PoP-admitted keys, cross-suite
  rejection, infinity and subgroup cases, dirty-memory hash-to-G2); a PrepareQC
  formed by others while this node answers `ClockAhead` (no Prepare of its own;
  Commit only on the others' PrepareQC); recovery from a future proposal;
  idle-chain heartbeat, enactment and fast-pause keepalives; the 31-seat result
  body; a genuine certificate fetched from `/v1/bridge/finality/{H}` is
  `NotEvidence`, and a genuine `X` with a forged `D_body` is E4; a hidden
  PrepareQC on a due-work block for longer than `gov.due_work_max_lag_ms`, then
  a re-proposal that commits; a BSC halt with backdated resumption after the
  time leg (`g` stays liable until L5 clears, and the forged rotation is
  slashed); a Taira halt past `liable_until_lc`, then a time jump (evidence
  admitted and the unbond refused in the same block); evidence near expiry
  across pruning and restart; a past pin, then an intermediate generation with
  shortened validity, then catch-up (P2 refuses); a captured `InboundOnly`
  revision, attestation of the other revisions, then attacker burns (the
  captured revision stays quarantined); a forged certificate through an
  internal EVM call (`SccpCertificate` carries it, and the keeper builds
  evidence from the event alone); skewed honest clocks (two at `T + d`, one at
  `T`) around a ballot opening (the bound is `2d`); a degraded epoch boundary,
  then a resync generation.
- **Governance clock (§4.7.2):** with `K` casting windows open, a closure and
  an opening due in one pass (the closure frees the slot and the opening takes
  it in the same pass); a deferred opening that takes its `s0` at the pass that
  opens it; a closure anchored at `t(h_open + 1) + casting_window_ms` for an
  opening block committed after a long commit lag; a ballot opening and a
  fast-pause enactment in one pass (the opening has the smaller position, so
  that ballot's resume retains the pause); a pass whose budget defers items
  (order kept, leftovers due, the keepalive due again).
- **Reconciliation (§4.10):** the phases Held, Reconciling and Reconciled; a
  forged-mint proof in the last block before `closes_at_ms` (counted) and at it
  (refused); `rho` with `B + F = 0`; payouts that sum to exactly `B` over `B +
  F` of face value in two different claim orders; a claim beyond `B + F` capped
  by the remaining liability; a pending refund that claims never consume; a
  bounce that would target a quarantined revision strands; `RecordSccpMessage`
  refused after reconciliation; `RetireRevision` refused before the window
  end; a second `OpenSccpReconciliation` refused; a claim kept `Pending` by a
  refused credit leaves `S` and `liability(r)` unchanged and its retry pays
  from the later `S`; a zero payout releases with no credit, fee or bounce; a
  forged-mint proof that would make `liability(r) + F` overflow `u128` is
  refused; a claim of a Reconciled revision is no longer held by forgery
  evidence recorded after the window end.
- **Core integration tests (4 peers):** the chain `RecordSccpMessage → commit →
  X → /v1/sccp/messages/{id}/proof`, verified by the wallet crate, including a
  failed record in the same block; escrow and liability invariants, including
  the definition-owner burn and permissioned transfer negatives and front-run
  registration of an escrow id; inbound (prove with the revision paused, then
  settle; self-claim from a zero-balance unregistered recipient; bounce onto
  the `Bidirectional` revision; liability shortfall); outbound (void proof and
  refund, a voided bounce going to `stranded`, and `ReleaseStranded`);
  governance through the real Parliament harness with the recommended `[gov]`
  profile (a route bundle enacted end to end once the launch gate stub is
  enabled for the test; attempts created and advanced by an account without
  `CanManageParliament`, and manager transitions with non-canonical content
  rejected; proposals on disjoint subjects enacted in either order without
  supersession; a pause proposal and a concurrent `SwitchRevision` on the same
  route, where whichever enacts second is `Superseded`; a stale
  `base_revisions` refusing attempt creation; pause, resume and pause again as
  three distinct proposals; `SetTairaPaused` ensure semantics after a frozen
  void; `SetDestinationPaused` on a revision retired in between; a retry
  attempt after `Rejected` succeeding and one after `Superseded` failing; an
  identical re-proposal after `ExecutionFailed` refused; `ExecutionFailed` with
  no state change when a precondition fails at enactment; the proposer rule and
  the `OnlyGenesis` grant rule; no direct path; every SCCP proposal refused
  while the gate is closed); controls (an enacted `SetDestinationPaused`
  produces a control leaf in the enacting block, the proof bundle verifies in
  the wallet crate and `applyControl` succeeds on EDR; `RecordSccpMessage` is
  refused while the destination is paused or the revision is held); `enabled =
  false` behavior; TON and EVM `RegisterRoute` address recomputation, and a
  pinned generation older than the current one.
- **Inbound:** per-chain positive proofs from captured mainnet data; Ethereum
  negatives (fewer than 342 participants, missing finality branch, slot
  ordering, wrong fork version); HeaderChain, HistoryContract window edges, and
  Backfill; BSC skipping across a set change; TON skipped key block and a shard
  walk across split and merge; equivocation freeze, weak-subjectivity
  rejection, fork-bound rejection under the active profile version (and
  acceptance once an extending version is activated, with no re-initialization,
  while a release that lacks that version fails closed); the checkpoint stride
  retention rule.
- **Contracts:** EDR (EVM) and Acton (TON) suites for every §5 rule: the
  committee state machine rows; the cheap path with a signature that does not
  verify and with the identity signature; checkpoint use across rotations (U1
  and U2); the saturating clock and time sums at the top of `u64` (EDR only:
  TON's 32-bit `now()` keeps every TON sum far below `2^64`, §5.1.2); the
  deployment bound on the pinned `untilMs` at both ends; deadline edges;
  `voidExpired` and `voidFrozen` range and revert rules, including
  `voidFrozen` after a latch; cap, bitmap
  word boundaries, bucket boundaries and bucket activation (a bucket deployed
  early by a stranger, and one redeployed by a third party after deletion);
  bounced consume, bounced internal transfer and unconsume, a failed
  `sccp_consumed` or `sccp_already_consumed`, recorded retries, and a mint in
  flight across a latch; TON value safety (burns and controls below
  `MINTER_FLOOR`, quotes taken before time advances, an event that cannot be
  sent); plain-burn rejection, the workchain rejection, and the
  canonical-calldata rejections of `transferToTaira` and `voidFrozen`, driven
  by `calldata_conformance`; `applyControl` (both tracks, stale and equal
  nonces rejected, a nonce gap accepted, a checkpoint-based control, the
  fast-pause expiry and clamp, a control leaf of another network, destination,
  revision or Taira network rejected, a transfer leaf offered as a control
  rejected, and burns, checkpoints and voids open while paused); immutables,
  `opCount`, `controlNonce = 0` and `sccp_init`; the two counter bounds of
  §5.1.2, reached by storage injection: `opCount` saturating at `2^64 − 1`
  under a burn, a mint, a control and a void, and a sender whose source
  nonces are exhausted (`BadNonce(2^64 − 1)` for every `expectedNonce`,
  nothing changed, other senders unaffected). Measured gas is recorded against
  §5.4.
- **ABI goldens:** the syscall `0xA0` argument text in
  `crates/ivm/spec/syscalls.toml`, the generated
  `crates/ivm_abi/src/syscalls_doc_gen.rs` and `crates/ivm/docs/syscalls.md`
  name only the `1=SubmitBallot` operation tag (§4.4), and `ivm_abi` defines no
  tag-2 constant. The ABI v1 hash golden in
  `crates/ivm/tests/abi_hash_versions.rs` and every committed `.to` fixture and
  manifest carry the hash of that surface. Syscall numbering and
  `abi_syscall_list_golden.rs` are unchanged.
- **Signed-only outbound record (§4.4):** both IVM hosts (`CoreHost` and the
  mock `WsvHost`) reject an encoded `RecordSccpMessage` under tags 0, 1, 2 and
  others with an empty queue; `CREATE_TRIGGER` in a generic and a contract
  frame, a signed user trigger registration, a raw IVM program, a supplied
  `IvmProved` replay and a trigger's instruction group cannot derive it; a
  top-level signed record succeeds as an `Instructions` executable and as a
  `Batch` item; a multisig proposal records from the multisig account once
  signed approval transactions reach quorum (also through the complete
  transaction executor), while an opaque proposal or approval of it is refused.

### 11.6 Mutation gate

The active source registry is `scripts/sumeragi_mutation_gate.py`; Core controls
run with `--core --strict`, while simulator and data-model controls run under
their own owners. `specs/sumeragi.md` §13.4 records the named controls and
oracles. SC1–SC25 originated as planning labels. SC4 is an implemented Core
registry ID; the other implemented cases use the HC/MS IDs below. An adjacent
rule's mutation is not a substitute for the exact planned fault. A registered
hook is not a passing qualification result: discovery, baseline, causal failure
and complete test accounting must all pass on the current candidate. Compiler,
resource and process failures are errors, never killed mutations.

| Planned rule | Registered source controls | Remaining exact mutation scope |
|---|---|---|
| SC1: `R` binds `X` (§3.6) | HC308 omits `X` from ordinary result publication; MS17 binds the vote to `R` | Current-candidate causal qualification required |
| SC2/SC3: outgoing boundary identity and `ROTATION` (§4.2.2) | HC226 changes the outgoing generation; HC325 substitutes the successor committee root; HC309 omits a pre-heartbeat key-change rotation | Current-candidate causal qualification required |
| SC4: dedicated consensus signing API (§3.8) | SC4, with actual single/aggregate cross-suite refusal controls | None for the registered suite fault |
| SC5/SC6: CT1 and CT3 (§4.3) | HC257, HC259, HC260, HC264, HC268, HC269; MS52 and MS66 cover the clock allowance, MS68 removes the simulator's retained-work canonical-floor wait, MS69 removes its completed-payload clock recheck, MS70 removes the final fresh-proposal clock recheck; DM36 bounds committed drift | Run the controls under their respective owners |
| SC12/SC17: CT5, certified exemption and first-Prepare boundary | HC258, HC281, HC282, HC291, HC294; MS51, MS65, MS67 | Run the production and simulator controls independently |
| SC7/SC8/SC22: heartbeat/governance due predicate and degraded run | HC278 bounds degraded heartbeat retries; HC302 preserves the original parent pause-due set; HC312 omits the heartbeat deadline; HC313 omits the pause-due leg | Current consumer controls require qualification; full cross-owner Parliament scheduling still needs its authoritative producer |
| SC9/SC16: K1 and K2 (§4.7.4) | HC277 rejects a second carrier; HC279 and HC280 cover canonical shape and stale-carrier selection; HC314 admits without established due work | Current-candidate causal qualification required |
| SC10/SC11/SC23: missing inputs, `BEAT`, resync | HC227 binds resync to the native parent; HC324 omits resync; HC228 preserves parent anchors through degradation; HC310 invalidates missing inputs; HC311 disables heartbeat rotation | Current-candidate causal qualification required |
| SC13/SC14/SC18: E4, E0 and E3 (§4.9) | HC315 omits signed body-digest comparison; HC316 omits captured liability; HC317 replaces the original core anchor with the outer block hash | Current-candidate causal qualification required |
| SC15/SC19: liable stake release and liability-clock cap (§4.8) | HC229 caps halt-time advancement; HC320 skips liability; HC321 skips the exact pending penalty | Current-candidate causal qualification required |
| SC20: L5 destination progress (§4.8) | HC251 keeps clearance work on its bounded pending index; HC322 omits original destination clearance | Current-candidate causal qualification required |
| SC21: immutable registration attribution and penalty coordinates | HC230, HC250 and HC305 bind captured members to original global registrations; HC318 substitutes forged height; HC319 substitutes the current peer-key mapping | Current-candidate causal qualification required |
| SC24: pending evidence and anchor retention (§4.11) | HC292, HC293 | None for these registered pruning faults |
| SC25: per-revision forgery hold (§4.10) | HC283 protects registration after forgery; HC285 protects monotone attestation; HC323 omits the forgery-floor hold | Current-candidate causal qualification required |

HC276–HC307 additionally cover exact CREATE2 binding, the proposal launch gate,
permanent quarantine and forged-mint payload binding, reconciliation reservation
and refused-credit accounting, fast-pause seat/quorum/expiry/lift/suspension,
signed instruction custody, bounded control enactment, original-parent due work,
clock budget feasibility, bundled advance expectations and local verifier
refusal. HC326 rejects substituted TON minter, wallet or bucket code even
after the caller recomputes its matching StateInit address. These are
source-owned hooks, not aliases for every open SC row.

Format pins owned by `iroha_data_model` and `iroha_crypto` are enforced by the
§11 golden tests in normal CI. Present clock liveness controls include
`clock_guard_liveness_with_f_plus_one_slow_clocks`,
`clock_guard_accepts_exact_drift_allowance`,
`clock_guard_due_work_lower_bound_at_first_prepare` and
`f33_hidden_prepareqc_due_work_block_commits_after_lag`. The production
`native_heartbeat_certificate_keeps_outgoing_generation_then_uses_successor`
and `resync_uses_real_native_parent_time_then_boundary_rotates_again` tests
exercise native heartbeat and resync behavior. Every planned SC fault now has
an actual source switch and named control. Mutation qualification still requires
the current baseline and exact causal kills under each implementation owner.

The full cross-owner G1–G3 order and original Policy Jury opening production still
require the Parliament interface. Consumer tests refuse an absent producer;
they never substitute an empty pass or a fabricated ballot anchor.

## 12. Phasing and implementation status

This revision is the implementation baseline. The table describes the current
candidate source. Component test results do not establish whole-node, corridor,
deployment or settlement readiness. The remaining internal integration and
qualification work is stated separately from external Parliament authority.

| Area | Status |
|---|---|
| Payload codec, amounts, transfer leaf, commitment tree, history accumulator (§3.1–§3.5) | Implemented with the sole 199-byte control leaf, complete independent pause state and exact authenticated cause. Native message/control/history proofs and wire fixtures cover the current layouts. |
| `RecordSccpMessage`, signed-only execution and the ABI closure for contract-originated sends (§4.4) | Implemented. Original-parent degradation, permanent forgery/quarantine and active pause gates run before monetary, nonce or leaf writes. The instruction frame authenticates signed-only pause operations and prevents nested or repeated dispatch from substituting authority. |
| Inbound prove and settle, self-claim, bounce, holds, liability shortfall, escrow guards, voids, refunds, strands and FASTPQ-bounded refunds (§4.12, §4.15, §4.16) | Accounting consumers and R1–R6 reconciliation are implemented, including exact proven payload binding, pending-refund reservation, floor-rounded U256 payouts and refusal without advancing claims. Native proof admission and self-claim retain their original allocation and work custody; current Core execution component qualification passes; end-to-end monetary enactment still requires qualified Parliament authority. |
| Exempt eligibility predicate and charge-on-failure (§4.19) | Original-parent predicates, class quotas, any-authority keeper advances, shared Keepalive and R-EX are implemented. The admitted native proof pipeline and its original-budget queue/execution controls pass Core component qualification. |
| Light clients for Ethereum, BSC and TON; profiles, aged-proof builders and RPC hygiene (§4.13, §8) | Protocol verifiers and builders are implemented. All three native kernels use original-pool admission and retained storage, including bootstrap, advance, proofs and equivocation. Component and Core dispatch tests cover the current kernels. Live RPC and real fork activation evidence remain external qualification. |
| Light-client keeper task | Node-generated keeper key, independent light-client advance, Keepalive, bounded destination-watch and L5 duties are implemented. Watch queues retain verified evidence through publication or expiry, and endpoint rotation/health telemetry expose unavailable duties. Daemon component qualification passes; live source-network progress remains externally qualified. |
| Parliament SCCP payload, subjects, attempts, `OnlyGenesis` grant and CLI (§4.14.3, §4.14.5) | Native actions, per-subject heads, monotone deployment progress, permanent quarantine, reconciliation opening and bounded pause suspension are implemented. Retired bridge-key fault clearing is removed. Proposer permission does not bypass the ballot launch gate. The actual binding certificate and casting-open provenance must come from the Parliament owner. |
| Torii read routes and Rust SDK (§6) | Native finality, committee DATA, message/control/history, anchor, forgery-hold, fast-pause and reconciliation views are implemented with request admission and retained response custody. The current-generation coalition slashable-floor projection reads the original staking, incarnation and offence records and is implemented. SDK, Torii and daemon component qualification passes. CLI observers authenticate terminal state against the original certified source cut and retained signed submission. |
| Wallet and CLI flows (§7) | Implemented with durable original signed submissions, authenticated native/EVM/TON terminal proofs, retained source-trust preimages and bounded confirmation deadlines. Recovery, maintenance and deployment read the exact locked journal step, including cached deployment outcomes. Current CLI regressions and independent step-selection review pass; live monetary flows still require qualified Parliament authority and external deployment evidence. |
| EVM contract (§5.1–§5.2) | Native EIP-2537 verification, committee handoff/checkpoints, exact calldata, consumed bitmap, supply cap and CREATE2 deployment are implemented. Locked Prague/Osaka suites exercise authenticated deployment and native certificate/control artifacts. A genuine four-validator native certificate passes local chain-id-1 checkpoint replay on both forks, with signature, network, replay and expired-committee refusals. Monetary routes remain launch-gated; independent audit and live deployment/value qualification remain open. |
| TON contracts (§5.3) | Minter, wallet and consumed buckets implement bounded 512-entry recovery with authenticated acknowledgements and exact finalized-event behavior. The minter storage allowance is 2,380 cells/790,000 bits; worst-case retained recovery and measured gas have native emulator coverage. Tolk/Python/Rust StateInit and message fixtures are updated. Independent audit and live deployment/value qualification remain open. |
| Consensus signing API and `DST_SIG` (§3.8) | The native allowlisted consensus BLS suite is used by signers, certificate readers and model proof verification. Old-suite and invalid-input rejection controls remain. Crypto component and current full certified-clock simulator qualification pass; the four-peer candidate exports a genuine native certificate for local EVM replay. |
| Finality header, certified result `R` and every reader (§3.6, §4.6) | Native producer/readers bind `X` into `R` and derive scope from original genesis/chain custody. Core, private-scope and publication tests cover the boundary; the four-peer native export and local EVM replay exercise the actual certificate boundary. The 31-seat body measurement is 30,763 of 65,315 bytes (§13 item 5). |
| `iroha_sccp::v1` reference and cross-language fixtures (§8, §11) | Native finality, committee, control and destination models and generators are implemented. SCCP CI runs independent Python drift checks, Rust/BLS fixtures, native EVM and native TON suites. Current combined-candidate qualification remains required. |
| Certified time CT1–CT5 and `Execute.certified` (§4.3) | Original-parent bounded due observations and the actual native Prepare signing guard are implemented; certified execution does not inherit a local-clock refusal. The simulator retains the original work and completed payload through committed-parent and immutable creation-floor pacing, and rechecks the clock immediately before fresh proposal signing. The current full simulator, clock baselines and all eight causal clock controls pass. Production Core controls remain part of the pending full Core mutation gate. |
| Genesis and Kagami SCCP staking profile (§4.8 L1) | Implemented with matching epoch geometry of at least one hour, 21-day unbonding, nonzero slash policy, original G1 staking bindings and fresh durable reset identities whose nonces are consumed exactly once. Kagami places initialization after automatic NPoS bootstrap. No routes are seeded. Current profile, signing-order and reset-history regressions pass; the real four-validator SCCP candidate also starts and publishes native finality while refusing unqualified route governance. |
| Frozen-surface golden tests and mutation entries (§11.6) | Native wire/reference fixtures and SCCP clock/Core mutation entries are registered. Current clock controls pass with a passing baseline and causal named-test kills; the full current Core mutation gate remains open. Compiler failures never count as mutation kills. |
| Self-contained penalty records, L3 release gate and daemon L1 refusal (§4.8–§4.9) | Native forgery evidence, permanent offence ownership, closed penalty records, retained liability release checks and configuration refusal are implemented. Current node/network qualification remains open. |
| Committee generations, anchors, `X`, degradation/resync and pruning (§4.2, §4.5, §4.6, §4.11) | Original-pool SCCP records and current/undo custody, genesis/key/heartbeat/resync transitions, destination clearance, original-parent anchors and sealed `X` publication are implemented. Bounded pruning reads the actual pending-forgery owner. Current combined candidate qualification remains open. |
| Shared Keepalive, `governance_due`, positions and millisecond clock (§4.7) | SCCP original-parent due work, quotas, certified-time handling and positioned rank-3 pause/reconciliation consumers are implemented. The minimum work budget is ten. The actual Parliament due iterator, ranks 0–2 and carried remaining budget are external owner inputs; unavailable authority is never treated as an empty set or a successful pass. |
| Control leaf and fast-pause track (§3.4, §4.14.6–§4.14.7) | Funded panels, acceptance/replacement, endorsement rounds, original-source certification, suspension, capacity/nonce preflight, enactment, expiry and selective lift consumers are implemented. Drawing reads the original verified pulse at its carrying height. Parliament must supply eligible citizens, the draw, shared positions and genuine Policy Jury casting-open provenance before this lifecycle can run end to end. |
| Liability clock, L5, evidence and L1 checks (§4.8–§4.9) | Parent-time clamping, retained-generation parameter bounds, keeper L5 feed, original forgery floor and release guards are implemented. Daemon component qualification passes; monetary corridor qualification still requires qualified Parliament authority and live deployment evidence. |
| Per-revision holds, quarantine and reconciliation (§4.10) | Original permanent causes and monotone floors, proof-window accounting and bounded shared due settlement are implemented. Opening/enactment require authentic external Parliament authority and cannot be manufactured by a component test. |
| Launch gates (§10.2) | Both readiness gates remain `false`. Native proposer/registration paths fail closed; no interim governance or genesis route can substitute for the missing qualified Parliament authority. |
| SCCP-owned governance specification | `specs/governance_pipeline.md` describes the implemented SCCP consumers and the explicit external Parliament interfaces. Full shared-pass qualification is still required. |
| First-release retirement | EIP-712 attestations, rosters, bridge-key files/signature sets and their obsolete readers are removed. CLI and contracts use native committees/certificates. Ethereum transaction signing remains. Cross-workspace validation must establish that no retired surface remains. |
| Parliament post-quantum ballot | External launch dependency. Standalone proof work does not supply a qualified binding ballot, authoritative eligibility/draw/due positions, casting-open anchor or finite attempt-latency contract. |

**Order of work.** M0 freezes the interfaces (the consensus API constants and
allowlist; the `CertifiedResultV1` types; the `Execute.certified` API; the
`iroha_sccp::v1` reference with the hash-only vectors and the state-machine,
control, fast-pause and liability rows; the TON wrapper test and exit-code
table; verification of `SCCP_EVM_DEPLOYER` on Ethereum and BSC) and asks the
Parliament workstream to confirm the interface items of §10.1. M1 implements
the core and contract work packages above in parallel. M2 produces
real-certificate vectors, the Torii routes, the original retained rotation projection, `monitor`,
evidence and deployment tooling, gas baselines and the Python re-derivation. M3
runs the 4-peer integration test and the three-way cross-check, rewrites
`status.md` and `roadmap.md` in place, and starts external audits (EIP-2537
glue, the Tolk binding, the consensus transcript change, the `X` producer and
clock guards, anchors and liability, holds and reconciliation). Launch stays
gated on the Parliament ballot and reconciliation (§10.2).

**Later.** SDK parity (§8) and MCP `iroha.*` read tools; destination-state
proofs through the inbound light clients, so that Taira can detect captured or
diverged destinations on chain and automate `AttestSccpDeploymentProgress`;
external custody of consensus vote keys; unifying every BLS signature on RFC
9380 suites; finalizer and claim tips (deferred by decision; a later payload
version, since no backward compatibility is required).

## 13. Open questions

1. **Fast pause panel term (resolved).** The default is 7 d. The first
   epoch-boundary pulse at or after its end draws the replacement (§4.14.7).
   An epoch-length term remains a supported Parliament parameter change.
2. **Parliament interface items.** Item 6 of §10.1 (the G2 segment order of
   ballot closures and openings with the capacity rule and positions) needs
   the Parliament workstream's confirmation before the interfaces freeze.
   Items 1, 2, 4 and 5 were confirmed on 2026-10-05; item 3 is settled above.
3. **Reconciliation (launch blocker).** R1–R6 (§4.10) are normative: the
   quarantine's hold on settlement ends at the window end, later claims settle
   at the fixed rate with the payout of R4, and the quarantine record and the
   outbound refusal never end. The layouts, routes and reconciliation commands
   implement this rule. Liability that no genuine mint or void can reach may
   keep the revision retained indefinitely under R5. The remaining launch
   dependency is the authentic Parliament shared pass and its qualification.
4. **The Parliament ballot (launch blocker).** `fast_pause_hold_ms` is pinned
   only once the ballot's windows are fixed; if one full-track attempt
   (`parliament_sccp_attempt_latency_ms()`) takes more than about 27 d, SCCP
   cannot be configured and the ballot timings must change (§4.1).
5. **31-seat result body (measured).** The largest body the validation rules
   admit is a 31-seat epoch boundary with a frozen preparation: three complete
   rosters (the current context, the successor and the E+2 preparation), the
   finalized pulse, every optional commitment, and the election bonds at their
   widest. It is 30 763 bytes, 47.0 % of the 65 315-byte bound (§3.6), so
   `X ‖ body` is 30 984 bytes and `MAX_RESULT_PREIMAGE_BYTES` stays 65 536.
   The `iroha_data_model` test
   `maximal_31_seat_boundary_with_frozen_preparation_fits_the_result_body_bound`
   pins the number.
6. **Measurements.** Gas and TON costs of §5.4, including `SccpCertificate`,
   and the CI baselines; TON's three checkpoint slots after measuring relayer
   races; generation, anchor and open-chunk storage on a 1 s-cadence chain with
   maximal churn (§4.11).
7. **Attribution under strict liability.** Cross-view equivocation forensics,
   and finer attribution when more than `f` members are Byzantine or honest
   stray Commit votes are reused (§9.12). Evidence ingestion carries a `TODO:`
   for it.
8. **Coverage and settlement delay.** Whether to check route caps against
   `coalition_slashable_floor` at enactment (today Parliament guidance only,
   §9.11), and whether an inbound settlement delay should close the burn race
   window.
9. **Destination-state proofs.** Proving a destination's `committeeState()`
   through the inbound light clients would let Taira detect captured
   deployments on chain and automate progress attestation; not in v1.
10. **Key custody and BLS unification.** External custody of consensus vote
    keys, and unifying every BLS signature on RFC 9380 suites (§3.8).
11. **Genesis staking records (implemented).** Initialization requires every
    original committee signer to have one global staking binding before G1
    publication (§4.2.2). Kagami places its explicit initializer after NPoS
    bootstrap; a missing binding refuses without creating parameters, escrows
    or a generation.
12. **Beacon re-keying.** Every validator-set change needs a new global-beacon
    session before the next pulse (§4.14.5 item 5). Who builds the in-node DKG
    and certificate automation, and the node-generated beacon credential?
13. **Taira decentralization.** Four validators on one host make the `f`-of-`n`
    assumption nominal, and the SCCP staking floor (21 d unbonding) is new for
    Taira's operators. Distributing validators is a deployment decision outside
    this spec.
14. **Real mainnet deployments for inbound fixtures.** Positive inbound tests
    with genuine `SccpTransferToTaira` events need the contracts deployed on
    mainnet and real burns. Until then, inbound verification is tested with
    captured mainnet blocks plus unit-level event binding. Who funds and
    performs the first mainnet deployments?
15. **Public RPC coverage of the default lists** (beacon light-client routes,
    `eth_getBlockReceipts` on BSC, the destination readers of the watch,
    liteserver reliability and retention) is still unverified, and the chosen
    endpoints' terms of use need a check before the lists are compiled in.
16. **Hard-fork cadence.** Ethereum Glamsterdam/Gloas and frequent BSC forks
    each require a release that appends a profile version and a Parliament
    `ActivateLightClientProfile` enacted before the active version's
    `supported_until` (§4.13.2). Every validator must run that release before
    the enactment height, so a full-track round must start well ahead of each
    fork, and the real fork parameters are still needed.
17. **Parameter tuning** needs measurement: 1 d heartbeat, 14 d validity, 7 d
    grace, 30 d progress cap, 7 d outbound TTL, the exempt cap of 32, the fast
    pause panel size, windows and 10 d hold, the self-claim fee,
    `gov.due_work_max_lag_ms`, and TON gas limits per step.
18. **Wrapped test XOR on mainnets** is stranded on every Taira reset. Token
    naming and user disclosure need product sign-off.
19. **`SCCP_EVM_DEPLOYER`.** Confirm that the keyless proxy's runtime code is
    identical on Ethereum and BSC before relying on it (§5.2.1).
20. **Checkpoint use across rotations (recorded rule and residual).** A stored
    checkpoint is usable only while its header is of the current generation,
    or is the handoff that installed it (§5.1.3, U1 and U2). The rule reads
    `cur` and the header, so destination storage is unchanged (§5.2.3,
    §5.3.1). Its residual is the forged handoff: it installs `cur`, stays
    usable under U2 until the next rotation, and leaves the genuine handoff
    not CUR, so nothing latches (§5.1.2 property 4). Detection is the
    published `SccpCertificate`; the response is slashing, the per-revision
    hold, and quarantine with reconciliation (§4.9–§4.10). Effects applied
    before a rotation survive it (§5.1.2 property 3). A progress attestation
    therefore asserts the installing handoff and the absence of forged
    effects, and not the generation alone (§4.10).

## 14. Decisions (binding)

**Decisions of 2026-09-26, as amended by revision 5.**

| # | Decision | Applied in |
|---|---|---|
| D1 | **Governance is the SORA Parliament only**, amended by D12–D13: every SCCP decision goes through `ProposeSccpRouteGovernance` → Parliament bodies with a binding jury → certificate → block-start enactment, with its proposer rule, the `SccpGovernanceProposalV1` payload and expected heads scoped per subject; the only other authority is the pause-only fast pause track. Fault clearing is deleted with the bridge keys | §1.1, §4.14, §9.13, §10 |
| D2 | **Destination pause through control leaves**, amended by D13: no privileged breaker or signed mint-control statement exists. Enacted Parliament pauses (track 1) and fast pauses (track 2) record a 199-byte control leaf carrying the complete pause state in the enacting block's commitment tree; anyone applies the newest one with `applyControl` (`0x32118e92`) or `applyControlFromCheckpoint` (`0x53899b1e`) (TON `sccp_apply_control*`) under a strictly increasing control nonce. Burns, checkpoints, rotations and voids stay open while paused | §3.4, §4.14.6, §4.14.7, §5.1.6 |
| D3 | **Validators come and go at any time**, amended by D11: exit is never blocked, but on a network with SCCP the release of a validator's stake waits until no generation that contained it is liable. There is no handoff signature: the outgoing generation's `CommitQC` of the boundary block is the handoff | §4.2, §4.8 |
| D4 | **Zero-touch validator setup**, amended by D8: no bridge key exists; the node generates only its keeper key, and the keeper is on by default with compiled default public RPC lists. The beacon credential must become node-generated the same way; until then the guarantee covers SCCP only | §4.13.4, §4.14.5, §9.1 |
| D5 | **Approved:** fee exemption for eligible keepalives, forgery evidence, keeper advances and recipient self-claims (advances and self-claims exempt on success and charged on failure; a failing keepalive or forgery evidence makes its block `Invalid`, as amended by D16 and D11); implicit recipient registration; the crates `iroha_sccp_rpc` and `iroha_sccp_wallet` (reqwest + rustls, TON ADNL crypto); default public RPC lists in `iroha_config` | §4.12, §4.19, §8 |
| D6 | **Deferred:** finalizer tips; a later payload version bump is acceptable | §12 |
| D7 | **Networks:** mainnet profiles only, no testnets; amended by D10 to three external networks | preamble, §2 |

**Decisions of 2026-10-04 and 2026-10-05.**

| # | Decision | Applied in |
|---|---|---|
| D8 | **No dedicated bridge keys** (2026-10-05). Destinations (Ethereum and BSC through EIP-2537; TON through native BLS opcodes) verify Taira's Sumeragi `CommitQC` (exactly `q = n − f` signers of a `3f + 1` committee, `4 ≤ n ≤ 31`) with a fixed-layout header `X` bound into the certified result `R`. Bridge keys, attestation transactions, attestation fault evidence and the attestor are deleted; the inbound light-client keeper is kept | §1, §3.6–§3.8, §4.2–§4.6, §5 |
| D9 | **BLS integrator scope** (2026-10-05). Only Sumeragi consensus votes (kinds `0x01`–`0x05`) and RS16 availability statements move to the IETF min-pk PoP ciphersuite (`DST_SIG`, message `SHA-256` of the allowlisted preimage) through a dedicated consensus API; every other BLS signature keeps the w3f transcript for now (`TODO:` unify later); consensus-key rogue-key protection keeps the w3f proof of possession. No peer key-consent signature in this release | §3.8, §9.3, §9.5; `specs/sumeragi.md` §1 item 6 |
| D10 | **TRON is removed** from SCCP v1 entirely (2026-10-05) | preamble, §2, §3, §4.13, §5, §11, §12 |
| D11 | **Exit delay plus slashing** (2026-10-05). Validators of a network with SCCP stay bonded and slashable for at least the destination validity window after leaving the committee, enforced at genesis and at parameter validation. Any `CommitQC`-valid certificate of a committee generation for a Taira commit preimage whose block or result does not match Taira's committed chain at that height is slashing evidence against every signer when presented on Taira, through the consensus penalty pipeline. Destination expiry is anchored so that identical or stale certificates never extend it | §4.2.3, §4.8–§4.10, §5.1.2, §9 |
| D12 | **Parliament with no key and no custodian** (2026-10-05). Binding juries use anonymous on-chain ballots (one-time hash credentials, a frozen roster Merkle root, a public vote plus nullifier plus post-quantum ZK membership proof; counts public) per `specs/parliament_private_ballot_design.md`. SCCP consumes only the 32-byte certificate id and `effect_preimage_hash` (and the ballot's `s0` anchor for the lift rule); enactment is a deterministic block-start step. Trust wording: "destinations need no Parliament key" | §4.14.3, §4.14.5, §10 |
| D13 | **Fast pause track** (pause-only track chosen 2026-10-04; standing panel 2026-10-05). Pause-only; a standing panel and a disjoint backup drawn per epoch outside the attempt reducer, with no new consensus-mandatory pulse slot; public account-signed endorsements; automatic failover to the backup; automatic lapse; separate Parliament-pause and fast-pause state. Applied with either panel deciding (which makes failover unconditional), seat acceptance with a reserve, renewal before lapse, and the per-epoch draw as the parameter value `fast_pause_panel_term_ms` = the epoch duration, with a 7 d default awaiting owner confirmation (§13 item 1) | §4.14.7 |
| D14 | **Light-client profile versions are activated by Parliament enactment** (2026-10-05; already implemented) | §4.13.2 |
| D15 | **SCCP launch waits for the Parliament** (2026-10-05): no route is registered until the post-quantum Parliament ballot exists; no interim governance; no genesis-seeded routes | §4.1, §10.2 |
| D16 | **Idle chains create no empty blocks** (2026-10-05): a permissionless, due-gated keepalive produces the blocks heartbeats and governance work need | §4.7 |
| D17 | **Cross-workstream agreement** (2026-10-04). SCCP owns the enactment proof (control leaf), the fast pause pipeline and the `governance_due` predicate with the block-start clock that the keepalive uses; the Parliament workstream owns the ballot; the standing panel is drawn outside the attempt reducer and registers no Parliament pulse demand; a missing pulse leaves the previous panel seated; the lift rule keys on the binding ballot's `s0`; the hold lifetime covers the full track with retries; re-pause has no cooldown. Applied with the hold rule amended on 2026-10-05: the ballot has no ballot retries, so the hold covers one full-track attempt (`parliament_sccp_attempt_latency_ms()`, ballot spec §11), and renewal before the lapse covers longer outages | §4.1, §4.7, §4.14.6, §4.14.7, §10.1 |
| D18 | **Cross-workstream agreement** (2026-10-05). The certificate interface is unchanged by the ballot decision; citizenship bonds are independent of validator staking (SCCP's exit delay and slashing live in the staking module); the Prepare-vote clock guard is specified normatively in `specs/sumeragi.md`, `max_clock_drift_ms` is a committed chain parameter capped at 60 000 ms, and the residual early firing of deadlines is stated explicitly. Applied with the residual corrected from the agreed `max_clock_drift_ms` to `2·max_clock_drift_ms` relative to an individual honest clock, which the Parliament workstream confirmed on 2026-10-05 (§10.1 item 5; ballot spec §3.4) | §4.1, §4.3, §4.14.5; `specs/sumeragi.md` §4.5 |
