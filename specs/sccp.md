# SCCP v1: SORA Cross-Chain Protocol (first release)

Status: normative design, first release, revision 4. Governance belongs to
the SORA Parliament alone, a destination pause is a Parliament-enacted control
message, validators join and leave freely, and validator nodes set up SCCP
with no operator step; §14 records these binding decisions. SCCP does not
change generic Sumeragi bridge finality (`specs/bridge_finality.md`).

SCCP moves Taira XOR between the Taira Iroha network and four external
mainnets. The first release admits exactly these profiles:

| Profile | Tag | SCCP domain | Native identity |
|---|---|---|---|
| `sora-taira` | `0x40` | 0 | runtime `NetworkId` (genesis header hash) |
| `ethereum-mainnet` | `0x41` | 1 | EVM chain id 1 |
| `bsc-mainnet` | `0x42` | 2 | EVM chain id 56 |
| `tron-mainnet` | `0x43` | 5 | TVM chain id `0x2b6653dc` |
| `ton-mainnet` | `0x44` | 4 | TON global id −239 |

There are no testnet profiles, no alias profiles and no compatibility layouts.

## 0. Conventions

- MUST, MUST NOT, SHOULD and MAY are used in the RFC 2119 sense.
- `‖` is byte concatenation. `u8`, `u16`, `u32`, `u64`, `u128` are unsigned
  integers encoded **big-endian** with exactly that width. `bytes32` is 32 raw
  bytes.
- `word(x)` is EIP-712 `encodeData` of one static value: an unsigned integer or
  `address` is left-zero-padded big-endian to 32 bytes, a `bytes32` is taken
  verbatim, and a `bool` is encoded as `uint256` 0 or 1.
- `keccak256` is Ethereum Keccak-256 (not SHA3-256). `ASCII("…")` is the literal
  byte string without terminator or length prefix.
- `N` is the secp256k1 group order
  `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`;
  `HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0`.
- "Taira-internal" structures are Norito types (`norito::{Encode, Decode}`,
  `norito::json`) and are only ever interpreted by Taira nodes and Rust tools.
  Whenever a Taira-internal value is hashed, the input is the headered Norito
  frame (`norito::to_bytes`), which advertises its layout flags.
  "Contract-visible" structures have the explicit byte layouts in §3 and MUST
  NOT depend on Norito, Rust enum discriminants or JSON spelling.
- Heights, epochs and timestamps refer to Taira unless qualified. On
  destinations `now_ms` is `block.timestamp × 1000` (EVM, TRON) or
  `now() × 1000` (TON).
- A Taira height `h` is **durably final** on a node when Kura holds the
  certified `SignedBlockWire` frame of `h` (the Sumeragi core's commit
  certificate over the block, `specs/sumeragi.md`) and the node's state has
  applied `h`. The Sumeragi core applies only certified blocks, so a committed
  height never reverts. Everywhere in this spec, "committed" means durably
  final.
- **Epochs** are the fixed-length epochs of the Sumeragi core
  (`specs/sumeragi.md` §11.7): with genesis height `g` and the scheduled
  `epoch_length_blocks`, the genesis block and the first `epoch_length`
  heights after it form epoch 0, and each following run of `epoch_length`
  heights is the next epoch (`sumeragi_epoch(h, g, epoch_length)`). A height
  is an epoch **boundary** iff it is the last height of its epoch.
  `current_epoch` is the epoch of the executing height; a node reading
  committed state uses the next height.
- **Amounts.** Taira XOR amounts are `Numeric` values of the XOR definition
  (scale ≤ 9). `taira_units(q) = mantissa(q) × 10^(9 − scale(q))`; it MUST be
  an exact integer with `0 < taira_units(q) < 2^128`. Every destination token
  has 9 decimals, so one token unit equals one Taira unit on every chain and no
  scaling happens anywhere.

## 1. Design summary

### 1.1 Trust model in one paragraph

Taira→external transfers are authorized by **bridge attestations**: for each
committed Taira block that carries SCCP messages, and for each epoch-boundary
block, the validators of that block's bridge roster sign a fixed-layout EIP-712
digest over the block's SCCP commitment root, a history root, and the current
and (at rotations) next roster digest with dedicated secp256k1 **bridge keys**.
Destination contracts keep a roster light client pinned at deployment to a
genuine Taira generation. They verify `⌊2n/3⌋+1` signatures with `ecrecover`
(EVM, TRON) or `ECRECOVER` (TON), verify a keccak Merkle path to the message,
consume the message nonce in an on-chain set, and mint under an immutable supply
cap before the message's deadline. A message that is not minted by its deadline
is **voided** on the destination with the same nonce bit, and Taira refunds it
once the void is proven. External→Taira transfers are proven natively by every
Taira node against permissionless on-chain light clients of the source chain.
A proven message is recorded and then settled, immediately or later, without
re-proving. There is no trusted setup, no prover, no relayer, no archive and no
hosted service: every step is a permissionless transaction that a wallet builds
from Taira Torii and public RPC. Validator nodes run an in-node light-client
keeper by default that advances the light clients from public RPC. It adds
liveness, never trust.

**Bridge keys attest; the Parliament decides.** A bridge key only ever signs
statements derived from committed Taira state. Every SCCP governance decision
(route registration and revisions, activation, pause and resume, parameters,
light-client re-initialization and trusted checkpoints, stranded releases, fault
clearing) is taken by the SORA Parliament through the existing
`ProposeSccpRouteGovernance` pipeline and enacted by core (§4.14). A
Parliament-enacted destination pause becomes a **control message** in the
enacting block's SCCP commitment tree; the bridge roster attests that block like
any other, and anyone applies the control on the destination (§5.1.6).
Validators come and go at any epoch boundary; their nodes generate and register
bridge keys automatically (§4.2, §4.9).

Safety of Taira→external equals the Taira consensus assumption (at most `f` of
`3f+1` validators faulty). Safety of external→Taira equals each source chain's
own finality assumption plus the Taira consensus assumption. Both additionally
trust the Parliament for what it enacts (§9.13).

### 1.2 Settled sub-decisions

| Question | Decision | Why |
|---|---|---|
| Attestation transport | Self-authenticating `SubmitSccpAttestationsV1` instruction in ordinary transactions, auto-submitted by each validator node from its bridge key's own account. It is fee-exempt on success behind admission pre-verification and queue deduplication (§4.8) | Durable, peer-identical, state-derived bytes that any Torii serves. It needs no Sumeragi wire change, and a stalled signer cannot halt consensus. The digest is transport-independent, so a later move to Commit-vote extensions changes no contract (§12). P2P gossip is rejected because it is neither durable nor state-derived. |
| Where the commitment root lives | Post-execution world state (`sccp_block_commitments[h]`), authenticated by the execution commitment of the block's commit certificate. The post-execution hook reads the consensus inputs of `h` from the Sumeragi core's schedule (§4.3.2). The block header carries no SCCP root | A proposal carries no execution result, so a header root authored before execution would break on any failed SCCP transaction (§4.5). |
| Bridge-key registry | New map keyed by `PeerId`, set by `SetSccpBridgeKeyV1`. The instruction carries a consensus-key consent over a per-peer monotone binding nonce, plus a secp256k1 proof of possession. The key's own secp256k1 universal account is its attestor account and is registered implicitly. There is a permanent never-reused address index and a fault bar (§4.2) | The consensus-key registry is indexed by the peer's own BLS key and admin-gated, and staking registration is lane-scoped and refuses fresh global candidates. One key per role means no second key file. |
| Validator setup | Zero-touch. A node running with role `validator` generates its bridge key on first start in an owner-only directory under its store, and submits `SetSccpBridgeKeyV1` itself, fee-exempt on success, as soon as its peer is registered. The attestor and the light-client keeper are enabled by default, with compiled default public RPC lists (§4.9, §4.13.4) | Validators join and leave freely; SCCP must not add a setup step or a funded account to that path. |
| Attestation roster | Scheduled consensus committee (§4.3.2) mapped to active bridge addresses, sorted ascending by address (keyless slots as zero, first), `t = ⌊2n/3⌋+1`. Grouped into **generations**: a new one at every epoch boundary whose `(peer, address)` member list differs from the current generation, on forced rotation (key change, fault, too many unusable slots) and on the 1 d heartbeat, which fires at the first block past it and is block-start work (§4.3.2). The outgoing generation signs the boundary block; there is no seat-change batching and no handoff bond (§4.3) | Deterministic and publicly derivable. Validators come and go like on Ethereum; SCCP never delays an exit. Ascending order lets contracts enforce signer uniqueness in O(1) per signature. |
| Fees and permissions | Attestations, fault evidence, keeper advances, recipient self-claims and bridge-key registration are fee-exempt on success (charged on failure) only under the authority, pre-verification, deduplication and per-block caps in §4.19. Everything else pays ordinary fees. The only SCCP permission token is `CanProposeSccpRouteGovernance`, which only allows proposing and is granted and revoked only in genesis | Signatures are the authority. A fee-exempt root is safe only when admission rejects invalid and duplicate payloads before the queue. |
| Storage/pruning | Messages, control messages, inbound records, consumed sets, history leaves, rosters, subjects and SCCP governance revisions: permanent. Signatures: pruned after `attestation_retention_ms` (at least the outbound TTL plus 1 d), except rotation attestations, which are kept until the outgoing roster expires plus 1 d (§4.10). Light-client checkpoints: one permanent per stride, the rest pruned after 30 d unless Parliament-installed (§4.13.1) | Old messages remain provable through the history root under any newer attestation. Old burns remain provable through retained checkpoints. |
| Equivocation | `SubmitSccpAttestationFaultV1`: any valid bridge signature over a non-canonical statement. Phase 1 records the fault, evicts the key, bars the peer from new keys until the Parliament clears it, and forces a new generation. Phase 2 slashes through the existing consensus penalty pipeline while the validator is still bonded (§4.11) | Off-chain signatures are otherwise unaccountable. |
| Long-range / weak subjectivity | Every generation carries `[valid_from_ms, valid_until_ms]`, with a 1 d heartbeat and 14 d validity, both Parliament-settable. Destinations refuse expired rosters and enforce an immutable `MAX_ROSTER_VALIDITY_MS` (30 d) and clock-skew bound on every installed roster. A destination that is not rotated in time freezes; its in-flight value is refunded through voids (§5.1.5, §4.16, §9.9) | Validators exit freely, so time bounds, not stake, limit how long retired keys stay dangerous to a lagging destination; voids make a freeze lossless. |
| Old messages | Append-only **history accumulator** over SCCP-bearing blocks. Every attestation signs its root, so any recent attestation proves any old message (§3.5) | Destinations only need the current roster, plus a 24 h grace for the previous one. |
| Failed transfers | Outbound: each message carries a destination-time `deadline_ms`. After it, or once the destination is provably frozen, anyone voids the nonce on the destination, and Taira refunds on proof of the void (§4.16, §5.1.8). Inbound: prove-then-settle, where a proof is recorded whenever the revision is not `Staged` and settlement retries without a proof (§4.12). Undecodable or uncreditable recipients bounce | No value can be stranded by a paused, retired, frozen or never-attested destination, or by a temporarily unsettleable claim. |
| New-user claims | Settlement registers a missing recipient account. A recipient with no XOR self-claims fee-exempt, and the fee is deducted from the proceeds (§4.12.4) | No faucet, sponsor program or hosted onboarding is needed. |
| Light-client liveness | Permissionless proof-carrying advances; an in-node keeper on validator nodes, enabled by default, using compiled default public RPC lists; and Parliament re-initialization and trusted checkpoints as a last resort, built and verified with public-RPC tooling (§4.13.4) | Light clients have weak-subjectivity bounds that idle lanes would otherwise exceed. The keeper adds liveness, never trust. |
| Escrow | One core-created escrow account per route, derived without the revision, created at genesis. Core rejects every non-SCCP debit, credit, registration or unregistration of it. `balance(escrow(route)) = Σ_r liability(r) + stranded(route)` (§4.15) | Registration cannot be front-run, and upgradable executor code cannot drain escrow. |
| Governance | SORA Parliament only, through the existing pipeline: `ProposeSccpRouteGovernance` (bonded citizen or `CanProposeSccpRouteGovernance`) → 8-body Parliament → due certificate → atomic enactment. The payload is the v1 action set, and the expected head is scoped per SCCP subject (route, route control, light-client lane, parameters, faulted peer) (§4.14). `RegisterRoute` pins the deployment's initial roster generation. TON deployment addresses are recomputed on Taira. SCCP attempts and their progress transitions are permissionless and core-derived, so no clerk controls the agenda. Genesis MUST seat the Parliament (§4.14.5) | Governance belongs to the Parliament, not to validators or their keys. Per-subject heads keep independent proposals from superseding each other. |
| Destination pause | A Parliament-enacted `SetDestinationPaused` records a **control leaf** in the enacting block's commitment tree. After the bridge roster attests that block, anyone calls `applyControl` on the destination, which verifies the attestation, the Merkle path and a strictly increasing control nonce. Burns, rotations and voids are never paused (§5.1.6) | One governance authority for both sides, no privileged or roster-signed control keys, and the destination needs no verification logic beyond what finalization already has. |
| Destination replay protection | Dense per-(network, revision) outbound nonce assigned by Taira. EVM/TRON use a bitmap `mapping(uint256 ⇒ uint256)`; TON uses sequentially deployed bucket child contracts of 512 flags that are never redeployed (§5) | One storage word per 256 messages instead of one slot per message. The TON account-state cap (65 536 cells) forbids an in-contract dictionary. |
| Token/bridge shape | One contract per destination: ERC-20/TRC-20 with the bridge built in (EVM/TRON), or one Jetton master with the bridge built in plus standard wallets and consumption buckets (TON). 9 decimals everywhere | Removes the TRON deployment cycle (token↔route), all cross-contract minting calls, code-hash rechecks and unit scaling. |
| Taira resets | Taira identity is the runtime `NetworkId`. Genesis carries a random reset nonce, so every reset has a fresh identity, and seeds the Parliament. Nothing Taira-specific is compiled into Rust or contracts. The Parliament should pause old deployments before a reset; otherwise they freeze when their last roster expires (§4.18) | A compiled Taira identity would make every reset and devnet unusable. |
| Contract toolchains | Solidity 0.8.31 (`solc` +commit.fd3a2265 for ETH/BSC; tronprotocol `tv_0.8.31` +commit.c2812a3d for TRON), legacy pipeline, `evmVersion: cancun`; Acton 1.2.0 / Tolk 1.4.2 for TON. All ship native macOS arm64 binaries (§5.5) | Every contract builds natively on macOS arm64, with no Rosetta or Docker. |

### 1.3 End-to-end shape

```mermaid
sequenceDiagram
    participant P as SORA Parliament (citizens)
    participant U as User wallet (local Rust)
    participant T as Any Taira peer (Torii)
    participant V as Taira validators (attestor, keeper)
    participant D as Destination contract
    V->>T: SetSccpBridgeKeyV1 (automatic on first start, fee-exempt)
    P->>T: ProposeSccpRouteGovernance → bodies → certificate → enactment (register, activate, pause…)
    U->>T: RecordSccpMessage{network, expected_revision, amount, recipient} (signed tx)
    Note over T,V: block h is durably final; post-state holds sccp_block_commitments[h] and subject[h]
    V->>T: SubmitSccpAttestationsV1 from each bridge key's own account (blocks h+1..h+2)
    U->>T: GET /v1/sccp/messages/{id}/proof
    U->>D: rotateRosters([...]) if D lags, then finalizeFromTaira(...) before deadline
    D->>D: verify t signatures, Merkle path, deadline, nonce bitmap, cap; mint
    Note over U,D: after the deadline: voidExpired(...) on D, then SubmitSccpOutboundVoidV1 on Taira refunds
    U->>D: transferToTaira(recipient, amount, nonce)  (reverse direction)
    V-->>T: AdvanceSccpLightClientV1 (in-node keeper, on by default, public RPC)
    U->>T: [Register<Account>(self)?, AdvanceSccpLightClientV1…, SubmitSccpInboundMessageV1] (signed tx)
    T->>T: native light-client proof check, inbound record, settlement (release or bounce)
    Note over P,D: an enacted SetDestinationPaused is a control leaf of the enacting block; once attested, anyone calls applyControl(...) on D
```

## 2. Networks, identities and lanes

### 2.1 Identity words

Each profile has a 1-byte tag and a 32-byte identity word:

| Profile | `tag` | `identity_word` |
|---|---|---|
| `sora-taira` | `0x40` | the 32 bytes of Taira's `NetworkId` (hash of the genesis block header), read from world state at runtime |
| `ethereum-mainnet` | `0x41` | `word(1)` |
| `bsc-mainnet` | `0x42` | `word(56)` |
| `tron-mainnet` | `0x43` | `word(0x2b6653dc)` |
| `ton-mainnet` | `0x44` | two's-complement `int256(−239)`, i.e. `0xFF…FF11` |

`network_bytes(p) = tag(p) ‖ identity_word(p)` (33 bytes).

SCCP reads Taira's identity only from world state: no SCCP hash or check uses
the Taira `ChainId` label or a compiled Taira chain id, genesis hash or
network id. The I105 discriminant is not part of any SCCP hash.

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
| TRON | `taira_tron_xor` | TRC-20 bridge contract | 9 |
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
| 5 | `tron_address21` | 21 | first byte `0x41`, remaining 20 bytes nonzero |
| 7 | `ton_account36` | 36 | `i32` workchain (big-endian) = 0, then a nonzero 32-byte account id |

Codecs 4 and 6 are unassigned. The 1024-byte bound
admits Taira multisig controllers with many members. A Taira authority whose
`AccountAddress` exceeds it cannot send (§4.4), and wallets refuse such
recipients before burning (§7.2).

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

- Each variable field has the length range of its codec (§3.1). Total payload
  ≤ 4 096 bytes.
- `source_domain ≠ dest_domain`, and exactly one of them is 0.
- `deadline_ms ≠ 0` iff `source_domain = 0`. A destination mints only while
  `now_ms ≤ deadline_ms` and voids only after it (§5.1.3, §5.1.8).
- `amount ≠ 0`; `amount < 2^96` when either endpoint is TON.
- Sender/recipient codecs are determined by the domains:

| Direction | `sender_codec` | `recipient_codec` |
|---|---|---|
| Taira → ETH/BSC | 3 | 2 |
| Taira → TRON | 3 | 5 |
| Taira → TON | 3 | 7 |
| ETH/BSC → Taira | 2 | 3 |
| TRON → Taira | 5 | 3 |
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
(a Parliament-enacted destination pause state, §4.14.6):

```
destination_word = word(address20)                  // EVM/TRON: contract address, TRON without 0x41
                 | ton_account_id32                 // TON: account id of the Jetton master (workchain 0)
transfer_leaf = keccak256(ASCII("SCCP/LEAF/V1") ‖ message_id ‖ destination_word)
control_leaf  = keccak256(
      ASCII("SCCP/CONTROL/V1")            // 15 bytes
    ‖ lane_bytes(sora-taira, target)      // 66 bytes: 0x40 ‖ Taira NetworkId ‖ tag(target) ‖ identity_word(target)
    ‖ destination_word                    // 32 bytes
    ‖ u32 route_revision                  // nonzero
    ‖ u64 control_nonce                   // ≥ 1, strictly increasing per (network, revision)
    ‖ u8  paused)                         // 0x00 = resume minting, 0x01 = pause minting
node(l, r) = keccak256(ASCII("SCCP/NODE/V1") ‖ l ‖ r)
```

A control leaf commands the deployment with `destination_word` on `target`,
revision `route_revision`, to set its minting pause to `paused` (§5.1.6). The
preimages differ in prefix and length (transfer 76 bytes, node 76 bytes with a
different prefix, control 126 bytes), and verifiers always compute the leaf
they check from its fields, so no leaf kind can pass as another or as an
internal node. `leaf` without qualification means either kind.

Example control leaves (pinned in `fixtures/sccp/control_v1.json`, §11), for
Taira `NetworkId = 0x11…11` (32 bytes of `0x11`), target `ethereum-mainnet`,
`destination_word = 0x00…00 ‖ 20 bytes of 0x22`, `route_revision = 1`:

```
control_nonce = 1, paused = 1  →  0x93d641053e51b4d28f40930e098212e8b6ab340ceaaf8ad38a458203ce98c662
control_nonce = 2, paused = 0  →  0x85fcfc8718c845c212df8ae486161d03bde8116eaa7dd74bbb2312667bce5cdf
```

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

Taira keeps an append-only list of every SCCP-bearing block (message count
> 0, counting transfer and control leaves), in height order:

```
history_leaf(height, sccp_root, message_count) =
    keccak256(ASCII("SCCP/HISTORY/V1") ‖ u64 height ‖ sccp_root ‖ u32 message_count)
history_root(size) = promote-odd root (§3.4 node rule) over the first `size` history leaves
```

`history_root(0) = 0x00…00`. The promote-odd tree equals a right-bagged Merkle
mountain range: with the perfect-subtree roots `P_a, P_b, …, P_z` of the binary
decomposition of `size` (largest first), `root = node(P_a, node(P_b, … node(P_y, P_z)))`.
Taira therefore maintains it in O(log size) state (the peaks), and verifiers use
the same `merkle_root` function with `(leaf_index, history_size)`. History
paths have at most 32 siblings (`history_size ≤ 2^32` is enforced).

### 3.6 EIP-712 domain and signed structures

Everything a bridge key ever signs is EIP-712 typed data under one domain:

```
EIP712Domain(string name,string version,bytes32 salt)
name    = "SCCP"
version = "1"
salt    = Taira NetworkId (32 bytes)

DOMAIN_TYPEHASH  = keccak256("EIP712Domain(string name,string version,bytes32 salt)")
                 = 0x599a80fcaa47b95e2323ab4d34d34e0cc9feda4b843edafcc30c7bdf60ea15bf
NAME_HASH        = keccak256("SCCP") = 0xd7bacbdfe367013f66397ff7242325c31126ab14c95620817c994f22f1d123ba
VERSION_HASH     = keccak256("1")    = 0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6
DOMAIN_SEPARATOR = keccak256(DOMAIN_TYPEHASH ‖ NAME_HASH ‖ VERSION_HASH ‖ salt)
digest(struct)   = keccak256(0x19 ‖ 0x01 ‖ DOMAIN_SEPARATOR ‖ hashStruct(struct))
hashStruct(s)    = keccak256(TYPEHASH(s) ‖ word(field_1) ‖ … ‖ word(field_k))
```

The domain deliberately omits `chainId` and `verifyingContract`: one Taira
attestation is valid on every destination, and destination binding lives in the
Merkle leaves (§3.4, including control leaves) and the payload domains. All
struct fields are static, so `hashStruct` is a fixed number of 32-byte words.
The `0x1901` prefix separates these digests from RLP transactions and
`personal_sign` messages.

A bridge key signs exactly two EIP-712 structs. It never signs a governance
approval or a control statement: governance is decided by the Parliament
(§4.14), and a control reaches a destination only as an attested leaf.

| Struct | Type string | TYPEHASH |
|---|---|---|
| Attestation | `SccpAttestation(uint64 height,uint64 epoch,uint64 timestampMs,bytes32 blockHash,bytes32 sccpRoot,uint32 messageCount,bytes32 historyRoot,uint64 historySize,bytes32 rosterDigest,bytes32 nextRosterDigest)` | `0x6ea54d1f320a2e5892d6a362adc4b569967facc991d3a327cbc84b746f520c66` |
| Key proof of possession | `SccpBridgeKey(bytes32 peerKeyHash,address bridgeAddress,uint64 activationEpoch)` | `0x87f74eabbf9693141811f707b2d51c6a18546376727b384e155d2539ed0a1a3a` |

#### 3.6.1 Attestation statement fields

| Field | Meaning |
|---|---|
| `height` | Taira block height `h` |
| `epoch` | epoch of `h` (§0) |
| `timestampMs` | `creation_time_ms` of block `h`'s header |
| `blockHash` | `HashOf<BlockHeader>` of block `h` (32 bytes) |
| `sccpRoot` | root of block `h`'s commitment tree, or zero if `messageCount = 0` |
| `messageCount` | number of SCCP messages (transfer and control leaves) committed by `h` (0..=512) |
| `historyRoot` | `history_root(historySize)` |
| `historySize` | number of SCCP-bearing blocks with height ≤ `h` (includes `h` if `messageCount > 0`) |
| `rosterDigest` | digest (§3.7) of the roster generation that signs `h` |
| `nextRosterDigest` | digest of the successor generation if `h` is a rotation boundary (§4.3), else zero |

Invariants checked by every verifier: `messageCount = 0 ⇔ sccpRoot = 0`;
`historySize = 0 ⇔ historyRoot = 0`; `messageCount ≤ 512`.

#### 3.6.2 Key PoP fields

`peerKeyHash = keccak256(raw public key bytes of the peer's consensus key)`
(the 48-byte compressed BLS-normal G1 key); `bridgeAddress` is the 20-byte
address of the bridge key; `activationEpoch` as registered.

### 3.7 Roster digest

```
roster_preimage =
  ASCII("SCCP/ROSTER/V1")        // 14 bytes
  ‖ taira_network_id            // 32
  ‖ u64 generation              // ≥ 1
  ‖ u64 valid_from_ms
  ‖ u64 valid_until_ms          // > valid_from_ms
  ‖ u8  n                       // 4..=31
  ‖ u8  t                       // MUST equal ⌊2n/3⌋ + 1
  ‖ member_0 ‖ … ‖ member_{n-1} // 20 bytes each
roster_digest = keccak256(roster_preimage)
```

Member ordering: all zero members (roster peers without an active bridge key)
come first, then nonzero members **strictly ascending** as 160-bit unsigned
integers. Every verifier MUST check the `n` range, the `t` formula and the
ordering while hashing. Because members are unique and signers are addressed by
position, a single key can never count twice. `n ≤ 31` holds because roster
derivation fails closed for any roster outside 4..=31 (§4.3.2).

### 3.8 Signatures

- A signature is 65 bytes `r ‖ s ‖ v` with `v ∈ {27, 28}`, `1 ≤ r < N`,
  `1 ≤ s ≤ HALF_N` (low-S). Recovery that yields the zero address is invalid.
- Signers use RFC 6979 deterministic nonces over the 32-byte digest (prehash).
  `iroha_crypto::EcdsaSecp256k1Sha256::sign_prehash_recoverable` produces this
  form: k256 normalizes to low-S and adjusts the recovery id. If the recovery
  id is ≥ 2, so that `v` would be 29 or 30, the signer MUST discard the
  signature and re-sign with fresh RFC 6979 extra entropy (probability
  ≈ 2^−127; a unit test forces this branch).
- A signature set is `(signer_bitmap: u32, signatures)`. Bit `i` refers to
  roster member `i`. `signatures` is the concatenation of one 65-byte signature
  per set bit, in ascending bit order. Bits ≥ `n` MUST be zero. Each set bit's
  member MUST be nonzero and equal the recovered address.
- The address of a key is `keccak256(X ‖ Y)[12..32]` of the uncompressed point.
  It is identical on ETH, BSC, TRON (without the `0x41` prefix) and TON.
  Verifiers MUST mask a recovered address to its low 160 bits before any
  comparison (TVM can return a `0x41` byte in the padding of an address word).

### 3.9 Constant summary

| Name | Value |
|---|---|
| Event `SccpTransferToTaira(bytes32,address,uint64,bytes)` topic0 | `0x79ac1cc63262b80bfbf96e55b2d49d96bd82f018ce0192f7002168724c7d264b` |
| Event `SccpFinalized(bytes32,uint64,address,uint256)` topic0 | `0x8ab0eb669cb9abcdf0e37e9ce8443162d317d10c2b059296e40aebbd3fa23748` |
| Event `SccpVoided(bytes32,uint64)` topic0 | `0xfc0fe8523e61c1e6bcbb957a8b692dd0b08e1774c4c4bd897fbc68c047c82fcf` |
| Event `SccpRosterRotated(uint64,bytes32,uint64)` topic0 | `0x8619e96c15d0af080499408d3d5fb9af0101014daa9acaad772a5aa03ebf315e` |
| Event `SccpControlApplied(uint64,bool)` topic0 | `0x38b98e72aaf30cffd4309ad36378e1587525135a709fe14074156ebb44254d65` |
| Leaf and node domain tags | `SCCP/LEAF/V1` (12 B), `SCCP/CONTROL/V1` (15 B), `SCCP/NODE/V1` (12 B), `SCCP/HISTORY/V1` (15 B) |
| `PREVIOUS_ROSTER_GRACE_MS` (contracts) | 86 400 000 (24 h) |
| `MAX_ROSTER_VALIDITY_MS` (contracts, Taira parameter bound) | 2 592 000 000 (30 d) |
| `MAX_CLOCK_SKEW_MS` (contracts) | 3 600 000 (1 h) |
| Max block leaves (transfers + controls) / block path | 512 / 9 |
| Max history path | 32 |

Implementations MUST pin all constants in golden tests (§11). Every selector,
event topic and typehash in this document was computed with the Keccak-256 of
pycryptodome
(`Crypto.Hash.keccak`, `digest_bits=256`) over the canonical signature
strings, with tuple types expanded as the Solidity ABI does.

## 4. Taira side

### 4.1 On-chain parameters and activation

SCCP consensus parameters are one Taira-internal value `SccpParametersV1`. It
lives in dedicated world state (`sccp_parameters`), not in the generic
`Parameter` set. It is written only by the genesis-only instruction
`InitializeSccpV1` and by the Parliament-enacted action `SetParameters`
(§4.14.3), so no executor upgrade, no `SetParameter` path and no validator can
alter it. Every field below is Parliament-settable within its rule.

```
InitializeSccpV1 {
    parameters: SccpParametersV1,
    reset_nonce: [u8; 32],      // fresh randomness per Taira genesis, nonzero (§4.18)
}
```

`InitializeSccpV1` is valid only inside the genesis block. It requires the
NPoS consensus parameters with `max_validators` in 4..=31. The Sumeragi core
schedules every live validator whatever `max_validators` is, so roster
derivation enforces 4..=31 itself and fails closed outside it (§3.7, §4.3.2).
It validates the parameters, stores them, creates the four
route escrow accounts (§4.15) and an empty registry. SCCP exists on a network
iff `sccp_parameters` is present; no compiled chain id gates it.
`InitializeSccpV1` does not check that the Parliament can be seated; the
genesis tooling does (§4.14.5, §4.18).

| Field | Taira genesis value | Rule |
|---|---|---|
| `enabled` | `true` | When false, only value-moving effects stop: `RecordSccpMessage` fails, and inbound settlement and outbound refunds stay `Pending`. Bridge keys, roster generations, subjects, attestations, fault evidence, light-client advances, inbound and void proof recording, Parliament enactment and control messages keep running, so re-enabling needs no recovery and destinations keep receiving rotations and controls. Per-route stops use `Paused` (§4.14.2) |
| `roster_max_age_ms` | 86 400 000 (1 d) | Heartbeat: force a new generation at the first block whose `creation_time_ms ≥ valid_from + roster_max_age` (block-start work, §4.3.2; until the core proposer builds blocks for pending start-of-block work, an idle Taira produces that block only when a transaction arrives, §13 item 2). `roster_max_age_ms ≥ 3 600 000` (1 h) |
| `roster_validity_ms` | 1 209 600 000 (14 d) | `valid_until = valid_from + roster_validity`; `2 × roster_max_age_ms + attestation_stall_ms + 86 400 000 ≤ roster_validity_ms ≤ MAX_ROSTER_VALIDITY_MS` (30 d), so a destination always has at least `roster_max_age + 1 d` to rotate (§5.1.5) |
| `outbound_ttl_ms` | 604 800 000 (7 d) | 1 d..=90 d; `deadline_ms = creation_time_ms(record block) + outbound_ttl_ms` |
| `min_outbound_amount` | 10^9 (1 XOR) | Floor per outbound message; bounds permanent dust records. `1 ≤ min_outbound_amount ≤ 10^15` (1 000 000 XOR) |
| `inbound_self_claim_fee` | 10^7 (0.01 XOR) | Deducted from the proceeds of a fee-exempt self-claim (§4.12.4). `inbound_self_claim_fee ≤ 10^10` (10 XOR), so self-claims stay usable for ordinary amounts |
| `attestation_retention_ms` | 2 592 000 000 (30 d) | Signature pruning horizon by block time (§4.10). `outbound_ttl_ms + 86 400 000 ≤ attestation_retention_ms ≤ 31 536 000 000` (365 d), so every signature a finalization or void can need before its deadline is still in state |
| `attestation_stall_ms` | 600 000 (10 min) | Attestation window by block time: outbound records are refused while an older subject of the signing generation is unattested (§4.4), and a rotation subject still unattested after it raises `SccpHandoffStalled` (§4.3.3). 60 000 ≤ `attestation_stall_ms` ≤ 86 400 000 |
| `max_attestation_entries_per_instruction` | 256 | Bound for `SubmitSccpAttestationsV1`. 64 ≤ value ≤ 1 024, so the node default batch of 64 (§4.9) always fits and 0 can never halt attestation |
| `max_exempt_transactions_per_block` | 128 | Cap on fee-exempt SCCP transactions per block (§4.19). 94 ≤ value ≤ 1 024: two attestor keys per validator during a key rotation at the largest roster (2 × 31), plus a reserve of 32 for keeper advances, key registrations, fault evidence and self-claims. Bridge-key accounts hold no funds, so a cap below this would halt attestation |

`InitializeSccpV1` and `SetParameters` (§4.14.3) check every rule of this
table, including the joint ones, against the complete new value. Windows are
in milliseconds of Taira block time, not in blocks, because Iroha produces no
empty blocks and block counts have no wall-clock bound (§4.14.5).

The defaults are tuned for free validator churn: generations may change at
every epoch boundary (3 600 blocks, about 4 h when Taira produces a block every
4 s), the 1 d heartbeat bounds how long a kept destination trusts any
generation, and 14 d validity leaves about 13 days to rotate an unattended
destination (§5.1.5, §9.9).

Node-local behavior (key directory, submission cadence, keeper endpoints)
lives in `iroha_config` `[sccp.attestor]` (§4.9) and `[sccp.light_client_keeper]`
(§4.13.4), with defaults that need no operator input. The native verifier work
limits are the `sccp` section of the committed `zk_validity_policy_v1` chain
parameter (protocol defaults when a chain commits none), bound into the
consensus policy hash; they are not node configuration. Each category has a per-transaction and a per-block
limit: proofs, proof bytes (plus a per-frame bound), native headers and header
bytes, Ethereum light-client updates, BSC vote attestations, secp256k1
recoveries (TRON) and Ed25519 signature checks (TON). Defaults admit one full
advance of every chain in a transaction and four in a block.

### 4.2 Bridge keys

#### 4.2.1 State

```
sccp_bridge_keys: PeerId → SccpBridgeKeyStateV1 {
    active:  Option<SccpBridgeKeyV1>,
    pending: Option<SccpBridgeKeyV1>,          // activates at pending.activation_epoch
    retired: Vec<SccpBridgeKeyV1>,             // tombstones, bounded to 16, oldest dropped from the vec only
    next_binding_nonce: u64,
    last_exempt_binding_epoch: Option<u64>,    // fee-exemption rate limit (§4.2.3)
    barred: Option<SccpFaultRefV1>,            // newest fault (§4.11); cleared only by the Parliament
}
SccpFaultRefV1 { address: [u8; 20], height: u64 }   // key of sccp_attestation_faults
SccpBridgeKeyV1 { public_key: [u8; 33] /* compressed secp256k1 */, address: [u8; 20],
                  activation_epoch: u64, registered_at_height: u64, faulted: bool }
sccp_bridge_key_owners:  [u8; 20] → PeerId      // permanent; an address is never reusable
```

**Attestor account.** The attestor account of a bridge key `k` is
`account_of(k)`: the universal single-key `AccountId` whose controller is `k`'s
secp256k1 public key (§0 universal-account model; secp256k1 is an admitted
signing algorithm on Taira). There is no separate attestor key or attestor-
account registry: each key submits its own signatures, key registration and
keeper advances from its own account, and a rotated key keeps its own account
for signing its old generations' handoffs. An account is recognized as a bridge
key's account by recomputing the §3.8 address of its single secp256k1
controller and looking it up in `sccp_bridge_key_owners`.

#### 4.2.2 `SetSccpBridgeKeyV1`

```
SetSccpBridgeKeyV1 {
    peer: PeerId,
    public_key: Option<[u8; 33]>,       // None = revoke from activation_epoch
    activation_epoch: u64,
    binding_nonce: u64,
    peer_signature: SignatureOf<SccpBridgeKeyBindingV1>,   // by the peer's consensus key
    key_pop: Option<[u8; 65]>,          // required iff public_key is Some
}
SccpBridgeKeyBindingV1 {
    domain: "iroha.sccp.bridge_key.v1", network_id: NetworkId, peer: PeerId,
    public_key: Option<[u8; 33]>, activation_epoch: u64, binding_nonce: u64,
}
```

Validation (all MUST hold):

1. SCCP exists; `peer` is a registered peer; `barred` is `None`.
2. `binding_nonce = next_binding_nonce(peer)`. A binding, including a
   revocation, can therefore never be replayed.
3. `peer_signature` verifies under the peer's consensus public key over the
   Norito frame of the binding (the `PublicLaneCandidateAuthorization`
   pattern).
4. If `public_key` is present: it decompresses to a valid point; `address` is
   derived per §3.8; `key_pop` is a valid §3.8 signature over the EIP-712
   `SccpBridgeKey{peerKeyHash, address, activation_epoch}` digest recovering
   `address`; `address ∉ sccp_bridge_key_owners` (never reused, including by the
   same peer); and, outside the genesis block, the transaction authority is
   `account_of(public_key)`.
5. `activation_epoch ≥ current_epoch + 1`, except inside the genesis block where
   `activation_epoch = 0` is REQUIRED.

Effect: `next_binding_nonce += 1`; store the key as `pending` (replacing an
existing pending entry, whose address stays burned in `sccp_bridge_key_owners`);
insert the owner index; and, if `account_of(public_key)` does not exist, core
registers `Account::new(account_of(public_key))` with the same effect and
validation-fee DS classification as `Register<Account>`. Promotion happens in
the post-execution hook of the boundary block that ends the epoch before
`activation_epoch` (§4.3.2), or immediately in genesis: `pending` becomes
`active` and the previous `active` moves to `retired`. Revocation clears
`active` at activation. Event `SccpBridgeKeySet { peer, address, account,
activation_epoch }`.

Genesis MAY carry `SetSccpBridgeKeyV1` with `activation_epoch = 0` for keys
that test and devnet tooling pre-provisioned into each node's key directory
(§4.9). The Taira reset does not: its genesis carries no bridge keys,
generation 1 is inert (§4.3.2), and the keys that the validator nodes register
themselves during epoch 0 form the first attestable generation at the first
epoch boundary. Deployments pin a non-inert generation, so route registration
starts after that boundary (3 600 blocks; the reset tooling's Parliament
driver ticks until it if Taira is idle, §4.14.5).

#### 4.2.3 Authority, fees and automatic registration

- **Registration** (`public_key` present): the authority is
  `account_of(public_key)`, which need not exist yet. Transaction admission
  (Torii ingress and P2P gossip, the `ordinary_transaction_ingress` pattern)
  pre-verifies checks 1–5 against committed state for a transaction that
  consists of exactly this one instruction, admits its unregistered authority
  (an extension of `allows_unregistered_authority` to exactly this shape),
  keeps at most one pending binding per peer, and counts it toward
  `max_exempt_transactions_per_block`. The transaction is fee-exempt on
  success when `last_exempt_binding_epoch ≠ current_epoch`, which it then
  sets; otherwise, and on failure, the ordinary fee is charged, and admission
  rejects a non-exempt registration whose authority cannot pay it. The node
  therefore registers at most one key per epoch for free, which covers every
  normal case (first start, a wiped store, a rotation).
- **Revocation** (`public_key` absent): any authority; ordinary fee.
- **Automatic registration.** A validator node registers its own key with no
  operator action (§4.9). It never needs a funded account.

### 4.3 Bridge roster generations

#### 4.3.1 State

```
sccp_rosters: u64 generation → SccpBridgeRosterV1 {
    generation, valid_from_ms, valid_until_ms,
    activation_height: u64,               // first height signed by this generation
    handoff_height: Option<u64>,          // rotation height that hands off to generation + 1
    members: Vec<SccpRosterMemberV1 { address: [u8; 20], peer: Option<PeerId> }>,  // §3.7 order
    threshold: u8, digest: [u8; 32],
}
sccp_roster_current: u64
sccp_heartbeat_marker: Option<u64>        // generation whose heartbeat block was forced (§4.3.2)
```

#### 4.3.2 Derivation

**Height inputs.** The post-execution hook of block `h`
(`ValidBlock::finalize_owned_execution_metadata`) reads the consensus inputs of
`h` from the Sumeragi core's lag-2 `consensus_schedule` in world state
(`SccpHeightInputsV1::from_sumeragi_schedule`). The block's output-seal
finalizer advances the schedule before the hook runs, so it holds the
scheduled committees of `h` and `h + 1` and the epoch length. The inputs are
the epoch of `h` and its last height (§0), the roster of `h`, which is the
scheduled committee of `h`, and at a boundary the next roster, which is the
scheduled committee of `h + 1`. The genesis block uses the same schedule. SCCP
never reads height inputs from Kura or from a parent finality artifact. The
core schedules every live validator in both consensus modes, so the roster
rule does not depend on the consensus mode.

Let `peers(E)` be the roster of epoch `E`: the scheduled committee of the
executing height for heights of `E`, and the scheduled committee of `h + 1`
for `E+1` at a boundary `h`. `members(E)` maps each peer to the address of its
active bridge key (active at the start of `E` and not faulted at the executing
height), or to the zero address, and orders them per §3.7. It is a list of
`(peer, address)` pairs; the roster digest (§3.7) hashes only the addresses.

- **Generation 1** is created in the post-execution hook of the genesis block
  from `peers(0)` and the genesis keys, if any: `valid_from_ms` = genesis
  `creation_time_ms`, `activation_height` = the genesis height.
- **Rotation heights** are epoch boundaries, fault blocks and heartbeat
  blocks. Block `h_b` is a boundary iff it is the last height of its epoch
  (§0), and then the schedule MUST hold the committee of `h_b + 1`. A fault
  block is a block that records an attestation fault (§4.11).
  A heartbeat block is a block with `creation_time_ms(h_b) − g.valid_from_ms ≥
  roster_max_age_ms` for the current generation `g`. Fault and heartbeat
  blocks use `peers(E)` of their own epoch.
- **Heartbeat as block-start work.** Iroha produces no empty blocks, so a
  heartbeat that waited for a transaction or an epoch boundary could miss the
  validity window on an idle Taira. At block start core evaluates the
  heartbeat condition against the candidate header's creation time
  (`State::deterministic_start_work_pending` reports it); when it holds and
  `sccp_heartbeat_marker ≠ Some(g)`, core writes
  `sccp_heartbeat_marker = Some(g)`. That write is deterministic start-of-block
  work, and a proposer MUST build a block for pending start-of-block work even
  with an empty queue. The Sumeragi core proposer does not probe start-of-block
  work yet, so until it does an idle Taira produces the heartbeat block only
  when a transaction arrives (§13 item 2). The marker fires at most once per
  generation: if the derivation fails closed (below), later blocks still retry
  it as heartbeat blocks, but no further empty block is forced for `g`.
- In the hook of a rotation height `h_b` (epoch `E`), the following runs in
  order:
  1. At a boundary, promote the bridge keys pending for `E+1`.
  2. Compute `M' = members(E+1)` (boundary) or `members(E)` (fault or
     heartbeat block).
  3. With `g` the current generation and `T = creation_time_ms(h_b)`, create
     `g+1` iff any of these holds:
     - a) **forced**: any nonzero address of `g` is no longer its peer's
       active non-faulted key (rotation, revocation, fault), or
       `unusable(g) > n_g − t_g`, where `unusable` counts `g`'s slots that are
       zero or whose peer is not in the next roster;
     - b) **membership change** (boundaries only): `M' ≠ g.members`, comparing
       the `(peer, address)` pairs, so replacing one keyless validator with
       another also counts. There is no minimum interval: every boundary at
       which a validator joins, leaves or gains or changes a key starts a new
       generation;
     - c) **heartbeat**: `T − g.valid_from_ms ≥ roster_max_age_ms`, at any
       rotation height.

  `g+1` gets members `M'`, `valid_from_ms = T`,
  `valid_until_ms = T + roster_validity_ms`, `activation_height = h_b + 1` and
  `threshold = ⌊2n/3⌋+1`, and `g.handoff_height = h_b`.
- The generation that signs height `h` is the generation with the greatest
  `activation_height ≤ h`. The rotation height `h_b` is signed by `g` and
  carries `nextRosterDigest = digest(g+1)`.
- A generation with fewer than `t` nonzero members is **inert**: its subjects
  are recorded but can never be attested, `RecordSccpMessage` is refused while
  it signs (§4.4), and no deployment can be pinned to it (§4.14.3). Rule (a)
  replaces it at the next rotation height.
- If the schedule lacks an input of `h` (the committee of `h`, or of `h + 1`
  at a boundary), or a roster size falls outside 4..=31, the hook fails closed
  for SCCP: no generation change, event
  `SccpRosterDerivationFailed`, and `RecordSccpMessage` is refused until a later
  rotation height succeeds. Block execution itself is not failed. While
  derivation fails, `g` stays current past any membership change and past its
  heartbeat. This extends the membership lag of §4.3.3 and §9.10 and is an
  exception to the guarantee of §5.1.5: `g`'s members may include peers that
  left the committee before earlier boundaries, and the next handoff is
  signed by `g` as it stands.

A zero-address slot counts in `n` but can never sign. Rule (a) replaces a
generation at the next rotation height once too many slots are unusable.
Between rotation heights, liveness requires `t` online attestors.

#### 4.3.3 Churn and handoff liveness

Validators join and leave under the consensus rules, and SCCP samples the
scheduled committee at rotation heights (§4.3.2). SCCP adds no bond, no
withdrawal delay, no seat-change batching and no hook in staking;
`FinalizePublicLaneUnbond` and every other staking instruction are
untouched.

- **Joining.** A node running with role `validator` registers its bridge key as
  soon as its peer is registered (§4.9). The core schedules the validator into
  the committee two heights after the block that registers its peer (or at its
  consensus key's later activation height), at any height
  (`specs/sumeragi.md` §10.1), and SCCP picks it up at the next rotation
  height. A key registered during epoch `E` is active from `E+1`, and
  the boundary of `E` promotes pending keys before it computes `members(E+1)`
  (§4.3.2 step 1), so a validator normally enters its first boundary
  generation with a key. A validator in a generation without an active key
  (for example a fault or heartbeat generation created in the epoch it joined)
  holds a zero slot until the boundary at which its key is promoted, which
  starts a new generation by rule (b).
- **Leaving.** A validator leaves the committee two heights after the block
  that unregisters its peer, at any height (`specs/sumeragi.md` §10.1). SCCP
  samples the committee only at rotation heights (§4.3.2), so the current
  generation `g` keeps a departed member's slot until a rotation height
  replaces `g`: by rule (b) at the next boundary, by rule (c) at the
  heartbeat, or by rule (a) earlier once unusable slots exceed `n_g − t_g`.
  The handoff at a rotation height `h_b` is signed by the outgoing generation
  `g`, whose members were sampled when `g` was created, so `g` can include
  peers that have left the committee since and are not validators at `h_b`
  (§13 item 9). Their attestors keep signing as observers while they run
  (§4.9), but nothing obliges them to. A member's obligation ends with the
  subjects at heights `≤` the handoff height of its last generation. While
  the derivation fails closed (§4.3.2), `g` also stays current past later
  boundaries, and this window grows.
- **Liveness assumption.** Destinations follow `g → g+1` only after `t`
  members of `g` sign `h_b`. SCCP assumes that `t` nonzero members of `g` sign
  `h_b` within `attestation_stall_ms` of its durable finality. Unless `g` is
  inert, rule (a) guarantees that `g` had at least `t` nonzero slots whose
  peers were in the roster at the last rotation height before `h_b` (members
  may have left since, see Leaving), and `h_b`'s own Commit QC was produced by
  at least `2f+1` validators of `E`. Zero slots never sign, the QC signers need not be the
  key holders, and an inert generation (§4.3.2) cannot sign at all, so this
  is an assumption, not a consequence: it
  asks that `t` of `g`'s key-holding validators keep their nodes up for a few
  blocks after the boundary. The attestor signs rotation subjects first and
  immediately, signs its pending handoffs before a graceful shutdown, and
  keeps signing its generations' subjects after its peer leaves the roster for
  as long as it runs (§4.9).
- **Stalled handoff.** If `h_b` is still unattested at the first block whose
  time is at least `attestation_stall_ms` after `h_b`'s, core emits
  `SccpHandoffStalled { height: h_b, generation: g }`, and Torii lists it
  (§6) with a `stalled` flag it computes from the latest block time. Stored
  signatures can still complete it later. If it is never completed,
  destinations on `g` cannot rotate past `g`: they keep
  minting what `g` attested until `g` expires, then freeze, and their in-flight
  value is refunded through voids (§4.16); the Parliament registers new
  revisions pinned to a current generation. Taira-side recording is not
  blocked by a stalled handoff of a previous generation (§4.4 step 2), and
  wallets refuse to send to a destination whose rotation chain to the current
  generation is broken (§7.1).

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
   `Bidirectional` (§4.14.2), `r = expected_revision`, and
   `destination_paused(r)` is false (§4.14.6).
2. Attestation liveness: the generation that signs the current height is not
   inert (§4.3.2), and the most recent subject signed by that generation with
   `timestamp_ms ≤ creation_time_ms(block) − attestation_stall_ms`, if any, is
   attested. This
   prevents locking funds that cannot be attested. A stalled handoff of an
   earlier generation does not block recording (§4.3.3).
3. `a = taira_units(amount)` is exact (§0), `a ≥ min_outbound_amount`, and
   `a < 2^96` for TON.
4. The authority's `AccountAddress` bytes are at most 1024 bytes.
5. `recipient` is valid for the target codec (§3.1) and passes every recipient
   rule the destination enforces (§5.1.3):
   - EVM/BSC/TRON: nonzero, and not the revision's contract address;
   - TON: workchain 0, nonzero account id, and not the minter account.
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
12. Allocate `commitment_index` = the number of leaves already recorded in
    this block. A failed transaction releases its indices by state rollback.
13. Insert:
    - `sccp_outbound_messages[message_id] = SccpOutboundMessageRecordV1
      { network, revision, nonce, height, commitment_index, deadline_ms,
      sender: AccountId, amount: a, payload, leaf, status: Recorded }`;
    - `sccp_block_leaves[(height, commitment_index)] = Transfer(message_id)`;
    - `sccp_outbound_by_nonce[(network, revision, nonce)] = message_id`.
14. Emit `SccpMessageRecorded { message_id, network, revision, nonce, height,
    commitment_index, deadline_ms }`.

Ordinary fees apply. Taira cannot observe mints; the destination's consumed set
is authoritative (§5). A record leaves `Recorded` only through a proven void
(§4.16); a minted record stays `Recorded`.

Contract-originated SCCP sends (Kotodama) are not part of v1: Kotodama has no
SCCP builtin, and the IVM host rejects every syscall `0xA0` operation tag
other than `1=SubmitBallot` with `PermissionDenied`, so it executes no
`RecordSccpMessage`. The `0xA0` ABI argument text still lists
`2=RecordSccpMessage` until `TODO(ws45)` removes it (§11). The post-execution
root (§4.5) would support contract-originated sends safely later.

### 4.5 Block commitment and history (post-execution)

The block header carries no SCCP root: the commitment root of a block exists
only in its post-execution world state.

All SCCP instructions are routed to the universal dataspace and execute
serially in one execution context, so nonce assignment and `commitment_index`
allocation are deterministic. Due Parliament certificates are enacted at block
start (`execute_due_parliament_certificate_v1`), before the block's
transactions, so the control leaves of a block precede its transfer leaves.

```
sccp_block_leaves: (u64 height, u32 commitment_index) → SccpLeafRefV1 =
    | Transfer(message_id)                              // §4.4
    | Control { network, revision, control_nonce }       // §4.14.6
```

In `ValidBlock::finalize_owned_execution_metadata`
(`crates/iroha_core/src/block/post_execution_tail.rs`), with the height inputs
of `h` (§4.3.2), after all transactions of block `h` have executed and before
the output seal:

1. Read the applied leaf outbox `sccp_block_leaves[(h, ·)]` and assert that its
   indices are exactly `0..m`. A gap is an execution invariant violation and
   fails the block. If `m > 0`, compute `root` per §3.4 over the stored leaves
   of the referenced transfer and control records, append
   `history_leaf(h, root, m)` to the accumulator (§3.5), and write
   `sccp_block_commitments[h] = { root, message_count: m, history_index }`.
2. If `h` is a rotation height, apply bridge-key promotion and the roster rule
   (§4.3.2).
3. If `m > 0`, `h` is a boundary, or step 2 created a new generation at `h`,
   write the attestation subject (§4.6). A heartbeat or fault block whose
   derivation failed closed writes no subject of its own, so a failing
   derivation cannot create a subject per block.
4. Run the pruning step (§4.10).

These writes are part of the post-state covered by the execution commitment
of the block's commit certificate (its ordinary-write and post-state roots,
`specs/sumeragi.md` §4.1), so the root is certificate-authenticated with no
vote-wire change.

### 4.6 Attestation subjects

```
sccp_attestation_subjects: u64 height → SccpAttestationSubjectV1 {
    height, epoch, timestamp_ms,
    sccp_root: [u8; 32], message_count: u32,
    history_root: [u8; 32], history_size: u64,
    generation: u64, roster_digest: [u8; 32], next_roster_digest: [u8; 32],
}
sccp_attestation_status: u64 height → SccpAttestationStatusV1 {
    signer_bitmap: u32, attested_at_height: Option<u64>,
}
```

The statement of height `h` is the subject plus `blockHash = block_hashes[h]`.
The hash is known once `h` is committed, and attestation instructions
necessarily execute at a later height. `statement_digest(h)` is the §3.6
attestation digest under the live `NetworkId`. Event
`SccpSubjectCreated { height, generation, message_count, rotation }`.

### 4.7 Attestation transport decision

Chosen: signatures travel as a self-authenticating instruction in ordinary
transactions (§4.8), submitted by each validator node's attestor (§4.9) from
the signing bridge key's own account (§4.2.1).

| Option | Durable & state-derived | Consensus coupling | Verdict |
|---|---|---|---|
| Instruction in later blocks | yes: stored in world state, identical on every peer | none (ordinary tx path) | **chosen**; latency +1–2 blocks (4–8 s) |
| P2P gossip (a new consensus message kind) | no, unless also embedded by the proposer, which reintroduces proposer-authored SCCP data | new message kind + reducer ingress | rejected |
| Sumeragi commit-vote extension (KAGEMUSHA seal pattern) | yes (in the commit certificate) | changes the Sumeragi vote and certificate wire; a validator without a bridge key would stall SCCP blocks | deferred optimization (§12); the digest is unchanged by it |

### 4.8 `SubmitSccpAttestationsV1`

```
SubmitSccpAttestationsV1 {
    entries: Vec<SccpAttestationSignatureV1 { height: u64, signer_index: u8, signature: [u8; 65] }>,
}
```

Validation runs cheap checks before any cryptography and stops at the first
invalid entry (the instruction then fails):

1. `1 ≤ len(entries) ≤ max_attestation_entries_per_instruction`; entries are
   sorted by `(height, signer_index)` without duplicates.
2. For every entry:
   - `height < current height` and `sccp_attestation_subjects[height]` exists;
   - `signer_index < n` of the subject's generation, and the member at that
     index is nonzero;
   - the transaction authority is `account_of` that member's key: its single
     secp256k1 controller has exactly the member's address (§3.8, §4.2.1).

   A transaction therefore carries only signatures of its own key.
3. For every entry, in order: the signature satisfies §3.8 and recovers that
   member's address from `statement_digest(height)`.

Execution, per entry: if bit `signer_index` of the status bitmap is already
set, the entry is skipped (ECDSA signatures are not unique, and only the first
valid one is stored). Otherwise store
`sccp_attestation_signatures[(height, signer_index)] = signature`, set the bit
and emit `SccpAttestationSigned`. When the bitmap first reaches
`popcount ≥ threshold`, set `attested_at_height` and emit
`SccpBlockAttested { height, generation, signer_bitmap }`. Signatures beyond
threshold are still stored (up to `n`). If no entry stored a new signature, the
instruction fails with `SccpAttestationsAllRecorded`.

Only canonical signatures can ever be stored, because Taira recomputes the
digest from its own state.

**Authority, fees and admission.** The authority MUST be the account of the
signing member's bridge key (checked per entry in step 2). That account was
registered implicitly with the key (§4.2.2) and needs no funds.
`SubmitSccpAttestationsV1` joins
`nexus_protocol_fee_exempt_instruction` (`crates/iroha_core/src/executor.rs`).
A transaction is fee-exempt only if it consists of exactly one such
instruction, and the exemption is conditional on success: a failed exempt
transaction is charged the ordinary fee. Transaction admission (Torii ingress
and P2P transaction gossip admission, via the `ordinary_transaction_ingress`
pattern) MUST:

- run checks 1–3 against committed state;
- keep a queue index of pending `(height, signer_index)` entries, and reject a
  transaction unless it adds at least one entry that is neither recorded nor
  queued;
- admit at most one pending exempt `SubmitSccpAttestationsV1` transaction per
  authority. The pending limit is per exempt kind (§4.19), so the same
  bridge-key account can also have a keeper advance (§4.13.4) or its own key
  registration pending at the same time.

Proposers include at most `max_exempt_transactions_per_block` exempt SCCP
transactions per block, and block validation enforces the cap. The instruction
is added to the wire-id registry, the Initial-executor admitted list, and the
validation-fee classification as "no DS effect".

### 4.9 Node attestor

An irohad component (`crates/irohad/src/sccp_attestor.rs`), modeled on the
Soracloud runtime mutation sink. It is enabled by default and needs no
operator input: a validator installs, starts and leaves exactly as it would
without SCCP.

- **Key directory and generation.** Bridge keys live in `key_dir`, by default
  `<kura.store_dir>/sccp/bridge-keys` (derived from the Kura store directory
  like the snapshot store directory, and overridable in `iroha_config`). The
  directory is created `0700`; each key is one owner-only (`0600`) regular
  file `<address-hex>.key` holding a headered Norito frame
  `SccpBridgeKeyFileV1 { secret: [u8; 32], created_at_ms: u64 }`; symlinks and
  other modes are refused. On start and at every epoch boundary, if SCCP
  exists, the peer is not barred, and the directory holds neither the peer's
  active or pending key nor an unregistered key, the node generates a fresh
  secp256k1 key from the OS CSPRNG,
  writes it atomically (temporary file, `fsync`, rename, directory `fsync`)
  and logs its address. Secrets are zeroized after use. A wiped store loses its
  keys; the node then simply generates and registers a new one (§4.3.2 rule (a)
  handles the lost slot).
- **Key classification.** A key whose address this peer owns in
  `sccp_bridge_key_owners` (active, pending or retired) is used for signing. A
  key whose address nobody owns is a registration candidate; only the newest
  one (by `created_at_ms`) is registered. A key owned by another peer is ignored with an error and
  the health gauge `sccp_attestor_foreign_key`.
- **Automatic registration.** While `auto_register` is true (the default), the
  node's role is `validator`, SCCP exists, its peer is registered and not
  barred, and no active or pending key of its peer equals its newest local
  key, the attestor builds `SetSccpBridgeKeyV1` with
  `binding_nonce = next_binding_nonce(peer)` and
  `activation_epoch = current_epoch + 1` from committed state, signs the
  binding with the node's consensus key, the PoP and the transaction with the
  bridge key (authority `account_of(key)`), and pushes it into its local queue.
  It retries once per epoch until the key is pending or active. This starts as
  soon as the peer is registered, so the key is normally active by the first
  boundary generation that includes the peer (§4.3.3). It is fee-exempt on success (§4.2.3); a barred peer reports
  `sccp_attestor_barred` until the Parliament clears the fault.
- **What it signs.** For each newly durably final height (§0), and for every
  height with a subject whose generation contains an address in the node's key
  set and whose slot bit is not yet set, the attestor computes the statement
  from **local durably final state and Kura**. It checks that the height is
  durably final and that the certified `post_state_root` matches the state it
  reads, then signs (§3.8). It never signs any other height. The bridge key
  signs nothing but three inputs: `SccpAttestation` digests derived this way;
  the `SccpBridgeKey` proof-of-possession digest (§3.6) of its own
  registration, built from committed state; and the transactions the node
  builds itself (attestations, its own key registration and keeper advances,
  §4.13.4).
- **Priority.** Rotation subjects (`next_roster_digest ≠ 0`) are signed and
  submitted first, as soon as they are durably final, then other subjects
  oldest first. A handoff is the only statement that can strand destinations
  if it is late (§4.3.3).
- **Future-dated rotations.** It refuses to sign a rotation subject whose
  `timestamp_ms` exceeds the local wall clock by more than
  `max_clock_drift_ms`, because a future-dated rotation would extend roster
  validity on destinations. It logs the refusal and raises a health gauge.
- **Submission.** It batches all pending entries of one key into one
  `SubmitSccpAttestationsV1` transaction per block (sorted, ≤ the parameter
  bound), signed by that key as `account_of(key)`, and pushes it through
  `AcceptedTransaction::accept` into the local queue. Entries still unrecorded
  after `resubmit_after_blocks` are resubmitted. Submissions are fee-exempt on
  success (§4.8), so the account holds no funds.
- **Key set and cleanup.** It keeps every owned key until every generation
  containing it has expired plus 1 d, then zeroizes and deletes the file. It
  picks the key per subject generation, so a validator that rotates its key
  still signs the handoff with its old key.
- **Leaving and shutdown.** After its peer leaves the roster the node runs as
  an observer and keeps signing every subject its generations cover, including
  the handoff (§4.3.3). On a graceful shutdown the attestor first signs every
  pending subject of its keys, submits them, and delays the node's exit until
  they are recorded or `shutdown_grace_ms` elapses, logging any handoff it
  could not complete.
- **Failure isolation.** If the key directory is unusable, the attestor is
  inert and health reports `sccp_attestor_unconfigured`. The node itself does
  not abort, because consensus must not depend on SCCP.
- **Liveness.** Torii capabilities report each member's last signed height,
  and telemetry exports it.

Configuration (user → actual → defaults, file-only, no environment variables;
every default works without editing):

```toml
[sccp.attestor]
enabled = true                      # default true
key_dir = ""                        # default: "<kura.store_dir>/sccp/bridge-keys"
auto_register = true                # submit SetSccpBridgeKeyV1 automatically (§4.2.3)
max_entries_per_transaction = 64    # ≤ on-chain bound
resubmit_after_blocks = 3
max_clock_drift_ms = 3600000
shutdown_grace_ms = 30000
```

The Taira launcher passes nothing for SCCP. An operator MAY point `key_dir`
elsewhere or pre-place a key file there; that override is the only optional
step.

### 4.10 Storage and pruning

| Map | Retention |
|---|---|
| `sccp_outbound_messages`, `sccp_block_leaves`, `sccp_outbound_by_nonce` | permanent (one record per value transfer, ≤ 4 KiB payload) |
| `sccp_control_messages` | permanent (one record per enacted destination control, §4.14.6) |
| `sccp_block_commitments`, history leaves and peaks | permanent (~48 B per SCCP block) |
| `sccp_attestation_subjects`, `sccp_attestation_status` | permanent (~250 B per SCCP block or rotation height) |
| `sccp_attestation_signatures` | pruned at the first block whose `creation_time_ms` exceeds the subject's `timestamp_ms + attestation_retention_ms`, **except** rotation subjects (`next_roster_digest ≠ 0`), which are kept until `valid_until_ms` of the outgoing generation plus 86 400 000 is older than the block time |
| `sccp_rosters`, `sccp_bridge_key_owners` | permanent |
| `sccp_inbound_messages` | permanent (one record per inbound message) |
| `sccp_attestation_faults` | permanent |
| light-client sets / checkpoints | §4.13.1 |
| `sccp_governance_revisions` | permanent (one counter per SCCP governance subject, §4.14.3) |
| Parliament proposals, attempts and certificates | owned by the Parliament pipeline, which keeps them per its own rules |

Pruning runs in the post-execution hook with a per-block work bound of 1 024
deletions. Pruned signatures stay in Kura block history, inside the
`SubmitSccpAttestationsV1` transactions, and Torii MAY serve them from there.
Old messages remain finalizable through the history root of any retained
attestation (§3.5).

### 4.11 Equivocation evidence and slashing

```
SubmitSccpAttestationFaultV1 {
    statement: SccpAttestationStatementV1,   // all 10 §3.6.1 fields
    signature: [u8; 65],
}
```

Validation requires three things:

- the signature satisfies §3.8 over the EIP-712 digest of `statement` under
  Taira's live domain;
- the recovered address is in `sccp_bridge_key_owners`;
- the statement is **faulty**.

A statement is faulty in one of three cases. Every height below the executing
height is certified and can never revert: the Sumeragi core executes `h+1`
only after the commit certificate of `h`, against its certified post-state
(`specs/sumeragi.md` §4.1, §10.2), although `h` may not yet be applied on the
executing node. The executing state therefore holds the canonical statement
of every lower height that has a subject.

- `statement.height ≥ current height`: honest attestors sign only durably
  final heights.
- No subject exists at `statement.height`.
- The subject exists, and a field of `statement` differs from the canonical
  statement (the subject plus `block_hashes[height]`).

Execution:

1. Record `sccp_attestation_faults[(address, height)] = { peer, statement_hash,
   reported_at_height }`. A duplicate fails with `SccpFaultAlreadyRecorded`.
2. Mark the key `faulted` and set the peer's
   `barred = Some(SccpFaultRefV1 { address, height })`, overwriting an older
   bar: the peer cannot register a new bridge key until the Parliament enacts
   `ClearBridgeKeyFault` naming this newest fault (§4.14.3).
3. Make the current block a rotation height (§4.3.2), so the key leaves the
   roster immediately rather than at the next epoch boundary.
4. Emit `SccpAttestationFault`.

**Fees and admission.** The instruction is fee-exempt only when it records a
new fault. Admission verifies it against committed state and deduplicates it
by `(address, height)` against state and the queue. It counts toward the
per-block exempt cap. Anyone may submit, including evidence copied from
destination-chain calldata.

**Phase 2 (TODO):** apply the existing indexed consensus penalty
(`apply_indexed_consensus_slash_to_validator`, after `slashing_delay_blocks`)
to the validator bonded under the faulty peer. Validators exit freely
(§4.3.3), so a penalty reaches only stake that is still bonded when it applies;
SCCP adds no bond to extend that. Evidence against an exited validator still records the
fault, evicts the key and bars the peer. On Taira today the unbonding delay is
0, so the time bounds of §9.9, not slashing, are the operative protection.

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
   `enabled` does not affect proving.
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

Effect: insert `sccp_inbound_messages[message_id] = SccpInboundRecordV1
{ network, revision, payload, source_locator, proven_at_height, fee_due,
status: Pending }` and emit `SccpInboundProven`. Then attempt settlement
(§4.12.3). If settlement cannot complete, the record stays `Pending` and the
instruction still succeeds.

`SettleSccpV1 { target: Inbound(message_id) | Refund { network, revision, nonce } }`
retries a `Pending` inbound settlement or outbound refund (§4.16) without a
proof. Anyone may submit it, and it pays the ordinary fee. It fails if it
changes nothing, so retry spam pays.

#### 4.12.2 Source event binding per chain

| Source | Evidence of the burn | Normalized fields come from |
|---|---|---|
| ETH, BSC | Receipt log with `status = 1`, `address` = deployment, `topics = [0x79ac1cc6…, message_id, word(sender)]`, `data = abi.encode(uint64 nonce, bytes payload)` | log topics and data |
| TRON | The `TriggerSmartContract` transaction with `contractRet = SUCCESS`, `contract_address` = deployment (21 B), `call_value = 0`, `call_token_value = 0`, and data = selector `0xebfc6ca8` ‖ the canonical `abi.encode(bytes recipient, uint256 tokenAmount, uint64 expectedNonce)`. The contract reverts on any other encoding (§5.1.7). TRON logs are not header-committed, so the existing transaction-inclusion rule over the full `Transaction` protobuf is reused. Every field that cannot change the executed call is accepted: the memo (`raw_data.data`), `Permission_id` (multisig and active permissions), `fee_limit`, `ref_block_*`, `expiration`, `timestamp`, and every `ret` field other than `contractRet` | `sender = owner_address`; `nonce = expectedNonce`; `amount = tokenAmount`; `recipient`. The remaining fields are route constants; Taira rebuilds the payload and requires byte equality |
| TON | A transaction of the deployment (minter) account with successful compute and action phases and an external-out message whose body is `sccp_transfer_to_taira` (§5.3.4) | out-message body |

#### 4.12.3 Settlement

Settlement proceeds only when SCCP is enabled and revision `r` is
`Bidirectional` or `InboundOnly`. Otherwise the record stays `Pending`.
`Paused` holds it; `Retired` cannot hold one (§4.14.2).

1. Decode `recipient` (codec 3) as `AccountAddress` and derive the
   `AccountId`. If decoding fails, bounce (§4.12.5).
2. Bounce if the recipient can never be credited:
   - it is an SCCP escrow account;
   - its controller uses a signing algorithm or curve that account admission
     does not allow; or
   - transfer control deterministically refuses an XOR credit to it.
3. If the account does not exist, core registers `Account::new(recipient)`,
   with the same effect and validation-fee DS classification as
   `Register<Account>`, and emits `SccpRecipientRegistered`.
4. If `liability(r) < amount`, the record stays `Pending` and core emits
   `SccpInboundLiabilityShortfall`. A shortfall means the external side
   released more than Taira locked, which indicates a source-chain or verifier
   compromise. The response is `ReportSccpLightClientEquivocationV1` where
   evidence exists, and otherwise a Parliament-enacted `FreezeLightClient`.
5. Transfer `amount − fee_due` XOR from the route escrow to the recipient and
   `fee_due` to the fee sink of the Nexus fee policy. Set
   `liability(r) −= amount` and `status = Released { height }`. Emit
   `SccpInboundReleased`.

#### 4.12.4 Authority, fees and self-claim

Anyone may submit a proof and pay the ordinary fee. The recipient is fixed by
the payload, so relaying cannot redirect funds.

**Self-claim.** A recipient that holds no XOR can claim alone, with no faucet
or sponsor. A transaction is fee-exempt as a self-claim when all of the
following hold:

- its authority equals the payload's recipient `AccountId`;
- its instructions are exactly `[Register<Account>(authority)?,
  AdvanceSccpLightClientV1*, SubmitSccpInboundMessageV1]` or
  `[SettleSccpV1::Inbound]`;
- admission pre-verifies it against committed state. For a proof, the
  included advances and the proof verify within the committed `sccp` limits and the
  message is not yet proven. For a settle, the record is `Pending`;
- the payload amount exceeds `inbound_self_claim_fee`;
- the queue holds at most one pending exempt self-claim per authority and per
  `message_id`;
- it counts toward `max_exempt_transactions_per_block`.

Execution sets `fee_due = inbound_self_claim_fee`, which is charged once, at
release. The existing `allows_unregistered_authority` rule already admits
`Register<Account>(self)` from an absent authority. A multisig recipient cannot
self-claim, but any funded account can claim for it.

#### 4.12.5 Bounce

If settlement step 1 or 2 bounces, the value returns to the source-chain
sender. A bounce requires `liability(r) ≥ amount`; otherwise the record stays
`Pending` with a shortfall event. The target revision `r'` is the route's
`Bidirectional` revision if one exists and `liability(r') + amount ≤
max_wrapped_supply(r')`; otherwise `r' = r`. Set `liability(r) −= amount` and
`liability(r') += amount`. Record an outbound message per §4.4 steps 9–14 on
`r'` with `amount` = the inbound amount, `sender` = the escrow account's
`AccountAddress` and `recipient` = the inbound `sender`. The activation,
liveness, minimum-amount and cap checks of §4.4 steps 1–6 are skipped (the cap
of `r'` was checked above). The inbound record becomes
`Bounced { bounce_message_id }`. Emit `SccpInboundBounced`. A bounce that is
later voided moves its amount to `stranded(route)` (§4.16).

### 4.13 Inbound light clients

Inbound finality is permissionless light-client state. World state stores
**authenticated validator sets** of each source chain with validity ranges,
plus finalized checkpoints. Each inbound or void proof carries its own finality
evidence, verified against a stored set. The Parliament only initializes,
re-initializes, freezes and installs trusted checkpoints (§4.14.3); every
advance is permissionless.

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
```

- **Sets** are retained until 180 days after they are superseded.
- **Checkpoints** are written idempotently by every accepted advance, proof and
  backfill.
- **Checkpoint retention.** A checkpoint at source height `s` is kept
  permanently if either:
  - it is the lowest checkpoint recorded in its stride bucket `⌊s / stride⌋`
    (stride: ETH 8 192, BSC 8 192, TRON 1 200 blocks; TON keeps none,
    because `OldMcBlocksInfo` covers old blocks); or
  - it was installed by the Parliament.

  Other checkpoints are pruned 30 days after recording. Permanent checkpoints
  cost a few MB per year per chain at most.

#### 4.13.2 Instructions and weak subjectivity

| Instruction | Permission | Effect |
|---|---|---|
| `InitializeLightClient` | Parliament-enacted action only (§4.14.3) | Installs params and a bootstrap set (weak-subjectivity checkpoint). Used when a route is first registered, after a freeze, after staleness and after every Taira reset |
| `AdvanceSccpLightClientV1 { network, expected_state_hash: Option<[u8;32]>, advance: SccpLcAdvanceV1 }` | anyone; ordinary fee (fee-exempt on success from an active or pending bridge key's account when it moves the head, §4.19) | Stores the next set(s) and checkpoints. Idempotent: re-proving stored data is `Ok` with no change, so concurrent wallets do not fail |
| `AdvanceSccpLightClientV1` with `advance = Backfill { segment }` | anyone; ordinary fee | Proof-carrying backwards ancestry: ≤ 256 parent-linked headers ending at a stored checkpoint. Records the segment's first header as a checkpoint (`origin: Backfill`) |
| `ReportSccpLightClientEquivocationV1 { network, a, b }` | anyone; ordinary fee | Two quorum-valid conflicting records (same period/epoch/key block/height, different content) set `frozen`. An advance that conflicts with stored data is rejected with a pointer to this instruction |
| `InstallTrustedCheckpoint` | Parliament-enacted action only (§4.14.3) | Installs a checkpoint at any source height, exempt from the weak-subjectivity bound. It recovers burns that are too old for §4.13.5 (`origin: Parliament`) |
| `FreezeLightClient` | Parliament-enacted action only (§4.14.3) | Sets `frozen` without equivocation evidence, for example on a suspected source-chain or verifier compromise |

**Weak subjectivity.** An advance or a proof is accepted only if its signing
set is fresh: the set is current, or was superseded (by source time) less than
`params.ws_bound_ms` before the Taira block time. Old events are proven by
ancestry from a fresh finality point or from a stored checkpoint, never by
stale keys. A light client whose newest set has aged beyond `ws_bound_ms`
cannot advance and needs re-initialization (§4.13.4). **Fork bound:** the
source-chain fork schedule and its `supported_until` (the last fork the
verifier supports) are part of the compiled chain profile of the running
release, read at execution time and never stored in `params`. They are bound
into the consensus policy hash together with the committed `sccp` limits, so peers
on releases with different schedules cannot silently diverge. Any advance or
proof signed under a fork beyond `supported_until` fails closed until a Taira
release extends the compiled profile; once the release is running, the same
light client continues with no Parliament action, freeze or re-initialization.

#### 4.13.3 Per chain

| Chain | Stored set | Advance | Inbound / void proof | `ws_bound_ms` |
|---|---|---|---|---|
| Ethereum | Sync committee per period (current and next), learned **only** from finalized updates. The fork schedule is compiled into the chain profile with `supported_until` (last supported fork epoch), not stored (§4.13.2) | ≤ 16 `LightClientUpdate`s. Each MUST carry a finality branch and satisfy `3·popcount(sync_committee_bits) ≥ 2·512` (≥ 342 participants) and `signature_slot > attested.slot ≥ finalized.slot`. It is verified against the stored committee of `period(signature_slot)`, with the domain fork version of `compute_epoch_at_slot(max(signature_slot, 1) − 1)`, by fast-aggregate BLS. A `next_sync_committee` branch is accepted only when the attested and finalized headers share a period | A finality update under exactly the same rules gives finalized execution block `E`. Ancestry from the event block `B`: `SameBlock` \| `HeaderChain` (≤ 256 parent-linked execution header RLPs from `B` to `E` or to a stored checkpoint) \| `HistoryContract` (EIP-2935 account and storage proof under `E`'s state root, `1 ≤ E−B ≤ 8191`; needs state at `E`). Then the event header RLP (keccak = hash, fields read by index) and the receipt MPT | 14 d |
| BSC | Parlia validator set (address, BLS key) with the epoch-checkpoint height where it took effect, and turn length | **Skipping:** only the set-transition epoch-checkpoint headers. Each carries the new set in `extraData` and is finalized by a fast-finality vote attestation (in a descendant within ≤ 256 headers) signed by at least `⌈2n/3⌉` of the previous stored set. If the set is unchanged, one later header with such a vote advances `latest_finalized`. Cost is O(set changes), not O(epochs) | Event header `B` plus a vote attestation finalizing `B` (in a descendant within ≤ 256 headers) signed by the stored set covering `B`, which must be fresh; then the receipt MPT | 5 d (BSC unbonding is 7 d) |
| TRON | The active witness set of each maintenance period (27 witness accounts with signing keys) and threshold 19 of those 27 | Header segments of ≤ 128 parent-linked headers. A segment need not link to the stored head; it authenticates itself. A header is solid when ≥ 19 distinct members of the active set of its maintenance period produced headers after it. The active set of period `p` is the set of distinct producers of the first 27 slots after `p`'s maintenance boundary, accepted once those headers are solid under period `p−1`'s set. Witnesses outside the set are evicted at the boundary. A witness's rotated signing key is learned from its solid headers | The segment in which `B` becomes solid, plus the transaction path in the SHA-256 promote-odd binary Merkle tree under `txTrieRoot` (not an MPT). Older events: unsigned `raw_data` headers parent-linked from `B` to a stored checkpoint (≤ 1 200 per proof, or `Backfill`) | 7 d (TRON unstaking is 14 d) |
| TON | Validator epoch per key block (config 34, 28, 15) | ≤ 16 key-block hops, each signed by the current subset, with `prev_key_block_seqno` = stored latest key block | Any masterchain block signed by the epoch named by its `prev_key_block_seqno`, or an `OldMcBlocksInfo` back-link from a fresh block. Then the shard registration, a ≤ 32 shard-block `prev_ref` walk (both predecessors after a merge; `before_split` allowed), and the account transaction and out-message | `utime_until + stake_held_for − margin` |

**BSC details.** A stored set is keyed by the height of the epoch checkpoint that
announced it and records the set that finalized that checkpoint. It covers vote
targets from `checkpoint + (n_prev / 2 + 1) · turn_prev` (Parlia switches after
`minerHistoryCheckLen` blocks of the previous set, and checks the votes on a
target against the set of the target's parent). A finality proof is one
attestation `(S → S + 1)`: it names the covering set, and the set's successor
when it is not the newest set, so the target must precede the successor's first
covered height. A superseded set stays fresh until `ws_bound_ms` after its
successor's checkpoint time. The newest set stays fresh until `ws_bound_ms`
after the newest finalized block, so the keeper's unchanged-set advances keep it
fresh. A transition step starts at the announcing checkpoint and must be
attested by the newest set before the new set takes over. Any other epoch
checkpoint above the newest set's checkpoint, in an advance, proof or evidence
record, must announce the newest set, so every transition is learned in order.
The bootstrap carries the trusted checkpoint and the checkpoint one epoch
earlier, whose set size and turn length fix the new set's first covered height.
Proofs name sets from `GET /v1/sccp/light-clients/{network}/sets`.

**TRON details.** Maintenance periods follow the compiled grid
`T_p = p · 21 600 000` ms (00:00, 06:00, 12:00 and 18:00 UTC);
builders check it against `/wallet/getnextmaintenancetime`. A header belongs to
the period of its timestamp; the maintenance block (the first header at or after
`T_p`) is still produced by the outgoing set. A header `x` is solid when at least
19 distinct members of the set of `x`'s period signed later headers of the
segment with their stored keys. Set `p + 1` is learned only from a segment that
contains its maintenance block and parent and extends past the learning window
(the first 27 slots plus the two skipped slots): the window's distinct producers
(account and recovered signer), each solid under set `p`, at least 19 of them.
Periods cannot be skipped; each advance segment must make a header solid, and
the newest solid header becomes the checkpoint and head. A rotated witness key
is learned at the next boundary. A superseded set is fresh until `ws_bound_ms`
after its period ends. TRON burns are proven from the call itself: the
normalized event carries the caller and the canonical `transferToTaira`
arguments, and Taira rebuilds the payload from them (§4.12.2). A void proof
carries the destination's void call (`voidExpired*` binds by nonce).

**TON details.** A stored epoch is keyed by its key block's seqno and holds
config 34 (with the config-28 shuffle flag) and config 15 `stake_held_for`, read
from a proof of the key block's state rooted at its `state_update` new hash. A
masterchain block is verified under the stored epoch its `prev_key_block_seqno`
names: the masterchain subset for the block's catchain session (the first `main`
validators, shuffled when config 28 says so) must carry the block's
`validator_list_hash_short`, and signatures of more than two thirds of the subset
weight must verify (ordinary or Simplex transcripts). An epoch is fresh until
`(utime_until + stake_held_for) · 1000 − 1 h` (TON light clients store
`ws_bound_ms = 0`). A hop's key block must name the newest epoch; re-proving a
stored hop is a no-op. A proof walks from the shard block the anchoring
masterchain block registers for the minter's shard down to the event block
(`TON_MAX_SHARD_LINKS = 32`), and the event block's proof must reach the minter's
transaction, whose cell may be pruned there and is then supplied in full. The
normalized sender is codec 7 (`int32 0 ‖ account`). TON records no checkpoints.
The keeper looks for a new key block hourly.

Approximate advance traffic to stay fresh: Ethereum, one update per sync
period (~27 h, ~25 KB). BSC, one skipping advance per validator-set change
(about daily, ~3 KB). TRON, one segment per maintenance period (4 per day,
~20 KB each). TON, one key-block hop per validator round (~18 h, ~20–60 KB).

The per-chain checks are stateless functions in `iroha_sccp`: Ethereum in
`ethereum_native.rs` and `ethereum_source.rs`, TON in `ton_native.rs`, the
Parlia header, roster and vote-attestation primitives in
`light_client/bsc.rs`, and the TRON header, signature, transaction and Merkle
primitives in `light_client/tron.rs`.

Deployment code identity is not proven per transfer. EVM and TRON deployments
are verified off-chain by Parliament reviewers before the vote (§4.14.4), and
TON deployment addresses are recomputed by Taira at registration (§4.14.3).

#### 4.13.4 Liveness, keeper and recovery

- **Wallets.** Anyone may advance, and wallets advance as part of a claim.
- **In-node keeper.** An irohad component
  (`crates/irohad/src/sccp_attestor/keeper.rs`, config
  `[sccp.light_client_keeper]`) runs on validator nodes and is enabled by
  default. It is effective whenever the node holds an active or pending
  registered bridge key (§4.9), and needs no other setup. It reads each light
  client from local state. When
  `now − head.last_progress_taira_ms ≥ advance_after_ms` (default:
  `ws_bound_ms / 4`), it builds proof-carrying advances from its public RPC
  endpoints with the same `iroha_sccp_rpc` builders that wallets use (§8), and
  submits them from that bridge key's account, fee-exempt on success
  (§4.19). Admission keeps at most one pending exempt advance per
  `(authority, network)`, separate from the attestor's pending attestation
  batch on the same account (§4.8), and the proposer includes at most one
  exempt advance per network per block. It drops, with a warning, any built
  advance larger than `max_advance_bytes`. Its submissions are verified like
  anyone's, so a lying endpoint can only cause rejected advances. Default
  lists of free public RPC endpoints per chain are compiled into the
  `iroha_config` defaults; an operator MAY
  override them and MAY add per-endpoint secret headers read from owner-only
  files.

  Configuration (user → actual → defaults, file-only, no environment
  variables; every default works without editing):

  ```toml
  [sccp.light_client_keeper]
  enabled = true                  # default true; effective only while the node holds an active or pending bridge key
  advance_after_ms = 0            # 0 = ws_bound_ms / 4 of each light client
  poll_interval_ms = 60000        # how often local light-client state is checked
  request_timeout_ms = 10000      # per RPC request, with failover to the next endpoint
  max_advance_bytes = 262144      # larger built advances are dropped; ≤ the on-chain per-ISI bounds

  [sccp.light_client_keeper.endpoints]
  ethereum_execution = []         # empty = the compiled default list
  ethereum_beacon = []            # empty = the compiled default list
  bsc = []                        # empty = the compiled default list
  tron = []                       # empty = the compiled default list
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
  their own endpoints before the bodies endorse and the Policy Jury votes.
  `InstallTrustedCheckpoint` recovers burns older than §4.13.5 allows. A
  Parliament round takes at least about 1 100 blocks with the recommended
  Taira profile, and its wall-clock time depends on block production
  (§4.14.5). It fits inside the ETH, BSC and TRON `ws_bound_ms` but not always
  inside a TON bootstrap's freshness, so a TON initialization is proposed on
  its own (§4.14.5). Recovery is never immediate; the keeper exists so that
  recovery is rarely needed.
- **Wallet guard.** Torii reports freshness, the weak-subjectivity deadline,
  `supported_until` and claim windows (§6). Wallets refuse to burn on a lane
  whose light client is frozen, has less than 25 % of its weak-subjectivity
  bound left, or is within 7 days of `supported_until` (§7.2).

#### 4.13.5 Claim windows

A proof is recorded permanently once accepted (§4.12.1), so these windows bind
only the **prove** step. Wallets journal raw evidence and submit the proof as
soon as the source block is final.

| Chain | Guaranteed window with standard public RPC | Beyond it |
|---|---|---|
| Ethereum | Unlimited while execution nodes serve headers and receipts (post-merge history). The prompt path (≤ 27 h) uses `HeaderChain` or `HistoryContract` from a fresh finality update. Later claims use `Backfill` segments from the nearest permanent checkpoint, which is at most 8 192 blocks away while the light client is kept fresh (≤ 32 segments) | `InstallTrustedCheckpoint` |
| BSC | ≥ 5 d after the validator set covering `B` is superseded; sets typically stay unchanged for a day or more | `InstallTrustedCheckpoint` at `B` |
| TRON | ≥ 7 d after the maintenance period covering `B` ends | `InstallTrustedCheckpoint` + `raw_data` header chain |
| TON | Unlimited while liteservers serve the blocks (archive liteservers for old blocks) | — |

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
    initial_roster_generation: u64,
    initial_roster_digest: [u8; 32],   // pinned at registration
    activation: SccpRouteActivationV1,
    destination_frozen: bool,          // set by a proven frozen void (§4.16)
    destination_paused: bool,          // pause state of the latest control message (§4.14.6)
    next_control_nonce: u64,           // starts at 1
    max_wrapped_supply: u128,          // Taira units = token units; equals the contract cap
    liability: u128,
    next_outbound_nonce: u64,
    registered_at_height: u64,
}
SccpDeploymentV1 =
  | Evm  { address: [u8; 20], runtime_code_hash: [u8; 32] }      // ETH, BSC
  | Tron { address: [u8; 21], runtime_code_hash: [u8; 32] }      // 0x41-prefixed
  | Ton  { master_account: [u8; 32], minter_code: SccpTonCodeRefV1,
           wallet_code: SccpTonCodeRefV1, bucket_code: SccpTonCodeRefV1 }
SccpTonCodeRefV1 { hash: [u8; 32], depth: u16 }   // cell representation hash and depth
sccp_destination_words: [u8; 32] → (SccpNetworkV1, u32)   // unique across all routes and revisions, never freed
sccp_governance_revisions: SccpGovernanceSubjectV1 → u64  // §4.14.3; absent = 0
```

#### 4.14.2 Activation states

`Staged` → `Bidirectional` ⇄ `Paused`; `Bidirectional`/`Paused` →
`InboundOnly` → `Retired`. Every transition except the automatic frozen-void
transition is a Parliament-enacted action (§4.14.3).

| State | Record | Inbound proof | Inbound settlement | Void proof | Refund |
|---|---|---|---|---|---|
| `Staged` | no | no | no | no | no |
| `Bidirectional` | yes | yes | yes | yes | yes |
| `Paused` | no | yes | held `Pending` | yes | held `Pending` |
| `InboundOnly` | no | yes | yes | yes | yes |
| `Retired` | no | yes (cannot occur, see below) | no | yes (cannot occur) | no |

- At most one revision per route is `Bidirectional` or `Paused`.
  `SwitchRevision` atomically moves the old revision to `InboundOnly` and a
  `Staged` successor to `Bidirectional`.
- `Retired` requires `liability(r) = 0` and no `Pending` inbound record or
  refund for `r`. Zero liability means every recorded message was either
  burned back and released, or voided and refunded, so the destination supply
  is zero (§4.15) and no burn on a retired deployment can exist. Minted
  messages keep status `Recorded` forever, because Taira never observes mints.
- A proven frozen void (§4.16) sets `destination_frozen` and moves `r` from
  `Bidirectional` or `Paused` to `InboundOnly` automatically.
- The Taira-side state and the destination's minting pause are independent:
  `Paused` stops Taira from recording, while `destination_paused` (§4.14.6)
  stops the destination from minting. A pause proposal normally carries both
  actions. `RecordSccpMessage` requires both to be clear (§4.4).

#### 4.14.3 Governance: the Parliament pipeline

SCCP has exactly one governance authority: the SORA Parliament. Validators and
bridge keys take no part in any decision. SCCP uses the Parliament pipeline
(`ProposeSccpRouteGovernance`, the SCCP body list of
`parliament_attempt_policy_v1`, the due certificate and automatic enactment)
with its own action payload and a per-subject expected head.

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
  | RegisterRoute      { network, revision, deployment, max_wrapped_supply, initial_roster_generation }
  | ActivateRevision   { network, revision }                  // Staged → Bidirectional
  | SwitchRevision     { network, from, to }                  // from → InboundOnly, to: Staged → Bidirectional
  | DeactivateOutbound { network, revision }                  // Bidirectional | Paused → InboundOnly
  | RetireRevision     { network, revision }                  // InboundOnly → Retired
  | RemoveStaged       { network, revision }                  // never activated, liability 0
  | ReleaseStranded    { network, amount: u128, recipient: AccountId, memo: String /* ≤ 256 B */ }
  | SetTairaPaused     { network, paused: bool }              // ensure: Bidirectional ⇄ Paused
  // subject RouteControl { network }
  | SetDestinationPaused { network, revision, paused: bool }  // records a control message (§4.14.6)
  // subject LightClient { network }
  | InitializeLightClient    { network, expected: Absent | Unusable, params, bootstrap }
  | InstallTrustedCheckpoint { network, checkpoint }
  | FreezeLightClient        { network }
  // subject Parameters
  | SetParameters      { next: SccpParametersV1 }
  // subject BridgeKeyFault { peer }
  | ClearBridgeKeyFault { peer, fault: SccpFaultRefV1 }

SccpGovernanceSubjectV1 =
  | Route { network } | RouteControl { network } | LightClient { network }
  | Parameters | BridgeKeyFault { peer }
```

`network` is always an external profile. Route registration, the Taira pause
and the destination pause, light-client recovery, parameters (including
`enabled` and the roster timing of §4.1), stranded releases and fault clearing
are therefore all Parliament decisions, and there is no other path to any of
them.

Every action that reads or writes a revision's `activation` is under
`Route{network}`, including `SetTairaPaused`, so the Route head covers every
state the route lifecycle depends on. `RouteControl{network}` covers only
`destination_paused` and `next_control_nonce`, which only
`SetDestinationPaused` writes.

Light-client chain data whose native integers can exceed 2^53 − 1 (TON
validator weights, which sum to 2^60, and the TON config and key-block data in
general) is carried in `params`, `bootstrap` and `checkpoint` as opaque bytes
(BoC), never as integer fields, because every Parliament proposal must pass
`first_release_exact_json_u64_invariant_error` (below).

**Pipeline.**

1. **Propose.** `ProposeSccpRouteGovernance` has one proposer rule
   (`ensure_sccp_route_governance_proposer`): the authority is a citizen whose
   bond is at least `gov.citizenship_bond_amount`, or holds
   `CanProposeSccpRouteGovernance`. `network_id` MUST equal the live
   `NetworkId`, the action count is 1..=16, every action passes static
   validation (external network, nonzero revision, amount and cap bounds,
   memo length, bounded bootstrap and checkpoint sizes, and every
   `RegisterRoute` destination word unused in `sccp_destination_words`),
   every `u64` in the payload (base revisions, generations, the parameters,
   and the integer fields of light-client params, bootstraps and
   checkpoints) is at most
   2^53 − 1 (the SCCP arm of `first_release_exact_json_u64_invariant_error`,
   which the pipeline applies at proposal and at attempt creation),
   and `base_revisions` lists exactly the subjects `S(P)` (below) with their
   current `rev(s)`. The proposal id is
   `ProposalKind::SccpRouteGovernance(..).fingerprint()` and the record is
   stored as `Proposed`; an identical re-proposal while it is `Proposed` is
   idempotent, and one after it left `Proposed` is refused (the id already
   exists). The full proposal body is in state, so every reviewer can fetch
   it from any Torii (§6). Ordinary fee.
2. **Attempt.** Any account creates the attempt with
   `CreateParliamentGovernanceAttemptV1`: for this kind it is permissionless
   and core-derived (§4.14.5 item 3). It additionally fails unless every
   `rev(s)` still equals `base_revisions` and every `RegisterRoute`
   destination word is still unused (checked next to the payout preflight of
   attempt creation); a proposal that fails this check is stale and can never
   get another attempt, so a new proposal against the current state is
   needed. `parliament_attempt_policy_v1` gives
   risk tier `Constitutional` and the SCCP body list: Rules
   Committee, Agenda Council, Interest Panel, Review Panel, Coordination
   Council, FMA Committee and Oversight Committee (public findings) and the
   Policy Jury (hidden timed-OVN binding ballot), plus a fresh Confirmation
   Jury when an approval's margin is below 5 % (possible only when the Policy
   Jury has more than 20 seats, §4.14.5). The expected head (below) is frozen
   into the attempt.
3. **Lifecycle.** Future-beacon sortition, invitations, deliberation, public
   findings, the Policy Jury ballot and certification run through
   `SubmitParliamentLifecycleTransitionV1` as for every other proposal kind,
   except that the manager-only transitions are permissionless for this kind
   (§4.14.5 item 3). The Parliament driver (§4.14.5 item 4) submits the
   progress transitions and keeps heights advancing.
4. **Enactment.** At `certificate height + gov.min_enactment_delay`, at block
   start, `execute_due_parliament_certificate_v1` recomputes the head. A
   changed head marks the proposal `Superseded`. Otherwise the SCCP enactment
   (`smartcontracts::isi::sccp::governance::enact`) applies every action in
   order in the isolated effect transaction and increments
   `sccp_governance_revisions[s]` by one for each subject `s` of the proposal,
   inside that same effect transaction. If any action's precondition fails at
   enactment, the effect transaction is dropped, no SCCP state changes, and
   the attempt is recorded `ExecutionFailed`. Core emits
   `SccpGovernanceEnacted { proposal_id, subjects }`.

**After a failed attempt.** A `Rejected` or `ExecutionFailed` attempt leaves
the proposal eligible for a retry attempt (sequence + 1, at most 16) on the
same id, which anyone may create while `base_revisions` still match. The same
content can never be proposed again under a new id, because the fingerprint
already exists. A retry repeats the same actions, so after an
`ExecutionFailed` caused by content that has gone stale (for example a
bootstrap that is no longer fresh), the retry fails the same way and a new
proposal with new content is needed. After `Superseded`, or whenever any
`rev(s)` has changed, a retry attempt always fails the `base_revisions`
check, and only a new proposal with the current base revisions (a new id)
can proceed.

There is no direct path: no instruction applies an SCCP governance action
outside Parliament enactment, and core rejects every `SetParameter` that
targets SCCP state (SCCP parameters are not in the generic `Parameter` set,
§4.1), whatever the executor.

**Expected head, scoped per subject.** Each action has exactly one subject (the
comment above it). For a proposal `P`, let `S(P)` be the sorted, deduplicated
list of its actions' subjects and `rev(s) = sccp_governance_revisions[s]`
(0 when absent). The attempt's expected head, which equals the head implied by
`base_revisions` because attempt creation checks them, is:

```
subject_id = GOVERNANCE_SUBJECT_ID_V1 hash of GovernanceSubjectPreimageV1::Sccp(S(P))
version    = 1 + Σ_{s ∈ S(P)} rev(s)                         // checked u64
head_root  = parliament_governance_head_root_v1(&[(s, rev(s)) for s in S(P)])
expected   = GovernanceExpectedHeadV1::Present { subject_id, version, head_root }
```

Only the enactment of an SCCP proposal changes `rev(s)`. Automatic SCCP state
changes (records, releases, liability, nonces, frozen voids, light-client
advances, bridge keys, faults) never touch a head; each action re-checks its
own preconditions at enactment instead, and the actions that such automatic
changes can race have "ensure" semantics or name the exact state they act on
(`SetTairaPaused`, `SetDestinationPaused`, `ClearBridgeKeyFault`, below).
Consequences:

- Proposals whose subject sets are disjoint never supersede each other:
  registering the TON route, re-initializing the Ethereum light client and
  changing parameters can all be in flight at once. Disjoint proposals can
  still interact only through automatic state changes and through the global
  destination-word index, which attempt creation and enactment re-check.
- Two proposals that share a subject are ordered by enactment; the later one
  becomes `Superseded` (or its attempt cannot be created) and must be proposed
  again against the new state. Proposers therefore batch related actions on
  one subject into one proposal.
- A proposal MAY span subjects (for example `RegisterRoute`,
  `InitializeLightClient` and `ActivateRevision` for one network, or a pause of
  every route before a Taira reset); it then competes with every proposal
  touching any of them. A pause (`SetTairaPaused` plus `SetDestinationPaused`)
  spans `Route{n}` and `RouteControl{n}`, so it and a concurrent lifecycle
  proposal on the same route (`SwitchRevision`, `DeactivateOutbound`, …)
  supersede each other in enactment order, which is intended because both
  change the route's activation; neither can end `ExecutionFailed` because of
  the other.

**Implementation notes:**

- The SCCP arm of `governed_subject_id_v1` and of
  `GovernanceSubjectPreimageV1` (`crates/iroha_data_model/src/governance/types.rs`)
  is `Sccp(Vec<SccpGovernanceSubjectV1>)`, and the SCCP arm of
  `parliament_expected_head_v1`
  (`crates/iroha_core/src/smartcontracts/isi/world.rs`) computes the head
  above. The reducer checks only subject-id equality and head validity, and
  there is no global per-subject lock. A `version ≥ 1` with a nonzero
  `head_root` satisfies the head validity check.
- `sccp_governance_revisions` is incremented inside the effect transaction:
  the failure path re-checks that the head is unchanged before recording
  `ExecutionFailed`.
- State snapshots persist `sccp_governance_revisions`.
- The `base_revisions` and destination-word checks run next to the payout
  preflight of `CreateParliamentGovernanceAttemptV1`.
- Certificates due at the same height execute in a deterministic order, so
  overlapping subjects supersede deterministically.

**Action rules** (all checked on Taira at enactment):

- `RegisterRoute` → `Staged`:
  - `revision = latest + 1` for the route;
  - `initial_roster_generation = G` exists, is not inert (§4.3.2), has
    `valid_until_ms(G) > block time + roster_max_age_ms`, and every handoff
    subject from `G` to the current generation is attested, so the deployment
    can be rotated forward to the signing generation. `digest(G)` is pinned as
    `initial_roster_digest`. `G` need not be the current generation, because a
    Parliament round spans several generations under churn;
  - `destination_word` is unused in `sccp_destination_words`;
  - `0 < max_wrapped_supply < 2^128`; for TON, `< 2^96`;
  - for TON, `master_account` MUST equal the address Taira computes from
    `StateInit{code: minter_code, data: canonical_initial_data}`. The initial
    data is built per §5.3.1 from the generation record of `G`, the live
    `NetworkId`, the revision, the cap and the wallet and bucket code refs.
    Taira computes the address with `iroha_sccp::v1::ton_cell`
    (`minter_account_id` over `state_init`, with code cells as
    `CellRef::opaque`); only code hashes and depths are needed.
- `ActivateRevision`: `r` is `Staged`, no other revision of the route is
  `Bidirectional` or `Paused`, and the network's light client is installed and
  not frozen, so burns on the new deployment are provable.
- `SwitchRevision`: `from` is `Bidirectional` or `Paused`, `to` is `Staged`;
  `from` becomes `InboundOnly` and `to` `Bidirectional` atomically.
- `DeactivateOutbound`: `r` is `Bidirectional` or `Paused`; it becomes
  `InboundOnly`.
- `RetireRevision`: `r` is `InboundOnly`, `liability(r) = 0`, and no inbound
  record or refund of `r` is `Pending`.
- `RemoveStaged`: `r` is `Staged` and was never activated; its destination word
  stays reserved.
- `ReleaseStranded`: `amount ≤ stranded(route)`; the recipient is creditable
  under §4.12.3 steps 2–3 and is registered if absent; `stranded −= amount`.
- `SetTairaPaused` ("ensure" semantics, addressed by network because at most
  one revision per route is `Bidirectional` or `Paused`): with
  `paused = true`, a `Bidirectional` revision becomes `Paused`, and if the
  route has a `Paused` revision or none that is `Bidirectional` or `Paused`
  (for example after a frozen void), nothing changes. With `paused = false`, a
  `Paused` revision becomes `Bidirectional`, and otherwise nothing changes. It
  never fails at enactment.
- `SetDestinationPaused`: if `r` exists and is not `Retired`, records a control
  message (§4.14.6); it is idempotent in effect but always consumes a nonce.
  If `r` has been retired or removed since the proposal, it is a successful
  no-op: a retired revision has zero liability and a removed one was never
  activated, so neither can have anything left to mint.
- `InitializeLightClient`: with `expected = Absent`, no light client is
  installed; with `expected = Unusable`, the installed one is frozen or has aged
  beyond its `ws_bound_ms`. The bootstrap's signing set MUST be fresh at the
  enactment block time (§4.13.2), so a slow round cannot install a stale
  checkpoint. A healthy light client is never replaced: to change its stored
  parameters, the Parliament freezes it and re-initializes it. The fork bound
  is not a stored parameter (§4.13.2), so a source-chain hard fork needs a
  Taira release but no Parliament action.
- `InstallTrustedCheckpoint`: the light client is installed; the checkpoint is
  written with `origin: Parliament` and MUST NOT conflict with a stored
  checkpoint at the same height (a conflict fails the action; equivocation is
  reported with `ReportSccpLightClientEquivocationV1`).
- `FreezeLightClient`: sets `frozen`.
- `SetParameters`: `next` satisfies every rule of §4.1. Parameters change only
  through this action, so `base_revisions` already guarantees that they are
  the ones the proposer saw; Torii shows the diff (§6).
- `ClearBridgeKeyFault`: the peer's `barred` equals `Some(fault)`; the bar is
  cleared. A fault recorded after the proposal replaces `barred` (§4.11), so
  the action then fails at enactment and the Parliament decides again with the
  newer fault in view. The faulted keys stay faulted and their addresses stay
  burned.

**Replay.** The pipeline enacts a proposal at most once. A retry attempt
(sequence ≤ 16) on the same id is allowed only after a `Rejected`,
`Superseded` or `ExecutionFailed` predecessor, and for SCCP it succeeds only
while `base_revisions` still match (see "After a failed attempt" above), so
after `Superseded` it never does. An `Enacted` proposal can never be proposed
or attempted again. Because `base_revisions` is part of the content, a
proposal id names one decision about one state of its subjects, and a later
decision with the same actions (pause, resume, pause again) has different base
revisions and a new id. Nonces, expiry heights and executed-action sets are
not needed.

#### 4.14.4 Deployment verification (reviewer diligence, no server)

Before the bodies endorse and the Policy Jury votes on a `RegisterRoute`,
reviewers (the Review Panel and FMA Committee members first, and anyone else)
run locally:

```
iroha sccp deployment verify --network <p> --address <a> --initial-generation <G>
```

The tool reads rosters from the reviewer's own node or cross-checks several
Torii peers, and reads the destination from the reviewer's configured RPC at a
finalized (EVM `finalized` tag) or solidified (TRON `/walletsolidity/…`)
block. It MUST confirm:

- **EVM/TRON.** The runtime code (`eth_getCode`; TRON
  `/walletsolidity/getcontractinfo` `runtimecode`) equals the locked artifact's
  runtime template with the immutable references (from the compiler's
  `immutableReferences`) filled with:
  - the live `NetworkId`, network tag, revision and cap;
  - `INITIAL_ROSTER_DIGEST` = the digest of generation `G` from Taira state,
    and `INITIAL_GENERATION = G`.

  Its keccak equals `runtime_code_hash`. The views return:
  - `opCount() = 0`, `totalSupply() = 0`, `controlNonce() = 0` and
    `mintingPaused() = false`;
  - `rosterState()` equal to generation `G` with `prevDigest = 0`, or to a
    later Taira generation reached through consecutive genuine Taira
    generations (then `prevDigest` is a genuine digest).
- **TON.** Taira recomputes the address at enactment (§4.14.3). The tool also
  checks that the account is active with the minter code, and that
  `get_sccp_state` reports `initialized`, a zero op count, zero supply and a
  zero control nonce.

The proposal's Torii view (§6) shows the recomputed checks that Taira will
repeat at enactment. With a genuine, current initial roster, nothing can be
minted, voided or burned before registration without genuine attestations.
Genuine attestations never carry leaves for an unregistered destination.
Anyone can deploy a destination contract; only the registered deployment
matters.

#### 4.14.5 Seating the Parliament on Taira

Without a seated Parliament no route can ever be registered, activated,
paused or recovered. `InitializeSccpV1` cannot check this, so the Taira reset
tooling and `scripts/taira_devnet.py` MUST provision all of the following in
genesis, the shared configuration or the reset ceremony, MUST refuse to
produce a network that lacks any of them, and `iroha taira doctor` MUST report
each one. The requirements come from the Parliament code as it stands
(`crates/iroha_core/src/governance/`,
`crates/iroha_core/src/smartcontracts/isi/world.rs`). Items 3 and 4 are SCCP
changes to how SCCP attempts are driven; the rest are not SCCP-specific, and
the recommended `[gov]` profile applies to every Parliament proposal kind on
Taira.

All windows below are block counts. Iroha produces no empty blocks: the
Sumeragi core builds a block only for queued transactions (it does not probe
start-of-block work, §4.3.2), so no Parliament window elapses on an idle
chain. Wall-clock figures therefore assume that blocks keep coming, which
item 4 ensures while an SCCP attempt is active.

1. **Citizens.** Sortition candidates are exactly the citizens whose recorded
   bond is at least `gov.citizenship_bond_amount`
   (`canonical_parliament_eligible_candidates_v1`, at most 65 536 citizens).
   Genesis MUST, for each of `C` citizens: register the citizen's account
   (`Register<Account>`; `RegisterCitizen` needs an existing account), mint the
   bond plus a fee float, and register the citizen with
   `RegisterCitizen { owner, amount ≥ citizenship_bond_amount }` (registering
   another owner is allowed only in the initial genesis). Parliament
   transactions are not fee-exempt (`nexus_protocol_fee_exempt_instruction`
   does not cover them), so citizens pay ordinary fees for invitations,
   endorsements and ballots. Each citizen is a distinct account whose key is a
   runtime secret generated by the reset tooling and handed to a distinct live
   participant; keys are never committed. Anyone can join later with
   `RegisterCitizen`.

   **Sybil cost on Taira.** The Taira faucet pays 25 000 XOR per claim at a
   4-bit proof of work (`[torii.faucet]`) against a 10 000 XOR bond, so today
   anyone can create funded citizens at almost no cost. Such citizens could
   capture bodies (bounded as in §9.13) or stall every round, pauses
   included, by accepting seats and staying silent (item 2). Taira MUST set
   `citizenship_bond_amount` far beyond faucet reach (recommended
   1 000 000 XOR, that is 40 faucet claims) and MUST enable adaptive faucet
   difficulty (`pow_adaptive_claims_per_extra_bit > 0` and
   `pow_adaptive_max_extra_bits > 0`), and the doctor checks both. Even then,
   Taira citizenship is only as scarce as test XOR (§9.13, §13).
2. **Body sizes and body liveness.** Each required body seats
   `s_b = min(size_b, C)` members (`body_committee_size`,
   `derive_attempt_body_plan_v1`); a citizen may sit on several bodies.
   - **Public findings.** The seven public-finding bodies run one after
     another. Each needs about six phase advances and `⌈2o/3⌉` endorsements of
     the same result root (`parliament_quorum_seats_v1`), where `o` is the
     number of seats accepted when the body's roster was sealed, within
     `parliament_public_finding_phase_blocks`.
   - **Policy Jury.** It needs at least 3 accepted members
     (`MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1`); its ballot quorum is over
     the seats accepted at sealing. Freezing the ballot corpus requires one
     accepted ballot per survivor, so every juror who registered for the
     ballot and did not record a dropout before the survivor freeze MUST cast
     a ballot, or the ballot fails and a retry costs a whole new ballot.
   - **Confirmation Jury.** An approval with a margin below 5 % needs a fresh
     Confirmation Jury of at least 3 citizens outside the Policy Jury. With at
     most 20 decisive ballots the margin test can never trigger, so a Policy
     Jury of at most 20 seats never needs one. If `policy_jury_size > 20`,
     Taira MUST also satisfy `policy_jury_size ≤ C − 3`.
   - **Config constraints.** `policy_jury_size ≥ 3`;
     `parliament_timed_ovn.max_corpus_entries ≥ max(policy_jury_size,
     confirmation_jury_size)` (asserted by the config); the registration and
     survivor-freeze windows each at least `max_corpus_entries` blocks (also
     asserted); and `coordination_council_size` set explicitly (its default is
     150). The `[gov]` values are part of the consensus execution policy, so
     every validator uses the same ones.

   Taira's current values (Rules 7, Agenda 9, Interest 11, Review 13,
   Oversight 7, FMA 5, Policy Jury 25, Coordination and Confirmation unset,
   default windows, `min_enactment_delay` 600) with its single genesis citizen
   cannot seat a Policy Jury, and their windows put a round at 13 004 blocks
   or more. The recommended Taira profile (all values pass the config
   asserts):

   | Setting | Taira today | Recommended |
   |---|---|---|
   | genesis citizens `C` | 1 | 16 |
   | `citizenship_bond_amount` | 10 000 | 1 000 000 |
   | `rules_committee_size`, `agenda_council_size`, `interest_panel_size`, `review_panel_size`, `coordination_council_size`, `fma_committee_size`, `oversight_committee_size` | 7, 9, 11, 13, unset (150), 5, 7 | 5 each |
   | `policy_jury_size` | 25 | 9 |
   | `confirmation_jury_size` | unset (1 000) | 7 |
   | `parliament_alternate_size` | 21 | 3 |
   | `parliament_timed_ovn.max_corpus_entries` | unset (1 000) | 16 |
   | `parliament_timed_ovn.registration_phase_blocks` | unset (3 600) | 300 |
   | `parliament_timed_ovn.survivor_freeze_phase_blocks` | unset (1 000) | 100 |
   | `parliament_timed_ovn.commitment_phase_blocks` | unset (3 600) | 300 |
   | `parliament_timed_ovn.release_delay_blocks` | unset (600) | 50 |
   | `parliament_timed_ovn.opening_phase_blocks` | unset (600) | 300 |
   | `parliament_invitation_phase_blocks` | unset (3 600) | 300 |
   | `parliament_public_finding_phase_blocks` | unset (3 600) | 900 |
   | `min_enactment_delay` | 600 | 50 |
   | `parliament_tle_key_lifecycle.max_fresh_ballots_per_session` | unset (1) | 8 |
   | `parliament_tle_key_lifecycle.session_lifetime_blocks` | unset (37 600) | 7 200 |

   `max_fresh_ballots_per_session` is a `[gov]` knob, not a constant; its V1
   default of 1 is a conservative adaptive-corruption bound. Raising it lets
   one TLE session cover every ballot registered while the roster is
   unchanged, at the cost that a threshold of that session's holders who
   later collude could open all of those ballots early instead of one. That is
   acceptable on Taira, a test network; a mainnet-grade profile is a
   governance decision.
3. **No clerk for SCCP.** `CreateParliamentGovernanceAttemptV1` and the
   manager-only transitions (`CompleteQualification`,
   `RegisterInitialSortition`, `RegisterSortitionRequest`, `AdvanceBodyPhase`,
   `RegisterBallotAttempt`, `EscalateRisk`) require `CanManageParliament` for
   other proposal kinds, which for SCCP would let one account outside the
   Parliament decide which proposals ever reach the bodies. For
   `ProposalKind::SccpRouteGovernance` they are permissionless and
   core-derived: `parliament_transition_requires_manager_v1` takes the
   proposal kind and returns false for SCCP, and each transition is valid only
   with the canonical content core derives from state. An attempt exists for
   exactly the `Proposed` SCCP proposal it names, whose `base_revisions` are
   current; `AdvanceBodyPhase` targets only the next phase once its
   precondition holds; `RegisterBallotAttempt` names only the active TLE key
   session, the active beacon session and the release height derived from the
   configured windows; `EscalateRisk` targets only the policy-derived tier;
   sortition registration uses only consensus-derived inputs (as
   `RegisterInitialSortition` already does). Where a manager transition
   carries a parameter that core does not derive today, the SCCP variant fixes
   it to that canonical value (TODO for the implementation: enumerate each
   such field in the `SubmitParliamentLifecycleTransitionV1` executor). Nobody chooses the
   SCCP agenda, and genesis grants `CanManageParliament` to nobody for SCCP.
   Other proposal kinds keep their manager rule.
4. **Parliament driver.** Every Parliament window is a block count, so on an
   idle Taira a round has no wall-clock bound, and two checkpoints are valid
   at one exact height only: `CloseBallotRegistration` at
   `registration_close_height` and `FreezeBallotSurvivors` at
   `survivor_freeze_height`. Missing either fails the ballot
   (`RegistrationDeadlineExpired`, `SurvivorDeadlineExpired`), and the retry
   costs another ballot and TLE session capacity. `FinalizeOpenedBallot` also
   needs someone to collect TLE partial releases from the signer peers. The
   reset tooling and `scripts/taira_devnet.py` MUST therefore run a
   **Parliament driver** (`iroha sccp governance drive`, §8) from a funded
   account. While any SCCP proposal is `Proposed` or any SCCP attempt is
   active (and, after a reset, until the first attestable generation exists,
   §4.18), it:
   - creates attempts for `Proposed` SCCP proposals whose `base_revisions`
     are current, oldest first;
   - submits every permissionless progress transition as soon as it is valid,
     and submits the two exact-height checkpoints so that they are included
     at exactly their heights;
   - collects the release partials and submits `FinalizeOpenedBallot`;
   - submits a tick (one `Log` instruction, ordinary fee) whenever the tip
     has been idle for `tick_interval_ms` (default 4 000), so the windows
     elapse and the beacon pulses the attempt requested are produced.

   The driver reads `GET /v1/sccp/governance/proposals` and, per active
   attempt, `GET /v1/gov/parliament/attempts/{id}/plan`. Core computes the
   plan over one committed view by trial-applying every permissionless
   transition to the reducer at the next native candidate height (`tip + 1`).
   This is advice, not a reservation: queueing, lane routing and consensus
   determine actual inclusion, and execution checks the actual carrier height.
   The due transitions go out in one transaction; each exact-height checkpoint
   (registration close, survivor freeze, ballot registration) goes out alone
   when the next candidate reaches its height, and also one candidate earlier
   in case inclusion is delayed (an early copy fails and pays its fee).
   Retry suppression follows each submission's candidate height and expires
   after the committed tip passes it. The driver refreshes the plan as the tip
   advances;
   ballots in `TimedCommitment` are relayed from published records and
   ballots in `Opening` finalized from the signer peers' partials. A missed
   checkpoint is failed by the next plan, and the retry ballot is planned
   automatically.

   Anyone may run a driver. Several drivers are harmless (a duplicate
   transition fails and pays its fee), and a driver has no discretion.
   Oldest-first is only the driver's default: attempt creation is
   permissionless, so anyone may create the attempt of any current proposal
   at any time, and a flood of junk proposals cannot hold a genuine one back
   except by competing for TLE session capacity at ballot registration. The
   doctor MUST report every active SCCP attempt with its next due checkpoint
   height and the height of its last progress transition, and fail when an
   attempt is active and the tip is not growing. Whether core should count an
   active attempt's pending checkpoint, pulse or enactment as block-start work
   and apply the exact-height checkpoints automatically at block start, which
   would make ticks and checkpoint timing unnecessary, is open (§13).
5. **Global threshold beacon.** Sortition consumes the finalized beacon pulse
   at `request_height + parliament_sortition_pulse_delay_blocks` (4 blocks),
   and each ballot's timed release consumes a later pulse. A global-beacon key
   session MUST be installed (`InstallGlobalBeaconKey`, an exact `2f+1`
   validator-roster lifecycle certificate; the Taira public-reset beacon
   bootstrap, whose FD200 partial-signer credential is optional today and
   becomes mandatory), and every validator MUST run its beacon partial signer.
   A pulse requires the active beacon session to match the height's roster,
   and the NPoS pre-boundary slot and every requested Parliament slot are
   consensus-mandatory (`crates/iroha_core/src/sumeragi/epoch_beacon.rs`). Every
   validator-set change therefore needs a new beacon DKG and
   `InstallGlobalBeaconKey` before the next pulse. That is a consensus
   prerequisite of free validator churn (D3) on Taira whether or not SCCP
   exists; it MUST be automated in-node (§12).
6. **Parliament TLE key sessions.** Each Policy Jury ballot binds an active
   Parliament TLE key session installed by `InstallParliamentTleKey` (an exact
   `2f+1` validator-roster lifecycle certificate over a finalized DKG
   transcript), and every validator holding a release-share seat MUST have TLE
   custody running; irohad refuses to start consensus otherwise.
   `RegisterBallotAttempt` requires the session's frozen roster to equal the
   current commit topology, so every roster change needs a new TLE DKG and
   certificate before the next ballot, and a session registers at most
   `max_fresh_ballots_per_session` ballots within `session_lifetime_blocks`.
   A ballot then keeps its session until its opening deadline, about 1 050
   blocks after registration opens with the recommended profile (9 400 with
   the defaults, about 2.6 epochs of 3 600 blocks). **Liveness assumption:** the session
   threshold of the frozen roster is online at the release height. A node
   that leaves the roster keeps its TLE custody running as an observer until
   every ballot it holds shares for has passed its retention deadline, and on
   a graceful shutdown it first releases every share that is already due and
   logs any it could not release. Session installation binds a roster and a
   DKG transcript, never a proposal's content, so installing sessions gives
   validators no say over which proposal is voted or how. **Launch gate:** an
   in-node TLE DKG with an automatic `InstallParliamentTleKey` certificate on
   every roster change and whenever the active session is exhausted or near
   its lifetime. No tooling automates this today (§12, §13).
7. **Node-generated credentials.** Items 5 and 6 MUST NOT add an operator
   step to the validator path (D4). The beacon partial signer (including its
   FD200 credential), the TLE release-share custody and its supervisor
   credential MUST default to key material that the node generates on first
   start under its store directory, owner-only as for bridge keys (§4.9), and
   MUST be overridable in `iroha_config` (the existing external provider
   binding `gov.parliament_tle_partial_release_signer_provider_*` becomes an
   optional override); no environment variables. Until this lands, joining a
   Taira validator requires configuring these Parliament credentials. That is
   a Parliament and consensus requirement, not an SCCP one, and D4's
   zero-touch guarantee covers SCCP only (§9.1).

Validators provide items 5 and 6 as infrastructure. A threshold of them can
withhold pulses or release shares (liveness) or open ballots early
(secrecy), but cannot choose members, proposals or outcomes (§9.13).

**Tooling.** Jurors register timed-OVN ballot keys and cast timed-OVN ballots
with `iroha gov parliament ballot register|cast` (§8). Ballot casting MUST
anchor its evidence on the Sumeragi core's `SumeragiFinalityVerifier`; until
it does, the CLI pins its trusted checkpoint from an independent source
(TODO(ws24)). `scripts/taira_devnet.py` generates the `C` citizen keys in its
owner-only workspace and runs the driver, the citizens' invitation responses,
endorsements and ballots itself, modeled on
`integration_tests/tests/sora_parliament_enactment.rs`. Disposable devnets
MAY build irohad with the `test-network-parliament-signers` feature for the
beacon and TLE signers; public Taira never does.

**Bring-up.** After a reset, three proposals seat the four routes (§4.18):
one for ETH, BSC and TRON (`RegisterRoute`, `InitializeLightClient` and
`ActivateRevision` each, 9 actions over 6 subjects), one with only the TON
`InitializeLightClient`, both proposed at once, and after the TON light client
is installed, one with the TON `RegisterRoute` and `ActivateRevision`. With
`max_fresh_ballots_per_session ≥ 2`, the first two ballots can share one TLE
session. The TON light client is proposed alone because a TON bootstrap stays
fresh only until `utime_until + stake_held_for − margin`, 9.1 to 27.3 hours
after capture with mainnet values (65 536 s rounds, 32 768 s stake hold), and
actions are atomic: a stale TON bootstrap at enactment would otherwise take
its route's registration down with it. With the recommended profile and a
driver, a round normally fits that window; with the default windows (13 004
blocks, about 14.4 h at 4 s, before deliberation) it usually does not. A
failed TON initialization is re-proposed with a fresh bootstrap. A bootstrap
rule that accepts a set that was fresh when proposed and then catches up is
not adopted, because it reopens a long-range window of up to the proposal's
age.

**Latency.** The fixed windows of one round sum to at least 13 004 blocks with
Taira's current values and about 1 104 blocks with the recommended profile
(invitation, ballot registration, survivor freeze, commitment and release
delay, the enactment delay and the sortition pulse delay). On top of that
come:

- the seven public-finding bodies, one after another, each with about six
  phase advances and its endorsements, each bounded by
  `parliament_public_finding_phase_blocks`;
- the ballot opening and finalization, bounded by `opening_phase_blocks`;
- a whole ballot per ballot retry (registration through opening: about
  1 050 blocks recommended, 9 400 default), plus TLE session capacity for it;
- queueing on TLE sessions: concurrent proposals are all in flight until
  ballot registration, and then register only as fast as sessions allow;
- a second ballot by a Confirmation Jury when the Policy Jury has more than
  20 seats (about 12 404 more blocks with the defaults).

At one block every 4 s, the recommended floor is about 74 minutes; the
wall-clock time is unbounded without blocks, which is why item 4 is
mandatory. This is the latency of every SCCP decision, including a pause
(§9.10).

#### 4.14.6 Destination control messages

```
sccp_control_messages: (SccpNetworkV1, u32 revision, u64 control_nonce) → SccpControlRecordV1 {
    paused: bool, height: u64, commitment_index: u32, leaf: [u8; 32], proposal_id: [u8; 32],
}
```

Enacting `SetDestinationPaused { network, revision: r, paused }` in block `h`:

1. `control_nonce = next_control_nonce(r)`, then `next_control_nonce(r) += 1`;
   `destination_paused(r) = paused`.
2. `leaf` = the control leaf of §3.4 with `target = network`, `r`'s
   destination word, `route_revision = r`, `control_nonce` and `paused`.
3. The block MUST have fewer than 512 leaves (otherwise the action fails).
   Allocate `commitment_index` = the number of leaves already recorded in `h`,
   insert `sccp_block_leaves[(h, commitment_index)] = Control { network, r,
   control_nonce }` and the control record, and emit
   `SccpControlRecorded { network, revision, control_nonce, paused, height,
   commitment_index }`.

The post-execution hook commits the control leaf with the block's transfers
(§4.5), so the bridge roster attests it like any SCCP block. Anyone then fetches
the proof bundle (§6) and calls `applyControl` on the destination (§5.1.6),
which accepts a control only with a nonce above the last applied one. Only the
newest control matters: applying it makes every older one stale. Controls are
recorded whether or not `enabled` is set, for any non-`Retired` revision, and
are never pruned. Taira cannot observe whether a control was applied; wallets
read the destination's `controlNonce()` and apply the newest control
themselves before finalizing (§7.1).

### 4.15 Escrow and liability invariants

- **One escrow per route.** It is
  `sccp_route_escrow_account_id_v1(network_id, route_id, "xor")`, derived
  without the revision and non-signable. `InitializeSccpV1` creates it in
  genesis for all four routes, so it cannot be front-run. Core rejects every
  ordinary `Register<Account>` and `Unregister<Account>` of an escrow id,
  whatever the executor.
- **Core custody guards.** `ensure_not_sccp_escrow_source` and
  `ensure_not_sccp_escrow_destination` in
  `crates/iroha_core/src/smartcontracts/isi/asset.rs` reject every transfer,
  burn, mint or other balance change that touches an escrow, except the SCCP
  effects:
  - credit by `RecordSccpMessage`;
  - debit by inbound release, outbound refund and a Parliament-enacted
    `ReleaseStranded`.

  The guards hold for every escrow in every revision state and are enforced
  in core, not in the upgradable executor. Neither the XOR definition owner
  (burn) nor holders of `CanTransferAssetWithDefinition` can move escrow funds.
- **Invariants after every transaction:**
  - `balance(escrow(route)) = Σ_r liability(r) + stranded(route)`;
  - `liability(r) ≤ max_wrapped_supply(r)` (a bounce checks the cap of its
    target revision);
  - on the destination, `supply(r) ≤ liability(r)` under the honest-majority
    assumption. Every mintable message was counted into liability when
    recorded, burns decrease supply before Taira releases, and a void and a
    mint consume the same nonce bit. The destination cap (§5.1.4) is defense
    in depth and never binds under honest operation.
- Tests assert all invariants, including negative tests for a definition-owner
  burn and a permissioned transfer against an escrow.

### 4.16 Outbound voids and refunds

A recorded outbound message that is never minted is recovered by voiding its
nonce on the destination and proving the void to Taira. No refund depends on
Taira observing an absence.

- **On the destination** (§5.1.8), a nonce is voided in one of two ways, and
  either one emits the void event:
  - `voidExpired`: after `deadline_ms`, with the same attestation proof as
    finalization;
  - `voidFrozen`: over a range of nonces, once both the current and the
    previous roster have expired.

  A void sets the nonce bit without minting. Mint and void consume the same
  bit, so exactly one of them can ever happen.
- **`SubmitSccpOutboundVoidV1 { network, revision, proof: SccpSourceProofV1 }`**:
  anyone may submit it (ordinary fee). The proof uses the network's light
  client (§4.13) and yields a normalized void event
  `{ emitter = r's deployment, first_nonce, count, message_id or zero,
  kind: Expired | Frozen }`:
  - EVM/BSC: `SccpVoided` logs.
  - TRON: a `SUCCESS` direct `TriggerSmartContract` call of `voidExpired*`
    (nonce = first static head word, count 1) or `voidFrozen(first, count)`.
  - TON: `sccp_voided` external-out messages.

  For each nonce whose record is `Recorded`:
  - if `message_id ≠ 0`, it MUST equal the record's;
  - the record becomes `Voided`;
  - a refund is attempted.

  A `Frozen` void also sets `destination_frozen` and moves `r` to
  `InboundOnly`.
- **Refund.** A refund proceeds when SCCP is enabled and `r` is not `Paused`;
  otherwise it waits in `Pending` for `SettleSccpV1::Refund`. It credits the
  record's `sender` under the rules of §4.12.3 steps 2–3, registering the
  account if it is absent. If the sender is the escrow (a bounce) or cannot be
  credited, the amount moves to `stranded(route)`. Then
  `liability(r) −= amount` and the status becomes `Refunded` or `Stranded`.
  A Parliament-enacted `ReleaseStranded` (§4.14.3) is the only way out of
  `stranded`.
- A destination paused by the Parliament (§4.14.6) keeps `voidExpired` open,
  so messages that cannot be minted while it is paused are refunded after
  their deadlines.
- **Wallets** refuse to record when the destination's roster has expired, or
  expires before the message could be finalized, or when the newest control
  for the revision is a pause (§7.1).

### 4.17 Events

`SccpEvent` (Taira data events): `MessageRecorded`,
`BlockCommitted { height, root, count, history_size }`, `SubjectCreated`,
`AttestationSigned`, `BlockAttested`,
`RosterGenerationCreated { generation, digest, activation_height, valid_until_ms }`,
`RosterDerivationFailed`, `HandoffStalled { height, generation }`,
`BridgeKeySet { peer, address, account, activation_epoch }`,
`AttestationFault`, `InboundProven`, `RecipientRegistered`, `InboundReleased`,
`InboundBounced`, `InboundLiabilityShortfall`, `OutboundVoided`,
`OutboundRefunded`, `OutboundStranded`, `StrandedReleased`,
`LightClientAdvanced`, `LightClientFrozen`, `LightClientInitialized`,
`TrustedCheckpointInstalled`, `RevisionActivationChanged { network, revision,
from, to }`, `ControlRecorded { network, revision, control_nonce, paused,
height, commitment_index }`, `GovernanceEnacted { proposal_id, subjects }`.

Proposal submission, attempts, certificates and enactment outcomes
(`Superseded`, `ExecutionFailed`) are reported by the existing Parliament
governance events; SCCP adds only `GovernanceEnacted` with the subjects it
changed.

### 4.18 Taira resets and devnets

- **Identity.** The Taira identity is the `NetworkId` read from state. SCCP
  hashes, the EIP-712 salt and escrow account derivation all use it. Nothing
  about Taira is compiled into Rust or contracts, so `scripts/taira_devnet.py`
  devnets work with the same binaries.
- **Fresh identity per reset.** Genesis `InitializeSccpV1` carries a fresh
  random 32-byte `reset_nonce`, so every reset has a new `NetworkId`. The
  reset tooling refuses a `NetworkId` or `reset_nonce` it has recorded before.
- **Before a reset**, the Parliament SHOULD enact one proposal that sets
  `SetDestinationPaused(true)` (and `SetTairaPaused(true)`) for every live
  revision, and anyone applies the controls on the destinations. A
  Parliament round takes at least about 1 100 blocks with the recommended
  profile, and more in wall-clock time when blocks are slow (§4.14.5), so this
  is planned with the reset. If it is not done, the old deployments keep minting what the
  old roster attested until their last roster expires (at most
  `roster_validity_ms`) and then freeze. The old bridge keys are destroyed with
  the node stores that hold them (§4.9). The old deployments are bound to the
  old identity. Their wrapped supply is stranded, and their burns are not
  accepted by the new Taira. This is accepted for a test network and MUST be
  stated in token metadata and the wallet UI ("Taira test XOR; redeemable only
  on Taira network `<NetworkId>`").
- **Genesis and the reset configuration MUST seed** `InitializeSccpV1` and
  everything the Parliament needs (§4.14.5):
  - in genesis: each citizen's account, bond, fee float and `RegisterCitizen`,
    and optionally a `CanProposeSccpRouteGovernance` grant for the reset
    operator's proposing account (§4.19); no `CanManageParliament` is needed
    for SCCP;
  - in the shared configuration: the recommended `[gov]` profile (body sizes,
    phase windows, `min_enactment_delay`, the TLE key lifecycle and the raised
    `citizenship_bond_amount`) and the adaptive `[torii.faucet]` difficulty;
  - in the reset ceremony: the global-beacon bootstrap and the first TLE
    session, installed by the in-node automation (§4.14.5 items 5–7), and a
    running Parliament driver.

  Genesis carries no bridge keys.
- **After a reset:**
  1. Each validator node generates its bridge key on first start and
     registers it during epoch 0 (§4.9). Generation 1 is inert; the first
     epoch boundary (3 600 blocks, reached with driver ticks if Taira is idle)
     creates the first attestable generation, published by any Torii.
  2. Anyone deploys fresh destination contracts pinned to that generation (or
     a successor).
  3. A citizen (or the holder of `CanProposeSccpRouteGovernance`) makes the
     bring-up proposals of §4.14.5: ETH, BSC and TRON together, the TON light
     client alone, and, once it is installed, the TON registration and
     activation. Reviewers verify the deployments and bootstraps (§4.14.4)
     while the Parliament deliberates, and the driver carries every attempt.
  4. The Parliament enacts the proposals and the routes activate.
- **Wallets** pin deployments per `NetworkId` in `[sccp]` client config and
  refuse a destination whose `tairaNetworkId()` differs from Torii's
  capabilities.

### 4.19 Permissions and fees

| Instruction | Authority | Fee |
|---|---|---|
| `InitializeSccpV1` | genesis block only | — |
| `SetSccpBridgeKeyV1` (register) | `account_of(public_key)`, which may be unregistered; the consent and PoP signatures authorize (§4.2.3) | exempt on success, at most once per peer per epoch; admission-verified |
| `SetSccpBridgeKeyV1` (revoke) | any (the consent signature authorizes) | ordinary |
| `SubmitSccpAttestationsV1` | the signing member key's own account | exempt on success; admission-verified and queue-deduplicated |
| `SubmitSccpAttestationFaultV1` | any | exempt when it records a new fault; admission-verified and deduplicated |
| `RecordSccpMessage` | the sender | ordinary |
| `SubmitSccpInboundMessageV1` | any | ordinary; exempt on success as a self-claim (§4.12.4) |
| `SettleSccpV1` | any | ordinary; exempt on success for an inbound self-claim |
| `SubmitSccpOutboundVoidV1` | any | ordinary |
| `AdvanceSccpLightClientV1` | any | ordinary; exempt on success from an active or pending bridge key's account when it moves the head (at most one pending per authority and network, and one per network per block) |
| `ReportSccpLightClientEquivocationV1` | any | ordinary |
| `ProposeSccpRouteGovernance` | a citizen bonded at ≥ `gov.citizenship_bond_amount`, or a holder of `CanProposeSccpRouteGovernance` | ordinary |
| `CreateParliamentGovernanceAttemptV1` and manager-only lifecycle transitions, for SCCP proposals | any; core-derived content only (§4.14.5 item 3) | ordinary |
| Other Parliament lifecycle transitions | per the Parliament pipeline (seated members, or permissionless progress) | ordinary |

Fee exemption is "exempt on success, charged on failure": a failed exempt
transaction is charged the ordinary fee when the authority can pay it, and the
pending limits and admission pre-verification bound the rest. Pending limits
are per exempt kind, never across kinds: one attestation batch per authority
(§4.8), one keeper advance per authority and network (§4.13.4), one key
binding per peer (§4.2.3), one self-claim per authority and per `message_id`
(§4.12.4), and fault evidence deduplicated by `(address, height)` (§4.11). A
bridge-key account can therefore have its attestation batch, a keeper advance
and its own registration pending at once. Fee-exempt SCCP transactions are
limited to `max_exempt_transactions_per_block` per block. Every SCCP
instruction routes to the universal dataspace.

The only SCCP permission token is `CanProposeSccpRouteGovernance`, which only
allows proposing. Its grant and revoke rule is `OnlyGenesis`, as for
`CanManageKagemushaReserve` (`INITIAL_GENESIS_ONLY_PERMISSION_NAMES` in
`crates/iroha_core/src/executor.rs`): genesis MAY grant it (for example to the
reset operator's proposing account), and after genesis nobody can grant or
revoke it. No manager role grants or revokes it. A holder can only put
proposals before the Parliament and pay their fees; bonded citizens can always
propose. The default executor gets allow-visitors for the SCCP instructions;
core enforces every SCCP rule. Implicit account registrations (a bridge key's
account, §4.2.2; a recipient at settlement, refund or stranded release,
§4.12.3) have the effect and validation-fee DS classification of
`Register<Account>`.

## 5. Destination contracts

### 5.1 Common semantics (all four chains)

#### 5.1.1 State

- **Immutable:** `tairaNetworkId`; network tag, domain and identity word;
  `routeRevision`; `maxWrappedSupply` (token units = Taira units);
  `DOMAIN_SEPARATOR`; route id; `INITIAL_ROSTER_DIGEST`; `INITIAL_GENERATION`.
  Constants: `PREVIOUS_ROSTER_GRACE_MS`, `MAX_ROSTER_VALIDITY_MS` and
  `MAX_CLOCK_SKEW_MS` (§3.9).
- **Current roster:** `digest`, `generation`, `validUntilMs`. TON also stores
  `valid_from_ms`, `n`, `t` and the members.
- **Previous roster:** `prevDigest` and `prevValidUntilMs`, both 0 until the
  first rotation. TON also stores the members.
- **Counters and flags:** the consumed set over outbound nonces; outbound
  source nonces; token supply; `mintingPaused`; `controlNonce` (the nonce of
  the last applied control, 0 initially); and `opCount`. `opCount` is
  monotone and counts finalizations, voids, burns and applied controls, but
  not rotations.
- There is no owner, guardian, admin key or roster-signed control statement.
  The only inputs that change the pause state are Taira control leaves under a
  genuine attestation (§5.1.6).

#### 5.1.2 Roster acceptance

An attestation with `rosterDigest = D` is signed by an **accepted** roster iff
`D ≠ 0` and either:

- `D = digest ∧ now_ms ≤ validUntilMs`, or
- `D = prevDigest ∧ prevDigest ≠ 0 ∧ now_ms ≤ prevValidUntilMs`.

On EVM/TRON the roster is supplied in calldata and MUST hash (§3.7, with the
`n`, `t` and ordering checks) to exactly `D`. On TON the members come from
storage. Signatures are verified per §3.8 and require `popcount ≥ t`, and every
set bit MUST address a nonzero member.

#### 5.1.3 `finalizeFromTaira` (direct) and historical mode

Direct-mode inputs are: an attestation `A`, signatures, the roster, and a
message proof `{payload, leafIndex, path}`. The checks, in order:

1. Chain identity: EVM `block.chainid`; TON `GLOBALID = −239`.
2. `mintingPaused = false`.
3. The roster is accepted (§5.1.2), and at least `t` valid signatures cover
   `digest(A)`.
4. `A.messageCount ≥ 1`. The payload is valid per §3.2 with:
   - `source_domain 0`; `dest_domain`, `route_revision` and `route_id` equal
     to this contract's own; `asset_id = "xor"`;
   - a recipient valid for the own codec. EVM/TRON: nonzero and not this
     contract. TON: `addr_std` workchain 0, not the minter;
   - `now_ms ≤ deadline_ms`.
5. The transfer `leaf` per §3.4 with the own destination word, and
   `merkle_root(leaf, leafIndex, A.messageCount, path) = A.sccpRoot`.
6. The payload's `nonce` is not consumed; mark it consumed.
7. `totalSupply (+ pending) + amount ≤ maxWrappedSupply`.
8. Mint `amount` to the recipient; `opCount += 1`; emit `SccpFinalized`.

Historical mode additionally takes
`{height, sccpRoot, messageCount, leafIndex, path}`. In step 5 it verifies the
message against that `sccpRoot/messageCount`, then checks
`merkle_root(history_leaf(height, sccpRoot, messageCount), leafIndex, A.historySize, path) = A.historyRoot`.
Any attestation by an accepted roster can therefore finalize any older message.

Finalization is permissionless; the recipient is fixed by the payload.

#### 5.1.4 Supply cap

`maxWrappedSupply` is immutable and is set at construction to Taira's
`max_wrapped_supply` (same units). Mint reverts if it would be exceeded.

#### 5.1.5 Rotation and weak subjectivity

`rotateRosters(RotationV1[] rotations)` on EVM/TRON (TON: one `sccp_rotate`
per message) applies each rotation in order:

1. `A.rosterDigest = digest` (the **current** roster only) and
   `now_ms ≤ validUntilMs`. The supplied current roster hashes to `digest`, and
   at least `t` valid signatures cover `digest(A)`.
2. `A.nextRosterDigest ≠ 0` and equals the recomputed digest of `next` (§3.7,
   including the ordering and threshold checks).
3. `next` satisfies all of:
   - `next.generation = generation + 1`;
   - `next.validFromMs = A.timestampMs`;
   - `next.validFromMs ≤ now_ms + MAX_CLOCK_SKEW_MS`;
   - `next.validUntilMs − next.validFromMs ≤ MAX_ROSTER_VALIDITY_MS`;
   - `now_ms < next.validUntilMs ≤ now_ms + MAX_ROSTER_VALIDITY_MS`.
4. Set `prevDigest = digest` and
   `prevValidUntilMs = min(validUntilMs, now_ms + PREVIOUS_ROSTER_GRACE_MS)`.
   Install `next` and emit `SccpRosterRotated(generation, digest, validUntilMs)`.

The constructor (EVM/TRON) or `sccp_init` (TON) applies the validity bounds of
step 3 to the initial roster: `validFromMs ≤ now_ms + MAX_CLOCK_SKEW_MS`,
validity ≤ `MAX_ROSTER_VALIDITY_MS`, and
`now_ms < validUntilMs ≤ now_ms + MAX_ROSTER_VALIDITY_MS`.

Rotations are sequential, and a lagging destination replays each generation in
order (Torii `/v1/sccp/rosters/rotations`, batched into one `rotateRosters`
call). If the current roster expires before anyone rotates, the destination is
**frozen for minting and `voidExpired` forever**:

- burns stay open;
- `voidFrozen` becomes available once the previous roster has also expired,
  and every in-flight message is refunded (§4.16);
- the Parliament registers a new revision.

Taira's heartbeat guarantees a new generation at the first block at or after
`valid_from + roster_max_age_ms`, and the heartbeat is block-start work
(§4.3.2). Its rotation subject is attested
within `attestation_stall_ms` under the liveness assumption of §4.3.3. Anyone
keeping a destination alive therefore has at least
`roster_validity − roster_max_age − attestation_stall` (about 13 days with the
defaults of 14 d, 1 d and 10 min) to rotate, and the §4.1 rule keeps that
window at least `roster_max_age + 1 d`. Three exceptions void this guarantee:
while the roster derivation fails closed (§4.3.2) no heartbeat generation is
created; while Taira itself is halted no block is produced; and until the
Sumeragi core proposer builds blocks for pending start-of-block work (§13
item 2), an idle Taira produces the heartbeat block only when a transaction
arrives, so the window shrinks by however long Taira stays idle past
`valid_from + roster_max_age_ms`. Under
validator churn a new generation can start at every epoch boundary (§4.3.2),
so a destination that lags by `k` generations replays `k` rotations; each
`rotateRosters` call carries up to 16. The minting pause does not block
rotation.

#### 5.1.6 Parliament controls (`applyControl`)

The minting pause of a destination is set only by the Parliament, through
control leaves (§3.4, §4.14.6). Direct-mode inputs are an attestation `A`,
signatures, the roster and a control proof
`{controlNonce, paused, leafIndex, path}`:

1. Chain identity, as in §5.1.3.
2. The roster is accepted (§5.1.2), and at least `t` valid signatures cover
   `digest(A)`.
3. `A.messageCount ≥ 1`. `leaf` is the control leaf of §3.4 computed from the
   contract's own immutables (`lane_bytes(sora-taira, own network)` with the
   own `tairaNetworkId`, the own destination word, the own `routeRevision`)
   and the supplied `controlNonce` and `paused`, and
   `merkle_root(leaf, leafIndex, A.messageCount, path) = A.sccpRoot`.
   Historical mode verifies the leaf against `{height, sccpRoot,
   messageCount}` and that block against `A.historyRoot` exactly as in §5.1.3.
4. `controlNonce > controlNonce_state`, else revert `StaleControl()`. Gaps are
   allowed: only the newest control needs to be applied.
5. Set `mintingPaused = paused` and `controlNonce_state = controlNonce`;
   `opCount += 1`; emit `SccpControlApplied(controlNonce, paused)`.

`applyControl` is permissionless and is not itself blocked by the pause. It
needs an accepted roster, so a frozen destination cannot apply controls, which
is harmless because it can never mint again. Burns, rotations and voids are
never paused. The destination therefore holds no privileged key at all: the
Parliament decides, the bridge roster only attests the committed Taira block
that carries the decision, and any relayer delivers it.

#### 5.1.7 `transferToTaira`

Burns wrapped XOR from the caller and emits the source event:

- **Canonical calldata** (EVM and TRON): the contract reverts with
  `NonCanonicalCalldata()` unless all of these hold:
  - `msg.data.length = 4 + 0x80 + ceil32(len)`;
  - the offset word of `tairaRecipient` is `0x60`;
  - `len` is in 1..=1024;
  - the padding after the recipient bytes is zero.

  Solidity's own decoder accepts other encodings. Taira proves TRON burns from
  calldata (§4.12.2), so only canonical calldata may succeed.
- recipient: `taira_account` bytes, 1..=1024.
- `tokenAmount > 0` and `tokenAmount < 2^128` (units are Taira units).
- **EVM/TRON:** `nonce = transferNonces[msg.sender]` MUST equal the
  caller-supplied `expectedNonce`, then increments. Per-sender nonces make the
  payload derivable from calldata, which TRON needs because its logs are not
  header-committed. TRON additionally requires `msg.sender == tx.origin`,
  because internal transactions are not provable on TRON.
- **TON:** the owner MUST be `addr_std` in workchain 0 without anycast.
  Otherwise the minter throws, and the standard bounce restores the wallet
  balance. `nonce = outbound_nonce++` (the Jetton master serializes all
  burns).
- Build the payload per §3.2 (`dest_domain 0`, `deadline_ms 0`, sender =
  caller, route constants) and `message_id` per §3.3 with lane `(own, Taira)`.
  Burn, `opCount += 1`, emit.

Burns are allowed while minting is paused and after roster expiry.

#### 5.1.8 Voids

- **`voidExpired(nonce, A, roster, signatures, messageProof)`** and its
  historical variant run steps 1, 3, 4, 5 and 6 of §5.1.3. They skip the pause
  check (step 2) and the cap check (step 7), and require
  `now_ms > deadline_ms` instead of `≤`. The `nonce` argument MUST equal the
  payload nonce. They mark the nonce consumed, set `opCount += 1` and emit
  `SccpVoided(messageId, nonce)`. Nothing is minted.
- **`voidFrozen(firstNonce, count)`** requires:
  - `1 ≤ count ≤ 256`; on TON, `≤ 512` within one bucket;
  - `now_ms > validUntilMs` and `now_ms > prevValidUntilMs`, which makes the
    freeze permanent;
  - every nonce in the range unconsumed, else revert.

  It marks them all consumed, sets `opCount += 1`, and emits
  `SccpVoided(0, nonce)` per nonce (TON: one external-out message for the
  range). It is permissionless: a frozen destination can never mint again, so
  voiding any nonce is safe.
- **TRON:** void functions require `msg.sender == tx.origin`, because void
  proofs are transaction-based (§4.16).

### 5.2 EVM and TRON (Solidity)

One source file, `contracts/evm/sccp/SccpTairaXor.sol`, is compiled by `solc`
0.8.31 for ETH/BSC and by tronprotocol `tv_0.8.31` for TRON. TRON bytecode MUST
come from the TRON compiler, because it inserts `CALLTOKENID`/`CALLTOKENVALUE`
guards. The contract is the ERC-20/BEP-20/TRC-20 token itself. It makes no
external calls (so it needs no reentrancy guard), and has no owner, no upgrade
path and no setters.

#### 5.2.1 Constructor

```solidity
constructor(
    bytes32 tairaNetworkId,      // nonzero
    uint8   networkTag,          // 0x41 | 0x42 | 0x43
    uint32  routeRevision,       // nonzero
    uint256 maxWrappedSupply,    // token units (9 decimals), nonzero, < 2^128
    RosterV1 memory initialRoster
)
```

The constructor:

- derives the domain (1/2/5), identity word, route id text and
  `REQUIRE_DIRECT_CALLER = (networkTag == 0x43)`;
- requires `block.chainid == identity word`;
- validates the roster (§3.7) and its validity bounds (§5.1.5);
- stores its digest as the immutable `INITIAL_ROSTER_DIGEST` and as the current
  digest, and its generation as the immutable `INITIAL_GENERATION` and as the
  current generation, with `validUntilMs`;
- leaves `prevDigest`, `prevValidUntilMs`, `controlNonce` and `opCount` at 0
  and `mintingPaused` false;
- computes `DOMAIN_SEPARATOR`.

Token metadata: name `Taira XOR`, symbol `tXOR`, decimals 9, initial supply 0.

#### 5.2.2 ABI

```solidity
struct AttestationV1 {
    uint64 height; uint64 epoch; uint64 timestampMs; bytes32 blockHash;
    bytes32 sccpRoot; uint32 messageCount; bytes32 historyRoot; uint64 historySize;
    bytes32 rosterDigest; bytes32 nextRosterDigest;
}
struct RosterV1 {
    uint64 generation; uint64 validFromMs; uint64 validUntilMs;
    uint8 threshold; bytes members;          // n × 20 bytes, §3.7 order
}
struct SignaturesV1 { uint32 signerBitmap; bytes signatures; }   // 65 × popcount
struct MessageProofV1 { bytes payload; uint32 leafIndex; bytes32[] path; }   // path ≤ 9
struct HistoryProofV1 {
    uint64 height; bytes32 sccpRoot; uint32 messageCount;
    uint64 leafIndex; bytes32[] path;        // path ≤ 32
}
struct RotationV1 {
    AttestationV1 attestation; RosterV1 current; SignaturesV1 signatures; RosterV1 next;
}
struct ControlProofV1 {
    uint64 controlNonce; bool paused; uint32 leafIndex; bytes32[] path;   // path ≤ 9
}
```

| Selector | Function | Notes |
|---|---|---|
| `0x8056d161` | `finalizeFromTaira(AttestationV1,RosterV1,SignaturesV1,MessageProofV1) returns (bytes32 messageId)` | §5.1.3 direct |
| `0x96925736` | `finalizeFromTairaHistorical(AttestationV1,RosterV1,SignaturesV1,HistoryProofV1,MessageProofV1) returns (bytes32)` | §5.1.3 historical |
| `0x909ea456` | `rotateRosters(RotationV1[])` | §5.1.5, applied in order |
| `0x0ce970d6` | `applyControl(AttestationV1,RosterV1,SignaturesV1,ControlProofV1)` | §5.1.6 direct |
| `0x935a913b` | `applyControlHistorical(AttestationV1,RosterV1,SignaturesV1,HistoryProofV1,ControlProofV1)` | §5.1.6 historical |
| `0xebfc6ca8` | `transferToTaira(bytes tairaRecipient,uint256 tokenAmount,uint64 expectedNonce) returns (bytes32 messageId)` | §5.1.7 |
| `0xc3de98ad` | `voidExpired(uint64,AttestationV1,RosterV1,SignaturesV1,MessageProofV1)` | §5.1.8 |
| `0xbe335b84` | `voidExpiredHistorical(uint64,AttestationV1,RosterV1,SignaturesV1,HistoryProofV1,MessageProofV1)` | §5.1.8 |
| `0x5b094c00` | `voidFrozen(uint64 firstNonce,uint64 count)` | §5.1.8 |
| `0x85a00f5c` | `rosterState() view returns (bytes32 digest,uint64 generation,uint64 validUntilMs,bytes32 prevDigest,uint64 prevValidUntilMs)` | |
| `0x95b67034` | `isConsumed(uint64 nonce) view returns (bool)` | |
| `0xf6f0e8a6` | `transferNonces(address) view returns (uint64)` | |
| `0x6b91d731` | `tairaNetworkId() view returns (bytes32)` | |
| `0x1818891a` | `routeRevision() view returns (uint32)` | |
| `0xd8bc4dcd` | `maxWrappedSupply() view returns (uint256)` | |
| `0xe1a283d6` | `mintingPaused() view returns (bool)` | |
| `0x4faac8ca` | `controlNonce() view returns (uint64)` | nonce of the last applied control |
| `0xf698da25` | `domainSeparator() view returns (bytes32)` | |
| `0x97525bf3` | `initialRosterDigest() view returns (bytes32)` | |
| `0x3ddaa7c6` | `initialRosterGeneration() view returns (uint64)` | |
| `0xcb58065f` | `opCount() view returns (uint64)` | |
| `0xdeddb507` | `maxRosterValidityMs() view returns (uint64)` | |

Plus the standard ERC-20 surface (`name`, `symbol`, `decimals`, `totalSupply`,
`balanceOf`, `transfer`, `transferFrom`, `approve`, `allowance`, `Transfer`,
`Approval`). Calldata is the standard Solidity ABI encoding of these
signatures. Selectors are the first four bytes of Keccak-256 over the
canonical signature with tuples expanded, for example
`applyControl((uint64,uint64,uint64,bytes32,bytes32,uint32,bytes32,uint64,bytes32,bytes32),(uint64,uint64,uint64,uint8,bytes),(uint32,bytes),(uint64,bool,uint32,bytes32[]))`
→ `0x0ce970d6` (§3.9 names the tool). None collides with an ERC-20 selector.

Events:

```solidity
event SccpTransferToTaira(bytes32 indexed messageId, address indexed sender, uint64 nonce, bytes payload);
event SccpFinalized(bytes32 indexed messageId, uint64 indexed nonce, address indexed recipient, uint256 tokenAmount);
event SccpVoided(bytes32 indexed messageId, uint64 indexed nonce);     // messageId = 0 for voidFrozen
event SccpRosterRotated(uint64 indexed generation, bytes32 digest, uint64 validUntilMs);
event SccpControlApplied(uint64 indexed controlNonce, bool paused);
```

`SccpTransferToTaira` is the inbound source event consumed by Taira (§4.12.2):
`data = abi.encode(uint64 nonce, bytes payload)` and `topics[2] = word(sender)`.
`SccpVoided` is the void event (§4.16). `SccpControlApplied` reports an
applied Parliament control (§5.1.6). Mint and burn also emit ERC-20
`Transfer` from/to `address(0)`.

Custom errors: `WrongChain()`, `MintingIsPaused()`, `RosterNotAccepted()`,
`BadRoster()`, `BadRosterValidity()`, `BadSignatures()`, `TooFewSignatures()`,
`BadProof()`, `BadPayload()`, `AlreadyConsumed(uint64)`,
`SupplyCapExceeded()`, `BadRotation()`, `BadRecipient()`, `BadAmount()`,
`BadNonce(uint64 expected)`, `DirectCallerRequired()`,
`NonCanonicalCalldata()`, `DeadlinePassed()`, `DeadlineNotReached()`,
`NotFrozen()`, `StaleControl()`.

#### 5.2.3 Storage

```
bytes32 rosterDigest;                                  // slot A
uint64  rosterGeneration; uint64 rosterValidUntilMs;   // slot B (packed)
uint64  controlNonce; bool mintingPaused;              //   … same slot B
bytes32 prevRosterDigest;                              // slot C
uint64  prevRosterValidUntilMs; uint64 opCount;        // slot D (packed)
mapping(uint256 => uint256) consumedBitmap;            // word = nonce >> 8, bit = nonce & 255
mapping(address => uint64) transferNonces;
ERC-20: totalSupply, balances, allowances
immutable: INITIAL_ROSTER_DIGEST, INITIAL_GENERATION, TAIRA_NETWORK_ID, NETWORK_TAG,
           ROUTE_REVISION, MAX_WRAPPED_SUPPLY, DOMAIN_SEPARATOR
```

#### 5.2.4 Verification details

- Members come from calldata. The contract recomputes `keccak256` over the
  packed preimage (members are already packed `bytes`), compares it with the
  claimed digest, and checks ordering, `n` and `t` on the fly.
- Signatures are verified sequentially with the `ecrecover` precompile (≤ 21
  recoveries, since `n ≤ 31`). The result is masked to 160 bits before
  comparison. On TRON each recovery costs about 0.92 ms of CPU, so the total
  stays ≤ 20 ms against the 80 ms limit and `BatchValidateSign` (0x09) is not
  needed.
- Payload parsing reads calldata slices, with no memory copies of the payload.
- `transferToTaira` builds the payload in memory and hashes it once for
  `payload_hash` and once for `message_id`.

#### 5.2.5 TRON specifics

- `block.chainid` returns `0x2b6653dc`; `block.timestamp` is in seconds.
- Signatures use `v ∈ {27, 28}` (compatible with current rules and TIP-935).
  `ecrecover` output is masked to 160 bits. A golden test on a local java-tron
  (TRE) node pins the recovered-address word.
- Energy fee is 100 sun. Calldata costs bandwidth (≈1 TRX per KB without free
  or staked bandwidth), so calldata is kept minimal (members 20 B each,
  signatures 65 B each).
- `transferToTaira`, `voidExpired*` and `voidFrozen` require a direct caller.
- One contract means no deployment-address cycle; deployment is one
  `CreateSmartContract` transaction.

### 5.3 TON (Tolk)

Three contracts: `SccpTairaXorMinter` (TEP-74 Jetton master with the bridge
built in), `SccpTairaXorWallet` (TEP-74 wallet) and `SccpConsumedBucket`
(replay flags). All are in workchain 0.

#### 5.3.1 Minter storage (TL-B) and canonical initial data

```
minter_data#_ initialized:Bool total_supply:Coins pending_supply:Coins
    outbound_nonce:uint64 op_count:uint64 control_nonce:uint64
    minting_paused:Bool deployed_buckets:uint64
    config:^MinterConfig roster:^RosterState prev_roster:(Maybe ^PrevRoster) = MinterData;
minter_config#_ taira_network_id:uint256 route_revision:uint32 max_supply:Coins
    initial_generation:uint64 initial_digest:uint256
    wallet_code:^Cell bucket_code:^Cell = MinterConfig;
roster_state#_ digest:uint256 generation:uint64 valid_from_ms:uint64 valid_until_ms:uint64
    n:uint8 t:uint8 members:^MemberChunk = RosterState;
prev_roster#_ digest:uint256 valid_until_ms:uint64 n:uint8 t:uint8
    members:^MemberChunk = PrevRoster;
member_chunk#_ addrs:(k × uint160) next:(Maybe ^MemberChunk) = MemberChunk;   // k = 6 except the last chunk
```

`prev_roster.valid_until_ms` stores the grace-capped value.
`get_jetton_data` builds the TEP-64 content (on-chain name `Taira XOR`, symbol
`tXOR`, decimals `9`) at run time from constants, so no content cell is stored.

**Canonical initial data** for a deployment pinned to Taira generation `G`:

- `initialized = false`; every counter and supply is zero;
  `minting_paused = false`; `deployed_buckets = 0`; `prev_roster = nothing`;
- `config` holds the live `NetworkId`, the revision, the cap, `G` and
  `digest(G)`, plus the wallet and bucket code;
- `roster` holds `digest(G)`, `G`, `valid_from_ms`, `valid_until_ms`, `n`, `t`
  and the members of Taira's generation record, in maximal 6-address chunks.

Taira recomputes the minter address from exactly this data at `RegisterRoute`
(§4.14.3). The stored roster fields are therefore bound to the pinned digest by
construction.

**`sccp_init`** (permissionless, once) completes deployment. It requires
`initialized = false` and `GLOBALID = −239`. It recomputes the §3.7 digest from
the stored roster fields and `taira_network_id`, and checks the `n` range, the
`t` formula and member ordering. It requires the result to equal both
`roster.digest` and `config.initial_digest`, requires
`generation = initial_generation`, and applies the §5.1.5 validity bounds. It
then sets `initialized = true`. Every other operation throws until then.

#### 5.3.2 Cell formats

```
attestation#_ height:uint64 epoch:uint64 timestamp_ms:uint64 message_count:uint32
    history_size:uint64 block_hash:uint256 sccp_root:uint256
    tail:^AttestationTail = Attestation;                              // 800 bits
attestation_tail#_ history_root:uint256 roster_digest:uint256
    next_roster_digest:uint256 = AttestationTail;                    // 768 bits
signatures#_ signer_bitmap:uint32 first:^SignatureCell = Signatures;
signature_cell#_ r:uint256 s:uint256 v:uint8 next:(Maybe ^SignatureCell) = SignatureCell;
message_proof#_ leaf_index:uint32 path_len:uint8 payload:^SnakeBytes
    path:(Maybe ^HashChunk) = MessageProof;
history_proof#_ height:uint64 sccp_root:uint256 message_count:uint32 leaf_index:uint64
    path_len:uint8 path:(Maybe ^HashChunk) = HistoryProof;
hash_chunk#_ hashes:(k × uint256) next:(Maybe ^HashChunk) = HashChunk;   // k = 3 except the last chunk
roster_spec#_ generation:uint64 valid_from_ms:uint64 valid_until_ms:uint64
    n:uint8 t:uint8 members:^MemberChunk = RosterSpec;
control_proof#_ control_nonce:uint64 paused:Bool leaf_index:uint32
    path_len:uint8 path:(Maybe ^HashChunk) = ControlProof;
```

- **`SnakeBytes`** is a standard snake cell. All data bits are bytes, and the
  continuation is the single reference when present. A chunk with a
  continuation holds exactly 127 bytes; the last chunk holds 1..=127 bytes;
  there are no empty chunks and no other references. Contracts reject any
  other shape, and golden BoCs pin it (§11).
- **Signatures** appear in ascending bitmap order, one per cell (521 bits; two
  do not fit in 1 023 bits).
- **Chunked lists** (`MemberChunk`, `HashChunk`) are maximally packed except
  the last chunk.

#### 5.3.3 Messages

To the minter:

| Op | TL-B | Sender |
|---|---|---|
| `0x53434930` | `sccp_init query_id:uint64` | anyone, once |
| `0x53434631` | `sccp_finalize query_id:uint64 response:MsgAddressInt attestation:^Attestation signatures:^Signatures message:^MessageProof` | anyone; value ≥ `finalize_required_value()` (§5.3.5) |
| `0x53434632` | `sccp_finalize_historical query_id:uint64 response:MsgAddressInt attestation:^Attestation signatures:^Signatures history:^HistoryProof message:^MessageProof` | anyone; same value |
| `0x53435631` | `sccp_void_expired query_id:uint64 response:MsgAddressInt nonce:uint64 attestation:^Attestation signatures:^Signatures message:^MessageProof` | anyone; value ≥ `void_required_value()` |
| `0x53435632` | `sccp_void_expired_historical query_id:uint64 response:MsgAddressInt nonce:uint64 attestation:^Attestation signatures:^Signatures history:^HistoryProof message:^MessageProof` | anyone |
| `0x53435633` | `sccp_void_frozen query_id:uint64 response:MsgAddressInt first_nonce:uint64 count:uint16` | anyone |
| `0x53435231` | `sccp_rotate query_id:uint64 response:MsgAddressInt attestation:^Attestation signatures:^Signatures next:^RosterSpec` | anyone |
| `0x53434d31` | `sccp_apply_control query_id:uint64 response:MsgAddressInt attestation:^Attestation signatures:^Signatures control:^ControlProof` | anyone (§5.1.6) |
| `0x53434d32` | `sccp_apply_control_historical query_id:uint64 response:MsgAddressInt attestation:^Attestation signatures:^Signatures history:^HistoryProof control:^ControlProof` | anyone |
| `0x53434431` | `sccp_deploy_buckets query_id:uint64 response:MsgAddressInt count:uint8` | anyone |
| `0x53434332` | `sccp_consumed query_id:uint64 nonce:uint64 amount:uint96 tail:^ConsumeTail` | own bucket (bounceable) |
| `0x53434336` | `sccp_already_consumed query_id:uint64 nonce:uint64 amount:uint96 tail:^ConsumeTail` | own bucket |
| `0x53434334` / `0x53434337` | `sccp_range_consumed` / `sccp_range_rejected query_id:uint64 first:uint64 count:uint16` | own bucket |
| `0x7bdd97de` | `burn_notification query_id:uint64 amount:Coins sender:MsgAddress response_destination:MsgAddress sccp:^SccpBurnToTaira` | own wallet |
| `0xd372158c` | `top_up query_id:uint64` | anyone |
| standard | `provide_wallet_address` / TEP-89 | anyone |

To a bucket (sender MUST be the minter):

| Op | TL-B |
|---|---|
| `0x53434331` | `sccp_consume query_id:uint64 nonce:uint64 amount:uint96 tail:^ConsumeTail` (first 256 body bits = `op ‖ query_id ‖ nonce ‖ amount`) |
| `0x53434333` | `sccp_consume_range query_id:uint64 first:uint64 count:uint16` |
| `0x53434335` | `sccp_unconsume nonce:uint64` |

```
consume_tail#_ kind:uint1 recipient:MsgAddress response:MsgAddressInt message_id:uint256 = ConsumeTail;  // kind 0 mint, 1 void
bucket_data#_ minter:MsgAddressInt index:uint64 bits:uint512 = BucketData;
sccp_burn_to_taira#53434254 recipient:^SnakeBytes = SccpBurnToTaira;
```

External-out messages from the minter:

```
sccp_finalized#5343464e message_id:uint256 nonce:uint64 = ExtOut;
sccp_voided#5343564f message_id:uint256 first_nonce:uint64 count:uint16 = ExtOut;   // message_id = 0 for frozen voids
sccp_transfer_to_taira#53435454 message_id:uint256 nonce:uint64 sender:MsgAddressInt
    amount:Coins payload:^SnakeBytes = ExtOut;
sccp_control_applied#5343434e control_nonce:uint64 paused:Bool = ExtOut;
```

#### 5.3.4 Flows

**Finalize (Taira→TON).**

1. **Minter checks.** `initialized`; `GLOBALID = −239`; not paused; the roster
   is accepted (current or previous, members from storage); the signatures
   (`ECRECOVER` with `v − 27`, low-S checked in-contract, address = low 160
   bits of `HASHEXT keccak256(x ‖ y)`); the Merkle path(s); the payload and
   deadline (§5.1.3); `amount < 2^96`; and
   `msg_value ≥ finalize_required_value()`. It then checks
   `total_supply + pending_supply + amount ≤ max_supply` and sets
   `pending_supply += amount`.
2. **Bucket dispatch.** Let `idx = nonce >> 9`.
   - If `idx < deployed_buckets`, send `sccp_consume` (bounceable) to
     `bucket(idx)` **without** a StateInit.
   - If `deployed_buckets ≤ idx < deployed_buckets + 4`, deploy buckets
     `deployed_buckets..=idx` with StateInit (`bits = 0`), carrying the
     consume on bucket `idx`, and set `deployed_buckets = idx + 1`.
   - Otherwise throw: the caller first calls `sccp_deploy_buckets`.

   A bucket is therefore never redeployed, and its bits can never be reset.
3. **Bucket.** Require sender = minter, and top the balance up to
   `BUCKET_FLOOR` (§5.3.5). If bit `nonce & 511` is unset, set it and reply
   `sccp_consumed` (bounceable) with the remaining value. Otherwise reply
   `sccp_already_consumed` (non-bounceable).
4. **Minter on `sccp_consumed`.** Require sender = `bucket(nonce >> 9)`,
   recomputed from `bucket_code`.
   - Kind **mint**: `pending_supply −= amount`; `total_supply += amount`;
     `op_count += 1`; send the standard `internal_transfer#178d4519`
     (bounceable, `query_id = nonce`) to the recipient's wallet with StateInit
     and `response_destination = response`; emit `sccp_finalized`.
   - Kind **void**: `op_count += 1`; emit `sccp_voided` (count 1); return the
     excess to `response`.

   Every value this handler spends was checked at entry, so it cannot fail. If
   it fails anyway, the bounce of `sccp_consumed` returns to the bucket, which
   clears the bit.
5. **Minter on `sccp_already_consumed`.** For kind mint,
   `pending_supply −= amount`. Return the value to `response`.
6. **Minter on a bounced `sccp_consume`** (bucket failed or does not exist):
   `pending_supply −= amount`. The value stays in the minter, because the
   256-bit bounce body does not carry `response`.
7. **Minter on a bounced `internal_transfer`**, whose first 256 bits carry
   `query_id = nonce` and `amount`: `total_supply −= amount`, and send
   `sccp_unconsume{nonce}` to the bucket. The bucket clears the bit only when
   the sender is the minter, and the message becomes finalizable again. No
   nonce is ever consumed without a mint or a void.

**Void (TON).** `sccp_void_expired*` runs finalize steps 1–4 with kind void:
no pause check, no cap or pending supply, and `now_ms > deadline_ms`, where the
`nonce` field MUST equal the payload nonce. `sccp_void_frozen` requires
`now_ms` past both roster expiries and a range inside one bucket
(`count ≤ 512`). It applies the same deploy rule and sends
`sccp_consume_range`. The bucket sets all bits in the range iff all are unset
and replies `sccp_range_consumed` (bounceable), or `sccp_range_rejected`
otherwise. The minter then emits `sccp_voided(0, first, count)`, and a bounced
`sccp_range_consumed` makes the bucket clear the range.

**Burn (TON→Taira).**

1. The owner sends TEP-74
   `burn#595f07bc query_id amount response_destination custom_payload` to its
   wallet with `custom_payload = sccp_burn_to_taira`.
2. The wallet requires the custom payload, so a plain burn is rejected and no
   value can be burned without a Taira record. It debits the balance and sends
   the extended `burn_notification`.
3. The minter:
   - verifies the wallet address;
   - requires the owner to be `addr_std` in workchain 0 without anycast;
   - validates the recipient bytes (1..=1024);
   - applies `total_supply −= amount` and `nonce = outbound_nonce++`;
   - builds the payload (`sender_codec 7` = owner) and computes `message_id`;
   - sets `op_count += 1`;
   - emits `sccp_transfer_to_taira` and returns the excess to
     `response_destination`.

Any failure throws, and the standard bounce of `burn_notification` restores the
wallet balance.

**Rotate / apply control.** These follow §5.1.5–5.1.6 with members read from
storage. The control leaf uses `lane_bytes(sora-taira, ton-mainnet)` with the
stored `taira_network_id` (target tag `0x44`, identity word `int256(−239)`),
`destination_word` = the minter account id, and the own `route_revision`. An
applied control sets `minting_paused` and `control_nonce`, increments
`op_count` and emits `sccp_control_applied`. A rotation rewrites
`roster_state` and moves the old one to `prev_roster`. Excess value returns to
`response`.

#### 5.3.5 Value, fees and storage rent

- `finalize_required_value()` and `void_required_value()` are computed at entry
  with `GETGASFEE` (per-step gas limits pinned from measured maxima),
  `GETFORWARDFEE` (per-message sizes, including the bucket and wallet StateInit)
  and `GETSTORAGEFEE` (the bucket floor top-up). There is no fixed TON
  constant, so price-config changes cannot break flows.
- **Minter floor.** Before sending any message, the minter reserves
  `MINTER_FLOOR` = `GETSTORAGEFEE` for its own cells and bits over 100 years
  (`raw_reserve`, mode 2). Anyone may add to it with `top_up`.
- **Bucket floor.** Each bucket keeps `BUCKET_FLOOR` = 100 years of its storage
  fee at current prices, topped up from each consume message. Anyone may top
  up a bucket.
- **Why buckets are never redeployed.** The minter attaches StateInit only for
  indices ≥ `deployed_buckets`. A bucket deleted for unpaid rent (practically
  excluded by the floor) makes its nonces unfinalizable and unvoidable until
  someone unfreezes it with its exact public state. It is never recreated with
  zero bits.
- **Duplicate finalizes.** Parallel duplicate finalizes of one message each
  reserve `pending_supply` until the bucket rejects them. Near the cap this can
  delay honest mints by one round trip; this is accepted.

#### 5.3.6 Get methods

- `get_jetton_data` and `get_wallet_address(owner)` (TEP-74).
- `get_sccp_state()` returns `(initialized, taira_network_id, route_revision,
  initial_generation, initial_digest, digest, generation, valid_until_ms,
  prev_digest, prev_valid_until_ms, outbound_nonce, op_count, minting_paused,
  control_nonce, total_supply, pending_supply, max_supply,
  deployed_buckets)`.
- `get_sccp_members() → tuple` and `get_bucket_address(index)`.

Consumption of a nonce is read from the bucket's account state (`bits`) or its
`get_bits` method. A bucket index ≥ `deployed_buckets` means nothing in it is
consumed.

#### 5.3.7 Tolk notes

Tolk 1.4.2 has no ECRECOVER or keccak builtins, so the contracts declare:

- `ECRECOVER` (opcode `0xF912`, stack in `hash v r s`, out `h x y -1` or `0`)
  with a normalizing asm wrapper, to be pinned by an Acton emulator test;
- `HASHEXT` id 3 (keccak256) over builders/slices;
- `GETGASFEE`, `GETFORWARDFEE` and `GETSTORAGEFEE`.

Mainnet global version is 15, so `v` 27/28 would also be accepted, but
contracts pass `v − 27` so they do not depend on that.

### 5.4 Cost estimates

These are estimates, not measurements, at current pricing. `n=4` is Taira
today and `n=31` is the protocol maximum. Tests MUST record measured values
(§11).

| Operation | ETH/BSC gas | TRON energy (+ bandwidth) | TON |
|---|---|---|---|
| `finalizeFromTaira`, n=4 (t=3) | 75k–110k | 35k–60k (+≈1.3 KB) | ≈15k gas at the minter; ≈0.02–0.04 TON consumed including bucket, wallet deployment and rent top-ups |
| `finalizeFromTaira`, n=31 (t=21) | 160k–200k | 95k–120k (+≈3 KB) | ≈50k gas at the minter; ≈0.03–0.05 TON consumed |
| historical mode | +8k–20k | +3k–8k (+≤1 KB) | +2k–5k gas |
| `rotateRosters`, one rotation, n=4 / n=31 | 65k–80k / 160k–180k | 40k–60k / 100k–130k | ≈15k / ≈60k gas (≤ 8 cell writes) |
| `voidExpired` | as finalize minus mint (−20k) | as finalize | as finalize minus wallet deployment |
| `voidFrozen`, 256 nonces | ≈55k + 1.2k per nonce | ≈40k + 1k per nonce | ≈10k gas + bucket round trip |
| `applyControl`, n=4 / n=31 | 55k–85k / 140k–175k | 30k–50k / 90k–110k | ≈12k / ≈45k gas at the minter, no bucket or wallet messages |
| `transferToTaira` | 55k–75k | 40k–60k | standard burn + ≈10k gas |

Drivers: `ecrecover` costs 3 000 (+100 call) per signature; calldata costs 16
gas per nonzero byte (EIP-7623 floor 40); a new consumed-bitmap word costs 22k,
then 2.9k per nonce within the word; a new balance slot costs 22k. Under the
scheduled Glamsterdam repricing (EIP-7976 64 gas/calldata byte floor, EIP-8037
new slot ≈98k), `finalizeFromTaira` at n=31 becomes floor-bound at ≈215k. The
digest-only roster storage and the bitmap consumed set were chosen to stay
robust to it.

**Churn.** A new generation can start at every epoch boundary whose member
list changed (§4.3.2), so the rotation cost a destination pays scales with
validator churn: at most one generation per epoch boundary (6 per day if
Taira produces a block every 4 s, fewer when blocks are slower) plus forced
rotations, and at least one per heartbeat. A finalizer that brings a lagging
destination up to date pays one rotation per missed generation, batched 16 per
`rotateRosters` call.

### 5.5 Toolchains and reproducible artifacts

| Target | Compiler | Settings |
|---|---|---|
| ETH, BSC | solc `0.8.31+commit.fd3a2265` (universal macOS arm64/x86-64, linux-amd64, linux-arm64) | `evmVersion: "cancun"`, `optimizer: {enabled: true, runs: 200}`, `viaIR: false`, `metadata.bytecodeHash: "none"`, `metadata.appendCBOR: false` |
| TRON | tronprotocol `tv_0.8.31` `0.8.31+commit.c2812a3d` (`solc-macos` universal, `solc-static-linux`, `solc-static-linux-arm`) | same settings; TRON mainnet has Cancun, Shanghai and optimized chain id enabled |
| TON | Acton 1.2.0 bundling Tolk 1.4.2 (`acton-aarch64-apple-darwin`, linux builds) | fixed optimization; code cell hashes and depths locked |

- `scripts/contract_tooling/compiler-lock.json` pins the URLs and sha256 of
  these binaries. `contract_artifact_corridor.py` builds, locks and verifies
  artifacts, including each contract's runtime template and
  `immutableReferences`. No Rosetta or Docker is needed on macOS arm64 for
  building. TRE (java-tron) runs need a container runtime and are a separate
  qualification step (§11).
- `evmVersion: cancun` must be explicit because both compilers default to
  `osaka`. The legacy pipeline avoids the via-IR-only 0.8.31 bugs. The source
  MUST NOT `delete` memory `bytes` elements or use custom storage layouts
  (0.8.31 legacy-pipeline bug patterns).
- `Acton.toml` pins `acton = "1.2.0"` (PascalCase wrapper names), and
  `acton simulator` provides local end-to-end emulation.

## 6. Torii read API (served by every Taira peer from state)

All routes are public GETs (`public_sccp_get` descriptors), JSON or Norito by
`Accept`, and derived only from committed state. Every honest peer therefore
returns identical bytes, and wallets may cross-check peers. Wallets never trust
these bytes: signatures, proofs and digests are verified locally (§7).

| Route | Path | Content |
|---|---|---|
| `sccp.capabilities` | `GET /v1/sccp/capabilities` | `{network_id, chain_id, profiles, eip712_domain_separator, parameters, latest_attested_height, current_generation, members_liveness[{index, address, peer, last_signed_height}], pending_handoffs (unattested rotation subjects, with `stalled`), exempt_caps, path templates, limits}` |
| `sccp.registry` | `GET /v1/sccp/registry` | routes, escrow, `stranded`, revisions, deployments, initial roster pin, activation, `destination_frozen`, `destination_paused`, `next_control_nonce`, liability, cap, `next_outbound_nonce` |
| `sccp.messages.recent` | `GET /v1/sccp/messages/recent?direction&network&after_index&limit≤50` | recent outbound and inbound records |
| `sccp.message.status` | `GET /v1/sccp/messages/{message_id}` | outbound `{recorded{deadline_ms}\|attested{signers,threshold}\|voided\|refunded\|stranded}` or inbound `{pending{reason}\|released\|bounced{bounce_message_id}\|unknown}` |
| `sccp.message.proof` | `GET /v1/sccp/messages/{message_id}/proof?attestation=own\|latest\|<height>` | `SccpMessageProofBundleV1`: payload, `deadline_ms`, leaf index, message count, path, attestation statement + digest, roster (members), signature set (≥ t, ascending), optional history proof. Returns 409 `sccp_attestation_pending` until attested. Immutable per query (ETag) |
| `sccp.outbound.by_nonce` | `GET /v1/sccp/outbound/{network}/{revision}?from_nonce&limit≤256` | records by nonce, with status and deadline (void and refund planning) |
| `sccp.attestation` | `GET /v1/sccp/attestations/{height}` and `/latest?generation=G` | statement, digest, status, signatures (from state, or from Kura when pruned) |
| `sccp.roster` | `GET /v1/sccp/rosters/{generation}`, `/current` | roster record, including peers, members, digest and handoff height |
| `sccp.roster.rotations` | `GET /v1/sccp/rosters/rotations?after_generation=G&limit≤16` | the ordered `[{attestation, signatures, current_roster, next_roster}]` catch-up chain, ready for one `rotateRosters` call; reports the first unattested handoff if the chain is broken |
| `sccp.controls` | `GET /v1/sccp/controls/{network}/{revision}?after_nonce&limit≤64` | control records (§4.14.6) with nonce, `paused`, height, commitment index, enacting proposal id and attestation status |
| `sccp.control.proof` | `GET /v1/sccp/controls/{network}/{revision}/{control_nonce}/proof?attestation=own\|latest\|<height>` | `SccpControlProofBundleV1`: control fields, leaf index, message count, path, attestation statement + digest, roster, signature set (≥ t, ascending), optional history proof; ready for one `applyControl` or `sccp_apply_control`. 409 `sccp_attestation_pending` until attested |
| `sccp.history.proof` | `GET /v1/sccp/history/{height}?size=S` | history leaf and path within `history_root(S)` |
| `sccp.bridge_keys` | `GET /v1/sccp/bridge-keys` | active, pending and retired keys with their accounts (`account_of(key)`); `barred`; binding nonces |
| `sccp.light_clients` | `GET /v1/sccp/light-clients`, `/{network}`, `/{network}/sets`, `/{network}/checkpoints?covering=N` | light-client summary; exact canonical state bytes and `state_hash`; freshness; weak-subjectivity deadline; `supported_until` of the running release's compiled profile (§4.13.2); claim windows (§4.13.5); the nearest retained checkpoint ≥ N |
| `sccp.governance` | `GET /v1/sccp/governance`, `/proposals?status&after`, `/proposals/{proposal_id}` | Implemented today: the revisions, and `/proposals` listing every open proposal oldest first with its full body, whether a new attempt would pass the preflight, and its newest attempt. Target: `sccp_governance_revisions` per subject; SCCP Parliament proposals with the **full `SccpGovernanceProposalV1` body**, subjects and `base_revisions`, whether they are still current (so a reviewer sees a proposal that will be superseded), the expected head frozen into each attempt, a diff against current state for `SetParameters` and activation changes, Parliament attempt id, stage and status, and enactment outcome; `readiness`: eligible citizens against the `[gov]` body sizes, beacon session active and matching the current roster, TLE session active with its remaining fresh-ballot capacity, and every active SCCP attempt with its next due checkpoint height and last progress height (§4.14.5) |

Writes use the generic `POST /v1/pipeline/transactions`,
`GET /v1/pipeline/transactions/{hash}/status` and `POST /v1/fees/quote`. There
are no SCCP-specific submit endpoints, and Torii serves no destination calldata
or BoC projections. The Parliament draft route
`POST /v1/gov/proposals/sccp-route-governance`
(`handle_gov_propose_sccp_route_governance`) takes the
`SccpGovernanceProposalV1` payload; Parliament participation uses the generic
Parliament routes.

## 7. Wallet flows (no hosted services)

Wallets run the native Rust library (§8) against any Taira peer's Torii and
the public RPC endpoints in the user's `[sccp]` client config. These are
third-party endpoints; nothing is operated by the project. Every flow verifies
before paying: attestation signatures against the destination's on-chain
roster digest, Merkle paths, and inbound and void proofs through the same
`iroha_sccp` verifier Taira runs. Every flow journals its raw evidence and
state transitions through `iroha_operation_journal`, keyed by
`NetworkId`, before submitting anything, so it resumes after a crash.

### 7.1 Taira → external

1. `GET /v1/sccp/capabilities` and check `network_id` against the pinned
   deployment set. `GET /v1/sccp/registry` returns the `Bidirectional`
   revision `r`.
2. Read the destination:
   - EVM/BSC: `eth_call rosterState()`, `tairaNetworkId()`, `mintingPaused()`,
     and the `eth_getCode` hash;
   - TRON: `/wallet/triggerconstantcontract` for the same views;
   - TON: `liteServer.runSmcMethod get_sccp_state`.

   Refuse on any mismatch. Also refuse if:
   - the newest control for `r` is a pause. The newest control is the one
     with the higher nonce among the destination's `controlNonce()` (with
     its `mintingPaused()`) and Taira's newest control for `r`
     (`GET /v1/sccp/controls/{network}/{r}`, recorded or attested). A pause
     that Taira recorded but nobody has applied yet therefore refuses, and a
     resume that Taira recorded but nobody has applied yet does not: step 5
     applies it before finalizing;
   - the destination's current roster expires within
     `outbound_ttl_ms + roster_max_age_ms` and no rotation to a later
     generation is available; or
   - the rotation chain from the destination's generation to the current
     generation has an unattested handoff
     (`/v1/sccp/rosters/rotations`, §4.3.3).
3. `POST /v1/fees/quote`, then sign and `POST /v1/pipeline/transactions` with
   `RecordSccpMessage{network, expected_revision: r, amount, recipient}`. Poll
   the status. Read `message_id` and `deadline_ms` from the
   `SccpMessageRecorded` event or `GET /v1/sccp/messages/recent`, and show the
   deadline.
4. Poll `GET /v1/sccp/messages/{id}` until `attested` (≈ 8–12 s).
5. If the destination's generation is behind the attestation's,
   `GET /v1/sccp/rosters/rotations?after_generation=<dest>` and submit one
   `rotateRosters` (EVM/TRON), or `sccp_rotate` messages batched in one
   wallet-v5 external message (TON). If Taira's newest control for `r`
   (`GET /v1/sccp/controls/{network}/{r}`) has a nonce above the destination's
   `controlNonce()`, apply it first with `applyControl` (§5.1.6) once it is
   attested. A pending resume is thereby applied before the finalization; a
   pending pause stops the finalization, which is the intended effect, and the
   message is refunded through a void after its deadline (§7.3).
6. `GET /v1/sccp/messages/{id}/proof?attestation=own` (direct), or `latest`
   (historical) when the own attestation's roster is no longer accepted.
   Verify locally and trim the signatures to exactly `t`.
7. Submit before `deadline_ms`:
   - EVM: `eth_sendRawTransaction` (EIP-1559 type-2) of `finalizeFromTaira*`;
   - TRON: `/wallet/broadcasthex` of a natively built `TriggerSmartContract`;
   - TON: `liteServer.sendMessage` of a wallet-v5 external message carrying
     `sccp_finalize`.

   With `--emit`, the wallet instead exports the unsigned transaction as raw
   bytes or a QR payload for an external signer. WalletConnect, TON Connect
   and TronLink are optional adapters.
8. Confirm with `isConsumed(nonce)` or the bucket bits, and the
   `SccpFinalized` log.

Anyone may perform steps 5–7 for the recipient. Wallet software MUST NOT skip
the control step of step 5.

### 7.2 External → Taira

1. **Pre-burn guard.** The revision is `Bidirectional` or `InboundOnly`. The
   lane's light client is not frozen, has at least 25 % of its
   weak-subjectivity bound left, and is not within 7 days of `supported_until`
   (`GET /v1/sccp/light-clients/{network}`). The recipient literal decodes
   (checksum verified) to `AccountAddress` bytes of at most 1024 bytes whose
   controller account admission allows. The account need not exist. Refuse
   otherwise.
2. **Burn.** EVM/TRON: read `transferNonces(sender)`, then call
   `transferToTaira(recipient, amount, expectedNonce)` with canonical ABI
   encoding. TON: jetton `burn` with `sccp_burn_to_taira`.
3. **Collect and journal evidence** from public RPC as soon as the source block
   is final:
   - **ETH:** `eth_getTransactionReceipt`, `eth_getBlockReceipts(B)` (rebuild
     the receipt trie), `eth_getBlockByNumber(B)` (re-encode the header and
     check the hash), beacon `/eth/v1/beacon/light_client/finality_update`.
     For ancestry, either `eth_getBlockByNumber(B+1..E)` for `HeaderChain`, or
     `eth_getProof(0x0000F90827F1C53a10cb7A02335B175320002935, [B mod 8191], E)`
     for `HistoryContract` (state at `E` must still be available).
   - **BSC:** the same receipt and header calls, and `eth_getBlockByNumber` of
     descendants for the vote attestation in `extraData`.
   - **TRON:** `/wallet/getblockbynum` (full transactions; use `raw_data_hex`,
     rebuild `txTrieRoot`), `/wallet/getblockbylimitnext` for the solidity
     segment, `/walletsolidity/gettransactioninfobyid` for discovery.
   - **TON:** liteserver ADNL (`ton.org/global-config.json` peers):
     `getMasterchainInfo`, `lookupBlock`, `getBlockHeader`, `getBlockProof`,
     `getShardBlockProof`, `getTransactions`, `getOneTransaction`.
4. `GET /v1/sccp/light-clients/{network}`. If the light client does not cover
   the evidence, build `AdvanceSccpLightClientV1` updates with
   `expected_state_hash`: ETH `/eth/v1/beacon/light_client/updates`; BSC set
   transitions; TRON segments; TON key-block `getBlockProof` links.
5. Run the verifier locally, then submit **promptly** (§4.13.5):
   - A user without XOR submits a self-claim `[Register<Account>(self)?,
     AdvanceSccpLightClientV1…, SubmitSccpInboundMessageV1]` signed by the
     recipient key (§4.12.4).
   - Otherwise the user submits the same instructions from any funded account.
6. If the record is `Pending` (revision paused, SCCP disabled), retry later
   with `SettleSccpV1::Inbound(message_id)`.

### 7.3 Refunds (outbound that did not mint)

1. After `deadline_ms`, check `isConsumed(nonce)` or the bucket bits. If the
   nonce is unconsumed:
   - if the destination roster is still accepted, submit `voidExpired*` with
     the same proof bundle as finalization;
   - if the destination is frozen, submit `voidFrozen(first, count)` over the
     unconsumed range (`GET /v1/sccp/outbound/{network}/{revision}`).
2. Collect the void evidence exactly as in §7.2 step 3 (the `SccpVoided` log,
   the TRON void transaction, or the TON `sccp_voided` external-out), and
   submit `SubmitSccpOutboundVoidV1`. If it is left `Pending`, retry with
   `SettleSccpV1::Refund`.

### 7.4 Destination upkeep, deployment and registration

- **Rotation keeper.** Anyone runs `iroha sccp roster sync --target <profile>`,
  which reads `rosterState`, walks `/v1/sccp/rosters/rotations`, submits one
  `rotateRosters`, and applies the newest pending control. It must run at
  least once per `roster_validity − roster_max_age − attestation_stall`
  (§5.1.5) per destination, which is also done implicitly by every finalizing
  wallet. Validator nodes do not
  rotate destinations, because they hold no external-chain funds.
- **Control relay.** After the Parliament enacts `SetDestinationPaused`,
  anyone (normally the proposer) runs
  `iroha sccp control apply --target <profile>`, which fetches
  `/v1/sccp/controls/{network}/{revision}/{nonce}/proof` for the newest
  control once it is attested and submits `applyControl`
  (`sccp_apply_control` on TON). `iroha sccp control status` compares Taira's
  newest control with the destination's `controlNonce()`.
- **Light-client keeper.** This runs in validator nodes by default (§4.13.4).
  Anyone may also run `iroha sccp light-client advance --network <p>`.
- **Deployment.** `iroha sccp deploy <evm|tron|ton>` deploys from locked
  artifacts with the deployer's key. It pins the current generation read from
  the operator's own node, or cross-checked across the configured peers. It
  calls `sccp_init` on TON and prints the `RegisterRoute` action. ETH and BSC
  deployments MUST use different deployer addresses or nonces, because
  destination words must be unique (§4.14.3).
- **Registration and every other decision.** A bonded citizen (or a holder of
  `CanProposeSccpRouteGovernance`) runs
  `iroha sccp governance propose --actions <file>`, which builds and checks an
  `SccpGovernanceProposalV1` (for a new route: `RegisterRoute`,
  `InitializeLightClient` with a bootstrap from
  `iroha sccp light-client bootstrap build`, and `ActivateRevision`) and
  submits `ProposeSccpRouteGovernance`. Reviewers run
  `iroha sccp deployment verify` and `iroha sccp light-client bootstrap
  verify` (§4.14.4) against the body shown by `iroha sccp governance show`.
  Anyone runs `iroha sccp governance drive` (§4.14.5 item 4), which creates
  the attempt and carries it through the permissionless transitions; the
  seated members act with the `iroha gov parliament` commands, and enactment
  is automatic (§4.14.3).

## 8. Off-chain Rust

- **`crates/iroha_sccp`** is network-free and linked into `iroha_core`. It
  holds:
  - the v1 payload codec and amount rules, hashes, transfer and control
    leaves, Merkle and history functions;
  - EIP-712 digests, the roster digest and signature verification;
  - the `SccpGovernanceProposalV1` static validation and subject mapping;
  - the per-chain inbound and void verifiers and light-client logic;
  - TON cell hashing and StateInit address derivation;
  - Torii DTOs (`api.rs`).
- **`crates/iroha_sccp_rpc`** (std; network I/O) is used by the irohad keeper,
  the CLI and the wallet. It holds:
  - endpoint lists with failover, and per-endpoint secret headers read from
    owner-only files;
  - blocking `reqwest` (rustls, no `json` feature) with `norito::json`
    parsing;
  - EVM JSON-RPC, the beacon API (JSON light-client and header routes), TRON
    HTTP (transaction bytes from `raw_data_hex`; `ret` re-encoding pinned by
    captured fixtures), and a TON ADNL-TCP liteclient with its ADNL handshake
    crypto built from workspace crypto crates;
  - the compiled default public endpoint lists that `iroha_config` exposes as
    defaults;
  - builders for advances, backfills, inbound proofs, void proofs and
    light-client bootstraps.
- **`crates/iroha_sccp_wallet`** (std; never in the `irohad` graph, enforced
  by the `sccp_wallet` layer in `ci/dependency_budget.json`) holds:
  - `pure/`: bundle and rotation verification, EVM ABI encoding and EIP-1559
    signing, the TRON `Transaction.raw` protobuf builder and signing, TON
    cell/BoC builders and wallet-v5 messages. These are FFI-exportable for SDK
    bridges;
  - `journal.rs`: the resumable journal keyed by `NetworkId`, built on
    `iroha_operation_journal`. The resumable, journaled flows of §7
    that write through it are still to be built (TODO(ws51));
  - `config.rs`: the client-config `[sccp]` table (file-only): endpoint lists,
    timeouts and pinned deployments per `NetworkId`.
- **`crates/irohad`** has `sccp_attestor.rs` (§4.9: key generation, automatic
  registration, signing, graceful-shutdown handoff) and its light-client
  keeper `sccp_attestor/keeper.rs` (§4.13.4). Both are enabled by default. Their
  configuration lives in `iroha_config` (`[sccp.attestor]` with `key_dir`
  derived from `kura.store_dir`, `[sccp.light_client_keeper]` with the default
  endpoint lists; user → actual → defaults; no environment variables).
- **CLI** `iroha sccp {info, routes, recent, send, status, proof, finalize,
  roster sync, control status|apply, burn, claim, settle, void, refund,
  light-client status|advance|backfill|bootstrap build|bootstrap verify,
  deploy, deployment verify, governance propose|show|drive, bridge-key
  status|rotate}`.
  - `governance propose` builds, statically validates and submits
    `ProposeSccpRouteGovernance`; Parliament participation uses the
    `iroha gov parliament` commands, including timed-OVN ballot-key
    registration and ballot casting (`ballot register|cast`, §4.14.5). There
    is no governance signing command, because bridge keys never approve
    anything.
  - `governance drive` is the Parliament driver of §4.14.5 item 4: it creates
    SCCP attempts, submits the permissionless progress transitions and the
    exact-height checkpoints, collects release partials for
    `FinalizeOpenedBallot`, and ticks an idle tip, from the configured funded
    account.
  - `bridge-key status` shows the node's keys and their on-chain state;
    `bridge-key rotate` writes a new key into the node's `key_dir`, which the
    running node registers itself. Neither is needed for normal operation.
  - Taira keys come from `account.private_key_file`.
  - External keys come only from owner-only key files or `iroha_wallet`
    named wallets.
  - `--emit` exports unsigned transactions for external signers.
  - No keys on argv or in environment variables.
- **SDKs (phase 2):** read models, `RecordSccpMessage` building, bundle
  verification and destination encoding, via `connect_norito_bridge` (Swift,
  Kotlin, C#) and `iroha_js_host` (JS). Python only verifies. Java has no
  SCCP surface.

## 9. Security analysis

### 9.1 Trust assumptions and operational dependencies

| Direction | Safety holds if | Liveness needs |
|---|---|---|
| Taira → X | fewer than `t = ⌊2n/3⌋+1` members of each generation accepted by the destination sign non-canonical statements (the Taira BFT assumption, applied to bridge keys), the deployment was pinned to a genuine generation (§9.7), and the Parliament registered a genuine deployment | `t` online attestors, including `t` of each outgoing generation for its handoff (§4.3.3); one honest submitter on X before the deadline; a rotation within the validity window, done by any finalizer or keeper. Otherwise a void and refund recovers the value |
| X → Taira | the source chain's finality assumption (ETH ≥ 2/3 sync committee; BSC ≥ 2/3 Parlia BLS votes; TRON ≥ 19 of the 27 active SRs; TON > 2/3 validator weight) within the weak-subjectivity bound, **and** Taira BFT, **and** a genuine Parliament-enacted light-client bootstrap | one submitter within the claim window (§4.13.5); a light client kept within `ws_bound` by wallets or keepers, or re-initialized by the Parliament |
| Governance | the SORA Parliament enacts only what its seated citizens approve: honest sortition (beacon uniqueness), ballot integrity (timed-OVN) and a citizen majority in each body (§9.13) | a seated Parliament: bonded citizens who respond within the windows, a running Parliament driver, the global beacon and TLE sessions re-keyed on every roster change, and the TLE session threshold online at each release height (§4.14.5) |

Taira today runs 4 validators on one host under one custody owner, and its
genesis citizens are provisioned by the same reset tooling, so the effective
trust in every direction is that operator. The protocol is correct
for any `n ≤ 31` and any citizen count; decentralization is a deployment
property.

**Operational dependencies.** None of these is a hosted service, and none adds
trust, but each needs someone to act:

- after each Taira reset, someone redeploys four mainnet contracts, a citizen
  makes the three bring-up proposals (§4.14.5), and the Parliament enacts
  them;
- the Parliament must stay seated: citizens respond within the phase windows,
  someone runs the Parliament driver (any funded account), and validators run
  the beacon and TLE signers;
- validators need do nothing for SCCP itself: their nodes generate and
  register bridge keys, attest and keep light clients fresh by default, from
  accounts that need no funds because those transactions are fee-exempt on
  success. This zero-touch guarantee covers SCCP only. The Parliament's
  beacon and TLE credentials are a separate validator requirement until they
  are node-generated by default (§4.14.5 item 7), and validator churn needs
  automated beacon and TLE re-keying (§4.14.5 items 5–6, §12);
- someone applies Parliament controls on destinations (any finalizing wallet
  does it as a side effect, §7.1);
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
  message id binds both network identities. A message therefore cannot be
  minted twice, or on another contract, chain, revision or Taira network. TON
  buckets are never redeployed, so their bits cannot be reset.
- **Taira:** `sccp_inbound_messages[message_id]` is permanent. Message ids are
  unique because source nonces are per-sender (EVM/TRON) or serialized (TON),
  and the payload includes the sender, nonce and revision. Void proofs act only
  on records in status `Recorded`.
- **Controls:** a destination applies a control only with a nonce above the
  last applied one, so a stale pause or resume can never be replayed after a
  newer one. The control leaf binds the Taira network, the target network, the
  destination word and the revision, so a control cannot be applied to another
  deployment, chain, revision or Taira network.
- **Governance:** each Parliament decision is enacted at most once by the
  Parliament pipeline, and its per-subject expected head supersedes it if
  another decision changed the same subject first (§4.14.3). No signed
  governance statement exists to replay.
- **Signatures:** attestation signatures cannot be replayed across Taira
  networks (EIP-712 salt) or into the key PoP (distinct typehashes).
  Bridge-key bindings carry a monotone per-peer nonce.

### 9.3 Rogue keys and key binding

A bridge key enters a roster only with (a) the peer's consensus-key consent
over a fresh binding nonce and (b) a proof of possession of the secp256k1 key
over a statement naming the peer and epoch. Addresses are globally unique and
never reused. One key therefore cannot occupy two slots, a key cannot be
claimed by two peers, and faults are attributable forever. ECDSA has no
aggregation, so rogue-key cancellation does not apply, and PoP prevents
registering someone else's address. A faulted peer is barred from new keys
until the Parliament clears it. Automatic registration changes none of this:
the node produces both signatures itself from its own consensus key and its
own bridge key, and a binding for a peer whose consensus key the submitter
does not hold cannot be formed.

### 9.4 Signature malleability and counting

Contracts and Taira enforce:

- low-S, `v ∈ {27,28}`, and nonzero `r` and `s`;
- a nonzero recovered address, masked to 160 bits;
- signers addressed by position through a bitmap;
- strictly ascending nonzero members.

Duplicated or malleated signatures therefore cannot inflate the count.
Consumption is keyed by nonce, never by signature bytes.

### 9.5 Domain separation

Digests are separated at several levels:

- the EIP-712 `0x1901` prefix, per-type typehashes, and the Taira `NetworkId`
  salt;
- ASCII role prefixes for the payload, message, transfer leaf, control leaf,
  node, history and roster hashes;
- distinct leaf and node prefixes and preimage lengths, with verifiers
  computing leaves themselves, so an internal node cannot pass as a leaf and a
  transfer cannot pass as a control or the reverse;
- a bound leaf index and count (positional proof with an authenticated
  `messageCount` / `historySize`).

The bridge key signs exactly three kinds of input: EIP-712 `SccpAttestation`
and `SccpBridgeKey` digests (keccak-256 with the `0x1901` prefix), and Iroha
transactions of its own account that the node builds itself (attestations, its
own key registration and keeper advances), which Iroha's secp256k1 scheme
hashes with SHA-256. Both are prehash signatures over different hash
functions: making one valid as the other needs a SHA-256 output equal to a
chosen keccak-256 digest, a 2^256 search. The attestor never signs caller-
supplied bytes. The key never signs Ethereum transactions.

### 9.6 Cross-chain / cross-route confusion

The same attestation is valid on all destinations by design. Each destination
accepts only leaves with its own destination word, domains, revision and route
id. Control leaves carry the Taira and target network bytes, the destination
word and the revision. Destination words are unique across all registered routes
and revisions. Deployments at colliding addresses on other chains (EVM CREATE
collisions) are rejected by the `block.chainid` / `GLOBALID` check and could
mint only unregistered, unredeemable tokens.

### 9.7 Deployment integrity

**Threat.** Without a Taira key, an attacker deploys a contract with a fake
initial roster. It mints to itself, burns back to zero supply, rotates to the
real generation, and gets the deployment registered. That would pre-consume
honest nonces and leave provable burns that drain escrow.

**Defense.**

- **EVM/TRON:** the initial roster digest and generation are immutables inside
  the verified runtime code. Taira pins `initial_roster_digest` from its own
  roster record. Parliament reviewers verify, against Taira state, that the
  code, the initial pin, `opCount = 0`, zero supply, zero control nonce and a
  genuine roster chain all hold before the vote (§4.14.4). A Parliament that
  registers an unverified deployment is covered by §9.13.
- **TON:** Taira itself recomputes the minter address from canonical initial
  data built from its own generation record (§4.14.3), and `sccp_init`
  rechecks the stored roster against the digest.

With a genuine initial roster, no mint, void or burn is possible before
registration.

### 9.8 Taira reset

A reset gives a new `NetworkId` (enforced by the genesis reset nonce), which
means a new domain separator, new lane bytes and new roster digests. No old
attestation, message or burn is valid across the reset. The Parliament should
pause old deployments before the reset (§4.18); either way they freeze when
their last roster expires, because the old keys are destroyed with the node
stores and no rotation can follow. Their burns are not accepted by the new
Taira. The stranded value is the documented cost (§4.18).

### 9.9 Long-range attacks and weak subjectivity with free exit

**Threat:** validators leave freely: SCCP adds no bond, no handoff delay and no
withdrawal hook, and Taira's unbonding delay is 0. After `t` members of a past
generation have left, they (or whoever obtains their keys) sign a fake
successor roster or fake messages against a destination that still trusts that
generation. This is the weak-subjectivity problem of Ethereum light clients:
exited keys stay dangerous for exactly as long as someone still trusts them.
Mitigations:

1. Destinations accept a generation only until its `valid_until_ms`. Taira
   starts a successor at the first epoch boundary after every membership
   change and at the first block past every `roster_max_age_ms` (1 d)
   (§4.3.2), except while the roster derivation fails closed, Taira is
   halted, or Taira is idle before the core proposer builds blocks for
   pending start-of-block work (§13 item 2). A kept destination rotates to it
   and then accepts the previous roster for at most the 24 h grace, so it
   never trusts a departed validator's key much beyond one day after the
   first successor generation that follows the departure. An unkept one
   trusts a generation for at most `roster_validity_ms` (14 d) from its
   `valid_from_ms`.
2. Every roster a destination installs is bounded by the immutable
   `MAX_ROSTER_VALIDITY_MS` (30 d) relative to the destination's own clock, and
   `validFromMs` must equal the attested block time within
   `MAX_CLOCK_SKEW_MS`. Even `t` retired keys cannot install a roster that
   outlives this bound. Honest attestors refuse future-dated rotation subjects
   (§4.9). Taira's parameter bound matches the contract constant, and the
   Parliament cannot set `roster_validity_ms` above it (§4.1).
3. An unkept destination freezes (minting and `voidExpired`) when its roster
   expires. It never accepts a rotation signed by an expired roster, and its
   in-flight value is refunded through `voidFrozen` (§4.16).
4. **Attribution without deterrence.** Any forged statement, including one
   found in any destination's calldata, is attributable via
   `SubmitSccpAttestationFaultV1` and bars the peer, but an exited validator
   has no stake left to slash, so slashing cannot back these bounds. The time
   bounds (1–3) are the protection, by design rather than only on today's
   Taira. The attack still needs `t` keys of one generation, that is a
   supermajority of that generation's validators colluding or compromised
   after they left.
5. Inbound light clients enforce per-chain `ws_bound_ms` against Taira block
   time, and freeze on proven equivocation.

Keeping destinations rotated is the operative defense. Every finalizing wallet
rotates as a side effect, and `iroha sccp roster sync` is cheap to run daily.

### 9.10 Liveness, censorship and failure recovery

- **Censorship.** Censoring `RecordSccpMessage`, attestations, proofs or voids
  on Taira requires control of proposers across leader rotation. Any validator
  node resubmits attestations, and any wallet can relay stored signatures.
  Destination-side censorship affects only timing, because every destination
  call is permissionless and idempotent.
- **Attestor failure.** Taira refuses new records when attestation of the
  signing generation stalls (§4.4 step 2). Missing members are visible in the
  capabilities liveness list, and forced generations drop unusable slots at
  the next rotation height.
- **Churn.** A handoff needs `t` nonzero members of the outgoing generation
  within the attestation window (§4.3.3). They need not all still be
  validators at the boundary: members that left the committee since `g` was
  created, or while the roster derivation fails closed (§4.3.2), sign only as
  observers (§4.3.3, §13 item 9). The attestor signs handoffs first and before
  a graceful shutdown, and the stalled-handoff event makes a failure
  visible. An abrupt loss of more than
  `n − t` usable members of one generation exactly at a boundary leaves that
  handoff unattested; destinations still on that generation then freeze at
  its expiry and refund through voids, and the Parliament registers new
  revisions. Value is delayed, not lost.
- **Churn and governance.** Every validator-set change needs a new global
  beacon session before the next pulse and a new Parliament TLE session
  before the next ballot, because both are bound to the roster (§4.14.5
  items 5–6). A ballot in flight across a roster change needs the session
  threshold of its frozen roster online at its release height, so departing
  validators keep their TLE custody running until their ballots' retention
  deadlines. Without automated re-keying, churn stalls governance (and, for
  the beacon, consensus) regardless of SCCP.
- **Pause latency.** A destination pause is a Parliament decision: at least
  one full round (at least 13 004 blocks with Taira's current windows, about
  1 104 with the recommended profile, plus the variable parts of §4.14.5, and
  unbounded in wall-clock time without the driver's ticks), then an
  attestation (seconds) and one `applyControl` by anyone. There is no faster
  emergency brake, because validators decide nothing. Until the control is
  applied, the destination keeps minting what the roster attests. What bounds
  the damage meanwhile: the immutable destination cap; Taira's own liability
  accounting, which never lets the destination mint more than was locked
  under honest attestation; and honest wallets, which apply a recorded control
  before finalizing (§7.1). Validators halting Taira is outside the protocol
  and is not part of SCCP's response. The Parliament MAY adopt shorter phase
  windows for SCCP (§13).
- **Destination freeze, pause or retirement never strands value.**
  - Unminted outbound messages are voided and refunded (§4.16), including on a
    paused destination, where `voidExpired` stays open.
  - Revision states admit proofs everywhere except `Staged`.
  - `Retired` requires zero liability.
- **Inbound.** A proof, once accepted, never expires (§4.12). Claim windows
  bind only the prove step (§4.13.5), and wallets prove promptly. Light
  clients are kept fresh by claims and by the in-node keeper. A source-chain
  hard fork beyond `supported_until` is recovered by a Taira release that
  extends the compiled profile (§4.13.2). A stale or frozen light client, or a
  burn older than its window, is recovered by Parliament re-initialization or
  a trusted checkpoint, with bootstraps built and checked from public RPC by
  reviewers. Wallets refuse to burn when a lane is at risk (§7.2), which
  bounds exposure to burns made just before a fork or staleness.
- **Governance liveness.** Without a seated Parliament (§4.14.5) nothing can be
  registered, paused or recovered, but existing routes keep working, value
  keeps flowing and voids and refunds stay available. Silent seated citizens
  fail ballots (every registered juror who has not dropped out must vote,
  §4.14.5 item 2), and cheap
  citizenship lets an attacker seat silent members at will, so the Taira bond
  must be out of faucet reach (§4.14.5 item 1).
- **`enabled = false`** stops only value movement. Proofs, rotations,
  controls and Parliament enactment keep running (§4.1).

### 9.11 Economic safety

- Destination supply ≤ the immutable cap. Taira never records a message that
  would exceed it (§4.15), so no attested message is unmintable because of the
  cap.
- Taira releases, bounces and refunds only up to the revision's liability. A
  compromised source-chain verification can drain at most the route's escrow,
  and a forged bounce is bounded the same way. A compromised Taira attestation
  can mint at most the destination cap minus supply.
- Recipient problems cannot lose value:
  - an absent account is registered at settlement;
  - an undecodable or uncreditable recipient bounces (§4.12.5);
  - a voided bounce lands in `stranded`, which only the Parliament can
    release.
- Dust: `min_outbound_amount` bounds the permanent records a sender can create
  per fee. Self-claims pay `inbound_self_claim_fee` from their proceeds, and
  the per-authority, per-peer, per-message and per-block caps bound fee-exempt
  load.

### 9.12 Key compromise

- **One bridge key (≤ `f`):** no effect on safety. The operator deletes the key
  file or runs `iroha sccp bridge-key rotate`; the node registers a new key,
  which activates at the next epoch and forces a new generation. Faults evict
  a misused key immediately.
- **`≥ t` keys of the current generation:** the attacker can mint on all
  destinations up to their caps. It cannot touch governance, because keys
  approve nothing. The response: the Parliament enacts destination pauses and
  Taira pauses, anyone applies the controls, validators replace their keys,
  and the Parliament registers new revisions if needed. Until then the caps
  bound the loss (§9.10, pause latency). The same compromise of consensus keys
  would already break Taira itself.
- **The node attestor** keeps the key hot in the node's store directory
  (owner-only files). It signs only durably final, locally derived statements
  and the node's own transactions, never caller-supplied input (§9.5).

### 9.13 Governance: the Parliament

- **Trust.** The Parliament is part of the trusted base for what it enacts. A
  captured Parliament could register a malicious deployment and let users send
  value into it (bounded by that revision's liability), re-initialize a light
  client from a fake bootstrap or install a fake checkpoint and release escrow
  of that route against forged burns (bounded by the route's liabilities),
  release `stranded` value, pause or resume destinations, or change
  parameters within their rules. It cannot mint on a destination, forge an
  attestation, move escrow of another route, or change a deployment's cap,
  rosters or consumed nonces.
- **Citizenship cost.** The Parliament is only as Sybil-resistant as its bond.
  On Taira, XOR comes from a faucet, so the bond MUST be far beyond faucet
  reach and the faucet MUST use adaptive difficulty (§4.14.5 item 1). Cheap
  citizens could otherwise capture bodies within the powers above, bounded by
  the affected routes' liabilities, or stall every round, pauses included, by
  accepting seats and staying silent.
- **What validators contribute.** Bridge keys only attest committed state
  (§4.9). Validators also run the global beacon and the Parliament TLE signers
  (§4.14.5): under the beacon's uniqueness a threshold of them can withhold
  pulses or release shares (liveness) or open a timed ballot early (ballot
  secrecy), but cannot choose members, findings, proposals or outcomes;
  session installation binds a roster and a DKG transcript, never a
  proposal.
- **No clerk.** SCCP attempts and their progress transitions are
  permissionless and core-derived (§4.14.5 item 3), so no account outside the
  Parliament chooses which SCCP proposals reach the bodies or when. A driver
  can only submit what core would accept from anyone.
- **Review.** Every enacted body is public before the vote (§6), and reviewers
  can check deployments and bootstraps with local tools against their own
  endpoints (§4.14.4, §4.13.4). Enactment re-checks every on-Taira
  precondition, including the TON address, the pinned generation and the
  bootstrap's freshness.
- **Latency** is a governance property: at least about 1 100 blocks per
  decision with the recommended profile, plus deliberation, and wall-clock
  time that depends on block production (§4.14.5, §9.10).

## 11. Tests and fixtures

Shared vectors live in `fixtures/sccp/`. They are generated by Rust (the TON
StateInit vectors by the contracts themselves) and consumed by contract, node
and SDK tests.

| Fixture | Content |
|---|---|
| `payload_v1.json` | payloads for all 8 directions (with `deadline_ms`), payload hashes, message ids, amount-scale conversions, rejected encodings |
| `commitment_tree_v1.json` | transfer and control leaves, mixed trees, roots and every path for counts 1..=17 and 512, including promoted nodes; a transfer/control/node confusion negative |
| `control_v1.json` | control leaves for every target network with fixed `NetworkId`, destination words, revisions, nonces and both pause values; the `SccpControlApplied` topic |
| `history_v1.json` | history leaves, roots and paths for sizes 1..=40; peak-bagging equivalence |
| `eip712_v1.json` | domain separator for a fixed `NetworkId`; attestation and key-PoP digests; low-S signatures from fixed keys; high-S, `v ∉ {27,28}` and forced recovery-id ≥ 2 negatives |
| `governance_v1.json` | `SccpGovernanceProposalV1` frames with `base_revisions`, subject sets, proposal ids, expected heads (`subject_id`, `version`, `head_root`) for fixed revision maps |
| `roster_v1.json` | roster digests for n = 4, 7, 31 with zero slots; ordering, threshold and validity-bound negatives |
| `evm_calldata_v1.json`, `ton_bodies_v1.json` | golden calldata and BoCs for finalize, historical, rotateRosters, `applyControl` (direct and historical), voids, transferToTaira and burn, with every selector of §5.2.2; non-canonical `transferToTaira` calldata negatives (offset, padding, trailing bytes); snake-cell negatives |
| `ton_stateinit_v1.json` | canonical minter initial data and address for a fixed generation, `NetworkId`, revision, cap and code refs |
| `native_transfer_event_v1.json` | `SccpTransferToTaira` and `SccpVoided` event vectors of the Ethereum light client in the keccak/big-endian layout |
| `rpc/{eth,bsc,tron,ton}/` | captured public-RPC responses for real mainnet blocks. They drive the proof builders and verifiers: finality, ancestry, inclusion, and TRON `raw_data_hex` with `ret` re-encoding, including a multisig-permission transaction |

Required tests:

- **Rust unit tests** for every new function: codecs and amount conversion,
  digests, transfer and control leaves, Merkle and history, roster derivation
  (membership change at every boundary with no minimum interval, including a
  swap of one keyless validator for another detected by the `(peer, address)`
  comparison; forced; heartbeat at a non-boundary block; fault rotation;
  inert generations; fail-closed derivation keeping `g`), signature rules
  including the recovery-id re-sign, every rule of the §4.1 parameter table
  including the joint ones and each boundary value, the governance subject
  mapping and expected head, the SCCP arm of the exact-JSON `u64` invariant,
  and every validation branch of each ISI and governance action.
- **Node (irohad) tests:** key generation into an empty `key_dir` (modes,
  atomic write, refusal of symlinks and foreign keys); key classification;
  automatic `SetSccpBridgeKeyV1` construction; rotation-subject priority;
  graceful-shutdown signing within `shutdown_grace_ms`; a wiped store
  generating and registering a new key; `[sccp.attestor]` and
  `[sccp.light_client_keeper]` defaults parsing with an empty config and the
  compiled endpoint lists.
- **Core, a 4-peer integration test:**
  - The chain `RecordSccpMessage → commit → sccp_block_commitments[h] →
    attestor signatures → BlockAttested → /v1/sccp/messages/{id}/proof`,
    verified by the wallet crate, including a failed record in the same
    block.
  - Zero-touch setup: a fresh validator node with default configuration
    generates its key, registers it fee-exempt from its unregistered key
    account (which core registers), and signs from the next epoch; a second
    exempt binding in the same epoch pays the fee.
  - Churn: a validator joins and one leaves at a boundary; a new generation
    starts there; the outgoing generation attests the boundary (including a
    leaving validator that shuts down gracefully); the handoff-stalled event
    when too many outgoing attestors are killed abruptly; recording is not
    blocked by the stalled handoff; the heartbeat, and, once the core
    proposer builds blocks for pending start-of-block work (§13 item 2), an
    idle Taira with an empty queue producing the heartbeat block through
    block-start work exactly once per generation.
  - Attestation admission rejects invalid, foreign-authority, unknown-subject,
    all-duplicate and queued-duplicate batches, and enforces the exempt cap;
    a keeper advance from the same bridge-key account is admitted while its
    attestation batch is pending.
  - Fault evidence: future height, missing subject, mismatched field;
    immediate rotation; peer bar.
  - Escrow and liability invariants, including the definition-owner burn and
    permissioned transfer negatives and front-run registration of an escrow
    id.
  - Inbound: prove with the revision paused, then settle; self-claim from a
    zero-balance unregistered recipient; bounce onto the `Bidirectional`
    revision; liability shortfall.
  - Outbound: void proof and refund, a voided bounce going to `stranded`, and
    `ReleaseStranded`.
  - Governance through the real Parliament, reusing the `sora_parliament_*`
    integration harness (citizens, beacon and TLE fixtures) with the
    recommended `[gov]` profile and the driver: a route bundle
    (`RegisterRoute`, `InitializeLightClient`, `ActivateRevision`) enacted
    end to end; attempts created and advanced by an account without
    `CanManageParliament`, and manager transitions with non-canonical content
    rejected; proposals on disjoint subjects (for example `LightClient{ETH}`
    and `Parameters`) enacted in either order without supersession; a pause
    proposal (`SetTairaPaused`, `SetDestinationPaused`) and a concurrent
    `SwitchRevision` on the same route, where whichever enacts second is
    `Superseded`; a stale `base_revisions` refusing attempt creation; pause,
    resume and pause again as three distinct proposals; `SetTairaPaused`
    ensure semantics after a frozen void (no-op success);
    `SetDestinationPaused` on a revision retired in between (no-op success);
    `ClearBridgeKeyFault` failing at enactment after a newer fault; a retry
    attempt after `Rejected` succeeding and one after `Superseded` failing;
    an identical re-proposal after `ExecutionFailed` refused; `ExecutionFailed`
    with no state change when a precondition fails at enactment (a stale
    bootstrap, a destination word taken by another route's enactment); the
    proposer rule and the `OnlyGenesis` grant rule; no direct path (every
    `SetParameter` targeting SCCP state rejected by core).
  - Controls: an enacted `SetDestinationPaused` produces a control leaf in the
    enacting block, the roster attests it, the proof bundle verifies in the
    wallet crate and `applyControl` succeeds on EDR; `RecordSccpMessage` is
    refused while `destination_paused` is set.
  - `enabled = false` behavior, with Parliament enactment and controls still
    running.
  - TON `RegisterRoute` address recomputation, and a pinned generation older
    than the current one with an attested rotation chain.
- **Inbound:**
  - per-chain positive proofs from captured mainnet data;
  - Ethereum negatives: fewer than 342 participants, missing finality branch,
    slot ordering, wrong fork version;
  - HeaderChain, HistoryContract window edges, and Backfill;
  - BSC skipping across a set change;
  - TRON active-set learning and eviction, and unknown-signer learning;
  - TON skipped key block, and a shard walk across split and merge;
  - equivocation freeze, weak-subjectivity rejection, fork-bound rejection
    from the compiled profile (and acceptance after the profile is extended,
    with no re-initialization);
  - the checkpoint stride retention rule.
- **Contracts:** EDR (EVM) and Acton (TON) suites for every §5 rule:
  - expired roster, previous-roster grace, batched sequential rotation, and
    the validity, skew and `validFromMs` bounds;
  - frozen destination, deadline edges, `voidExpired`, and `voidFrozen` range
    and revert rules;
  - cap, bitmap word boundaries, bucket boundaries and the non-redeploy rule;
  - bounced consume, bounced internal transfer and unconsume, and bounced
    `sccp_consumed`;
  - plain-burn rejection, and the workchain and canonical-calldata rejections;
  - `applyControl`: pause and resume, stale and equal nonces rejected, a nonce
    gap accepted, historical mode, a control leaf of another network,
    destination, revision or Taira network rejected, a transfer leaf offered
    as a control rejected, and burns, rotations and voids open while paused;
  - initial-roster immutables, `opCount`, `controlNonce = 0`, and `sccp_init`.

  Measured gas and energy are recorded against §5.4. TRON bytecode also runs
  on a local java-tron (TRE) node, including the `ecrecover` masking golden.
- **ABI goldens (open, `TODO(ws45)`):** the syscall `0xA0` argument text in
  `crates/ivm/spec/syscalls.toml`, the generated
  `crates/ivm_abi/src/syscalls_doc_gen.rs` and `crates/ivm/docs/syscalls.md`
  must name only the `1=SubmitBallot` operation tag (§4.4), and `ivm_abi`
  must not define a tag-2 constant. The text still names
  `2=RecordSccpMessage`. Removing that tag changes the ABI v1 hash, so the hash
  golden in `crates/ivm/tests/abi_hash_versions.rs` and every committed `.to`
  fixture and manifest are regenerated in the same change. Syscall numbering
  and `abi_syscall_list_golden.rs` are unchanged.

## 12. Phasing and later work

- **Phase 1 (this spec):** everything above except items marked phase 2.
  Delivery order:
  1. shared primitives (including control leaves) and the Solidity contract;
  2. the Taira outbound pipeline (automatic bridge keys, generations under
     churn, attestor, record, Torii);
  3. the Parliament SCCP payload: `SccpGovernanceProposalV1`, the action
     executor, per-subject expected heads, control messages;
  4. **the Ethereum lane end-to-end first**: Taira→ETH live against a local EVM
     with chain id 1, including a Parliament-enacted pause applied with
     `applyControl`, and ETH→Taira proven from captured mainnet data;
  5. inbound settlement, voids and refunds;
  6. BSC (same contract, skipping light client);
  7. TRON (same source, TRON compiler, TRE qualification under colima on
     macOS);
  8. TON;
  9. SDKs.
- **SCCP's own Parliament changes (phase 1):** the per-subject head, the
  permissionless core-derived SCCP attempts and manager transitions, the
  `OnlyGenesis` grant rule, and `iroha sccp governance drive` (§4.14.3,
  §4.14.5 items 3–4).
- **Prerequisites owned by governance and consensus, not SCCP (launch gates
  for SCCP governance on Taira):** seating the Parliament (§4.14.5): genesis
  citizens with accounts, bonds and fee floats in the reset tooling and
  `scripts/taira_devnet.py`; the recommended `[gov]` profile, the raised bond
  and the adaptive faucet; a mandatory global-beacon bootstrap; in-node beacon
  and Parliament TLE DKGs with automatic `InstallGlobalBeaconKey` and
  `InstallParliamentTleKey` certificates on every roster change and whenever a
  TLE session is exhausted; TLE custody that outlives a validator's departure
  until its ballots' retention deadlines; node-generated beacon and TLE
  credentials (§4.14.5 item 7); and ballot evidence anchored on the Sumeragi
  core's `SumeragiFinalityVerifier` (§4.14.5). Routes cannot be registered on
  Taira before these land; integration tests use the Parliament test harness
  meanwhile.
- **Phase 2:** stake slashing for SCCP faults while still bonded (§4.11); SDK
  parity (§8); MCP `iroha.*` read tools.
- **Later:**
  - carry attestations in Sumeragi commit votes (same digest, no contract
    change);
  - finalizer and claim tips (deferred by decision; a later payload version
    bump, since no backwards compatibility is required);
  - Taira-side verification of EVM deployments by storage proofs through the
    ETH/BSC light clients, replacing reviewer diligence for EVM;
  - destination attested-root caching if measured traffic justifies it.

## 13. Open questions

1. **Parliament TLE and beacon re-keying.** Every roster change needs a new
   beacon session before the next pulse and a new TLE session before the next
   ballot (§4.14.5 items 5–6), and the recommended profile raises
   `max_fresh_ballots_per_session` to 8. No tooling automates the DKGs and
   certificates. Who builds the in-node DKGs, and is 8 ballots per session an
   acceptable adaptive-corruption bound for Taira?
2. **Parliament work at block start.** Iroha produces no empty blocks, so the
   Parliament driver ticks an idle tip, and `CloseBallotRegistration` and
   `FreezeBallotSurvivors` must land at exact heights (§4.14.5 item 4).
   Should core count an active attempt's pending checkpoint, requested pulse
   or enactment as block-start work (as the SCCP heartbeat is, §4.3.2), and
   apply the two exact-height checkpoints automatically at block start? Both
   would remove the ticks and the timing risk. Relatedly, the SCCP heartbeat
   needs the Sumeragi core proposer to build a block for pending
   start-of-block work, probing with the current ledger time at least once
   per proposal timeout; it does not yet (§4.3.2). Who owns that proposer
   change?
3. **Pause latency.** A destination pause takes at least one Parliament round:
   at least about 1 104 blocks with the recommended profile plus
   deliberation, and 13 004 or more with Taira's current windows (§9.10). Is
   an SCCP-specific track with fewer bodies or shorter windows for
   `SetDestinationPaused(true)` and `SetTairaPaused(true)` wanted, and who
   decides its policy?
4. **Taira citizens.** Who holds the 16 genesis citizen keys, and how do they
   stay responsive within the phase windows, given that one silent juror
   fails a ballot? Citizenship on Taira is only as scarce as faucet XOR, even
   with the raised bond and adaptive faucet difficulty (§4.14.5 item 1);
   Taira's Parliament is as nominal as its validator set until independent
   citizens join.
5. **Rotation cost under churn.** A generation per membership change (up to 6
   per day at one block every 4 s) makes lagging destinations pay one rotation each,
   160k–180k gas at `n = 31` on Ethereum. Should SCCP later sign a skip
   certificate (the current generation vouching for a later one), or should
   epochs be longer? Needs measurement once real churn exists.
6. **Abrupt exits at a boundary.** If more than `n − t` members of one
   generation vanish without signing its handoff, destinations on it freeze
   (§4.3.3). How often this happens under real churn, and whether
   `shutdown_grace_ms` suffices, needs measurement.
7. **Taira decentralization and stake.** Four validators on one host with
   `unbonding_delay = 0` make the `t`-of-`n` assumption nominal. With free exit
   by design, slashing never backs the weak-subjectivity bounds (§9.9).
   Distributing validators is a deployment decision outside this spec.
8. **Real mainnet deployments for inbound fixtures.** Positive inbound tests
   with genuine `SccpTransferToTaira` events need the contracts deployed on
   mainnet and real burns. Until then, inbound verification is tested with
   captured mainnet blocks (finality, ancestry, inclusion) plus unit-level
   event binding. Who funds and performs the first mainnet deployments?
9. **Committee changes between boundaries.** The Sumeragi core schedules
   every live validator in both consensus modes and has no election epochs,
   so its committee can change at any height, not only at an epoch boundary.
   SCCP derives generations only at rotation heights (§4.3.2), so a validator
   that leaves mid-epoch stays in the signing generation until the next one.
   Whether that needs a rotation at every committee change needs measurement
   under real churn.
10. **Public RPC coverage of the default lists** (beacon light-client routes,
    `eth_getBlockReceipts` on BSC, TRON full blocks with `raw_data_hex`,
    liteserver reliability and retention) is still unverified, and the chosen
    endpoints' terms of use need a check before the lists are compiled in.
11. **Hard-fork cadence.** Ethereum Glamsterdam/Gloas and frequent BSC forks
    each require a Taira release that extends the compiled profile before
    `supported_until` (§4.13.2); no Parliament action is needed. This is a
    release obligation.
12. **TRON contract callers** cannot burn or void (direct-caller rule), because
    internal transactions are not provable without committed logs.
13. **Parameter tuning** needs measurement: 1 d heartbeat, 14 d validity, 7 d
    outbound TTL, 24 h grace, 10 min stall bound, the exempt cap of 128,
    self-claim fee,
    `shutdown_grace_ms`, TON gas limits per step, and the TON
    `ECRECOVER`/fee opcode wrappers.
14. **Wrapped test XOR on mainnets** is stranded on every Taira reset. Token
    naming and user disclosure need product sign-off.

## 14. Decisions (binding, 2026-09-26)

| # | Decision | Applied in |
|---|---|---|
| D1 | **Governance is the SORA Parliament only**; validators and bridge keys take no part, and no governance statement is ever signed. Every SCCP decision (route registration and revisions with deployment and cap, activation including pause, resume and retirement, destination controls, parameters, stranded releases, fault clearing, light-client initialization, re-initialization, freezing and trusted checkpoints) goes through the pipeline `ProposeSccpRouteGovernance` → 8-body Parliament → due certificate → enactment, with its proposer rule, the `SccpGovernanceProposalV1` payload, and expected heads scoped per subject (route, route control, light-client lane, parameters, faulted peer). Genesis MUST seat the Parliament (§4.14.5) | §1.1, §1.2, §3.6, §4.1, §4.11, §4.13, §4.14.3–§4.14.5, §4.18, §4.19, §6, §7.4, §9.13 |
| D2 | **Destination pause = Parliament pause.** No roster-controlled breaker or signed mint-control statement exists. An enacted `SetDestinationPaused` records a control leaf (`SCCP/CONTROL/V1`, §3.4) in the enacting block's commitment tree; the roster attests it like any block; anyone applies it with `applyControl` (`0x0ce970d6`; historical `0x935a913b`; TON `sccp_apply_control`) under a strictly increasing control nonce. Burns, rotations and voids stay open while paused | §3.4, §3.9, §4.4, §4.5, §4.14.6, §5.1.6, §5.2, §5.3, §5.4, §6, §7.1, §9.2, §9.10 |
| D3 | **Validators come and go at any time.** No handoff bond, no staking change, no seat-change batching. A new generation starts at every boundary whose member set differs, plus forced rotation and the heartbeat; the outgoing generation signs the boundary block; the attestor prioritizes handoffs and signs them before a graceful shutdown. Defaults are a 1 d heartbeat and 14 d validity under the immutable 30 d maximum, all Parliament-settable | §1.2, §4.1, §4.3, §4.4, §4.9, §5.1.5, §5.4, §9.9, §9.10 |
| D4 | **Zero-touch validator setup.** The node generates its bridge key on first start under its store directory (overridable, no environment variables), and registers it itself, fee-exempt on success, as soon as its peer is registered. The attestor account is the key's own secp256k1 account, registered implicitly. Attestor and keeper are on by default with compiled default public RPC lists. The Taira launcher passes nothing. The Parliament's beacon and TLE credentials must become node-generated the same way; until then the guarantee covers SCCP only | §1.2, §4.2, §4.9, §4.13.4, §4.14.5, §4.19, §8, §9.1, §9.5 |
| D5 | **Approved:** fee exemption on success (charged on failure) for attestations, fault evidence, keeper advances, recipient self-claims and bridge-key registration; implicit recipient registration; the crates `iroha_sccp_rpc` and `iroha_sccp_wallet` (reqwest + rustls, TON ADNL crypto); colima for TRON TRE; default public RPC lists in `iroha_config` | §4.2.3, §4.8, §4.12, §4.19, §8, §12 |
| D6 | **Deferred:** finalizer tips; a later payload version bump is acceptable | §12 |
| D7 | **Networks:** the four mainnet profiles only; no testnets | preamble, §2 |
