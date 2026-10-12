<!--
SPDX-License-Identifier: Apache-2.0
-->

# Bridge finality proofs

Torii serves public reads of the certified chain for bridges, light clients
and other off-chain verifiers. Every proof carries the canonical certified
block with its embedded commit certificate; trust always starts from a signed
genesis, or a checkpoint, that the caller authenticated independently of the
response. There is one proof layout and no alternate decoder.

The types live in `iroha_data_model::sumeragi_finality`. Torii builds each
response from one immutable State view with
`iroha_core::sumeragi::finality::{build_proof, build_bundle, build_attestation}`,
which read the chain through the certified-chain reader
([`sumeragi.md`](sumeragi.md) §12.7).

## Routes

| Route | Response |
| --- | --- |
| `GET /v1/bridge/finality/{height}` | `SumeragiFinalityProof` |
| `GET /v1/bridge/finality/bundle/{height}` | `SumeragiFinalityBundle` |
| `GET /v1/bridge/finality/attestation/{height}` | `SumeragiFinalityAttestation` |
| `GET /v1/bridge/finality/attestation/latest` | `SumeragiFinalityAttestation` for the durable tip |

Responses are canonical Norito by default and Norito JSON through `Accept`
negotiation. A proof or bundle is served only for a height whose certificate
the certified read verified (genesis: the signed genesis itself), and the node
checks the proof with `SumeragiFinalityProof::decode_checked` before serving
it. A height the State view has not committed, or whose frame or certificate
is missing, returns `NotFound`; every other read or verification failure is an
internal error. Nothing is served from unverified data.

## Proof

`SumeragiFinalityProof` has exactly three fields (unknown fields are rejected):

- `block_header`: the Iroha `BlockHeader` of the requested height.
- `block_wire`: the canonical result-bearing `SignedBlockWire`, at most
  `MAX_FINALITY_BLOCK_BYTES` (32 MiB). It embeds the block's
  `CommitCertificate`: the core header, the `CommitQC`, the signed RS16
  availability table and the preimage of the execution result `R`. Under
  [`sumeragi.md`](sumeragi.md) §4.1.1 that preimage is `F ‖ body`: the
  221-byte finality header (`SccpFinalityHeaderV1`, called `X` in
  [`sccp.md`](sccp.md) §3.6) followed by the canonical
  `ExecutionResultCommitment`, at most 64 KiB together, and
  `R = SHA-256(RESULT_TAG ‖ F ‖ H(RESULT_BODY_TAG ‖ body))`. Genesis carries a
  result-only certificate (no core header, `CommitQC` or availability table).
- `committee`: the committee of that height as
  `FinalityValidator { public_key, proof_of_possession }` entries in canonical
  key order.

Certificates are per node (§12.7): two honest nodes may serve different valid
`CommitQC`s (any `q` signers) for the same block, header and result.

### Structural check

`SumeragiFinalityProof::decode_checked` checks a proof without selecting a
trust root. It requires:

1. a non-empty, bounded, canonical block wire that matches `block_header` and
   carries execution results, with valid proposal commitments and output
   Merkle cache;
2. a committee of the exact first-release global geometry (`3f + 1`, 4..=31
   members) of distinct BLS-normal keys, each with a valid proof of
   possession, in canonical order;
3. a result preimage that decodes through `CertifiedResultV1::decode`, the
   only decoder of `F ‖ body`, with scope `TairaGlobal` for the global
   instance (kind 0, index 0) and `NonGlobal` for every other root. `decode`
   checks C1–C4 and the scope rule of [`sccp.md`](sccp.md) §3.6: `F` parses
   (fixed magic and flags; an inactive `F` is all zero after its flags; an
   active `F` has a nonzero generation and committee root, consistent
   message-count, history and rotation fields, and a nonzero height) and
   `F.height` equals the body's height; `F.network_id` equals the network of
   the epoch context the schedule assigns to that height; an active `F` names
   `committee_root` of that context's committee, and a boundary decision in
   the body whose successor committee differs is reflected as a rotation to
   exactly that root; and a `NonGlobal` scope requires an inactive `F`. The
   proof holds the block, so it then calls
   `CertifiedResultV1::check_block(height, timestamp_ms)` with the block
   header's height and canonical time, which checks C5: `F.height` and
   `F.timestamp_ms` equal them. The body names the block's
   height, lists exactly this committee as its current epoch context, and
   commits the exact executed-wire length and hash and the block's transaction
   input and output commitments; a beacon pulse in the result must name the
   block's parent. `R` is `result_of_preimage(F ‖ body)`;
4. at height 1, a result-only certificate; at every later height, a non-empty
   block and a Commit `CommitQC` of the core header's height, instance, block
   hash and result `R`, in the committee's epoch, over the canonical
   resultless proposal (payload length and hash), with a structurally valid
   availability table and an exact-quorum BLS aggregate signature that
   verifies under the committee with the consensus suite of
   [`sumeragi.md`](sumeragi.md) §1 item 6 (`DST_SIG` over `SHA-256` of the
   Commit preimage).

A successful structural check is not authentication: the committee is the
proof's own claim. The SCCP fields of an active `F` (commitment root, message
count, history, generation, rotation validity) cannot be derived from the
body; their only authority is the quorum signature, and SCCP's forgery
evidence holds the signers to them ([`sccp.md`](sccp.md) §4.9).

**Status.** The `F ‖ body` layout and the consensus suite are the target of
`sccp.md` revision 5. The types exist in
`iroha_data_model::sumeragi_finality::certified_result`
(`SccpFinalityHeaderV1`, `CertifiedResultV1` with `decode` and `check_block`),
but `decode_checked` does not use them yet, and nodes do not yet certify the
`F`-bound `R` or sign under the consensus suite (`TODO:` WP-C1, WP-C2). Until
they do, the as-built result is `R = H("iroha/sumeragi/result/v1" ‖ body)`
and check 3 decodes the body alone ([`sumeragi.md`](sumeragi.md) Appendix
E51).

### Contiguous verification

`SumeragiFinalityVerifier` is the only constructor of `VerifiedSumeragiBlock`,
the authenticated receipt that applications consume.

- `SumeragiFinalityVerifier::new(genesis, chain_id, validators)` takes a signed
  genesis whose signature the caller has verified and the validators it
  registers (keys and proofs of possession, equal to the genesis epoch
  committee). It derives the global consensus instance from the genesis hash
  and the chain id. It never learns trust from a proof.
- `verify(proof)` admits only the next height of the authenticated prefix.
  Height 1 must reproduce the selected genesis: header hash, canonical
  resultless proposal, committee and epoch context. Every later proof must
  extend its parent: its schedule is a valid successor of the parent's
  authenticated schedule, its core header names the verifier's instance and
  the parent's core hash and result, its Iroha header names the parent block
  hash, and its committee is the configuration the parent scheduled for this
  height. At an epoch boundary the selection anchor must be the parent block,
  and the next leader seed and any frozen election seed must derive from the
  parent's certified beacon pulse. The signed RS16 availability table and
  every original row must verify against the canonical proposal under the
  scheduled height configuration (`verify_payload_availability`).
- `verify_retained_decision` and `verify_same_decision` re-verify another
  certificate witness for a height already in the prefix; every decision
  field must match.
- `VerifiedSumeragiBlock::verify_committed_transaction` checks that a
  successful external transaction, with its network, signature and output,
  is included in the authenticated block. Genesis execution needs a certified
  successor or independent node statements.

## Checkpoints and pages

`SumeragiFinalityVerifier::export_checkpoint` exports the authenticated tip as
a `SumeragiFinalityCheckpoint`: network id, chain id, the canonical signed
genesis, the genesis committee, the retained decisions of the tip and at most
two predecessors, and the tip proof (canonical encoding at most 68 MiB).
Importing it with `from_trusted_checkpoint` is an explicit trust-root
operation: the caller must select the checkpoint independently, and a peer
response never becomes its own checkpoint. Import re-verifies the tip
certificate and the genesis bindings.

`verify_checkpoint_page` verifies a page of consecutive proofs that starts at
the checkpoint height, within caller-chosen bounds of at most 65 536 proofs and
64 MiB, and returns the page tip with the next checkpoint. Callers persist that checkpoint only
after their own application checks succeed. `iroha_core::sumeragi::finality::build_checkpoint`
exports a checkpoint from the node's own history for local self-checks.

## Bundle

`SumeragiFinalityBundle` has exactly two fields: `network_id`, the
genesis-derived network of the serving node, and `finality_proof`, the proof
above. Consumers compare `network_id` with the network they selected
independently before verifying the proof.

## Node attestation

`GET /v1/bridge/finality/attestation/{height}` returns a node-signed statement
about the node's durable tip. The request carries a fresh nonzero challenge in
exactly one `X-Iroha-Finality-Challenge` header (64 lowercase hexadecimal
characters). The requested height must be the node's durable tip; `latest`
selects the tip of the State view that builds the statement.

`SumeragiFinalityAttestation` is `{ body, signature }`. The body carries the
challenge, the genesis-derived network id, the node's BLS `PeerId` and its
fingerprint, the build and configuration fingerprints, the genesis block hash,
the genesis proof, the node's `SumeragiStatus` at the tip and the tip proof.
The node signs `H("iroha:sumeragi-finality-attestation:v1\0" ‖ Norito(body))`
with its BLS-normal node key, under the existing w3f transcript, never under
the consensus suite's `DST_SIG`: a chosen-challenge statement can never verify
as a vote or a certificate share ([`sumeragi.md`](sumeragi.md) §1 item 6).
`SumeragiFinalityAttestation::verify` checks the
body's internal bindings (nonzero challenge, node identity and fingerprint,
genesis-derived network, a non-halted status of the current protocol version
whose committed and applied heights equal the tip, the status instance, and
the structural check of both embedded proofs) and the signature. Callers
select the node independently
and verify both embedded proofs with their own verifier; a statement from one
node authenticates only that node's observation.

The failure contract (`bridge_finality_attestation_failure`), status codes and
retry rules are in [`torii/api_contract.md`](torii/api_contract.md). Every
attestation response is `no-store`, carries `X-Content-Type-Options: nosniff`
and varies by `X-Iroha-Finality-Challenge, Accept`. The
[genesis readiness probe](bridge_genesis_readiness.md) is built on this route.

## SDK

The Rust client reads these routes with `Client::get_sumeragi_finality_proof`
(structural check only), `Client::get_next_sumeragi_finality_proof` (admits the
proof into the caller's verifier), `Client::get_sumeragi_finality_attestation`
and `Client::poll_sumeragi_genesis_readiness`. Successful responses are bounded
by twice the 32 MiB block bound plus 4 MiB.

`get_sumeragi_finality_attestation` returns an opaque
`AuthenticatedFinalityAttestation` after its canonical decode, body and node-signature
checks and exact requested height, challenge, network and peer binding. The carrier
allows only immutable borrowing or consuming conversion to the raw statement; raw
conversion discards authentication provenance. Deployment HTTP observations retain
this carrier to avoid repeating the same structural and node-signature verification.
They still independently bind every response to the observation's selected peer,
challenge and network and verify its tip against the authenticated contiguous prefix
and committee. Arbitrary raw sources undergo the full attestation verification.

The deployment verifier retains the exact tip capability produced by checkpoint
import and successful observation. Within a prefix, it can reuse that capability
only when the complete offered proof equals the retained tip, including its header,
canonical block and certificate bytes, ordered committee and proofs of possession.
Different witnesses still undergo native verification; every node statement still
needs fresh request binding and authentication. Active enclosing decoder budgets
retain the original physical reads, allocation charges and refusal behavior.
