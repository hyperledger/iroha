# SCCP TON liteserver transport fixtures

Recorded `liteServer.*` exchanges and an ADNL-TCP handshake vector, replayed by
`crates/iroha_sccp_rpc/tests/ton_liteclient.rs` through an in-process mock
liteserver. `iroha_sccp` also decodes the answers
(`crates/iroha_sccp/src/test_support/ton_capture.rs`) and runs them through the
TON light client and its native primitives
(`crates/iroha_sccp/src/test_fixtures/ton_mainnet_capture_tests.rs` and
`light_client/ton/tests.rs`): the key-block bootstrap, the config-28 shuffle
against the subset hash of real headers, the Simplex signatures of a block and
of a key-block hop, and proofs that prune `state_update` (`specs/sccp.md`
§4.13.3). The tests never reach the network.

## `recorded.json` and `answers/`

`recorded.json` indexes every exchange by name:

- `request`: hex of the exact `data` of `liteServer.query` (the request TL,
  preceded by `liteServer.waitMasterchainSeqno` for
  `wait_masterchain_seqno_get_time`). The mock answers a request only when the
  client's bytes equal a recorded request, so the replay also pins the client's
  TL encoding.
- `answer`: the file holding the raw TL answer, byte for byte as the liteserver
  sent it inside `adnl.message.answer`; `answer_bytes` is its length.

The top-level fields name what the requests refer to: the masterchain block
(`masterchain_block_seqno`, ten blocks below the liteserver's last block
`masterchain_last_seqno`), its previous key block (`key_block_seqno`) and that
key block's previous key block (`prev_key_block_seqno`), the USDT jetton master
account, the logical time of its latest transaction and the
`get_jetton_data` method id.

Captured on 2026-09-28 from the TON mainnet liteserver
`5.9.10.47:19949:n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk=` (from
`https://ton.org/global-config.json`) with an independent Python ADNL-TCP client
(`cryptography` for X25519 and AES-256-CTR). The exchanges are, in order:

| Exchange | Request |
|---|---|
| `get_masterchain_info` | `getMasterchainInfo` |
| `lookup_block_seqno` | `lookupBlock` mode 1 of masterchain block `masterchain_block_seqno` |
| `lookup_key_block_seqno`, `lookup_prev_key_block_seqno` | `lookupBlock` mode 1 of the two key blocks (their `prev_key_block_seqno` read from the header proofs) |
| `lookup_block_utime`, `lookup_block_lt` | `lookupBlock` mode 4 (the block's `gen_utime`) and mode 2 (its `start_lt`) |
| `get_block_header` | `getBlockHeader` mode 0 of the block |
| `get_block_proof_forward` | `getBlockProof` mode 1 from the key block to the block (one `blockLinkForward`) |
| `get_block_proof_key_hop` | `getBlockProof` mode 1 from the previous key block to the key block (a key-block hop) |
| `get_block_proof_backward` | `getBlockProof` mode 1 from the block back to the key block (one `blockLinkBack`) |
| `get_block` | of the block |
| `get_config_params` | mode 0, parameters 34, 28 and 15 at the key block |
| `get_account_state` | the jetton master at the block |
| `get_transactions` | 3 transactions of the jetton master from its latest `(lt, hash)` (taken from `toncenter.com` `getAddressInformation`) |
| `get_one_transaction`, `get_shard_block_proof` | of the first returned transaction's shard block |
| `run_smc_method_result`, `run_smc_method_all` | `get_jetton_data` with an empty stack, modes `0x4` and `0x1f` |
| `get_time`, `wait_masterchain_seqno_get_time` | `getTime`, bare and behind `waitMasterchainSeqno(last, 5000)` |
| `error_block_not_found` | `lookupBlock` of a masterchain seqno 1 000 000 blocks ahead: `liteServer.error` 651 |
| `error_send_message` | `sendMessage` of the three bytes `000102`: `liteServer.error` 0 |

Mainnet runs simplex consensus: the forward links of
`get_block_proof_forward` and `get_block_proof_key_hop` carry `liteServer.signatureSet.simplex` (constructor `0xac249800`: catchain
seqno, validator subset hash, signatures, session id, slot and the signed
candidate), not the catchain-era `liteServer.signatureSet.ordinary`.

To re-record, repeat these queries against any mainnet liteserver in the same
order (the key blocks follow from the chosen block's header proof) and replace
the files; the tests read every identifier from the recording.

## `adnl_handshake_vector.json`

A handshake and framing vector generated with the same independent Python
implementation (and cross-checked with libsodium's Ed25519-to-Curve25519
conversions) from fixed inputs: the server's Ed25519 seed and public key, the
client's ephemeral X25519 scalar and 160 handshake parameters, the expected key
id, Edwards-encoded client key, shared secret and 256-byte handshake packet; one
client packet (a `getMasterchainInfo` query with a fixed query id and nonce),
the server's empty confirmation and answer (the recorded masterchain info) on
the continuous server stream, and a `tcp.ping`/`tcp.pong` exchange that
continues both streams. The inputs are SHA-256 hashes of labels of the form
`iroha sccp v1 adnl vector: …`.
