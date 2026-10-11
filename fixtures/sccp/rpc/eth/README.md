# Captured Ethereum mainnet light-client and execution responses

Real mainnet public-RPC responses that drive the SCCP v1 Ethereum light client
(`crates/iroha_sccp/src/light_client/ethereum.rs`) from a bootstrap across a
sync-committee period change to a finalized receipt (`specs/sccp.md` §4.13.3,
§7.2 step 3, §11). `crates/iroha_sccp/tests/ethereum_light_client.rs` replays
them at a controlled Taira time (the finality update's signature slot plus
60 s); the tests never reach the network. The Ethereum builder tests
(`crates/iroha_sccp_rpc/src/builders/ethereum/evidence_tests.rs`) replay the
same responses through the advance builder and the ancestry selection
(`HistoryContract` from the captured `eth_getProof`, `HeaderChain` without it).

Recorded on 2026-09-27 by `capture.py` in this directory:

| Summary | Value |
|---|---|
| Bootstrap slot | `15301376` (sync-committee period 1867) |
| Updates | periods 1867 and 1868 (`start_period=1867&count=2`); they teach the committees of 1868 and 1869 |
| Finality update | signature slot `15308190`, finalized slot `15308096`, finalized execution block `E = 26069545` |
| Event block | `B = 26069527` (the block with the fewest transactions among the 64 before `E`) |
| Ancestry | headers `B + 1 ..= E` (`HeaderChain`) and `eth_getProof` of the EIP-2935 contract at `E`, slot `B mod 8191` (`HistoryContract`) |

Sources:

- `https://ethereum-beacon-api.publicnode.com` for the beacon light-client
  routes, requested with `accept: application/json`;
- `https://ethereum-rpc.publicnode.com` for `eth_getBlockByNumber` and
  `eth_getBlockReceipts`;
- `https://eth.drpc.org` for `eth_getProof` at `E`. The publicnode execution
  endpoint answers `eth_getProof` only inside a short window behind the head
  ("distance to target block exceeds maximum proof window"), which a finalized
  block `E` is already outside; `1rpc.io/eth`, `eth-mainnet.public.blastapi.io`
  and `rpc.mevblocker.io` also served it.

`recorded.json` indexes every exchange (request, source, HTTP status) and holds
the summary above. Bodies are stored byte for byte, except that
`block_<n>.json` drops the `transactions` array of `eth_getBlockByNumber(n,
false)` (noted per entry under `trimmed`); every header field is unchanged, so
each header still re-encodes to its `hash`.

Mainnet has no SCCP deployment, so the replayed proofs verify finality,
ancestry and receipt inclusion and then stop at the event check
(`EthereumLcError::Event(WrongTopic)` on a three-topic ERC-20 log). Proofs of
SCCP events run over EDR-shaped blocks finalized by the synthetic beacon chain
(`iroha_sccp::test_support::ethereum`).

## Recapture

```text
python3 fixtures/sccp/rpc/eth/capture.py fixtures/sccp/rpc/eth
```

The script captures everything within a few minutes so that `E` is still
inside the `eth_getProof` window. Equivalent single requests:

```text
curl -s -H 'accept: application/json' \
  https://ethereum-beacon-api.publicnode.com/eth/v1/beacon/light_client/finality_update
curl -s -H 'accept: application/json' \
  https://ethereum-beacon-api.publicnode.com/eth/v1/beacon/headers/<epoch-boundary slot of the previous period>
curl -s -H 'accept: application/json' \
  https://ethereum-beacon-api.publicnode.com/eth/v1/beacon/light_client/bootstrap/<root>
curl -s -H 'accept: application/json' \
  'https://ethereum-beacon-api.publicnode.com/eth/v1/beacon/light_client/updates?start_period=<P-1>&count=2'
curl -s -X POST -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["<n>",false]}' \
  https://ethereum-rpc.publicnode.com
curl -s -X POST -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockReceipts","params":["<B>"]}' \
  https://ethereum-rpc.publicnode.com
curl -s -X POST -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_getProof","params":["0x0000F90827F1C53a10cb7A02335B175320002935",["<B mod 8191 as a 32-byte word>"],"<E>"]}' \
  https://eth.drpc.org
```

After a recapture, update the block numbers (`EVENT_BLOCK`, `FINALIZED_BLOCK`)
and period numbers in `crates/iroha_sccp/tests/ethereum_light_client.rs`, and
`MAINNET_EVENT`, `MAINNET_FINALIZED` and the periods in
`crates/iroha_sccp_rpc/src/builders/ethereum/evidence_tests.rs`.
