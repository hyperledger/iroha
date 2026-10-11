# SCCP RPC transport fixtures

Recorded responses replayed by `crates/iroha_sccp_rpc/tests/transport.rs`
through an in-process mock HTTP server. The tests never reach the network.

`recorded.json` indexes every exchange: the public endpoint it was recorded
from, the request that produced it, the HTTP status, content type and the body
file. Bodies are stored byte-for-byte unless the entry has a `trimmed` note;
trimming only drops array elements (receipts, answers of a batch) and never
edits a kept value.

Recorded on 2026-09-26 (Ethereum block `0x18daf08`, beacon slot `15301120`)
from:

- `https://ethereum-rpc.publicnode.com` (Ethereum execution JSON-RPC),
- `https://bsc-dataseed.bnbchain.org` (BSC JSON-RPC),
- `https://lodestar-mainnet.chainsafe.io` (beacon header API, JSON).

Synthetic replies (HTTP 401, 403, 405, 429 and 5xx, JSON-RPC rate-limit and
unsupported-method errors, a batch refused as a whole, HTML and truncated
success bodies, timeouts, malformed hex and a successful
`eth_sendRawTransaction`) are built inline by the tests and are not stored
here. JSON-RPC ids in replayed bodies are rewritten by the mock server to the
id of the request it answers.
