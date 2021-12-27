# API Specification for Client Libraries

## Endpoints for [API](./config.md#toriiapi_url)

### Transaction

**Protocol**: HTTP

**Encoding**: [Parity Scale Codec](#parity-scale-codec)

**Endpoint**: `/transaction`

**Method**: `POST`

**Expects**: Body: `VersionedTransaction` [*](#iroha-structures)

**Responses**:
- 200 OK - Transaction Accepted (But not guaranteed to have passed consensus yet)
- 400 Bad Request - Transaction Rejected (Malformed)
- 401 Unauthorized - Transaction Rejected (Improperly signed)

### Query

**Protocol**: HTTP

**Encoding**: [Parity Scale Codec](#parity-scale-codec)

**Endpoint**: `/query`

**Method**: `POST`

**Expects**:
- Body: `VersionedSignedQueryRequest` [*](#iroha-structures)
- Query parameters:
  + `start` - Optional parameter in queries where results can be indexed. Use to return results from specified point. Results are ordered where can be by id which uses rust's [PartialOrd](https://doc.rust-lang.org/std/cmp/trait.PartialOrd.html#derivable) and [Ord](https://doc.rust-lang.org/std/cmp/trait.Ord.html) traits.
  + `limit` - Optional parameter in queries where results can be indexed. Use to return specific number of results.

**Responses**:
- 200 OK - Query Executed Successfully and Found Value
  + Body: `VersionedQueryResult` [*](#iroha-structures)
- 4xx - Query Rejected or Found Nothing

Status and whether each step succeeded:
| Status | Decode & Versioning | Signature | Permission | Find |
| -- | -- | -- | -- | -- |
| 400 | N | - | - | - |
| 401 | Y | N | - | - |
| 404 | Y | Y | N | - |
| 404 | Y | Y | Y | N |
| 200 | Y | Y | Y | Y |

#### Asset Not Found 404
Hint and whether each object exists:
| Hint | Domain | Account | Asset Definition | Asset |
| -- | -- | -- | -- | -- |
| "domain" | N | - | - | - |
| "account" | Y | N | - | - |
| "definition" | Y | - | N | - |
| - | Y | Y | Y | N |

#### Account Not Found 404
Hint and whether each object exists:
| Hint | Domain | Account |
| -- | -- | -- |
| "domain" | N | - |
| - | Y | N |

### Events

**Protocol**: HTTP

**Protocol Upgrade**: `WebSocket`

**Encoding**: [Parity Scale Codec](#parity-scale-codec)

**Endpoint**: `/events`

**Expects**:

First message after handshake from client: `EventStreamSubscriptionRequest` [*](#iroha-structures)

When server is ready to transmit events it sends: `EventStreamSubscriptionAccepted` [*](#iroha-structures)

Server sends `Event` and expects `EventReceived`  [*](#iroha-structures) after each, before sending the next event.

**Notes**:

Usually, the client  waits for Transaction events.

Transaction event statuses can be either `Validating`, `Committed` or `Rejected`.

Transaction statuses proceed from `Validating` to either  `Committed` or `Rejected`.
However, due to the distributed nature of the network, some peers might receive events out of order (e.g. `Committed` before `Validating`).

It's possible that some peers in the network are offline for the validation round. If the client connects to them while they are offline, the peers might not respond with the `Validating` status.
But when the offline peers come back online they will synchronize the blocks. They are then guaranteed to respond with the `Committed` (or `Rejected`) status depending on the information found in the block.

### Blocks stream

**Protocol**: HTTP

**Protocol Upgrade**: `WebSocket`

**Encoding**: [Parity Scale Codec](#parity-scale-codec)

**Endpoint**: `/block/stream`

**Expects**:

First message after handshake to initiate communication from client: `BlockStreamSubscriptionRequest` [*](#iroha-structures)

When server is ready to transmit blocks it sends: `BlockStreamSubscriptionAccepted` [*](#iroha-structures)

Server sends `Block` and expects `BlockReceived`  [*](#iroha-structures) after each, before sending the next block.

**Notes**:

Via this endpoint client first provides the starting block number(i.e. height) in the subscription request. After sending
the confirmation message, server starts streaming all the blocks from the given block number up to the current block and
continues to stream blocks as they are added to the blockchain.

### Configuration

**Protocol**: HTTP

**Encoding**: JSON

**Endpoint**: `/configuration`

**Method**: `GET`

**Expects**:
There are 2 variants:
- It either expects json body `"Value"` and returns configuration value as json
- Or it expects json body like below and returns documentation for specific field (as json string) or null (here for field `a.b.c`):
```json
{
    "Docs": ["a", "b", "c"]
}
```

**Examples**:
To get the top-level configuration docs for [`Torii`]
```bash
curl -X GET -H 'content-type: application/json' http://127.0.0.1:8080/configuration -d '{"Docs" : ["torii"]} ' -i
```

**Responses**:
- 200 OK - Field was found and either doc or value is returned in json body.
- 404 Not Found - Field wasn't found

### Health

**Protocol**: HTTP

**Encoding**: JSON

**Endpoint**: `/health`

**Method**: `GET`

**Expects**: -

**Responses**:
- 200 OK - The peer is up.
Also returns current status of peer in json string:
```
"Healthy"
```

## Endpoints for [status/metrics](./config.md#toriitelemetry_url)

### Status

**Protocol**: HTTP

**Encoding**: JSON

**Endpoint**: `/status`

**Method**: `GET`

**Expects**: -

**Responses**:
- 200 OK - reports status:
  + Number of connected peers, except for the reporting peer itself
  + Number of committed blocks (block height)
  + Total number of transactions
  + `uptime` since creation of the genesis block in milliseconds.

```json
{
    "peers": 3,
    "blocks": 1,
    "txs": 3,
    "uptime": 3200,
}
```

### Metrics

**Protocol**: HTTP

**Encoding**: Prometheus

**Endpoint**: `/metrics`

**Method**: `GET`

**Expects**: -

**Responses**:
- 200 OK - currently mirrors status:
  + Number of connected peers, except for the reporting peer itself
  + Number of committed blocks (block height)
  + Total number of transactions
  + `uptime` since creation of the genesis block in milliseconds.

```bash
# HELP block_height Current block height
# TYPE block_height counter
block_height 0
# HELP connected_peers Total number of currently connected peers
# TYPE connected_peers gauge
connected_peers 0
# HELP txs Transactions committed
# TYPE txs counter
txs 0
# HELP uptime_since_genesis_ms Uptime of the network, starting from creation of the genesis block
# TYPE uptime_since_genesis_ms gauge
uptime_since_genesis_ms 0
```

## Parity Scale Codec

For more information on codec check [Substrate Dev Hub](https://substrate.dev/docs/en/knowledgebase/advanced/codec) and codec's [Github repository](https://github.com/paritytech/parity-scale-codec).

## Reference Iroha Client Implementation

[Iroha client in Rust.](../../../client)

## Iroha Structures

- `VersionedTransaction` - `iroha_data_model::transaction::VersionedTransaction`
- `VersionedSignedQueryRequest` - `iroha_data_model::query::VersionedSignedQueryRequest`
- `VersionedQueryResult` - `iroha_data_model::query::VersionedQueryResult`

- `EventStreamSubscriptionRequest` - `iroha_data_model::events::EventSubscriberMessage::SubscriptionRequest`
- `EventStreamSubscriptionAccepted` - `iroha_data_model::events::EventPublisherMessage::SubscriptionAccepted`
- `Event` - `iroha_data_model::events::EventPublisherMessage::Event`
- `EventReceived` - `iroha_data_model::events::EventSubscriberMessage::EventReceived`

- `BlockStreamSubscriptionAccepted` - `iroha_core::block::stream::BlockPublisherMessage::SubscriptionAccepted`
- `BlockStreamSubscriptionRequest` - `iroha_core::block::stream::BlockSubscriberMessage::SubscriptionRequest`
- `Block` - `iroha_core::block::stream::BlockPublisherMessage::Block`
- `BlockReceived` - `iroha_core::block::stream::BlockSubscriberMessage::BlockReceived`
