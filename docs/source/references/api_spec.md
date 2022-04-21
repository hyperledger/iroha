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

| Response        | Status | Body [*](#iroha-structures) |
| --------------- | ------ | ---- |
| Decode err.     |    400 | `QueryError::Decode(Box<iroha_version::error::Error>)` |
| Version err.    |    400 | `QueryError::Version(UnsupportedVersionError)` |
| Signature err.  |    401 | `QueryError::Signature(String)` |
| Permission err. |    403 | `QueryError::Permission(String)` |
| Evaluate err.   |    400 | `QueryError::Evaluate(String)` |
| Find err.       |    404 | `QueryError::Find(Box<FindError>)` |
| Conversion err. |    400 | `QueryError::Conversion(String)` |
| Success         |    200 | `VersionedPaginatedQueryResult` |

#### Asset Not Found 404
Whether each prerequisite object was found and `FindError`:
| Domain | Account | Asset Definition | Asset | `FindError` |
| -- | -- | -- | -- | -- |
| N | - | - | - | `FindError::Domain(DomainId)` |
| Y | N | - | - | `FindError::Account(AccountId)` |
| Y | - | N | - | `FindError::AssetDefinition(AssetDefinitionId)` |
| Y | Y | Y | N | `FindError::Asset(AssetId)` |

#### Account Not Found 404
Whether each prerequisite object was found and `FindError`:
| Domain | Account | `FindError` |
| -- | -- | -- |
| N | - | `FindError::Domain(DomainId)` |
| Y | N | `FindError::Account(AccountId)` |

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

### Pending transactions

**Protocol**: HTTP

**Encoding**: [Parity Scale Codec](#parity-scale-codec)

**Endpoint**: `/pending_transactions`

**Method**: `GET`

**Expects**:

_Internal use only_. Returns the transactions pending at the moment.



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

### Configuration

**Protocol**: HTTP

**Encoding**: JSON

**Endpoint**: `/configuration`

**Method**: `POST`

**Expects**:
One configuration option is currently supported: `LogLevel`. It is set to the log-level in uppercase.
```json
{
    "LogLevel":"WARN"
}
```
Acceptable values are `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`, corresponding to the [respective configuration options](./config.md#logger.max_log_level).

**Responses**:
- 200 OK - Log level has changed successfully. The confirmed new log level is returned in the body.
- 400 Bad Request - request body malformed.
- 500 Internal Server Error - Request body valid, but changing the log level failed (lock contention).

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
  + Number of view_changes in the current round

```json
{
    "peers": 3,
    "blocks": 1,
    "txs_accepted": 3,
    "txs_rejected": 0,
    "uptime": {
        "secs": 5,
        "nanos": 937000000
    },
    "view_changes": 0
}
```

### Metrics

**Protocol**: HTTP

**Encoding**: Prometheus

**Endpoint**: `/metrics`

**Method**: `GET`

**Expects**: -

**Responses**:
- 200 OK - reports 8 of 10 metrics:

```bash
# HELP accounts User accounts registered at this time
# TYPE accounts gauge
accounts{domain="genesis"} 1
accounts{domain="wonderland"} 1
# HELP block_height Current block height
# TYPE block_height counter
block_height 1
# HELP connected_peers Total number of currently connected peers
# TYPE connected_peers gauge
connected_peers 0
# HELP domains Total number of domains
# TYPE domains gauge
domains 2
# HELP tx_amount average amount involved in a transaction on this peer
# TYPE tx_amount histogram
tx_amount_bucket{le="0.005"} 0
tx_amount_bucket{le="0.01"} 0
tx_amount_bucket{le="0.025"} 0
tx_amount_bucket{le="0.05"} 0
tx_amount_bucket{le="0.1"} 0
tx_amount_bucket{le="0.25"} 0
tx_amount_bucket{le="0.5"} 0
tx_amount_bucket{le="1"} 0
tx_amount_bucket{le="2.5"} 0
tx_amount_bucket{le="5"} 0
tx_amount_bucket{le="10"} 0
tx_amount_bucket{le="+Inf"} 2
tx_amount_sum 26
tx_amount_count 2
# HELP txs Transactions committed
# TYPE txs counter
txs{type="accepted"} 1
txs{type="rejected"} 0
txs{type="total"} 1
# HELP uptime_since_genesis_ms Network up-time, from creation of the genesis block
# TYPE uptime_since_genesis_ms gauge
uptime_since_genesis_ms 54572974
# HELP view_changes Number of view_changes in the current round
# TYPE view_changes gauge
view_changes 0
```

## Parity Scale Codec

For more information on codec check [Substrate Dev Hub](https://substrate.dev/docs/en/knowledgebase/advanced/codec) and codec's [Github repository](https://github.com/paritytech/parity-scale-codec).

## Reference Iroha Client Implementation

[Iroha client in Rust.](../../../client)

## Iroha Structures

- `VersionedTransaction` - `iroha_data_model::transaction::VersionedTransaction`
- `VersionedSignedQueryRequest` - `iroha_data_model::query::VersionedSignedQueryRequest`

- `VersionedQueryResult` - `iroha_data_model::query::VersionedQueryResult`
- `QueryError` - `iroha_core::smartcontracts::isi::query::Error`
- `UnsupportedVersionError` - `iroha_core::smartcontracts::isi::query::UnsupportedVersionError`
- `FindError` - `iroha_core::smartcontracts::isi::error::FindError`

- `EventStreamSubscriptionRequest` - `iroha_data_model::events::EventSubscriberMessage::SubscriptionRequest`
- `EventStreamSubscriptionAccepted` - `iroha_data_model::events::EventPublisherMessage::SubscriptionAccepted`
- `Event` - `iroha_data_model::events::EventPublisherMessage::Event`
- `EventReceived` - `iroha_data_model::events::EventSubscriberMessage::EventReceived`

- `BlockStreamSubscriptionAccepted` - `iroha_core::block::stream::BlockPublisherMessage::SubscriptionAccepted`
- `BlockStreamSubscriptionRequest` - `iroha_core::block::stream::BlockSubscriberMessage::SubscriptionRequest`
- `Block` - `iroha_core::block::stream::BlockPublisherMessage::Block`
- `BlockReceived` - `iroha_core::block::stream::BlockSubscriberMessage::BlockReceived`
