# API Specification for Client Libraries

## Endpoints for API

### Transaction

**Protocol**: HTTP

**Encoding**: [Parity Scale Codec](#parity-scale-codec)

**Endpoint**: `/transaction`

**Method**: `POST`

**Expects**: Body: `VersionedSignedTransaction`

**Responses**:

| Status | Description                                                            |
|--------|------------------------------------------------------------------------|
| 200    | Transaction Accepted (But not guaranteed to have passed consensus yet) |
| 400    | Transaction Rejected (Malformed)                                       |
| 401    | Transaction Rejected (Improperly signed)                               |

### Query

**Protocol**: HTTP

**Encoding**: [Parity Scale Codec](#parity-scale-codec)

**Endpoint**: `/query`

**Method**: `POST`

**Expects**:

- Body: `VersionedSignedQuery`
- Query parameters:
    - `start`: Optional parameter in queries where results can be indexed. Use to return results from specified point.
      Results are ordered where can be by id which uses
      rust's [PartialOrd](https://doc.rust-lang.org/std/cmp/trait.PartialOrd.html#derivable)
      and [Ord](https://doc.rust-lang.org/std/cmp/trait.Ord.html) traits.
    - `limit`: Optional parameter in queries where results can be indexed. Use to return specific number of results.
    - `sort_by_metadata_key`: Optional parameter in queries. Use to sort results containing metadata with a given key.

**Responses**:

| Response        | Status |                      Body                  |
|-----------------|--------|--------------------------------------------|
| Signature err.  | 401    | `QueryExecutionFail::Signature(String)`    |
| Permission err. | 403    | `QueryExecutionFail::Permission(String)`   |
| Evaluate err.   | 400    | `QueryExecutionFail::Evaluate(String)`     |
| Find err.       | 404    | `QueryExecutionFail::Find(Box<FindError>)` |
| Conversion err. | 400    | `QueryExecutionFail::Conversion(String)`   |
| Success         | 200    | `VersionedPaginatedQueryResult`            |

#### Account Not Found 404

Whether each prerequisite object was found and `FindError`:

| Domain | Account | `FindError`                     |
|--------|---------|---------------------------------|
| N      | -       | `FindError::Domain(DomainId)`   |
| Y      | N       | `FindError::Account(AccountId)` |

#### Asset Not Found 404

Whether each prerequisite object was found and `FindError`:

| Domain | Account | Asset Definition | Asset | `FindError`                                     |
|--------|---------|------------------|-------|-------------------------------------------------|
| N      | -       | -                | -     | `FindError::Domain(DomainId)`                   |
| Y      | N       | -                | -     | `FindError::Account(AccountId)`                 |
| Y      | -       | N                | -     | `FindError::AssetDefinition(AssetDefinitionId)` |
| Y      | Y       | Y                | N     | `FindError::Asset(AssetId)`                     |

### Events

**Protocol**: HTTP

**Protocol Upgrade**: `WebSocket`

**Encoding**: [Parity Scale Codec](#parity-scale-codec)

**Endpoint**: `/events`

**Communication**:

After handshake, client should send `VersionedEventSubscriptionRequest`. Then server sends `VersionedEventMessage`.

**Notes**:

Usually, the client waits for Transaction events.

Transaction event statuses can be either `Validating`, `Committed` or `Rejected`.

Transaction statuses proceed from `Validating` to either `Committed` or `Rejected`.
However, due to the distributed nature of the network, some peers might receive events out of order (e.g. `Committed`
before `Validating`).

It's possible that some peers in the network are offline for the validation round. If the client connects to them while
they are offline, the peers might not respond with the `Validating` status.
But when the offline peers come back online they will synchronize the blocks. They are then guaranteed to respond with
the `Committed` (or `Rejected`) status depending on the information found in the block.

### Pending Transactions

**Protocol**: HTTP

**Encoding**: [Parity Scale Codec](#parity-scale-codec)

**Endpoint**: `/pending_transactions`

**Method**: `GET`

**Expects**:

_Internal use only._ Returns the transactions pending at the moment.

### Blocks Stream

**Protocol**: HTTP

**Protocol Upgrade**: `WebSocket`

**Encoding**: [Parity Scale Codec](#parity-scale-codec)

**Endpoint**: `/block/stream`

**Communication**:

Client should send `VersionedBlockSubscriptionRequest` to initiate communication after WebSocket handshake. Then server sends `VersionedBlockMessage`.

**Notes**:

Via this endpoint client first provides the starting block number (i.e. height) in the subscription request. After
sending the confirmation message, server starts streaming all the blocks from the given block number up to the current
block and continues to stream blocks as they are added to the blockchain.

### Get Configuration

**Protocol**: HTTP

**Encoding**: JSON

**Endpoint**: `/configuration`

**Method**: `GET`

**Expects**:
There are 2 options:

- Expects: a JSON body `"Value"`. Returns: configuration value as JSON.
- Expects: a JSON body that specifies the field (see example below). Returns: documentation for a specific field (as
  JSON string) or `null`.

Note that if the requested field has more fields inside of it, then all the documentation for its inner members is
returned as well.
Here is an example for getting a field `a.b.c`:

```json
{
  "Docs": [
    "a",
    "b",
    "c"
  ]
}
```

**Examples**:
To get the top-level configuration docs for [`Torii`] and all the fields within it:

```bash
curl -X GET -H 'content-type: application/json' http://127.0.0.1:8080/configuration -d '{"Docs" : ["torii"]} ' -i
```

**Responses**:

- 200 OK: Field was found and either doc or value is returned in json body.
- 404 Not Found: Field wasn't found

### Configuration

**Protocol**: HTTP

**Encoding**: JSON

**Endpoint**: `/configuration`

**Method**: `POST`

**Expects**:
One configuration option is currently supported: `LogLevel`. It is set to the log-level in uppercase.

```json
{
  "LogLevel": "WARN"
}
```

Acceptable values are `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`, corresponding to
the [respective configuration options](./config.md#loggermaxloglevel).

**Responses**:

- 200 OK: Log level has changed successfully. The confirmed new log level is returned in the body.
- 400 Bad Request: request body malformed.
- 500 Internal Server Error: Request body valid, but changing the log level failed (lock contention).

### Health

**Protocol**: HTTP

**Encoding**: JSON

**Endpoint**: `/health`

**Method**: `GET`

**Expects**: -

**Responses**:

- 200 OK: The peer is up.
  Also returns current status of peer in json string:

```
"Healthy"
```

## Endpoints for Status/Metrics

### Status

**Protocol**: HTTP

**Encoding**: JSON

**Endpoint**: `/status`

**Method**: `GET`

**Expects**: -

**Responses**:

200 OK reports status as JSON:

```json5
// Note: while this snippet is JSON5 (for better readability),
//       the actual response is JSON
{
  /**
   * Number of connected peers, except for the reporting peer itself
   */
  peers: 3,
  /**
   * Number of committed blocks (block height)
   */
  blocks: 1,
  /**
   * Total number of accepted transactions
   */
  txs_accepted: 3,
  /**
   * Total number of rejected transactions
   */
  txs_rejected: 0,
  /**
   * Uptime with nanosecond precision since creation of the genesis block
   */
  uptime: {
    secs: 5,
    nanos: 937000000,
  },
  /**
   * Number of view changes in the current round
   */
  view_changes: 0,
}
```

**CAUTION**: Almost all fields are 64-bit integers and should be handled with care in JavaScript. Only the `nanos` field
is a 32-bit integer. See `iroha_telemetry::metrics::Status`.

**Sub-routing**: To obtain the value of a specific field, one can append the name of the field to the path,
e.g. `status/peers`. This returns the corresponding JSON value, inline, so strings are quoted, numbers are not and maps
are presented as above.

### Metrics

**Protocol**: HTTP

**Encoding**: Prometheus

**Endpoint**: `/metrics`

**Method**: `GET`

**Expects**: -

**Responses**:

- 200 OK reports 8 of 10 metrics:

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

Learn [how to use metrics](https://hyperledger.github.io/iroha-2-docs/guide/advanced/metrics.html).

### API Version

**Protocol**: HTTP

**Encoding**: JSON

**Endpoint**: `/api_version`

**Method**: `GET`

**Expects**: -

**Responses**:

- 200 OK: The current version of API used by Iroha returned as a json string.
  Grabbed from the genesis block's version, so at least a minimal subnet of 4 peers
  should be running and the genesis be submitted at the time of request.

```
"1"
```

## Parity Scale Codec

For more information on codec check [Substrate Dev Hub](https://substrate.dev/docs/en/knowledgebase/advanced/codec) and
codec's [GitHub repository](https://github.com/paritytech/parity-scale-codec).

## Reference Iroha Client Implementation

[Iroha client in Rust.](../../../client)
