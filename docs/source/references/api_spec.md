# API Specification for Client Libraries

## Endpoints

### Submit Instructions

**Protocol**: HTTP

**Encoding**: Parity Scale Codec

**Endpoint**: `/instruction`

**Method**: `POST`

**Expects**: Body: `Transaction`

**Responses**:
- 200 OK - Transaction Acccepted (But not guaranteed to have passed consensus yet)
- 500 Internal Server Error - Transaction Rejected (Malformed or improperly signed)

### Submit Query

**Protocol**: HTTP

**Encoding**: Parity Scale Codec

**Endpoint**: `/query`

**Method**: `GET`

**Expects**:
- Body: `SignedQueryRequest`
- Query parameters:
 + `start` - Optional parameter in queries where results can be indexed. Use to return results from specified point. Results are ordered where can be by id which uses rust's [PartialOrd](https://doc.rust-lang.org/std/cmp/trait.PartialOrd.html#derivable) and [Ord](https://doc.rust-lang.org/std/cmp/trait.Ord.html) traits.
 + `limit` - Optional parameter in queries where results can be indexed. Use to return specific number of results.

**Responses**:
- 200 OK - Query Executed Successfuly. Body: `QueryResult`
- 500 Internal Server Error - Query Rejected (Failed to parse/execute or improperly signed)

### Listen to Events

**Protocol**: HTTP

**Protocol Upgrade**: `WebSocket`

**Encoding**: JSON

**Endpoint**: `/events`

**Expects**: 

First message after handshake from client: `SubscriptionRequest`

Server sends `Event` and expects `EventReceived` after each, before sending the next event.

### Metrics

**Protocol**: HTTP

**Encoding**: Parity Scale Codec

**Endpoint**: `/metrics`

**Method**: `GET`

**Expects**: -

**Responses**:
- 200 OK - Metrics Calculated Successfully. Body: `Metrics`
- 500 Internal Server Error - Failed to get metrics

### Health

**Protocol**: HTTP

**Encoding**: Parity Scale Codec

**Endpoint**: `/health`

**Method**: `GET`

**Expects**: -

**Responses**:
- 200 OK - The peer is up.

## Parity Scale Codec

For more information on codec check [Substrate Dev Hub](https://substrate.dev/docs/en/knowledgebase/advanced/codec) and codec's [Github repository](https://github.com/paritytech/parity-scale-codec).

## Reference Iroha Client Implementation

[Iroha client in Rust.](../../../iroha_client)

## Iroha Structures

- `Transaction` - `iroha_data_model::transaction::Transaction`
- `SignedQueryRequest` - `iroha_data_model::query::SignedQueryRequest`
- `QueryResult` - `iroha_data_model::query::QueryResult`
- `SubscriptionRequest` - `iroha_data_model::events::SubscriptionRequest`
- `Event` - `iroha_data_model::events::Event`
- `EventReceived` - `iroha_data_model::events::EventReceived`
- `Metrics` - `iroha::maintenance::Metrics`
