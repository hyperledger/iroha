# Iroha Configuration reference

In this document we provide a reference and detailed descriptions of Iroha's configuration options. The options have different underlying types and default values, which are denoted in code as types wrapped in a single `Option<..>` or in a double `Option<Option<..>>`. For the detailed explanation, please refer to this [section](#configuration-types).

## Configuration types

### `Option<..>`

A type wrapped in a single `Option<..>` signifies that in the corresponding `json` block there is a fallback value for this type, and that it only serves as a reference. If a default for such a type has a `null` value, it means that there is no meaningful fallback available for this particular value.

All the default values can be freely obtained from a provided [sample configuration file](../../../configs/peer/config.json), but it should only serve as a starting point. If left unchanged, the sample configuration file would still fail to build due to it having `null` in place of [public](#public_key) and [private](#private_key) keys as well as [API endpoint URL](#torii.api_url). These should be provided either by modifying the sample config file or as environment variables. No other overloading of configuration values happens besides reading them from a file and capturing the environment variables.

For both types of configuration options wrapped in a single `Option<..>` (i.e. both those that have meaningful defaults and those that have `null`), failure to provide them in any of the above two ways results in an error.

### `Option<Option<..>>`

`Option<Option<..>>` types should be distinguished from types wrapped in a single `Option<..>`. Only the double option ones are allowed to stay `null`, meaning that **not** providing them in an environment variable or a file will **not** result in an error.

Thus, only these types are truly optional in the mundane sense of the word. An example of this distinction is genesis [public](#genesis.account_public_key) and [private](#genesis.account_private_key) key. While the first one is a single `Option<..>` wrapped type, the latter is wrapped in `Option<Option<..>>`. This means that the genesis *public* key should always be provided by the user, be it via a file config or an environment variable, whereas the *private* key is only needed for the peer that submits the genesis block, and can be omitted for all others. The same logic goes for other double option fields such as logger file path.

### Sumeragi: default `null` values

A special note about sumeragi fields with `null` as default: only the [`trusted_peers`](#sumeragi.trusted_peers) field out of the three can be initialized via a provided file or an environment variable.

The other two fields, namely [`key_pair`](#sumeragi.key_pair) and [`peer_id`](#sumeragi.peer_id), go through a process of finalization where their values are derived from the corresponding ones in the uppermost Iroha config (using its [`public_key`](#public_key) and [`private_key`](#private_key) fields) or the Torii config (via its [`p2p_addr`](#torii.p2p_addr)). This ensures that these linked fields stay in sync, and prevents the programmer error when different values are provided to these field pairs. Providing either `sumeragi.key_pair` or `sumeragi.peer_id` by hand will result in an error, as it should never be done directly.

## Default configuration

The following is the default configuration used by Iroha.

```json
{
  "PUBLIC_KEY": null,
  "PRIVATE_KEY": null,
  "DISABLE_PANIC_TERMINAL_COLORS": false,
  "KURA": {
    "INIT_MODE": "strict",
    "BLOCK_STORE_PATH": "./storage",
    "DEBUG_OUTPUT_NEW_BLOCKS": false
  },
  "SUMERAGI": {
    "KEY_PAIR": null,
    "PEER_ID": null,
    "BLOCK_TIME_MS": 2000,
    "TRUSTED_PEERS": null,
    "COMMIT_TIME_LIMIT_MS": 4000,
    "MAX_TRANSACTIONS_IN_BLOCK": 512,
    "ACTOR_CHANNEL_CAPACITY": 100,
    "GOSSIP_BATCH_SIZE": 500,
    "GOSSIP_PERIOD_MS": 1000
  },
  "TORII": {
    "P2P_ADDR": null,
    "API_URL": null,
    "MAX_TRANSACTION_SIZE": 32768,
    "MAX_CONTENT_LEN": 16384000
  },
  "BLOCK_SYNC": {
    "GOSSIP_PERIOD_MS": 10000,
    "BLOCK_BATCH_SIZE": 4,
    "ACTOR_CHANNEL_CAPACITY": 100
  },
  "QUEUE": {
    "MAX_TRANSACTIONS_IN_QUEUE": 65536,
    "MAX_TRANSACTIONS_IN_QUEUE_PER_USER": 65536,
    "TRANSACTION_TIME_TO_LIVE_MS": 86400000,
    "FUTURE_THRESHOLD_MS": 1000
  },
  "LOGGER": {
    "LEVEL": "INFO",
    "FORMAT": "full"
  },
  "GENESIS": {
    "ACCOUNT_PUBLIC_KEY": null,
    "ACCOUNT_PRIVATE_KEY": null
  },
  "WSV": {
    "ASSET_METADATA_LIMITS": {
      "max_len": 1048576,
      "max_entry_byte_size": 4096
    },
    "ASSET_DEFINITION_METADATA_LIMITS": {
      "max_len": 1048576,
      "max_entry_byte_size": 4096
    },
    "ACCOUNT_METADATA_LIMITS": {
      "max_len": 1048576,
      "max_entry_byte_size": 4096
    },
    "DOMAIN_METADATA_LIMITS": {
      "max_len": 1048576,
      "max_entry_byte_size": 4096
    },
    "IDENT_LENGTH_LIMITS": {
      "min": 1,
      "max": 128
    },
    "TRANSACTION_LIMITS": {
      "max_instruction_number": 4096,
      "max_wasm_size_bytes": 4194304
    },
    "WASM_RUNTIME_CONFIG": {
      "FUEL_LIMIT": 23000000,
      "MAX_MEMORY": 524288000
    }
  },
  "NETWORK": {
    "ACTOR_CHANNEL_CAPACITY": 100
  },
  "TELEMETRY": {
    "NAME": null,
    "URL": null,
    "MIN_RETRY_PERIOD": 1,
    "MAX_RETRY_DELAY_EXPONENT": 4,
    "FILE": null
  },
  "SNAPSHOT": {
    "CREATE_EVERY_MS": 60000,
    "DIR_PATH": "./storage",
    "CREATION_ENABLED": true
  },
  "LIVE_QUERY_STORE": {
    "QUERY_IDLE_TIME_MS": 30000
  }
}
```

## `block_sync`

`BlockSynchronizer` configuration

Has type `Option<block_sync::ConfigurationProxy>`[^1]. Can be configured via environment variable `IROHA_BLOCK_SYNC`

```json
{
  "ACTOR_CHANNEL_CAPACITY": 100,
  "BLOCK_BATCH_SIZE": 4,
  "GOSSIP_PERIOD_MS": 10000
}
```

### `block_sync.actor_channel_capacity`

Buffer capacity of actor's MPSC channel

Has type `Option<u32>`[^1]. Can be configured via environment variable `BLOCK_SYNC_ACTOR_CHANNEL_CAPACITY`

```json
100
```

### `block_sync.block_batch_size`

The number of blocks that can be sent in one message.

Has type `Option<u32>`[^1]. Can be configured via environment variable `BLOCK_SYNC_BLOCK_BATCH_SIZE`

```json
4
```

### `block_sync.gossip_period_ms`

The period of time to wait between sending requests for the latest block.

Has type `Option<u64>`[^1]. Can be configured via environment variable `BLOCK_SYNC_GOSSIP_PERIOD_MS`

```json
10000
```

## `disable_panic_terminal_colors`

Disable coloring of the backtrace and error report on panic

Has type `Option<bool>`[^1]. Can be configured via environment variable `IROHA_DISABLE_PANIC_TERMINAL_COLORS`

```json
false
```

## `genesis`

`GenesisBlock` configuration

Has type `Option<Box<genesis::ConfigurationProxy>>`[^1]. Can be configured via environment variable `IROHA_GENESIS`

```json
{
  "ACCOUNT_PRIVATE_KEY": null,
  "ACCOUNT_PUBLIC_KEY": null
}
```

### `genesis.account_private_key`

The private key of the genesis account, only needed for the peer that submits the genesis block.

Has type `Option<Option<PrivateKey>>`[^1]. Can be configured via environment variable `IROHA_GENESIS_ACCOUNT_PRIVATE_KEY`

```json
null
```

### `genesis.account_public_key`

The public key of the genesis account, should be supplied to all peers.

Has type `Option<PublicKey>`[^1]. Can be configured via environment variable `IROHA_GENESIS_ACCOUNT_PUBLIC_KEY`

```json
null
```

## `kura`

`Kura` configuration

Has type `Option<Box<kura::ConfigurationProxy>>`[^1]. Can be configured via environment variable `IROHA_KURA`

```json
{
  "BLOCK_STORE_PATH": "./storage",
  "DEBUG_OUTPUT_NEW_BLOCKS": false,
  "INIT_MODE": "strict"
}
```

### `kura.block_store_path`

Path to the existing block store folder or path to create new folder.

Has type `Option<String>`[^1]. Can be configured via environment variable `KURA_BLOCK_STORE_PATH`

```json
"./storage"
```

### `kura.debug_output_new_blocks`

Whether or not new blocks be outputted to a file called blocks.json.

Has type `Option<bool>`[^1]. Can be configured via environment variable `KURA_DEBUG_OUTPUT_NEW_BLOCKS`

```json
false
```

### `kura.init_mode`

Initialization mode: `strict` or `fast`.

Has type `Option<Mode>`[^1]. Can be configured via environment variable `KURA_INIT_MODE`

```json
"strict"
```

## `live_query_store`

LiveQueryStore configuration

Has type `Option<live_query_store::ConfigurationProxy>`[^1]. Can be configured via environment variable `IROHA_LIVE_QUERY_STORE`

```json
{
  "QUERY_IDLE_TIME_MS": 30000
}
```

### `live_query_store.query_idle_time_ms`

Time query can remain in the store if unaccessed

Has type `Option<NonZeroU64>`[^1]. Can be configured via environment variable `LIVE_QUERY_STORE_QUERY_IDLE_TIME_MS`

```json
30000
```

## `logger`

`Logger` configuration

Has type `Option<Box<logger::ConfigurationProxy>>`[^1]. Can be configured via environment variable `IROHA_LOGGER`

```json
{
  "FORMAT": "full",
  "LEVEL": "INFO"
}
```

### `logger.format`

Output format

Has type `Option<Format>`[^1]. Can be configured via environment variable `LOG_FORMAT`

```json
"full"
```

### `logger.level`

Level of logging verbosity

Has type `Option<Level>`[^1]. Can be configured via environment variable `LOG_LEVEL`

```json
"INFO"
```

## `network`

Network configuration

Has type `Option<network::ConfigurationProxy>`[^1]. Can be configured via environment variable `IROHA_NETWORK`

```json
{
  "ACTOR_CHANNEL_CAPACITY": 100
}
```

### `network.actor_channel_capacity`

Buffer capacity of actor's MPSC channel

Has type `Option<u32>`[^1]. Can be configured via environment variable `IROHA_NETWORK_ACTOR_CHANNEL_CAPACITY`

```json
100
```

## `private_key`

Private key of this peer

Has type `Option<PrivateKey>`[^1]. Can be configured via environment variable `IROHA_PRIVATE_KEY`

```json
null
```

## `public_key`

Public key of this peer

Has type `Option<PublicKey>`[^1]. Can be configured via environment variable `IROHA_PUBLIC_KEY`

```json
null
```

## `queue`

`Queue` configuration

Has type `Option<queue::ConfigurationProxy>`[^1]. Can be configured via environment variable `IROHA_QUEUE`

```json
{
  "FUTURE_THRESHOLD_MS": 1000,
  "MAX_TRANSACTIONS_IN_QUEUE": 65536,
  "MAX_TRANSACTIONS_IN_QUEUE_PER_USER": 65536,
  "TRANSACTION_TIME_TO_LIVE_MS": 86400000
}
```

### `queue.future_threshold_ms`

The threshold to determine if a transaction has been tampered to have a future timestamp.

Has type `Option<u64>`[^1]. Can be configured via environment variable `QUEUE_FUTURE_THRESHOLD_MS`

```json
1000
```

### `queue.max_transactions_in_queue`

The upper limit of the number of transactions waiting in the queue.

Has type `Option<u32>`[^1]. Can be configured via environment variable `QUEUE_MAX_TRANSACTIONS_IN_QUEUE`

```json
65536
```

### `queue.max_transactions_in_queue_per_user`

The upper limit of the number of transactions waiting in the queue for single user.

Has type `Option<u32>`[^1]. Can be configured via environment variable `QUEUE_MAX_TRANSACTIONS_IN_QUEUE_PER_USER`

```json
65536
```

### `queue.transaction_time_to_live_ms`

The transaction will be dropped after this time if it is still in the queue.

Has type `Option<u64>`[^1]. Can be configured via environment variable `QUEUE_TRANSACTION_TIME_TO_LIVE_MS`

```json
86400000
```

## `snapshot`

SnapshotMaker configuration

Has type `Option<Box<snapshot::ConfigurationProxy>>`[^1]. Can be configured via environment variable `IROHA_SNAPSHOT`

```json
{
  "CREATE_EVERY_MS": 60000,
  "CREATION_ENABLED": true,
  "DIR_PATH": "./storage"
}
```

### `snapshot.create_every_ms`

The period of time to wait between attempts to create new snapshot.

Has type `Option<u64>`[^1]. Can be configured via environment variable `SNAPSHOT_CREATE_EVERY_MS`

```json
60000
```

### `snapshot.creation_enabled`

Flag to enable or disable snapshot creation

Has type `Option<bool>`[^1]. Can be configured via environment variable `SNAPSHOT_CREATION_ENABLED`

```json
true
```

### `snapshot.dir_path`

Path to the directory where snapshots should be stored

Has type `Option<String>`[^1]. Can be configured via environment variable `SNAPSHOT_DIR_PATH`

```json
"./storage"
```

## `sumeragi`

`Sumeragi` configuration

Has type `Option<Box<sumeragi::ConfigurationProxy>>`[^1]. Can be configured via environment variable `IROHA_SUMERAGI`

```json
{
  "ACTOR_CHANNEL_CAPACITY": 100,
  "BLOCK_TIME_MS": 2000,
  "COMMIT_TIME_LIMIT_MS": 4000,
  "GOSSIP_BATCH_SIZE": 500,
  "GOSSIP_PERIOD_MS": 1000,
  "KEY_PAIR": null,
  "MAX_TRANSACTIONS_IN_BLOCK": 512,
  "PEER_ID": null,
  "TRUSTED_PEERS": null
}
```

### `sumeragi.actor_channel_capacity`

Buffer capacity of actor's MPSC channel

Has type `Option<u32>`[^1]. Can be configured via environment variable `SUMERAGI_ACTOR_CHANNEL_CAPACITY`

```json
100
```

### `sumeragi.block_time_ms`

The period of time a peer waits for the `CreatedBlock` message after getting a `TransactionReceipt`

Has type `Option<u64>`[^1]. Can be configured via environment variable `SUMERAGI_BLOCK_TIME_MS`

```json
2000
```

### `sumeragi.commit_time_limit_ms`

The period of time a peer waits for `CommitMessage` from the proxy tail.

Has type `Option<u64>`[^1]. Can be configured via environment variable `SUMERAGI_COMMIT_TIME_LIMIT_MS`

```json
4000
```

### `sumeragi.gossip_batch_size`

max number of transactions in tx gossip batch message. While configuring this, pay attention to `p2p` max message size.

Has type `Option<u32>`[^1]. Can be configured via environment variable `SUMERAGI_GOSSIP_BATCH_SIZE`

```json
500
```

### `sumeragi.gossip_period_ms`

Period in milliseconds for pending transaction gossiping between peers.

Has type `Option<u64>`[^1]. Can be configured via environment variable `SUMERAGI_GOSSIP_PERIOD_MS`

```json
1000
```

### `sumeragi.key_pair`

The key pair consisting of a private and a public key.

Has type `Option<KeyPair>`[^1]. Can be configured via environment variable `SUMERAGI_KEY_PAIR`

```json
null
```

### `sumeragi.max_transactions_in_block`

The upper limit of the number of transactions per block.

Has type `Option<u32>`[^1]. Can be configured via environment variable `SUMERAGI_MAX_TRANSACTIONS_IN_BLOCK`

```json
512
```

### `sumeragi.peer_id`

Current Peer Identification.

Has type `Option<PeerId>`[^1]. Can be configured via environment variable `SUMERAGI_PEER_ID`

```json
null
```

### `sumeragi.trusted_peers`

Optional list of predefined trusted peers.

Has type `Option<TrustedPeers>`[^1]. Can be configured via environment variable `SUMERAGI_TRUSTED_PEERS`

```json
null
```

## `telemetry`

Telemetry configuration

Has type `Option<Box<telemetry::ConfigurationProxy>>`[^1]. Can be configured via environment variable `IROHA_TELEMETRY`

```json
{
  "FILE": null,
  "MAX_RETRY_DELAY_EXPONENT": 4,
  "MIN_RETRY_PERIOD": 1,
  "NAME": null,
  "URL": null
}
```

### `telemetry.file`

The filepath that to write dev-telemetry to

Has type `Option<Option<PathBuf>>`[^1]. Can be configured via environment variable `TELEMETRY_FILE`

```json
null
```

### `telemetry.max_retry_delay_exponent`

The maximum exponent of 2 that is used for increasing delay between reconnections

Has type `Option<u8>`[^1]. Can be configured via environment variable `TELEMETRY_MAX_RETRY_DELAY_EXPONENT`

```json
4
```

### `telemetry.min_retry_period`

The minimum period of time in seconds to wait before reconnecting

Has type `Option<u64>`[^1]. Can be configured via environment variable `TELEMETRY_MIN_RETRY_PERIOD`

```json
1
```

### `telemetry.name`

The node's name to be seen on the telemetry

Has type `Option<Option<String>>`[^1]. Can be configured via environment variable `TELEMETRY_NAME`

```json
null
```

### `telemetry.url`

The url of the telemetry, e.g., ws://127.0.0.1:8001/submit

Has type `Option<Option<Url>>`[^1]. Can be configured via environment variable `TELEMETRY_URL`

```json
null
```

## `torii`

`Torii` configuration

Has type `Option<Box<torii::ConfigurationProxy>>`[^1]. Can be configured via environment variable `IROHA_TORII`

```json
{
  "API_URL": null,
  "MAX_CONTENT_LEN": 16384000,
  "MAX_TRANSACTION_SIZE": 32768,
  "P2P_ADDR": null
}
```

### `torii.api_url`

Torii address for client API.

Has type `Option<SocketAddr>`[^1]. Can be configured via environment variable `TORII_API_URL`

```json
null
```

### `torii.max_content_len`

Maximum number of bytes in raw message. Used to prevent from DOS attacks.

Has type `Option<u32>`[^1]. Can be configured via environment variable `TORII_MAX_CONTENT_LEN`

```json
16384000
```

### `torii.max_transaction_size`

Maximum number of bytes in raw transaction. Used to prevent from DOS attacks.

Has type `Option<u32>`[^1]. Can be configured via environment variable `TORII_MAX_TRANSACTION_SIZE`

```json
32768
```

### `torii.p2p_addr`

Torii address for p2p communication for consensus and block synchronization purposes.

Has type `Option<SocketAddr>`[^1]. Can be configured via environment variable `TORII_P2P_ADDR`

```json
null
```

## `wsv`

`WorldStateView` configuration

Has type `Option<Box<wsv::ConfigurationProxy>>`[^1]. Can be configured via environment variable `IROHA_WSV`

```json
{
  "ACCOUNT_METADATA_LIMITS": {
    "max_entry_byte_size": 4096,
    "max_len": 1048576
  },
  "ASSET_DEFINITION_METADATA_LIMITS": {
    "max_entry_byte_size": 4096,
    "max_len": 1048576
  },
  "ASSET_METADATA_LIMITS": {
    "max_entry_byte_size": 4096,
    "max_len": 1048576
  },
  "DOMAIN_METADATA_LIMITS": {
    "max_entry_byte_size": 4096,
    "max_len": 1048576
  },
  "IDENT_LENGTH_LIMITS": {
    "max": 128,
    "min": 1
  },
  "TRANSACTION_LIMITS": {
    "max_instruction_number": 4096,
    "max_wasm_size_bytes": 4194304
  },
  "WASM_RUNTIME_CONFIG": {
    "FUEL_LIMIT": 23000000,
    "MAX_MEMORY": 524288000
  }
}
```

### `wsv.account_metadata_limits`

[`MetadataLimits`] of any account metadata.

Has type `Option<MetadataLimits>`[^1]. Can be configured via environment variable `WSV_ACCOUNT_METADATA_LIMITS`

```json
{
  "max_entry_byte_size": 4096,
  "max_len": 1048576
}
```

### `wsv.asset_definition_metadata_limits`

[`MetadataLimits`] of any asset definition metadata.

Has type `Option<MetadataLimits>`[^1]. Can be configured via environment variable `WSV_ASSET_DEFINITION_METADATA_LIMITS`

```json
{
  "max_entry_byte_size": 4096,
  "max_len": 1048576
}
```

### `wsv.asset_metadata_limits`

[`MetadataLimits`] for every asset with store.

Has type `Option<MetadataLimits>`[^1]. Can be configured via environment variable `WSV_ASSET_METADATA_LIMITS`

```json
{
  "max_entry_byte_size": 4096,
  "max_len": 1048576
}
```

### `wsv.domain_metadata_limits`

[`MetadataLimits`] of any domain metadata.

Has type `Option<MetadataLimits>`[^1]. Can be configured via environment variable `WSV_DOMAIN_METADATA_LIMITS`

```json
{
  "max_entry_byte_size": 4096,
  "max_len": 1048576
}
```

### `wsv.ident_length_limits`

[`LengthLimits`] for the number of chars in identifiers that can be stored in the WSV.

Has type `Option<LengthLimits>`[^1]. Can be configured via environment variable `WSV_IDENT_LENGTH_LIMITS`

```json
{
  "max": 128,
  "min": 1
}
```

### `wsv.transaction_limits`

Limits that all transactions need to obey, in terms of size

Has type `Option<TransactionLimits>`[^1]. Can be configured via environment variable `WSV_TRANSACTION_LIMITS`

```json
{
  "max_instruction_number": 4096,
  "max_wasm_size_bytes": 4194304
}
```

### `wsv.wasm_runtime_config`

WASM runtime configuration

Has type `Option<wasm::ConfigurationProxy>`[^1]. Can be configured via environment variable `WSV_WASM_RUNTIME_CONFIG`

```json
{
  "FUEL_LIMIT": 23000000,
  "MAX_MEMORY": 524288000
}
```

#### `wsv.wasm_runtime_config.fuel_limit`

The fuel limit determines the maximum number of instructions that can be executed within a smart contract.

Has type `Option<u64>`[^1]. Can be configured via environment variable `WASM_FUEL_LIMIT`

```json
23000000
```

#### `wsv.wasm_runtime_config.max_memory`

Maximum amount of linear memory a given smart contract can allocate.

Has type `Option<u32>`[^1]. Can be configured via environment variable `WASM_MAX_MEMORY`

```json
524288000
```

