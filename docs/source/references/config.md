# Iroha Configuration reference

In this document we provide a reference and detailed descriptions of Iroha's configuration options. The options have different underlying types and default values, which are denoted in code as types wrapped in a single `Option<..>` or in a double `Option<Option<..>>`. For the detailed explanation, please refer to this [section](#configuration-types).

## Configuration types

### `Option<..>`

A type wrapped in a single `Option<..>` signifies that in the corresponding `json` block there is a fallback value for this type, and that it only serves as a reference. If a default for such a type has a `null` value, it means that there is no meaningful fallback available for this particular value.

All the default values can be freely obtained from a provided [sample configuration file](../../../configs/peer/config.json), but it should only serve as a starting point. If left unchanged, the sample configuration file would still fail to build due to it having `null` in place of [public](#public_key) and [private](#private_key) keys as well as [endpoint](#torii.api_url) [URLs](#torii.telemetry_url). These should be provided either by modifying the sample config file or as environment variables. No other overloading of configuration values happens besides reading them from a file and capturing the environment variables.

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
    "BLOCKS_PER_STORAGE_FILE": 1000,
    "ACTOR_CHANNEL_CAPACITY": 100
  },
  "SUMERAGI": {
    "KEY_PAIR": null,
    "PEER_ID": null,
    "BLOCK_TIME_MS": 1000,
    "TRUSTED_PEERS": null,
    "COMMIT_TIME_LIMIT_MS": 2000,
    "TX_RECEIPT_TIME_LIMIT_MS": 500,
    "TRANSACTION_LIMITS": {
      "max_instruction_number": 4096,
      "max_wasm_size_bytes": 4194304
    },
    "ACTOR_CHANNEL_CAPACITY": 100,
    "GOSSIP_BATCH_SIZE": 500,
    "GOSSIP_PERIOD_MS": 1000
  },
  "TORII": {
    "P2P_ADDR": null,
    "API_URL": null,
    "TELEMETRY_URL": null,
    "MAX_TRANSACTION_SIZE": 32768,
    "MAX_CONTENT_LEN": 16384000
  },
  "BLOCK_SYNC": {
    "GOSSIP_PERIOD_MS": 10000,
    "BLOCK_BATCH_SIZE": 4,
    "ACTOR_CHANNEL_CAPACITY": 100
  },
  "QUEUE": {
    "MAXIMUM_TRANSACTIONS_IN_BLOCK": 8192,
    "MAXIMUM_TRANSACTIONS_IN_QUEUE": 65536,
    "TRANSACTION_TIME_TO_LIVE_MS": 86400000,
    "FUTURE_THRESHOLD_MS": 1000
  },
  "LOGGER": {
    "MAX_LOG_LEVEL": "INFO",
    "TELEMETRY_CAPACITY": 1000,
    "COMPACT_MODE": false,
    "LOG_FILE_PATH": null,
    "TERMINAL_COLORS": true
  },
  "GENESIS": {
    "ACCOUNT_PUBLIC_KEY": null,
    "ACCOUNT_PRIVATE_KEY": null,
    "WAIT_FOR_PEERS_RETRY_COUNT_LIMIT": 100,
    "WAIT_FOR_PEERS_RETRY_PERIOD_MS": 500,
    "GENESIS_SUBMISSION_DELAY_MS": 1000
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
    "WASM_RUNTIME_CONFIG": {
      "FUEL_LIMIT": 1000000,
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
  }
}
```

## `block_sync`

`BlockSynchronizer` configuration

Has type `Option<block_sync::ConfigurationProxy>`. Can be configured via environment variable `IROHA_BLOCK_SYNC`. Refer to [configuration types](#configuration-types) for details.

```json
{
  "ACTOR_CHANNEL_CAPACITY": 100,
  "BLOCK_BATCH_SIZE": 4,
  "GOSSIP_PERIOD_MS": 10000
}
```

### `block_sync.actor_channel_capacity`

Buffer capacity of actor's MPSC channel

Has type `Option<u32>`. Can be configured via environment variable `BLOCK_SYNC_ACTOR_CHANNEL_CAPACITY`. Refer to [configuration types](#configuration-types) for details.

```json
100
```

### `block_sync.block_batch_size`

The number of blocks that can be sent in one message.

Has type `Option<u32>`. Can be configured via environment variable `BLOCK_SYNC_BLOCK_BATCH_SIZE`. Refer to [configuration types](#configuration-types) for details.

```json
4
```

### `block_sync.gossip_period_ms`

The period of time to wait between sending requests for the latest block.

Has type `Option<u64>`. Can be configured via environment variable `BLOCK_SYNC_GOSSIP_PERIOD_MS`. Refer to [configuration types](#configuration-types) for details.

```json
10000
```

## `disable_panic_terminal_colors`

Disable coloring of the backtrace and error report on panic

Has type `Option<bool>`. Can be configured via environment variable `IROHA_DISABLE_PANIC_TERMINAL_COLORS`. Refer to [configuration types](#configuration-types) for details.

```json
false
```

## `genesis`

`GenesisBlock` configuration

Has type `Option<genesis::ConfigurationProxy>`. Can be configured via environment variable `IROHA_GENESIS`. Refer to [configuration types](#configuration-types) for details.

```json
{
  "ACCOUNT_PRIVATE_KEY": null,
  "ACCOUNT_PUBLIC_KEY": null,
  "GENESIS_SUBMISSION_DELAY_MS": 1000,
  "WAIT_FOR_PEERS_RETRY_COUNT_LIMIT": 100,
  "WAIT_FOR_PEERS_RETRY_PERIOD_MS": 500
}
```

### `genesis.account_private_key`

The private key of the genesis account, only needed for the peer that submits the genesis block.

Has type `Option<Option<PrivateKey>>`. Can be configured via environment variable `IROHA_GENESIS_ACCOUNT_PRIVATE_KEY`. Refer to [configuration types](#configuration-types) for details.

```json
null
```

### `genesis.account_public_key`

The public key of the genesis account, should be supplied to all peers.

Has type `Option<PublicKey>`. Can be configured via environment variable `IROHA_GENESIS_ACCOUNT_PUBLIC_KEY`. Refer to [configuration types](#configuration-types) for details.

```json
null
```

### `genesis.genesis_submission_delay_ms`

The delay before genesis block submission after minimum number of peers were discovered to be online.

Has type `Option<u64>`. Can be configured via environment variable `IROHA_GENESIS_GENESIS_SUBMISSION_DELAY_MS`. Refer to [configuration types](#configuration-types) for details.

```json
1000
```

### `genesis.wait_for_peers_retry_count_limit`

The number of attempts to connect to peers while waiting for them to submit genesis.

Has type `Option<u64>`. Can be configured via environment variable `IROHA_GENESIS_WAIT_FOR_PEERS_RETRY_COUNT_LIMIT`. Refer to [configuration types](#configuration-types) for details.

```json
100
```

### `genesis.wait_for_peers_retry_period_ms`

The period in milliseconds in which to retry connecting to peers while waiting for them to submit genesis.

Has type `Option<u64>`. Can be configured via environment variable `IROHA_GENESIS_WAIT_FOR_PEERS_RETRY_PERIOD_MS`. Refer to [configuration types](#configuration-types) for details.

```json
500
```

## `kura`

`Kura` configuration

Has type `Option<kura::ConfigurationProxy>`. Can be configured via environment variable `IROHA_KURA`. Refer to [configuration types](#configuration-types) for details.

```json
{
  "ACTOR_CHANNEL_CAPACITY": 100,
  "BLOCKS_PER_STORAGE_FILE": 1000,
  "BLOCK_STORE_PATH": "./storage",
  "INIT_MODE": "strict"
}
```

### `kura.actor_channel_capacity`

Default buffer capacity of actor's MPSC channel.

Has type `Option<u32>`. Can be configured via environment variable `KURA_ACTOR_CHANNEL_CAPACITY`. Refer to [configuration types](#configuration-types) for details.

```json
100
```

### `kura.block_store_path`

Path to the existing block store folder or path to create new folder.

Has type `Option<String>`. Can be configured via environment variable `KURA_BLOCK_STORE_PATH`. Refer to [configuration types](#configuration-types) for details.

```json
"./storage"
```

### `kura.blocks_per_storage_file`

Maximum number of blocks to write into a single storage file.

Has type `Option<NonZeroU64>`. Can be configured via environment variable `KURA_BLOCKS_PER_STORAGE_FILE`. Refer to [configuration types](#configuration-types) for details.

```json
1000
```

### `kura.init_mode`

Initialization mode: `strict` or `fast`.

Has type `Option<Mode>`. Can be configured via environment variable `KURA_INIT_MODE`. Refer to [configuration types](#configuration-types) for details.

```json
"strict"
```

## `logger`

`Logger` configuration

Has type `Option<logger::ConfigurationProxy>`. Can be configured via environment variable `IROHA_LOGGER`. Refer to [configuration types](#configuration-types) for details.

```json
{
  "COMPACT_MODE": false,
  "LOG_FILE_PATH": null,
  "MAX_LOG_LEVEL": "INFO",
  "TELEMETRY_CAPACITY": 1000,
  "TERMINAL_COLORS": true
}
```

### `logger.compact_mode`

Compact mode (no spans from telemetry)

Has type `Option<bool>`. Can be configured via environment variable `COMPACT_MODE`. Refer to [configuration types](#configuration-types) for details.

```json
false
```

### `logger.log_file_path`

If provided, logs will be copied to said file in the

Has type `Option<Option<std::path::PathBuf>>`. Can be configured via environment variable `LOG_FILE_PATH`. Refer to [configuration types](#configuration-types) for details.

```json
null
```

### `logger.max_log_level`

Maximum log level

Has type `Option<SyncLevel>`. Can be configured via environment variable `MAX_LOG_LEVEL`. Refer to [configuration types](#configuration-types) for details.

```json
"INFO"
```

### `logger.telemetry_capacity`

Capacity (or batch size) for telemetry channel

Has type `Option<u32>`. Can be configured via environment variable `TELEMETRY_CAPACITY`. Refer to [configuration types](#configuration-types) for details.

```json
1000
```

### `logger.terminal_colors`

Enable ANSI terminal colors for formatted output.

Has type `Option<bool>`. Can be configured via environment variable `TERMINAL_COLORS`. Refer to [configuration types](#configuration-types) for details.

```json
true
```

## `network`

Network configuration

Has type `Option<network::ConfigurationProxy>`. Can be configured via environment variable `IROHA_NETWORK`. Refer to [configuration types](#configuration-types) for details.

```json
{
  "ACTOR_CHANNEL_CAPACITY": 100
}
```

### `network.actor_channel_capacity`

Buffer capacity of actor's MPSC channel

Has type `Option<u32>`. Can be configured via environment variable `IROHA_NETWORK_ACTOR_CHANNEL_CAPACITY`. Refer to [configuration types](#configuration-types) for details.

```json
100
```

## `private_key`

Private key of this peer

Has type `Option<PrivateKey>`. Can be configured via environment variable `IROHA_PRIVATE_KEY`. Refer to [configuration types](#configuration-types) for details.

```json
null
```

## `public_key`

Public key of this peer

Has type `Option<PublicKey>`. Can be configured via environment variable `IROHA_PUBLIC_KEY`. Refer to [configuration types](#configuration-types) for details.

```json
null
```

## `queue`

`Queue` configuration

Has type `Option<queue::ConfigurationProxy>`. Can be configured via environment variable `IROHA_QUEUE`. Refer to [configuration types](#configuration-types) for details.

```json
{
  "FUTURE_THRESHOLD_MS": 1000,
  "MAXIMUM_TRANSACTIONS_IN_BLOCK": 8192,
  "MAXIMUM_TRANSACTIONS_IN_QUEUE": 65536,
  "TRANSACTION_TIME_TO_LIVE_MS": 86400000
}
```

### `queue.future_threshold_ms`

The threshold to determine if a transaction has been tampered to have a future timestamp.

Has type `Option<u64>`. Can be configured via environment variable `QUEUE_FUTURE_THRESHOLD_MS`. Refer to [configuration types](#configuration-types) for details.

```json
1000
```

### `queue.maximum_transactions_in_block`

The upper limit of the number of transactions per block.

Has type `Option<u32>`. Can be configured via environment variable `QUEUE_MAXIMUM_TRANSACTIONS_IN_BLOCK`. Refer to [configuration types](#configuration-types) for details.

```json
8192
```

### `queue.maximum_transactions_in_queue`

The upper limit of the number of transactions waiting in the queue.

Has type `Option<u32>`. Can be configured via environment variable `QUEUE_MAXIMUM_TRANSACTIONS_IN_QUEUE`. Refer to [configuration types](#configuration-types) for details.

```json
65536
```

### `queue.transaction_time_to_live_ms`

The transaction will be dropped after this time if it is still in the queue.

Has type `Option<u64>`. Can be configured via environment variable `QUEUE_TRANSACTION_TIME_TO_LIVE_MS`. Refer to [configuration types](#configuration-types) for details.

```json
86400000
```

## `sumeragi`

`Sumeragi` configuration

Has type `Option<sumeragi::ConfigurationProxy>`. Can be configured via environment variable `IROHA_SUMERAGI`. Refer to [configuration types](#configuration-types) for details.

```json
{
  "ACTOR_CHANNEL_CAPACITY": 100,
  "BLOCK_TIME_MS": 1000,
  "COMMIT_TIME_LIMIT_MS": 2000,
  "GOSSIP_BATCH_SIZE": 500,
  "GOSSIP_PERIOD_MS": 1000,
  "KEY_PAIR": null,
  "PEER_ID": null,
  "TRANSACTION_LIMITS": {
    "max_instruction_number": 4096,
    "max_wasm_size_bytes": 4194304
  },
  "TRUSTED_PEERS": null,
  "TX_RECEIPT_TIME_LIMIT_MS": 500
}
```

### `sumeragi.actor_channel_capacity`

Buffer capacity of actor's MPSC channel

Has type `Option<u32>`. Can be configured via environment variable `SUMERAGI_ACTOR_CHANNEL_CAPACITY`. Refer to [configuration types](#configuration-types) for details.

```json
100
```

### `sumeragi.block_time_ms`

The period of time a peer waits for the `CreatedBlock` message after getting a `TransactionReceipt`

Has type `Option<u64>`. Can be configured via environment variable `SUMERAGI_BLOCK_TIME_MS`. Refer to [configuration types](#configuration-types) for details.

```json
1000
```

### `sumeragi.commit_time_limit_ms`

The period of time a peer waits for `CommitMessage` from the proxy tail.

Has type `Option<u64>`. Can be configured via environment variable `SUMERAGI_COMMIT_TIME_LIMIT_MS`. Refer to [configuration types](#configuration-types) for details.

```json
2000
```

### `sumeragi.gossip_batch_size`

Maximum number of transactions in tx gossip batch message. While configuring this, pay attention to `p2p` max message size.

Has type `Option<u32>`. Can be configured via environment variable `SUMERAGI_GOSSIP_BATCH_SIZE`. Refer to [configuration types](#configuration-types) for details.

```json
500
```

### `sumeragi.gossip_period_ms`

Period in milliseconds for pending transaction gossiping between peers.

Has type `Option<u64>`. Can be configured via environment variable `SUMERAGI_GOSSIP_PERIOD_MS`. Refer to [configuration types](#configuration-types) for details.

```json
1000
```

### `sumeragi.key_pair`

The key pair consisting of a private and a public key.

Has type `Option<KeyPair>`. Can be configured via environment variable `SUMERAGI_KEY_PAIR`. Refer to [configuration types](#configuration-types) for details.

```json
null
```

### `sumeragi.peer_id`

Current Peer Identification.

Has type `Option<PeerId>`. Can be configured via environment variable `SUMERAGI_PEER_ID`. Refer to [configuration types](#configuration-types) for details.

```json
null
```

### `sumeragi.transaction_limits`

The limits to which transactions must adhere

Has type `Option<TransactionLimits>`. Can be configured via environment variable `SUMERAGI_TRANSACTION_LIMITS`. Refer to [configuration types](#configuration-types) for details.

```json
{
  "max_instruction_number": 4096,
  "max_wasm_size_bytes": 4194304
}
```

### `sumeragi.trusted_peers`

Optional list of predefined trusted peers.

Has type `Option<TrustedPeers>`. Can be configured via environment variable `SUMERAGI_TRUSTED_PEERS`. Refer to [configuration types](#configuration-types) for details.

```json
null
```

### `sumeragi.tx_receipt_time_limit_ms`

The period of time a peer waits for `TxReceipt` from the leader.

Has type `Option<u64>`. Can be configured via environment variable `SUMERAGI_TX_RECEIPT_TIME_LIMIT_MS`. Refer to [configuration types](#configuration-types) for details.

```json
500
```

## `telemetry`

Telemetry configuration

Has type `Option<telemetry::ConfigurationProxy>`. Can be configured via environment variable `IROHA_TELEMETRY`. Refer to [configuration types](#configuration-types) for details.

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

Has type `Option<Option<std::path::PathBuf>>`. Can be configured via environment variable `TELEMETRY_FILE`. Refer to [configuration types](#configuration-types) for details.

```json
null
```

### `telemetry.max_retry_delay_exponent`

The maximum exponent of 2 that is used for increasing delay between reconnections

Has type `Option<u8>`. Can be configured via environment variable `TELEMETRY_MAX_RETRY_DELAY_EXPONENT`. Refer to [configuration types](#configuration-types) for details.

```json
4
```

### `telemetry.min_retry_period`

The minimum period of time in seconds to wait before reconnecting

Has type `Option<u64>`. Can be configured via environment variable `TELEMETRY_MIN_RETRY_PERIOD`. Refer to [configuration types](#configuration-types) for details.

```json
1
```

### `telemetry.name`

The node's name to be seen on the telemetry

Has type `Option<Option<String>>`. Can be configured via environment variable `TELEMETRY_NAME`. Refer to [configuration types](#configuration-types) for details.

```json
null
```

### `telemetry.url`

The url of the telemetry, e.g., ws://127.0.0.1:8001/submit

Has type `Option<Option<Url>>`. Can be configured via environment variable `TELEMETRY_URL`. Refer to [configuration types](#configuration-types) for details.

```json
null
```

## `torii`

`Torii` configuration

Has type `Option<torii::ConfigurationProxy>`. Can be configured via environment variable `IROHA_TORII`. Refer to [configuration types](#configuration-types) for details.

```json
{
  "API_URL": null,
  "MAX_CONTENT_LEN": 16384000,
  "MAX_TRANSACTION_SIZE": 32768,
  "P2P_ADDR": null,
  "TELEMETRY_URL": null
}
```

### `torii.api_url`

Torii URL for client API.

Has type `Option<String>`. Can be configured via environment variable `TORII_API_URL`. Refer to [configuration types](#configuration-types) for details.

```json
null
```

### `torii.max_content_len`

Maximum number of bytes in raw message. Used to prevent from DOS attacks.

Has type `Option<u32>`. Can be configured via environment variable `TORII_MAX_CONTENT_LEN`. Refer to [configuration types](#configuration-types) for details.

```json
16384000
```

### `torii.max_transaction_size`

Maximum number of bytes in raw transaction. Used to prevent from DOS attacks.

Has type `Option<u32>`. Can be configured via environment variable `TORII_MAX_TRANSACTION_SIZE`. Refer to [configuration types](#configuration-types) for details.

```json
32768
```

### `torii.p2p_addr`

Torii URL for p2p communication for consensus and block synchronization purposes.

Has type `Option<String>`. Can be configured via environment variable `TORII_P2P_ADDR`. Refer to [configuration types](#configuration-types) for details.

```json
null
```

### `torii.telemetry_url`

Torii URL for reporting internal status and metrics for administration.

Has type `Option<String>`. Can be configured via environment variable `TORII_TELEMETRY_URL`. Refer to [configuration types](#configuration-types) for details.

```json
null
```

## `wsv`

`WorldStateView` configuration

Has type `Option<wsv::ConfigurationProxy>`. Can be configured via environment variable `IROHA_WSV`. Refer to [configuration types](#configuration-types) for details.

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
  "WASM_RUNTIME_CONFIG": {
    "FUEL_LIMIT": 1000000,
    "MAX_MEMORY": 524288000
  }
}
```

### `wsv.account_metadata_limits`

[`MetadataLimits`] of any account metadata.

Has type `Option<MetadataLimits>`. Can be configured via environment variable `WSV_ACCOUNT_METADATA_LIMITS`. Refer to [configuration types](#configuration-types) for details.

```json
{
  "max_entry_byte_size": 4096,
  "max_len": 1048576
}
```

### `wsv.asset_definition_metadata_limits`

[`MetadataLimits`] of any asset definition metadata.

Has type `Option<MetadataLimits>`. Can be configured via environment variable `WSV_ASSET_DEFINITION_METADATA_LIMITS`. Refer to [configuration types](#configuration-types) for details.

```json
{
  "max_entry_byte_size": 4096,
  "max_len": 1048576
}
```

### `wsv.asset_metadata_limits`

[`MetadataLimits`] for every asset with store.

Has type `Option<MetadataLimits>`. Can be configured via environment variable `WSV_ASSET_METADATA_LIMITS`. Refer to [configuration types](#configuration-types) for details.

```json
{
  "max_entry_byte_size": 4096,
  "max_len": 1048576
}
```

### `wsv.domain_metadata_limits`

[`MetadataLimits`] of any domain metadata.

Has type `Option<MetadataLimits>`. Can be configured via environment variable `WSV_DOMAIN_METADATA_LIMITS`. Refer to [configuration types](#configuration-types) for details.

```json
{
  "max_entry_byte_size": 4096,
  "max_len": 1048576
}
```

### `wsv.ident_length_limits`

[`LengthLimits`] for the number of chars in identifiers that can be stored in the WSV.

Has type `Option<LengthLimits>`. Can be configured via environment variable `WSV_IDENT_LENGTH_LIMITS`. Refer to [configuration types](#configuration-types) for details.

```json
{
  "max": 128,
  "min": 1
}
```

### `wsv.wasm_runtime_config`

WASM runtime configuration

Has type `Option<wasm::ConfigurationProxy>`. Can be configured via environment variable `WSV_WASM_RUNTIME_CONFIG`. Refer to [configuration types](#configuration-types) for details.

```json
{
  "FUEL_LIMIT": 1000000,
  "MAX_MEMORY": 524288000
}
```

#### `wsv.wasm_runtime_config.fuel_limit`

The fuel limit determines the maximum number of instructions that can be executed within a smart contract.

Has type `Option<u64>`. Can be configured via environment variable `WASM_FUEL_LIMIT`. Refer to [configuration types](#configuration-types) for details.

```json
1000000
```

#### `wsv.wasm_runtime_config.max_memory`

Maximum amount of linear memory a given smart contract can allocate.

Has type `Option<u32>`. Can be configured via environment variable `WASM_MAX_MEMORY`. Refer to [configuration types](#configuration-types) for details.

```json
524288000
```

