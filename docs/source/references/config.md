# Iroha Configuration reference

In this document we provide a reference and detailed descriptions of Iroha's configuration options.

## Default configuration

The following is the default configuration used by Iroha.

```json
{
  "PUBLIC_KEY": "ed01201c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b",
  "PRIVATE_KEY": {
    "digest_function": "ed25519",
    "payload": "282ed9f3cf92811c3818dbc4ae594ed59dc1a2f78e4241e31924e101d6b1fb831c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b"
  },
  "DISABLE_PANIC_TERMINAL_COLORS": false,
  "KURA": {
    "INIT_MODE": "strict",
    "BLOCK_STORE_PATH": "./storage",
    "BLOCKS_PER_STORAGE_FILE": 1000,
    "ACTOR_CHANNEL_CAPACITY": 100
  },
  "SUMERAGI": {
    "PEER_ID": {
      "address": "127.0.0.1:1337",
      "public_key": "ed01201c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b"
    },
    "BLOCK_TIME_MS": 1000,
    "TRUSTED_PEERS": [
      {
        "address": "127.0.0.1:1337",
        "public_key": "ed01201c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b"
      }
    ],
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
    "P2P_ADDR": "127.0.0.1:1337",
    "API_URL": "127.0.0.1:8080",
    "TELEMETRY_URL": "127.0.0.1:8180",
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
    "ACCOUNT_PUBLIC_KEY": "ed01204cffd0ee429b1bdd36b3910ec570852b8bb63f18750341772fb46bc856c5caaf",
    "ACCOUNT_PRIVATE_KEY": {
      "digest_function": "ed25519",
      "payload": "d748e18ce60cb30dea3e73c9019b7af45a8d465e3d71bcc9a5ef99a008205e534cffd0ee429b1bdd36b3910ec570852b8bb63f18750341772fb46bc856c5caaf"
    },
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

Has type `block_sync::Configuration`. Can be configured via environment variable `IROHA_BLOCK_SYNC`

```json
{
  "ACTOR_CHANNEL_CAPACITY": 100,
  "BLOCK_BATCH_SIZE": 4,
  "GOSSIP_PERIOD_MS": 10000
}
```

### `block_sync.actor_channel_capacity`

Buffer capacity of actor's MPSC channel

Has type `u32`. Can be configured via environment variable `BLOCK_SYNC_ACTOR_CHANNEL_CAPACITY`

```json
100
```

### `block_sync.block_batch_size`

The number of blocks that can be sent in one message.

Has type `u32`. Can be configured via environment variable `BLOCK_SYNC_BLOCK_BATCH_SIZE`

```json
4
```

### `block_sync.gossip_period_ms`

The period of time to wait between sending requests for the latest block.

Has type `u64`. Can be configured via environment variable `BLOCK_SYNC_GOSSIP_PERIOD_MS`

```json
10000
```

## `disable_panic_terminal_colors`

Disable coloring of the backtrace and error report on panic

Has type `bool`. Can be configured via environment variable `IROHA_DISABLE_PANIC_TERMINAL_COLORS`

```json
false
```

## `genesis`

`GenesisBlock` configuration

Has type `genesis::Configuration`. Can be configured via environment variable `IROHA_GENESIS`

```json
{
  "ACCOUNT_PRIVATE_KEY": {
    "digest_function": "ed25519",
    "payload": "d748e18ce60cb30dea3e73c9019b7af45a8d465e3d71bcc9a5ef99a008205e534cffd0ee429b1bdd36b3910ec570852b8bb63f18750341772fb46bc856c5caaf"
  },
  "ACCOUNT_PUBLIC_KEY": "ed01204cffd0ee429b1bdd36b3910ec570852b8bb63f18750341772fb46bc856c5caaf",
  "GENESIS_SUBMISSION_DELAY_MS": 1000,
  "WAIT_FOR_PEERS_RETRY_COUNT_LIMIT": 100,
  "WAIT_FOR_PEERS_RETRY_PERIOD_MS": 500
}
```

### `genesis.account_private_key`

The private key of the genesis account, only needed for the peer that submits the genesis block.

Has type `Option<PrivateKey>`. Can be configured via environment variable `IROHA_GENESIS_ACCOUNT_PRIVATE_KEY`

```json
{
  "digest_function": "ed25519",
  "payload": "d748e18ce60cb30dea3e73c9019b7af45a8d465e3d71bcc9a5ef99a008205e534cffd0ee429b1bdd36b3910ec570852b8bb63f18750341772fb46bc856c5caaf"
}
```

### `genesis.account_public_key`

The public key of the genesis account, should be supplied to all peers.

Has type `PublicKey`. Can be configured via environment variable `IROHA_GENESIS_ACCOUNT_PUBLIC_KEY`

```json
"ed01204cffd0ee429b1bdd36b3910ec570852b8bb63f18750341772fb46bc856c5caaf"
```

### `genesis.genesis_submission_delay_ms`

The delay before genesis block submission after minimum number of peers were discovered to be online.

Has type `u64`. Can be configured via environment variable `IROHA_GENESIS_GENESIS_SUBMISSION_DELAY_MS`

```json
1000
```

### `genesis.wait_for_peers_retry_count_limit`

The number of attempts to connect to peers while waiting for them to submit genesis.

Has type `u64`. Can be configured via environment variable `IROHA_GENESIS_WAIT_FOR_PEERS_RETRY_COUNT_LIMIT`

```json
100
```

### `genesis.wait_for_peers_retry_period_ms`

The period in milliseconds in which to retry connecting to peers while waiting for them to submit genesis.

Has type `u64`. Can be configured via environment variable `IROHA_GENESIS_WAIT_FOR_PEERS_RETRY_PERIOD_MS`

```json
500
```

## `kura`

`Kura` configuration

Has type `kura::Configuration`. Can be configured via environment variable `IROHA_KURA`

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

Has type `u32`. Can be configured via environment variable `KURA_ACTOR_CHANNEL_CAPACITY`

```json
100
```

### `kura.block_store_path`

Path to the existing block store folder or path to create new folder.

Has type `String`. Can be configured via environment variable `KURA_BLOCK_STORE_PATH`

```json
"./storage"
```

### `kura.blocks_per_storage_file`

Maximum number of blocks to write into a single storage file.

Has type `NonZeroU64`. Can be configured via environment variable `KURA_BLOCKS_PER_STORAGE_FILE`

```json
1000
```

### `kura.init_mode`

Initialization mode: `strict` or `fast`.

Has type `Mode`. Can be configured via environment variable `KURA_INIT_MODE`

```json
"strict"
```

## `logger`

`Logger` configuration

Has type `logger::Configuration`. Can be configured via environment variable `IROHA_LOGGER`

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

Has type `bool`. Can be configured via environment variable `COMPACT_MODE`

```json
false
```

### `logger.log_file_path`

If provided, logs will be copied to said file in the

Has type `Option<std::path::PathBuf>`. Can be configured via environment variable `LOG_FILE_PATH`

```json
null
```

### `logger.max_log_level`

Maximum log level

Has type `SyncLevel`. Can be configured via environment variable `MAX_LOG_LEVEL`

```json
"INFO"
```

### `logger.telemetry_capacity`

Capacity (or batch size) for telemetry channel

Has type `u32`. Can be configured via environment variable `TELEMETRY_CAPACITY`

```json
1000
```

### `logger.terminal_colors`

Enable ANSI terminal colors for formatted output.

Has type `bool`. Can be configured via environment variable `TERMINAL_COLORS`

```json
true
```

## `network`

Network configuration

Has type `network::Configuration`. Can be configured via environment variable `IROHA_NETWORK`

```json
{
  "ACTOR_CHANNEL_CAPACITY": 100
}
```

### `network.actor_channel_capacity`

Buffer capacity of actor's MPSC channel

Has type `u32`. Can be configured via environment variable `IROHA_NETWORK_ACTOR_CHANNEL_CAPACITY`

```json
100
```

## `private_key`

Private key of this peer

Has type `PrivateKey`. Can be configured via environment variable `IROHA_PRIVATE_KEY`

```json
{
  "digest_function": "ed25519",
  "payload": "282ed9f3cf92811c3818dbc4ae594ed59dc1a2f78e4241e31924e101d6b1fb831c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b"
}
```

## `public_key`

Public key of this peer

Has type `PublicKey`. Can be configured via environment variable `IROHA_PUBLIC_KEY`

```json
"ed01201c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b"
```

## `queue`

`Queue` configuration

Has type `queue::Configuration`. Can be configured via environment variable `IROHA_QUEUE`

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

Has type `u64`. Can be configured via environment variable `QUEUE_FUTURE_THRESHOLD_MS`

```json
1000
```

### `queue.maximum_transactions_in_block`

The upper limit of the number of transactions per block.

Has type `u32`. Can be configured via environment variable `QUEUE_MAXIMUM_TRANSACTIONS_IN_BLOCK`

```json
8192
```

### `queue.maximum_transactions_in_queue`

The upper limit of the number of transactions waiting in the queue.

Has type `u32`. Can be configured via environment variable `QUEUE_MAXIMUM_TRANSACTIONS_IN_QUEUE`

```json
65536
```

### `queue.transaction_time_to_live_ms`

The transaction will be dropped after this time if it is still in the queue.

Has type `u64`. Can be configured via environment variable `QUEUE_TRANSACTION_TIME_TO_LIVE_MS`

```json
86400000
```

## `sumeragi`

`Sumeragi` configuration

Has type `sumeragi::Configuration`. Can be configured via environment variable `IROHA_SUMERAGI`

```json
{
  "ACTOR_CHANNEL_CAPACITY": 100,
  "BLOCK_TIME_MS": 1000,
  "COMMIT_TIME_LIMIT_MS": 2000,
  "GOSSIP_BATCH_SIZE": 500,
  "GOSSIP_PERIOD_MS": 1000,
  "PEER_ID": {
    "address": "127.0.0.1:1337",
    "public_key": "ed01201c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b"
  },
  "TRANSACTION_LIMITS": {
    "max_instruction_number": 4096,
    "max_wasm_size_bytes": 4194304
  },
  "TRUSTED_PEERS": [
    {
      "address": "127.0.0.1:1337",
      "public_key": "ed01201c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b"
    }
  ],
  "TX_RECEIPT_TIME_LIMIT_MS": 500
}
```

### `sumeragi.actor_channel_capacity`

Buffer capacity of actor's MPSC channel

Has type `u32`. Can be configured via environment variable `SUMERAGI_ACTOR_CHANNEL_CAPACITY`

```json
100
```

### `sumeragi.block_time_ms`

The period of time a peer waits for the `CreatedBlock` message after getting a `TransactionReceipt`

Has type `u64`. Can be configured via environment variable `SUMERAGI_BLOCK_TIME_MS`

```json
1000
```

### `sumeragi.commit_time_limit_ms`

The period of time a peer waits for `CommitMessage` from the proxy tail.

Has type `u64`. Can be configured via environment variable `SUMERAGI_COMMIT_TIME_LIMIT_MS`

```json
2000
```

### `sumeragi.gossip_batch_size`

Maximum number of transactions in tx gossip batch message. While configuring this, pay attention to `p2p` max message size.

Has type `u32`. Can be configured via environment variable `SUMERAGI_GOSSIP_BATCH_SIZE`

```json
500
```

### `sumeragi.gossip_period_ms`

Period in milliseconds for pending transaction gossiping between peers.

Has type `u64`. Can be configured via environment variable `SUMERAGI_GOSSIP_PERIOD_MS`

```json
1000
```

### `sumeragi.key_pair`

The key pair consisting of a private and a public key.

Has type `KeyPair`. Can be configured via environment variable `SUMERAGI_KEY_PAIR`

```json
{
  "private_key": {
    "digest_function": "ed25519",
    "payload": "282ed9f3cf92811c3818dbc4ae594ed59dc1a2f78e4241e31924e101d6b1fb831c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b"
  },
  "public_key": "ed01201c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b"
}
```

### `sumeragi.peer_id`

Current Peer Identification.

Has type `PeerId`. Can be configured via environment variable `SUMERAGI_PEER_ID`

```json
{
  "address": "127.0.0.1:1337",
  "public_key": "ed01201c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b"
}
```

### `sumeragi.transaction_limits`

The limits to which transactions must adhere

Has type `TransactionLimits`. Can be configured via environment variable `SUMERAGI_TRANSACTION_LIMITS`

```json
{
  "max_instruction_number": 4096,
  "max_wasm_size_bytes": 4194304
}
```

### `sumeragi.trusted_peers`

Optional list of predefined trusted peers.

Has type `TrustedPeers`. Can be configured via environment variable `SUMERAGI_TRUSTED_PEERS`

```json
[
  {
    "address": "127.0.0.1:1337",
    "public_key": "ed01201c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b"
  }
]
```

### `sumeragi.tx_receipt_time_limit_ms`

The period of time a peer waits for `TxReceipt` from the leader.

Has type `u64`. Can be configured via environment variable `SUMERAGI_TX_RECEIPT_TIME_LIMIT_MS`

```json
500
```

## `telemetry`

Telemetry configuration

Has type `telemetry::Configuration`. Can be configured via environment variable `IROHA_TELEMETRY`

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

Has type `Option<std::path::PathBuf>`. Can be configured via environment variable `TELEMETRY_FILE`

```json
null
```

### `telemetry.max_retry_delay_exponent`

The maximum exponent of 2 that is used for increasing delay between reconnections

Has type `u8`. Can be configured via environment variable `TELEMETRY_MAX_RETRY_DELAY_EXPONENT`

```json
4
```

### `telemetry.min_retry_period`

The minimum period of time in seconds to wait before reconnecting

Has type `u64`. Can be configured via environment variable `TELEMETRY_MIN_RETRY_PERIOD`

```json
1
```

### `telemetry.name`

The node's name to be seen on the telemetry

Has type `Option<String>`. Can be configured via environment variable `TELEMETRY_NAME`

```json
null
```

### `telemetry.url`

The url of the telemetry, e.g., ws://127.0.0.1:8001/submit

Has type `Option<Url>`. Can be configured via environment variable `TELEMETRY_URL`

```json
null
```

## `torii`

`Torii` configuration

Has type `torii::Configuration`. Can be configured via environment variable `IROHA_TORII`

```json
{
  "API_URL": "127.0.0.1:8080",
  "MAX_CONTENT_LEN": 16384000,
  "MAX_TRANSACTION_SIZE": 32768,
  "P2P_ADDR": "127.0.0.1:1337",
  "TELEMETRY_URL": "127.0.0.1:8180"
}
```

### `torii.api_url`

Torii URL for client API.

Has type `String`. Can be configured via environment variable `TORII_API_URL`

```json
"127.0.0.1:8080"
```

### `torii.max_content_len`

Maximum number of bytes in raw message. Used to prevent from DOS attacks.

Has type `u32`. Can be configured via environment variable `TORII_MAX_CONTENT_LEN`

```json
16384000
```

### `torii.max_transaction_size`

Maximum number of bytes in raw transaction. Used to prevent from DOS attacks.

Has type `u32`. Can be configured via environment variable `TORII_MAX_TRANSACTION_SIZE`

```json
32768
```

### `torii.p2p_addr`

Torii URL for p2p communication for consensus and block synchronization purposes.

Has type `String`. Can be configured via environment variable `TORII_P2P_ADDR`

```json
"127.0.0.1:1337"
```

### `torii.telemetry_url`

Torii URL for reporting internal status and metrics for administration.

Has type `String`. Can be configured via environment variable `TORII_TELEMETRY_URL`

```json
"127.0.0.1:8180"
```

## `wsv`

`WorldStateView` configuration

Has type `wsv::Configuration`. Can be configured via environment variable `IROHA_WSV`

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

Has type `MetadataLimits`. Can be configured via environment variable `WSV_ACCOUNT_METADATA_LIMITS`

```json
{
  "max_entry_byte_size": 4096,
  "max_len": 1048576
}
```

### `wsv.asset_definition_metadata_limits`

[`MetadataLimits`] of any asset definition metadata.

Has type `MetadataLimits`. Can be configured via environment variable `WSV_ASSET_DEFINITION_METADATA_LIMITS`

```json
{
  "max_entry_byte_size": 4096,
  "max_len": 1048576
}
```

### `wsv.asset_metadata_limits`

[`MetadataLimits`] for every asset with store.

Has type `MetadataLimits`. Can be configured via environment variable `WSV_ASSET_METADATA_LIMITS`

```json
{
  "max_entry_byte_size": 4096,
  "max_len": 1048576
}
```

### `wsv.domain_metadata_limits`

[`MetadataLimits`] of any domain metadata.

Has type `MetadataLimits`. Can be configured via environment variable `WSV_DOMAIN_METADATA_LIMITS`

```json
{
  "max_entry_byte_size": 4096,
  "max_len": 1048576
}
```

### `wsv.ident_length_limits`

[`LengthLimits`] for the number of chars in identifiers that can be stored in the WSV.

Has type `LengthLimits`. Can be configured via environment variable `WSV_IDENT_LENGTH_LIMITS`

```json
{
  "max": 128,
  "min": 1
}
```

### `wsv.wasm_runtime_config`

WASM runtime configuration

Has type `wasm::Configuration`. Can be configured via environment variable `WSV_WASM_RUNTIME_CONFIG`

```json
{
  "FUEL_LIMIT": 1000000,
  "MAX_MEMORY": 524288000
}
```

