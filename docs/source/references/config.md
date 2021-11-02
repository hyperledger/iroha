# Iroha config description

Configuration of iroha is done via options in the following document. Here is defaults for whole config:

```json
{
  "PUBLIC_KEY": "ed0100",
  "PRIVATE_KEY": {
    "digest_function": "",
    "payload": ""
  },
  "KURA": {
    "INIT_MODE": "strict",
    "BLOCK_STORE_PATH": "./blocks",
    "BLOCKS_PER_STORAGE_FILE": 1000,
    "MAILBOX": 100
  },
  "SUMERAGI": {
    "PEER_ID": {
      "address": "",
      "public_key": "ed0100"
    },
    "BLOCK_TIME_MS": 1000,
    "TRUSTED_PEERS": [],
    "COMMIT_TIME_MS": 1000,
    "TX_RECEIPT_TIME_MS": 200,
    "N_TOPOLOGY_SHIFTS_BEFORE_RESHUFFLE": 1,
    "MAX_INSTRUCTION_NUMBER": 4096,
    "MAILBOX": 100
  },
  "TORII": {
    "P2P_ADDR": "127.0.0.1:1337",
    "API_URL": "127.0.0.1:8080",
    "MAX_TRANSACTION_SIZE": 32768,
    "MAX_SUMERAGI_MESSAGE_SIZE": 16384000,
    "MAX_INSTRUCTION_NUMBER": 4096
  },
  "BLOCK_SYNC": {
    "GOSSIP_PERIOD_MS": 10000,
    "BATCH_SIZE": 4,
    "MAILBOX": 100
  },
  "QUEUE": {
    "MAXIMUM_TRANSACTIONS_IN_BLOCK": 8192,
    "MAXIMUM_TRANSACTIONS_IN_QUEUE": 65536,
    "TRANSACTION_TIME_TO_LIVE_MS": 86400000,
    "FUTURE_THRESHOLD_MS": 1000
  },
  "LOGGER": {
    "MAX_LOG_LEVEL": "DEBUG",
    "TELEMETRY_CAPACITY": 1000,
    "COMPACT_MODE": false,
    "LOG_FILE_PATH": null
  },
  "GENESIS": {
    "ACCOUNT_PUBLIC_KEY": null,
    "ACCOUNT_PRIVATE_KEY": null,
    "WAIT_FOR_PEERS_RETRY_COUNT": 0,
    "WAIT_FOR_PEERS_RETRY_PERIOD_MS": 0
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
    }
  },
  "TELEMETRY": {
    "NAME": null,
    "URL": null,
    "FILE": null
  },
  "NETWORK": {
    "MAILBOX": 100
  }
}
```

## `block_sync`

`BlockSynchronizer` configuration.

Has type `BlockSyncConfiguration`. Can be configured via environment variable `IROHA_BLOCK_SYNC`

```json
{
  "BATCH_SIZE": 4,
  "GOSSIP_PERIOD_MS": 10000,
  "MAILBOX": 100
}
```

### `block_sync.batch_size`

The number of blocks, which can be send in one message.

Has type `u32`. Can be configured via environment variable `BLOCK_SYNC_BATCH_SIZE`

```json
4
```

### `block_sync.gossip_period_ms`

The time between peer sharing its latest block hash with other peers in milliseconds.

Has type `u64`. Can be configured via environment variable `BLOCK_SYNC_GOSSIP_PERIOD_MS`

```json
10000
```

### `block_sync.mailbox`

Mailbox size

Has type `usize`. Can be configured via environment variable `BLOCK_SYNC_MAILBOX`

```json
100
```

## `genesis`

Configuration for `GenesisBlock`.

Has type `GenesisConfiguration`. Can be configured via environment variable `IROHA_GENESIS`

```json
{
  "ACCOUNT_PRIVATE_KEY": null,
  "ACCOUNT_PUBLIC_KEY": null,
  "WAIT_FOR_PEERS_RETRY_COUNT": 0,
  "WAIT_FOR_PEERS_RETRY_PERIOD_MS": 0
}
```

### `genesis.account_private_key`

Genesis account private key, only needed on the peer that submits the genesis block.

Has type `Option<PrivateKey>`. Can be configured via environment variable `IROHA_GENESIS_ACCOUNT_PRIVATE_KEY`

```json
null
```

### `genesis.account_public_key`

Genesis account public key, should be supplied to all the peers.

Has type `Option<PublicKey>`. Can be configured via environment variable `IROHA_GENESIS_ACCOUNT_PUBLIC_KEY`

```json
null
```

### `genesis.wait_for_peers_retry_count`

Number of attempts to connect to peers, while waiting for them to submit genesis.

Has type `u64`. Can be configured via environment variable `IROHA_GENESIS_WAIT_FOR_PEERS_RETRY_COUNT`

```json
0
```

### `genesis.wait_for_peers_retry_period_ms`

Period in milliseconds in which to retry connecting to peers, while waiting for them to submit genesis.

Has type `u64`. Can be configured via environment variable `IROHA_GENESIS_WAIT_FOR_PEERS_RETRY_PERIOD_MS`

```json
0
```

## `kura`

`Kura` related configuration.

Has type `KuraConfiguration`. Can be configured via environment variable `IROHA_KURA`

```json
{
  "BLOCKS_PER_STORAGE_FILE": 1000,
  "BLOCK_STORE_PATH": "./blocks",
  "INIT_MODE": "strict",
  "MAILBOX": 100
}
```

### `kura.block_store_path`

Path to the existing block store folder or path to create new folder.

Has type `String`. Can be configured via environment variable `KURA_BLOCK_STORE_PATH`

```json
"./blocks"
```

### `kura.blocks_per_storage_file`

Maximum number of blocks to write into single storage file

Has type `NonZeroU64`. Can be configured via environment variable `KURA_BLOCKS_PER_STORAGE_FILE`

```json
1000
```

### `kura.init_mode`

Possible modes: `strict`, `fast`.

Has type `Mode`. Can be configured via environment variable `KURA_INIT_MODE`

```json
"strict"
```

### `kura.mailbox`

Default mailbox size

Has type `usize`. Can be configured via environment variable `KURA_MAILBOX`

```json
100
```

## `logger`

`Logger` configuration.

Has type `LoggerConfiguration`. Can be configured via environment variable `IROHA_LOGGER`

```json
{
  "COMPACT_MODE": false,
  "LOG_FILE_PATH": null,
  "MAX_LOG_LEVEL": "DEBUG",
  "TELEMETRY_CAPACITY": 1000
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

Has type `Option<PathBuf>`. Can be configured via environment variable `LOG_FILE_PATH`

```json
null
```

### `logger.max_log_level`

Maximum log level

Has type `LevelEnv`. Can be configured via environment variable `MAX_LOG_LEVEL`

```json
"DEBUG"
```

### `logger.telemetry_capacity`

Capacity (or batch size) for telemetry channel

Has type `usize`. Can be configured via environment variable `TELEMETRY_CAPACITY`

```json
1000
```

## `network`

Network configuration

Has type `NetworkConfiguration`. Can be configured via environment variable `IROHA_NETWORK`

```json
{
  "MAILBOX": 100
}
```

### `network.mailbox`

Actor mailbox size

Has type `usize`. Can be configured via environment variable `IROHA_NETWORK_MAILBOX`

```json
100
```

## `private_key`

Private key of this peer.

Has type `PrivateKey`. Can be configured via environment variable `IROHA_PRIVATE_KEY`

```json
{
  "digest_function": "",
  "payload": ""
}
```

## `public_key`

Public key of this peer.

Has type `PublicKey`. Can be configured via environment variable `IROHA_PUBLIC_KEY`

```json
"ed0100"
```

## `queue`

`Queue` configuration.

Has type `QueueConfiguration`. Can be configured via environment variable `IROHA_QUEUE`

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

The upper limit of the number of transactions waiting in this queue.

Has type `u32`. Can be configured via environment variable `QUEUE_MAXIMUM_TRANSACTIONS_IN_QUEUE`

```json
65536
```

### `queue.transaction_time_to_live_ms`

The transaction will be dropped after this time if it is still in a `Queue`.

Has type `u64`. Can be configured via environment variable `QUEUE_TRANSACTION_TIME_TO_LIVE_MS`

```json
86400000
```

## `sumeragi`

`Sumeragi` related configuration.

Has type `SumeragiConfiguration`. Can be configured via environment variable `IROHA_SUMERAGI`

```json
{
  "BLOCK_TIME_MS": 1000,
  "COMMIT_TIME_MS": 1000,
  "MAILBOX": 100,
  "MAX_INSTRUCTION_NUMBER": 4096,
  "N_TOPOLOGY_SHIFTS_BEFORE_RESHUFFLE": 1,
  "PEER_ID": {
    "address": "",
    "public_key": "ed0100"
  },
  "TRUSTED_PEERS": [],
  "TX_RECEIPT_TIME_MS": 200
}
```

### `sumeragi.block_time_ms`

Amount of time peer waits for the `CreatedBlock` message after getting a `TransactionReceipt`

Has type `u64`. Can be configured via environment variable `SUMERAGI_BLOCK_TIME_MS`

```json
1000
```

### `sumeragi.commit_time_ms`

Amount of time Peer waits for CommitMessage from the proxy tail.

Has type `u64`. Can be configured via environment variable `SUMERAGI_COMMIT_TIME_MS`

```json
1000
```

### `sumeragi.key_pair`

Key pair of private and public keys.

Has type `KeyPair`. Can be configured via environment variable `SUMERAGI_KEY_PAIR`

```json
{
  "private_key": {
    "digest_function": "",
    "payload": ""
  },
  "public_key": "ed0100"
}
```

### `sumeragi.mailbox`

Mailbox size

Has type `usize`. Can be configured via environment variable `SUMERAGI_MAILBOX`

```json
100
```

### `sumeragi.max_instruction_number`

Maximum instruction number per transaction

Has type `u64`. Can be configured via environment variable `SUMERAGI_MAX_INSTRUCTION_NUMBER`

```json
4096
```

### `sumeragi.n_topology_shifts_before_reshuffle`

After N view changes topology will change tactic from shifting by one, to reshuffle.

Has type `u64`. Can be configured via environment variable `SUMERAGI_N_TOPOLOGY_SHIFTS_BEFORE_RESHUFFLE`

```json
1
```

### `sumeragi.peer_id`

Current Peer Identification.

Has type `PeerId`. Can be configured via environment variable `SUMERAGI_PEER_ID`

```json
{
  "address": "",
  "public_key": "ed0100"
}
```

### `sumeragi.trusted_peers`

Optional list of predefined trusted peers.

Has type `TrustedPeers`. Can be configured via environment variable `SUMERAGI_TRUSTED_PEERS`

```json
[]
```

### `sumeragi.tx_receipt_time_ms`

Amount of time Peer waits for TxReceipt from the leader.

Has type `u64`. Can be configured via environment variable `SUMERAGI_TX_RECEIPT_TIME_MS`

```json
200
```

## `telemetry`

Configuration for telemetry

Has type `iroha_telemetry::Configuration`. Can be configured via environment variable `IROHA_TELEMETRY`

```json
{
  "FILE": null,
  "NAME": null,
  "URL": null
}
```

### `telemetry.file`

The filepath that to write dev-telemetry to

Has type `Option<PathBuf>`. Can be configured via environment variable `TELEMETRY_FILE`

```json
null
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

`Torii` related configuration.

Has type `ToriiConfiguration`. Can be configured via environment variable `IROHA_TORII`

```json
{
  "API_URL": "127.0.0.1:8080",
  "MAX_INSTRUCTION_NUMBER": 4096,
  "MAX_SUMERAGI_MESSAGE_SIZE": 16384000,
  "MAX_TRANSACTION_SIZE": 32768,
  "P2P_ADDR": "127.0.0.1:1337"
}
```

### `torii.api_url`

Torii URL for client API.

Has type `String`. Can be configured via environment variable `TORII_API_URL`

```json
"127.0.0.1:8080"
```

### `torii.max_instruction_number`

Maximum number of instruction per transaction. Used to prevent from DOS attacks.

Has type `u64`. Can be configured via environment variable `TORII_MAX_INSTRUCTION_NUMBER`

```json
4096
```

### `torii.max_sumeragi_message_size`

Maximum number of bytes in raw message. Used to prevent from DOS attacks.

Has type `usize`. Can be configured via environment variable `TORII_MAX_SUMERAGI_MESSAGE_SIZE`

```json
16384000
```

### `torii.max_transaction_size`

Maximum number of bytes in raw transaction. Used to prevent from DOS attacks.

Has type `usize`. Can be configured via environment variable `TORII_MAX_TRANSACTION_SIZE`

```json
32768
```

### `torii.p2p_addr`

Torii URL for p2p communication for consensus and block synchronization purposes.

Has type `String`. Can be configured via environment variable `TORII_P2P_ADDR`

```json
"127.0.0.1:1337"
```

## `wsv`

Configuration for [`WorldStateView`](crate::wsv::WorldStateView).

Has type `WorldStateViewConfiguration`. Can be configured via environment variable `IROHA_WSV`

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
  }
}
```

### `wsv.account_metadata_limits`

[`MetadataLimits`] of any account's metadata.

Has type `MetadataLimits`. Can be configured via environment variable `WSV_ACCOUNT_METADATA_LIMITS`

```json
{
  "max_entry_byte_size": 4096,
  "max_len": 1048576
}
```

### `wsv.asset_definition_metadata_limits`

[`MetadataLimits`] of any asset definition's metadata.

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

[`MetadataLimits`] of any domain's metadata.

Has type `MetadataLimits`. Can be configured via environment variable `WSV_DOMAIN_METADATA_LIMITS`

```json
{
  "max_entry_byte_size": 4096,
  "max_len": 1048576
}
```

### `wsv.ident_length_limits`

[`LengthLimits`]for the number of chars in identifiers that can be stored in the WSV.

Has type `LengthLimits`. Can be configured via environment variable `WSV_IDENT_LENGTH_LIMITS`

```json
{
  "max": 128,
  "min": 1
}
```

