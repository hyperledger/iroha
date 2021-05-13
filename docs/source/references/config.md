# Iroha config description

Configuration of iroha is done via options in the following document. Here is defaults for whole config:

```json
{
  "PUBLIC_KEY": "ed0100",
  "PRIVATE_KEY": {
    "digest_function": "",
    "payload": ""
  },
  "KURA_CONFIGURATION": {
    "KURA_INIT_MODE": "strict",
    "KURA_BLOCK_STORE_PATH": "./blocks"
  },
  "SUMERAGI_CONFIGURATION": {
    "PEER_ID": {
      "address": "",
      "public_key": "ed0100"
    },
    "BLOCK_TIME_MS": 1000,
    "TRUSTED_PEERS": [],
    "MAX_FAULTY_PEERS": 0,
    "COMMIT_TIME_MS": 1000,
    "TX_RECEIPT_TIME_MS": 200,
    "N_TOPOLOGY_SHIFTS_BEFORE_RESHUFFLE": 1,
    "MAX_INSTRUCTION_NUMBER": 4096
  },
  "TORII_CONFIGURATION": {
    "TORII_P2P_URL": "127.0.0.1:1337",
    "TORII_API_URL": "127.0.0.1:8080",
    "TORII_MAX_TRANSACTION_SIZE": 32768,
    "TORII_MAX_SUMERAGI_MESSAGE_SIZE": 16384000,
    "TORII_MAX_INSTRUCTION_NUMBER": 4096
  },
  "BLOCK_SYNC_CONFIGURATION": {
    "GOSSIP_PERIOD_MS": 10000,
    "BATCH_SIZE": 4
  },
  "QUEUE_CONFIGURATION": {
    "MAXIMUM_TRANSACTIONS_IN_BLOCK": 8192,
    "MAXIMUM_TRANSACTIONS_IN_QUEUE": 65536,
    "TRANSACTION_TIME_TO_LIVE_MS": 86400000
  },
  "LOGGER_CONFIGURATION": {
    "MAX_LOG_LEVEL": "DEBUG",
    "TELEMETRY_CAPACITY": 1000,
    "COMPACT_MODE": false
  },
  "GENESIS_CONFIGURATION": {
    "GENESIS_ACCOUNT_PUBLIC_KEY": "ed0100",
    "GENESIS_ACCOUNT_PRIVATE_KEY": null,
    "GENESIS_BLOCK_PATH": null,
    "WAIT_FOR_PEERS_RETRY_COUNT": 0,
    "WAIT_FOR_PEERS_RETRY_PERIOD_MS": 0
  },
  "WSV_CONFIGURATION": {
    "ASSET_METADATA_LIMITS": {
      "max_len": 1048576,
      "max_entry_byte_size": 4096
    },
    "ACCOUNT_METADATA_LIMITS": {
      "max_len": 1048576,
      "max_entry_byte_size": 4096
    },
    "LENGTH_LIMITS": {
      "min": 1,
      "max": 128
    }
  },
  "TELEMETRY": {
    "telemetry_file": null
  }
}
```

## `block_sync_configuration`

`BlockSynchronizer` configuration.

Has type `BlockSyncConfiguration`. Can be configured via environment variable `IROHA_BLOCK_SYNC_CONFIGURATION`

```json
{
  "BATCH_SIZE": 4,
  "GOSSIP_PERIOD_MS": 10000
}
```

### `block_sync_configuration.batch_size`

The number of blocks, which can be send in one message.

Has type `u64`. Can be configured via environment variable `BLOCK_SYNC_BATCH_SIZE`

```json
4
```

### `block_sync_configuration.gossip_period_ms`

The time between peer sharing its latest block hash with other peers in milliseconds.

Has type `u64`. Can be configured via environment variable `BLOCK_SYNC_GOSSIP_PERIOD_MS`

```json
10000
```

## `genesis_configuration`

Configuration for `GenesisBlock`.

Has type `GenesisConfiguration`. Can be configured via environment variable `IROHA_GENESIS_CONFIGURATION`

```json
{
  "GENESIS_ACCOUNT_PRIVATE_KEY": null,
  "GENESIS_ACCOUNT_PUBLIC_KEY": "ed0100",
  "GENESIS_BLOCK_PATH": null,
  "WAIT_FOR_PEERS_RETRY_COUNT": 0,
  "WAIT_FOR_PEERS_RETRY_PERIOD_MS": 0
}
```

### `genesis_configuration.genesis_account_private_key`

Genesis account private key, only needed on the peer that submits the genesis block.

Has type `Option<PrivateKey>`. Can be configured via environment variable `IROHA_GENESIS_ACCOUNT_PRIVATE_KEY`

```json
null
```

### `genesis_configuration.genesis_account_public_key`

Genesis account public key, should be supplied to all the peers.

Has type `PublicKey`. Can be configured via environment variable `IROHA_GENESIS_ACCOUNT_PUBLIC_KEY`

```json
"ed0100"
```

### `genesis_configuration.genesis_block_path`

Genesis block path. Can be `None` if this peer does not submit the genesis block.

Has type `Option<String>`. Can be configured via environment variable `IROHA_GENESIS_BLOCK_PATH`

```json
null
```

### `genesis_configuration.wait_for_peers_retry_count`

Number of attempts to connect to peers, while waiting for them to submit genesis.

Has type `u64`. Can be configured via environment variable `IROHA_WAIT_FOR_PEERS_RETRY_COUNT`

```json
0
```

### `genesis_configuration.wait_for_peers_retry_period_ms`

Period in milliseconds in which to retry connecting to peers, while waiting for them to submit genesis.

Has type `u64`. Can be configured via environment variable `IROHA_WAIT_FOR_PEERS_RETRY_PERIOD_MS`

```json
0
```

## `kura_configuration`

`Kura` related configuration.

Has type `KuraConfiguration`. Can be configured via environment variable `IROHA_KURA_CONFIGURATION`

```json
{
  "KURA_BLOCK_STORE_PATH": "./blocks",
  "KURA_INIT_MODE": "strict"
}
```

### `kura_configuration.kura_block_store_path`

Path to the existing block store folder or path to create new folder.

Has type `String`. Can be configured via environment variable `KURA_BLOCK_STORE_PATH`

```json
"./blocks"
```

### `kura_configuration.kura_init_mode`

Possible modes: `strict`, `fast`.

Has type `Mode`. Can be configured via environment variable `KURA_INIT_MODE`

```json
"strict"
```

## `logger_configuration`

`Logger` configuration.

Has type `LoggerConfiguration`. Can be configured via environment variable `IROHA_LOGGER_CONFIGURATION`

```json
{
  "COMPACT_MODE": false,
  "MAX_LOG_LEVEL": "DEBUG",
  "TELEMETRY_CAPACITY": 1000
}
```

### `logger_configuration.compact_mode`

Compact mode (no spans from telemetry)

Has type `bool`. Can be configured via environment variable `COMPACT_MODE`

```json
false
```

### `logger_configuration.max_log_level`

Maximum log level

Has type `LevelEnv`. Can be configured via environment variable `MAX_LOG_LEVEL`

```json
"DEBUG"
```

### `logger_configuration.telemetry_capacity`

Capacity (or batch size) for telemetry channel

Has type `usize`. Can be configured via environment variable `TELEMETRY_CAPACITY`

```json
1000
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

## `queue_configuration`

`Queue` configuration.

Has type `QueueConfiguration`. Can be configured via environment variable `IROHA_QUEUE_CONFIGURATION`

```json
{
  "MAXIMUM_TRANSACTIONS_IN_BLOCK": 8192,
  "MAXIMUM_TRANSACTIONS_IN_QUEUE": 65536,
  "TRANSACTION_TIME_TO_LIVE_MS": 86400000
}
```

### `queue_configuration.maximum_transactions_in_block`

The upper limit of the number of transactions per block.

Has type `u32`. Can be configured via environment variable `QUEUE_MAXIMUM_TRANSACTIONS_IN_BLOCK`

```json
8192
```

### `queue_configuration.maximum_transactions_in_queue`

The upper limit of the number of transactions waiting in this queue.

Has type `u32`. Can be configured via environment variable `QUEUE_MAXIMUM_TRANSACTIONS_IN_QUEUE`

```json
65536
```

### `queue_configuration.transaction_time_to_live_ms`

The transaction will be dropped after this time if it is still in a `Queue`.

Has type `u64`. Can be configured via environment variable `QUEUE_TRANSACTION_TIME_TO_LIVE_MS`

```json
86400000
```

## `sumeragi_configuration`

`Sumeragi` related configuration.

Has type `SumeragiConfiguration`. Can be configured via environment variable `IROHA_SUMERAGI_CONFIGURATION`

```json
{
  "BLOCK_TIME_MS": 1000,
  "COMMIT_TIME_MS": 1000,
  "MAX_FAULTY_PEERS": 0,
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

### `sumeragi_configuration.block_time_ms`

Amount of time peer waits for the `CreatedBlock` message after getting a `TransactionReceipt`

Has type `u64`. Can be configured via environment variable `SUMERAGI_BLOCK_TIME_MS`

```json
1000
```

### `sumeragi_configuration.commit_time_ms`

Amount of time Peer waits for CommitMessage from the proxy tail.

Has type `u64`. Can be configured via environment variable `SUMERAGI_COMMIT_TIME_MS`

```json
1000
```

### `sumeragi_configuration.key_pair`

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

### `sumeragi_configuration.max_faulty_peers`

Maximum amount of peers to fail and do not compromise the consensus.

Has type `u32`. Can be configured via environment variable `SUMERAGI_MAX_FAULTY_PEERS`

```json
0
```

### `sumeragi_configuration.max_instruction_number`

Maximum instruction number per transaction

Has type `usize`. Can be configured via environment variable `SUMERAGI_MAX_INSTRUCTION_NUMBER`

```json
4096
```

### `sumeragi_configuration.n_topology_shifts_before_reshuffle`

After N view changes topology will change tactic from shifting by one, to reshuffle.

Has type `u32`. Can be configured via environment variable `SUMERAGI_N_TOPOLOGY_SHIFTS_BEFORE_RESHUFFLE`

```json
1
```

### `sumeragi_configuration.peer_id`

Current Peer Identification.

Has type `PeerId`. Can be configured via environment variable `SUMERAGI_PEER_ID`

```json
{
  "address": "",
  "public_key": "ed0100"
}
```

### `sumeragi_configuration.trusted_peers`

Optional list of predefined trusted peers.

Has type `TrustedPeers`. Can be configured via environment variable `SUMERAGI_TRUSTED_PEERS`

```json
[]
```

### `sumeragi_configuration.tx_receipt_time_ms`

Amount of time Peer waits for TxReceipt from the leader.

Has type `u64`. Can be configured via environment variable `SUMERAGI_TX_RECEIPT_TIME_MS`

```json
200
```

## `telemetry`

Configuration for telemetry

Has type `telemetry::Configuration`. Can be configured via environment variable `IROHA_TELEMETRY`

```json
{
  "telemetry_file": null
}
```

### `telemetry.telemetry_file`

Has type `Option<PathBuf>`. Can be configured via environment variable `TELEMETRY_FILE`

```json
null
```

## `torii_configuration`

`Torii` related configuration.

Has type `ToriiConfiguration`. Can be configured via environment variable `IROHA_TORII_CONFIGURATION`

```json
{
  "TORII_API_URL": "127.0.0.1:8080",
  "TORII_MAX_INSTRUCTION_NUMBER": 4096,
  "TORII_MAX_SUMERAGI_MESSAGE_SIZE": 16384000,
  "TORII_MAX_TRANSACTION_SIZE": 32768,
  "TORII_P2P_URL": "127.0.0.1:1337"
}
```

### `torii_configuration.torii_api_url`

Torii URL for client API.

Has type `String`. Can be configured via environment variable `TORII_API_URL`

```json
"127.0.0.1:8080"
```

### `torii_configuration.torii_max_instruction_number`

Maximum number of instruction per transaction. Used to prevent from DOS attacks.

Has type `usize`. Can be configured via environment variable `TORII_MAX_INSTRUCTION_NUMBER`

```json
4096
```

### `torii_configuration.torii_max_sumeragi_message_size`

Maximum number of bytes in raw message. Used to prevent from DOS attacks.

Has type `usize`. Can be configured via environment variable `TORII_MAX_SUMERAGI_MESSAGE_SIZE`

```json
16384000
```

### `torii_configuration.torii_max_transaction_size`

Maximum number of bytes in raw transaction. Used to prevent from DOS attacks.

Has type `usize`. Can be configured via environment variable `TORII_MAX_TRANSACTION_SIZE`

```json
32768
```

### `torii_configuration.torii_p2p_url`

Torii URL for p2p communication for consensus and block synchronization purposes.

Has type `String`. Can be configured via environment variable `TORII_P2P_URL`

```json
"127.0.0.1:1337"
```

## `wsv_configuration`

Configuration for [`WorldStateView`](crate::wsv::WorldStateView).

Has type `WorldStateViewConfiguration`. Can be configured via environment variable `IROHA_WSV_CONFIGURATION`

```json
{
  "ACCOUNT_METADATA_LIMITS": {
    "max_entry_byte_size": 4096,
    "max_len": 1048576
  },
  "ASSET_METADATA_LIMITS": {
    "max_entry_byte_size": 4096,
    "max_len": 1048576
  },
  "LENGTH_LIMITS": {
    "max": 128,
    "min": 1
  }
}
```

### `wsv_configuration.account_metadata_limits`

[`MetadataLimits`] of any account's metadata.

Has type `MetadataLimits`. Can be configured via environment variable `WSV_ACCOUNT_METADATA_LIMITS`

```json
{
  "max_entry_byte_size": 4096,
  "max_len": 1048576
}
```

### `wsv_configuration.asset_metadata_limits`

[`MetadataLimits`] for every asset with store.

Has type `MetadataLimits`. Can be configured via environment variable `WSV_ASSET_METADATA_LIMITS`

```json
{
  "max_entry_byte_size": 4096,
  "max_len": 1048576
}
```

### `wsv_configuration.length_limits`

[`LengthLimits`] of identifiers in bytes that can be stored in the WSV.

Has type `LengthLimits`. Can be configured via environment variable `WSV_LENGTH_LIMITS`

```json
{
  "max": 128,
  "min": 1
}
```

