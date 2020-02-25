# iroha-kura

>> To reach the performance targets, Iroha v2 does not use a database to store data, but instead implements a custom storage solution, called Kura, that is specially designed for storing and validating blockchain data.

Up to date description can be found in [whitepaper](https://github.com/hyperledger/iroha/blob/iroha2/iroha_2_whitepaper.md#28-data-storage).

## Functionality

- [ ] Disk based store of validated blocks.
- [ ] In-memory store of a world-state-view.
- Two initialization modes:
  - [ ] `fastInit` - reads all transactions in all block keeping its order without any validation;
  - [ ] `strictInit` - `fastInit` with transactions and blocks validation (signatures correctness and business rules).
- [ ] Audit mechanism. //TODO: who starts audit and who process its result? Should we make a pause during audit?

## Use cases

### Blocks store

>> Kura takes as input blocks, which comprise multiple transactions. Kura is meant to take only blocks as input that have passed stateless and stateful validation, and have been finalized by consensus. For finalized blocks, Kura simply commits the block to the block storage on the disk and updates atomically the in-memory hashmaps that make up the key-value store that is the world-state-view. To optimize networking syncing, which works on 100 block chunks, chunks of 100 blocks each are stored in files in the block store.

### Read blocks copies

>> Kura also helps out with stateful validation, by providing functions that retrieve a copy of values affected in the world-state-view by the transactions in a block, returning the values as a copy. This then allows the stateful validation component to apply the transactions to update the world-state-view and confirm that no transactions in the block violate business rule invariants (e.g., no account shall have a negative balance of an asset after a transaction).

## Assumptions

### Internal storage

Kura stores information on the disk with always synchronized in-memory cache.
We use https://docs.rs/chashmap/2.2.2/chashmap/ - it's not lockless, but better then a default HashMap, still having the similar API.
