#include "vendor/impl/rocksdb_block_storage.hpp"

#include "vendor/impl/rocksdb_block_storage_factory.hpp"

std::unique_ptr<iroha::ametsuchi::BlockStorage> RocksdbBlockStorageFactory::create() {
  return std::make_unique<RocksdbBlockStorage>();
}