#ifndef ROCKSDB_BLOCK_STORAGE_FACTORY_HPP
#define ROCKSDB_BLOCK_STORAGE_FACTORY_HPP

#include "ametsuchi/block_storage_factory.hpp"

   class RocksdbBlockStorageFactory : public iroha::ametsuchi::BlockStorageFactory {
     public:
      std::unique_ptr<iroha::ametsuchi::BlockStorage> create() override;
    };

#endif  // ROCKSDB_BLOCK_STORAGE_FACTORY_HPP
