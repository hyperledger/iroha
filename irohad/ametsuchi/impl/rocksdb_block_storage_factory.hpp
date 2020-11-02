/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ROCKSDB_BLOCK_STORAGE_FACTORY_HPP
#define ROCKSDB_BLOCK_STORAGE_FACTORY_HPP

#include "ametsuchi/block_storage_factory.hpp"

namespace iroha {
  namespace ametsuchi {
   class RocksdbBlockStorageFactory : public BlockStorageFactory {
     public:
      std::unique_ptr<BlockStorage> create() override;
    };
}  // namespace ametsuchi
}  // namespace iroha

#endif  // ROCKSDB_BLOCK_STORAGE_FACTORY_HPP
