/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/rocksdb_block_storage.hpp"

#include "ametsuchi/impl/rocksdb_block_storage_factory.hpp"

using namespace iroha::ametsuchi;

std::unique_ptr<BlockStorage> RocksdbBlockStorageFactory::create() {
  return std::make_unique<RocksdbBlockStorage>();
}