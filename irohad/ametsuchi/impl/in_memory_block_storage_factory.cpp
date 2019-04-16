/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/in_memory_block_storage_factory.hpp"

#include "ametsuchi/impl/in_memory_block_storage.hpp"

using namespace iroha::ametsuchi;

std::unique_ptr<BlockStorage> InMemoryBlockStorageFactory::create() {
  return std::make_unique<InMemoryBlockStorage>();
}
