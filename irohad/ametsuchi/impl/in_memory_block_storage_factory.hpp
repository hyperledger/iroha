/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_IN_MEMORY_BLOCK_STORAGE_FACTORY_HPP
#define IROHA_IN_MEMORY_BLOCK_STORAGE_FACTORY_HPP

#include "ametsuchi/block_storage_factory.hpp"

namespace iroha {
  namespace ametsuchi {

    class InMemoryBlockStorageFactory : public BlockStorageFactory {
     public:
      iroha::expected::Result<std::unique_ptr<BlockStorage>, std::string>
      create() override;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_IN_MEMORY_BLOCK_STORAGE_FACTORY_HPP
