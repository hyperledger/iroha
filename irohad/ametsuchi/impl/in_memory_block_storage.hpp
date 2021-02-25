/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_IN_MEMORY_BLOCK_STORAGE_HPP
#define IROHA_IN_MEMORY_BLOCK_STORAGE_HPP

#include "ametsuchi/block_storage.hpp"

#include <map>

namespace iroha {
  namespace ametsuchi {

    /**
     * Ordered map implementation of block storage
     */
    class InMemoryBlockStorage : public BlockStorage {
     public:
      bool insert(
          std::shared_ptr<const shared_model::interface::Block> block) override;

      boost::optional<std::unique_ptr<shared_model::interface::Block>> fetch(
          shared_model::interface::types::HeightType height) const override;

      size_t size() const override;

      void reload() override;

      void clear() override;

      expected::Result<void, std::string> forEach(
          FunctionType function) const override;

     private:
      std::map<shared_model::interface::types::HeightType,
               std::shared_ptr<const shared_model::interface::Block>>
          block_store_;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_IN_MEMORY_BLOCK_STORAGE_HPP
