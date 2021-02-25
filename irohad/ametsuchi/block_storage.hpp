/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BLOCK_STORAGE_HPP
#define IROHA_BLOCK_STORAGE_HPP

#include <boost/optional/optional_fwd.hpp>
#include <cstdint>
#include <functional>
#include <memory>

#include "common/result_fwd.hpp"
#include "interfaces/iroha_internal/block.hpp"

namespace iroha {
  namespace ametsuchi {

    /**
     * Append-only block storage interface
     */
    class BlockStorage {
     public:
      /**
       * Append block, if the storage doesn't already contain the same block
       * @return true if inserted successfully, false otherwise
       */
      virtual bool insert(
          std::shared_ptr<const shared_model::interface::Block> block) = 0;

      /**
       * Get block with given height
       * @return block if exists, boost::none otherwise
       */
      virtual boost::optional<std::unique_ptr<shared_model::interface::Block>>
      fetch(shared_model::interface::types::HeightType height) const = 0;

      /**
       * Returns the size of the storage
       */
      virtual size_t size() const = 0;

      /**
       * Reloads blocks in case their were modified externally
       */
      virtual void reload() = 0;

      /**
       * Clears the contents of storage
       */
      virtual void clear() = 0;

      /// type of function which can be applied to the elements of the storage
      using FunctionType = std::function<expected::Result<void, std::string>(
          std::shared_ptr<const shared_model::interface::Block>)>;

      /**
       * Iterates through all the stored blocks
       */
      virtual expected::Result<void, std::string> forEach(
          FunctionType function) const = 0;

      virtual ~BlockStorage() = default;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_BLOCK_STORAGE_HPP
