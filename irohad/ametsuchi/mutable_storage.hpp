/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MUTABLE_STORAGE_HPP
#define IROHA_MUTABLE_STORAGE_HPP

#include <functional>

#include "ametsuchi/block_storage.hpp"
#include "ametsuchi/ledger_state.hpp"
#include "common/result.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    class Block;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  struct LedgerState;

  namespace ametsuchi {

    class WsvQuery;

    /**
     * Mutable storage is used apply blocks to the storage.
     * Allows to query the world state view, transactions, and blocks.
     */
    class MutableStorage {
     public:
      /**
       * Predicate type checking block
       * Function parameters:
       *  - Block - block to be checked
       *  - LedgerState - the state of ledger on which the block is applied
       */
      using MutableStoragePredicate = std::function<bool(
          std::shared_ptr<const shared_model::interface::Block>,
          const LedgerState &)>;

      struct CommitResult {
        std::shared_ptr<const LedgerState> ledger_state;
        std::unique_ptr<BlockStorage> block_storage;
      };

      /**
       * Applies block without additional validation function
       * @see apply(block, function)
       */
      virtual bool apply(
          std::shared_ptr<const shared_model::interface::Block> block) = 0;

      /**
       * Applies a block to current mutable state using logic specified in
       * function
       * @param block Block to be applied
       * @param predicate Checks whether block is applicable prior to applying
       * transactions
       * @return True if block was successfully applied, false otherwise.
       */
      virtual bool applyIf(
          std::shared_ptr<const shared_model::interface::Block> block,
          MutableStoragePredicate predicate) = 0;

      /// Apply the local changes made to this MutableStorage to block_storage
      /// and the global WSV.
      virtual expected::Result<MutableStorage::CommitResult, std::string>
      commit(BlockStorage &block_storage) && = 0;

      virtual ~MutableStorage() = default;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MUTABLE_STORAGE_HPP
