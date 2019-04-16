/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MUTABLE_STORAGE_HPP
#define IROHA_MUTABLE_STORAGE_HPP

#include <functional>

#include <rxcpp/rx.hpp>
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    class Block;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace ametsuchi {

    class WsvQuery;
    class PeerQuery;

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
       *  - PeerQuery - interface for ledger peers list retrieval
       *  - HashType - hash of top block in blockchain
       */
      using MutableStoragePredicate = std::function<bool(
          std::shared_ptr<const shared_model::interface::Block>,
          // TODO 30.01.2019 lebdron: IR-265 Remove PeerQueryFactory
          PeerQuery &,
          const shared_model::interface::types::HashType &)>;

      /**
       * Applies block without additional validation function
       * @see apply(block, function)
       */
      virtual bool apply(
          std::shared_ptr<const shared_model::interface::Block> block) = 0;

      /**
       * Applies an observable of blocks to current mutable state using logic
       * specified in function
       * @param blocks Blocks to be applied
       * @param predicate Checks whether block is applicable prior to applying
       * transactions
       * @return True if blocks were successfully applied, false otherwise.
       */
      virtual bool apply(
          rxcpp::observable<std::shared_ptr<shared_model::interface::Block>>
              blocks,
          MutableStoragePredicate predicate) = 0;

      virtual ~MutableStorage() = default;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MUTABLE_STORAGE_HPP
