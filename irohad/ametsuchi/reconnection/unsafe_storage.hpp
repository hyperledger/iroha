/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_UNSAFE_STORAGE_HPP
#define IROHA_UNSAFE_STORAGE_HPP

#include <vector>

#include <rxcpp/rx.hpp>
#include "ametsuchi/block_query_factory.hpp"
#include "ametsuchi/mutable_factory.hpp"
#include "ametsuchi/peer_query_factory.hpp"
#include "ametsuchi/query_executor_factory.hpp"
#include "ametsuchi/reconnection/return_wrapper.hpp"
#include "ametsuchi/temporary_factory.hpp"
#include "common/result.hpp"

namespace shared_model {
  namespace interface {
    class Block;
  }
}  // namespace shared_model

namespace iroha {

  namespace ametsuchi {

    class BlockQuery;
    class WsvQuery;

    /**
     * Storage interface, which allows queries on current committed state, and
     * creation of state which can be mutated with blocks and transactions.
     * Note: every call uses only one try to connect to data base. If the
     * connection lost method will return error option of ReturnTypeWrapper
     */
    class UnsafeStorage : public TemporaryFactory,
                          public MutableFactory,
                          public PeerQueryFactory,
                          public BlockQueryFactory,
                          public QueryExecutorFactory {
     public:
      virtual ReturnWrapperType<std::shared_ptr<WsvQuery>> getWsvQuery()
          const = 0;

      virtual ReturnWrapperType<std::shared_ptr<BlockQuery>> getBlockQuery()
          const = 0;

      /**
       * Raw insertion of blocks without validation
       * @param block - block for insertion
       * @return true if inserted
       */
      virtual ReturnWrapperType<bool> insertBlock(
          std::shared_ptr<const shared_model::interface::Block> block) = 0;

      /**
       * Raw insertion of blocks without validation
       * @param blocks - collection of blocks for insertion
       * @return true if inserted
       */
      virtual ReturnWrapperType<bool> insertBlocks(
          const std::vector<std::shared_ptr<shared_model::interface::Block>>
              &blocks) = 0;

      /**
       * method called when block is written to the storage
       * @return observable with the Block committed
       */
      virtual rxcpp::observable<
          std::shared_ptr<const shared_model::interface::Block>>
      on_commit() = 0;

      /**
       * Remove all records from the tables and remove all the blocks
       */
      virtual void reset() = 0;

      /**
       * Remove all information from ledger
       * Tables and the database will be removed too
       */
      virtual void dropStorage() = 0;

      virtual void freeConnections() = 0;

      virtual ~UnsafeStorage() = default;
    };

  }  // namespace ametsuchi

}  // namespace iroha

#endif  // IROHA_UNSAFE_STORAGE_HPP
