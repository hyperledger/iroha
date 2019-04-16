/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BLOCK_QUERY_HPP
#define IROHA_BLOCK_QUERY_HPP

#include <boost/optional.hpp>
#include <rxcpp/rx.hpp>
#include "ametsuchi/tx_cache_response.hpp"
#include "common/result.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "interfaces/transaction.hpp"

namespace iroha {

  namespace ametsuchi {
    /**
     * Public interface for queries on blocks and transactions
     */
    class BlockQuery {
     protected:
      using wTransaction =
          std::shared_ptr<shared_model::interface::Transaction>;
      using wBlock = std::shared_ptr<shared_model::interface::Block>;

     public:
      virtual ~BlockQuery() = default;

      /**
       * Get given number of blocks starting with given height.
       * @param height - starting height
       * @param count - number of blocks to retrieve
       * @return observable of Model Block
       */
      virtual std::vector<wBlock> getBlocks(
          shared_model::interface::types::HeightType height,
          uint32_t count) = 0;

      /**
       * Get all blocks starting from given height.
       * @param from - starting height
       * @return observable of Model Block
       */
      virtual std::vector<wBlock> getBlocksFrom(
          shared_model::interface::types::HeightType height) = 0;

      /**
       * Get given number of blocks from top.
       * @param count - number of blocks to retrieve
       * @return observable of Model Block
       */
      virtual std::vector<wBlock> getTopBlocks(uint32_t count) = 0;

      /**
       * Get height of the top block.
       * @return height
       */
      virtual uint32_t getTopBlockHeight() = 0;

      /**
       * Synchronously checks whether transaction with given hash is present in
       * any block
       * @param hash - transaction's hash
       * @return TxCacheStatusType which returns status (Committed, Rejected or
       * Missing) of transaction if storage query was successful, boost::none
       * otherwise
       */
      virtual boost::optional<TxCacheStatusType> checkTxPresence(
          const shared_model::crypto::Hash &hash) = 0;

      /**
       * Get the top-most block
       * @return result of Model Block or error message
       */
      virtual expected::Result<wBlock, std::string> getTopBlock() = 0;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_BLOCK_QUERY_HPP
