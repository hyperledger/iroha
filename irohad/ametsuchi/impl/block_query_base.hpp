/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BLOCK_QUERY_BASE_HPP
#define IROHA_BLOCK_QUERY_BASE_HPP

#include <soci/soci.h>

#include "ametsuchi/block_query.hpp"
#include "ametsuchi/block_storage.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha::ametsuchi {

  /**
   * Class which implements BlockQuery.
   */
  class BlockQueryBase : public BlockQuery {
   public:
    BlockQueryBase(BlockStorage &block_storage, logger::LoggerPtr log);

    BlockResult getBlock(
        shared_model::interface::types::HeightType height) override;

    shared_model::interface::types::HeightType getTopBlockHeight() override;

    void reloadBlockstore() override;

    std::optional<TxCacheStatusType> checkTxPresence(
        const shared_model::crypto::Hash &hash) override;

    // res > 0 => Committed
    // res == 0 => Rejected
    // res < 0 => Missing
    virtual std::optional<int32_t> getTxStatus(
        const shared_model::crypto::Hash &hash) = 0;

   protected:
    BlockStorage &block_storage_;
    logger::LoggerPtr log_;
  };

}  // namespace iroha::ametsuchi

#endif  // IROHA_POSTGRES_BLOCK_QUERY_HPP
