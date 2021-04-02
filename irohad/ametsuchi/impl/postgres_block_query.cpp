/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_block_query.hpp"

#include <boost/format.hpp>

#include "ametsuchi/impl/soci_utils.hpp"
#include "common/byteutils.hpp"
#include "common/cloneable.hpp"
#include "logger/logger.hpp"

namespace iroha {
  namespace ametsuchi {
    PostgresBlockQuery::PostgresBlockQuery(std::weak_ptr<soci::session> &&sql,
                                           BlockStorage &block_storage,
                                           logger::LoggerPtr log)
        : wsql_(std::move(sql)),
          block_storage_(block_storage),
          log_(std::move(log)) {}

    PostgresBlockQuery::PostgresBlockQuery(std::shared_ptr<soci::session> &&sql,
                                           BlockStorage &block_storage,
                                           logger::LoggerPtr log)
        : psql_(std::move(sql)),
          wsql_(psql_),
          block_storage_(block_storage),
          log_(std::move(log)) {}

    BlockQuery::BlockResult PostgresBlockQuery::getBlock(
        shared_model::interface::types::HeightType height) {
      auto block = block_storage_.fetch(height);
      if (not block) {
        auto error =
            boost::format("Failed to retrieve block with height %d") % height;
        return expected::makeError(
            GetBlockError{GetBlockError::Code::kNoBlock, error.str()});
      }
      return std::move(*block);
    }

    shared_model::interface::types::HeightType
    PostgresBlockQuery::getTopBlockHeight() {
      return block_storage_.size();
    }

    void PostgresBlockQuery::reloadBlockstore() {
      block_storage_.reload();
    }

    std::optional<TxCacheStatusType> PostgresBlockQuery::checkTxPresence(
        const shared_model::crypto::Hash &hash) {
      int res = -1;
      const auto &hash_str = hash.hex();

      try {
        *sql() << "SELECT status FROM tx_status_by_hash WHERE hash = :hash",
            soci::into(res), soci::use(hash_str);
      } catch (const std::exception &e) {
        log_->error("Failed to execute query: {}", e.what());
        return std::nullopt;
      }

      // res > 0 => Committed
      // res == 0 => Rejected
      // res < 0 => Missing
      if (res > 0) {
        return std::make_optional<TxCacheStatusType>(
            tx_cache_status_responses::Committed{hash});
      } else if (res == 0) {
        return std::make_optional<TxCacheStatusType>(
            tx_cache_status_responses::Rejected{hash});
      }
      return std::make_optional<TxCacheStatusType>(
          tx_cache_status_responses::Missing{hash});
    }

  }  // namespace ametsuchi
}  // namespace iroha
