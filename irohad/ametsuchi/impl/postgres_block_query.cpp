/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_block_query.hpp"

#include <optional>

#include <boost/format.hpp>
#include "ametsuchi/impl/soci_reconnection_hacks.hpp"
#include "ametsuchi/impl/soci_utils.hpp"
#include "common/byteutils.hpp"
#include "common/cloneable.hpp"
#include "common/stubborn_caller.hpp"
#include "logger/logger.hpp"

namespace iroha {
  namespace ametsuchi {
    PostgresBlockQuery::PostgresBlockQuery(soci::session &sql,
                                           BlockStorage &block_storage,
                                           logger::LoggerPtr log)
        : sql_(sql), block_storage_(block_storage), log_(std::move(log)) {}

    PostgresBlockQuery::PostgresBlockQuery(std::unique_ptr<soci::session> sql,
                                           BlockStorage &block_storage,
                                           logger::LoggerPtr log)
        : psql_(std::move(sql)),
          sql_(*psql_),
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

    std::optional<TxCacheStatusType> PostgresBlockQuery::checkTxPresence(
        const shared_model::crypto::Hash &hash) {
      const auto &hash_str = hash.hex();

      return retryOnException<SessionRenewedException>(
                 log_,
                 [&]() -> std::optional<int> {
                   ReconnectionThrowerHack reconnection_checker{sql_};
                   try {
                     int res = -1;
                     sql_ << "SELECT status FROM tx_status_by_hash WHERE hash "
                             "= :hash",
                         soci::into(res), soci::use(hash_str);
                     return res;
                   } catch (const std::exception &e) {
                     reconnection_checker.throwIfReconnected(e.what());
                     log_->error("Failed to execute query: {}", e.what());
                     return std::nullopt;
                   }
                 })
          | [&](auto res) {
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
            };
    }

  }  // namespace ametsuchi
}  // namespace iroha
