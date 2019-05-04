/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_block_query.hpp"

#include <boost/format.hpp>
#include "ametsuchi/impl/soci_utils.hpp"
#include "common/byteutils.hpp"
#include "logger/logger.hpp"

namespace iroha {
  namespace ametsuchi {
    PostgresBlockQuery::PostgresBlockQuery(
        soci::session &sql,
        KeyValueStorage &file_store,
        std::shared_ptr<shared_model::interface::BlockJsonDeserializer>
            converter,
        logger::LoggerPtr log)
        : sql_(sql),
          block_store_(file_store),
          converter_(std::move(converter)),
          log_(std::move(log)) {}

    PostgresBlockQuery::PostgresBlockQuery(
        std::unique_ptr<soci::session> sql,
        KeyValueStorage &file_store,
        std::shared_ptr<shared_model::interface::BlockJsonDeserializer>
            converter,
        logger::LoggerPtr log)
        : psql_(std::move(sql)),
          sql_(*psql_),
          block_store_(file_store),
          converter_(std::move(converter)),
          log_(std::move(log)) {}

    BlockQuery::BlockResult PostgresBlockQuery::getBlock(
        shared_model::interface::types::HeightType height) {
      auto serialized_block = block_store_.get(height);
      if (not serialized_block) {
        auto error =
            boost::format("Failed to retrieve block with height %d") % height;
        return expected::makeError(error.str());
      }
      return converter_->deserialize(bytesToString(*serialized_block));
    }

    shared_model::interface::types::HeightType
    PostgresBlockQuery::getTopBlockHeight() {
      return block_store_.last_id();
    }

    boost::optional<TxCacheStatusType> PostgresBlockQuery::checkTxPresence(
        const shared_model::crypto::Hash &hash) {
      int res = -1;
      const auto &hash_str = hash.hex();

      try {
        sql_ << "SELECT status FROM tx_status_by_hash WHERE hash = :hash",
            soci::into(res), soci::use(hash_str);
      } catch (const std::exception &e) {
        log_->error("Failed to execute query: {}", e.what());
        return boost::none;
      }

      // res > 0 => Committed
      // res == 0 => Rejected
      // res < 0 => Missing
      if (res > 0) {
        return boost::make_optional<TxCacheStatusType>(
            tx_cache_status_responses::Committed{hash});
      } else if (res == 0) {
        return boost::make_optional<TxCacheStatusType>(
            tx_cache_status_responses::Rejected{hash});
      }
      return boost::make_optional<TxCacheStatusType>(
          tx_cache_status_responses::Missing{hash});
    }

  }  // namespace ametsuchi
}  // namespace iroha
