/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_block_query.hpp"

#include <boost/format.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/algorithm/for_each.hpp>

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

    std::vector<BlockQuery::wBlock> PostgresBlockQuery::getBlocks(
        shared_model::interface::types::HeightType height, uint32_t count) {
      shared_model::interface::types::HeightType last_id =
          block_store_.last_id();
      auto to = std::min(last_id, height + count - 1);
      std::vector<BlockQuery::wBlock> result;
      if (height > to or count == 0) {
        return result;
      }
      for (auto i = height; i <= to; i++) {
        auto block = getBlock(i);
        block.match(
            [&result](
                expected::Value<std::unique_ptr<shared_model::interface::Block>>
                    &v) { result.emplace_back(std::move(v.value)); },
            [this](const expected::Error<std::string> &e) {
              log_->error(e.error);
            });
      }
      return result;
    }

    std::vector<BlockQuery::wBlock> PostgresBlockQuery::getBlocksFrom(
        shared_model::interface::types::HeightType height) {
      return getBlocks(height, block_store_.last_id());
    }

    std::vector<BlockQuery::wBlock> PostgresBlockQuery::getTopBlocks(
        uint32_t count) {
      auto last_id = block_store_.last_id();
      count = std::min(count, last_id);
      return getBlocks(last_id - count + 1, count);
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

    uint32_t PostgresBlockQuery::getTopBlockHeight() {
      return block_store_.last_id();
    }

    expected::Result<BlockQuery::wBlock, std::string>
    PostgresBlockQuery::getTopBlock() {
      return getBlock(block_store_.last_id())
          .match(
              [](expected::Value<
                  std::unique_ptr<shared_model::interface::Block>> &v)
                  -> expected::Result<BlockQuery::wBlock, std::string> {
                return expected::makeValue<BlockQuery::wBlock>(
                    std::move(v.value));
              },
              [](expected::Error<std::string> &e)
                  -> expected::Result<BlockQuery::wBlock, std::string> {
                return expected::makeError(std::move(e.error));
              });
    }

    expected::Result<std::unique_ptr<shared_model::interface::Block>,
                     std::string>
    PostgresBlockQuery::getBlock(
        shared_model::interface::types::HeightType id) const {
      auto serialized_block = block_store_.get(id);
      if (not serialized_block) {
        auto error = boost::format("Failed to retrieve block with id %d") % id;
        return expected::makeError(error.str());
      }
      return converter_->deserialize(bytesToString(*serialized_block));
    }
  }  // namespace ametsuchi
}  // namespace iroha
