/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_block_storage.hpp"

#include "common/hexutils.hpp"
#include "logger/logger.hpp"

using namespace iroha::ametsuchi;

PostgresBlockStorage::PostgresBlockStorage(
    std::shared_ptr<PoolWrapper> pool_wrapper,
    std::shared_ptr<BlockTransportFactory> block_factory,
    std::string table,
    logger::LoggerPtr log)
    : pool_wrapper_(std::move(pool_wrapper)),
      block_factory_(std::move(block_factory)),
      table_(std::move(table)),
      log_(std::move(log)) {}

bool PostgresBlockStorage::insert(
    std::shared_ptr<const shared_model::interface::Block> block) {
  shared_model::interface::types::HeightType last_block = 0;
  using T = boost::tuple<shared_model::interface::types::HeightType>;
  soci::session sql(*pool_wrapper_->connection_pool_);
  auto result_last_block = execute<T>(
      [&] { return (sql.prepare << "SELECT MAX(height) FROM " << table_); });
  try {
    last_block =
        flatMapValue<
            boost::optional<shared_model::interface::types::HeightType>>(
            result_last_block,
            [](auto &last) { return boost::make_optional(last); })
            .value_or(0);
  } catch (const std::exception &e) {
    log_->warn("Problem with a query result parsing: {}", e.what());
  }

  if (last_block != 0) {
    if (block->height() != last_block + 1) {
      log_->warn(
          "Only blocks with sequential heights could be inserted. Last block "
          "height: {}, inserting: {}",
          last_block,
          block->height());
      return false;
    }
  }

  auto h = block->height();
  auto b = block->blob().hex();

  soci::statement st = (sql.prepare << "INSERT INTO " << table_
                                    << " (height, block_data) VALUES(:height, "
                                       ":block_data)",
                        soci::use(h),
                        soci::use(b));
  log_->debug("insert block {}: {}", h, b);
  try {
    st.execute(true);
    return true;
  } catch (const std::exception &e) {
    log_->warn("Failed to insert block {}, reason {}", h, e.what());
    return false;
  }
}

boost::optional<std::shared_ptr<const shared_model::interface::Block>>
PostgresBlockStorage::fetch(
    shared_model::interface::types::HeightType height) const {
  using T = boost::tuple<std::string>;
  soci::session sql(*pool_wrapper_->connection_pool_);
  auto result = execute<T>([&] {
    return (sql.prepare << "SELECT block_data FROM " << table_
                        << " WHERE height = :height",
            soci::use(height));
  });
  return flatMapValue<
      boost::optional<std::shared_ptr<const shared_model::interface::Block>>>(
      result, [&](auto &block_data) {
        log_->debug("fetched: {}", block_data);
        auto byte_block = iroha::hexstringToBytestring(block_data);
        if (not byte_block) {
          return boost::optional<
              std::shared_ptr<const shared_model::interface::Block>>(
              boost::none);
        }

        iroha::protocol::Block_v1 b1;
        b1.ParseFromString(*byte_block);
        iroha::protocol::Block block;
        *block.mutable_block_v1() = b1;
        return block_factory_->createBlock(std::move(block))
            .match(
                [&](auto &&v) {
                  return boost::make_optional(
                      std::shared_ptr<const shared_model::interface::Block>(
                          std::move(v.value)));
                },
                [&](const auto &e)
                    -> boost::optional<
                        std::shared_ptr<const shared_model::interface::Block>> {
                  log_->error("Could not build block at height {}: {}",
                              height,
                              e.error);
                  return boost::none;
                });
      });
}

size_t PostgresBlockStorage::size() const {
  using T = boost::tuple<shared_model::interface::types::HeightType>;
  soci::session sql(*pool_wrapper_->connection_pool_);
  auto result = execute<T>(
      [&] { return (sql.prepare << "SELECT COUNT(*) FROM " << table_); });
  return flatMapValue<
             boost::optional<shared_model::interface::types::HeightType>>(
             result, [](auto &count) { return boost::make_optional(count); })
      .value_or(0);
}

void PostgresBlockStorage::clear() {
  soci::session sql(*pool_wrapper_->connection_pool_);
  soci::statement st = (sql.prepare << "TRUNCATE " << table_);
  try {
    st.execute(true);
  } catch (const std::exception &e) {
    log_->warn("Failed to clear {} table, reason {}", table_, e.what());
  }
}

void PostgresBlockStorage::forEach(
    iroha::ametsuchi::BlockStorage::FunctionType function) const {
  using T = boost::tuple<shared_model::interface::types::HeightType>;
  soci::session sql(*pool_wrapper_->connection_pool_);
  // TODO: IR-577 Add caching if it will gain a performance boost
  // luckychess 29.06.2019
  auto result_min = execute<T>(
      [&] { return (sql.prepare << "SELECT MIN(height) FROM " << table_); });
  auto min =
      flatMapValue<boost::optional<shared_model::interface::types::HeightType>>(
          result_min, [](auto &min) { return boost::make_optional(min); })
          .value_or(0);
  auto result_max = execute<T>(
      [&] { return (sql.prepare << "SELECT MAX(height) FROM " << table_); });
  auto max =
      flatMapValue<boost::optional<shared_model::interface::types::HeightType>>(
          result_max, [](auto &max) { return boost::make_optional(max); })
          .value_or(0);
  while (min <= max) {
    function(*fetch(min));
    ++min;
  }
}

template <typename T, typename F>
boost::optional<soci::rowset<T>> PostgresBlockStorage::execute(F &&f) const {
  try {
    return soci::rowset<T>{std::forward<F>(f)()};
  } catch (const std::exception &e) {
    log_->error("Failed to execute query: {}", e.what());
    return boost::none;
  }
}

PostgresTemporaryBlockStorage::PostgresTemporaryBlockStorage(
    std::shared_ptr<PoolWrapper> pool_wrapper,
    std::shared_ptr<BlockTransportFactory> block_factory,
    std::string table,
    logger::LoggerPtr log)
    : PostgresBlockStorage(std::move(pool_wrapper),
                           std::move(block_factory),
                           std::move(table),
                           std::move(log)) {}

PostgresTemporaryBlockStorage::~PostgresTemporaryBlockStorage() {
  soci::session sql(*pool_wrapper_->connection_pool_);
  soci::statement st = (sql.prepare << "DROP TABLE IF EXISTS " << table_);
  try {
    st.execute(true);
  } catch (const std::exception &e) {
    log_->warn("Failed to drop {} table, reason {}", table_, e.what());
  }
}
