/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_block_storage.hpp"

#include "common/hexutils.hpp"
#include "logger/logger.hpp"

using namespace iroha::ametsuchi;

PostgresBlockStorage::PostgresBlockStorage(
    soci::session &sql,
    std::shared_ptr<BlockTransportFactory> block_factory,
    logger::LoggerPtr log)
    : sql_(sql),
      block_factory_(std::move(block_factory)),
      log_(std::move(log)) {}

bool PostgresBlockStorage::insert(
    std::shared_ptr<const shared_model::interface::Block> block) {
  shared_model::interface::types::HeightType last_block = 0;
  using T = boost::tuple<shared_model::interface::types::HeightType>;
  auto result_last_block = execute<T>(
      [&] { return (sql_.prepare << "SELECT MAX(height) FROM blocks"); });
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

  if (block->height() != last_block + 1) {
    log_->warn(
        "Only blocks with sequential heights could be inserted. Last block "
        "height: {}, inserting: {}",
        last_block,
        block->height());
    return false;
  }

  soci::statement st =
      (sql_.prepare << "INSERT INTO blocks(height, block_data) VALUES(:height, "
                       ":block_data)",
       soci::use(block->height()),
       soci::use(block->blob().hex()));
  log_->debug("insert: {}", block->blob().hex());
  try {
    st.execute(true);
    return true;
  } catch (const std::exception &e) {
    log_->warn(
        "Failed to insert block {}, reason {}", block->height(), e.what());
    return false;
  }
}

boost::optional<std::shared_ptr<const shared_model::interface::Block>>
PostgresBlockStorage::fetch(
    shared_model::interface::types::HeightType height) const {
  using T = boost::tuple<std::string>;
  auto result = execute<T>([&] {
    return (
        sql_.prepare << "SELECT block_data FROM blocks WHERE height = :height",
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

        iroha::protocol::Block_v1 block;
        block.ParseFromString(*byte_block);
        return block_factory_->build(std::move(block))
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
                              e.error.error);
                  return boost::none;
                });
      });
}

size_t PostgresBlockStorage::size() const {
  using T = boost::tuple<shared_model::interface::types::HeightType>;
  auto result = execute<T>(
      [&] { return (sql_.prepare << "SELECT COUNT(*) FROM blocks"); });
  return flatMapValue<
             boost::optional<shared_model::interface::types::HeightType>>(
             result, [](auto &count) { return boost::make_optional(count); })
      .value_or(0);
}

void PostgresBlockStorage::clear() {
  soci::statement st = sql_.prepare << "TRUNCATE blocks";
  try {
    st.execute(true);
  } catch (const std::exception &e) {
    log_->warn("Failed to clear blocks table, reason {}", e.what());
  }
}

void PostgresBlockStorage::forEach(
    iroha::ametsuchi::BlockStorage::FunctionType function) const {
  using T = boost::tuple<shared_model::interface::types::HeightType>;
  auto result_min = execute<T>(
      [&] { return (sql_.prepare << "SELECT MIN(height) FROM blocks"); });
  auto min =
      flatMapValue<boost::optional<shared_model::interface::types::HeightType>>(
          result_min, [](auto &min) { return boost::make_optional(min); })
          .value_or(0);
  auto result_max = execute<T>(
      [&] { return (sql_.prepare << "SELECT MAX(height) FROM blocks"); });
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
