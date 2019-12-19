/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_block_storage.hpp"

#include "common/hexutils.hpp"
#include "logger/logger.hpp"

using namespace iroha::ametsuchi;

using shared_model::interface::types::HeightType;

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
  auto inserted_height = block->height();

  if (block_height_range_) {
    auto &current_top = block_height_range_->max;
    if (inserted_height != current_top + 1) {
      log_->warn(
          "Only blocks with sequential heights could be inserted. "
          "Last block height: {}, inserting: {}",
          current_top,
          inserted_height);
      return false;
    }
    ++current_top;
  } else {
    block_height_range_ = HeightRange{inserted_height, inserted_height};
  }

  auto b = block->blob().hex();

  soci::session sql(*pool_wrapper_->connection_pool_);
  soci::statement st = (sql.prepare << "INSERT INTO " << table_
                                    << " (height, block_data) VALUES(:height, "
                                       ":block_data)",
                        soci::use(inserted_height),
                        soci::use(b));
  log_->debug("insert block {}: {}", inserted_height, b);
  try {
    st.execute(true);
    return true;
  } catch (const std::exception &e) {
    log_->warn(
        "Failed to insert block {}, reason {}", inserted_height, e.what());
    return false;
  }
}

boost::optional<std::unique_ptr<shared_model::interface::Block>>
PostgresBlockStorage::fetch(
    shared_model::interface::types::HeightType height) const {
  soci::session sql(*pool_wrapper_->connection_pool_);
  using QueryTuple = boost::tuple<boost::optional<std::string>>;
  QueryTuple row;
  try {
    sql << "SELECT block_data FROM " << table_ << " WHERE height = :height",
        soci::use(height), soci::into(row);
  } catch (const std::exception &e) {
    log_->error("Failed to execute query: {}", e.what());
    return boost::none;
  }
  return rebind(viewQuery<QueryTuple>(row)) | [&, this](auto row) {
    return iroha::ametsuchi::apply(row, [&, this](auto &block_data) {
      log_->debug("fetched: {}", block_data);
      return iroha::hexstringToBytestring(block_data) |
          [&, this](auto byte_block) {
            iroha::protocol::Block_v1 b1;
            b1.ParseFromString(byte_block);
            iroha::protocol::Block block;
            *block.mutable_block_v1() = b1;
            return block_factory_->createBlock(std::move(block))
                .match(
                    [&](auto &&v) {
                      return boost::make_optional(
                          std::unique_ptr<shared_model::interface::Block>(
                              std::move(v.value)));
                    },
                    [&](const auto &e)
                        -> boost::optional<
                            std::unique_ptr<shared_model::interface::Block>> {
                      log_->error("Could not build block at height {}: {}",
                                  height,
                                  e.error);
                      return boost::none;
                    });
          };
    });
  };
}

size_t PostgresBlockStorage::size() const {
  return (block_height_range_ |
          [](auto range) {
            return boost::make_optional(range.max - range.min + 1);
          })
      .value_or(0);
}

void PostgresBlockStorage::clear() {
  soci::session sql(*pool_wrapper_->connection_pool_);
  soci::statement st = (sql.prepare << "TRUNCATE " << table_);
  try {
    st.execute(true);
    block_height_range_ = boost::none;
  } catch (const std::exception &e) {
    log_->warn("Failed to clear {} table, reason {}", table_, e.what());
  }
}

void PostgresBlockStorage::forEach(
    iroha::ametsuchi::BlockStorage::FunctionType function) const {
  block_height_range_ | [this, &function](auto range) {
    soci::session sql(*pool_wrapper_->connection_pool_);
    while (range.min <= range.max) {
      function(*this->fetch(range.min));
      ++range.min;
    }
  };
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
