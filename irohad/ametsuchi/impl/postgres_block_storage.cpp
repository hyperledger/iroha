/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_block_storage.hpp"

#include "common/hexutils.hpp"
#include "common/result.hpp"
#include "logger/logger.hpp"

using namespace iroha::ametsuchi;

using shared_model::interface::types::HeightType;

iroha::expected::Result<std::unique_ptr<PostgresBlockStorage>, std::string>
PostgresBlockStorage::create(
    std::shared_ptr<PoolWrapper> pool_wrapper,
    std::shared_ptr<BlockTransportFactory> block_factory,
    std::string table_name,
    bool drop_table_at_destruction,
    logger::LoggerPtr log) {
  soci::session sql(*pool_wrapper->connection_pool_);
  return queryBlockHeightsRange(sql, table_name) | [&](auto height_range) {
    return std::unique_ptr<PostgresBlockStorage>(
        new PostgresBlockStorage(std::move(pool_wrapper),
                                 std::move(block_factory),
                                 std::move(table_name),
                                 drop_table_at_destruction,
                                 height_range,
                                 std::move(log)));
  };
}

PostgresBlockStorage::PostgresBlockStorage(
    std::shared_ptr<PoolWrapper> pool_wrapper,
    std::shared_ptr<BlockTransportFactory> block_factory,
    std::string table_name,
    bool drop_table_at_destruction,
    boost::optional<HeightRange> height_range,
    logger::LoggerPtr log)
    : block_height_range_(std::move(height_range)),
      pool_wrapper_(std::move(pool_wrapper)),
      block_factory_(std::move(block_factory)),
      table_name_(std::move(table_name)),
      drop_table_at_destruction_(drop_table_at_destruction),
      log_(std::move(log)) {}

PostgresBlockStorage::~PostgresBlockStorage() {
  if (drop_table_at_destruction_) {
    dropTable();
  }
}

bool PostgresBlockStorage::insert(
    std::shared_ptr<const shared_model::interface::Block> block) {
  const auto inserted_height = block->height();

  if (block_height_range_) {
    const auto current_top = block_height_range_->max;
    if (inserted_height != current_top + 1) {
      log_->warn(
          "Only blocks with sequential heights could be inserted. "
          "Last block height: {}, inserting: {}",
          current_top,
          inserted_height);
      return false;
    }
  }

  auto b = block->blob().hex();

  soci::session sql(*pool_wrapper_->connection_pool_);
  soci::statement st = (sql.prepare << "INSERT INTO " << table_name_
                                    << " (height, block_data) VALUES(:height, "
                                       ":block_data)",
                        soci::use(inserted_height),
                        soci::use(b));
  log_->debug("insert block {}: {}", inserted_height, b);
  try {
    st.execute(true);

    if (block_height_range_) {
      assert(block_height_range_->max + 1 == inserted_height);
      ++block_height_range_->max;
    } else {
      block_height_range_ = HeightRange{inserted_height, inserted_height};
    }

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
    sql << "SELECT block_data FROM " << table_name_
        << " WHERE height = :height",
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

void PostgresBlockStorage::reload() {
  // no need to reload
}

void PostgresBlockStorage::clear() {
  soci::session sql(*pool_wrapper_->connection_pool_);
  soci::statement st = (sql.prepare << "TRUNCATE " << table_name_);
  try {
    st.execute(true);
    block_height_range_ = boost::none;
  } catch (const std::exception &e) {
    log_->warn("Failed to clear {} table, reason {}", table_name_, e.what());
  }
}

iroha::expected::Result<void, std::string> PostgresBlockStorage::forEach(
    iroha::ametsuchi::BlockStorage::FunctionType function) const {
  return block_height_range_ |
             [this,
              &function](auto range) -> expected::Result<void, std::string> {
    soci::session sql(*pool_wrapper_->connection_pool_);
    while (range.min <= range.max) {
      auto maybe_block = this->fetch(range.min);
      if (maybe_block) {
        auto maybe_error = function(std::move(maybe_block).value());
        if (iroha::expected::hasError(maybe_error)) {
          return maybe_error.assumeError();
        }
      } else {
        return fmt::format("Failed to fetch block {}", range.min);
      }
      ++range.min;
    }
    return {};
  };
}

iroha::expected::Result<boost::optional<PostgresBlockStorage::HeightRange>,
                        std::string>
PostgresBlockStorage::queryBlockHeightsRange(soci::session &sql,
                                             const std::string &table_name) {
  using QueryTuple =
      boost::tuple<boost::optional<size_t>, boost::optional<size_t>>;
  QueryTuple row;
  try {
    sql << "SELECT MIN(height), MAX(height) FROM " << table_name,
        soci::into(row);
  } catch (const std::exception &e) {
    return fmt::format("Failed to execute query: {}", e.what());
  }
  return rebind(viewQuery<QueryTuple>(row)) | [](auto row) {
    return iroha::ametsuchi::apply(row, [](size_t min, size_t max) {
      assert(max >= min);
      return boost::make_optional(HeightRange{min, max});
    });
  };
}

void PostgresBlockStorage::dropTable() {
  soci::session sql(*pool_wrapper_->connection_pool_);
  soci::statement st = (sql.prepare << "DROP TABLE IF EXISTS " << table_name_);
  try {
    st.execute(true);
  } catch (const std::exception &e) {
    log_->error("Failed to drop {} table, reason {}", table_name_, e.what());
  }
}
