/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_block_storage_factory.hpp"

#include "common/result.hpp"
#include "logger/logger.hpp"

using namespace iroha::ametsuchi;

PostgresBlockStorageFactory::PostgresBlockStorageFactory(
    std::shared_ptr<PoolWrapper> pool_wrapper,
    std::shared_ptr<shared_model::proto::ProtoBlockFactory> block_factory,
    std::function<std::string()> table_name_provider,
    logger::LoggerPtr log)
    : pool_wrapper_(std::move(pool_wrapper)),
      block_factory_(std::move(block_factory)),
      table_name_provider_(std::move(table_name_provider)),
      log_(std::move(log)) {}

iroha::expected::Result<std::unique_ptr<BlockStorage>, std::string>
PostgresBlockStorageFactory::create() {
  soci::session sql(*pool_wrapper_->connection_pool_);
  auto table_name = table_name_provider_();
  return createTable(sql, table_name) | [this, &table_name] {
    return PostgresBlockStorage::create(
        pool_wrapper_, block_factory_, std::move(table_name), true, log_);
  };
}

iroha::expected::Result<void, std::string>
PostgresBlockStorageFactory::createTable(soci::session &sql,
                                         const std::string &table) {
  soci::statement st =
      (sql.prepare << "CREATE TABLE IF NOT EXISTS " << table
                   << "(height bigint PRIMARY KEY, block_data text not null)");
  try {
    st.execute(true);
    return {};
  } catch (const std::exception &e) {
    return expected::makeError("Unable to create block store: "
                               + std::string(e.what()));
  }
}
