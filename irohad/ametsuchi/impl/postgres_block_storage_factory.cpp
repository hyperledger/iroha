/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_block_storage_factory.hpp"

using namespace iroha::ametsuchi;

PostgresBlockStorageFactory::PostgresBlockStorageFactory(
    soci::session &sql,
    std::shared_ptr<PostgresBlockStorage::BlockTransportFactory> block_factory,
    logger::LoggerPtr log)
    : sql_(sql),
      block_factory_(std::move(block_factory)),
      log_(std::move(log)) {}

std::unique_ptr<BlockStorage> PostgresBlockStorageFactory::create() {
  return std::make_unique<PostgresBlockStorage>(
      sql_, std::move(block_factory_), std::move(log_));
}
