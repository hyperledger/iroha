/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/rocksdb_block_storage_factory.hpp"

#include "ametsuchi/impl/rocksdb_block_storage.hpp"
#include "ametsuchi/impl/rocksdb_common.hpp"

using namespace iroha::ametsuchi;

RocksDbBlockStorageFactory::RocksDbBlockStorageFactory(
    std::shared_ptr<RocksDBContext> db_context,
    std::shared_ptr<shared_model::interface::BlockJsonConverter>
        json_block_converter,
    logger::LoggerManagerTreePtr log_manager)
    : db_context_(std::move(db_context)),
      json_block_converter_(std::move(json_block_converter)),
      log_manager_(std::move(log_manager)) {}

iroha::expected::Result<std::unique_ptr<BlockStorage>, std::string>
RocksDbBlockStorageFactory::create() {
  return std::make_unique<RocksDbBlockStorage>(
      db_context_,
      json_block_converter_,
      log_manager_->getChild("RocksDbBlockFactory")->getLogger());
}
