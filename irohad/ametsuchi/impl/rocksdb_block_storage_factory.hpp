/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ROCKSDB_BLOCK_STORAGE_FACTORY_HPP
#define IROHA_ROCKSDB_BLOCK_STORAGE_FACTORY_HPP

#include "ametsuchi/block_storage_factory.hpp"

#include "interfaces/iroha_internal/block_json_converter.hpp"
#include "logger/logger_manager.hpp"

namespace iroha::ametsuchi {
  struct RocksDBContext;

  class RocksDbBlockStorageFactory : public BlockStorageFactory {
   public:
    RocksDbBlockStorageFactory(
        std::shared_ptr<RocksDBContext> db_context,
        std::shared_ptr<shared_model::interface::BlockJsonConverter>
            json_block_converter,
        logger::LoggerManagerTreePtr log_manager);

    iroha::expected::Result<std::unique_ptr<BlockStorage>, std::string> create()
        override;

   private:
    std::shared_ptr<RocksDBContext> db_context_;
    std::shared_ptr<shared_model::interface::BlockJsonConverter>
        json_block_converter_;
    logger::LoggerManagerTreePtr log_manager_;
  };

}  // namespace iroha::ametsuchi

#endif  // IROHA_ROCKSDB_BLOCK_STORAGE_FACTORY_HPP
