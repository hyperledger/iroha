/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_BLOCK_STORAGE_FACTORY_HPP
#define IROHA_POSTGRES_BLOCK_STORAGE_FACTORY_HPP

#include "ametsuchi/block_storage_factory.hpp"

#include "ametsuchi/impl/postgres_block_storage.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace ametsuchi {
    class PostgresBlockStorageFactory : public BlockStorageFactory {
     public:
      PostgresBlockStorageFactory(
          std::shared_ptr<PoolWrapper> pool_wrapper,
          std::shared_ptr<shared_model::proto::ProtoBlockFactory> block_factory,
          std::function<std::string()> table_name_provider,
          logger::LoggerPtr log);

      iroha::expected::Result<std::unique_ptr<BlockStorage>, std::string>
      create() override;

      static iroha::expected::Result<void, std::string> createTable(
          soci::session &sql, const std::string &table);

     private:
      std::shared_ptr<PoolWrapper> pool_wrapper_;
      std::shared_ptr<shared_model::proto::ProtoBlockFactory> block_factory_;
      std::function<std::string()> table_name_provider_;
      logger::LoggerPtr log_;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_BLOCK_STORAGE_FACTORY_HPP
