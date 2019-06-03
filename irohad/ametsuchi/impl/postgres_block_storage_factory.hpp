/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_BLOCK_STORAGE_FACTORY_HPP
#define IROHA_POSTGRES_BLOCK_STORAGE_FACTORY_HPP

#include "ametsuchi/block_storage_factory.hpp"

#include "ametsuchi/impl/postgres_block_storage.hpp"
#include "ametsuchi/impl/soci_utils.hpp"
#include "backend/protobuf/proto_block_factory.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace ametsuchi {
    class PostgresBlockStorageFactory : public BlockStorageFactory {
     public:
      PostgresBlockStorageFactory(
          soci::session &sql,
          std::shared_ptr<PostgresBlockStorage::BlockTransportFactory>
              block_factory,
          logger::LoggerPtr log);
      std::unique_ptr<BlockStorage> create() override;

     private:
      soci::session &sql_;
      std::shared_ptr<PostgresBlockStorage::BlockTransportFactory>
          block_factory_;
      logger::LoggerPtr log_;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_BLOCK_STORAGE_FACTORY_HPP
