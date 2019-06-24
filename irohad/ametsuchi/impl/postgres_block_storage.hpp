/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_BLOCK_STORAGE_HPP
#define IROHA_POSTGRES_BLOCK_STORAGE_HPP

#include "ametsuchi/block_storage.hpp"

#include "ametsuchi/impl/pool_wrapper.hpp"
#include "ametsuchi/impl/soci_utils.hpp"
#include "backend/protobuf/block.hpp"
#include "backend/protobuf/proto_block_factory.hpp"
#include "interfaces/iroha_internal/abstract_transport_factory.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace ametsuchi {
    class PostgresBlockStorage : public BlockStorage {
     public:
      using BlockTransportFactory = shared_model::proto::ProtoBlockFactory;

      PostgresBlockStorage(std::shared_ptr<PoolWrapper> pool_wrapper,
                           std::shared_ptr<BlockTransportFactory> block_factory,
                           std::string table,
                           logger::LoggerPtr log);

      bool insert(
          std::shared_ptr<const shared_model::interface::Block> block) override;

      boost::optional<std::shared_ptr<const shared_model::interface::Block>>
      fetch(shared_model::interface::types::HeightType height) const override;

      size_t size() const override;

      void clear() override;

      void forEach(FunctionType function) const override;

     private:
      /**
       * Executes given lambda of type F, catches exceptions if any, logs the
       * message, and returns an optional rowset<T>
       */
      template <typename T, typename F>
      boost::optional<soci::rowset<T>> execute(F &&f) const;

     protected:
      std::shared_ptr<PoolWrapper> pool_wrapper_;
      std::shared_ptr<BlockTransportFactory> block_factory_;
      std::string table_;
      logger::LoggerPtr log_;
    };

    class PostgresTemporaryBlockStorage : public PostgresBlockStorage {
     public:
      PostgresTemporaryBlockStorage(
          std::shared_ptr<PoolWrapper> pool_wrapper,
          std::shared_ptr<BlockTransportFactory> block_factory,
          std::string table,
          logger::LoggerPtr log);
      ~PostgresTemporaryBlockStorage() override;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_BLOCK_STORAGE_HPP
