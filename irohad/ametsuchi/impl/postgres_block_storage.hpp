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
#include "common/result_fwd.hpp"
#include "interfaces/iroha_internal/abstract_transport_factory.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace ametsuchi {
    class PostgresBlockStorage : public BlockStorage {
     public:
      using BlockTransportFactory = shared_model::proto::ProtoBlockFactory;

      static iroha::expected::Result<std::unique_ptr<PostgresBlockStorage>,
                                     std::string>
      create(std::shared_ptr<PoolWrapper> pool_wrapper,
             std::shared_ptr<BlockTransportFactory> block_factory,
             std::string table_name,
             // IR-910 23.09.2020 @lebdron: refactor with separate classes
             bool drop_table_at_destruction,
             logger::LoggerPtr log);

      ~PostgresBlockStorage() override;

      bool insert(
          std::shared_ptr<const shared_model::interface::Block> block) override;

      boost::optional<std::unique_ptr<shared_model::interface::Block>> fetch(
          shared_model::interface::types::HeightType height) const override;

      size_t size() const override;

      void reload() override;

      void clear() override;

      expected::Result<void, std::string> forEach(
          FunctionType function) const override;

     private:
      struct HeightRange {
        shared_model::interface::types::HeightType min;
        shared_model::interface::types::HeightType max;
      };

      PostgresBlockStorage(std::shared_ptr<PoolWrapper> pool_wrapper,
                           std::shared_ptr<BlockTransportFactory> block_factory,
                           std::string table,
                           bool drop_table_at_destruction,
                           boost::optional<HeightRange> height_range,
                           logger::LoggerPtr log);

      static iroha::expected::Result<boost::optional<HeightRange>, std::string>
      queryBlockHeightsRange(soci::session &sql, const std::string &table_name);

      void dropTable();

      mutable boost::optional<HeightRange> block_height_range_;
      std::shared_ptr<PoolWrapper> pool_wrapper_;
      std::shared_ptr<BlockTransportFactory> block_factory_;
      std::string table_name_;
      bool drop_table_at_destruction_;
      logger::LoggerPtr log_;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_BLOCK_STORAGE_HPP
