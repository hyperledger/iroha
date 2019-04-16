/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_FLAT_BLOCK_QUERY_HPP
#define IROHA_POSTGRES_FLAT_BLOCK_QUERY_HPP

#include "ametsuchi/block_query.hpp"

#include <soci/soci.h>
#include <boost/optional.hpp>
#include "ametsuchi/impl/flat_file/flat_file.hpp"
#include "interfaces/iroha_internal/block_json_deserializer.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace ametsuchi {

    class FlatFile;

    /**
     * Class which implements BlockQuery with a Postgres backend.
     */
    class PostgresBlockQuery : public BlockQuery {
     public:
      PostgresBlockQuery(
          soci::session &sql,
          KeyValueStorage &file_store,
          std::shared_ptr<shared_model::interface::BlockJsonDeserializer>
              converter,
          logger::LoggerPtr log);

      PostgresBlockQuery(
          std::unique_ptr<soci::session> sql,
          KeyValueStorage &file_store,
          std::shared_ptr<shared_model::interface::BlockJsonDeserializer>
              converter,
          logger::LoggerPtr log);

      std::vector<wBlock> getBlocks(
          shared_model::interface::types::HeightType height,
          uint32_t count) override;

      std::vector<wBlock> getBlocksFrom(
          shared_model::interface::types::HeightType height) override;

      std::vector<wBlock> getTopBlocks(uint32_t count) override;

      uint32_t getTopBlockHeight() override;

      boost::optional<TxCacheStatusType> checkTxPresence(
          const shared_model::crypto::Hash &hash) override;

      expected::Result<wBlock, std::string> getTopBlock() override;

     private:
      /**
       * Retrieve block with given id from block storage
       * @param id - height of a block to retrieve
       * @return block with given height
       */
      expected::Result<std::unique_ptr<shared_model::interface::Block>,
                       std::string>
      getBlock(shared_model::interface::types::HeightType id) const;

      std::unique_ptr<soci::session> psql_;
      soci::session &sql_;

      KeyValueStorage &block_store_;
      std::shared_ptr<shared_model::interface::BlockJsonDeserializer>
          converter_;

      logger::LoggerPtr log_;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_FLAT_BLOCK_QUERY_HPP
