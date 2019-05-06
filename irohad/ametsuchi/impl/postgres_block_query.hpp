/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_BLOCK_QUERY_HPP
#define IROHA_POSTGRES_BLOCK_QUERY_HPP

#include "ametsuchi/block_query.hpp"

#include <soci/soci.h>
#include <boost/optional.hpp>
#include "ametsuchi/key_value_storage.hpp"
#include "interfaces/iroha_internal/block_json_deserializer.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace ametsuchi {

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

      BlockResult getBlock(
          shared_model::interface::types::HeightType height) override;

      shared_model::interface::types::HeightType getTopBlockHeight() override;

      boost::optional<TxCacheStatusType> checkTxPresence(
          const shared_model::crypto::Hash &hash) override;

     private:
      std::unique_ptr<soci::session> psql_;
      soci::session &sql_;

      KeyValueStorage &block_store_;
      std::shared_ptr<shared_model::interface::BlockJsonDeserializer>
          converter_;

      logger::LoggerPtr log_;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_BLOCK_QUERY_HPP
