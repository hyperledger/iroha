/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_BLOCK_QUERY_HPP
#define IROHA_POSTGRES_BLOCK_QUERY_HPP

#include <soci/soci.h>

#include "ametsuchi/block_query.hpp"
#include "ametsuchi/block_storage.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace ametsuchi {

    /**
     * Class which implements BlockQuery with a Postgres backend.
     */
    class PostgresBlockQuery : public BlockQuery {
     public:
      PostgresBlockQuery(std::weak_ptr<soci::session> &&sql,
                         BlockStorage &block_storage,
                         logger::LoggerPtr log);

      PostgresBlockQuery(std::shared_ptr<soci::session> &&sql,
                         BlockStorage &block_storage,
                         logger::LoggerPtr log);

      BlockResult getBlock(
          shared_model::interface::types::HeightType height) override;

      shared_model::interface::types::HeightType getTopBlockHeight() override;

      void reloadBlockstore() override;

      std::optional<TxCacheStatusType> checkTxPresence(
          const shared_model::crypto::Hash &hash) override;

     private:
      std::shared_ptr<soci::session> psql_;
      std::weak_ptr<soci::session> wsql_;
      BlockStorage &block_storage_;
      logger::LoggerPtr log_;

      std::shared_ptr<soci::session> sql() const {
        return std::shared_ptr<soci::session>(wsql_);
      }
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_BLOCK_QUERY_HPP
