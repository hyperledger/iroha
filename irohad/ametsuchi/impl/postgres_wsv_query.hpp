/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_WSV_QUERY_HPP
#define IROHA_POSTGRES_WSV_QUERY_HPP

#include <soci/soci.h>

#include "ametsuchi/wsv_query.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace ametsuchi {
    class PostgresWsvQuery : public WsvQuery {
     public:
      PostgresWsvQuery(std::weak_ptr<soci::session> const &wsql,
                       logger::LoggerPtr log)
          : wsql_(wsql), log_(std::move(log)) {}

      PostgresWsvQuery(std::shared_ptr<soci::session> &&ssql,
                       logger::LoggerPtr log)
          : shared_sql_(std::move(ssql)),
            wsql_(shared_sql_),
            log_(std::move(log)) {}

      boost::optional<std::vector<std::string>> getSignatories(
          const shared_model::interface::types::AccountIdType &account_id)
          override;

      boost::optional<
          std::vector<std::shared_ptr<shared_model::interface::Peer>>>
      getPeers() override;

      boost::optional<std::shared_ptr<shared_model::interface::Peer>>
      getPeerByPublicKey(shared_model::interface::types::PublicKeyHexStringView
                             public_key) override;

      iroha::expected::Result<iroha::TopBlockInfo, std::string>
      getTopBlockInfo() const override;

     private:
      /**
       * Executes given lambda of type F, catches exceptions if any, logs the
       * message, and returns an optional rowset<T>
       */
      template <typename T, typename F>
      auto execute(F &&f) -> boost::optional<soci::rowset<T>>;

      // TODO andrei 24.09.2018: IR-1718 Consistent soci::session fields in
      // storage classes
      std::shared_ptr<soci::session> shared_sql_;  // used in storage_impl

      std::weak_ptr<soci::session> wsql_;
      logger::LoggerPtr log_;

      std::shared_ptr<soci::session> sql() const {
        return std::shared_ptr<soci::session>(wsql_);
      }
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_WSV_QUERY_HPP
