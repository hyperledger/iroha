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
      PostgresWsvQuery(soci::session &sql, logger::LoggerPtr log);

      PostgresWsvQuery(std::unique_ptr<soci::session> sql,
                       logger::LoggerPtr log);

      boost::optional<std::vector<std::string>> getSignatories(
          const shared_model::interface::types::AccountIdType &account_id)
          override;

      boost::optional<
          std::vector<std::shared_ptr<shared_model::interface::Peer>>>
      getPeers(bool syncing_peers) override;

      iroha::expected::Result<size_t, std::string> countPeers(
          bool syncing_peers) override;
      iroha::expected::Result<size_t, std::string> countDomains() override;
      iroha::expected::Result<size_t, std::string> countTransactions() override;

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

      iroha::expected::Result<size_t, std::string> count(
          std::string_view, std::string_view column = "*");

      // TODO andrei 24.09.2018: IR-1718 Consistent soci::session fields in
      // storage classes
      std::unique_ptr<soci::session> psql_;
      soci::session &sql_;
      logger::LoggerPtr log_;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_WSV_QUERY_HPP
