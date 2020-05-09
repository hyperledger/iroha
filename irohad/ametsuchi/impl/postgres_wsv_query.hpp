/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_WSV_QUERY_HPP
#define IROHA_POSTGRES_WSV_QUERY_HPP

#include "ametsuchi/wsv_query.hpp"

#include <soci/soci.h>
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace ametsuchi {
    class PostgresWsvQuery : public WsvQuery {
     public:
      PostgresWsvQuery(soci::session &sql, logger::LoggerPtr log);

      PostgresWsvQuery(std::unique_ptr<soci::session> sql,
                       logger::LoggerPtr log);

      std::optional<std::vector<std::string>> getSignatories(
          const shared_model::interface::types::AccountIdType &account_id)
          override;

      std::optional<
          std::vector<std::shared_ptr<shared_model::interface::Peer>>>
      getPeers() override;

      std::optional<std::shared_ptr<shared_model::interface::Peer>>
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
      auto execute(F &&f) -> std::optional<soci::rowset<T>>;

      // TODO andrei 24.09.2018: IR-1718 Consistent soci::session fields in
      // storage classes
      std::unique_ptr<soci::session> psql_;
      soci::session &sql_;
      logger::LoggerPtr log_;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_WSV_QUERY_HPP
