/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_WSV_QUERY_HPP
#define IROHA_POSTGRES_WSV_QUERY_HPP

#include "ametsuchi/wsv_query.hpp"

#include <soci/soci.h>
#include "interfaces/common_objects/common_objects_factory.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace ametsuchi {
    class PostgresWsvQuery : public WsvQuery {
     public:
      PostgresWsvQuery(
          soci::session &sql,
          std::shared_ptr<shared_model::interface::CommonObjectsFactory>
              factory,
          logger::LoggerPtr log);

      PostgresWsvQuery(
          std::unique_ptr<soci::session> sql,
          std::shared_ptr<shared_model::interface::CommonObjectsFactory>
              factory,
          logger::LoggerPtr log);

      boost::optional<std::vector<shared_model::interface::types::PubkeyType>>
      getSignatories(const shared_model::interface::types::AccountIdType
                         &account_id) override;

      boost::optional<
          std::vector<std::shared_ptr<shared_model::interface::Peer>>>
      getPeers() override;

     private:
      /**
       * Transforms result to optional
       * value -> optional<value>
       * error -> nullopt
       * @tparam T type of object inside
       * @param result BuilderResult
       * @return optional<T>
       */
      template <typename T>
      boost::optional<std::shared_ptr<T>> fromResult(
          shared_model::interface::CommonObjectsFactory::FactoryResult<
              std::unique_ptr<T>> &&result);

      /**
       * Executes given lambda of type F, catches exceptions if any, logs the
       * message, and returns an optional rowset<T>
       */
      template <typename T, typename F>
      auto execute(F &&f) -> boost::optional<soci::rowset<T>>;

      // TODO andrei 24.09.2018: IR-1718 Consistent soci::session fields in
      // storage classes
      std::unique_ptr<soci::session> psql_;
      soci::session &sql_;
      std::shared_ptr<shared_model::interface::CommonObjectsFactory> factory_;
      logger::LoggerPtr log_;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_WSV_QUERY_HPP
