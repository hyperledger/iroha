/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_SETTING_QUERY_HPP
#define IROHA_POSTGRES_SETTING_QUERY_HPP

#include <soci/soci.h>

#include <boost/optional.hpp>

#include "ametsuchi/setting_query.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace ametsuchi {

    /**
     * Class which implements SettingQuery with a Postgres backend.
     */
    class PostgresSettingQuery : public SettingQuery {
     public:
      PostgresSettingQuery(std::shared_ptr<soci::session> &&sql,
                           logger::LoggerPtr log);

      expected::Result<
          std::unique_ptr<const shared_model::validation::Settings>,
          std::string>
      get() override;

     private:
      expected::Result<
          std::unique_ptr<const shared_model::validation::Settings>,
          std::string>
      update(std::unique_ptr<shared_model::validation::Settings> base);

      std::shared_ptr<soci::session> psql_;
      std::weak_ptr<soci::session> wsql_;

      logger::LoggerPtr log_;

      std::shared_ptr<soci::session> sql() const {
        return std::shared_ptr<soci::session>(wsql_);
      }
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_SETTING_QUERY_HPP
