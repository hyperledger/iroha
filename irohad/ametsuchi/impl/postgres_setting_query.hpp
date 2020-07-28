/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_SETTING_QUERY_HPP
#define IROHA_POSTGRES_SETTING_QUERY_HPP

#include "ametsuchi/setting_query.hpp"

#include <soci/soci.h>
#include <boost/optional.hpp>
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace ametsuchi {

    /**
     * Class which implements SettingQuery with a Postgres backend.
     */
    class PostgresSettingQuery : public SettingQuery {
     public:
      PostgresSettingQuery(std::unique_ptr<soci::session> sql,
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

      std::unique_ptr<soci::session> psql_;
      soci::session &sql_;

      logger::LoggerPtr log_;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_SETTING_QUERY_HPP
