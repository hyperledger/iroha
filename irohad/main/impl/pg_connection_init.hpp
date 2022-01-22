/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PG_CONNECTION_INIT_HPP
#define IROHA_PG_CONNECTION_INIT_HPP

#include <soci/soci.h>

#include <soci/callbacks.h>
#include <soci/postgresql/soci-postgresql.h>
#include <boost/algorithm/string.hpp>
#include <boost/range/algorithm/replace_if.hpp>

#include "ametsuchi/impl/failover_callback_holder.hpp"
#include "ametsuchi/impl/postgres_command_executor.hpp"
#include "ametsuchi/impl/postgres_options.hpp"
#include "ametsuchi/reconnection_strategy.hpp"
#include "common/result.hpp"
#include "interfaces/permissions.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"
#include "main/startup_params.hpp"

namespace iroha {
  namespace ametsuchi {

    struct PoolWrapper;

    class PgConnectionInit {
     public:
      static expected::Result<std::shared_ptr<iroha::ametsuchi::PoolWrapper>,
                              std::string>
      init(StartupWsvDataPolicy startup_wsv_data_policy,
           iroha::ametsuchi::PostgresOptions const &pg_opt,
           logger::LoggerManagerTreePtr log_manager,
           bool skip_schema_check = false);

      static expected::Result<void, std::string> prepareWorkingDatabase(
          StartupWsvDataPolicy startup_wsv_data_policy,
          const PostgresOptions &options,
          bool skip_schema_check = false);

      static expected::Result<std::shared_ptr<PoolWrapper>, std::string>
      prepareConnectionPool(
          const ReconnectionStrategyFactory &reconnection_strategy_factory,
          const PostgresOptions &options,
          const int pool_size,
          logger::LoggerManagerTreePtr log_manager);

      static iroha::expected::Result<void, std::string> rollbackPrepared(
          soci::session &sql, const std::string &prepared_block_name);

      /*
       * Drop working database.
       * @return Error message if dropping has failed.
       */
      static expected::Result<void, std::string> dropWorkingDatabase(
          const PostgresOptions &options);

      /**
       * Removes all peers from WSV
       * @return error message if reset has failed
       */
      static expected::Result<void, std::string> resetPeers(soci::session &sql);
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_PG_CONNECTION_INIT_HPP
