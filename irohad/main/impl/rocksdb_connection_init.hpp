/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_RDB_CONNECTION_INIT_HPP
#define IROHA_RDB_CONNECTION_INIT_HPP

#include <boost/algorithm/string.hpp>
#include <boost/range/algorithm/replace_if.hpp>

#include "ametsuchi/impl/failover_callback_holder.hpp"
#include "ametsuchi/impl/rocksdb_command_executor.hpp"
#include "ametsuchi/impl/rocksdb_options.hpp"
#include "common/result.hpp"
#include "interfaces/permissions.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"
#include "main/startup_params.hpp"

namespace iroha::ametsuchi {

  struct RocksDBPort;
  struct RocksDBContext;
  class RocksDbCommon;

  class RdbConnectionInit {
   public:
    static expected::Result<std::shared_ptr<RocksDBPort>, std::string> init(
        StartupWsvDataPolicy startup_wsv_data_policy,
        iroha::ametsuchi::RocksDbOptions const &opt,
        logger::LoggerManagerTreePtr log_manager);

    static expected::Result<std::shared_ptr<RocksDBPort>, std::string>
    prepareWorkingDatabase(StartupWsvDataPolicy startup_wsv_data_policy,
                           const iroha::ametsuchi::RocksDbOptions &options);

    /*
     * Drop working database.
     * @return Error message if dropping has failed.
     */
    static expected::Result<void, std::string> dropWorkingDatabase(
        RocksDbCommon &common, const iroha::ametsuchi::RocksDbOptions &options);
  };

}  // namespace iroha::ametsuchi

#endif  // IROHA_PG_CONNECTION_INIT_HPP
