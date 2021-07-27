/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ROCKSDB_SETTING_QUERY_HPP
#define IROHA_ROCKSDB_SETTING_QUERY_HPP

#include "ametsuchi/setting_query.hpp"

#include "logger/logger_fwd.hpp"

namespace iroha::ametsuchi {

  struct RocksDBContext;

  /**
   * Class which implements SettingQuery with a RocksDB backend.
   */
  class RocksDbSettingQuery : public SettingQuery {
   public:
    RocksDbSettingQuery(std::shared_ptr<RocksDBContext> db_context,
                        logger::LoggerPtr log);

    expected::Result<std::unique_ptr<const shared_model::validation::Settings>,
                     std::string>
    get() override;

   private:
    expected::Result<std::unique_ptr<const shared_model::validation::Settings>,
                     std::string>
    update(std::unique_ptr<shared_model::validation::Settings> base);

    std::shared_ptr<RocksDBContext> db_context_;
    logger::LoggerPtr log_;
  };

}  // namespace iroha::ametsuchi

#endif  // IROHA_POSTGRES_SETTING_QUERY_HPP
