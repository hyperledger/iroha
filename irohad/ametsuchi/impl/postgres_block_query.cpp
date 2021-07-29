/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_block_query.hpp"

#include <boost/format.hpp>

#include "ametsuchi/impl/soci_utils.hpp"
#include "common/byteutils.hpp"
#include "common/cloneable.hpp"
#include "logger/logger.hpp"

namespace iroha::ametsuchi {

  PostgresBlockQuery::PostgresBlockQuery(soci::session &sql,
                                         BlockStorage &block_storage,
                                         logger::LoggerPtr log)
      : BlockQueryBase(block_storage, std::move(log)), sql_(sql) {}

  PostgresBlockQuery::PostgresBlockQuery(std::unique_ptr<soci::session> sql,
                                         BlockStorage &block_storage,
                                         logger::LoggerPtr log)
      : BlockQueryBase(block_storage, std::move(log)),
        psql_(std::move(sql)),
        sql_(*psql_) {}

  std::optional<int32_t> PostgresBlockQuery::getTxStatus(
      const shared_model::crypto::Hash &hash) {
    int res = -1;
    const auto &hash_str = hash.hex();

    try {
      sql_ << "SELECT status FROM tx_status_by_hash WHERE hash = :hash",
          soci::into(res), soci::use(hash_str);
    } catch (const std::exception &e) {
      log_->error("Failed to execute query: {}", e.what());
      return std::nullopt;
    }

    return res;
  }

}  // namespace iroha::ametsuchi
