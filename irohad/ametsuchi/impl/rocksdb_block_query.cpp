/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/rocksdb_block_query.hpp"

#include "ametsuchi/impl/rocksdb_common.hpp"
#include "common/cloneable.hpp"
#include "logger/logger.hpp"

namespace iroha::ametsuchi {

  RocksDbBlockQuery::RocksDbBlockQuery(
      std::shared_ptr<RocksDBContext> db_context,
      BlockStorage &block_storage,
      logger::LoggerPtr log)
      : BlockQueryBase(block_storage, std::move(log)),
        db_context_(std::move(db_context)) {}

  std::optional<int32_t> RocksDbBlockQuery::getTxStatus(
      const shared_model::crypto::Hash &hash) {
    int res = -1;
    RocksDbCommon common(db_context_);

    if (auto status =
            forTransactionStatus<kDbOperation::kGet, kDbEntry::kCanExist>(
                common, hash);
        expected::hasError(status)) {
      log_->error("Failed to execute query: {}, code: {}",
                  status.assumeError().description,
                  status.assumeError().code);
      return std::nullopt;
    } else if (status.assumeValue()) {
      auto const &[tx_status] = staticSplitId<1ull>(*status.assumeValue(), "#");
      res = (!tx_status.empty() && tx_status[0] == 'T') ? 1 : 0;
    }

    return res;
  }

}  // namespace iroha::ametsuchi
