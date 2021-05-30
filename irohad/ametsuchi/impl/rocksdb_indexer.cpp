/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/rocksdb_indexer.hpp"

#include <fmt/core.h>

#include "ametsuchi/impl/rocksdb_common.hpp"
#include "cryptography/hash.hpp"

using namespace iroha::ametsuchi;
using namespace shared_model::interface::types;

RocksDBIndexer::RocksDBIndexer(std::shared_ptr<RocksDBPort> db_port)
    : db_context_(std::make_shared<RocksDBContext>(db_port)) {}

void RocksDBIndexer::txHashStatus(const HashType &tx_hash, bool is_committed) {
  RocksDbCommon common(db_context_);
  common.valueBuffer().assign(is_committed ? "TRUE" : "FALSE");
  forTransactionStatus<kDbOperation::kPut>(common, tx_hash.hex());
}

void RocksDBIndexer::committedTxHash(const HashType &committed_tx_hash) {
  txHashStatus(committed_tx_hash, true);
}

void RocksDBIndexer::rejectedTxHash(const HashType &rejected_tx_hash) {
  txHashStatus(rejected_tx_hash, false);
}

void RocksDBIndexer::txPositions(
    shared_model::interface::types::AccountIdType const &account,
    HashType const &hash,
    boost::optional<AssetIdType> &&asset_id,
    TimestampType const ts,
    TxPosition const &position) {
  RocksDbCommon common(db_context_);

  common.valueBuffer().assign(
      fmt::format("{}#{}#{}", asset_id ? *asset_id : "", ts, hash.hex()));
  forTransactionByPosition<kDbOperation::kPut>(
      common, account, position.height, position.index);

  common.valueBuffer().assign(hash.hex());
  forTransactionByTimestamp<kDbOperation::kPut>(common, account, ts);
}

iroha::expected::Result<void, std::string> RocksDBIndexer::flush() {
  RocksDbCommon common(db_context_);
  if (!common.commit().ok())
    return expected::makeError("Unable to flush transactions data.");
  return {};
}
