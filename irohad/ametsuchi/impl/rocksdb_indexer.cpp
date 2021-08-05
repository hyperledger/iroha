/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/rocksdb_indexer.hpp"

#include <fmt/core.h>

#include "ametsuchi/impl/rocksdb_common.hpp"
#include "common/to_lower.hpp"
#include "cryptography/hash.hpp"

using namespace iroha::ametsuchi;
using namespace shared_model::interface::types;

RocksDBIndexer::RocksDBIndexer(std::shared_ptr<RocksDBContext> db_context)
    : db_context_(std::move(db_context)) {}

void RocksDBIndexer::txHashStatus(const TxPosition &position,
                                  TimestampType const ts,
                                  const HashType &tx_hash,
                                  bool is_committed) {
  RocksDbCommon common(db_context_);
  common.valueBuffer() = is_committed ? "TRUE" : "FALSE";
  common.valueBuffer() += '#';
  common.valueBuffer() += std::to_string(position.height);
  common.valueBuffer() += '#';
  common.valueBuffer() += std::to_string(position.index);
  common.valueBuffer() += '#';
  common.valueBuffer() += std::to_string(ts);

  std::string h_hex;
  forTransactionStatus<kDbOperation::kPut>(common,
                                           toLowerAppend(tx_hash.hex(), h_hex));

  if (is_committed) {
    uint64_t txs_count = 0ull;
    if (auto result =
            forTxsTotalCount<kDbOperation::kGet, kDbEntry::kCanExist>(common);
        expected::hasValue(result) && result.assumeValue())
      txs_count = *result.assumeValue();

    common.encode(txs_count + 1ull);
    forTxsTotalCount<kDbOperation::kPut>(common);
  }
}

void RocksDBIndexer::committedTxHash(
    const TxPosition &position,
    shared_model::interface::types::TimestampType const ts,
    const HashType &committed_tx_hash) {
  txHashStatus(position, ts, committed_tx_hash, true);
}

void RocksDBIndexer::rejectedTxHash(
    const TxPosition &position,
    shared_model::interface::types::TimestampType const ts,
    const HashType &rejected_tx_hash) {
  txHashStatus(position, ts, rejected_tx_hash, false);
}

void RocksDBIndexer::txPositions(
    shared_model::interface::types::AccountIdType const &account,
    HashType const &hash,
    boost::optional<AssetIdType> &&asset_id,
    TimestampType const ts,
    TxPosition const &position) {
  RocksDbCommon common(db_context_);

  if (auto res = forTransactionByPosition<kDbOperation::kCheck,
                                          kDbEntry::kMustNotExist>(
          common, account, ts, position.height, position.index);
      expected::hasError(res))
    return;

  std::string h_hex;
  common.valueBuffer().assign(fmt::format(
      "{}%{}", asset_id ? *asset_id : "", toLowerAppend(hash.hex(), h_hex)));

  forTransactionByPosition<kDbOperation::kPut>(
      common, account, ts, position.height, position.index);
  forTransactionByTimestamp<kDbOperation::kPut>(
      common, account, ts, position.height, position.index);

  uint64_t txs_count = 0ull;
  if (auto result = forTxsTotalCount<kDbOperation::kGet, kDbEntry::kCanExist>(
          common, account);
      expected::hasValue(result) && result.assumeValue())
    txs_count = *result.assumeValue();

  common.encode(txs_count + 1ull);
  forTxsTotalCount<kDbOperation::kPut>(common, account);

  /// update first transaction ts from this account
  if (TimestampType(0ull) != ts) {
    uint64_t first_tx_time = std::numeric_limits<TimestampType>::max();
    if (auto res =
            forAccountFirstTxTs<kDbOperation::kGet, kDbEntry::kMustExist>(
                common, account);
        expected::hasValue(res))
      first_tx_time = *res.assumeValue();

    auto const current_frame = (ts / framepoint) * framepoint;
    auto const frame_begin =
        std::min(first_tx_time, current_frame);
    if (frame_begin != first_tx_time) {
      common.encode(frame_begin);
      forAccountFirstTxTs<kDbOperation::kPut>(common, account);
    }

    common.valueBuffer().clear();
    auto frame = current_frame + framepoint;
    while (frame >= frame_begin
           && !expected::hasError(
               forTransactionByTimestamp<kDbOperation::kCheck,
                                         kDbEntry::kMustNotExist>(
                   common, account, frame, 0ull, 0ull))) {
      forTransactionByTimestamp<kDbOperation::kPut>(
          common, account, frame, 0ull, 0ull);
      frame -= framepoint;
    }
  }
}

iroha::expected::Result<void, std::string> RocksDBIndexer::flush() {
  RocksDbCommon common(db_context_);
  if (!common.commit().ok())
    return expected::makeError("Unable to flush transactions data.");
  return {};
}
