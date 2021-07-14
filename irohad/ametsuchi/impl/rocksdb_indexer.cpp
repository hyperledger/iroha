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

RocksDBIndexer::RocksDBIndexer(std::shared_ptr<RocksDBContext> db_context)
    : db_context_(std::move(db_context)) {}

void RocksDBIndexer::txHashStatus(const TxPosition &position,
                                  const HashType &tx_hash,
                                  bool is_committed) {
  RocksDbCommon common(db_context_);
  common.valueBuffer() = is_committed ? "TRUE" : "FALSE";
  common.valueBuffer() += '#';
  common.valueBuffer() += std::to_string(position.height);
  common.valueBuffer() += '#';
  common.valueBuffer() += std::to_string(position.index);

  std::string h_hex;
  h_hex.reserve(tx_hash.hex().size());

  for (auto const c : tx_hash.hex())
    h_hex += std::tolower(c);

  forTransactionStatus<kDbOperation::kPut>(common, h_hex);
}

void RocksDBIndexer::committedTxHash(const TxPosition &position,
                                     const HashType &committed_tx_hash) {
  txHashStatus(position, committed_tx_hash, true);
}

void RocksDBIndexer::rejectedTxHash(const TxPosition &position,
                                    const HashType &rejected_tx_hash) {
  txHashStatus(position, rejected_tx_hash, false);
}

void RocksDBIndexer::txPositions(
    shared_model::interface::types::AccountIdType const &account,
    HashType const &hash,
    boost::optional<AssetIdType> &&asset_id,
    TimestampType const ts,
    TxPosition const &position) {
  RocksDbCommon common(db_context_);

  std::string h_hex;
  h_hex.reserve(hash.hex().size());

  for (auto const c : hash.hex())
    h_hex += std::tolower(c);

  common.valueBuffer().assign(
      fmt::format("{}#{}", asset_id ? *asset_id : "", h_hex));

  forTransactionByPosition<kDbOperation::kPut>(
      common, account, position.height, position.index, ts);
  forTransactionByTimestamp<kDbOperation::kPut>(
      common, account, ts, position.height, position.index);

  uint64_t txs_count = 0ull;
  if (auto result = forTxsTotalCount<kDbOperation::kGet, kDbEntry::kCanExist>(
          common, account);
      expected::hasValue(result) && result.assumeValue())
    txs_count = *result.assumeValue();

  common.encode(txs_count + 1ull);
  forTxsTotalCount<kDbOperation::kPut>(common, account);

  txs_count = 0ull;
  if (auto result =
          forTxsTotalCount<kDbOperation::kGet, kDbEntry::kCanExist>(common);
      expected::hasValue(result) && result.assumeValue())
    txs_count = *result.assumeValue();

  common.encode(txs_count + 1ull);
  forTxsTotalCount<kDbOperation::kPut>(common);
}

iroha::expected::Result<void, std::string> RocksDBIndexer::flush() {
  RocksDbCommon common(db_context_);
  if (!common.commit().ok())
    return expected::makeError("Unable to flush transactions data.");
  return {};
}
