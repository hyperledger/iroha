/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_indexer.hpp"

#include <fmt/core.h>
#include <soci/soci.h>
#include <boost/format.hpp>
#include "cryptography/hash.hpp"

using namespace iroha::ametsuchi;
using namespace shared_model::interface::types;

PostgresIndexer::PostgresIndexer(soci::session &sql) : sql_(sql) {}

void PostgresIndexer::txHashStatus(const HashType &tx_hash, bool is_committed) {
  tx_hash_status_.hash.emplace_back(tx_hash.hex());
  tx_hash_status_.status.emplace_back(is_committed ? "TRUE" : "FALSE");
}

void PostgresIndexer::committedTxHash(
    const TxPosition &position,
    shared_model::interface::types::TimestampType const ts,
    const HashType &committed_tx_hash) {
  txHashStatus(committed_tx_hash, true);
}

void PostgresIndexer::rejectedTxHash(
    const TxPosition &position,
    shared_model::interface::types::TimestampType const ts,
    const HashType &rejected_tx_hash) {
  txHashStatus(rejected_tx_hash, false);
}

void PostgresIndexer::txPositions(
    shared_model::interface::types::AccountIdType const &account,
    HashType const &hash,
    boost::optional<AssetIdType> &&asset_id,
    TimestampType const ts,
    TxPosition const &position) {
  tx_positions_.account.emplace_back(account);
  tx_positions_.hash.emplace_back(hash.hex());
  tx_positions_.asset_id.emplace_back(std::move(asset_id));
  tx_positions_.ts.emplace_back(ts);
  tx_positions_.height.emplace_back(position.height);
  tx_positions_.index.emplace_back(position.index);
}

iroha::expected::Result<void, std::string> PostgresIndexer::flush() {
  try {
    cache_.clear();
    assert(tx_hash_status_.hash.size() == tx_hash_status_.status.size());
    if (not tx_hash_status_.hash.empty()) {
      cache_ +=
          "INSERT INTO tx_status_by_hash"
          "(hash, status) VALUES ";
      for (size_t ix = 0; ix < tx_hash_status_.hash.size(); ++ix) {
        cache_ += fmt::format("('{}','{}')",
                              tx_hash_status_.hash[ix],
                              tx_hash_status_.status[ix]);
        if (ix != tx_hash_status_.hash.size() - 1)
          cache_ += ',';
      }
      cache_ += ";\n";

      tx_hash_status_.hash.clear();
      tx_hash_status_.status.clear();
    }

    assert(tx_positions_.account.size() == tx_positions_.hash.size());
    assert(tx_positions_.account.size() == tx_positions_.asset_id.size());
    assert(tx_positions_.account.size() == tx_positions_.ts.size());
    assert(tx_positions_.account.size() == tx_positions_.height.size());
    assert(tx_positions_.account.size() == tx_positions_.index.size());
    if (!tx_positions_.account.empty()) {
      cache_ +=
          "INSERT INTO tx_positions"
          "(creator_id, hash, asset_id, ts, height, index) VALUES ";
      for (size_t ix = 0; ix < tx_positions_.account.size(); ++ix) {
        if (tx_positions_.asset_id[ix]) {
          cache_ += fmt::format("('{}','{}','{}',{},{},{})",
                                tx_positions_.account[ix],
                                tx_positions_.hash[ix],
                                *tx_positions_.asset_id[ix],
                                tx_positions_.ts[ix],
                                tx_positions_.height[ix],
                                tx_positions_.index[ix]);
        } else {
          cache_ += fmt::format("('{}','{}',NULL,{},{},{})",
                                tx_positions_.account[ix],
                                tx_positions_.hash[ix],
                                tx_positions_.ts[ix],
                                tx_positions_.height[ix],
                                tx_positions_.index[ix]);
        }
        if (ix != tx_positions_.account.size() - 1)
          cache_ += ',';
      }
      cache_ += " ON CONFLICT DO NOTHING;\n";

      tx_positions_.account.clear();
      tx_positions_.hash.clear();
      tx_positions_.asset_id.clear();
      tx_positions_.ts.clear();
      tx_positions_.height.clear();
      tx_positions_.index.clear();
    }

    if (!cache_.empty())
      sql_ << cache_;
  } catch (const std::exception &e) {
    return e.what();
  }
  return {};
}
