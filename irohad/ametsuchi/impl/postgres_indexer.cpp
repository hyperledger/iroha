/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_indexer.hpp"

#include <soci/soci.h>
#include <boost/format.hpp>
#include "ametsuchi/impl/soci_reconnection_hacks.hpp"
#include "cryptography/hash.hpp"

using namespace iroha::ametsuchi;
using namespace shared_model::interface::types;

PostgresIndexer::PostgresIndexer(soci::session &sql) : sql_(sql) {}

void PostgresIndexer::txHashStatus(const HashType &tx_hash, bool is_committed) {
  tx_hash_status_.hash.emplace_back(tx_hash.hex());
  tx_hash_status_.status.emplace_back(is_committed ? "TRUE" : "FALSE");
}

void PostgresIndexer::committedTxHash(const HashType &committed_tx_hash) {
  txHashStatus(committed_tx_hash, true);
}

void PostgresIndexer::rejectedTxHash(const HashType &rejected_tx_hash) {
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
  ReconnectionThrowerHack reconnection_checker{sql_};
  try {
    assert(tx_hash_status_.hash.size() == tx_hash_status_.status.size());
    if (not tx_hash_status_.hash.empty()) {
      sql_ << "INSERT INTO tx_status_by_hash"
              "(hash, status) VALUES "
              "(:hash, :status);",
          soci::use(tx_hash_status_.hash), soci::use(tx_hash_status_.status);

      tx_hash_status_.hash.clear();
      tx_hash_status_.status.clear();
    }

    assert(tx_positions_.account.size() == tx_positions_.hash.size());
    assert(tx_positions_.account.size() == tx_positions_.asset_id.size());
    assert(tx_positions_.account.size() == tx_positions_.ts.size());
    assert(tx_positions_.account.size() == tx_positions_.height.size());
    assert(tx_positions_.account.size() == tx_positions_.index.size());
    if (!tx_positions_.account.empty()) {
      sql_ << "INSERT INTO tx_positions"
              "(creator_id, hash, asset_id, ts, height, index) VALUES "
              "(:creator_id, :hash, :asset_id, :ts, :height, :index) ON "
              "CONFLICT DO NOTHING;",
          soci::use(tx_positions_.account), soci::use(tx_positions_.hash),
          soci::use(tx_positions_.asset_id), soci::use(tx_positions_.ts),
          soci::use(tx_positions_.height), soci::use(tx_positions_.index);

      tx_positions_.account.clear();
      tx_positions_.hash.clear();
      tx_positions_.asset_id.clear();
      tx_positions_.ts.clear();
      tx_positions_.height.clear();
      tx_positions_.index.clear();
    }

  } catch (const std::exception &e) {
    reconnection_checker.throwIfReconnected(e.what());
    return e.what();
  }
  return {};
}
