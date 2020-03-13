/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_indexer.hpp"

#include <soci/soci.h>
#include <boost/format.hpp>
#include "cryptography/hash.hpp"

using namespace iroha::ametsuchi;
using namespace shared_model::interface::types;

PostgresIndexer::PostgresIndexer(soci::session &sql) : sql_(sql) {}

void PostgresIndexer::txHashPosition(const HashType &hash,
                                     TxPosition position) {
  tx_hash_position_.hash.emplace_back(hash.hex());
  tx_hash_position_.height.emplace_back(position.height);
  tx_hash_position_.index.emplace_back(position.index);
}

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

void PostgresIndexer::txPositionByCreator(const AccountIdType creator,
                                          TxPosition position) {
  tx_position_by_creator_.creator.emplace_back(creator);
  tx_position_by_creator_.height.emplace_back(position.height);
  tx_position_by_creator_.index.emplace_back(position.index);
}

void PostgresIndexer::accountAssetTxPosition(const AccountIdType &account_id,
                                             const AssetIdType &asset_id,
                                             TxPosition position) {
  account_asset_tx_position_.account_id.emplace_back(account_id);
  account_asset_tx_position_.asset_id.emplace_back(asset_id);
  account_asset_tx_position_.height.emplace_back(position.height);
  account_asset_tx_position_.index.emplace_back(position.index);
}

iroha::expected::Result<void, std::string> PostgresIndexer::flush() {
  try {
    assert(tx_hash_position_.hash.size() == tx_hash_position_.height.size());
    assert(tx_hash_position_.hash.size() == tx_hash_position_.index.size());
    if (not tx_hash_position_.hash.empty()) {
      sql_ << "INSERT INTO position_by_hash"
              "(hash, height, index) VALUES "
              "(:hash, :height, :index);",
          soci::use(tx_hash_position_.hash),
          soci::use(tx_hash_position_.height),
          soci::use(tx_hash_position_.index);

      tx_hash_position_.hash.clear();
      tx_hash_position_.height.clear();
      tx_hash_position_.index.clear();
    }

    assert(tx_hash_status_.hash.size() == tx_hash_status_.status.size());
    if (not tx_hash_status_.hash.empty()) {
      sql_ << "INSERT INTO tx_status_by_hash"
              "(hash, status) VALUES "
              "(:hash, :status);",
          soci::use(tx_hash_status_.hash), soci::use(tx_hash_status_.status);

      tx_hash_status_.hash.clear();
      tx_hash_status_.status.clear();
    }

    assert(tx_position_by_creator_.creator.size()
           == tx_position_by_creator_.height.size());
    assert(tx_position_by_creator_.creator.size()
           == tx_position_by_creator_.index.size());
    if (not tx_position_by_creator_.creator.empty()) {
      sql_ << "INSERT INTO tx_position_by_creator"
              "(creator_id, height, index) VALUES "
              "(:creator_id, :height, :index);",
          soci::use(tx_position_by_creator_.creator),
          soci::use(tx_position_by_creator_.height),
          soci::use(tx_position_by_creator_.index);

      tx_position_by_creator_.creator.clear();
      tx_position_by_creator_.height.clear();
      tx_position_by_creator_.index.clear();
    }

    assert(account_asset_tx_position_.account_id.size()
           == account_asset_tx_position_.asset_id.size());
    assert(account_asset_tx_position_.account_id.size()
           == account_asset_tx_position_.height.size());
    assert(account_asset_tx_position_.account_id.size()
           == account_asset_tx_position_.index.size());
    if (not account_asset_tx_position_.account_id.empty()) {
      sql_ << "INSERT INTO position_by_account_asset"
              "(account_id, asset_id, height, index) VALUES "
              "(:account_id, :asset_id, :height, :index);",
          soci::use(account_asset_tx_position_.account_id),
          soci::use(account_asset_tx_position_.asset_id),
          soci::use(account_asset_tx_position_.height),
          soci::use(account_asset_tx_position_.index);

      account_asset_tx_position_.account_id.clear();
      account_asset_tx_position_.asset_id.clear();
      account_asset_tx_position_.height.clear();
      account_asset_tx_position_.index.clear();
    }
  } catch (const std::exception &e) {
    return e.what();
  }
  return {};
}
