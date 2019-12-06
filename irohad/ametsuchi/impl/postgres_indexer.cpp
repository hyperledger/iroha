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
  boost::format base(
      "INSERT INTO position_by_hash"
      "(hash, height, index) VALUES "
      "('%s', '%s', '%s');\n");
  statements_.append(
      (base % hash.hex() % position.height % position.index).str());
}

void PostgresIndexer::txHashStatus(const HashType &rejected_tx_hash,
                                   bool is_committed) {
  boost::format base(
      "INSERT INTO tx_status_by_hash"
      "(hash, status) VALUES "
      "('%s', '%s');\n");
  statements_.append(
      (base % rejected_tx_hash.hex() % (is_committed ? "TRUE" : "FALSE"))
          .str());
}

void PostgresIndexer::committedTxHash(const HashType &committed_tx_hash) {
  txHashStatus(committed_tx_hash, true);
}

void PostgresIndexer::rejectedTxHash(const HashType &rejected_tx_hash) {
  txHashStatus(rejected_tx_hash, false);
}

void PostgresIndexer::txPositionByCreator(const AccountIdType creator,
                                          TxPosition position) {
  boost::format base(
      "INSERT INTO tx_position_by_creator"
      "(creator_id, height, index) VALUES "
      "('%s', '%s', '%s');\n");
  statements_.append((base % creator % position.height % position.index).str());
}

void PostgresIndexer::accountAssetTxPosition(const AccountIdType &account_id,
                                             const AssetIdType &asset_id,
                                             TxPosition position) {
  boost::format base(
      "INSERT INTO position_by_account_asset"
      "(account_id, asset_id, height, index) VALUES "
      "('%s', '%s', '%s', '%s');\n");
  statements_.append(
      (base % account_id % asset_id % position.height % position.index).str());
}

iroha::expected::Result<void, std::string> PostgresIndexer::flush() {
  try {
    sql_ << statements_;
    statements_.clear();
  } catch (const std::exception &e) {
    return e.what();
  }
  return {};
}
