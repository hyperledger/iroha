/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_block_index.hpp"

#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/indexed.hpp>
#include <boost/range/adaptor/transformed.hpp>

#include "ametsuchi/tx_cache_response.hpp"
#include "common/visitor.hpp"
#include "interfaces/commands/command_variant.hpp"
#include "interfaces/commands/transfer_asset.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "logger/logger.hpp"

using namespace iroha::ametsuchi;
using namespace shared_model::interface::types;

//using TxPosition = iroha::ametsuchi::Indexer::TxPosition;

namespace {
  // Return transfer asset if command contains it
  boost::optional<const shared_model::interface::TransferAsset &>
  getTransferAsset(const shared_model::interface::Command &cmd) noexcept {
    using ReturnType =
        boost::optional<const shared_model::interface::TransferAsset &>;
    return iroha::visit_in_place(
        cmd.get(),
        [](const shared_model::interface::TransferAsset &c) {
          return ReturnType(c);
        },
        [](const auto &) -> ReturnType { return boost::none; });
  }
}  // namespace

// Collect all assets belonging to creator, sender, and receiver
// to make account_id:height:asset_id -> list of tx indexes
// for transfer asset in command
void PostgresBlockIndex::makeAccountAssetIndex(
    const AccountIdType &account_id,
    shared_model::interface::types::HashType const &hash,
    shared_model::interface::types::TimestampType const ts,
    TxPosition position,
    const shared_model::interface::Transaction::CommandsType &commands) {
  bool creator_was_added = false;
  for (const auto &transfer :
       commands | boost::adaptors::transformed(getTransferAsset)
           | boost::adaptors::filtered(
               [](const auto &opt_tx) { return static_cast<bool>(opt_tx); })
           | boost::adaptors::transformed(
               [](const auto &opt_tx) -> const auto & { return *opt_tx; })) {
    const auto &src_id = transfer.srcAccountId();
    const auto &dest_id = transfer.destAccountId();

    const auto ids = {src_id, dest_id};
    const auto asset_id = transfer.assetId();
    // flat map accounts to unindexed keys
    for (const auto &id : ids) {
      this->txPositions(id, hash, asset_id, ts, position);
      creator_was_added |= id == account_id;
    }
    if (not creator_was_added) {
      this->txPositions(account_id, hash, asset_id, ts, position);
    }
  }
}

PostgresBlockIndex::PostgresBlockIndex(//std::unique_ptr<Indexer> indexer,
                                       soci::session &sql,
                                       logger::LoggerPtr log)
    : sql_(sql), log_(std::move(log)) {}
    // : indexer_(std::move(indexer)), log_(std::move(log)) {}

void PostgresBlockIndex::index(const shared_model::interface::Block &block,
                               bool do_flush) {
  auto height = block.height();
  for (auto tx : block.transactions() | boost::adaptors::indexed(0)) {
    const auto &creator_id = tx.value().creatorAccountId();
    const TxPosition position{height, static_cast<size_t>(tx.index())};

    this->committedTxHash(tx.value().hash());
    makeAccountAssetIndex(creator_id,
                          tx.value().hash(),
                          tx.value().createdTime(),
                          position,
                          tx.value().commands());
    this->txPositions(creator_id,
                          tx.value().hash(),
                          boost::none,
                          tx.value().createdTime(),
                          position);
  }

  for (const auto &rejected_tx_hash : block.rejected_transactions_hashes()) {
    this->rejectedTxHash(rejected_tx_hash);
  }

  if (do_flush) {
    if (auto e = resultToOptionalError(this->flush())) {
      log_->error(e.value());
    }
  }
}



#include <fmt/core.h>
#include <soci/soci.h>
#include <boost/format.hpp>
#include "cryptography/hash.hpp"

using namespace iroha::ametsuchi;
using namespace shared_model::interface::types;


void PostgresBlockIndex::txHashStatus(const HashType &tx_hash, bool is_committed) {
  tx_hash_status_.hash.emplace_back(tx_hash.hex());
  tx_hash_status_.status.emplace_back(is_committed ? "TRUE" : "FALSE");
}

void PostgresBlockIndex::committedTxHash(const HashType &committed_tx_hash) {
  txHashStatus(committed_tx_hash, true);
}

void PostgresBlockIndex::rejectedTxHash(const HashType &rejected_tx_hash) {
  txHashStatus(rejected_tx_hash, false);
}

void PostgresBlockIndex::txPositions(
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

iroha::expected::Result<void, std::string> PostgresBlockIndex::flush() {
  try {
    std::string cache_str;
    assert(tx_hash_status_.hash.size() == tx_hash_status_.status.size());
    if (not tx_hash_status_.hash.empty()) {
      cache_str +=
          "INSERT INTO tx_status_by_hash"
          "(hash, status) VALUES ";
      for (size_t ix = 0; ix < tx_hash_status_.hash.size(); ++ix) {
        cache_str += fmt::format("('{}','{}')",
                              tx_hash_status_.hash[ix],
                              tx_hash_status_.status[ix]);
        if (ix != tx_hash_status_.hash.size() - 1)
          cache_str += ',';
      }
      cache_str += ";\n";

      tx_hash_status_.hash.clear();
      tx_hash_status_.status.clear();
    }

    assert(tx_positions_.account.size() == tx_positions_.hash.size());
    assert(tx_positions_.account.size() == tx_positions_.asset_id.size());
    assert(tx_positions_.account.size() == tx_positions_.ts.size());
    assert(tx_positions_.account.size() == tx_positions_.height.size());
    assert(tx_positions_.account.size() == tx_positions_.index.size());
    if (!tx_positions_.account.empty()) {
      cache_str +=
          "INSERT INTO tx_positions"
          "(creator_id, hash, asset_id, ts, height, index) VALUES ";
      for (size_t ix = 0; ix < tx_positions_.account.size(); ++ix) {
        if (tx_positions_.asset_id[ix]) {
          cache_str += fmt::format("('{}','{}','{}',{},{},{})",
                                tx_positions_.account[ix],
                                tx_positions_.hash[ix],
                                *tx_positions_.asset_id[ix],
                                tx_positions_.ts[ix],
                                tx_positions_.height[ix],
                                tx_positions_.index[ix]);
        } else {
          cache_str += fmt::format("('{}','{}',NULL,{},{},{})",
                                tx_positions_.account[ix],
                                tx_positions_.hash[ix],
                                tx_positions_.ts[ix],
                                tx_positions_.height[ix],
                                tx_positions_.index[ix]);
        }
        if (ix != tx_positions_.account.size() - 1)
          cache_str += ',';
      }
      cache_str += " ON CONFLICT DO NOTHING;\n";

      tx_positions_.account.clear();
      tx_positions_.hash.clear();
      tx_positions_.asset_id.clear();
      tx_positions_.ts.clear();
      tx_positions_.height.clear();
      tx_positions_.index.clear();
    }

    if (cache_str.size())
      sql_ << cache_str;

    return {};

  } catch (const std::exception &e) {
    return e.what();
  }
}
