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

using TxPosition = iroha::ametsuchi::Indexer::TxPosition;

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
    TxPosition position,
    const shared_model::interface::Transaction::CommandsType &commands) {
  for (const auto &transfer :
       commands | boost::adaptors::transformed(getTransferAsset)
           | boost::adaptors::filtered(
                 [](const auto &opt_tx) { return static_cast<bool>(opt_tx); })
           | boost::adaptors::transformed(
                 [](const auto &opt_tx) -> const auto & { return *opt_tx; })) {
    const auto &src_id = transfer.srcAccountId();
    const auto &dest_id = transfer.destAccountId();

    const auto ids = {account_id, src_id, dest_id};
    const auto &asset_id = transfer.assetId();
    // flat map accounts to unindexed keys
    for (const auto &id : ids) {
      indexer_->accountAssetTxPosition(id, asset_id, position);
    }
  }
}

PostgresBlockIndex::PostgresBlockIndex(std::unique_ptr<Indexer> indexer,
                                       logger::LoggerPtr log)
    : indexer_(std::move(indexer)), log_(std::move(log)) {}

void PostgresBlockIndex::index(const shared_model::interface::Block &block) {
  auto height = block.height();
  for (const auto &tx : block.transactions() | boost::adaptors::indexed(0)) {
    const auto &creator_id = tx.value().creatorAccountId();
    const TxPosition position{height, static_cast<size_t>(tx.index())};

    makeAccountAssetIndex(creator_id, position, tx.value().commands());
    indexer_->txHashPosition(tx.value().hash(), position);
    indexer_->committedTxHash(tx.value().hash());
    indexer_->txPositionByCreator(creator_id, position);
  }

  for (const auto &rejected_tx_hash : block.rejected_transactions_hashes()) {
    indexer_->rejectedTxHash(rejected_tx_hash);
  }

  if (auto e = resultToOptionalError(indexer_->flush())) {
    log_->error(e.value());
  }
}
