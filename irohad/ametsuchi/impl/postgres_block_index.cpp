/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_block_index.hpp"

#include <boost/range/adaptor/indexed.hpp>
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
  std::optional<std::reference_wrapper<const shared_model::interface::TransferAsset>>
  getTransferAsset(const shared_model::interface::Command &cmd) noexcept {
    using ReturnType =
        std::optional<std::reference_wrapper<const shared_model::interface::TransferAsset>>;
    return iroha::visit_in_place(
        cmd.get(),
        [](const shared_model::interface::TransferAsset &c) {
          return ReturnType(c);
        },
        [](const auto &) -> ReturnType { return std::nullopt; });
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
  for (const auto &command : commands) {
    if (auto opt_transfer = getTransferAsset(command)) {
      const auto &src_id = opt_transfer->get().srcAccountId();
      const auto &dest_id = opt_transfer->get().destAccountId();

      const auto ids = {src_id, dest_id};
      const auto asset_id = opt_transfer->get().assetId();
      // flat map accounts to unindexed keys
      for (const auto &id : ids) {
        indexer_->txPositions(id, hash, asset_id, ts, position);
        creator_was_added |= id == account_id;
      }
      if (not creator_was_added) {
        indexer_->txPositions(account_id, hash, asset_id, ts, position);
      }
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

    indexer_->committedTxHash(tx.value().hash());
    makeAccountAssetIndex(creator_id,
                          tx.value().hash(),
                          tx.value().createdTime(),
                          position,
                          tx.value().commands());
    indexer_->txPositions(creator_id,
                          tx.value().hash(),
                          std::nullopt,
                          tx.value().createdTime(),
                          position);
  }

  for (const auto &rejected_tx_hash : block.rejected_transactions_hashes()) {
    indexer_->rejectedTxHash(rejected_tx_hash);
  }

  if (auto e = resultToOptionalError(indexer_->flush())) {
    log_->error(e.value());
  }
}
