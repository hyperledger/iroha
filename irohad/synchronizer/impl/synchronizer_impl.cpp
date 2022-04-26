/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "synchronizer/impl/synchronizer_impl.hpp"

#include <utility>

#include "ametsuchi/block_query_factory.hpp"
#include "ametsuchi/command_executor.hpp"
#include "ametsuchi/mutable_storage.hpp"
#include "common/bind.hpp"
#include "common/result.hpp"
#include "common/visitor.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "logger/logger.hpp"
#include "main/iroha_status.hpp"
#include "main/subscription.hpp"

using iroha::synchronizer::SynchronizerImpl;

SynchronizerImpl::SynchronizerImpl(
    std::unique_ptr<iroha::ametsuchi::CommandExecutor> command_executor,
    std::shared_ptr<validation::ChainValidator> validator,
    std::shared_ptr<ametsuchi::MutableFactory> mutable_factory,
    std::shared_ptr<ametsuchi::BlockQueryFactory> block_query_factory,
    std::shared_ptr<network::BlockLoader> block_loader,
    logger::LoggerPtr log)
    : command_executor_(std::move(command_executor)),
      validator_(std::move(validator)),
      mutable_factory_(std::move(mutable_factory)),
      block_query_factory_(std::move(block_query_factory)),
      block_loader_(std::move(block_loader)),
      log_(std::move(log)) {}

std::optional<iroha::synchronizer::SynchronizationEvent>
SynchronizerImpl::processOutcome(consensus::GateObject object) {
  log_->info("processing consensus outcome");

  auto process_reject =
      [](auto outcome_type,
         const auto &msg) -> std::optional<SynchronizationEvent> {
    assert(msg.ledger_state->top_block_info.height + 1
           == msg.round.block_round);
    return SynchronizationEvent{outcome_type, msg.round, msg.ledger_state};
  };

  return std::visit(
      make_visitor(
          [this](const consensus::PairValid &msg) {
            assert(msg.ledger_state->top_block_info.height + 1
                   == msg.round.block_round);
            return this->processNext(msg);
          },
          [this](const consensus::VoteOther &msg) {
            assert(msg.ledger_state->top_block_info.height + 1
                   == msg.round.block_round);
            return this->processDifferent(msg, msg.round.block_round);
          },
          [&](const consensus::ProposalReject &msg) {
            return process_reject(SynchronizationOutcomeType::kReject, msg);
          },
          [&](const consensus::BlockReject &msg) {
            return process_reject(SynchronizationOutcomeType::kReject, msg);
          },
          [&](const consensus::AgreementOnNone &msg) {
            return process_reject(SynchronizationOutcomeType::kNothing, msg);
          },
          [this](const consensus::Future &msg) {
            assert(msg.ledger_state->top_block_info.height + 1
                   < msg.round.block_round);
            // we do not know the ledger state for round n, so we
            // cannot claim that the bunch of votes we got is a
            // commit certificate and hence we do not know if the
            // block n is committed and cannot require its
            // acquisition.
            return this->processDifferent(msg, msg.round.block_round - 1);
          }),
      object);
}

iroha::ametsuchi::CommitResult SynchronizerImpl::downloadAndCommitMissingBlocks(
    const shared_model::interface::types::HeightType start_height,
    const shared_model::interface::types::HeightType target_height,
    const shared_model::interface::types::PublicKeyCollectionType
        &public_keys) {
  auto storage_result = getStorage();
  if (iroha::expected::hasError(storage_result)) {
    return std::move(storage_result).assumeError();
  }
  auto storage = std::move(storage_result).assumeValue();
  shared_model::interface::types::HeightType my_height = start_height;

  iroha::IrohaStatus status;
  status.is_syncing = true;
  iroha::getSubscription()->notify(iroha::EventTypes::kOnIrohaStatus, status);

  /// To reset iroha is_syncing status on break loop
  std::unique_ptr<bool, void (*)(bool *)> iroha_status_reseter(
      (bool *)0x1, [](bool *) {
        iroha::IrohaStatus status;
        status.is_syncing = false;
        iroha::getSubscription()->notify(iroha::EventTypes::kOnIrohaStatus,
                                         status);
      });

  shared_model::interface::types::HeightType const end_height = std::min(
      start_height + shared_model::interface::types::HeightType(1000ull),
      target_height);

  // TODO andrei 17.10.18 IR-1763 Add delay strategy for loading blocks
  using namespace iroha::expected;
  for (const auto &public_key : public_keys) {
    while (true) {
      bool peer_ok = false;
      log_->debug(
          "trying to download blocks from {} to {} from peer with key {}",
          my_height + 1,
          target_height,
          public_key);
      auto maybe_reader = block_loader_->retrieveBlocks(
          my_height,
          shared_model::interface::types::PublicKeyHexStringView{public_key});

      if (hasError(maybe_reader)) {
        log_->warn(
            "failed to retrieve blocks starting from {} from peer {}: {}",
            my_height,
            public_key,
            maybe_reader.assumeError());
        continue;
      }

      auto block_var = maybe_reader.assumeValue()->read();
      for (auto maybe_block = std::get_if<
               std::shared_ptr<const shared_model::interface::Block>>(
               &block_var);
           maybe_block;
           block_var = maybe_reader.assumeValue()->read(),
                maybe_block = std::get_if<
                    std::shared_ptr<const shared_model::interface::Block>>(
                    &block_var)) {
        if (not(peer_ok =
                    validator_->validateAndApply(*maybe_block, *storage))) {
          break;
        }

        my_height = (*maybe_block)->height();
        if (my_height > end_height)
          break;
      }
      if (auto error = std::get_if<std::string>(&block_var)) {
        log_->warn("failed to retrieve block: {}", *error);
      }
      if (my_height >= end_height) {
        return mutable_factory_->commit(std::move(storage));
      }
      if (not peer_ok) {
        // if the last block did not apply or we got no new blocks from this
        // peer we should switch to next peer
        break;
      }
    }
  }

  return expected::makeError(
      "Failed to download and commit any blocks from given peers");
}

iroha::expected::Result<std::unique_ptr<iroha::ametsuchi::MutableStorage>,
                        std::string>
SynchronizerImpl::getStorage() {
  return mutable_factory_->createMutableStorage(command_executor_);
}

std::optional<iroha::synchronizer::SynchronizationEvent>
SynchronizerImpl::processNext(const consensus::PairValid &msg) {
  log_->info("at handleNext");
  if (mutable_factory_->preparedCommitEnabled()) {
    auto result = mutable_factory_->commitPrepared(msg.block);
    if (iroha::expected::hasValue(result)) {
      return SynchronizationEvent{SynchronizationOutcomeType::kCommit,
                                  msg.round,
                                  std::move(std::move(result).assumeValue())};
    }
    log_->error("Error committing prepared block: {}", result.assumeError());
  }
  auto maybe_storage = getStorage();

  if (expected::hasError(maybe_storage)) {
    log_->error("Failed to getStorage(): {}", maybe_storage.assumeError());
    return std::nullopt;
  }

  if (not maybe_storage.assumeValue()->apply(msg.block)) {
    log_->error("Block failed to apply.");
    return std::nullopt;
  }

  auto maybe_result =
      mutable_factory_->commit(std::move(maybe_storage.assumeValue()));

  if (expected::hasError(maybe_result)) {
    log_->error("Failed to commit: {}", maybe_result.assumeError());
    return std::nullopt;
  }

  return SynchronizationEvent{SynchronizationOutcomeType::kCommit,
                              msg.round,
                              std::move(maybe_result.assumeValue())};
}

std::optional<iroha::synchronizer::SynchronizationEvent>
SynchronizerImpl::processDifferent(
    const consensus::Synchronizable &msg,
    shared_model::interface::types::HeightType required_height) {
  log_->info("at handleDifferent");

  auto commit_result =
      downloadAndCommitMissingBlocks(msg.ledger_state->top_block_info.height,
                                     required_height,
                                     msg.public_keys);

  if (expected::hasError(commit_result)) {
    log_->error("Synchronization failed in processDifferent(): {}",
                commit_result.assumeError());
    return std::nullopt;
  }

  auto &ledger_state = commit_result.assumeValue();
  assert(ledger_state);
  const auto new_height = ledger_state->top_block_info.height;
  return SynchronizationEvent{SynchronizationOutcomeType::kCommit,
                              new_height != msg.round.block_round
                                  ? consensus::Round{new_height, 0}
                                  : msg.round,
                              std::move(ledger_state)};
}
