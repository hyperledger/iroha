/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "synchronizer/impl/synchronizer_impl.hpp"

#include <utility>

#include "ametsuchi/block_query_factory.hpp"
#include "ametsuchi/mutable_storage.hpp"
#include "common/visitor.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "logger/logger.hpp"

namespace iroha {
  namespace synchronizer {

    SynchronizerImpl::SynchronizerImpl(
        std::shared_ptr<network::ConsensusGate> consensus_gate,
        std::shared_ptr<validation::ChainValidator> validator,
        std::shared_ptr<ametsuchi::MutableFactory> mutable_factory,
        std::shared_ptr<ametsuchi::BlockQueryFactory> block_query_factory,
        std::shared_ptr<network::BlockLoader> block_loader,
        logger::LoggerPtr log)
        : validator_(std::move(validator)),
          mutable_factory_(std::move(mutable_factory)),
          block_query_factory_(std::move(block_query_factory)),
          block_loader_(std::move(block_loader)),
          notifier_(notifier_lifetime_),
          log_(std::move(log)) {
      consensus_gate->onOutcome().subscribe(
          subscription_, [this](consensus::GateObject object) {
            this->processOutcome(object);
          });
    }

    void SynchronizerImpl::processOutcome(consensus::GateObject object) {
      log_->info("processing consensus outcome");

      visit_in_place(
          object,
          [this](const consensus::PairValid &msg) { this->processNext(msg); },
          [this](const consensus::VoteOther &msg) {
            this->processDifferent(msg, SynchronizationOutcomeType::kCommit);
          },
          [this](const consensus::ProposalReject &msg) {
            this->processDifferent(msg, SynchronizationOutcomeType::kReject);
          },
          [this](const consensus::BlockReject &msg) {
            this->processDifferent(msg, SynchronizationOutcomeType::kReject);
          },
          [this](const consensus::AgreementOnNone &msg) {
            this->processDifferent(msg, SynchronizationOutcomeType::kNothing);
          });
    }

    boost::optional<std::unique_ptr<LedgerState>>
    SynchronizerImpl::downloadMissingBlocks(
        const shared_model::interface::types::HeightType start_height,
        const shared_model::interface::types::HeightType target_height,
        const PublicKeysRange &public_keys) {
      // TODO mboldyrev 21.03.2019 IR-423 Allow consensus outcome update
      while (true) {
        // TODO andrei 17.10.18 IR-1763 Add delay strategy for loading blocks
        for (const auto &public_key : public_keys) {
          auto storage = getStorage().value_or(nullptr);
          if (not storage) {
            return boost::none;
          }

          shared_model::interface::types::HeightType my_height = start_height;
          auto network_chain =
              block_loader_->retrieveBlocks(start_height, public_key)
                  .tap([&my_height](
                           const std::shared_ptr<shared_model::interface::Block>
                               &block) { my_height = block->height(); });

          if (validator_->validateAndApply(network_chain, *storage)
              and my_height >= target_height) {
            return mutable_factory_->commit(std::move(storage));
          }
        }
      }
      return boost::none;
    }

    boost::optional<std::unique_ptr<ametsuchi::MutableStorage>>
    SynchronizerImpl::getStorage() {
      auto mutable_storage_var = mutable_factory_->createMutableStorage();
      if (auto e =
              boost::get<expected::Error<std::string>>(&mutable_storage_var)) {
        log_->error("could not create mutable storage: {}", e->error);
        return {};
      }
      return {std::move(
          boost::get<
              expected::Value<std::unique_ptr<ametsuchi::MutableStorage>>>(
              &mutable_storage_var)
              ->value)};
    }

    void SynchronizerImpl::processNext(const consensus::PairValid &msg) {
      log_->info("at handleNext");
      auto ledger_state = mutable_factory_->commitPrepared(msg.block);
      if (ledger_state) {
        notifier_.get_subscriber().on_next(
            SynchronizationEvent{SynchronizationOutcomeType::kCommit,
                                 msg.round,
                                 std::move(*ledger_state)});
      } else {
        auto opt_storage = getStorage();
        if (opt_storage == boost::none) {
          return;
        }
        std::unique_ptr<ametsuchi::MutableStorage> storage =
            std::move(opt_storage.value());
        if (storage->apply(msg.block)) {
          ledger_state = mutable_factory_->commit(std::move(storage));
          if (ledger_state) {
            notifier_.get_subscriber().on_next(
                SynchronizationEvent{SynchronizationOutcomeType::kCommit,
                                     msg.round,
                                     std::move(*ledger_state)});
          } else {
            log_->error("failed to commit mutable storage");
          }
        } else {
          log_->warn("Block was not committed due to fail in mutable storage");
        }
      }
    }

    boost::optional<shared_model::interface::types::HeightType>
    SynchronizerImpl::getTopBlockHeight() const {
      decltype(getTopBlockHeight()) top_block_height;
      if (auto block_query = block_query_factory_->createBlockQuery()) {
        top_block_height = (*block_query)->getTopBlockHeight();
      } else {
        log_->error(
            "Unable to create block query and retrieve top block height");
      }
      return top_block_height;
    }

    void SynchronizerImpl::processDifferent(
        const consensus::Synchronizable &msg,
        SynchronizationOutcomeType alternative_outcome) {
      log_->info("at handleDifferent");

      auto top_block_height = getTopBlockHeight();
      if (not top_block_height) {
        log_->error(
            "Failed to synchronize: could not get my top block height.");
        return;
      }

      const shared_model::interface::types::HeightType required_height =
          SynchronizationOutcomeType::kCommit == alternative_outcome
          ? msg.round.block_round
          : msg.round.block_round - 1;
      int64_t height_diff = required_height - *top_block_height;

      if (height_diff < 0) {
        log_->info(
            "Storage is already in synchronized state. Top block height is {}",
            *top_block_height);
        return;
      }

      if (height_diff == 0) {
        notifier_.get_subscriber().on_next(SynchronizationEvent{
            alternative_outcome, msg.round, msg.ledger_state});
        return;
      }

      assert(height_diff > 0);

      auto ledger_state = downloadMissingBlocks(
          *top_block_height, required_height, msg.public_keys);

      shared_model::interface::types::HeightType new_height;
      // TODO 11.04.2019 mboldyrev IR-442 use storage commit status type
      BOOST_ASSERT_MSG(ledger_state, "Commit failed!");
      if (ledger_state) {
        new_height = (*ledger_state)->top_block_info.height;
      } else {
        log_->critical(
            "Synchronization cancelled because "
            "downloaded blocks commit failed!");
        return;
      }

      const bool higher_than_expected = new_height > required_height;
      notifier_.get_subscriber().on_next(SynchronizationEvent{
          higher_than_expected ? SynchronizationOutcomeType::kCommit
                               : alternative_outcome,
          higher_than_expected ? consensus::Round{new_height, 0} : msg.round,
          ledger_state ? std::move(*ledger_state)
                       : std::unique_ptr<LedgerState>{}});
    }

    rxcpp::observable<SynchronizationEvent>
    SynchronizerImpl::on_commit_chain() {
      return notifier_.get_observable();
    }

    SynchronizerImpl::~SynchronizerImpl() {
      notifier_lifetime_.unsubscribe();
      subscription_.unsubscribe();
    }

  }  // namespace synchronizer
}  // namespace iroha
