/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "simulator/impl/simulator.hpp"

#include <boost/range/adaptor/transformed.hpp>
#include "ametsuchi/command_executor.hpp"
#include "common/bind.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "interfaces/iroha_internal/proposal.hpp"
#include "logger/logger.hpp"

namespace iroha {
  namespace simulator {

    Simulator::Simulator(
        std::unique_ptr<iroha::ametsuchi::CommandExecutor> command_executor,
        std::shared_ptr<network::OrderingGate> ordering_gate,
        std::shared_ptr<validation::StatefulValidator> statefulValidator,
        std::shared_ptr<ametsuchi::TemporaryFactory> factory,
        std::shared_ptr<CryptoSignerType> crypto_signer,
        std::unique_ptr<shared_model::interface::UnsafeBlockFactory>
            block_factory,
        logger::LoggerPtr log)
        : command_executor_(std::move(command_executor)),
          validator_(std::move(statefulValidator)),
          ametsuchi_factory_(std::move(factory)),
          crypto_signer_(std::move(crypto_signer)),
          block_factory_(std::move(block_factory)),
          log_(std::move(log)),
          on_proposal_subscription_(std::make_shared<OnProposalSubscriber>(
              getSubscription()
                  ->getEngine<EventTypes, network::OrderingEvent>())),
          on_verified_proposal_subscription_(
              std::make_shared<OnVerifiedProposalSubscriber>(
                  getSubscription()
                      ->getEngine<EventTypes,
                                  VerifiedProposalCreatorEvent>())) {
      on_proposal_subscription_->setCallback(
          [this](auto, auto &, auto const key, network::OrderingEvent event) {
            assert(EventTypes::kOnProposal == key);
            if (event.proposal) {
              auto validated_proposal_and_errors =
                  this->processProposal(*getProposalUnsafe(event));

              getSubscription()->notify(
                  EventTypes::kOnVerifiedProposal,
                  VerifiedProposalCreatorEvent{validated_proposal_and_errors,
                                               event.round,
                                               event.ledger_state});
            } else {
              getSubscription()->notify(
                  EventTypes::kOnVerifiedProposal,
                  VerifiedProposalCreatorEvent{
                      boost::none, event.round, event.ledger_state});
            }
          });

      on_verified_proposal_subscription_->setCallback(
          [this](auto,
                 auto &,
                 auto const key,
                 VerifiedProposalCreatorEvent event) {
            assert(EventTypes::kOnVerifiedProposal == key);
            if (event.verified_proposal_result) {
              auto proposal_and_errors = getVerifiedProposalUnsafe(event);
              auto block = this->processVerifiedProposal(
                  proposal_and_errors, event.ledger_state->top_block_info);
              if (block) {
                getSubscription()->notify(
                    EventTypes::kOnBlockCreatorEvent,
                    BlockCreatorEvent{
                        RoundData{proposal_and_errors->verified_proposal,
                                  *block},
                        event.round,
                        event.ledger_state});
              }
            } else {
              getSubscription()->notify(
                  EventTypes::kOnBlockCreatorEvent,
                  BlockCreatorEvent{
                      boost::none, event.round, event.ledger_state});
            }
          });

      on_proposal_subscription_->subscribe<SubscriptionEngineHandlers::kYac>(
          0, EventTypes::kOnProposal);
      on_verified_proposal_subscription_
          ->subscribe<SubscriptionEngineHandlers::kYac>(
              0, EventTypes::kOnVerifiedProposal);
    }

    std::shared_ptr<validation::VerifiedProposalAndErrors>
    Simulator::processProposal(
        const shared_model::interface::Proposal &proposal) {
      log_->info("process proposal: {}", proposal);

      auto storage = ametsuchi_factory_->createTemporaryWsv(command_executor_);

      std::shared_ptr<iroha::validation::VerifiedProposalAndErrors>
          validated_proposal_and_errors =
              validator_->validate(proposal, *storage);
      ametsuchi_factory_->prepareBlock(std::move(storage));

      return validated_proposal_and_errors;
    }

    boost::optional<std::shared_ptr<shared_model::interface::Block>>
    Simulator::processVerifiedProposal(
        const std::shared_ptr<iroha::validation::VerifiedProposalAndErrors>
            &verified_proposal_and_errors,
        const TopBlockInfo &top_block_info) {
      const auto &proposal = verified_proposal_and_errors->verified_proposal;
      if (proposal)
        log_->info("process verified proposal: {}", *proposal);
      else
        log_->info("process verified proposal: no proposal");
      std::vector<shared_model::crypto::Hash> rejected_hashes;
      for (const auto &rejected_tx :
           verified_proposal_and_errors->rejected_transactions) {
        rejected_hashes.push_back(rejected_tx.tx_hash);
      }
      std::shared_ptr<shared_model::interface::Block> block =
          block_factory_->unsafeCreateBlock(top_block_info.height + 1,
                                            top_block_info.top_hash,
                                            proposal->createdTime(),
                                            proposal->transactions(),
                                            rejected_hashes);
      crypto_signer_->sign(*block);
      log_->info("Created block: {}", *block);
      return block;
    }

  }  // namespace simulator
}  // namespace iroha
