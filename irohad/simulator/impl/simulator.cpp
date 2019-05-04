/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "simulator/impl/simulator.hpp"

#include <boost/range/adaptor/transformed.hpp>
#include "common/bind.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "interfaces/iroha_internal/proposal.hpp"
#include "logger/logger.hpp"

namespace iroha {
  namespace simulator {

    Simulator::Simulator(
        std::shared_ptr<network::OrderingGate> ordering_gate,
        std::shared_ptr<validation::StatefulValidator> statefulValidator,
        std::shared_ptr<ametsuchi::TemporaryFactory> factory,
        std::shared_ptr<ametsuchi::BlockQueryFactory> block_query_factory,
        std::shared_ptr<CryptoSignerType> crypto_signer,
        std::unique_ptr<shared_model::interface::UnsafeBlockFactory>
            block_factory,
        logger::LoggerPtr log)
        : notifier_(notifier_lifetime_),
          block_notifier_(block_notifier_lifetime_),
          validator_(std::move(statefulValidator)),
          ametsuchi_factory_(std::move(factory)),
          block_query_factory_(block_query_factory),
          crypto_signer_(std::move(crypto_signer)),
          block_factory_(std::move(block_factory)),
          log_(std::move(log)) {
      ordering_gate->onProposal().subscribe(
          proposal_subscription_, [this](const network::OrderingEvent &event) {
            if (event.proposal) {
              auto validated_proposal_and_errors =
                  this->processProposal(*getProposalUnsafe(event));

              if (validated_proposal_and_errors) {
                notifier_.get_subscriber().on_next(
                    VerifiedProposalCreatorEvent{*validated_proposal_and_errors,
                                                 event.round,
                                                 event.ledger_state});
              }
            } else {
              notifier_.get_subscriber().on_next(VerifiedProposalCreatorEvent{
                  boost::none, event.round, event.ledger_state});
            }
          });

      notifier_.get_observable().subscribe(
          verified_proposal_subscription_,
          [this](const VerifiedProposalCreatorEvent &event) {
            if (event.verified_proposal_result) {
              auto proposal_and_errors = getVerifiedProposalUnsafe(event);
              auto block = this->processVerifiedProposal(proposal_and_errors);
              if (block) {
                block_notifier_.get_subscriber().on_next(BlockCreatorEvent{
                    RoundData{proposal_and_errors->verified_proposal, *block},
                    event.round,
                    event.ledger_state});
              }
            } else {
              block_notifier_.get_subscriber().on_next(BlockCreatorEvent{
                  boost::none, event.round, event.ledger_state});
            }
          });
    }

    Simulator::~Simulator() {
      notifier_lifetime_.unsubscribe();
      block_notifier_lifetime_.unsubscribe();
      proposal_subscription_.unsubscribe();
      verified_proposal_subscription_.unsubscribe();
    }

    rxcpp::observable<VerifiedProposalCreatorEvent>
    Simulator::onVerifiedProposal() {
      return notifier_.get_observable();
    }

    boost::optional<std::shared_ptr<validation::VerifiedProposalAndErrors>>
    Simulator::processProposal(
        const shared_model::interface::Proposal &proposal) {
      log_->info("process proposal");

      // Get last block from local ledger
      if (auto block_query_opt = block_query_factory_->createBlockQuery()) {
        auto block_var =
            (*block_query_opt)
                ->getBlock((*block_query_opt)->getTopBlockHeight());
        if (auto e = boost::get<expected::Error<std::string>>(&block_var)) {
          log_->warn("Could not fetch last block: " + e->error);
          return boost::none;
        }

        last_block = std::move(
            boost::get<expected::Value<
                std::unique_ptr<shared_model::interface::Block>>>(&block_var)
                ->value);
      } else {
        log_->error("could not create block query");
        return boost::none;
      }

      if (last_block->height() + 1 != proposal.height()) {
        log_->warn("Last block height: {}, proposal height: {}",
                   last_block->height(),
                   proposal.height());
        return boost::none;
      }

      auto temporary_wsv_var = ametsuchi_factory_->createTemporaryWsv();
      if (auto e =
              boost::get<expected::Error<std::string>>(&temporary_wsv_var)) {
        log_->error("could not create temporary storage: {}", e->error);
        return boost::none;
      }

      auto storage = std::move(
          boost::get<expected::Value<std::unique_ptr<ametsuchi::TemporaryWsv>>>(
              &temporary_wsv_var)
              ->value);

      std::shared_ptr<iroha::validation::VerifiedProposalAndErrors>
          validated_proposal_and_errors =
              validator_->validate(proposal, *storage);
      ametsuchi_factory_->prepareBlock(std::move(storage));

      return validated_proposal_and_errors;
    }

    boost::optional<std::shared_ptr<shared_model::interface::Block>>
    Simulator::processVerifiedProposal(
        const std::shared_ptr<iroha::validation::VerifiedProposalAndErrors>
            &verified_proposal_and_errors) {
      log_->info("process verified proposal");

      auto height = block_query_factory_->createBlockQuery() |
          [&](const auto &block_query) {
            return block_query->getTopBlockHeight() + 1;
          };
      if (not height) {
        log_->error("Unable to query top block height");
        return boost::none;
      }
      const auto &proposal = verified_proposal_and_errors->verified_proposal;
      std::vector<shared_model::crypto::Hash> rejected_hashes;
      for (const auto &rejected_tx :
           verified_proposal_and_errors->rejected_transactions) {
        rejected_hashes.push_back(rejected_tx.tx_hash);
      }
      std::shared_ptr<shared_model::interface::Block> block =
          block_factory_->unsafeCreateBlock(height,
                                            last_block->hash(),
                                            proposal->createdTime(),
                                            proposal->transactions(),
                                            rejected_hashes);
      crypto_signer_->sign(*block);

      // TODO 2019-03-15 andrei: IR-404 Make last_block an explicit dependency
      last_block.reset();

      return block;
    }

    rxcpp::observable<BlockCreatorEvent> Simulator::onBlock() {
      return block_notifier_.get_observable();
    }

  }  // namespace simulator
}  // namespace iroha
