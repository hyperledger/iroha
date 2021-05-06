/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "simulator/impl/simulator.hpp"

#include "ametsuchi/command_executor.hpp"
#include "common/bind.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "interfaces/iroha_internal/proposal.hpp"
#include "logger/logger.hpp"

namespace iroha {
  namespace simulator {

    Simulator::Simulator(
        std::unique_ptr<iroha::ametsuchi::CommandExecutor> command_executor,
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
          log_(std::move(log)) {}

    VerifiedProposalCreatorEvent Simulator::processProposal(
        network::OrderingEvent const &event) {
      if (event.proposal) {
        auto const &proposal = *getProposalUnsafe(event);
        log_->info("process proposal: {}", proposal);

        auto storage =
            ametsuchi_factory_->createTemporaryWsv(command_executor_);

        std::shared_ptr<iroha::validation::VerifiedProposalAndErrors>
            validated_proposal_and_errors =
                validator_->validate(proposal, *storage);
        ametsuchi_factory_->prepareBlock(std::move(storage));

        return VerifiedProposalCreatorEvent{
            validated_proposal_and_errors, event.round, event.ledger_state};
      } else {
        return VerifiedProposalCreatorEvent{
            boost::none, event.round, event.ledger_state};
      }
    }

    BlockCreatorEvent Simulator::processVerifiedProposal(
        VerifiedProposalCreatorEvent const &event) {
      if (event.verified_proposal_result) {
        auto verified_proposal_and_errors = getVerifiedProposalUnsafe(event);
        auto const &top_block_info = event.ledger_state->top_block_info;
        auto const &proposal = verified_proposal_and_errors->verified_proposal;
        if (proposal) {
          log_->info("process verified proposal: {}", *proposal);
        } else {
          log_->info("process verified proposal: no proposal");
        }
        std::vector<shared_model::crypto::Hash> rejected_hashes;
        rejected_hashes.reserve(
            verified_proposal_and_errors->rejected_transactions.size());
        for (const auto &rejected_tx :
             verified_proposal_and_errors->rejected_transactions) {
          rejected_hashes.push_back(rejected_tx.tx_hash);
        }
        std::shared_ptr<shared_model::interface::Block> block =
            block_factory_->unsafeCreateBlock(top_block_info.height + 1,
                                              top_block_info.top_hash,
                                              proposal->createdTime(),
                                              proposal->transactions(),
                                              std::move(rejected_hashes));
        crypto_signer_->sign(*block);
        log_->info("Created block: {}", *block);
        return BlockCreatorEvent{
            RoundData{verified_proposal_and_errors->verified_proposal, block},
            event.round,
            event.ledger_state};
      } else {
        return BlockCreatorEvent{boost::none, event.round, event.ledger_state};
      }
    }

  }  // namespace simulator
}  // namespace iroha
