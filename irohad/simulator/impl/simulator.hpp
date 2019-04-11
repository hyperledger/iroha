/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SIMULATOR_HPP
#define IROHA_SIMULATOR_HPP

#include "simulator/block_creator.hpp"
#include "simulator/verified_proposal_creator.hpp"

#include <boost/optional.hpp>
#include "ametsuchi/block_query_factory.hpp"
#include "ametsuchi/temporary_factory.hpp"
#include "cryptography/crypto_provider/abstract_crypto_model_signer.hpp"
#include "interfaces/iroha_internal/unsafe_block_factory.hpp"
#include "logger/logger_fwd.hpp"
#include "network/ordering_gate.hpp"
#include "validation/stateful_validator.hpp"

namespace iroha {
  namespace simulator {

    class Simulator : public VerifiedProposalCreator, public BlockCreator {
     public:
      using CryptoSignerType = shared_model::crypto::AbstractCryptoModelSigner<
          shared_model::interface::Block>;

      Simulator(
          std::shared_ptr<network::OrderingGate> ordering_gate,
          std::shared_ptr<validation::StatefulValidator> statefulValidator,
          std::shared_ptr<ametsuchi::TemporaryFactory> factory,
          std::shared_ptr<ametsuchi::BlockQueryFactory> block_query_factory,
          std::shared_ptr<CryptoSignerType> crypto_signer,
          std::unique_ptr<shared_model::interface::UnsafeBlockFactory>
              block_factory,
          logger::LoggerPtr log);

      ~Simulator() override;

      boost::optional<std::shared_ptr<validation::VerifiedProposalAndErrors>>
      processProposal(
          const shared_model::interface::Proposal &proposal) override;

      rxcpp::observable<VerifiedProposalCreatorEvent> onVerifiedProposal()
          override;

      boost::optional<std::shared_ptr<shared_model::interface::Block>>
      processVerifiedProposal(
          const std::shared_ptr<iroha::validation::VerifiedProposalAndErrors>
              &verified_proposal_and_errors) override;

      rxcpp::observable<BlockCreatorEvent> onBlock() override;

     private:
      // internal
      rxcpp::composite_subscription notifier_lifetime_;
      rxcpp::subjects::subject<VerifiedProposalCreatorEvent> notifier_;
      rxcpp::composite_subscription block_notifier_lifetime_;
      rxcpp::subjects::subject<BlockCreatorEvent> block_notifier_;

      rxcpp::composite_subscription proposal_subscription_;
      rxcpp::composite_subscription verified_proposal_subscription_;

      std::shared_ptr<validation::StatefulValidator> validator_;
      std::shared_ptr<ametsuchi::TemporaryFactory> ametsuchi_factory_;
      std::shared_ptr<ametsuchi::BlockQueryFactory> block_query_factory_;
      std::shared_ptr<CryptoSignerType> crypto_signer_;
      std::unique_ptr<shared_model::interface::UnsafeBlockFactory>
          block_factory_;

      logger::LoggerPtr log_;

      // last block
      std::shared_ptr<const shared_model::interface::Block> last_block;
    };
  }  // namespace simulator
}  // namespace iroha

#endif  // IROHA_SIMULATOR_HPP
