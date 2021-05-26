/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SIMULATOR_HPP
#define IROHA_SIMULATOR_HPP

#include "simulator/block_creator.hpp"
#include "simulator/verified_proposal_creator.hpp"

#include "ametsuchi/temporary_factory.hpp"
#include "cryptography/crypto_provider/abstract_crypto_model_signer.hpp"
#include "interfaces/iroha_internal/unsafe_block_factory.hpp"
#include "logger/logger_fwd.hpp"
#include "network/ordering_gate.hpp"
#include "validation/stateful_validator.hpp"

namespace iroha {
  namespace ametsuchi {
    class CommandExecutor;
  }

  namespace simulator {

    class Simulator : public VerifiedProposalCreator, public BlockCreator {
     public:
      using CryptoSignerType = shared_model::crypto::AbstractCryptoModelSigner<
          shared_model::interface::Block>;

      Simulator(
          // TODO IR-598 mboldyrev 2019.08.10: remove command_executor from
          // Simulator
          std::unique_ptr<iroha::ametsuchi::CommandExecutor> command_executor,
          std::shared_ptr<validation::StatefulValidator> statefulValidator,
          std::shared_ptr<ametsuchi::TemporaryFactory> factory,
          std::shared_ptr<CryptoSignerType> crypto_signer,
          std::unique_ptr<shared_model::interface::UnsafeBlockFactory>
              block_factory,
          logger::LoggerPtr log);

      VerifiedProposalCreatorEvent processProposal(
          network::OrderingEvent const &event) override;

      BlockCreatorEvent processVerifiedProposal(
          VerifiedProposalCreatorEvent const &event) override;

     private:
      // internal
      std::shared_ptr<iroha::ametsuchi::CommandExecutor> command_executor_;

      std::shared_ptr<validation::StatefulValidator> validator_;
      std::shared_ptr<ametsuchi::TemporaryFactory> ametsuchi_factory_;
      std::shared_ptr<CryptoSignerType> crypto_signer_;
      std::unique_ptr<shared_model::interface::UnsafeBlockFactory>
          block_factory_;

      logger::LoggerPtr log_;
    };
  }  // namespace simulator
}  // namespace iroha

#endif  // IROHA_SIMULATOR_HPP
