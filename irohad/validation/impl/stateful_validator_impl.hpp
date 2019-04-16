/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_STATEFUL_VALIDATIOR_IMPL_HPP
#define IROHA_STATEFUL_VALIDATIOR_IMPL_HPP

#include "validation/stateful_validator.hpp"

#include "interfaces/iroha_internal/transaction_batch_parser.hpp"
#include "interfaces/iroha_internal/unsafe_proposal_factory.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace validation {

    /**
     * Interface for performing stateful validation
     */
    class StatefulValidatorImpl : public StatefulValidator {
     public:
      StatefulValidatorImpl(
          std::unique_ptr<shared_model::interface::UnsafeProposalFactory>
              factory,
          std::shared_ptr<shared_model::interface::TransactionBatchParser>
              batch_parser,
          logger::LoggerPtr log);

      std::unique_ptr<validation::VerifiedProposalAndErrors> validate(
          const shared_model::interface::Proposal &proposal,
          ametsuchi::TemporaryWsv &temporaryWsv) override;

     private:
      std::unique_ptr<shared_model::interface::UnsafeProposalFactory> factory_;
      std::shared_ptr<shared_model::interface::TransactionBatchParser>
          batch_parser_;
      logger::LoggerPtr log_;
    };

  }  // namespace validation
}  // namespace iroha

#endif  // IROHA_STATEFUL_VALIDATION_IMPL_HPP
