/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_VALIDATION_STATEFUL_VALIDATOR_HPP
#define IROHA_VALIDATION_STATEFUL_VALIDATOR_HPP

#include "ametsuchi/temporary_wsv.hpp"
#include "interfaces/iroha_internal/proposal.hpp"
#include "validation/stateful_validator_common.hpp"

namespace iroha {
  namespace validation {

    /**
     * Interface for performing stateful validation
     */
    class StatefulValidator {
     public:
      virtual ~StatefulValidator() = default;

      // TODO andrei 16.10.18 IR-1761 Rename methods in validators

      /**
       * Function perform stateful validation on proposal
       * and return proposal with valid transactions
       * @param proposal - proposal for validation
       * @param wsv  - temporary wsv for validation,
       * this wsv not affected on ledger,
       * all changes after removing wsv will be ignored
       * @return proposal with valid transactions and errors, which appeared in
       * a process of validating
       */
      virtual std::unique_ptr<VerifiedProposalAndErrors> validate(
          const shared_model::interface::Proposal &proposal,
          ametsuchi::TemporaryWsv &temporaryWsv) = 0;
    };
  }  // namespace validation
}  // namespace iroha
#endif  // IROHA_VALIDATION_STATELESS_VALIDATOR_HPP
