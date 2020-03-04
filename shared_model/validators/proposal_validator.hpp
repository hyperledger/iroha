/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROPOSAL_VALIDATOR_HPP
#define IROHA_PROPOSAL_VALIDATOR_HPP

#include <boost/format.hpp>
#include "interfaces/common_objects/types.hpp"
#include "interfaces/iroha_internal/proposal.hpp"
#include "validators/abstract_validator.hpp"
#include "validators/validation_error_helpers.hpp"
#include "validators/validators_common.hpp"

// TODO 22/01/2018 x3medima17: write stateless validator IR-836

namespace shared_model {
  namespace validation {

    /**
     * Class that validates proposal
     */
    template <typename FieldValidator, typename TransactionsCollectionValidator>
    class ProposalValidator : public AbstractValidator<interface::Proposal> {
     public:
      ProposalValidator(std::shared_ptr<ValidatorsConfig> config)
          : transactions_collection_validator_(config),
            field_validator_(config) {}

      /**
       * Applies validation on proposal
       * @param proposal
       * @return found error if any
       */
      std::optional<ValidationError> validate(
          const interface::Proposal &proposal) const {
        ValidationErrorCreator error_creator;

        error_creator |= field_validator_.validateHeight(proposal.height());
        error_creator |= transactions_collection_validator_.validate(
            proposal.transactions(), proposal.createdTime());

        return std::move(error_creator).getValidationError("Proposal");
      }

     private:
      TransactionsCollectionValidator transactions_collection_validator_;
      FieldValidator field_validator_;
    };

  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_PROPOSAL_VALIDATOR_HPP
