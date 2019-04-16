/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROPOSAL_VALIDATOR_HPP
#define IROHA_PROPOSAL_VALIDATOR_HPP

#include <boost/format.hpp>
#include <regex>
#include "datetime/time.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/iroha_internal/proposal.hpp"
#include "validators/abstract_validator.hpp"
#include "validators/answer.hpp"
#include "validators/container_validator.hpp"

// TODO 22/01/2018 x3medima17: write stateless validator IR-836

namespace shared_model {
  namespace validation {

    /**
     * Class that validates proposal
     */
    template <typename FieldValidator, typename TransactionsCollectionValidator>
    class ProposalValidator
        : public ContainerValidator<interface::Proposal,
                                    FieldValidator,
                                    TransactionsCollectionValidator>,
          public AbstractValidator<interface::Proposal> {
     public:
      using ContainerValidator<
          interface::Proposal,
          FieldValidator,
          TransactionsCollectionValidator>::ContainerValidator;
      /**
       * Applies validation on proposal
       * @param proposal
       * @return Answer containing found error if any
       */
      Answer validate(const interface::Proposal &prop) const {
        return ContainerValidator<
            interface::Proposal,
            FieldValidator,
            TransactionsCollectionValidator>::validate(prop, "Proposal");
      }
    };

  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_PROPOSAL_VALIDATOR_HPP
