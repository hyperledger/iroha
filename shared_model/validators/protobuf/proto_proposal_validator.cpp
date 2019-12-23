/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "validators/protobuf/proto_proposal_validator.hpp"

#include <fmt/core.h>
#include <boost/range/adaptor/indexed.hpp>
#include "proposal.pb.h"
#include "validators/validation_error_helpers.hpp"

namespace shared_model {
  namespace validation {

    ProtoProposalValidator::ProtoProposalValidator(
        ProtoValidatorType transaction_validator)
        : transaction_validator_(std::move(transaction_validator)) {}

    std::optional<ValidationError> ProtoProposalValidator::validate(
        const iroha::protocol::Proposal &proposal) const {
      ValidationErrorCreator error_creator;

      for (auto tx : proposal.transactions() | boost::adaptors::indexed(1)) {
        ValidationErrorCreator tx_error_creator;
        tx_error_creator |= transaction_validator_->validate(tx.value());
        error_creator |=
            std::move(tx_error_creator)
                .getValidationErrorWithGeneratedName(
                    [&] { return fmt::format("Transaction #{}", tx.index()); });
      }

      return std::move(error_creator).getValidationError("Protobuf Proposal");
    }

  }  // namespace validation
}  // namespace shared_model
