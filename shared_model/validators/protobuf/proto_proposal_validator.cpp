/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "validators/protobuf/proto_proposal_validator.hpp"

namespace shared_model {
  namespace validation {

    ProtoProposalValidator::ProtoProposalValidator(
        ProtoValidatorType transaction_validator)
        : transaction_validator_(std::move(transaction_validator)) {}

    Answer ProtoProposalValidator::validate(
        const iroha::protocol::Proposal &proposal) const {
      Answer answer;
      std::string tx_reason_name = "Protobuf Proposal";
      ReasonsGroupType reason{tx_reason_name, GroupedReasons()};

      for (const auto &tx : proposal.transactions()) {
        if (auto tx_answer = transaction_validator_->validate(tx)) {
          reason.second.emplace_back(tx_answer.reason());
        }
      }

      if (not reason.second.empty()) {
        answer.addReason(std::move(reason));
      }

      return answer;
    }

  }  // namespace validation
}  // namespace shared_model
