/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/protobuf/proto_transaction_validator.hpp"

#include "transaction.pb.h"
#include "validators/validators_common.hpp"

namespace shared_model {
  namespace validation {

    Answer ProtoTransactionValidator::validate(
        const iroha::protocol::Transaction &tx) const {
      Answer answer;
      std::string tx_reason_name = "Protobuf Transaction";
      ReasonsGroupType reason(tx_reason_name, GroupedReasons());
      for (const auto &command : tx.payload().reduced_payload().commands()) {
        auto result = command_validator_.validate(command);
        if (result.hasErrors()) {
          reason.second.push_back(result.reason());
        }
      }
      if (tx.payload().has_batch()) {
        if (not iroha::protocol::Transaction_Payload_BatchMeta::
                BatchType_IsValid(tx.payload().batch().type())) {
          reason.second.emplace_back("Invalid batch type");
        }
      }
      if (not reason.second.empty()) {
        answer.addReason(std::move(reason));
      }
      return answer;
    }
  }  // namespace validation
}  // namespace shared_model
