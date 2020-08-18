/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/protobuf/proto_transaction_validator.hpp"

#include <ciso646>

#include "transaction.pb.h"
#include "validators/validation_error_helpers.hpp"
#include "validators/validators_common.hpp"

namespace shared_model {
  namespace validation {

    std::optional<ValidationError> ProtoTransactionValidator::validate(
        const iroha::protocol::Transaction &tx) const {
      ValidationErrorCreator error_creator;
      for (const auto &command : tx.payload().reduced_payload().commands()) {
        error_creator |= command_validator_.validate(command);
      }
      if (tx.payload().has_batch()) {
        if (not iroha::protocol::Transaction_Payload_BatchMeta::
                BatchType_IsValid(tx.payload().batch().type())) {
          error_creator.addReason("Invalid batch type.");
        }
      }
      return std::move(error_creator)
          .getValidationError("Protobuf Transaction");
    }
  }  // namespace validation
}  // namespace shared_model
