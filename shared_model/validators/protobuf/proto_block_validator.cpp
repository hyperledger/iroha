/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/protobuf/proto_block_validator.hpp"

#include <ciso646>

#include <fmt/core.h>
#include <boost/range/adaptor/indexed.hpp>
#include "block.pb.h"
#include "validators/validation_error_helpers.hpp"
#include "validators/validators_common.hpp"

namespace shared_model::validation {
  std::optional<ValidationError> ProtoBlockValidator::validate(
      iroha::protocol::Block const &block) const {
    ValidationErrorCreator error_creator;

    // make sure version one_of field of the Block is set
    if (block.block_version_case() == iroha::protocol::Block::kBlockV1) {
      return validate(block.block_v1());
    } else {
      error_creator.addReason("Unknown block version.");
    }

    return std::move(error_creator).getValidationError("Protobuf Block");
  }
  std::optional<ValidationError> ProtoBlockValidator::validate(
      iroha::protocol::Block_v1 const &block) const {
    ValidationErrorCreator error_creator;

    const auto &payload = block.payload();

    for (auto hash :
         payload.rejected_transactions_hashes() | boost::adaptors::indexed(1)) {
      if (not validateHexString(hash.value())) {
        error_creator.addChildError(ValidationError{
            fmt::format(
                "Rejected transaction hash #{} {}", hash.index(), hash.value()),
            {"Not a hex string."}});
      }
    }

    if (not validateHexString(payload.prev_block_hash())) {
      error_creator.addReason("Prev block hash has incorrect format");
    }

    return std::move(error_creator).getValidationError("Protobuf Block");
  }
}  // namespace shared_model::validation
