/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/protobuf/proto_block_validator.hpp"

#include <fmt/core.h>
#include <boost/range/adaptor/indexed.hpp>
#include "block.pb.h"
#include "validators/validation_error_helpers.hpp"
#include "validators/validators_common.hpp"

namespace shared_model {
  namespace validation {
    boost::optional<ValidationError> ProtoBlockValidator::validate(
        const iroha::protocol::Block &block) const {
      ValidationErrorCreator error_creator;

      // make sure version one_of field of the Block is set
      if (block.block_version_case() == iroha::protocol::Block::kBlockV1) {
        const auto &payload = block.block_v1().payload();

        for (const auto &hash : payload.rejected_transactions_hashes()
                 | boost::adaptors::indexed(1)) {
          if (not validateHexString(hash.value())) {
            error_creator.addChildError(
                ValidationError{fmt::format("Rejected transaction hash #{} {}",
                                            hash.index(),
                                            hash.value()),
                                {"Not a hex string."}});
          }
        }

        if (not validateHexString(payload.prev_block_hash())) {
          error_creator.addReason("Prev block hash has incorrect format");
        }

      } else {
        error_creator.addReason("Unknown block version.");
      }

      return std::move(error_creator).getValidationError("Protobuf Block");
    }
  }  // namespace validation
}  // namespace shared_model
