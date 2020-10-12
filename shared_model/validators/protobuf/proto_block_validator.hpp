/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_BLOCK_VALIDATOR_HPP
#define IROHA_PROTO_BLOCK_VALIDATOR_HPP

#include "validators/abstract_validator.hpp"

namespace iroha::protocol {
  class Block;
  class Block_v1;
}  // namespace iroha::protocol

namespace shared_model::validation {
  class ProtoBlockValidator
      : public AbstractValidator<iroha::protocol::Block>,
        public AbstractValidator<iroha::protocol::Block_v1> {
   public:
    std::optional<ValidationError> validate(
        iroha::protocol::Block const &block) const override;
    std::optional<ValidationError> validate(
        iroha::protocol::Block_v1 const &block) const override;
  };
}  // namespace shared_model::validation

#endif  // IROHA_PROTO_BLOCK_VALIDATOR_HPP
