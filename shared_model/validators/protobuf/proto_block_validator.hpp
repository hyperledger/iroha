/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_BLOCK_VALIDATOR_HPP
#define IROHA_PROTO_BLOCK_VALIDATOR_HPP

#include "validators/abstract_validator.hpp"

namespace iroha {
  namespace protocol {
    class Block;
  }
}  // namespace iroha

namespace shared_model {
  namespace validation {
    class ProtoBlockValidator
        : public AbstractValidator<iroha::protocol::Block> {
     public:
      boost::optional<ValidationError> validate(
          const iroha::protocol::Block &block) const override;
    };
  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_PROTO_BLOCK_VALIDATOR_HPP
