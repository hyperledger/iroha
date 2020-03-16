/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_COMMAND_VALIDATOR_HPP
#define IROHA_PROTO_COMMAND_VALIDATOR_HPP

#include "validators/abstract_validator.hpp"

namespace iroha {
  namespace protocol {
    class Command;
  }
}  // namespace iroha

namespace shared_model {
  namespace validation {

    class ProtoCommandValidator
        : public AbstractValidator<iroha::protocol::Command> {
     public:
      std::optional<ValidationError> validate(
          const iroha::protocol::Command &command) const override;
    };
  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_PROTO_COMMAND_VALIDATOR_HPP
