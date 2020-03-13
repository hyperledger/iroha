/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_TRANSACTION_VALIDATOR_HPP
#define IROHA_PROTO_TRANSACTION_VALIDATOR_HPP

#include "validators/abstract_validator.hpp"

#include "validators/protobuf/proto_command_validator.hpp"

namespace iroha {
  namespace protocol {
    class Transaction;
  }
}  // namespace iroha

namespace shared_model {
  namespace validation {

    class ProtoTransactionValidator
        : public AbstractValidator<iroha::protocol::Transaction> {
     public:
      std::optional<ValidationError> validate(
          const iroha::protocol::Transaction &tx) const override;

     private:
      ProtoCommandValidator command_validator_;
    };
  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_PROTO_TRANSACTION_VALIDATOR_HPP
