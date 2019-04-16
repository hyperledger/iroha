/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_TRANSACTION_VALIDATOR_HPP
#define IROHA_PROTO_TRANSACTION_VALIDATOR_HPP

#include "validators/abstract_validator.hpp"

#include "transaction.pb.h"

namespace shared_model {
  namespace validation {

    class ProtoTransactionValidator
        : public AbstractValidator<iroha::protocol::Transaction> {
     public:
      Answer validate(const iroha::protocol::Transaction &tx) const override;
    };
  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_PROTO_TRANSACTION_VALIDATOR_HPP
