/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ANY_ORDER_VALIDATOR_HPP
#define IROHA_ANY_ORDER_VALIDATOR_HPP

#include "order_validator.hpp"

namespace shared_model {
  namespace validation {
    class AnyOrderValidator : public OrderValidator {
     public:
      Answer validate(const interface::types::SharedTxsCollectionType
                          &transactions) const override {
        return Answer();
      };
    };
  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_ANY_ORDER_VALIDATOR_HPP
