/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_AMOUNT_TRUE_VALIDATOR_HPP
#define IROHA_SHARED_MODEL_AMOUNT_TRUE_VALIDATOR_HPP

#include "interfaces/common_objects/amount.hpp"
#include "validators/answer.hpp"

namespace shared_model {
  namespace validation {

    /**
     * Class that validates fields of commands, concrete queries, transaction,
     * and query
     */
    class AmountTrueValidator {
     public:
      void validateAmount(ReasonsGroupType &reason,
                          const interface::Amount &amount) const {};
    };
  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_AMOUNT_TRUE_VALIDATOR_HPP
