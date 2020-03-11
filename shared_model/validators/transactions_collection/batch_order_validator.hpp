/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BATCH_ORDER_VALIDATOR_HPP
#define IROHA_BATCH_ORDER_VALIDATOR_HPP

#include <optional>
#include "interfaces/common_objects/transaction_sequence_common.hpp"
#include "validators/validators_common.hpp"

namespace shared_model {
  namespace validation {
    struct ValidationError;

    class BatchOrderValidator {
     public:
      BatchOrderValidator(std::shared_ptr<ValidatorsConfig> config);

      std::optional<ValidationError> validate(
          const interface::types::TransactionsForwardCollectionType
              &transactions) const;

     private:
      const uint64_t max_batch_size_;
      const bool partial_ordered_batches_are_valid_;
    };
  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_ORDER_VALIDATOR_HPP
