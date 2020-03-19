/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_TRANSACTION_BATCH_VALIDATOR_HPP
#define IROHA_TRANSACTION_BATCH_VALIDATOR_HPP

#include "validators/abstract_validator.hpp"

#include <memory>

#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "validators/validators_common.hpp"

namespace shared_model {
  namespace validation {

    template <typename BatchOrderValidator>
    class BatchValidator
        : public AbstractValidator<interface::TransactionBatch> {
     public:
      BatchValidator(std::shared_ptr<ValidatorsConfig> config);

      std::optional<ValidationError> validate(
          const interface::TransactionBatch &batch) const override;

     private:
      BatchOrderValidator batch_order_validator_;
    };
  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_TRANSACTION_BATCH_VALIDATOR_HPP
