/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_TRANSACTION_BATCH_VALIDATOR_HPP
#define IROHA_TRANSACTION_BATCH_VALIDATOR_HPP

#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "validators/abstract_validator.hpp"
#include "validators/validators_common.hpp"

namespace shared_model {
  namespace validation {

    class BatchValidator
        : public AbstractValidator<interface::TransactionBatch> {
     public:
      BatchValidator(std::shared_ptr<ValidatorsConfig> config);

      Answer validate(const interface::TransactionBatch &batch) const override;

     private:
      Answer validate(interface::types::TransactionsForwardCollectionType
                          transactions) const;

      const uint64_t max_batch_size_;
    };
  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_TRANSACTION_BATCH_VALIDATOR_HPP
