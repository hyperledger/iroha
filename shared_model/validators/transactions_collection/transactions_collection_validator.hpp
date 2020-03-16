/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TRANSACTIONS_COLLECTION_VALIDATOR_HPP
#define IROHA_TRANSACTIONS_COLLECTION_VALIDATOR_HPP

#include "interfaces/common_objects/transaction_sequence_common.hpp"
#include "interfaces/common_objects/types.hpp"
#include "validators/transaction_batch_validator.hpp"
#include "validators/validation_error.hpp"

namespace shared_model {
  namespace validation {

    /**
     * Validator of transaction's collection, this is not fair implementation
     * now, it always returns empty answer
     */
    template <typename TransactionValidator,
              typename OrderValidator,
              bool CollectionCanBeEmpty>
    class TransactionsCollectionValidator {
     protected:
      TransactionValidator transaction_validator_;
      OrderValidator order_validator_;
      bool txs_duplicates_allowed_;

     private:
      template <typename Validator>
      std::optional<ValidationError> validateImpl(
          const interface::types::TransactionsForwardCollectionType
              &transactions,
          Validator &&validator) const;

     public:
      TransactionsCollectionValidator(std::shared_ptr<ValidatorsConfig> config);

      // TODO: IR-1505, igor-egorov, 2018-07-05 Remove method below when
      // proposal and block will return collection of shared transactions
      /**
       * Validates collection of transactions
       * @param transactions collection of transactions
       * @return validation error, if any
       */
      std::optional<ValidationError> validate(
          const interface::types::TransactionsForwardCollectionType
              &transactions) const;

      std::optional<ValidationError> validate(
          const interface::types::SharedTxsCollectionType &transactions) const;

      std::optional<ValidationError> validate(
          const interface::types::TransactionsForwardCollectionType
              &transactions,
          interface::types::TimestampType current_timestamp) const;

      std::optional<ValidationError> validate(
          const interface::types::SharedTxsCollectionType &transactions,
          interface::types::TimestampType current_timestamp) const;

      const TransactionValidator &getTransactionValidator() const;
    };

  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_TRANSACTIONS_COLLECTION_VALIDATOR_HPP
