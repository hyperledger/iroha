/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TRANSACTIONS_COLLECTION_VALIDATOR_HPP
#define IROHA_TRANSACTIONS_COLLECTION_VALIDATOR_HPP

#include "interfaces/common_objects/transaction_sequence_common.hpp"
#include "interfaces/common_objects/types.hpp"
#include "validators/answer.hpp"
#include "validators/transaction_batch_validator.hpp"

namespace shared_model {
  namespace validation {

    /**
     * Validator of transaction's collection, this is not fair implementation
     * now, it always returns empty answer
     */
    template <typename TransactionValidator, bool CollectionCanBeEmpty = false>
    class TransactionsCollectionValidator {
     protected:
      TransactionValidator transaction_validator_;
      std::shared_ptr<AbstractValidator<interface::TransactionBatch>>
          batch_validator_;
      bool txs_duplicates_allowed_;

     private:
      template <typename Validator>
      Answer validateImpl(
          const interface::types::TransactionsForwardCollectionType
              &transactions,
          Validator &&validator) const;

      explicit TransactionsCollectionValidator(
          std::shared_ptr<ValidatorsConfig> config,
          TransactionValidator transactions_validator);

     public:
      explicit TransactionsCollectionValidator(
          std::shared_ptr<ValidatorsConfig> config)
          : TransactionsCollectionValidator(config,
                                            TransactionValidator(config)) {}

      // TODO: IR-1505, igor-egorov, 2018-07-05 Remove method below when
      // proposal and block will return collection of shared transactions
      /**
       * Validates collection of transactions
       * @param transactions collection of transactions
       * @return Answer containing errors if any
       */
      Answer validate(const interface::types::TransactionsForwardCollectionType
                          &transactions) const;

      Answer validate(
          const interface::types::SharedTxsCollectionType &transactions) const;

      Answer validate(const interface::types::TransactionsForwardCollectionType
                          &transactions,
                      interface::types::TimestampType current_timestamp) const;

      Answer validate(
          const interface::types::SharedTxsCollectionType &transactions,
          interface::types::TimestampType current_timestamp) const;

      const TransactionValidator &getTransactionValidator() const;
    };

  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_TRANSACTIONS_COLLECTION_VALIDATOR_HPP
