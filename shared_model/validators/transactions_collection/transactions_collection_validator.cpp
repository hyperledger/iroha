/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/transactions_collection/transactions_collection_validator.hpp"

#include <algorithm>
#include <unordered_map>

#include <fmt/core.h>
#include <boost/range/adaptor/indexed.hpp>
#include <boost/range/adaptor/indirected.hpp>
#include "interfaces/common_objects/transaction_sequence_common.hpp"
#include "interfaces/iroha_internal/transaction_batch_impl.hpp"
#include "interfaces/iroha_internal/transaction_batch_parser_impl.hpp"
#include "validators/default_validator.hpp"
#include "validators/field_validator.hpp"
#include "validators/transaction_validator.hpp"
#include "validators/transactions_collection/batch_order_validator.hpp"
#include "validators/validation_error_helpers.hpp"

namespace shared_model {
  namespace validation {

    template <typename TransactionValidator,
              typename OrderValidator,
              bool CollectionCanBeEmpty>
    TransactionsCollectionValidator<TransactionValidator,
                                    OrderValidator,
                                    CollectionCanBeEmpty>::
        TransactionsCollectionValidator(
            std::shared_ptr<ValidatorsConfig> config)
        : transaction_validator_(config),
          order_validator_(config),
          txs_duplicates_allowed_(config->txs_duplicates_allowed) {}

    template <typename TransactionValidator,
              typename OrderValidator,
              bool CollectionCanBeEmpty>
    template <typename Validator>
    std::optional<ValidationError>
    TransactionsCollectionValidator<TransactionValidator,
                                    OrderValidator,
                                    CollectionCanBeEmpty>::
        validateImpl(const interface::types::TransactionsForwardCollectionType
                         &transactions,
                     Validator &&validator) const {
      ValidationErrorCreator error_creator;

      if (boost::empty(transactions)) {
        if (not CollectionCanBeEmpty) {
          error_creator.addReason("Transaction sequence is empty");
        }
        return std::move(error_creator).getValidationError("Transaction list");
      }

      std::unordered_map<shared_model::crypto::Hash,
                         size_t,
                         shared_model::crypto::Hash::Hasher>
          tx_number_by_hash;
      for (auto tx : transactions | boost::adaptors::indexed(1)) {
        ValidationErrorCreator tx_error_creator;
        if (not txs_duplicates_allowed_) {
          auto emplace_result =
              tx_number_by_hash.emplace(tx.value().hash(), tx.index());
          if (not emplace_result.second) {
            tx_error_creator.addReason(fmt::format(
                "Duplicates transaction #{}.", emplace_result.first->second));
          }
        }
        tx_error_creator |= std::forward<Validator>(validator)(tx.value());
        error_creator |=
            std::move(tx_error_creator)
                .getValidationErrorWithGeneratedName([&] {
                  return fmt::format("Transaction #{} with hash {}",
                                     tx.index(),
                                     tx.value().hash().hex());
                });
      }

      interface::TransactionBatchParserImpl batch_parser;
      for (auto &batch : batch_parser.parseBatches(transactions)) {
        error_creator |= order_validator_.validate(batch);
      }

      return std::move(error_creator).getValidationError("Transaction list");
    }

    template <typename TransactionValidator,
              typename OrderValidator,
              bool CollectionCanBeEmpty>
    std::optional<ValidationError> TransactionsCollectionValidator<
        TransactionValidator,
        OrderValidator,
        CollectionCanBeEmpty>::validate(const shared_model::interface::types::
                                            TransactionsForwardCollectionType
                                                &transactions) const {
      return validateImpl(transactions, [this](const auto &tx) {
        return transaction_validator_.validate(tx);
      });
    }

    template <typename TransactionValidator,
              typename OrderValidator,
              bool CollectionCanBeEmpty>
    std::optional<ValidationError>
    TransactionsCollectionValidator<TransactionValidator,
                                    OrderValidator,
                                    CollectionCanBeEmpty>::
        validate(const shared_model::interface::types::SharedTxsCollectionType
                     &transactions) const {
      return validate(transactions | boost::adaptors::indirected);
    }

    template <typename TransactionValidator,
              typename OrderValidator,
              bool CollectionCanBeEmpty>
    std::optional<ValidationError>
    TransactionsCollectionValidator<TransactionValidator,
                                    OrderValidator,
                                    CollectionCanBeEmpty>::
        validate(const interface::types::TransactionsForwardCollectionType
                     &transactions,
                 interface::types::TimestampType current_timestamp) const {
      return validateImpl(
          transactions, [this, current_timestamp](const auto &tx) {
            return transaction_validator_.validate(tx, current_timestamp);
          });
    }

    template <typename TransactionValidator,
              typename OrderValidator,
              bool CollectionCanBeEmpty>
    std::optional<ValidationError>
    TransactionsCollectionValidator<TransactionValidator,
                                    OrderValidator,
                                    CollectionCanBeEmpty>::
        validate(const interface::types::SharedTxsCollectionType &transactions,
                 interface::types::TimestampType current_timestamp) const {
      return validate(transactions | boost::adaptors::indirected,
                      current_timestamp);
    }

    template <typename TransactionValidator,
              typename OrderValidator,
              bool CollectionCanBeEmpty>
    const TransactionValidator &TransactionsCollectionValidator<
        TransactionValidator,
        OrderValidator,
        CollectionCanBeEmpty>::getTransactionValidator() const {
      return transaction_validator_;
    }

    template class TransactionsCollectionValidator<
        DefaultUnsignedTransactionValidator,
        BatchOrderValidator,
        true>;

    template class TransactionsCollectionValidator<
        DefaultUnsignedTransactionValidator,
        BatchOrderValidator,
        false>;

    template class TransactionsCollectionValidator<
        DefaultSignedTransactionValidator,
        BatchOrderValidator,
        true>;

    template class TransactionsCollectionValidator<
        DefaultSignedTransactionValidator,
        BatchOrderValidator,
        false>;

  }  // namespace validation
}  // namespace shared_model
