/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/transactions_collection/transactions_collection_validator.hpp"

#include <algorithm>

#include <boost/format.hpp>
#include <boost/range/adaptor/indirected.hpp>
#include "interfaces/common_objects/transaction_sequence_common.hpp"
#include "interfaces/iroha_internal/transaction_batch_impl.hpp"
#include "interfaces/iroha_internal/transaction_batch_parser_impl.hpp"
#include "validators/default_validator.hpp"
#include "validators/field_validator.hpp"
#include "validators/signable_validator.hpp"
#include "validators/transaction_validator.hpp"
#include "validators/transactions_collection/batch_order_validator.hpp"

namespace shared_model {
  namespace validation {

    template <typename TransactionValidator, bool CollectionCanBeEmpty>
    TransactionsCollectionValidator<TransactionValidator,
                                    CollectionCanBeEmpty>::
        TransactionsCollectionValidator(
            std::shared_ptr<ValidatorsConfig> config,
            TransactionValidator transactions_validator)
        : transaction_validator_(std::move(transactions_validator)),
          batch_validator_(std::make_shared<BatchValidator>(config)),
          txs_duplicates_allowed_(config->txs_duplicates_allowed) {}

    template <typename TransactionValidator, bool CollectionCanBeEmpty>
    template <typename Validator>
    Answer TransactionsCollectionValidator<TransactionValidator,
                                           CollectionCanBeEmpty>::
        validateImpl(const interface::types::TransactionsForwardCollectionType
                         &transactions,
                     Validator &&validator) const {
      Answer res;
      ReasonsGroupType reason;
      reason.first = "Transaction list";

      auto tx_collection_empty = boost::empty(transactions);
      if (tx_collection_empty and CollectionCanBeEmpty) {
        return res;
      }
      if (tx_collection_empty) {
        reason.second.emplace_back("Transaction sequence can not be empty");
        res.addReason(std::move(reason));
        return res;
      }

      for (const auto &tx : transactions) {
        auto answer = std::forward<Validator>(validator)(tx);
        if (answer.hasErrors()) {
          auto message =
              (boost::format("Tx %s : %s") % tx.hash().hex() % answer.reason())
                  .str();
          reason.second.push_back(message);
        }
      }

      if (!txs_duplicates_allowed_) {
        std::unordered_set<std::string> hashes = {};
        for (const auto &tx : transactions) {
          if (hashes.count(tx.hash().hex())) {
            auto message =
                (boost::format("Transaction with hash %s has already appeared "
                               "within a collection")
                 % tx.hash().hex())
                    .str();
            reason.second.push_back(message);
          } else {
            hashes.insert(tx.hash().hex());
          }
        }
      }

      interface::TransactionBatchParserImpl batch_parser;
      auto batches = batch_parser.parseBatches(transactions);
      for (auto &batch : batches) {
        interface::types::SharedTxsCollectionType batch_transactions;
        for (auto &tx : batch) {
          batch_transactions.emplace_back(
              const_cast<interface::Transaction *>(&tx), [](auto) {});
        }
        std::unique_ptr<interface::TransactionBatch> batch_ptr =
            std::make_unique<interface::TransactionBatchImpl>(
                batch_transactions);
        if (auto answer = batch_validator_->validate(*batch_ptr)) {
          reason.second.emplace_back(answer.reason());
        }
      }

      if (not reason.second.empty()) {
        res.addReason(std::move(reason));
      }
      return res;
    }

    template <typename TransactionValidator, bool CollectionCanBeEmpty>
    Answer TransactionsCollectionValidator<TransactionValidator,
                                           CollectionCanBeEmpty>::
        validate(const shared_model::interface::types::
                     TransactionsForwardCollectionType &transactions) const {
      return validateImpl(transactions, [this](const auto &tx) {
        return transaction_validator_.validate(tx);
      });
    }

    template <typename TransactionValidator, bool CollectionCanBeEmpty>
    Answer TransactionsCollectionValidator<TransactionValidator,
                                           CollectionCanBeEmpty>::
        validate(const shared_model::interface::types::SharedTxsCollectionType
                     &transactions) const {
      return validate(transactions | boost::adaptors::indirected);
    }

    template <typename TransactionValidator, bool CollectionCanBeEmpty>
    Answer TransactionsCollectionValidator<TransactionValidator,
                                           CollectionCanBeEmpty>::
        validate(const interface::types::TransactionsForwardCollectionType
                     &transactions,
                 interface::types::TimestampType current_timestamp) const {
      return validateImpl(
          transactions, [this, current_timestamp](const auto &tx) {
            return transaction_validator_.validate(tx, current_timestamp);
          });
    }

    template <typename TransactionValidator, bool CollectionCanBeEmpty>
    Answer TransactionsCollectionValidator<TransactionValidator,
                                           CollectionCanBeEmpty>::
        validate(const interface::types::SharedTxsCollectionType &transactions,
                 interface::types::TimestampType current_timestamp) const {
      return validate(transactions | boost::adaptors::indirected,
                      current_timestamp);
    }

    template <typename TransactionValidator, bool CollectionCanBeEmpty>
    const TransactionValidator &TransactionsCollectionValidator<
        TransactionValidator,
        CollectionCanBeEmpty>::getTransactionValidator() const {
      return transaction_validator_;
    }

    template class TransactionsCollectionValidator<
        DefaultUnsignedTransactionValidator,
        true>;

    template class TransactionsCollectionValidator<
        DefaultUnsignedTransactionValidator,
        false>;

    template class TransactionsCollectionValidator<
        DefaultSignedTransactionValidator,
        true>;

    template class TransactionsCollectionValidator<
        DefaultSignedTransactionValidator,
        false>;

  }  // namespace validation
}  // namespace shared_model
