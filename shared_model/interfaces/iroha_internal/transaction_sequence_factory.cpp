/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/iroha_internal/transaction_sequence_factory.hpp"

#include <unordered_map>

#include <fmt/core.h>
#include "interfaces/iroha_internal/batch_meta.hpp"
#include "interfaces/iroha_internal/transaction_batch_factory_impl.hpp"
#include "interfaces/iroha_internal/transaction_batch_helpers.hpp"
#include "interfaces/iroha_internal/transaction_batch_impl.hpp"
#include "interfaces/transaction.hpp"
#include "validators/transactions_collection/batch_order_validator.hpp"
#include "validators/validation_error_helpers.hpp"

namespace shared_model {
  namespace interface {
    namespace {
      // we use an unnamed namespace here because we don't want to add test as
      // include path for the shared_model_interfaces_factories target
      // TODO igor-egorov 05.06.2018 IR-438 (Re)Move TransactionSequence classes
      const uint64_t kTestsMaxBatchSize(10000);
      const auto kValidatorsConfig =
          std::make_shared<validation::ValidatorsConfig>(kTestsMaxBatchSize);
    }  // namespace
    auto batch_validator =
        std::make_shared<validation::DefaultBatchValidator>(kValidatorsConfig);
    const std::unique_ptr<TransactionBatchFactory> batch_factory =
        std::make_unique<TransactionBatchFactoryImpl>(batch_validator);

    template <typename TransactionsCollectionValidator, typename FieldValidator>
    iroha::expected::Result<TransactionSequence, std::string>
    TransactionSequenceFactory::createTransactionSequence(
        const types::SharedTxsCollectionType &transactions,
        const TransactionsCollectionValidator &validator,
        const FieldValidator &field_validator) {
      std::unordered_map<interface::types::HashType,
                         std::vector<std::shared_ptr<Transaction>>,
                         interface::types::HashType::Hasher>
          extracted_batches;

      const auto &transaction_validator = validator.getTransactionValidator();

      types::BatchesCollectionType batches;
      auto insert_batch =
          [&batches](iroha::expected::Value<std::unique_ptr<TransactionBatch>>
                         &&value) {
            batches.push_back(std::move(value.value));
          };

      validation::ValidationErrorCreator error_creator;
      if (transactions.empty()) {
        error_creator.addReason("Sequence is empty.");
      }
      for (auto tx : transactions | boost::adaptors::indexed(1)) {
        validation::ValidationErrorCreator tx_error_creator;
        // perform stateless validation checks
        // check signatures validness
        if (not boost::empty(tx.value()->signatures())) {
          tx_error_creator |= field_validator.validateSignatures(
              tx.value()->signatures(), tx.value()->payload());
        }
        // check transaction validness
        tx_error_creator |= transaction_validator.validate(*tx.value());

        // if transaction is valid, try to form batch out of it
        if (auto meta = tx.value()->batchMeta()) {
          auto hashes = meta.value()->reducedHashes();
          auto batch_hash =
              TransactionBatchHelpers::calculateReducedBatchHash(hashes);
          extracted_batches[batch_hash].push_back(tx.value());
        } else {
          batch_factory->createTransactionBatch(tx.value())
              .match(insert_batch, [&tx_error_creator](const auto &err) {
                tx_error_creator.addReason(fmt::format(
                    "Could not create transaction batch from this tx: {}.",
                    err.error));
              });
        }

        error_creator |=
            std::move(tx_error_creator)
                .getValidationErrorWithGeneratedName([&] {
                  return fmt::format("Transaction #{} with reduced hash {}",
                                     tx.index(),
                                     tx.value()->reducedHash().hex());
                });
      }

      for (const auto &it : extracted_batches) {
        validation::ValidationErrorCreator batch_error_creator;
        batch_factory->createTransactionBatch(it.second).match(
            insert_batch, [&batch_error_creator](const auto &err) {
              batch_error_creator.addReason(fmt::format(
                  "Could not create transaction batch: {}.", err.error));
            });

        error_creator |=
            std::move(batch_error_creator)
                .getValidationErrorWithGeneratedName([&] {
                  return fmt::format("Batch from meta with reduced hash {}.",
                                     it.first.hex());
                });
      }

      if (auto error = std::move(error_creator)
                           .getValidationError("TransactionSequence")) {
        return error.value().toString();
      }

      return iroha::expected::makeValue(TransactionSequence(batches));
    }

    template iroha::expected::Result<TransactionSequence, std::string>
    TransactionSequenceFactory::createTransactionSequence(
        const types::SharedTxsCollectionType &transactions,
        const validation::DefaultUnsignedTransactionsValidator &validator,
        const validation::FieldValidator &field_validator);

    template iroha::expected::Result<TransactionSequence, std::string>
    TransactionSequenceFactory::createTransactionSequence(
        const types::SharedTxsCollectionType &transactions,
        const validation::DefaultSignedTransactionsValidator &validator,
        const validation::FieldValidator &field_validator);
  }  // namespace interface
}  // namespace shared_model
