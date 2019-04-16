/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/iroha_internal/transaction_sequence_factory.hpp"

#include <unordered_map>

#include "interfaces/iroha_internal/batch_meta.hpp"
#include "interfaces/iroha_internal/transaction_batch_factory_impl.hpp"
#include "interfaces/iroha_internal/transaction_batch_helpers.hpp"
#include "interfaces/iroha_internal/transaction_batch_impl.hpp"
#include "interfaces/transaction.hpp"
#include "validators/answer.hpp"

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
        std::make_shared<validation::BatchValidator>(kValidatorsConfig);
    const std::unique_ptr<TransactionBatchFactory> batch_factory =
        std::make_unique<TransactionBatchFactoryImpl>(batch_validator);

    template <typename TransactionValidator, typename FieldValidator>
    iroha::expected::Result<TransactionSequence, std::string>
    TransactionSequenceFactory::createTransactionSequence(
        const types::SharedTxsCollectionType &transactions,
        const validation::TransactionsCollectionValidator<TransactionValidator>
            &validator,
        const FieldValidator &field_validator) {
      std::unordered_map<interface::types::HashType,
                         std::vector<std::shared_ptr<Transaction>>,
                         interface::types::HashType::Hasher>
          extracted_batches;

      const auto &transaction_validator = validator.getTransactionValidator();

      types::BatchesCollectionType batches;
      auto insert_batch =
          [&batches](iroha::expected::Value<std::unique_ptr<TransactionBatch>>
                         &value) { batches.push_back(std::move(value.value)); };

      validation::Answer result;
      if (transactions.empty()) {
        result.addReason(std::make_pair(
            "Transaction collection error",
            std::vector<std::string>{"sequence can not be empty"}));
      }
      for (const auto &tx : transactions) {
        // perform stateless validation checks
        validation::ReasonsGroupType reason;
        reason.first = "Transaction: ";
        // check signatures validness
        if (not boost::empty(tx->signatures())) {
          field_validator.validateSignatures(
              reason, tx->signatures(), tx->payload());
          if (not reason.second.empty()) {
            result.addReason(std::move(reason));
            continue;
          }
        }
        // check transaction validness
        auto tx_errors = transaction_validator.validate(*tx);
        if (tx_errors) {
          reason.second.emplace_back(tx_errors.reason());
          result.addReason(std::move(reason));
          continue;
        }

        // if transaction is valid, try to form batch out of it
        if (auto meta = tx->batchMeta()) {
          auto hashes = meta.get()->reducedHashes();
          auto batch_hash =
              TransactionBatchHelpers::calculateReducedBatchHash(hashes);
          extracted_batches[batch_hash].push_back(tx);
        } else {
          batch_factory->createTransactionBatch(tx).match(
              insert_batch, [&tx, &result](const auto &err) {
                result.addReason(std::make_pair(
                    std::string("Error in transaction with reduced hash: ")
                        + tx->reducedHash().hex(),
                    std::vector<std::string>{err.error}));
              });
        }
      }

      for (const auto &it : extracted_batches) {
        batch_factory->createTransactionBatch(it.second).match(
            insert_batch, [&it, &result](const auto &err) {
              result.addReason(std::make_pair(
                  it.first.toString(), std::vector<std::string>{err.error}));
            });
      }

      if (result.hasErrors()) {
        return iroha::expected::makeError(result.reason());
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
