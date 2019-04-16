/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/transaction_batch_validator.hpp"

#include <boost/range/adaptor/indirected.hpp>
#include "interfaces/iroha_internal/batch_meta.hpp"
#include "interfaces/transaction.hpp"

namespace {
  enum class BatchCheckResult {
    kOk,
    kNoBatchMeta,
    kIncorrectBatchMetaSize,
    kIncorrectHashes,
    kTooManyTransactions
  };
  /**
   * Check that all transactions from the collection are mentioned in batch_meta
   * and are positioned correctly
   * @param transactions to be checked
   * @param max_batch_size - maximum amount of transactions within a batch
   * @return enum, reporting about success result or containing a found error
   */
  BatchCheckResult batchIsWellFormed(
      const shared_model::interface::types::TransactionsForwardCollectionType
          &transactions,
      const uint64_t max_batch_size) {
    // a batch cannot contain more transactions than max_proposal_size,
    // otherwise it would not be processed anyway
    const uint64_t batch_size = boost::size(transactions);
    if (batch_size > max_batch_size) {
      return BatchCheckResult::kTooManyTransactions;
    }
    // equality of transactions batchMeta is checked during batch parsing
    auto batch_meta_opt = transactions.begin()->batchMeta();
    const auto transactions_quantity = boost::size(transactions);
    if (not batch_meta_opt and transactions_quantity == 1) {
      // batch is created from one tx - there is no batch_meta in valid case
      return BatchCheckResult::kOk;
    }
    if (not batch_meta_opt) {
      // in all other cases batch_meta must present
      return BatchCheckResult::kNoBatchMeta;
    }

    const auto &batch_hashes = batch_meta_opt->get()->reducedHashes();
    if (batch_hashes.size() != transactions_quantity) {
      return BatchCheckResult::kIncorrectBatchMetaSize;
    }

    auto hashes_are_correct =
        std::equal(boost::begin(batch_hashes),
                   boost::end(batch_hashes),
                   boost::begin(transactions),
                   boost::end(transactions),
                   [](const auto &tx_reduced_hash, const auto &tx) {
                     return tx_reduced_hash == tx.reducedHash();
                   });
    if (not hashes_are_correct) {
      return BatchCheckResult::kIncorrectHashes;
    }

    return BatchCheckResult::kOk;
  }
}  // namespace

namespace shared_model {
  namespace validation {

    BatchValidator::BatchValidator(std::shared_ptr<ValidatorsConfig> config)
        : max_batch_size_(config->max_batch_size) {}

    Answer BatchValidator::validate(
        const interface::TransactionBatch &batch) const {
      auto transactions = batch.transactions();
      return validate(transactions | boost::adaptors::indirected);
    }

    Answer BatchValidator::validate(
        interface::types::TransactionsForwardCollectionType transactions)
        const {
      std::string reason_name = "Transaction batch factory: ";
      validation::ReasonsGroupType batch_reason;
      batch_reason.first = reason_name;

      bool has_at_least_one_signature = std::any_of(
          transactions.begin(), transactions.end(), [](const auto &tx) {
            return not boost::empty(tx.signatures());
          });
      if (not has_at_least_one_signature) {
        batch_reason.second.emplace_back(
            "Transaction batch should contain at least one signature");
        // no stronger check for signatures is required here
        // here we are checking only batch logic, not transaction-related
      }

      switch (batchIsWellFormed(transactions, max_batch_size_)) {
        case BatchCheckResult::kOk:
          break;
        case BatchCheckResult::kNoBatchMeta:
          batch_reason.second.emplace_back(
              "There is no batch meta in provided transactions");
          break;
        case BatchCheckResult::kIncorrectBatchMetaSize:
          batch_reason.second.emplace_back(
              "Sizes of batch_meta and provided transactions are different");
          break;
        case BatchCheckResult::kIncorrectHashes:
          batch_reason.second.emplace_back(
              "Hashes of provided transactions and ones in batch_meta are "
              "different");
          break;
        case BatchCheckResult::kTooManyTransactions:
          batch_reason.second.emplace_back(
              "Batch contains too many transactions");
          break;
      }

      validation::Answer answer;
      if (not batch_reason.second.empty()) {
        answer.addReason(std::move(batch_reason));
      }
      return answer;
    }

  }  // namespace validation
}  // namespace shared_model
