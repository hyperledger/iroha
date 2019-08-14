/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/transaction_batch_validator.hpp"

#include <boost/range/adaptor/indirected.hpp>
#include <unordered_set>
#include "interfaces/iroha_internal/batch_meta.hpp"
#include "interfaces/transaction.hpp"

namespace {
  enum class BatchCheckResult {
    kOk,
    kNoBatchMeta,
    kIncorrectBatchMetaSize,
    kIncorrectHashes,
    kTooManyTransactions,
    kDuplicateTransactions
  };
  /**
   * Check that all transactions from the collection are mentioned in batch_meta
   * and are positioned correctly
   * @param transactions to be checked
   * @param max_batch_size - maximum amount of transactions within a batch
   * @param partial_ordered_batches_are_valid - batch meta can contain more
   * hashes of batch transactions than it actually has
   * @return enum, reporting about success result or containing a found error
   */
  BatchCheckResult batchIsWellFormed(
      const shared_model::interface::types::TransactionsForwardCollectionType
          &transactions,
      const uint64_t max_batch_size,
      const bool partial_ordered_batches_are_valid) {
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

    bool batch_is_atomic = batch_meta_opt->get()->type()
        == shared_model::interface::types::BatchType::ATOMIC;

    const auto &batch_hashes = batch_meta_opt->get()->reducedHashes();
    // todo igor-egorov 24.04.2019 IR-455 Split batches validator
    if ((batch_is_atomic or not partial_ordered_batches_are_valid)
        and (batch_hashes.size() != transactions_quantity)) {
      return BatchCheckResult::kIncorrectBatchMetaSize;
    }

    std::unordered_set<std::string> hashes = {};
    auto hashes_begin = boost::begin(batch_hashes);
    auto hashes_end = boost::end(batch_hashes);
    auto transactions_begin = boost::begin(transactions);
    auto transactions_end = boost::end(transactions);
    bool hashes_are_correct = true;
    bool hashes_are_unique = true;

    for (; transactions_begin != transactions_end; ++hashes_begin) {
      if (hashes_begin == hashes_end) {
        hashes_are_correct = false;
        break;
      }

      if (hashes.count(hashes_begin->hex())) {
        hashes_are_unique = false;
        break;
      }

      if (*hashes_begin == transactions_begin->reducedHash()) {
        ++transactions_begin;
      }

      hashes.insert(hashes_begin->hex());
    }

    if (not hashes_are_unique) {
      return BatchCheckResult::kDuplicateTransactions;
    }

    if (not hashes_are_correct) {
      return BatchCheckResult::kIncorrectHashes;
    }

    return BatchCheckResult::kOk;
  }
}  // namespace

namespace shared_model {
  namespace validation {

    BatchValidator::BatchValidator(std::shared_ptr<ValidatorsConfig> config)
        : max_batch_size_(config->max_batch_size),
          partial_ordered_batches_are_valid_(
              config->partial_ordered_batches_are_valid) {}

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

      switch (batchIsWellFormed(
          transactions, max_batch_size_, partial_ordered_batches_are_valid_)) {
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
        case BatchCheckResult::kDuplicateTransactions:
          batch_reason.second.emplace_back(
              "Batch contains duplicate transactions");
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
