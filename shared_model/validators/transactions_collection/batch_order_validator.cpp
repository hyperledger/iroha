/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/transactions_collection/batch_order_validator.hpp"

#include <ciso646>
#include <unordered_map>

#include <fmt/core.h>
#include <boost/range/adaptor/indexed.hpp>
#include "cryptography/hash.hpp"
#include "interfaces/iroha_internal/batch_meta.hpp"
#include "interfaces/transaction.hpp"
#include "validators/validation_error_helpers.hpp"

using namespace shared_model::validation;

BatchOrderValidator::BatchOrderValidator(
    std::shared_ptr<ValidatorsConfig> config)
    : max_batch_size_(config->max_batch_size),
      partial_ordered_batches_are_valid_(
          config->partial_ordered_batches_are_valid) {}

std::optional<ValidationError> BatchOrderValidator::validate(
    const shared_model::interface::types::TransactionsForwardCollectionType
        &transactions) const {
  ValidationErrorCreator error_creator;

  // Check that the batch has at least one signature.
  // No stronger check for signatures is required here
  // here we are checking only batch logic, not transaction-related.
  const bool has_at_least_one_signature =
      std::any_of(transactions.begin(), transactions.end(), [](const auto &tx) {
        return not boost::empty(tx.signatures());
      });
  if (not has_at_least_one_signature) {
    error_creator.addReason("Transaction batch has no signatures.");
  }

  // a batch cannot contain more transactions than max_proposal_size,
  // otherwise it would not be processed anyway
  const uint64_t batch_size = boost::size(transactions);
  if (batch_size > max_batch_size_) {
    error_creator.addReason(
        fmt::format("Batch contains too many transactions. Maximum allowed "
                    "number of transactions in a batch is {}.",
                    max_batch_size_));
  }
  // equality of transactions batchMeta is checked during batch parsing
  auto batch_meta_opt = transactions.begin()->batchMeta();
  const auto transactions_quantity = boost::size(transactions);
  if (not batch_meta_opt and transactions_quantity == 1) {
    // batch is created from one tx - there is no batch_meta in valid case
    return std::move(error_creator).getValidationError("Batch transactions");
  }
  if (not batch_meta_opt) {
    // in all other cases batch_meta must present
    error_creator.addReason("There is no batch meta in provided transactions.");
  }

  bool batch_is_atomic = batch_meta_opt->get()->type()
      == shared_model::interface::types::BatchType::ATOMIC;

  const auto &batch_hashes = batch_meta_opt->get()->reducedHashes();
  // todo igor-egorov 24.04.2019 IR-455 Split batches validator
  if (batch_hashes.size() != transactions_quantity) {
    if (batch_is_atomic) {
      error_creator.addReason(
          "Sizes of batch_meta and provided transactions are different in an "
          "atomic batch.");
    } else if (not partial_ordered_batches_are_valid_) {
      error_creator.addReason(
          "Sizes of batch_meta and provided transactions are different, but "
          "partial ordered batches are not allowed.");
    }
  }

  // Compare tx hashes from batch meta and from transactions themselves.
  // If partial batches are ok, we can skip some hashes from batch meta, but
  // apart from that, all transaction hashes must match the batch meta hashes in
  // the same order.
  const bool may_skip_batch_meta_hashes =
      not batch_is_atomic and partial_ordered_batches_are_valid_;
  auto batch_hash_it = batch_hashes.begin();
  for (auto tx : transactions | boost::adaptors::indexed(1)) {
    ValidationErrorCreator tx_error_creator;
    if (may_skip_batch_meta_hashes) {
      auto matching_batch_hash_it = std::find(
          batch_hash_it, batch_hashes.end(), tx.value().reducedHash());
      if (matching_batch_hash_it == batch_hashes.end()) {
        matching_batch_hash_it = std::find(
            batch_hashes.begin(), batch_hash_it, tx.value().reducedHash());
        if (matching_batch_hash_it == batch_hashes.end()) {
          tx_error_creator.addReason("No corresponding hash in batch meta.");
        } else {
          tx_error_creator.addReason(
              "The corresponding hash in batch meta is out of order.");
        }
      } else {
        batch_hash_it = matching_batch_hash_it;
      }
    } else {
      if (batch_hash_it == batch_hashes.end()) {
        tx_error_creator.addReason("Does not have corresponding hash.");
      } else if (*batch_hash_it != tx.value().reducedHash()) {
        tx_error_creator.addReason("Does not match corresponding hash.");
      }
    }
    error_creator |=
        std::move(tx_error_creator).getValidationErrorWithGeneratedName([&] {
          return fmt::format("Transaction #{} with hash {}",
                             tx.index(),
                             tx.value().hash().hex());
        });
    if (batch_hash_it != batch_hashes.end()) {
      ++batch_hash_it;
    }
  }

  // Check hashes uniqueness in batch meta.
  std::unordered_map<shared_model::crypto::Hash,
                     size_t,
                     shared_model::crypto::Hash::Hasher>
      batch_meta_hashes;
  for (auto hash : batch_hashes | boost::adaptors::indexed(1)) {
    ValidationErrorCreator hash_error_creator;
    auto emplace_result = batch_meta_hashes.emplace(hash.value(), hash.index());
    if (not emplace_result.second) {
      hash_error_creator.addReason(
          fmt::format("Duplicates hash #{}", emplace_result.first->second));
    }
    error_creator |=
        std::move(hash_error_creator).getValidationErrorWithGeneratedName([&] {
          return fmt::format("Reduced transaction hash #{} {}",
                             hash.index(),
                             hash.value().hex());
        });
  }

  return std::move(error_creator).getValidationError("Batch transactions");
}
