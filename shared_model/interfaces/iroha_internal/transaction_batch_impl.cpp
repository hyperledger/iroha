/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/iroha_internal/transaction_batch_impl.hpp"

#include <algorithm>
#include <numeric>

#include <boost/range/adaptor/transformed.hpp>

#include "interfaces/iroha_internal/transaction_batch_helpers.hpp"
#include "interfaces/transaction.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {

    TransactionBatchImpl::TransactionBatchImpl(
        types::SharedTxsCollectionType transactions)
        : transactions_(std::move(transactions)) {
      reduced_hash_ = TransactionBatchHelpers::calculateReducedBatchHash(
          transactions_ | boost::adaptors::transformed([](const auto &tx) {
            return tx->reducedHash();
          }));

      for (auto &tx : transactions_) tx->storeBatchHash(reduced_hash_);
    }

    const types::SharedTxsCollectionType &TransactionBatchImpl::transactions()
        const {
      return transactions_;
    }

    const types::HashType &TransactionBatchImpl::reducedHash() const {
      return reduced_hash_;
    }

    bool TransactionBatchImpl::hasAllSignatures() const {
      return std::all_of(
          transactions_.begin(), transactions_.end(), [](const auto tx) {
            return boost::size(tx->signatures()) >= tx->quorum();
          });
    }

    std::string TransactionBatchImpl::toString() const {
      return detail::PrettyStringBuilder()
          .init("Batch")
          .appendNamed("reducedHash", reducedHash())
          .appendNamed("hasAllSignatures", hasAllSignatures())
          .appendNamed("transactions", transactions())
          .finalize();
    }

    bool TransactionBatchImpl::addSignature(
        size_t number_of_tx,
        types::SignedHexStringView signed_blob,
        types::PublicKeyHexStringView public_key) {
      if (number_of_tx >= transactions_.size()) {
        return false;
      } else {
        return transactions_.at(number_of_tx)
            ->addSignature(signed_blob, public_key);
      }
    }

    bool TransactionBatchImpl::operator==(const TransactionBatch &rhs) const {
      return reducedHash() == rhs.reducedHash()
          and std::equal(transactions().begin(),
                         transactions().end(),
                         rhs.transactions().begin(),
                         rhs.transactions().end(),
                         [](auto const &left, auto const &right) {
                           return left->equalsByValue(*right);
                         });
    }
  }  // namespace interface
}  // namespace shared_model
