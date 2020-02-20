/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/iroha_internal/transaction_sequence.hpp"

#include <numeric>

#include "interfaces/iroha_internal/transaction_batch.hpp"

namespace shared_model {
  namespace interface {

    const types::SharedTxsCollectionType &TransactionSequence::transactions()
        const {
      if (not transactions_) {
        types::SharedTxsCollectionType result;
        auto transactions_amount =
            std::accumulate(std::begin(batches_),
                            std::end(batches_),
                            0ul,
                            [](size_t acc_size, auto batch) {
                              return acc_size + batch->transactions().size();
                            });
        result.reserve(transactions_amount);
        for (const auto &batch : batches_) {
          auto &transactions = batch->transactions();
          std::copy(transactions.begin(),
                    transactions.end(),
                    std::back_inserter(result));
        }
        transactions_.emplace(std::move(result));
      }
      return transactions_.value();
    }

    const types::BatchesCollectionType &TransactionSequence::batches() const {
      return batches_;
    }

    std::string TransactionSequence::toString() const {
      return detail::PrettyStringBuilder()
          .init("TransactionSequence")
          .append(batches_)
          .finalize();
    }

    TransactionSequence::TransactionSequence(
        const types::BatchesCollectionType &batches)
        : batches_(batches) {}

  }  // namespace interface
}  // namespace shared_model
