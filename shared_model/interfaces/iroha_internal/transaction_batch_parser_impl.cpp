/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/iroha_internal/transaction_batch_parser_impl.hpp"

#include <boost/range/adaptor/indirected.hpp>
#include <boost/range/combine.hpp>
#include "interfaces/iroha_internal/batch_meta.hpp"
#include "interfaces/transaction.hpp"

namespace {
  /**
   * Zips in_range and out_range, where in_range elements are objects, parses
   * batches based on batchMeta values of in_range, and returns a collection of
   * corresponding sub-ranges of out_range
   */
  template <typename InRange, typename OutRange>
  auto parseBatchesImpl(InRange in_range, const OutRange &out_range) {
    std::vector<OutRange> result;
    auto meta = [](const auto &tx) { return boost::get<0>(tx).batchMeta(); };
    auto it = [](auto &p) { return boost::get<1>(p.get_iterator_tuple()); };

    auto range = boost::combine(in_range, out_range);
    auto begin = std::begin(range), end = std::end(range);
    while (begin != end) {
      const auto beginning_tx_meta_opt = meta(*begin);
      auto next = std::find_if(std::next(begin), end, [&](const auto &tx) {
        const auto current_tx_meta_opt = meta(tx);
        return not(current_tx_meta_opt and beginning_tx_meta_opt)
            or (**current_tx_meta_opt != **beginning_tx_meta_opt);
      });

      result.emplace_back(it(begin), it(next));
      begin = next;
    }

    return result;
  }
}  // namespace

namespace shared_model {
  namespace interface {

    std::vector<types::TransactionsForwardCollectionType>
    TransactionBatchParserImpl::parseBatches(
        types::TransactionsForwardCollectionType txs) const noexcept {
      return parseBatchesImpl(txs, txs);
    }

    std::vector<types::TransactionsCollectionType>
    TransactionBatchParserImpl::parseBatches(
        types::TransactionsCollectionType txs) const noexcept {
      return parseBatchesImpl(txs, txs);
    }

    std::vector<types::SharedTxsCollectionType>
    TransactionBatchParserImpl::parseBatches(
        const types::SharedTxsCollectionType &txs) const noexcept {
      return parseBatchesImpl(txs | boost::adaptors::indirected, txs);
    }

  }  // namespace interface
}  // namespace shared_model
