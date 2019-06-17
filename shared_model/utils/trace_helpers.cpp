/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "utils/trace_helpers.hpp"

#include <boost/algorithm/string/join.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include "interfaces/transaction.hpp"

using namespace shared_model::interface;

TxHashesPrinter::TxHashesPrinter(const types::TransactionsCollectionType &txs)
    : txs_(txs) {}

std::string TxHashesPrinter::toString() const {
  return boost::algorithm::join(
      txs_ | boost::adaptors::transformed([](const auto &tx) {
        return tx.hash().hex();
      }),
      ", ");
}
