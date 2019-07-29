/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_TRACE_HELPERS_HPP
#define IROHA_SHARED_MODEL_TRACE_HELPERS_HPP

#include "interfaces/common_objects/range_types.hpp"

#include <boost/algorithm/string/join.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include "interfaces/common_objects/transaction_sequence_common.hpp"
#include "interfaces/transaction.hpp"

namespace shared_model {
  namespace interface {

    template <class T>
    class TxHashesPrinter {
     public:
      explicit TxHashesPrinter(const T &txs) : txs_(txs) {}

      template <
          class Q = T,
          std::enable_if_t<std::is_same<types::SharedTxsCollectionType,
                                        typename std::decay<Q>::type>::value,
                           int> * = nullptr>
      std::string toString() const {
        return boost::algorithm::join(
            txs_ | boost::adaptors::transformed([](const auto &tx) {
              return tx->hash().hex();
            }),
            ", ");
      }

      template <
          class Q = T,
          std::enable_if_t<std::is_same<types::TransactionsCollectionType,
                                        typename std::decay<Q>::type>::value,
                           int> * = nullptr>
      std::string toString() const {
        return boost::algorithm::join(
            txs_ | boost::adaptors::transformed([](const auto &tx) {
              return tx.hash().hex();
            }),
            ", ");
      }

     private:
      const T &txs_;
    };

  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_TRACE_HELPERS_HPP
