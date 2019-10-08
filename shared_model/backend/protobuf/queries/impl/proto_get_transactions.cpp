/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_transactions.hpp"

#include <boost/range/numeric.hpp>

namespace shared_model {
  namespace proto {

    GetTransactions::GetTransactions(iroha::protocol::Query &query)
        : get_transactions_{query.payload().get_transactions()},
          transaction_hashes_{boost::accumulate(
              get_transactions_.tx_hashes(),
              TransactionHashesType{},
              [](auto &&acc, const auto &hash) {
                acc.push_back(crypto::Hash::fromHexString(hash));
                return std::forward<decltype(acc)>(acc);
              })} {}

    const GetTransactions::TransactionHashesType &
    GetTransactions::transactionHashes() const {
      return transaction_hashes_;
    }

  }  // namespace proto
}  // namespace shared_model
