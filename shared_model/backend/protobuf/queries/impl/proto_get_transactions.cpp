/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_transactions.hpp"

#include <boost/range/adaptor/transformed.hpp>

namespace shared_model {
  namespace proto {

    GetTransactions::GetTransactions(iroha::protocol::Query &query)
        : get_transactions_{query.payload().get_transactions()},
          transaction_hashes_{boost::copy_range<TransactionHashesType>(
              get_transactions_.tx_hashes()
              | boost::adaptors::transformed([](const auto &hash) {
                  return crypto::Hash::fromHexString(hash);
                }))} {}

    const GetTransactions::TransactionHashesType &
    GetTransactions::transactionHashes() const {
      return transaction_hashes_;
    }

  }  // namespace proto
}  // namespace shared_model
