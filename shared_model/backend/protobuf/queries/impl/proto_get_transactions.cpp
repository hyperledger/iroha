/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_transactions.hpp"
#include <boost/range/numeric.hpp>

namespace shared_model {
  namespace proto {

    template <typename QueryType>
    GetTransactions::GetTransactions(QueryType &&query)
        : TrivialProto(std::forward<QueryType>(query)),
          get_transactions_{proto_->payload().get_transactions()},
          transaction_hashes_{boost::accumulate(
              get_transactions_.tx_hashes(),
              TransactionHashesType{},
              [](auto &&acc, const auto &hash) {
                acc.push_back(crypto::Hash::fromHexString(hash));
                return std::forward<decltype(acc)>(acc);
              })} {}

    template GetTransactions::GetTransactions(GetTransactions::TransportType &);
    template GetTransactions::GetTransactions(
        const GetTransactions::TransportType &);
    template GetTransactions::GetTransactions(
        GetTransactions::TransportType &&);

    GetTransactions::GetTransactions(const GetTransactions &o)
        : GetTransactions(o.proto_) {}

    GetTransactions::GetTransactions(GetTransactions &&o) noexcept
        : GetTransactions(std::move(o.proto_)) {}

    const GetTransactions::TransactionHashesType &
    GetTransactions::transactionHashes() const {
      return transaction_hashes_;
    }

  }  // namespace proto
}  // namespace shared_model
