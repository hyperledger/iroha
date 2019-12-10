/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_transactions.hpp"

#include <boost/range/adaptor/transformed.hpp>
#include "common/result.hpp"
#include "cryptography/blob.hpp"

namespace shared_model {
  namespace proto {

    iroha::expected::Result<std::unique_ptr<GetTransactions>, std::string>
    GetTransactions::create(iroha::protocol::Query &query) {
      using namespace iroha::expected;
      TransactionHashesType transaction_hashes;
      for (const auto &hash : query.payload().get_transactions().tx_hashes()) {
        if (auto e = resultToOptionalError(
                shared_model::crypto::Blob::fromHexString(hash) |
                    [&](auto &&hash) -> Result<void, std::string> {
                  transaction_hashes.emplace_back(std::move(hash));
                  return {};
                })) {
          return e.value();
        }
      }
      return std::make_unique<GetTransactions>(query,
                                               std::move(transaction_hashes));
    }

    GetTransactions::GetTransactions(iroha::protocol::Query &query,
                                     TransactionHashesType transaction_hashes)
        : get_transactions_{query.payload().get_transactions()},
          transaction_hashes_{std::move(transaction_hashes)} {}

    const GetTransactions::TransactionHashesType &
    GetTransactions::transactionHashes() const {
      return transaction_hashes_;
    }

  }  // namespace proto
}  // namespace shared_model
