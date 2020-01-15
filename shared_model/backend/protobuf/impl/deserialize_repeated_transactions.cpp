/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/deserialize_repeated_transactions.hpp"

using namespace shared_model;
using namespace shared_model::proto;

iroha::expected::Result<interface::types::SharedTxsCollectionType,
                        TransactionFactoryType::Error>
shared_model::proto::deserializeTransactions(
    const TransactionFactoryType &transaction_factory,
    const google::protobuf::RepeatedPtrField<iroha::protocol::Transaction>
        &transactions) {
  interface::types::SharedTxsCollectionType tx_collection;
  for (const auto &tx : transactions) {
    auto model_tx = transaction_factory.build(tx);
    if (auto e = iroha::expected::resultToOptionalError(model_tx)) {
      return *e;
    }
    tx_collection.emplace_back(std::move(model_tx).assumeValue());
  }
  return tx_collection;
}
