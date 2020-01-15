/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/iroha_internal/parse_and_create_batches.hpp"

#include "interfaces/iroha_internal/transaction_batch.hpp"

using namespace shared_model;
using namespace shared_model::interface;

iroha::expected::Result<types::BatchesCollectionType, std::string>
shared_model::interface::parseAndCreateBatches(
    const TransactionBatchParser &batch_parser,
    const TransactionBatchFactory &batch_factory,
    const types::SharedTxsCollectionType &transactions) {
  auto batch_candidates = batch_parser.parseBatches(transactions);

  types::BatchesCollectionType batches;
  for (auto &cand : batch_candidates) {
    auto batch = batch_factory.createTransactionBatch(cand);
    if (auto e = iroha::expected::resultToOptionalError(batch)) {
      return *e;
    }
    batches.push_back(std::move(batch).assumeValue());
  }
  return batches;
}
