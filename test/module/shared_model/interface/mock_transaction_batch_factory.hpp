/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_MOCK_TRANSACTION_BATCH_FACTORY_HPP
#define IROHA_SHARED_MODEL_MOCK_TRANSACTION_BATCH_FACTORY_HPP

#include <gmock/gmock.h>
#include "interfaces/iroha_internal/transaction_batch_factory.hpp"

struct MockTransactionBatchFactory
    : public shared_model::interface::TransactionBatchFactory {
  MOCK_CONST_METHOD1(
      createTransactionBatch,
      FactoryResult<std::unique_ptr<shared_model::interface::TransactionBatch>>(
          const shared_model::interface::types::SharedTxsCollectionType &));

  MOCK_CONST_METHOD1(
      createTransactionBatch,
      FactoryResult<std::unique_ptr<shared_model::interface::TransactionBatch>>(
          std::shared_ptr<shared_model::interface::Transaction>));
};

#endif  // IROHA_SHARED_MODEL_MOCK_TRANSACTION_BATCH_FACTORY_HPP
