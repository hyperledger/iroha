/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_INTERFACE_PARSE_AND_CREATE_BATCHES_HPP
#define IROHA_SHARED_MODEL_INTERFACE_PARSE_AND_CREATE_BATCHES_HPP

#include "common/result.hpp"
#include "interfaces/common_objects/transaction_sequence_common.hpp"
#include "interfaces/iroha_internal/transaction_batch_factory.hpp"
#include "interfaces/iroha_internal/transaction_batch_parser.hpp"
#include "interfaces/transaction.hpp"

namespace shared_model {
  namespace interface {

    iroha::expected::Result<types::BatchesCollectionType, std::string>
    parseAndCreateBatches(const TransactionBatchParser &batch_parser,
                          const TransactionBatchFactory &batch_factory,
                          const types::SharedTxsCollectionType &transactions);
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_INTERFACE_PARSE_AND_CREATE_BATCHES_HPP
