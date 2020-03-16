/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/transaction_batch_validator.hpp"

#include <boost/range/adaptor/indirected.hpp>
#include "interfaces/transaction.hpp"
#include "validators/transactions_collection/batch_order_validator.hpp"

using namespace shared_model::validation;

template <typename BatchOrderValidator>
BatchValidator<BatchOrderValidator>::BatchValidator(
    std::shared_ptr<ValidatorsConfig> config)
    : batch_order_validator_(BatchOrderValidator{std::move(config)}) {}

template <typename BatchOrderValidator>
std::optional<ValidationError> BatchValidator<BatchOrderValidator>::validate(
    const shared_model::interface::TransactionBatch &batch) const {
  return batch_order_validator_.validate(batch.transactions()
                                         | boost::adaptors::indirected);
}

template class shared_model::validation::BatchValidator<BatchOrderValidator>;
