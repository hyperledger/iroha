/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/iroha_internal/transaction_batch_factory_impl.hpp"

#include "interfaces/iroha_internal/transaction_batch_impl.hpp"
#include "interfaces/transaction.hpp"
#include "validators/validation_error_helpers.hpp"

namespace shared_model {
  namespace interface {

    TransactionBatchFactoryImpl::TransactionBatchFactoryImpl(
        std::shared_ptr<validation::AbstractValidator<TransactionBatch>>
            batch_validator)
        : batch_validator_(std::move(batch_validator)) {}

    TransactionBatchFactoryImpl::FactoryImplResult
    TransactionBatchFactoryImpl::createTransactionBatch(
        const types::SharedTxsCollectionType &transactions) const {
      std::unique_ptr<TransactionBatch> batch_ptr =
          std::make_unique<TransactionBatchImpl>(transactions);
      if (auto error = batch_validator_->validate(*batch_ptr)) {
        return iroha::expected::makeError(error->toString());
      }
      return iroha::expected::makeValue(std::move(batch_ptr));
    }

    TransactionBatchFactoryImpl::FactoryImplResult
    TransactionBatchFactoryImpl::createTransactionBatch(
        std::shared_ptr<Transaction> transaction) const {
      return createTransactionBatch(
          types::SharedTxsCollectionType{std::move(transaction)});
    }
  }  // namespace interface
}  // namespace shared_model
