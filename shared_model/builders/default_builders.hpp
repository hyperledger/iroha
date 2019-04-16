/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_DEFAULT_BUILDERS_HPP
#define IROHA_DEFAULT_BUILDERS_HPP

#include "builders/protobuf/transaction_responses/proto_transaction_status_builder.hpp"
#include "builders/transaction_responses/transaction_status_builder.hpp"
#include "validators/amount_true_validator.hpp"
#include "validators/field_validator.hpp"

namespace shared_model {
  namespace builder {

    using DefaultTransactionStatusBuilder =
        shared_model::builder::TransactionStatusBuilder<
            shared_model::proto::TransactionStatusBuilder>;

  }  // namespace builder
}  // namespace shared_model

#endif  // IROHA_DEFAULT_BUILDERS_HPP
