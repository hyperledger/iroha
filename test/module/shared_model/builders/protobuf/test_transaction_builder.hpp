/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_TRANSACTION_BUILDER_HPP
#define IROHA_TEST_TRANSACTION_BUILDER_HPP

#include "module/shared_model/builders/protobuf/builder_templates/transaction_template.hpp"

/**
 * Builder alias, to build shared model proto transaction object avoiding
 * validation and "required fields" check
 */
using TestTransactionBuilder = shared_model::proto::TemplateTransactionBuilder<
    shared_model::proto::Transaction>;

/**
 * Builder for creating \class shared_model::proto::UnsignedWrapper of \class
 * ProtoTxType
 */
using TestUnsignedTransactionBuilder =
    shared_model::proto::TemplateTransactionBuilder<>;

#endif  // IROHA_TEST_TRANSACTION_BUILDER_HPP
