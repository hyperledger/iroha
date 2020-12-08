/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_TRANSACTION_BUILDER_HPP
#define IROHA_TEST_TRANSACTION_BUILDER_HPP

#include <memory>

#include "builders/protobuf/builder_templates/transaction_template.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "module/shared_model/validators/validators.hpp"

using ProtoTxType = shared_model::proto::Transaction;

/**
 * Builder alias, to build shared model proto transaction object avoiding
 * validation and "required fields" check
 */
using TestTransactionBuilder = shared_model::proto::TemplateTransactionBuilder<
    (1 << shared_model::proto::TemplateTransactionBuilder<>::total) - 1,
    shared_model::validation::AlwaysValidValidator,
    ProtoTxType>;

/**
 * Builder for creating \class shared_model::proto::UnsignedWrapper of \class
 * ProtoTxType
 */
using TestUnsignedTransactionBuilder =
    shared_model::proto::TemplateTransactionBuilder<
        (1 << shared_model::proto::TemplateTransactionBuilder<>::total) - 1,
        shared_model::validation::AlwaysValidValidator,
        shared_model::proto::UnsignedWrapper<ProtoTxType>>;

/**
 * Wrapper for making shared_ptr on transaction from the passed builder
 * @tparam Builder - universal reference type of the passed builder
 * @param builder - instance of the passed builder
 * @return shared_ptr to completed object
 */
template <typename Builder>
inline auto makePolyTxFromBuilder(Builder &&builder) {
  return std::make_shared<ProtoTxType>(builder.build());
}

template <typename Builder>
inline auto completeUnsignedTxBuilder(Builder &&builder) {
  return std::make_shared<ProtoTxType>(
      builder.build()
          .signAndAddSignature(
              shared_model::crypto::DefaultCryptoAlgorithmType::
                  generateKeypair())
          .finish());
}

#endif  // IROHA_TEST_TRANSACTION_BUILDER_HPP
