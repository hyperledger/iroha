/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TRANSACTION_SEQUENCE_BUILDER_HPP
#define IROHA_TRANSACTION_SEQUENCE_BUILDER_HPP

#include "builders/protobuf/transport_builder.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/iroha_internal/transaction_sequence_factory.hpp"
#include "module/irohad/common/validators_config.hpp"

namespace shared_model {
  namespace proto {

    /**
     * Class for building Transaction Sequence
     * @tparam SV Stateless validator type
     */
    template <typename SV>
    class /*[[deprecated]]*/ TransportBuilder<interface::TransactionSequence,
                                              SV> {
      TransportBuilder<interface::TransactionSequence, SV>(
          SV stateless_validator,
          std::shared_ptr<validation::ValidatorsConfig> config)
          : stateless_validator_(std::move(stateless_validator)),
            validators_config_(std::move(config)) {}

     public:
      // we do such default initialization only because it is deprecated and
      // used only in tests
      TransportBuilder<interface::TransactionSequence, SV>(
          std::shared_ptr<validation::ValidatorsConfig> config)
          : TransportBuilder<interface::TransactionSequence, SV>(
                SV(iroha::test::kTestsValidatorsConfig), std::move(config)) {}

      /**
       * Builds TransactionSequence from transport object
       * @param transport protobuf object from which TransactionSequence is
       * built
       * @return Result containing either TransactionSequence or message string
       */
      template <class T>
      iroha::expected::Result<interface::TransactionSequence, std::string>
      build(const T &transport) {
        const auto &txs = transport.transactions();
        std::vector<std::shared_ptr<interface::Transaction>> shm_txs;
        std::transform(txs.begin(),
                       txs.end(),
                       std::back_inserter(shm_txs),
                       [](const iroha::protocol::Transaction &tx) {
                         return std::make_shared<Transaction>(tx);
                       });
        return interface::TransactionSequenceFactory::createTransactionSequence(
            shm_txs,
            stateless_validator_,
            validation::FieldValidator(validators_config_));
      }

     private:
      SV stateless_validator_;
      std::shared_ptr<validation::ValidatorsConfig> validators_config_;
    };
  }  // namespace proto
}  // namespace shared_model
#endif  // IROHA_TRANSACTION_SEQUENCE_BUILDER_HPP
