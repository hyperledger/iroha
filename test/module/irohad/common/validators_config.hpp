/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_VALIDATORS_CONFIG_HPP
#define IROHA_VALIDATORS_CONFIG_HPP

#include "validators/validators_common.hpp"

namespace iroha {
  namespace test {

    static inline uint64_t getTestsMaxBatchSize() {
      return 10000;
    }

    static const std::shared_ptr<shared_model::validation::ValidatorsConfig>
        kTestsValidatorsConfig(
            std::make_shared<shared_model::validation::ValidatorsConfig>(
                getTestsMaxBatchSize()));

    static const std::shared_ptr<shared_model::validation::ValidatorsConfig>
        kProposalTestsValidatorsConfig(
            std::make_shared<shared_model::validation::ValidatorsConfig>(
                getTestsMaxBatchSize(), false, true));

  }  // namespace test
}  // namespace iroha

#endif  // IROHA_VALIDATORS_CONFIG_HPP
