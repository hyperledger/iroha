/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_VALIDATORS_CONFIG_HPP
#define IROHA_VALIDATORS_CONFIG_HPP

#include <memory>

#include "framework/test_crypto_verifier.hpp"
#include "validators/settings.hpp"
#include "validators/validators_common.hpp"

namespace iroha {
  namespace test {

    static inline uint64_t getTestsMaxBatchSize() {
      return 10000;
    }

    static inline std::shared_ptr<shared_model::validation::ValidatorsConfig>
    getTestsValidatorsConfig(
        std::shared_ptr<shared_model::crypto::CryptoVerifier> crypto_verifier =
            getTestCryptoVerifier()) {
      static std::shared_ptr<shared_model::validation::ValidatorsConfig>
          config = std::make_shared<shared_model::validation::ValidatorsConfig>(
              getTestsMaxBatchSize(), std::move(crypto_verifier));
      return config;
    }

    static inline const std::shared_ptr<
        shared_model::validation::ValidatorsConfig>
    getProposalTestsValidatorsConfig(
        std::shared_ptr<shared_model::crypto::CryptoVerifier> crypto_verifier =
            getTestCryptoVerifier()) {
      static std::shared_ptr<shared_model::validation::ValidatorsConfig>
          config = std::make_shared<shared_model::validation::ValidatorsConfig>(
              getTestsMaxBatchSize(),
              std::move(crypto_verifier),
              shared_model::validation::getDefaultSettings(),
              false,
              true);
      return config;
    }

  }  // namespace test
}  // namespace iroha

#endif  // IROHA_VALIDATORS_CONFIG_HPP
