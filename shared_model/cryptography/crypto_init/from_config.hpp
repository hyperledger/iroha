/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_INIT_HPP
#define IROHA_CRYPTO_INIT_HPP

#include <functional>
#include <stdexcept>
#include <string>

#include "cryptography/crypto_provider/crypto_provider.hpp"
#include "logger/logger_manager_fwd.hpp"
#include "main/iroha_conf_loader.hpp"

namespace shared_model::crypto {
  class CryptoVerifierMultihash;
}

namespace iroha {
  class InitCryptoProviderException : public std::runtime_error {
    using std::runtime_error::runtime_error;
  };

  struct PartialCryptoInit {
    using InitSignerFunc = std::function<void(
        std::unique_ptr<shared_model::crypto::CryptoSigner>)>;
    using InitVerifierFunc = std::function<void(
        std::unique_ptr<shared_model::crypto::CryptoVerifierMultihash>)>;

    std::optional<InitSignerFunc> init_signer;
    std::optional<InitVerifierFunc> init_verifier;
  };

  /**
   * init crypto
   * @param config crypto config
   * @param keypair_name flag, if any, or empty string
   * @param log_manager logger node for components
   * @return crypto provider
   * throws InitCryptoProviderException on failure
   */
  shared_model::crypto::CryptoProvider makeCryptoProvider(
      IrohadConfig::Crypto const &config,
      std::string const &keypair_name,
      logger::LoggerManagerTreePtr log_manager);
}  // namespace iroha

#endif
