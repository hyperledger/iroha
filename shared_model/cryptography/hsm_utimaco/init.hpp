/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_INIT_UTIMACO_HPP
#define IROHA_CRYPTO_INIT_UTIMACO_HPP

#include "cryptography/crypto_init/from_config.hpp"

#include "main/iroha_conf_loader.hpp"

namespace iroha {
  /**
   * init HSM Utimaco crypto provider components
   * @param initializer what to initialize
   * @param param how to initialize
   * @param log_manager logger node for components
   * throws InitCryptoProviderException on failure
   */
  void initCryptoProviderUtimaco(iroha::PartialCryptoInit initializer,
                                 IrohadConfig::Crypto::HsmUtimaco const &param,
                                 logger::LoggerManagerTreePtr log_manager);
}  // namespace iroha

#endif
