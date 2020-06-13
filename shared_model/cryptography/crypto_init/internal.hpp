/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_INIT_INTERNAL_HPP
#define IROHA_CRYPTO_INIT_INTERNAL_HPP

#include "cryptography/crypto_init/from_config.hpp"

#include "main/iroha_conf_loader.hpp"

namespace iroha {
  /**
   * init internal crypto provider components
   * @param initializer what to initialize
   * @param param how to initialize
   * @param log_manager logger node for components
   * throws InitCryptoProviderException on failure
   */
  void initCryptoProviderInternal(iroha::PartialCryptoInit initializer,
                                  IrohadConfig::Crypto::Default const &param,
                                  logger::LoggerManagerTreePtr log_manager);
}  // namespace iroha

#endif
