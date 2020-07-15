/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_INIT_PKCS11_HPP
#define IROHA_CRYPTO_INIT_PKCS11_HPP

#include "cryptography/crypto_init/from_config.hpp"

#include "main/iroha_conf_loader.hpp"

namespace iroha {
  /**
   * init PKCS11 crypto provider components
   * @param initializer what to initialize
   * @param param how to initialize
   * @param log_manager logger node for components
   * throws InitCryptoProviderException on failure
   */
  void initCryptoProviderPkcs11(iroha::PartialCryptoInit initializer,
                                IrohadConfig::Crypto::Pkcs11 const &param,
                                logger::LoggerManagerTreePtr log_manager);
}  // namespace iroha

#endif
