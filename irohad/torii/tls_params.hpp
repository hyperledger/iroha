/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TORII_TLS_PARAMS
#define TORII_TLS_PARAMS

#include <string>


namespace iroha {
  namespace torii {
    /**
     * Simple container for TLS server parameters
     */
    struct TlsParams {
        size_t port;
        std::string key_path;
    };
  }  // namespace torii
}  // namespace iroha

#endif  // TORII_TLS_PARAMS

