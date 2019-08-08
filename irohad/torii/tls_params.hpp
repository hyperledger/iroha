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
     *
     * - port - listening port for TLS server
     * - key_path - path to a keypair to use
     *   Filenames are a result of appending '.crt' and '.key' to this path
     *   For example, if key_path == "/path/to/a/key", then the corresponding
     *   key file would be "/path/to/a/key.key", and the certificate would be
     *   "/path/to/a/key.crt"
     */
    struct TlsParams {
      size_t port;
      std::string key_path;
    };
  }  // namespace torii
}  // namespace iroha

#endif  // TORII_TLS_PARAMS
