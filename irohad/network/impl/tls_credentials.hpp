/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CLIENT_TLS_CREDENTIALS_HPP
#define CLIENT_TLS_CREDENTIALS_HPP

#include <memory>

#include "common/result.hpp"

namespace iroha {
  namespace network {

    struct TlsCredentials {
      TlsCredentials(std::string private_key, std::string certificate);

      std::string private_key;
      std::string certificate;

      static iroha::expected::Result<std::unique_ptr<TlsCredentials>,
                                     std::string>
      load(const std::string &path);
    };

  }  // namespace network
}  // namespace iroha

#endif
