/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PEER_TLS_CERTIFICATES_PROVIDER_HPP
#define IROHA_PEER_TLS_CERTIFICATES_PROVIDER_HPP

#include <memory>
#include <string>

#include "common/result.hpp"
#include "interfaces/common_objects/types.hpp"

namespace iroha {
  namespace network {

    class PeerTlsCertificatesProvider {
     public:
      virtual ~PeerTlsCertificatesProvider() = default;

      // REMOVE
      virtual iroha::expected::Result<std::string, std::string> get(
          const std::string &address) const = 0;

      /*virtual*/ iroha::expected::Result<std::string, std::string> get(
          const shared_model::interface::types::PubkeyType &address) const
          /*= 0*/;
    };

  };  // namespace network
};    // namespace iroha

#endif
