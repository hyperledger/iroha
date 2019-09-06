/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PEER_TLS_CERTIFICATES_PROVIDER_ROOT_HPP
#define IROHA_PEER_TLS_CERTIFICATES_PROVIDER_ROOT_HPP

#include "network/impl/peer_tls_certificates_provider.hpp"

namespace iroha {
  namespace network {

    class PeerTlsCertificatesProviderRoot : public PeerTlsCertificatesProvider {
     public:
      PeerTlsCertificatesProviderRoot(std::string root_certificate);

      iroha::expected::Result<std::string, std::string> get(
          const std::string &address) const override;

     private:
      std::string root_certificate_;
    };

  };  // namespace network
};    // namespace iroha

#endif
