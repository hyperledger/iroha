/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PEER_TLS_CERTIFICATES_PROVIDER_WSV_HPP
#define IROHA_PEER_TLS_CERTIFICATES_PROVIDER_WSV_HPP

#include "network/impl/peer_tls_certificates_provider.hpp"

#include <memory>

namespace iroha {
  namespace ametsuchi {
    class PeerQuery;
  }
  namespace network {

    class PeerTlsCertificatesProviderWsv : public PeerTlsCertificatesProvider {
     public:
      PeerTlsCertificatesProviderWsv(
          std::shared_ptr<iroha::ametsuchi::PeerQuery> peer_query);

      iroha::expected::Result<std::string, std::string> get(
          const std::string &address) const override;

     private:
      std::shared_ptr<iroha::ametsuchi::PeerQuery> peer_query_;
    };

  };  // namespace network
};    // namespace iroha

#endif
