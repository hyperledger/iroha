/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PEER_TLS_CERTIFICATES_PROVIDER_WSV_HPP
#define IROHA_PEER_TLS_CERTIFICATES_PROVIDER_WSV_HPP

#include "network/peer_tls_certificates_provider.hpp"

#include <memory>

#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    class Peer;
  }
}  // namespace shared_model

namespace iroha {
  namespace ametsuchi {
    class PeerQuery;
  }
  namespace network {

    class PeerTlsCertificatesProviderWsv : public PeerTlsCertificatesProvider {
     public:
      PeerTlsCertificatesProviderWsv(
          std::shared_ptr<iroha::ametsuchi::PeerQuery> peer_query);

      ~PeerTlsCertificatesProviderWsv();

      iroha::expected::Result<
          shared_model::interface::types::TLSCertificateType,
          std::string>
      get(const shared_model::interface::Peer &peer) const override;

      iroha::expected::Result<
          shared_model::interface::types::TLSCertificateType,
          std::string>
      get(shared_model::interface::types::PublicKeyHexStringView public_key)
          const override;

     private:
      class Impl;
      std::unique_ptr<Impl> impl_;
    };

  };  // namespace network
};    // namespace iroha

#endif
