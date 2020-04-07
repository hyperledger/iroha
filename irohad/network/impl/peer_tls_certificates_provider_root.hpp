/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PEER_TLS_CERTIFICATES_PROVIDER_ROOT_HPP
#define IROHA_PEER_TLS_CERTIFICATES_PROVIDER_ROOT_HPP

#include "network/peer_tls_certificates_provider.hpp"

namespace iroha {
  namespace network {

    class PeerTlsCertificatesProviderRoot : public PeerTlsCertificatesProvider {
     public:
      PeerTlsCertificatesProviderRoot(
          shared_model::interface::types::TLSCertificateType root_certificate);

      iroha::expected::Result<
          shared_model::interface::types::TLSCertificateType,
          std::string>
      get(const shared_model::interface::Peer &) const override;

      iroha::expected::Result<
          shared_model::interface::types::TLSCertificateType,
          std::string>
          get(shared_model::interface::types::PublicKeyHexStringView)
              const override;

     private:
      shared_model::interface::types::TLSCertificateType root_certificate_;
    };

  }  // namespace network
}  // namespace iroha

#endif
