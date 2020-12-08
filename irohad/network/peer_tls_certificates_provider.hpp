/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PEER_TLS_CERTIFICATES_PROVIDER_HPP
#define IROHA_PEER_TLS_CERTIFICATES_PROVIDER_HPP

#include <memory>
#include <string>

#include "common/result.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    class Peer;
  }
}  // namespace shared_model

namespace iroha {
  namespace network {

    class PeerTlsCertificatesProvider {
     public:
      virtual ~PeerTlsCertificatesProvider() = default;

      /// Get peer TLS certificate.
      virtual iroha::expected::Result<
          shared_model::interface::types::TLSCertificateType,
          std::string>
      get(const shared_model::interface::Peer &peer) const = 0;

      /// Get peer TLS certificate by peer public key.
      virtual iroha::expected::Result<
          shared_model::interface::types::TLSCertificateType,
          std::string>
      get(shared_model::interface::types::PublicKeyHexStringView public_key)
          const = 0;
    };

  }  // namespace network
}  // namespace iroha

#endif
