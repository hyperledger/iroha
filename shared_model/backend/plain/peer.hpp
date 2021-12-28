/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PLAIN_PEER_HPP
#define IROHA_SHARED_MODEL_PLAIN_PEER_HPP

#include "interfaces/common_objects/peer.hpp"

#include <optional>

namespace shared_model {
  namespace plain {

    class Peer final : public interface::Peer {
     public:
      Peer(const interface::types::AddressTypeView address,
           std::string public_key_hex,
           const std::optional<interface::types::TLSCertificateTypeView>
               &tls_certificate,
           bool is_syncing_peer);

      const interface::types::AddressType &address() const override;

      const std::string &pubkey() const override;

      const std::optional<interface::types::TLSCertificateType>
          &tlsCertificate() const override;

      void setTlsCertificate(interface::types::TLSCertificateTypeView cert);

      bool isSyncingPeer() const override;

     private:
      const interface::types::AddressType address_;
      const std::string public_key_hex_;
      bool is_syncing_peer_;
      std::optional<interface::types::TLSCertificateType> tls_certificate_;
    };

  }  // namespace plain
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PLAIN_PEER_HPP
