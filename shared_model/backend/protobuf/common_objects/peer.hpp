/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_PEER_HPP
#define IROHA_SHARED_MODEL_PROTO_PEER_HPP

#include "interfaces/common_objects/peer.hpp"

#include <optional>

#include "backend/protobuf/util.hpp"
#include "cryptography/hash.hpp"
#include "primitive.pb.h"
#include "utils/reference_holder.hpp"

namespace shared_model {
  namespace proto {
    class Peer final : public interface::Peer {
     public:
      template <typename PeerType>
      explicit Peer(PeerType &&peer) : proto_(std::forward<PeerType>(peer)) {
        if (proto_->certificate_case()) {
          tls_certificate_ = proto_->tls_certificate();
        }
      }

      Peer(const Peer &o) : Peer(o.proto_) {}

      Peer(Peer &&o) noexcept : Peer(std::move(o.proto_)) {}

      const interface::types::AddressType &address() const override {
        return proto_->address();
      }

      const std::optional<interface::types::TLSCertificateType>
          &tlsCertificate() const override {
        return tls_certificate_;
      }

      const std::string &pubkey() const override {
        return proto_->peer_key();
      }

      bool isSyncingPeer() const override {
        return proto_->syncing_peer();
      }

     private:
      detail::ReferenceHolder<iroha::protocol::Peer> proto_;
      std::optional<std::string> tls_certificate_;
    };
  }  // namespace proto
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_PROTO_PEER_HPP
