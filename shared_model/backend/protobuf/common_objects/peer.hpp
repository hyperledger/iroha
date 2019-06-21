/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_PEER_HPP
#define IROHA_SHARED_MODEL_PROTO_PEER_HPP

#include "backend/protobuf/util.hpp"
#include "cryptography/hash.hpp"
#include "cryptography/public_key.hpp"
#include "interfaces/common_objects/peer.hpp"
#include "primitive.pb.h"
#include "utils/reference_holder.hpp"

namespace shared_model {
  namespace proto {
    class Peer final : public interface::Peer {
     public:
      template <typename PeerType>
      explicit Peer(PeerType &&peer) : proto_(std::forward<PeerType>(peer)) {}

      Peer(const Peer &o) : Peer(o.proto_) {}

      Peer(Peer &&o) noexcept : Peer(std::move(o.proto_)) {}

      const interface::types::AddressType &address() const override {
        return proto_->address();
      }

      const interface::types::TLSCertificateType &tlsCertificate() const override {
        return proto_->tls_certificate();
      }

      const interface::types::PubkeyType &pubkey() const override {
        return public_key_;
      }

     private:
      detail::ReferenceHolder<iroha::protocol::Peer> proto_;
      const interface::types::PubkeyType public_key_{
          crypto::Hash::fromHexString(proto_->peer_key())};
    };
  }  // namespace proto
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_PROTO_PEER_HPP
