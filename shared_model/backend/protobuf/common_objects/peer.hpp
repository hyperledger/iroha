/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_PEER_HPP
#define IROHA_SHARED_MODEL_PROTO_PEER_HPP

#include "interfaces/common_objects/peer.hpp"

#include <optional>

#include "backend/protobuf/util.hpp"
#include "common/result.hpp"
#include "cryptography/hash.hpp"
#include "cryptography/public_key.hpp"
#include "primitive.pb.h"
#include "utils/reference_holder.hpp"

namespace shared_model {
  namespace proto {
    class Peer final : public interface::Peer {
     public:
      template <typename PeerType>
      static iroha::expected::Result<std::unique_ptr<Peer>, std::string> create(
          PeerType &&peer) {
        return shared_model::crypto::Blob::fromHexString(peer.peer_key()) |
            [&](auto &&pubkey) {
              return std::make_unique<Peer>(
                  std::forward<PeerType>(peer),
                  interface::types::PubkeyType{std::move(pubkey)});
            };
      }

      template <typename PeerType>
      Peer(PeerType &&peer, interface::types::PubkeyType pubkey)
          : proto_(std::forward<PeerType>(peer)),
            public_key_(std::move(pubkey)) {
        if (proto_->certificate_case()) {
          tls_certificate_ = proto_->tls_certificate();
        }
      }

      const interface::types::AddressType &address() const override {
        return proto_->address();
      }

      const std::optional<interface::types::TLSCertificateType>
          &tlsCertificate() const override {
        return tls_certificate_;
      }

      const interface::types::PubkeyType &pubkey() const override {
        return public_key_;
      }

     private:
      detail::ReferenceHolder<iroha::protocol::Peer> proto_;
      const interface::types::PubkeyType public_key_;
      std::optional<std::string> tls_certificate_;
    };
  }  // namespace proto
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_PROTO_PEER_HPP
