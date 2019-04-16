/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PB_COMMON_HPP
#define IROHA_PB_COMMON_HPP

#include "commands.pb.h"
#include "cryptography/ed25519_sha3_impl/internal/sha3_hash.hpp"
#include "model/account.hpp"
#include "model/account_asset.hpp"
#include "model/asset.hpp"
#include "model/domain.hpp"
#include "model/peer.hpp"
#include "model/signature.hpp"
#include "qry_responses.pb.h"

namespace iroha {
  namespace model {
    namespace converters {
      // peer
      protocol::Peer serializePeer(iroha::model::Peer iroha_peer);
      iroha::model::Peer deserializePeer(protocol::Peer pb_peer);

      iroha::protocol::Account serializeAccount(
          const iroha::model::Account &account);
      iroha::protocol::Asset serializeAsset(const iroha::model::Asset &asset);
      iroha::protocol::AccountAsset serializeAccountAsset(
          const iroha::model::AccountAsset &account_asset);
      iroha::protocol::Domain serializeDomain(
          const iroha::model::Domain &domain);
    }  // namespace converters
  }    // namespace model

  /**
   * Calculate hash from protobuf model object
   * @tparam T - protobuf model type
   * @param pb - protobuf model object
   * @return hash of object payload
   */
  template <typename T>
  hash256_t hash(const T &pb) {
    return sha3_256(pb.payload().SerializeAsString());
  }
}  // namespace iroha

#endif  // IROHA_PB_COMMON_HPP
