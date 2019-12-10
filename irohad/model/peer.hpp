/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PEER_HPP
#define IROHA_PEER_HPP

#include "crypto/keypair.hpp"

namespace iroha {
  namespace model {

    /**
     * Peer is Model, which contains information about network participants
     */
    struct Peer {
      /**
       * IP address of peer for connection
       */
      std::string address{};

      using AddressType = decltype(address);

      /**
       * Public key of peer
       */
      pubkey_t pubkey{};

      using KeyType = decltype(pubkey);

      bool operator==(const Peer &obj) const {
        if (address == obj.address && pubkey == obj.pubkey) {
          return true;
        } else {
          return false;
        }
      }

      Peer() = default;

      Peer(const AddressType &address, const KeyType &pubkey)
          : address(address), pubkey(pubkey) {}
    };
  }  // namespace model
}  // namespace iroha

namespace std {
  template <>
  struct hash<iroha::model::Peer> {
    std::size_t operator()(const iroha::model::Peer &obj) const {
      auto str = obj.address;
      str.append(reinterpret_cast<const char *>(obj.pubkey.data()),
                 obj.pubkey.size());
      return std::hash<std::string>()(str);
    }
  };
}  // namespace std
#endif  // IROHA_PEER_H
