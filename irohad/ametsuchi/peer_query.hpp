/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PEER_QUERY_HPP
#define IROHA_PEER_QUERY_HPP

#include <memory>
#include <vector>

#include <boost/optional.hpp>
#include "interfaces/common_objects/string_view_types.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    class Peer;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace ametsuchi {

    /**
     * Interface provide clean dependency for getting peers in system
     */
    class PeerQuery {
     protected:
      using wPeer = std::shared_ptr<shared_model::interface::Peer>;

     public:
      // TODO andrei 17.10.18 IR-1764 Make PeerQuery::getLedgerPeers const

      /**
       * Fetch peers stored in ledger
       * @return list of peers in insertion to ledger order
       */
      virtual boost::optional<std::vector<wPeer>> getLedgerPeers(
          bool syncing_peers) = 0;

      /**
       * Fetch peer with given public key from ledger
       * @return the peer if found, none otherwise
       */
      virtual boost::optional<PeerQuery::wPeer> getLedgerPeerByPublicKey(
          shared_model::interface::types::PublicKeyHexStringView public_key)
          const = 0;

      virtual ~PeerQuery() = default;
    };

  }  // namespace ametsuchi
}  // namespace iroha
#endif  // IROHA_PEER_QUERY_HPP
