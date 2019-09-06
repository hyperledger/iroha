/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PEER_QUERY_WSV_HPP
#define IROHA_PEER_QUERY_WSV_HPP

#include "ametsuchi/peer_query.hpp"

#include <memory>
#include <vector>

#include "interfaces/common_objects/types.hpp"

namespace iroha {
  namespace ametsuchi {

    class WsvQuery;

    /**
     * Implementation of PeerQuery interface based on WsvQuery fetching
     */
    class PeerQueryWsv : public PeerQuery {
     public:
      explicit PeerQueryWsv(std::shared_ptr<WsvQuery> wsv);

      /**
       * Fetch peers stored in ledger
       * @return list of peers in insertion to ledger order
       */
      boost::optional<std::vector<wPeer>> getLedgerPeers() override;

      /**
       * Fetch peer with given address from ledger
       * @return the peer if found, none otherwise
       */
      boost::optional<PeerQuery::wPeer> getLedgerPeerByAddress(
          const shared_model::interface::types::AddressType &address) override;

     private:
      std::shared_ptr<WsvQuery> wsv_;
    };

  }  // namespace ametsuchi
}  // namespace iroha
#endif  // IROHA_PEER_QUERY_WSV_HPP
