/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/peer_query_wsv.hpp"

#include <numeric>

#include "ametsuchi/wsv_query.hpp"

namespace iroha {
  namespace ametsuchi {

    PeerQueryWsv::PeerQueryWsv(std::shared_ptr<WsvQuery> wsv)
        : wsv_(std::move(wsv)) {}

    boost::optional<std::vector<PeerQuery::wPeer>>
    PeerQueryWsv::getLedgerPeers() {
      return wsv_->getPeers();
    }

    boost::optional<PeerQuery::wPeer> PeerQueryWsv::getLedgerPeerByPublicKey(
        const shared_model::interface::types::PubkeyType &public_key) {
      return wsv_->getPeerByPublicKey(public_key);
    }

  }  // namespace ametsuchi
}  // namespace iroha
