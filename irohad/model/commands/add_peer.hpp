/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ADD_PEER_HPP
#define IROHA_ADD_PEER_HPP

#include "model/command.hpp"
#include "model/peer.hpp"

namespace iroha {
  namespace model {

    struct Peer;

    /**
     * Provide user's intent for adding peer to current network
     */
    struct AddPeer : public Command {
      Peer peer;

      bool operator==(const Command &command) const override;

      AddPeer() {}

      AddPeer(const Peer &peer) : peer(peer) {}
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_ADD_PEER_HPP
