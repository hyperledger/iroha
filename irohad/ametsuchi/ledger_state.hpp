/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_LEDGER_STATE_HPP
#define IROHA_LEDGER_STATE_HPP

#include <memory>

#include "interfaces/common_objects/peer.hpp"
#include "interfaces/common_objects/types.hpp"

namespace iroha {
  using PeerList = std::vector<std::shared_ptr<shared_model::interface::Peer>>;

  struct LedgerState {
    std::shared_ptr<PeerList> ledger_peers;
    shared_model::interface::types::HeightType height;

    LedgerState(std::shared_ptr<PeerList> peers,
                shared_model::interface::types::HeightType height)
        : ledger_peers(std::move(peers)), height(height) {}
  };
}  // namespace iroha

#endif  // IROHA_LEDGER_STATE_HPP
