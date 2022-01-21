/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_LEDGER_STATE_HPP
#define IROHA_LEDGER_STATE_HPP

#include "cryptography/hash.hpp"
#include "interfaces/common_objects/peer.hpp"
#include "interfaces/common_objects/types.hpp"

namespace iroha {
  struct TopBlockInfo {
    shared_model::interface::types::HeightType height;
    shared_model::crypto::Hash top_hash;

    TopBlockInfo() {}

    TopBlockInfo(shared_model::interface::types::HeightType height,
                 shared_model::crypto::Hash top_hash)
        : height(height), top_hash(std::move(top_hash)) {}
  };

  struct LedgerState {
    shared_model::interface::types::PeerList ledger_peers;
    shared_model::interface::types::PeerList ledger_syncing_peers;
    TopBlockInfo top_block_info;

    LedgerState(shared_model::interface::types::PeerList peers,
                shared_model::interface::types::PeerList syncing_peers,
                shared_model::interface::types::HeightType height,
                shared_model::crypto::Hash top_hash)
        : ledger_peers(std::move(peers)),
          ledger_syncing_peers(std::move(syncing_peers)),
          top_block_info(height, std::move(top_hash)) {}
  };
}  // namespace iroha

#endif  // IROHA_LEDGER_STATE_HPP
