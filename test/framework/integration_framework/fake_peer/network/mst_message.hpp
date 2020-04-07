/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INTEGRATION_FRAMEWORK_FAKE_PEER_MST_MESSAGE_HPP_
#define INTEGRATION_FRAMEWORK_FAKE_PEER_MST_MESSAGE_HPP_

#include "multi_sig_transactions/state/mst_state.hpp"

namespace integration_framework {
  namespace fake_peer {
    struct MstMessage final {
      MstMessage(shared_model::interface::types::PublicKeyHexStringView f,
                 iroha::MstState s)
          : peer_hex_key_from(f), state(std::move(s)) {}
      std::string peer_hex_key_from;
      iroha::MstState state;
    };
  }  // namespace fake_peer
}  // namespace integration_framework

#endif /* INTEGRATION_FRAMEWORK_FAKE_PEER_MST_MESSAGE_HPP_ */
