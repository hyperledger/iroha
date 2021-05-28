/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_NETWORK_INTERFACE_HPP
#define IROHA_YAC_NETWORK_INTERFACE_HPP

#include <memory>
#include <optional>
#include <vector>

#include "consensus/yac/storage/storage_result.hpp"

namespace shared_model::interface {
  class Peer;
}  // namespace shared_model::interface

namespace iroha::consensus::yac {
  struct VoteMessage;

  class YacNetworkNotifications {
   public:
    /**
     * Callback on receiving collection of votes
     * @param state - provided message
     */
    virtual std::optional<Answer> onState(std::vector<VoteMessage> state) = 0;

    virtual ~YacNetworkNotifications() = default;
  };

  class YacNetwork {
   public:
    /**
     * Directly share collection of votes
     * @param to - peer recipient
     * @param state - message for sending
     */
    virtual void sendState(const shared_model::interface::Peer &to,
                           const std::vector<VoteMessage> &state) = 0;

    /// Prevent any new outgoing network activity. Be passive.
    virtual void stop() = 0;

    /**
     * Virtual destructor required for inheritance
     */
    virtual ~YacNetwork() = default;
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_YAC_NETWORK_INTERFACE_HPP
