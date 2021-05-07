/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/integration_framework/fake_peer/network/yac_network_notifier.hpp"

#include "consensus/yac/outcome_messages.hpp"
#include "consensus/yac/transport/impl/network_impl.hpp"
#include "consensus/yac/transport/yac_network_interface.hpp"
#include "consensus/yac/vote_message.hpp"

namespace integration_framework {
  namespace fake_peer {

    std::optional<iroha::consensus::yac::Answer> YacNetworkNotifier::onState(
        YacNetworkNotifier::StateMessage state) {
      auto state_ptr = std::make_shared<const StateMessage>(std::move(state));
      std::lock_guard<std::mutex> guard(votes_subject_mutex_);
      votes_subject_.get_subscriber().on_next(state_ptr);
      return std::nullopt;
    }

    rxcpp::observable<std::shared_ptr<const YacMessage>>
    YacNetworkNotifier::getObservable() {
      return votes_subject_.get_observable();
    }

  }  // namespace fake_peer
}  // namespace integration_framework
