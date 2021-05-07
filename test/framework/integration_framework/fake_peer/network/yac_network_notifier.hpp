/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef FAKE_PEER_YAC_NETWORK_NOTIFIER_HPP_
#define FAKE_PEER_YAC_NETWORK_NOTIFIER_HPP_

#include "consensus/yac/transport/yac_network_interface.hpp"

#include <mutex>

#include <rxcpp/rx-lite.hpp>
#include "framework/integration_framework/fake_peer/types.hpp"

namespace integration_framework {
  namespace fake_peer {

    class YacNetworkNotifier final
        : public iroha::consensus::yac::YacNetworkNotifications {
     public:
      using StateMessage = std::vector<iroha::consensus::yac::VoteMessage>;

      std::optional<iroha::consensus::yac::Answer> onState(
          StateMessage state) override;

      rxcpp::observable<std::shared_ptr<const YacMessage>> getObservable();

     private:
      rxcpp::subjects::subject<std::shared_ptr<const YacMessage>>
          votes_subject_;
      std::mutex votes_subject_mutex_;
    };

  }  // namespace fake_peer
}  // namespace integration_framework

#endif /* FAKE_PEER_YAC_NETWORK_NOTIFIER_HPP_ */
