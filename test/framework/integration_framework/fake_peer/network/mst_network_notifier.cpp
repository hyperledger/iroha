/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/integration_framework/fake_peer/network/mst_network_notifier.hpp"

namespace integration_framework {
  namespace fake_peer {

    void MstNetworkNotifier::onNewState(
        const shared_model::crypto::PublicKey &from,
        iroha::MstState new_state) {
      std::lock_guard<std::mutex> guard(mst_subject_mutex_);
      mst_subject_.get_subscriber().on_next(
          std::make_shared<MstMessage>(from, std::move(new_state)));
    }

    rxcpp::observable<std::shared_ptr<MstMessage>>
    MstNetworkNotifier::getObservable() {
      return mst_subject_.get_observable();
    }

  }  // namespace fake_peer
}  // namespace integration_framework
