/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/integration_framework/fake_peer/network/ordering_gate_network_notifier.hpp"

#include "interfaces/iroha_internal/transaction_batch.hpp"

namespace integration_framework {
  namespace fake_peer {

    void OgNetworkNotifier::onProposal(
        std::shared_ptr<shared_model::interface::Proposal> proposal) {
      std::lock_guard<std::mutex> guard(proposals_subject_mutex_);
      proposals_subject_.get_subscriber().on_next(std::move(proposal));
    }

    rxcpp::observable<std::shared_ptr<shared_model::interface::Proposal>>
    OgNetworkNotifier::getObservable() {
      return proposals_subject_.get_observable();
    }

  }  // namespace fake_peer
}  // namespace integration_framework
