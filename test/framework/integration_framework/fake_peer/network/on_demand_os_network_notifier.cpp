/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/integration_framework/fake_peer/network/on_demand_os_network_notifier.hpp"

#include <chrono>

#include "backend/protobuf/proposal.hpp"
#include "framework/integration_framework/fake_peer/behaviour/behaviour.hpp"
#include "framework/integration_framework/fake_peer/fake_peer.hpp"
#include "framework/integration_framework/fake_peer/proposal_storage.hpp"
#include "ordering/ordering_types.hpp"

namespace integration_framework::fake_peer {

  OnDemandOsNetworkNotifier::OnDemandOsNetworkNotifier(
      const std::shared_ptr<FakePeer> &fake_peer)
      : fake_peer_wptr_(fake_peer) {}

  void OnDemandOsNetworkNotifier::onBatches(CollectionType batches) {
    std::lock_guard<std::mutex> guard(batches_subject_mutex_);
    batches_subject_.get_subscriber().on_next(
        std::make_shared<BatchesCollection>(std::move(batches)));
  }

  iroha::ordering::PackedProposalData
  OnDemandOsNetworkNotifier::waitForLocalProposal(
      iroha::consensus::Round const &round,
      std::chrono::milliseconds const & /*delay*/) {
    return onRequestProposal(round);
  }

  iroha::ordering::PackedProposalData
  OnDemandOsNetworkNotifier::onRequestProposal(iroha::consensus::Round round) {
    {
      std::lock_guard<std::mutex> guard(rounds_subject_mutex_);
      rounds_subject_.get_subscriber().on_next(round);
    }
    auto fake_peer = fake_peer_wptr_.lock();
    BOOST_ASSERT_MSG(fake_peer, "Fake peer shared pointer is not set!");
    const auto behaviour = fake_peer->getBehaviour();
    if (behaviour) {
      auto opt_proposal = behaviour->processOrderingProposalRequest(round);
      if (opt_proposal) {
        return iroha::ordering::PackedProposalData{{std::make_pair(
            std::shared_ptr<const shared_model::interface::Proposal>(
                std::static_pointer_cast<const shared_model::proto::Proposal>(
                    *opt_proposal)),
            iroha::ordering::BloomFilter256{})}};
      }
    }
    return {};
  }

  void OnDemandOsNetworkNotifier::onCollaborationOutcome(
      iroha::consensus::Round round) {}

  void OnDemandOsNetworkNotifier::onTxsCommitted(const HashesSetType &hashes) {}
  void OnDemandOsNetworkNotifier::onDuplicates(const HashesSetType &hashes) {}

  void OnDemandOsNetworkNotifier::forCachedBatches(
      std::function<void(
          iroha::ordering::OnDemandOrderingService::BatchesSetType &)> const
          &f) {}

  bool OnDemandOsNetworkNotifier::isEmptyBatchesCache() {
    return true;
  }

  bool OnDemandOsNetworkNotifier::hasEnoughBatchesInCache() const {
    return false;
  }

  uint32_t OnDemandOsNetworkNotifier::availableTxsCountBatchesCache() {
    return 0ul;
  }

  void OnDemandOsNetworkNotifier::processReceivedProposal(
      CollectionType batches) {}

  bool OnDemandOsNetworkNotifier::hasProposal(
      iroha::consensus::Round round) const {
    return false;
  }

  rxcpp::observable<iroha::consensus::Round>
  OnDemandOsNetworkNotifier::getProposalRequestsObservable() {
    return rounds_subject_.get_observable();
  }

  rxcpp::observable<std::shared_ptr<BatchesCollection>>
  OnDemandOsNetworkNotifier::getBatchesObservable() {
    return batches_subject_.get_observable();
  }

}  // namespace integration_framework::fake_peer
