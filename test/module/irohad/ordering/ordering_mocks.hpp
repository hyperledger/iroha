/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ORDERING_MOCKS_HPP
#define IROHA_ORDERING_MOCKS_HPP

#include <gmock/gmock.h>

#include "interfaces/common_objects/peer.hpp"
#include "module/irohad/ordering/mock_on_demand_os_notification.hpp"
#include "ordering/on_demand_ordering_service.hpp"
#include "ordering/on_demand_os_transport.hpp"

namespace iroha::ordering::transport {
  struct MockOdOsNotificationFactory : public OdOsNotificationFactory {
    MOCK_METHOD((iroha::expected::Result<std::unique_ptr<OdOsNotification>,
                                         std::string>),
                create,
                (const shared_model::interface::Peer &),
                (override));
    MOCK_CONST_METHOD0(getRequestDelay, std::chrono::milliseconds());
  };
}  // namespace iroha::ordering::transport

namespace iroha::ordering {
  struct MockOnDemandOrderingService : public OnDemandOrderingService {
    MOCK_METHOD(void, onBatches, (CollectionType), (override));

    MOCK_METHOD(PackedProposalData,
                onRequestProposal,
                (consensus::Round),
                (override));

    MOCK_METHOD0(availableTxsCountBatchesCache, uint32_t());
    MOCK_METHOD(void, onCollaborationOutcome, (consensus::Round), (override));
    MOCK_METHOD(void, onTxsCommitted, (const HashesSetType &), (override));
    MOCK_METHOD(void, onDuplicates, (const HashesSetType &), (override));
    MOCK_METHOD1(forCachedBatches,
                 void(std::function<void(
                          OnDemandOrderingService::BatchesSetType &)> const &));
    MOCK_METHOD(bool, isEmptyBatchesCache, (), (override));
    MOCK_METHOD(bool, hasEnoughBatchesInCache, (), (const, override));
    MOCK_METHOD(bool, hasProposal, (consensus::Round), (const, override));
    MOCK_METHOD(void, processReceivedProposal, (CollectionType), (override));

    MOCK_METHOD2(waitForLocalProposal,
                 PackedProposalData(consensus::Round const &,
                                    std::chrono::milliseconds const &));
  };
}  // namespace iroha::ordering

#endif  // IROHA_ORDERING_MOCKS_HPP
