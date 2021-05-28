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

namespace iroha {
  namespace ordering {
    namespace transport {

      struct MockOdOsNotificationFactory : public OdOsNotificationFactory {
        MOCK_METHOD1(create,
                     iroha::expected::Result<std::unique_ptr<OdOsNotification>,
                                             std::string>(
                         const shared_model::interface::Peer &));
      };

    }  // namespace transport

    struct MockOnDemandOrderingService : public OnDemandOrderingService {
      MOCK_METHOD1(onBatches, void(CollectionType));

      MOCK_METHOD1(
          onRequestProposal,
          std::optional<std::shared_ptr<const ProposalType>>(consensus::Round));

      MOCK_METHOD1(onCollaborationOutcome, void(consensus::Round));
      MOCK_METHOD1(onTxsCommitted, void(const HashesSetType &));
      MOCK_METHOD1(
          forCachedBatches,
          void(std::function<
               void(const OnDemandOrderingService::BatchesSetType &)> const &));
      MOCK_METHOD(bool, isEmptyBatchesCache, (), (const, override));
      MOCK_METHOD(bool, hasProposal, (consensus::Round), (const, override));
    };

  }  // namespace ordering
}  // namespace iroha

#endif  // IROHA_ORDERING_MOCKS_HPP
