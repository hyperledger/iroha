/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ORDERING_MOCKS_HPP
#define IROHA_ORDERING_MOCKS_HPP

#include <gmock/gmock.h>

#include "module/irohad/ordering/mock_on_demand_os_notification.hpp"
#include "ordering/impl/ordering_gate_cache/ordering_gate_cache.hpp"
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

    namespace cache {
      struct MockOrderingGateCache : public OrderingGateCache {
        MOCK_METHOD1(addToBack, void(const BatchesSetType &));
        MOCK_METHOD0(pop, BatchesSetType());
        MOCK_METHOD1(remove, void(const HashesSetType &));
        MOCK_CONST_METHOD0(head, const BatchesSetType &());
        MOCK_CONST_METHOD0(tail, const BatchesSetType &());
      };
    }  // namespace cache

    struct MockOnDemandOrderingService : public OnDemandOrderingService {
      MOCK_METHOD1(onBatches, void(CollectionType));

      MOCK_METHOD1(onRequestProposal,
                   std::optional<std::shared_ptr<const ProposalType>>(
                       consensus::Round));

      MOCK_METHOD1(onCollaborationOutcome, void(consensus::Round));
    };

  }  // namespace ordering
}  // namespace iroha

#endif  // IROHA_ORDERING_MOCKS_HPP
