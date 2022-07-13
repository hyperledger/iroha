/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_ON_DEMAND_OS_NOTIFICATION_HPP
#define IROHA_MOCK_ON_DEMAND_OS_NOTIFICATION_HPP

#include "ordering/on_demand_os_transport.hpp"
#include "ordering/ordering_types.hpp"

#include <gmock/gmock.h>

namespace iroha {
  namespace ordering {
    namespace transport {

      struct MockOdOsNotification : public OdOsNotification {
        MOCK_METHOD1(onBatches, void(CollectionType));
        MOCK_METHOD1(onBatchesToWholeNetwork, void(CollectionType));
        MOCK_METHOD2(onRequestProposal,
                     void(consensus::Round, PackedProposalData));
        MOCK_CONST_METHOD0(getRequestDelay, std::chrono::milliseconds());
      };

    }  // namespace transport
  }    // namespace ordering
}  // namespace iroha

#endif  // IROHA_MOCK_ON_DEMAND_OS_NOTIFICATION_HPP
