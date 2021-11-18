/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_ON_DEMAND_OS_NOTIFICATION_HPP
#define IROHA_MOCK_ON_DEMAND_OS_NOTIFICATION_HPP

#include <gmock/gmock.h>

#include "ordering/on_demand_os_transport.hpp"

namespace iroha {
  namespace ordering {
    namespace transport {

      struct MockOdOsNotification : public OdOsNotification {
        MOCK_METHOD(void, onBatches, (CollectionType), (override));

        MOCK_METHOD(void,
                    onRequestProposal,
                    (consensus::Round, shared_model::crypto::Hash const &),
                    (override));
      };

    }  // namespace transport
  }    // namespace ordering
}  // namespace iroha

#endif  // IROHA_MOCK_ON_DEMAND_OS_NOTIFICATION_HPP
