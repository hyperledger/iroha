/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TORII_STATUS_BUS_IMPL
#define TORII_STATUS_BUS_IMPL

#include "torii/status_bus.hpp"

namespace iroha {
  namespace torii {
    /**
     * StatusBus implementation
     */
    class StatusBusImpl : public StatusBus {
     public:
      StatusBusImpl(
          rxcpp::observe_on_one_worker worker = rxcpp::observe_on_new_thread());

      ~StatusBusImpl() override;

      void publish(StatusBus::Objects) override;
      /// Subscribers will be invoked in separate thread
      rxcpp::observable<StatusBus::Objects> statuses() override;

      // Need to create once, otherwise will create thread for each subscriber
      rxcpp::observe_on_one_worker worker_;
      rxcpp::composite_subscription cs_;
      rxcpp::subjects::synchronize<StatusBus::Objects, decltype(worker_)>
          subject_;
    };
  }  // namespace torii
}  // namespace iroha

#endif  // TORII_STATUS_BUS_IMPL
