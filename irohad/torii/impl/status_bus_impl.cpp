/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "torii/impl/status_bus_impl.hpp"

namespace iroha {
  namespace torii {
    StatusBusImpl::StatusBusImpl(rxcpp::observe_on_one_worker worker)
        : worker_(worker), subject_(worker_, cs_) {}

    StatusBusImpl::~StatusBusImpl() {
      cs_.unsubscribe();
    }

    void StatusBusImpl::publish(StatusBus::Objects resp) {
      subject_.get_subscriber().on_next(resp);
    }

    rxcpp::observable<StatusBus::Objects> StatusBusImpl::statuses() {
      return subject_.get_observable();
    }
  }  // namespace torii
}  // namespace iroha
