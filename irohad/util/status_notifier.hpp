/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_UTILITY_STATUS_NOTIFIER_HPP
#define IROHA_UTILITY_STATUS_NOTIFIER_HPP

#include "util/status.hpp"

namespace iroha {
  namespace utility_service {

    class StatusNotifier {
     public:
      virtual ~StatusNotifier();

      virtual void notify(Status status);
    };

  }  // namespace utility_service
}  // namespace iroha

#endif  // IROHA_UTILITY_STATUS_NOTIFIER_HPP
