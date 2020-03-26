/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_UTILITY_STATUS_HPP
#define IROHA_UTILITY_STATUS_HPP

namespace iroha {
  namespace utility_service {

    enum class Status {
      kUnknown,
      kInitialization,
      kRunning,
      kTermination,
      kStopped,
      kFailed,
    };

  }  // namespace utility_service
}  // namespace iroha

#endif  // IROHA_UTILITY_STATUS_HPP
