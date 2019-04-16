/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MST_TIME_PROVIDER_IMPL_HPP
#define IROHA_MST_TIME_PROVIDER_IMPL_HPP

#include <chrono>
#include "multi_sig_transactions/mst_time_provider.hpp"

namespace iroha {

  class MstTimeProviderImpl : public MstTimeProvider {
   public:
    TimeType getCurrentTime() const override {
      return std::chrono::system_clock::now().time_since_epoch()
          / std::chrono::milliseconds(1);
    }
  };
}  // namespace iroha

#endif  // IROHA_MST_TIME_PROVIDER_IMPL_HPP
