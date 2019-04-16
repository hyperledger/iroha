/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MST_TIME_PROVIDER_HPP
#define IROHA_MST_TIME_PROVIDER_HPP

#include "multi_sig_transactions/mst_types.hpp"

namespace iroha {

  /**
   * Interface provides current time for iroha
   */
  class MstTimeProvider {
   public:
    virtual ~MstTimeProvider() = default;
    /**
     * Fetching current time in system
     * @return current time
     */
    virtual TimeType getCurrentTime() const = 0;
  };
}  // namespace iroha

#endif  // IROHA_MST_TIME_PROVIDER_HPP
