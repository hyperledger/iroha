/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/pool_wrapper.hpp"

#include <soci/soci.h>
#include "ametsuchi/impl/failover_callback_holder.hpp"

using namespace iroha::ametsuchi;

PoolWrapper::PoolWrapper(
    std::shared_ptr<soci::connection_pool> connection_pool,
    std::unique_ptr<FailoverCallbackHolder> failover_callback_holder,
    bool enable_prepared_transactions)
    : connection_pool_(std::move(connection_pool)),
      failover_callback_holder_(std::move(failover_callback_holder)),
      enable_prepared_transactions_(enable_prepared_transactions) {}
