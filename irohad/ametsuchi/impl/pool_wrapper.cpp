/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/pool_wrapper.hpp"

#include "ametsuchi/impl/failover_callback_factory.hpp"

using namespace iroha::ametsuchi;

PoolWrapper::PoolWrapper(
    std::shared_ptr<soci::connection_pool> connection_pool,
    std::unique_ptr<FailoverCallbackFactory> failover_callback_factory,
    bool enable_prepared_transactions)
    : connection_pool_(std::move(connection_pool)),
      failover_callback_factory_(std::move(failover_callback_factory)),
      enable_prepared_transactions_(enable_prepared_transactions) {}
