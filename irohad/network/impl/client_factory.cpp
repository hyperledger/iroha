/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/client_factory.hpp"

using namespace iroha::network;

ClientFactory::ClientFactory(std::unique_ptr<ChannelPool> channel_pool)
    : channel_pool_(std::move(channel_pool)) {}
