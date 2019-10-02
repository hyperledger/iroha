/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/generic_client_factory.hpp"

using namespace iroha::network;

GenericClientFactory::GenericClientFactory(
    std::unique_ptr<ChannelProvider> channel_provider)
    : channel_provider_(std::move(channel_provider)) {}
