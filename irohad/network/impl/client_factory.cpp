/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/client_factory.hpp"

#include "network/impl/channel_pool.hpp"

using namespace iroha::network;

template <typename T>
std::unique_ptr<typename T::Stub> ClientFactory::createClient(
    const std::string &address) {
  auto channel = channel_pool_->getChannel(address);
  return T::template NewStub<T>(channel);
}

/*
// predefined template instances, because other targets could not link properly
// against non-instantiated templates
#define INSTANTIATE_CLIENT_FOR(T)   \
  template std::unique_ptr<T::Stub> \
  iroha::network::ClientFactory::createClient<T>(const std::string &);

INSTANTIATE_CLIENT_FOR(iroha::protocol::CommandService_v1)
INSTANTIATE_CLIENT_FOR(iroha::protocol::QueryService_v1)
INSTANTIATE_CLIENT_FOR(iroha::consensus::yac::proto::Yac)
INSTANTIATE_CLIENT_FOR(iroha::ordering::proto::OnDemandOrdering)
INSTANTIATE_CLIENT_FOR(iroha::network::proto::Loader)
*/
