/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/client_factory.hpp"

#include <fstream>
#include <sstream>

#include "endpoint.grpc.pb.h"
#include "loader.grpc.pb.h"
#include "ordering.grpc.pb.h"
#include "yac.grpc.pb.h"

namespace iroha {
  namespace network {
    ClientFactory::ClientFactory(
        std::shared_ptr<ametsuchi::PeerQuery> peer_query,
        const boost::optional<std::string> &keypair_path)
        : channel_pool_(std::move(peer_query), keypair_path),
          tls_enabled_(true) {}

    ClientFactory::ClientFactory(
        const std::string &root_certificate_path,
        const boost::optional<std::string> &keypair_path)
        : channel_pool_(root_certificate_path, keypair_path),
          tls_enabled_(true) {}

    ClientFactory::ClientFactory() : tls_enabled_(false) {}

    template <typename T>
    std::unique_ptr<typename T::Stub> ClientFactory::createClient(
        const std::string &address) {
      auto channel = channel_pool_.getChannel(address);
      return createClientWithChannel<T>(channel);
    }

    bool ClientFactory::isTLSEnabled() {
      return tls_enabled_;
    }

    template <typename T>
    auto ClientFactory::createClientWithChannel(
        std::shared_ptr<grpc::Channel> channel) {
      return T::NewStub(channel);
    }
  }  // namespace network
}  // namespace iroha

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