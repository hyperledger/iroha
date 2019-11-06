/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CHANNEL_FACTORY_HPP
#define IROHA_CHANNEL_FACTORY_HPP

#include "network/impl/channel_provider.hpp"

#include <memory>
#include <set>
#include <string>

#include <grpc++/grpc++.h>

#include "common/result.hpp"
#include "interfaces/common_objects/types.hpp"
#include "network/impl/grpc_channel_params.hpp"

namespace iroha {
  namespace network {

    /**
     * Creates client params which enable sending and receiving messages of
     * INT_MAX bytes size with retries (see implementation for details).
     */
    std::unique_ptr<GrpcChannelParams> getDefaultChannelParams();

    grpc::ChannelArguments makeChannelArguments(
        const std::set<std::string> &services, const GrpcChannelParams &params);

    /**
     * Creates channel arguments corresponding to provided params.
     * @tparam Service type for gRPC stub, e.g. proto::Yac
     * @param params grpc channel params
     * @return gRPC channel arguments
     */
    template <typename Service>
    grpc::ChannelArguments makeChannelArguments(
        const GrpcChannelParams &params) {
      return makeChannelArguments(Service::service_full_name(), params);
    }

    /**
     * Creates client
     * @tparam Service type for gRPC stub, e.g. proto::Yac
     * @param address ip address and port for connection, ipv4:port
     * @param params grpc channel params
     * @return gRPC stub of parametrized type
     */
    template <typename Service>
    std::unique_ptr<typename Service::StubInterface> createInsecureClient(
        const std::string &address, const GrpcChannelParams &params) {
      auto channel =
          createInsecureChannel(address, Service::service_full_name(), params);
      return Service::NewStub(std::move(channel));
    }

    /**
     * Creates client
     * @tparam Service type for gRPC stub, e.g. proto::Yac
     * @param address ip address to connect to
     * @param port port to connect to
     * @param params grpc channel params
     * @return gRPC stub of parametrized type
     */
    template <typename Service>
    std::unique_ptr<typename Service::StubInterface> createInsecureClient(
        const std::string &ip, size_t port, const GrpcChannelParams &params) {
      return createInsecureClient<Service>(ip + ":" + std::to_string(port),
                                           params);
    }

    /**
     * Creates client
     * @param address ip address and port to connect to, ipv4:port
     * @param service_full_name gRPC service full name,
     *  e.g. iroha.consensus.yac.proto.Yac
     * @param params grpc channel params
     * @return grpc channel with provided params
     */
    std::shared_ptr<grpc::Channel> createInsecureChannel(
        const shared_model::interface::types::AddressType &address,
        const std::string &service_full_name,
        const GrpcChannelParams &params);

    class ChannelFactory : public ChannelProvider {
     public:
      /// @param params grpc channel params
      ChannelFactory(std::shared_ptr<const GrpcChannelParams> params);

      ~ChannelFactory() override;

      iroha::expected::Result<std::shared_ptr<grpc::Channel>, std::string>
      getChannel(const std::string &service_full_name,
                 const shared_model::interface::Peer &peer) override;

     protected:
      virtual iroha::expected::Result<std::shared_ptr<grpc::ChannelCredentials>,
                                      std::string>
      getChannelCredentials(const shared_model::interface::Peer &) const;

     private:
      class ChannelArgumentsProvider;
      std::unique_ptr<ChannelArgumentsProvider> args_;
    };

  }  // namespace network
}  // namespace iroha

#endif
