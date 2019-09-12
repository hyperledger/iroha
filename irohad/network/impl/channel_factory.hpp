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

#include "ametsuchi/peer_query.hpp"
#include "interfaces/common_objects/types.hpp"
#include "network/impl/grpc_channel_params.hpp"

namespace shared_model {
  namespace interface {
    class Peer;
  }
}  // namespace shared_model

namespace iroha {
  namespace network {

    /**
     * Creates client params which enable sending and receiving messages of
     * INT_MAX bytes size with retries...
     */
    std::unique_ptr<GrpcChannelParams> getDefaultChannelParams();

    grpc::ChannelArguments makeChannelArguments(
        const std::set<std::string> &services, const GrpcChannelParams &params);

    /**
     * Creates channel arguments out of provided params.
     * @tparam T type for gRPC stub, e.g. proto::Yac
     * @param params grpc channel params
     * @return gRPC channel arguments
     */
    template <typename T>
    grpc::ChannelArguments makeChannelArguments(
        const GrpcChannelParams &params) {
      return makeChannelArguments(T::service_full_name(), params);
    }

    /**
     * Creates client
     * @tparam Service type for gRPC stub, e.g. proto::Yac
     * @param address ip address and port for connection, ipv4:port
     * @return gRPC stub of parametrized type
     */
    template <typename Service>
    std::unique_ptr<typename Service::StubInterface> createInsecureClient(
        const std::string &address, const GrpcChannelParams &params) {
      auto channel =
          createInsecureChannel(address, Service::service_full_name(), params);
    }

    std::shared_ptr<grpc::Channel> createInsecureChannel(
        const shared_model::interface::types::AddressType &address,
        const std::string &service_full_name,
        const GrpcChannelParams &params);

    class ChannelFactory : public ChannelProvider {
     public:
      ChannelFactory(std::shared_ptr<const GrpcChannelParams> params);

      virtual ~ChannelFactory();

      /**
       * Get or create a grpc::Channel (from a pool of channels)
       * @param address address to connect to (ip:port)
       * @param root_certificate_path - (optionally) override the certificate
       *        for TLS
       * @return result with a channel to that address or string error
       *
       * @note the return type has shared_ptr due to the grpc interface
       */
      std::shared_ptr<grpc::Channel> createChannel(
          const std::string &service_full_name,
          const shared_model::interface::Peer &peer) override;

     protected:
      virtual std::shared_ptr<grpc::ChannelCredentials> getChannelCredentials(
          const shared_model::interface::Peer &) const;

     private:
      class ChannelArgumentsProvider;
      std::unique_ptr<ChannelArgumentsProvider> args_;
    };

  }  // namespace network
}  // namespace iroha

#endif
