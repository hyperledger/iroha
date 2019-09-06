/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CHANNEL_FACTORY_HPP
#define IROHA_CHANNEL_FACTORY_HPP

#include <memory>
#include <set>
#include <string>

#include <grpc++/grpc++.h>

#include "ametsuchi/peer_query.hpp"
#include "common/result.hpp"

namespace iroha {
  namespace network {
    struct GrpcChannelParams;

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

    class ChannelFactory {
     public:
      ChannelFactory(std::shared_ptr<GrpcChannelParams> params);

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
      iroha::expected::Result<std::shared_ptr<grpc::Channel>, std::string>
      createChannel(const std::string &service_full_name,
                    const std::string &address) const;

     protected:
      virtual iroha::expected::Result<std::shared_ptr<grpc::ChannelCredentials>,
                                      std::string>
      getChannelCredentials(const std::string &address) const;

     private:
      class ChannelArgumentsProvider;
      std::unique_ptr<ChannelArgumentsProvider> args_;
    };

  }  // namespace network
}  // namespace iroha

#endif
