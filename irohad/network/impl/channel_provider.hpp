/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CHANNEL_PROVIDER_HPP
#define IROHA_CHANNEL_PROVIDER_HPP

#include <memory>
#include <string>

#include <grpc++/grpc++.h>

namespace shared_model {
  namespace interface {
    class Peer;
  }
}  // namespace shared_model

namespace iroha {
  namespace network {
    class ChannelFactory;

    class ChannelProvider {
     public:
      virtual ~ChannelProvider() = default;

      /**
       * Get or create a grpc::Channel (from a pool of channels)
       * @param address address to connect to (ip:port)
       * @param root_certificate_path - (optionally) override the certificate
       *        for TLS
       * @return std::shared_ptr<grpc::Channel> to that address
       */
      virtual std::shared_ptr<grpc::Channel> getChannel(
          const std::string &service_full_name,
          const shared_model::interface::Peer &peer) = 0;
    };

  }  // namespace network
}  // namespace iroha

#endif
