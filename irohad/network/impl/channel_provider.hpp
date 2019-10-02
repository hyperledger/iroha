/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CHANNEL_PROVIDER_HPP
#define IROHA_CHANNEL_PROVIDER_HPP

#include <memory>
#include <string>

#include <grpc++/grpc++.h>
#include "common/result.hpp"

namespace shared_model {
  namespace interface {
    class Peer;
  }
}  // namespace shared_model

namespace iroha {
  namespace network {

    class ChannelProvider {
     public:
      virtual ~ChannelProvider() = default;

      /**
       * Get or create a grpc::Channel (from a pool of channels)
       * @param service_full_name the full name of grpc service,
       *  e.g. iroha.consensus.yac.proto.Yac
       * @param peer the target peer
       * @return std::shared_ptr<grpc::Channel> to that address
       */
      virtual iroha::expected::Result<std::shared_ptr<grpc::Channel>,
                                      std::string>
      getChannel(const std::string &service_full_name,
                 const shared_model::interface::Peer &peer) = 0;
    };

  }  // namespace network
}  // namespace iroha

#endif
