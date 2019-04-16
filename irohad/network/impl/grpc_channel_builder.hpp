/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_GRPC_CHANNEL_BUILDER_HPP
#define IROHA_GRPC_CHANNEL_BUILDER_HPP

#include <grpc++/grpc++.h>

namespace iroha {
  namespace network {

    /**
     * Creates client which is capable of sending and receiving
     * messages of INT_MAX bytes size
     * @tparam T type for gRPC stub, e.g. proto::Yac
     * @param address ip address for connection, ipv4:port
     * @return gRPC stub of parametrized type
     */
    template <typename T>
    auto createClient(const grpc::string& address) {
      // in order to bypass built-in limitation of gRPC message size
      grpc::ChannelArguments args;
      args.SetMaxSendMessageSize(INT_MAX);
      args.SetMaxReceiveMessageSize(INT_MAX);

      return
          T::NewStub(grpc::CreateCustomChannel(
              address, grpc::InsecureChannelCredentials(), args));
    }
  } // namespace network
} // namespace iroha

#endif  // IROHA_GRPC_CHANNEL_BUILDER_HPP
