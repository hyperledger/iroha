/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CLIENT_PROVIDER
#define IROHA_CLIENT_PROVIDER

#include "network/impl/channel_pool.hpp"

#include <string>

#include <boost/optional.hpp>

namespace iroha {
  namespace network {
    class ClientFactory {
     public:
      /**
       * Constructor with TLS, fetching certificates from peer data
       * @param peer_query peer query to fetch TLS certificates for peers
       * @param keypair_path optional path to a pair of PEM-encoded key and
       *        certificate for client authentication
       */
      ClientFactory(
          std::shared_ptr<ametsuchi::PeerQuery> peer_query,
          const boost::optional<std::string> &keypair_path = boost::none);

      /**
       * Constructor with TLS, fetching certificate from a file
       * @param root_certificate_path path to the PEM-encoded root certificate
       * @param keypair_path optional path to a pair of PEM-encoded key and
       *        certificate for client authentication
       */
      ClientFactory(
          const std::string &root_certificate_path,
          const boost::optional<std::string> &keypair_path = boost::none);

      /**
       * Constructor without TLS
       */
      ClientFactory();

      /**
       * Creates client which is capable of sending and receiving
       * messages of INT_MAX bytes size
       * @tparam T type for gRPC stub, e.g. proto::Yac
       * @param address ip address for connection, ipv4:port
       * @return gRPC stub of parametrized type
       */
      template <typename T>
      std::unique_ptr<typename T::Stub> createClient(
          const std::string &address);

      /**
       * Is TLS enabled in this factory?
       * @return whether TLS is enabled
       */
      bool isTLSEnabled();

     private:
      template <typename T>
      auto createClientWithChannel(std::shared_ptr<grpc::Channel> channel);

      ChannelPool channel_pool_;
      bool tls_enabled_ = false;
    };
  }  // namespace network
}  // namespace iroha

#endif  // IROHA_CLIENT_PROVIDER