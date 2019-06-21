/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CHANNEL_POOL
#define IROHA_CHANNEL_POOL

#include <string>
#include <unordered_map>

#include <grpc++/grpc++.h>

#include "ametsuchi/peer_query.hpp"

namespace iroha {
  namespace network {
    class ChannelPool {
     public:
      /**
       * Constructor with TLS, fetching certificates from peers
       * @param peer_query peer query to use for certificate search
       * @param keypair_path optional path to a pair of PEM-encoded key and
       *        certificate for client authentication
       */
      explicit ChannelPool(
          std::shared_ptr<ametsuchi::PeerQuery> peer_query,
          const boost::optional<std::string> &keypair_path = boost::none);

      /**
       * Constructor with TLS, reading the root certificate from a file
       * @param root_certificate_path - path to the PEM-encoded root certificate
       * @param keypair_path optional path to a pair of PEM-encoded key and
       *        certificate for client authentication
       */
      explicit ChannelPool(
          const std::string &root_certificate_path,
          const boost::optional<std::string> &keypair_path = boost::none);

      /**
       * Constructor without TLS
       */
      ChannelPool();

      /**
       * Get or create a grpc::Channel (from a pool of channels)
       * @param address address to connect to (ip:port)
       * @param root_certificate_path - (optionally) override the certificate
       *        for TLS
       * @return std::shared_ptr<grpc::Channel> to that address
       */
      std::shared_ptr<grpc::Channel> getChannel(const std::string &address);

     private:
      auto createChannel(const std::string &address);
      boost::optional<std::string> getCertificate(const std::string &address);

      std::shared_ptr<grpc::ChannelCredentials> getChannelCredentials(
          const std::string &address);

      std::unordered_map<std::string, std::shared_ptr<grpc::Channel>> channels_;

      bool tls_enabled_ = false;
      boost::optional<std::shared_ptr<ametsuchi::PeerQuery>> peer_query_ =
          boost::none;
      boost::optional<std::string> root_certificate_ = boost::none;
      boost::optional<std::string> private_key_ = boost::none;
      boost::optional<std::string> certificate_ = boost::none;

      static std::string readFile(const std::string &path);
      void readKeypair(const boost::optional<std::string> &path);
    };
  };  // namespace network
};    // namespace iroha

#endif