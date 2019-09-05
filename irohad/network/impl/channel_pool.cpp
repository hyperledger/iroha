/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/channel_pool.hpp"

#include <fstream>
#include <sstream>

#include "backend/protobuf/common_objects/peer.hpp"

namespace iroha {
  namespace network {
    ChannelPool::ChannelPool(std::shared_ptr<ametsuchi::PeerQuery> peer_query,
                             const boost::optional<std::string> &keypair_path)
        : tls_enabled_(true), peer_query_(peer_query) {
      readKeypair(keypair_path);
    }

    ChannelPool::ChannelPool(const std::string &root_certificate_path,
                             const boost::optional<std::string> &keypair_path)
        : tls_enabled_(true),
          root_certificate_(readFile(root_certificate_path)) {
      readKeypair(keypair_path);
    }

    ChannelPool::ChannelPool() : tls_enabled_(false) {}

    auto ChannelPool::createChannel(const std::string &address) {
      // in order to bypass built-in limitation of gRPC message size
      grpc::ChannelArguments args;
      args.SetMaxSendMessageSize(INT_MAX);
      args.SetMaxReceiveMessageSize(INT_MAX);

      return grpc::CreateCustomChannel(
          address, getChannelCredentials(address), args);
    }

    std::shared_ptr<grpc::Channel> ChannelPool::getChannel(
        const std::string &address) {
      if (channels_.find(address) == channels_.end()) {
        channels_[address] = createChannel(address);
      }
      return channels_[address];
    }

    boost::optional<std::string> ChannelPool::getCertificate(
        const std::string &address) {
      if (not tls_enabled_)
        return boost::none;
      auto peers = (*peer_query_)->getLedgerPeers();
      for (const auto &peer : *peers) {
        if (peer->address() == address) {
          return peer->tlsCertificate();
        }
      }
      return boost::none;
    }

    std::shared_ptr<grpc::ChannelCredentials>
    ChannelPool::getChannelCredentials(const std::string &address) {
      if (root_certificate_) {
        auto options = grpc::SslCredentialsOptions();
        options.pem_root_certs = *root_certificate_;
        return grpc::SslCredentials(options);
      }
      if (tls_enabled_) {
        auto options = grpc::SslCredentialsOptions();
        auto cert = getCertificate(address);
        options.pem_root_certs = *cert;
        if (private_key_) {
          options.pem_private_key = *private_key_;
        }
        if (certificate_) {
          options.pem_cert_chain = *certificate_;
        }
        return grpc::SslCredentials(options);
      } else {
        return grpc::InsecureChannelCredentials();
      }
    }

    std::string ChannelPool::readFile(const std::string &path) {
      std::ifstream certificate_file(path);
      std::stringstream ss;
      ss << certificate_file.rdbuf();
      return ss.str();
    }

    void ChannelPool::readKeypair(const boost::optional<std::string> &path) {
      if (path) {
        private_key_ = readFile(*path + ".key");
        certificate_ = readFile(*path + ".crt");
      }
    }
  };  // namespace network
};    // namespace iroha
