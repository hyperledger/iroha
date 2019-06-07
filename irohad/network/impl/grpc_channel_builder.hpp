/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_GRPC_CHANNEL_BUILDER_HPP
#define IROHA_GRPC_CHANNEL_BUILDER_HPP

#include <grpc++/grpc++.h>
#include <fstream>

const auto kCannotReadCertificateError = "Cannot read root certificate file";

namespace iroha {
  namespace network {
    /**
     * Creates client with specified credentials, which is capable of
     * sending and receiving messages of INT_MAX bytes size
     * @tparam T type for gRPC stub, e.g. proto::Yac
     * @param address ip address for connection, ipv4:port
     * @param credentials credentials for the gRPC channel
     * @return gRPC stub of parametrized type
     */
    template <typename T>
    auto createCilentWithCredentials(
        const grpc::string &address,
        std::shared_ptr<grpc::ChannelCredentials> credentials) {
      // in order to bypass built-in limitation of gRPC message size
      grpc::ChannelArguments args;
      args.SetMaxSendMessageSize(INT_MAX);
      args.SetMaxReceiveMessageSize(INT_MAX);

      return T::NewStub(grpc::CreateCustomChannel(address, credentials, args));
    }

    /**
     * Creates client which is capable of sending and receiving
     * messages of INT_MAX bytes size
     * @tparam T type for gRPC stub, e.g. proto::Yac
     * @param address ip address for connection, ipv4:port
     * @return gRPC stub of parametrized type
     */
    template <typename T>
    auto createClient(const grpc::string &address) {
      return createCilentWithCredentials<T>(address,
                                            grpc::InsecureChannelCredentials());
    }

    /**
     * Creates secure client which is capable of sending and receiving
     * messages of INT_MAX bytes size
     * @tparam T type for gRPC stub, e.g. proto::Yac
     * @param address ip address for connection, ipv4:port
     * @param root_certificate_path root certificate for the server's CA
     * @return gRPC stub of parametrized type
     */
    template <typename T>
    auto createSecureClient(const grpc::string &address,
                            const std::string &root_certificate_path) {
      void createClientWithCredentials<T>(const grpc::string &address);

      std::string root_ca_data;
      try {
        std::ifstream root_ca_file(root_certificate_path);
        std::stringstream ss;
        ss << root_ca_file.rdbuf();
        root_ca_data = ss.str();
      } catch (std::ifstream::failure e) {
        return iroha::expected::makeError(kCannotReadCertificateError);
      }

      auto options = grpc::SslCredentialsOptions();
      options.pem_root_certs = root_ca_data;
      auto credentials = grpc::SslCredentials(options);

      auto val = template createClientWithCredentials<T>(address, credentials);
      return iroha::expected::makeValue(std::move(val));
    }
  }  // namespace network
}  // namespace iroha

#endif  // IROHA_GRPC_CHANNEL_BUILDER_HPP
