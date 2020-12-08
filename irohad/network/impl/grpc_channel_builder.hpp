/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_GRPC_CHANNEL_BUILDER_HPP
#define IROHA_GRPC_CHANNEL_BUILDER_HPP

#include <limits>
#include <memory>

#include <fmt/format.h>
#include <grpc++/grpc++.h>

namespace iroha {
  namespace network {
    namespace details {
      constexpr unsigned int kMaxRequestMessageBytes =
          std::numeric_limits<int>::max();
      constexpr unsigned int kMaxResponseMessageBytes =
          std::numeric_limits<int>::max();
      constexpr unsigned int kClientRequestRetryAttempts = 3;
      constexpr unsigned int kClientRequestTimeoutSeconds = 10;

      template <typename T>
      grpc::ChannelArguments getChannelArguments() {
        grpc::ChannelArguments args;
        args.SetServiceConfigJSON(fmt::format(R"(
            {{
              "methodConfig": [ {{
                "name": [
                  {{ "service": "{}" }}
                ],
                "retryPolicy": {{
                  "maxAttempts": {},
                  "initialBackoff": "1s",
                  "maxBackoff": "2s",
                  "backoffMultiplier": 1.2,
                  "retryableStatusCodes": [
                    "UNKNOWN",
                    "DEADLINE_EXCEEDED",
                    "ABORTED",
                    "INTERNAL"
                  ]
                }},
                "maxRequestMessageBytes": {},
                "maxResponseMessageBytes": {},
                "timeout": "{}s"
              }} ]
            }})",
                                              T::service_full_name(),
                                              kClientRequestRetryAttempts,
                                              kMaxRequestMessageBytes,
                                              kMaxResponseMessageBytes,
                                              kClientRequestTimeoutSeconds));
        return args;
      }
    }  // namespace details

    /**
     * Creates client with specified credentials, which is capable of
     * sending and receiving messages of INT_MAX bytes size with retry policy
     * (see details::getChannelArguments()).
     * @tparam T type for gRPC stub, e.g. proto::Yac
     * @param address ip address for connection, ipv4:port
     * @param credentials credentials for the gRPC channel
     * @return gRPC stub of parametrized type
     */
    template <typename T>
    auto createClientWithCredentials(
        const grpc::string &address,
        std::shared_ptr<grpc::ChannelCredentials> credentials) {
      return T::NewStub(grpc::CreateCustomChannel(
          address, credentials, details::getChannelArguments<T>()));
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
      return createClientWithCredentials<T>(address,
                                            grpc::InsecureChannelCredentials());
    }

    /**
     * Creates secure client which is capable of sending and receiving
     * messages of INT_MAX bytes size
     * @tparam T type for gRPC stub, e.g. proto::Yac
     * @param address ip address for connection, ipv4:port
     * @param root_certificate root certificate for the server's CA
     * @return gRPC stub of parametrized type
     */
    template <typename T>
    std::unique_ptr<typename T::Stub> createSecureClient(
        const grpc::string &address, const std::string &root_certificate) {
      auto options = grpc::SslCredentialsOptions();
      options.pem_root_certs = root_certificate;
      auto credentials = grpc::SslCredentials(options);

      return createClientWithCredentials<T>(address, credentials);
    }
  }  // namespace network
}  // namespace iroha

#endif  // IROHA_GRPC_CHANNEL_BUILDER_HPP
