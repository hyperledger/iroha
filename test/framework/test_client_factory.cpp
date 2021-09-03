/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/test_client_factory.hpp"

#include "common/bind.hpp"
#include "framework/test_logger.hpp"
#include "logger/logger_manager.hpp"
#include "network/impl/channel_factory.hpp"
#include "network/impl/channel_pool.hpp"

namespace iroha {
  namespace network {
    std::unique_ptr<GenericClientFactory> getTestInsecureClientFactory(
        std::optional<std::shared_ptr<const GrpcChannelParams>> maybe_params) {
      std::unique_ptr<ChannelFactory> channel_factory =
          std::make_unique<ChannelFactory>(maybe_params);

      return std::make_unique<GenericClientFactory>(
          std::make_unique<ChannelPool>(std::move(channel_factory)));
    }

    std::shared_ptr<grpc::Channel> createSecureChannel(
        const shared_model::interface::types::AddressType &address,
        const std::string &service_full_name,
        std::optional<shared_model::interface::types::TLSCertificateType>
            peer_cert,
        std::optional<TlsCredentials> my_creds,
        std::optional<std::reference_wrapper<GrpcChannelParams const>>
            maybe_params) {
      auto options = grpc::SslCredentialsOptions();
      if (peer_cert) {
        options.pem_root_certs = std::move(peer_cert).value();
      }
      if (my_creds) {
        options.pem_private_key = my_creds.value().private_key;
        options.pem_cert_chain = my_creds.value().certificate;
      }
      if (not maybe_params)
        return grpc::CreateChannel(address, grpc::SslCredentials(options));

      return grpc::CreateCustomChannel(
          address,
          grpc::SslCredentials(options),
          detail::makeChannelArguments({service_full_name}, *maybe_params));
    }

  }  // namespace network
}  // namespace iroha
