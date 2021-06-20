/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/channel_factory_tls.hpp"

#include "interfaces/common_objects/peer.hpp"
#include "network/impl/grpc_channel_params.hpp"
#include "network/impl/tls_credentials.hpp"
#include "network/peer_tls_certificates_provider.hpp"

using namespace iroha::expected;
using namespace iroha::network;

ChannelFactoryTls::ChannelFactoryTls(
    std::optional<std::shared_ptr<const GrpcChannelParams>> maybe_params,
    std::optional<std::shared_ptr<const PeerTlsCertificatesProvider>>
        peer_cert_provider,
    std::optional<std::shared_ptr<const TlsCredentials>> my_creds)
    : ChannelFactory(std::move(maybe_params)),
      peer_cert_provider_(std::move(peer_cert_provider)),
      my_creds_(std::move(my_creds)) {}

Result<std::shared_ptr<grpc::ChannelCredentials>, std::string>
ChannelFactoryTls::getChannelCredentials(
    const shared_model::interface::Peer &peer) const {
  auto options = grpc::SslCredentialsOptions();
  if (peer_cert_provider_) {
    if (auto e = resultToOptionalError(
            peer_cert_provider_.value()->get(peer) |
                [&options](auto &&cert) -> Result<void, std::string> {
              options.pem_root_certs = std::move(cert);
              return {};
            })) {
      return e.value();
    }
  }
  if (my_creds_) {
    options.pem_private_key = my_creds_.value()->private_key;
    options.pem_cert_chain = my_creds_.value()->certificate;
  }
  return grpc::SslCredentials(options);
}
