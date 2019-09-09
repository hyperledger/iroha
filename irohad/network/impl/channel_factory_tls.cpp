/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/channel_factory_tls.hpp"

#include "network/impl/grpc_channel_params.hpp"
#include "network/impl/peer_tls_certificates_provider.hpp"

using namespace iroha::expected;
using namespace iroha::network;

ChannelFactoryTls::ChannelFactoryTls(
    std::shared_ptr<GrpcChannelParams> params,
    std::unique_ptr<PeerTlsCertificatesProvider> peer_cert_provider,
    boost::optional<TlsCredentials> my_creds)
    : ChannelFactory(std::move(params)),
      peer_cert_provider_(std::move(peer_cert_provider)),
      my_creds_(std::move(my_creds)) {}

Result<std::shared_ptr<grpc::ChannelCredentials>, std::string>
ChannelFactoryTls::getChannelCredentials(const std::string &address) const {
  return peer_cert_provider_->get(address) | [this](auto &&cert) {
    auto options = grpc::SslCredentialsOptions();
    options.pem_root_certs = std::move(cert);
    if (my_creds_) {
      options.pem_private_key = my_creds_->private_key;
      options.pem_cert_chain = my_creds_->certificate;
    }
    return grpc::SslCredentials(options);
  };
}
