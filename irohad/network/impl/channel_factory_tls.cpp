/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/channel_factory_tls.hpp"

#include "interfaces/common_objects/peer.hpp"
#include "logger/logger.hpp"
#include "network/impl/grpc_channel_params.hpp"
#include "network/impl/peer_tls_certificates_provider.hpp"

using namespace iroha::expected;
using namespace iroha::network;

ChannelFactoryTls::ChannelFactoryTls(
    std::shared_ptr<const GrpcChannelParams> params,
    boost::optional<std::shared_ptr<PeerTlsCertificatesProvider>>
        peer_cert_provider,
    boost::optional<std::shared_ptr<const TlsCredentials>> my_creds,
    logger::LoggerPtr log)
    : ChannelFactory(std::move(params)),
      peer_cert_provider_(std::move(peer_cert_provider)),
      my_creds_(std::move(my_creds)),
      log_(std::move(log)) {}

std::shared_ptr<grpc::ChannelCredentials>
ChannelFactoryTls::getChannelCredentials(
    const shared_model::interface::Peer &peer) const {
  auto options = grpc::SslCredentialsOptions();
  if (peer_cert_provider_) {
    peer_cert_provider_.value()->get(peer).match(
        [&options](auto &&cert) {
          options.pem_root_certs = std::move(cert.value);
        },
        [this](const auto &error) {
          this->log_->error("Skipping certificate check for peer {}. {}",
                            error.error);
        });
  }
  if (my_creds_) {
    options.pem_private_key = my_creds_.value()->private_key;
    options.pem_cert_chain = my_creds_.value()->certificate;
  }
  return grpc::SslCredentials(options);
}
