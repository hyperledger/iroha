/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/channel_factory_tls.hpp"

#include <fstream>
#include <sstream>

#include "common/bind.hpp"
#include "network/impl/grpc_channel_params.hpp"
#include "network/impl/peer_tls_certificates_provider.hpp"

using namespace iroha::expected;
using namespace iroha::network;

using iroha::operator|;

ChannelFactoryTls::ChannelFactoryTls(
    std::shared_ptr<GrpcChannelParams> params,
    std::unique_ptr<PeerTlsCertificatesProvider> peer_cert_provider,
    boost::optional<ClientTlsCredentials> my_creds)
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

Result<std::unique_ptr<ChannelFactoryTls>, std::string>
ChannelFactoryTls::create(
    std::unique_ptr<GrpcChannelParams> params,
    std::unique_ptr<PeerTlsCertificatesProvider> peer_cert_provider,
    const boost::optional<std::string> &my_creds_path) {
  static const auto read_file = [](const std::string &path) {
    std::ifstream certificate_file(path);
    std::stringstream ss;
    ss << certificate_file.rdbuf();
    return ss.str();
  };
  boost::optional<ClientTlsCredentials> my_creds;
  try {
    my_creds = my_creds_path | [](const auto &my_creds_path) {
      ClientTlsCredentials my_creds;
      my_creds.private_key = read_file(my_creds_path + ".key");
      my_creds.certificate = read_file(my_creds_path + ".crt");
      return my_creds;
    };
  } catch (std::exception e) {
    return makeError(e.what());
  }
  return makeValue(std::make_unique<ChannelFactoryTls>(
      std::move(params), std::move(peer_cert_provider), std::move(my_creds)));
}
