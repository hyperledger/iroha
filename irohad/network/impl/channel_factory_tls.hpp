/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CHANNEL_FACTORY_TLS_HPP
#define IROHA_CHANNEL_FACTORY_TLS_HPP

#include "network/impl/channel_factory.hpp"

#include <memory>

namespace iroha {
  namespace network {

    class PeerTlsCertificatesProvider;
    struct TlsCredentials;

    class ChannelFactoryTls : public ChannelFactory {
     public:
      ChannelFactoryTls(
          std::shared_ptr<const GrpcChannelParams> params,
          boost::optional<std::shared_ptr<const PeerTlsCertificatesProvider>>
              peer_cert_provider,
          boost::optional<std::shared_ptr<const TlsCredentials>> my_creds);

     protected:
      iroha::expected::Result<std::shared_ptr<grpc::ChannelCredentials>,
                              std::string>
      getChannelCredentials(
          const shared_model::interface::Peer &peer) const override;

     private:
      boost::optional<std::shared_ptr<const PeerTlsCertificatesProvider>>
          peer_cert_provider_;
      boost::optional<std::shared_ptr<const TlsCredentials>> my_creds_;
    };

  }  // namespace network
}  // namespace iroha

#endif
