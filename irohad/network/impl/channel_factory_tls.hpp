/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CHANNEL_FACTORY_TLS_HPP
#define IROHA_CHANNEL_FACTORY_TLS_HPP

#include "network/impl/channel_factory.hpp"

#include <memory>

#include "ametsuchi/peer_query.hpp"
#include "logger/logger_fwd.hpp"
#include "network/impl/tls_credentials.hpp"

namespace iroha {
  namespace network {

    class PeerTlsCertificatesProvider;

    class ChannelFactoryTls : public ChannelFactory {
     public:
      ChannelFactoryTls(
          std::shared_ptr<const GrpcChannelParams> params,
          boost::optional<std::shared_ptr<PeerTlsCertificatesProvider>>
              peer_cert_provider,
          boost::optional<std::shared_ptr<const TlsCredentials>> my_creds,
          logger::LoggerPtr log);

     protected:
      std::shared_ptr<grpc::ChannelCredentials> getChannelCredentials(
          const shared_model::interface::Peer &peer) const override;

     private:
      boost::optional<std::shared_ptr<PeerTlsCertificatesProvider>>
          peer_cert_provider_;
      boost::optional<std::shared_ptr<const TlsCredentials>> my_creds_;
      logger::LoggerPtr log_;
    };

  };  // namespace network
};    // namespace iroha

#endif
