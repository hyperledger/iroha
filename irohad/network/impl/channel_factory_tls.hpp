/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CHANNEL_FACTORY_TLS_HPP
#define IROHA_CHANNEL_FACTORY_TLS_HPP

#include "network/impl/channel_factory.hpp"

#include <memory>

#include "ametsuchi/peer_query.hpp"
#include "common/result.hpp"

namespace iroha {
  namespace network {

    class PeerTlsCertificatesProvider;

    struct ClientTlsCredentials {
      std::string private_key;
      std::string certificate;
    };

    class ChannelFactoryTls : public ChannelFactory {
     public:
      ChannelFactoryTls(
          std::shared_ptr<GrpcChannelParams> params,
          std::unique_ptr<PeerTlsCertificatesProvider> peer_cert_provider,
          boost::optional<ClientTlsCredentials> my_creds);

      static iroha::expected::Result<std::unique_ptr<ChannelFactoryTls>,
                                     std::string>
      create(std::shared_ptr<GrpcChannelParams> params,
             std::unique_ptr<PeerTlsCertificatesProvider> peer_cert_provider,
             const boost::optional<std::string> &my_creds_path);

     protected:
      iroha::expected::Result<std::shared_ptr<grpc::ChannelCredentials>,
                              std::string>
      getChannelCredentials(const std::string &address) const override;

      boost::optional<std::string> getCertificate(
          const std::string &address) const;

     private:
      std::unique_ptr<PeerTlsCertificatesProvider> peer_cert_provider_;
      boost::optional<ClientTlsCredentials> my_creds_;
    };

  };  // namespace network
};    // namespace iroha

#endif
