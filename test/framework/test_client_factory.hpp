/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_CLIENT_FACTORY_HPP
#define IROHA_TEST_CLIENT_FACTORY_HPP

#include <optional>

#include "interfaces/common_objects/types.hpp"
#include "network/impl/client_factory_impl.hpp"
#include "network/impl/generic_client_factory.hpp"
#include "network/impl/grpc_channel_params.hpp"
#include "network/impl/tls_credentials.hpp"

namespace iroha {
  namespace network {
    std::unique_ptr<GenericClientFactory> getTestInsecureClientFactory(
        std::optional<std::shared_ptr<const GrpcChannelParams>> maybe_params);

    template <typename Transport>
    auto makeTransportClientFactory(
        std::shared_ptr<iroha::network::GenericClientFactory> generic_factory) {
      return std::make_unique<
          iroha::network::ClientFactoryImpl<typename Transport::Service>>(
          std::move(generic_factory));
    }

    /**
     * Creates secure client.
     * @tparam Service type for gRPC stub, e.g. proto::Yac
     * @param address ip address to connect to
     * @param port port to connect to
     * @param peer_cert the certificate to authenticate the peer
     * @param my_creds the private key and certificate to authenticate myself
     * @param maybe_params grpc channel params
     * @return gRPC stub of parametrized type
     */
    template <typename Service>
    std::unique_ptr<typename Service::StubInterface> createSecureClient(
        const std::string &ip,
        size_t port,
        std::optional<shared_model::interface::types::TLSCertificateType>
            peer_cert,
        std::optional<TlsCredentials> my_creds,
        std::optional<std::reference_wrapper<GrpcChannelParams const>>
            maybe_params) {
      return Service::NewStub(
          createSecureChannel(ip + ":" + std::to_string(port),
                              Service::service_full_name(),
                              std::move(peer_cert),
                              std::move(my_creds),
                              maybe_params));
    }

    /**
     * Creates secure channel
     * @param address ip address and port to connect to, ipv4:port
     * @param service_full_name gRPC service full name,
     *  e.g. iroha.consensus.yac.proto.Yac
     * @param peer_cert the certificate to authenticate the peer
     * @param my_creds the private key and certificate to authenticate myself
     * @param maybe_params grpc channel params
     * @return grpc channel with provided params
     */
    std::shared_ptr<grpc::Channel> createSecureChannel(
        const shared_model::interface::types::AddressType &address,
        const std::string &service_full_name,
        std::optional<shared_model::interface::types::TLSCertificateType>
            peer_cert,
        std::optional<TlsCredentials> my_creds,
        std::optional<std::reference_wrapper<GrpcChannelParams const>>
            maybe_params);

  }  // namespace network
}  // namespace iroha

#endif
