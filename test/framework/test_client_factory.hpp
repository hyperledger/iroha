/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TEST_GRPC_CHANNEL_BUILDER_HPP
#define TEST_GRPC_CHANNEL_BUILDER_HPP

#include <boost/optional.hpp>
#include "interfaces/common_objects/types.hpp"
#include "network/impl/client_factory.hpp"
#include "network/impl/grpc_channel_params.hpp"

namespace iroha {
  namespace network {
    struct TlsCredentials;

    std::unique_ptr<GrpcChannelParams> getDefaultTestChannelParams();

    std::unique_ptr<GenericClientFactory> getTestInsecureClientFactory(
        std::shared_ptr<const GrpcChannelParams> params =
            getDefaultTestChannelParams());

    std::unique_ptr<GenericClientFactory> getTestTlsClientFactory(
        boost::optional<shared_model::interface::types::TLSCertificateType>
            certificate = boost::none,
        boost::optional<std::shared_ptr<const TlsCredentials>> my_creds =
            boost::none,
        std::shared_ptr<const GrpcChannelParams> params =
            getDefaultTestChannelParams());

  }  // namespace network
}  // namespace iroha

#endif /* TEST_GRPC_CHANNEL_BUILDER_HPP */
