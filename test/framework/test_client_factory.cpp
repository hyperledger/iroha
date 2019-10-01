/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/test_client_factory.hpp"

#include "common/bind.hpp"
#include "framework/test_logger.hpp"
#include "logger/logger_manager.hpp"
#include "network/impl/channel_factory.hpp"
#include "network/impl/channel_factory_tls.hpp"
#include "network/impl/channel_pool.hpp"
#include "network/impl/peer_tls_certificates_provider_root.hpp"
#include "network/impl/tls_credentials.hpp"

using namespace std::literals::chrono_literals;

template <typename Collection, typename Elem>
void remove_elem(Collection &collection, const Elem &elem) {
  collection.erase(std::remove(collection.begin(), collection.end(), elem));
}

static const auto log_manager =
    getTestLoggerManager() -> getChild("GenericClientFactory");

namespace iroha {
  namespace network {

    std::unique_ptr<GrpcChannelParams> getDefaultTestChannelParams() {
      static const auto retry_policy = [] {
        auto retry_policy = getDefaultChannelParams()->retry_policy;
        assert(retry_policy);
        retry_policy->max_attempts = 3u;
        retry_policy->initial_backoff = 1s;
        retry_policy->max_backoff = 1s;
        retry_policy->backoff_multiplier = 1.f;
        remove_elem(retry_policy->retryable_status_codes, "UNAVAILABLE");
        return retry_policy;
      }();
      auto params = getDefaultChannelParams();
      params->retry_policy = retry_policy;
      return params;
    }

    std::unique_ptr<GenericClientFactory> getTestInsecureClientFactory(
        std::shared_ptr<const GrpcChannelParams> params) {
      std::unique_ptr<ChannelFactory> channel_factory =
          std::make_unique<ChannelFactory>(params);

      return std::make_unique<GenericClientFactory>(
          std::make_unique<ChannelPool>(std::move(channel_factory)));
    }

    std::unique_ptr<GenericClientFactory> getTestTlsClientFactory(
        boost::optional<shared_model::interface::types::TLSCertificateType>
            certificate,
        boost::optional<std::shared_ptr<const TlsCredentials>> my_creds,
        std::shared_ptr<const GrpcChannelParams> params) {
      auto peer_cert_provider =
          std::move(certificate) | [](auto &&certificate) {
            return boost::make_optional(
                std::shared_ptr<const PeerTlsCertificatesProvider>(
                    std::make_unique<PeerTlsCertificatesProviderRoot>(
                        std::move(certificate))));
          };

      std::unique_ptr<ChannelFactory> channel_factory =
          std::make_unique<ChannelFactoryTls>(
              params, peer_cert_provider, my_creds);

      return std::make_unique<GenericClientFactory>(
          std::make_unique<ChannelPool>(std::move(channel_factory)));
    }

  }  // namespace network
}  // namespace iroha
