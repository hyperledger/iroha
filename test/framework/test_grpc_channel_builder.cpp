/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/test_grpc_channel_builder.hpp"

using namespace std::literals::chrono_literals;

template <typename Collection, typename Elem>
void remove_elem(Collection &collection, const Elem &elem) {
  collection.erase(std::remove(collection.begin(), collection.end(), elem));
}

namespace iroha {
  namespace network {

    std::unique_ptr<GrpcClientParams> getDefaultTestChannelParams() {
      static const auto retry_policy = [] {
        GrpcClientParams retry_policy = getDefaultChannelParams()->retry_policy;
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
  }  // namespace network
}  // namespace iroha
