/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_GRPC_CHANNEL_BUILDER_PARAMS_HPP
#define IROHA_GRPC_CHANNEL_BUILDER_PARAMS_HPP

#include <chrono>
#include <limits>
#include <optional>

namespace iroha {
  namespace network {

    struct GrpcChannelParams {
      struct RetryPolicy {
        unsigned int max_attempts;
        std::chrono::seconds initial_backoff;
        std::chrono::seconds max_backoff;
        float backoff_multiplier;
        std::vector<std::string> retryable_status_codes;
      };
      unsigned int max_request_message_bytes;
      unsigned int max_response_message_bytes;
      std::optional<RetryPolicy> retry_policy;
    };

  }  // namespace network
}  // namespace iroha

#endif  // IROHA_GRPC_CHANNEL_BUILDER_PARAMS_HPP
