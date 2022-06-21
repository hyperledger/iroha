/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CHANNEL_CONSTANTS_HPP
#define IROHA_CHANNEL_CONSTANTS_HPP

namespace iroha::network {

  /// Determines maximum packet size can be sent via grpc
  static constexpr int kMaxMessageSize = 128 * 1024 * 1024;

}  // namespace iroha::network

#endif  // IROHA_CHANNEL_CONSTANTS_HPP
