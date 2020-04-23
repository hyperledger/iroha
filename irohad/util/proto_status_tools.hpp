/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef UTIL_PROTO_STATUS_TOOLS_HPP
#define UTIL_PROTO_STATUS_TOOLS_HPP

#include <memory>
#include <optional>
#include <string>

#include "backend/protobuf/proto_enum_to_string.hpp"
#include "util/status.hpp"
#include "utility_endpoint.pb.h"

namespace iroha {
  namespace utility_service {
    std::optional<std::unique_ptr<proto::Status>> makeProtoStatus(
        Status status);

    std::optional<Status> makeStatus(const proto::Status &status);
  }  // namespace utility_service

  namespace to_string {
    std::string toString(const ::iroha::utility_service::Status &val);
  }  // namespace to_string
}  // namespace iroha

IROHA_DEFINE_PROTO_ENUM_TO_STRING(
    ::iroha::utility_service::proto::Status::StatusEnum)

#endif /* UTIL_PROTO_STATUS_TOOLS_HPP */
