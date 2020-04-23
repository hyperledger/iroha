/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "util/proto_status_tools.hpp"

#include <boost/assign.hpp>
#include <boost/bimap/bimap.hpp>
#include <boost/bimap/set_of.hpp>
#include <optional>
#include "common/bind.hpp"
#include "util/status.hpp"

using iroha::operator|;

namespace iroha {
  namespace utility_service {

    using ProtoStatusBimap =
        boost::bimaps::bimap<boost::bimaps::set_of<Status>,
                             boost::bimaps::set_of<proto::Status::StatusEnum>>;

    static const ProtoStatusBimap &getProtoStatusBimap() {
      // clang-format off
      static const ProtoStatusBimap map =
          boost::assign::list_of<ProtoStatusBimap::relation>
            (Status::kUnknown,        proto::Status_StatusEnum_unknown)
            (Status::kInitialization, proto::Status_StatusEnum_initialization)
            (Status::kRunning,        proto::Status_StatusEnum_running)
            (Status::kTermination,    proto::Status_StatusEnum_termination)
            (Status::kStopped,        proto::Status_StatusEnum_stopped)
            (Status::kFailed,         proto::Status_StatusEnum_failed);
      // clang-format on
      return map;
    }

    std::optional<std::unique_ptr<proto::Status>> makeProtoStatus(
        Status status) {
      auto const &proto_statuses = getProtoStatusBimap().left;
      auto status_it = proto_statuses.find(status);
      if (status_it == proto_statuses.end()) {
        assert(status_it != proto_statuses.end());
        return std::nullopt;
      }
      auto proto_status = std::make_unique<proto::Status>();
      proto_status->set_status(status_it->second);
      return std::make_optional(std::move(proto_status));
    }

    std::optional<Status> makeStatus(const proto::Status &status) {
      auto const &iface_statuses = getProtoStatusBimap().right;
      auto status_it = iface_statuses.find(status.status());
      if (status_it == iface_statuses.end()) {
        assert(status_it != iface_statuses.end());
        return std::nullopt;
      }
      return status_it->second;
    }

  }  // namespace utility_service
}  // namespace iroha

namespace iroha {
  namespace to_string {
    std::string toString(const ::iroha::utility_service::Status &val) {
      const auto &map = ::iroha::utility_service::getProtoStatusBimap().left;
      auto it = map.find(val);
      if (it == map.end()) {
        assert(it != map.end());
        return "<unknown>";
      }
      return ::iroha::to_string::toString(it->second);
    }
  }  // namespace to_string
}  // namespace iroha
