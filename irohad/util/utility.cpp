/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "util/utility.hpp"

namespace iroha {
  namespace service {
    UtilityService::UtilityService(const std::string &shutdown_key,
                                   std::promise<void> &shutdown_promise)
        : kShutdownKey(shutdown_key), kShutdownPromise(shutdown_promise) {}

    grpc::Status UtilityService::Shutdown(
        ::grpc::ServerContext *context,
        const ::iroha::protocol::ShutdownRequest *request,
        ::google::protobuf::Empty *response) {
      if (request->shutdown_key() == kShutdownKey) {
        kShutdownPromise.set_value();
      }
      return ::grpc::Status::OK;
    }
  }  // namespace service
}  // namespace iroha
