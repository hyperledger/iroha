/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_UTILITY_HPP
#define IROHA_UTILITY_HPP

#include <future>

#include "utility_endpoint.grpc.pb.h"
#include "utility_endpoint.pb.h"

namespace iroha {
  namespace service {

    class UtilityService : public iroha::protocol::UtilityService_v1::Service {
     public:
      UtilityService(const std::string &shutdown_key,
                     std::promise<void> &shutdown_promise);

      grpc::Status Shutdown(grpc::ServerContext *context,
                            const iroha::protocol::ShutdownRequest *request,
                            google::protobuf::Empty *response);

     private:
      const std::string kShutdownKey;
      std::promise<void> &kShutdownPromise;
    };
  }  // namespace service
}  // namespace iroha

#endif  // IROHA_UTILITY_HPP
