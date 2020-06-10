/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_UTILITY_SERVICE_HPP
#define IROHA_UTILITY_SERVICE_HPP

#include "logger/logger_fwd.hpp"
#include "status_notifier.hpp"
#include "utility_endpoint.grpc.pb.h"
#include "utility_endpoint.pb.h"

namespace iroha {
  namespace utility_service {

    class UtilityService : public proto::UtilityService_v1::Service,
                           public StatusNotifier {
     public:
      using ShutdownCallback = void (*)();

      UtilityService(ShutdownCallback shutdown_callback, logger::LoggerPtr log);

      ~UtilityService();

      ::grpc::Status Status(
          ::grpc::ServerContext *context,
          const ::google::protobuf::Empty * /* request */,
          ::grpc::ServerWriter<::iroha::utility_service::proto::Status> *writer)
          override;

      ::grpc::Status Shutdown(
          ::grpc::ServerContext *context,
          const ::google::protobuf::Empty * /* request */,
          ::google::protobuf::Empty * /* response */) override;

      void notify(enum Status status) override;

     private:
      struct Impl;
      std::unique_ptr<Impl> impl_;

      const ShutdownCallback shutdown_callback_;
      logger::LoggerPtr log_;
    };

  }  // namespace utility_service
}  // namespace iroha

#endif  // IROHA_UTILITY_SERVICE_HPP
