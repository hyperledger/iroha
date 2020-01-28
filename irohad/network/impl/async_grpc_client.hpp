/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ASYNC_GRPC_CLIENT_HPP
#define IROHA_ASYNC_GRPC_CLIENT_HPP

#include <ciso646>
#include <thread>

#include <google/protobuf/empty.pb.h>
#include <grpc++/grpc++.h>
#include <grpcpp/impl/codegen/async_unary_call.h>
#include "logger/logger.hpp"

namespace iroha {
  namespace network {

    /**
     * Asynchronous gRPC client which does no processing of server responses
     * @tparam Response type of server response
     */
    template <typename Response>
    class AsyncGrpcClient {
     public:
      explicit AsyncGrpcClient(logger::LoggerPtr log)
          : thread_(&AsyncGrpcClient::asyncCompleteRpc, this),
            log_(std::move(log)) {}

      /**
       * Listen to gRPC server responses
       */
      void asyncCompleteRpc() {
        void *got_tag;
        auto ok = false;
        while (cq_.Next(&got_tag, &ok)) {
          auto call = static_cast<AsyncClientCall *>(got_tag);
          if (not call->status.ok()) {
            log_->warn("RPC failed: {}; tag = {}", call->status.error_message(), got_tag);
          }
          log_->info("AsyncClientCall::asyncCompleteRpc()::while_loop; tag = {} [before deleting call]", got_tag);
          delete call;
          log_->info("AsyncClientCall::asyncCompleteRpc()::while_loop; tag = {} [after deleting call]", got_tag);
        }
      }

      ~AsyncGrpcClient() {
        cq_.Shutdown();
        if (thread_.joinable()) {
          thread_.join();
        }
      }

      grpc::CompletionQueue cq_;
      std::thread thread_;

      /**
       * State and data information of gRPC call
       */
      struct AsyncClientCall {
        Response reply;

        grpc::ClientContext context;

        grpc::Status status;

        std::unique_ptr<grpc::ClientAsyncResponseReaderInterface<Response>>
            response_reader;
      };

      /**
       * Universal method to perform all needed sends
       * @tparam lambda which must return unique pointer to
       * ClientAsyncResponseReader<Response> object
       */
      template <typename F>
      void Call(F &&lambda) {
        auto call = new AsyncClientCall;
        log_->info("AsyncClientCall::Call(); tag = {} [BEGIN]", static_cast<void *>(call));
        call->response_reader = lambda(&call->context, &cq_);
        call->response_reader->Finish(&call->reply, &call->status, call);
        log_->info("AsyncClientCall::Call(); tag = {} [END]", static_cast<void *>(call));
      }

     private:
      logger::LoggerPtr log_;
    };
  }  // namespace network
}  // namespace iroha

#endif  // IROHA_ASYNC_GRPC_CLIENT_HPP
