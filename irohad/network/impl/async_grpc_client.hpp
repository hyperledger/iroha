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
            log_->warn("RPC failed: {}", call->status.error_message());
          }

          auto callback = std::move(call->status_callback);
          auto status = std::move(call->status);

          delete call;

          callback(status);
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
        AsyncClientCall(std::function<void(grpc::Status)> callback)
            : status_callback(std::move(callback)) {}

        Response reply;

        grpc::ClientContext context;

        grpc::Status status;

        std::unique_ptr<grpc::ClientAsyncResponseReaderInterface<Response>>
            response_reader;

        std::function<void(grpc::Status)> status_callback = [](auto) {};
      };

      /**
       * Universal method to perform all needed sends
       * @tparam lambda which must return unique pointer to
       * ClientAsyncResponseReader<Response> object
       * @param status_callback - callback which invokes on finish of the call
       * @return observable with connection status
       */
      template <typename F>
      void Call(F &&lambda, std::function<void(grpc::Status)> status_callback) {
        auto call = new AsyncClientCall(std::move(status_callback));
        call->response_reader = lambda(&call->context, &cq_);
        call->response_reader->Finish(&call->reply, &call->status, call);
      }

     private:
      logger::LoggerPtr log_;
    };
  }  // namespace network
}  // namespace iroha

#endif  // IROHA_ASYNC_GRPC_CLIENT_HPP
