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
          std::unique_ptr<AsyncClientCall> call(
              static_cast<AsyncClientCall *>(got_tag));
          assert(call);
          if (not call->status.ok()) {
            log_->warn("RPC failed: {}", call->status.error_message());
          }
          try {
            call->onResponse();
          } catch (std::exception const &e) {
            log_->warn("Response callback exception: {}", e.what());
          } catch (...) {
          }
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

      struct AsyncClientCall {
        grpc::ClientContext context;

        grpc::Status status;

        virtual void onResponse() = 0;

        virtual ~AsyncClientCall() = default;
      };

      /**
       * State and data information of gRPC call
       */
      template <typename Response>
      struct AsyncClientCallImpl : AsyncClientCall {
        Response reply;

        std::unique_ptr<grpc::ClientAsyncResponseReaderInterface<Response>>
            response_reader;

        std::function<void(grpc::Status &, Response &)> on_response;

        void onResponse() override {
          if (on_response) {
            on_response(status, reply);
          }
        }
      };

      /**
       * Universal method to perform all needed sends
       * @tparam lambda which must return unique pointer to
       * ClientAsyncResponseReader<Response> object
       */
      template <typename F, typename Response>
      void Call(F &&lambda,
                std::function<void(grpc::Status &, Response &)> on_response) {
        auto call = new AsyncClientCallImpl<Response>;
        call->on_response = std::move(on_response);
        call->response_reader = lambda(&call->context, &cq_);
        call->response_reader->Finish(&call->reply, &call->status, call);
      }

     private:
      logger::LoggerPtr log_;
    };
  }  // namespace network
}  // namespace iroha

#endif  // IROHA_ASYNC_GRPC_CLIENT_HPP
