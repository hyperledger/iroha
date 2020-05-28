/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "util/utility_service.hpp"

#include <map>
#include <set>

#include "util/proto_status_tools.hpp"

#include <boost/optional.hpp>
#include <rxcpp/rx.hpp>
#include "common/run_loop_handler.hpp"
#include "logger/logger.hpp"
#include "util/status.hpp"

using namespace iroha::utility_service;

static bool isFinalStatus(const Status &status) {
  return status == Status::kStopped or status == Status::kFailed;
}

struct UtilityService::Impl {
  Impl(iroha::utility_service::Status initial_status)
      : status_observable(std::move(initial_status)) {}
  rxcpp::subjects::behavior<iroha::utility_service::Status> status_observable;
};

UtilityService::UtilityService(ShutdownCallback shutdown_callback,
                               logger::LoggerPtr log)
    : impl_(std::make_unique<Impl>(::iroha::utility_service::Status::kUnknown)),
      shutdown_callback_(shutdown_callback),
      log_(std::move(log)) {}

UtilityService::~UtilityService() = default;

void UtilityService::notify(enum Status status) {
  impl_->status_observable.get_subscriber().on_next(status);
}

grpc::Status UtilityService::Shutdown(
    ::grpc::ServerContext *context,
    const ::google::protobuf::Empty * /* request */,
    ::google::protobuf::Empty * /* response */) {
  log_->info("Got shutdown request from client {}.", context->peer());
  (*shutdown_callback_)();
  return ::grpc::Status::OK;
}

::grpc::Status UtilityService::Status(
    ::grpc::ServerContext *context,
    const ::google::protobuf::Empty * /* request */,
    ::grpc::ServerWriter<proto::Status> *writer) {
  log_->trace("Got status request from client {}.", context->peer());

  rxcpp::schedulers::run_loop run_loop;
  auto current_thread = rxcpp::synchronize_in_one_worker(
      rxcpp::schedulers::make_run_loop(run_loop));

  rxcpp::composite_subscription subscription;
  impl_->status_observable.get_observable()
      .observe_on(current_thread)
      .take_while([log = log_, context, writer](auto status) {
        if (context->IsCancelled()) {
          log->debug("Client unsubscribed from status stream.");
          return false;
        }

        proto::Status proto_status;
        proto_status.set_status(makeProtoStatus(status));

        log->trace("Sending {} to {}", proto_status.status(), context->peer());

        if (not writer->Write(proto_status)) {
          log->error("Write to stream has failed for client {}",
                     context->peer());
          return false;
        }

        return not isFinalStatus(status);
      })
      .subscribe(subscription,
                 [](const auto &) {},
                 [log = log_, context](std::exception_ptr ep) {
                   try {
                     std::rethrow_exception(ep);
                   } catch (const std::exception &e) {
                     log->error("Exception during status streaming to {}: {}",
                                context->peer(),
                                e.what());
                   }
                 },
                 [log = log_, context] {
                   log->trace("Status stream to {} finished.", context->peer());
                 });

  iroha::schedulers::handleEvents(subscription, run_loop);

  return ::grpc::Status::OK;
}
