/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "grpc_response_handler.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"

using namespace grpc;
namespace iroha_cli {

  GrpcResponseHandler::GrpcResponseHandler(
      logger::LoggerManagerTreePtr log_manager)
      : tx_handler_(log_manager->getChild("Transaction")->getLogger()),
        query_handler_(log_manager->getChild("Query")->getLogger()),
        log_(log_manager->getChild("Grpc")->getLogger()) {
    handler_map_[CANCELLED] = "Operation canceled";
    handler_map_[UNKNOWN] = "Unknown error";
    handler_map_[INVALID_ARGUMENT] = "INVALID_ARGUMENT";
    handler_map_[DEADLINE_EXCEEDED] = "DEADLINE_EXCEEDED";
    handler_map_[NOT_FOUND] = "NOT_FOUND";
    handler_map_[ALREADY_EXISTS] = "ALREADY_EXISTS";
    handler_map_[PERMISSION_DENIED] = "PERMISSION_DENIED";
    handler_map_[UNAUTHENTICATED] = "UNAUTHENTICATED";
    handler_map_[RESOURCE_EXHAUSTED] = "RESOURCE_EXHAUSTED";
    handler_map_[FAILED_PRECONDITION] = "FAILED_PRECONDITION";
    handler_map_[ABORTED] = "ABORTED";
    handler_map_[OUT_OF_RANGE] = "OUT_OF_RANGE";
    handler_map_[INTERNAL] = "INTERNAL";
    handler_map_[UNIMPLEMENTED] = "UNIMPLEMENTED";
    handler_map_[UNAVAILABLE] = "Server is unavailable";
    handler_map_[DATA_LOSS] = "DATA_LOSS";
  }

  void GrpcResponseHandler::handle(
      CliClient::Response<CliClient::TxStatus> response) {
    if (response.status.ok()) {
      tx_handler_.handle(response.answer);
    } else {
      handleGrpcErrors(response.status.error_code());
    }
  }

  void GrpcResponseHandler::handle(
      CliClient::Response<iroha::protocol::QueryResponse> response) {
    if (response.status.ok()) {
      query_handler_.handle(response.answer);
    } else {
      handleGrpcErrors(response.status.error_code());
    }
  }

  void GrpcResponseHandler::handleGrpcErrors(grpc::StatusCode code) {
    auto it = handler_map_.find(code);
    if (it != handler_map_.end()) {
      log_->error(it->second);
    } else {
      log_->error("Handler for grpc {} not implemented", code);
    }
  }

}  // namespace iroha_cli
