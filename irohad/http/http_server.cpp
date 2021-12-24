/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "http/http_server.hpp"

#include <fmt/core.h>
#include <cassert>
#include "CivetServer.h"

#include "common/mem_operations.hpp"
#include "logger/logger.hpp"

namespace iroha::network {
  std::string HttpServer::Options::toString() const {
    return fmt::format("Options [ports:{}, request_timeout_ms: {}]",
                       ports,
                       request_timeout_ms);
  }

  HttpRequestResponse::HttpRequestResponse(mg_connection *connection,
                                           mg_request_info const *request_info)
      : connection_(connection), request_info_(request_info) {}

  std::optional<int> HttpRequestResponse::init() {
    if (0 == strcmp(request_info_->request_method, "GET")) {
      method_ = eMethodType::kGet;
    }

    /**
     * Uncomment for PUT, POST and DELETE processing.
     */
    /* else if (0 == strcmp(request_info_->request_method, "PUT")) {
       method_ = eMethodType::kPut;
     } else if (0 == strcmp(request_info_->request_method, "POST")) {
       method_ = eMethodType::kPost;
     } else if (0 == strcmp(request_info_->request_method, "DELETE")) {
       method_ = eMethodType::kDelete;
     } */
    else {
      mg_send_http_error(connection_, 405, "Only GET method supported");
      return 405;
    }
    return std::nullopt;
  }

  bool HttpRequestResponse::setJsonResponse(std::string_view data) {
    if (!method_)
      return false;

    mg_send_http_ok(
        connection_, "application/json; charset=utf-8", (long long)data.size());
    mg_write(connection_, data.data(), data.size());
    return true;
  }

  eMethodType HttpRequestResponse::getMethodType() const {
    assert(method_);
    return *method_;
  }

  HttpServer::HttpServer(Options options, logger::LoggerPtr logger)
      : context_(nullptr),
        options_(std::move(options)),
        logger_(std::move(logger)) {}

  HttpServer::~HttpServer() {
    stop();
  }

  bool HttpServer::start() {
    if (context_ != nullptr) {
      logger_->error("Http server already started.");
      return false;
    }

    if (options_.ports.empty()) {
      logger_->error("Http server ports are not defined.");
      return false;
    }

    logger_->info("Try to start Http server with options: {}", options_);
    mg_init_library(0);

    mg_callbacks callbacks{};
    callbacks.log_message = [](const struct mg_connection *conn,
                               const char *message) { return 1; };

    const char *options[] = {"listening_ports",
                             options_.ports.data(),
                             "request_timeout_ms",
                             options_.request_timeout_ms.empty()
                                 ? "10000"
                                 : options_.request_timeout_ms.data(),
                             nullptr};

    context_ = mg_start(&callbacks, nullptr, options);
    if (nullptr == context_) {
      logger_->error("Cannot start Http server. Check options.");
      return false;
    }

    logger_->info("Http server started successfully");
    return true;
  }

  void HttpServer::stop() {
    if (context_) {
      mg_stop(context_);
      context_ = nullptr;
    }
    mg_exit_library();
    logger_->info("Http server stopped");
  }

  void HttpServer::registerHandler(std::string_view uri,
                                   HandlerCallback &&handler) {
    if (uri.empty()) {
      logger_->error("URI cannot be empty.");
      return;
    }

    if (nullptr == context_) {
      logger_->error("Server is not started.");
      return;
    }

    handlers_.emplace_back(std::move(handler), logger_);
    mg_set_request_handler(
        context_,
        uri.data(),
        [](struct mg_connection *conn, void *cbdata) {
          assert(nullptr != cbdata);
          HandlerData &handler = *(HandlerData *)cbdata;

          HttpRequestResponse req_res(conn, mg_get_request_info(conn));
          if (auto code = req_res.init(); code) {
            handler.logger->error(
                "Init HttpRequestResponse failed with code: {}", *code);
            return *code;
          }

          if (!handler.callback) {
            handler.logger->error("No registered callback");
            mg_send_http_error(conn, 500, "Server error");
            return 500;
          }

          handler.callback(req_res);
          return 200;
        },
        &handlers_.back());
  }

}  // namespace iroha::network
