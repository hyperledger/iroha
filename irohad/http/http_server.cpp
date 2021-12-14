/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "http/http_server.hpp"

#include "civetweb.h"
#include <fmt/core.h>

#include "logger/logger.hpp"
#include "common/mem_operations.hpp"

namespace iroha::network {
  std::string HttpServer::Options::toString() const {
    return fmt::format("Options [ports:{}, request_timeout_ms: {}]",
                       ports,
                       request_timeout_ms);
  }

  HttpServer::HttpServer(Options const &options,
                         logger::LoggerPtr const &logger)
      : context_(nullptr), options_(options), logger_(logger) {}

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

    struct mg_callbacks callbacks;
    memzero(callbacks);

    callbacks.log_message = [](const struct mg_connection *conn,
                               const char *message) {
      puts(message);
      return 1;
    };

    const char *options[] = {"listening_ports",
                             options_.ports.data(),
                             "request_timeout_ms",
                             options_.request_timeout_ms.empty()
                                 ? "10000"
                                 : options_.request_timeout_ms.data(),
                             nullptr};

    context_ = mg_start(&callbacks, 0, options);
    if (nullptr == context_) {
      logger_->error("Cannot start Http server. Check options.");
      return false;
    }

    logger_->info("Http server started successfully");
    return true;
  }

  void HttpServer::stop() {
    if (context_)
      mg_stop(context_);
    logger_->info("Http server stopped");
  }

  void HttpServer::registerHandler(std::string_view uri,
                                   HandlerCallback const &handler) {
    if (uri.empty()) {
      logger_->error("URI cannot be empty.");
      return false;
    }

    if (nullptr == context_) {
      logger_->error("Server is not started.");
      return false;
    }

    mg_set_request_handler(
        context_,
        uri.data(),
        [handler](struct mg_connection *conn, void * /*cbdata*/) {
          const struct mg_request_info *ri = mg_get_request_info(conn);

          if (0 == strcmp(ri->request_method, "GET")) {
            return ExampleGET(conn, path1, path2);
          }
          if ((0 == strcmp(ri->request_method, "PUT"))
              || (0 == strcmp(ri->request_method, "POST"))
              || (0 == strcmp(ri->request_method, "PATCH"))) {
            /* In this example, do the same for PUT, POST and PATCH */
            return ExamplePUT(conn, path1, path2);
          }

          mg_send_http_error(
              conn, 405, "Only GET, PUT, POST and PATCH method supported");
          return 405;


          Headers headers;
          ResponseData response;
          auto const response_code = handler(headers, response);

          mg_printf(conn,
                    "HTTP/1.1 200 OK\r\nContent-Type: "
                    "text/plain\r\nConnection: close\r\n\r\n");
          mg_printf(conn, "Server will shut down.\n");
          mg_printf(conn, "Bye!\n");
          return 1;
        },
        0);
  }

}