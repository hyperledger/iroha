/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_HTTP_SERVER_HPP
#define IROHA_HTTP_SERVER_HPP

#include <functional>
#include <list>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

#include "common/common.hpp"
#include "logger/logger_fwd.hpp"

struct mg_context;
struct mg_request_info;
struct mg_connection;

namespace iroha::network {

  enum eMethodType { kGet, kPut, kPost, kDelete };
  constexpr std::string_view kHealthcheckDefaultPort = "50508";

  class HttpRequestResponse {
    mg_connection *connection_;
    mg_request_info const *request_info_;
    std::optional<eMethodType> method_;

   public:
    HttpRequestResponse(mg_connection *connection,
                        mg_request_info const *request_info);
    std::optional<int> init();

    bool setJsonResponse(std::string_view data);

    eMethodType getMethodType() const;
  };

  class HttpServer : utils::NoMove, utils::NoCopy {
   public:
    using Headers = std::vector<std::pair<std::string, std::string>>;
    using ResponseData = std::string;
    using HandlerCallback = std::function<void(HttpRequestResponse &)>;

    struct HandlerData {
      HandlerCallback callback;
      logger::LoggerPtr logger;

      HandlerData(HandlerCallback c, logger::LoggerPtr l)
          : callback(std::move(c)), logger(std::move(l)) {}
    };

    struct Options {
      std::string ports;               // ex. "50500,50501,50502"
      std::string request_timeout_ms;  // default: 10000

      std::string toString() const;
    };

   private:
    mg_context *context_;
    Options options_;
    logger::LoggerPtr logger_;
    std::list<HandlerData> handlers_;

   public:
    HttpServer(Options options, logger::LoggerPtr logger);
    ~HttpServer();

    bool start();
    void stop();
    void registerHandler(std::string_view uri, HandlerCallback &&handler);
  };

}  // namespace iroha::network

#endif  // IROHA_HTTP_SERVER_HPP
