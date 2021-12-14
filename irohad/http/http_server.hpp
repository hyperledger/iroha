/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_HTTP_SERVER_HPP
#define IROHA_HTTP_SERVER_HPP

#include <vector>
#include <pair>
#include <functional>
#include <string_view>

#include "common/common.hpp"
#include "logger/logger_fwd.hpp"

struct mg_context;

namespace iroha::network {

  class HttpServer : utils::NoMove, utils::NoCopy {
   public:
    using Headers = std::vector<std::pair<std::string, std::string>>;
    using ResponseData = std::string;
    using HandlerCallback = std::function<int32_t(Headers &, ResponseData &)>;

    struct Options {
      std::string ports; // ex. "50500,50501,50502"
      std::string request_timeout_ms; // default: 10000

      std::string toString() const;
    };

   private:
    mg_context *context_;
    Options options_;
    logger::LoggerPtr logger_;

   public:
    HttpServer(Options const &options, logger::LoggerPtr const &logger);
    ~HttpServer();

    bool start();
    void stop();
    void registerHandler(std::string_view uri, HandlerCallback const &handler);
  };

}  // namespace iroha

#endif  // IROHA_HTTP_SERVER_HPP
