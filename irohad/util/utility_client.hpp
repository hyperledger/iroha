/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef UTILITY_CLIENT_HPP
#define UTILITY_CLIENT_HPP

#include <chrono>
#include <string>

#include <logger/logger_fwd.hpp>
#include "util/status.hpp"

namespace iroha {
  namespace utility_service {

    class UtilityClient {
     public:
      UtilityClient(std::string const &irohad_address, logger::LoggerPtr log);

      ~UtilityClient();

      bool waitForServerReady(std::chrono::milliseconds timeout) const;

      /**
       * Callback function receives current daemon status and should return true
       * to continnue status listerning and false otherwise.
       */
      using StatusCallback = bool (*)(const Status &);

      bool status(StatusCallback callback) const;

      bool shutdown() const;

     private:
      struct StubHolder;

      logger::LoggerPtr log_;
      std::unique_ptr<StubHolder> stub_holder_;
    };

  }  // namespace utility_service
}  // namespace iroha

#endif /* UTILITY_CLIENT_HPP */
