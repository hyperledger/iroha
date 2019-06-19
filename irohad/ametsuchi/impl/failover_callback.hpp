/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_FAILOVER_CALLBACK_HPP
#define IROHA_FAILOVER_CALLBACK_HPP

#include <memory>

#include <soci/soci.h>

#include <soci/callbacks.h>

#include "ametsuchi/reconnection_strategy.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace ametsuchi {
    /**
     * Class provides reconnection callback for postgresql session
     * Note: the class is a workaround for SOCI 4.0, support in future versions
     * is not guaranteed
     */
    class FailoverCallback final : public soci::failover_callback {
     public:
      using InitFunctionType = std::function<void(soci::session &)>;
      FailoverCallback(
          soci::session &connection,
          InitFunctionType init,
          std::string connection_options,
          std::unique_ptr<ReconnectionStrategy> reconnection_strategy,
          logger::LoggerPtr log);

      FailoverCallback(const FailoverCallback &) = delete;
      FailoverCallback &operator=(const FailoverCallback &) = delete;

      void started() override;

      void finished(soci::session &) override;

      void failed(bool &should_reconnect, std::string &) override;

      void aborted() override;

     private:
      bool reconnectionLoop();

      soci::session &connection_;
      InitFunctionType init_session_;
      const std::string connection_options_;
      std::unique_ptr<ReconnectionStrategy> reconnection_strategy_;
      logger::LoggerPtr log_;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_FAILOVER_CALLBACK_HPP
