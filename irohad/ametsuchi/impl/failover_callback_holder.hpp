/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_FAILOVER_CALLBACK_HOLDER_HPP
#define IROHA_FAILOVER_CALLBACK_HOLDER_HPP

#include "ametsuchi/impl/failover_callback.hpp"

namespace iroha {
  namespace ametsuchi {
    class FailoverCallbackHolder {
     public:
      FailoverCallback &makeFailoverCallback(
          soci::session &connection,
          FailoverCallback::InitFunctionType init,
          std::string connection_options,
          std::unique_ptr<ReconnectionStrategy> reconnection_strategy,
          logger::LoggerPtr log);

     private:
      std::vector<std::unique_ptr<FailoverCallback>> callbacks_;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_FAILOVER_CALLBACK_HOLDER_HPP
