/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_AMETSUCHI_MOCK_VM_CALLER_HPP
#define IROHA_TEST_AMETSUCHI_MOCK_VM_CALLER_HPP

#include "ametsuchi/vm_caller.hpp"

#include <gmock/gmock.h>
#include "common/result.hpp"

namespace iroha::ametsuchi {
  class MockVmCaller : public VmCaller {
   public:
    MOCK_CONST_METHOD8(
        call,
        iroha::expected::Result<std::string, std::string>(
            soci::session &sql,
            std::string const &tx_hash,
            shared_model::interface::types::CommandIndexType cmd_index,
            shared_model::interface::types::EvmCodeHexStringView input,
            shared_model::interface::types::AccountIdType const &caller,
            std::optional<std::reference_wrapper<const std::string>> callee,
            CommandExecutor &command_executor,
            SpecificQueryExecutor &query_executor));
  };
}  // namespace iroha::ametsuchi

#endif
