/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_AMETSUCHI_MOCK_VM_CALLER_HPP
#define IROHA_TEST_AMETSUCHI_MOCK_VM_CALLER_HPP

#include "ametsuchi/vm_caller.hpp"

#include <gmock/gmock.h>

#include "ametsuchi/burrow_storage.hpp"
#include "ametsuchi/command_executor.hpp"
#include "ametsuchi/specific_query_executor.hpp"
#include "common/result.hpp"

namespace iroha::ametsuchi {
  class MockVmCaller : public VmCaller {
   public:
    virtual ~MockVmCaller() = default;

    MOCK_CONST_METHOD8(
        call,
        iroha::expected::Result<std::optional<std::string>, std::string>(
            std::string const &tx_hash,
            shared_model::interface::types::CommandIndexType cmd_index,
            shared_model::interface::types::EvmCodeHexStringView input,
            shared_model::interface::types::AccountIdType const &caller,
            std::optional<
                shared_model::interface::types::EvmCalleeHexStringView> callee,
            BurrowStorage &burrow_storage,
            CommandExecutor &command_executor,
            SpecificQueryExecutor &query_executor));
  };
}  // namespace iroha::ametsuchi

#endif
