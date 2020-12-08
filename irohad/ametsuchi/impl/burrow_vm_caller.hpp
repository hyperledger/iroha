/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_BURROW_VM_CALLER_HPP
#define IROHA_AMETSUCHI_BURROW_VM_CALLER_HPP

#include "ametsuchi/vm_caller.hpp"

namespace iroha::ametsuchi {
  class BurrowVmCaller : public VmCaller {
   public:
    iroha::expected::Result<std::optional<std::string>, std::string> call(
        std::string const &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        shared_model::interface::types::EvmCodeHexStringView input,
        shared_model::interface::types::AccountIdType const &caller,
        std::optional<shared_model::interface::types::EvmCalleeHexStringView>
            callee,
        BurrowStorage &burrow_storage,
        CommandExecutor &command_executor,
        SpecificQueryExecutor &query_executor) const override;
  };
}  // namespace iroha::ametsuchi

#endif
