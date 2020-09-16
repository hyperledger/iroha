/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_VM_CALLER_HPP
#define IROHA_AMETSUCHI_VM_CALLER_HPP

#include <functional>
#include <memory>
#include <optional>
#include <string>

#include "common/result_fwd.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "interfaces/common_objects/types.hpp"

namespace iroha::ametsuchi {
  class BurrowStorage;
  class CommandExecutor;
  class SpecificQueryExecutor;

  class VmCaller {
   public:
    virtual ~VmCaller() = default;

    virtual iroha::expected::Result<std::optional<std::string>, std::string>
    call(std::string const &tx_hash,
         shared_model::interface::types::CommandIndexType cmd_index,
         shared_model::interface::types::EvmCodeHexStringView input,
         shared_model::interface::types::AccountIdType const &caller,
         std::optional<shared_model::interface::types::EvmCalleeHexStringView>
             callee,
         BurrowStorage &burrow_storage,
         CommandExecutor &command_executor,
         SpecificQueryExecutor &query_executor) const = 0;
  };
}  // namespace iroha::ametsuchi

#endif
