/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/burrow_vm_caller.hpp"

#include <fmt/core.h>
#include <soci/session.h>
#include BURROW_VM_CALL_HEADER
#include "ametsuchi/command_executor.hpp"
#include "ametsuchi/impl/postgres_burrow_storage.hpp"
#include "ametsuchi/query_executor.hpp"
#include "common/result.hpp"

using namespace iroha::ametsuchi;

iroha::expected::Result<std::string, std::string> BurrowVmCaller::call(
    soci::session &sql,
    std::string const &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    shared_model::interface::types::EvmCodeHexStringView input,
    shared_model::interface::types::AccountIdType const &caller,
    std::optional<shared_model::interface::types::EvmCalleeHexStringView>
        callee,
    CommandExecutor &command_executor,
    SpecificQueryExecutor &query_executor) const {
  const char *callee_raw = callee
      ? static_cast<std::string_view &>(callee.value()).data()
      : static_cast<const char *>(nullptr);
  const char *input_raw =
      const_cast<char *>(static_cast<std::string_view const &>(input).data());
  auto burrow_storage =
      std::make_unique<PostgresBurrowStorage>(sql, tx_hash, cmd_index);
  auto res = VmCall(input_raw,
                    caller.c_str(),
                    callee_raw,
                    &command_executor,
                    &query_executor,
                    burrow_storage.get());
  if (res.r1 == 0) {
    return iroha::expected::makeError(fmt::format("Engine error: {}.", res.r1));
  }
  return iroha::expected::makeValue("");
}
