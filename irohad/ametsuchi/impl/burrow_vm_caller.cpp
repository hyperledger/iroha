/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/burrow_vm_caller.hpp"

#include <fmt/core.h>
#include <soci/session.h>
#include BURROW_VM_CALL_HEADER
#include "ametsuchi/command_executor.hpp"
#include "common/hexutils.hpp"
#include "common/result.hpp"

using namespace iroha::ametsuchi;

iroha::expected::Result<std::optional<std::string>, std::string>
BurrowVmCaller::call(
    std::string const &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    shared_model::interface::types::EvmCodeHexStringView input,
    shared_model::interface::types::AccountIdType const &caller,
    std::optional<shared_model::interface::types::EvmCalleeHexStringView>
        callee,
    BurrowStorage &burrow_storage,
    CommandExecutor &command_executor,
    SpecificQueryExecutor &query_executor) const {
  const char *callee_raw = callee
      ? static_cast<std::string_view &>(callee.value()).data()
      : static_cast<const char *>(nullptr);
  const char *input_raw =
      const_cast<char *>(static_cast<std::string_view const &>(input).data());
  std::string nonce = tx_hash;
  const char *nonce_raw =
      const_cast<char *>(nonce.append(numToHexstring(cmd_index)).c_str());
  auto raw_result = VmCall(input_raw,
                           caller.c_str(),
                           callee_raw,
                           nonce_raw,
                           &command_executor,
                           &query_executor,
                           &burrow_storage);

  // convert raw c strings to c++ types

  iroha::expected::Result<std::optional<std::string>, std::string>
      returnable_result;
  if (raw_result.r1 != nullptr) {
    returnable_result = iroha::expected::makeError(
        fmt::format("Engine error: {}.", raw_result.r1));
  } else if (raw_result.r0 != nullptr) {
    returnable_result = iroha::expected::makeValue(raw_result.r0);
  } else {
    returnable_result = iroha::expected::makeValue(std::nullopt);
  }

  // free raw memory

  for (auto maybe_mem : {raw_result.r0, raw_result.r1}) {
    if (maybe_mem) {
      free(maybe_mem);
    }
  }

  return returnable_result;
}
