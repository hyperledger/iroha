/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/plain/engine_receipt.hpp"

using namespace shared_model::interface::types;
using namespace shared_model::plain;

namespace {
  auto payloadToPayloadType(
      std::optional<EvmAddressHexString> const &callee,
      std::optional<EvmAddressHexString> const &contract_address) {
    assert(!callee != !contract_address);
    if (!!callee) {
      return shared_model::interface::EngineReceipt::PayloadType::
          kPayloadTypeCallResult;
    }
    return shared_model::interface::EngineReceipt::PayloadType::
        kPayloadTypeContractAddress;
  };
}  // namespace

EngineReceipt::EngineReceipt(
    shared_model::interface::types::CommandIndexType cmd_index,
    shared_model::interface::types::AccountIdType const &caller,
    std::optional<shared_model::interface::types::EvmDataHexString> const
        &callee,
    std::optional<shared_model::interface::types::EvmDataHexString> const
        &contract_address,
    std::optional<shared_model::interface::types::EvmDataHexString> const
        &e_response)
    : cmd_index_(cmd_index),
      caller_(caller),
      payload_type_(payloadToPayloadType(callee, contract_address)),
      callee_(callee),
      contract_address_(contract_address),
      e_response_(e_response),
      call_result_(
          payloadToPayloadType(callee, contract_address)
                  == shared_model::interface::EngineReceipt::PayloadType::
                         kPayloadTypeCallResult
              ? std::optional<
                    shared_model::interface::EngineReceipt::CallResult>(
                    {*callee_, e_response_})
              : std::nullopt) {}

shared_model::interface::types::AccountIdType EngineReceipt::getCaller() const {
  return caller_;
}

shared_model::interface::EngineReceipt::PayloadType
EngineReceipt::getPayloadType() const {
  return payload_type_;
}

int32_t EngineReceipt::getCommandIndex() const {
  return cmd_index_;
}

std::optional<shared_model::interface::EngineReceipt::CallResult> const &
EngineReceipt::getResponseData() const {
  return call_result_;
}

std::optional<shared_model::interface::types::EvmAddressHexString> const &
EngineReceipt::getContractAddress() const {
  return contract_address_;
}

shared_model::interface::EngineReceipt::EngineLogsCollectionType const &
EngineReceipt::getEngineLogs() const {
  return engine_logs_;
}

shared_model::interface::EngineReceipt::EngineLogsCollectionType &
EngineReceipt::getMutableLogs() {
  return engine_logs_;
}
