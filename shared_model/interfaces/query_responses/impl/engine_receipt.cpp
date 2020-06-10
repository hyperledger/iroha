/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/engine_receipt.hpp"

#include <iostream>

#include "cryptography/hash.hpp"

using namespace shared_model::interface;

bool EngineReceipt::operator==(ModelType const &rhs) const {
  if (&rhs == static_cast<ModelType const *>(this)) {
    return true;
  }

  return getCommandIndex() == rhs.getCommandIndex()
      && getCaller() == rhs.getCaller()
      && getPayloadType() == rhs.getPayloadType()
      && getResponseData()->callee == rhs.getResponseData()->callee
      && getResponseData()->response_data
      == rhs.getResponseData()->response_data
      && getContractAddress() == rhs.getContractAddress()
      && getEngineLogs() == rhs.getEngineLogs();
}

std::string EngineReceipt::toString() const {
  return detail::PrettyStringBuilder()
      .init("EngineReceipt")
      .appendNamed("command_index", getCommandIndex())
      .appendNamed("from", getCaller())
      .appendNamed("payload_type",
                   EngineReceipt::payloadTypeToStr(getPayloadType()))
      .appendNamed("contract_address",
                   !!getContractAddress() ? *getContractAddress()
                                          : std::string("no contract address"))
      .appendNamed("response_data",
                   !!getResponseData() ? getResponseData()->toString()
                                       : std::string("no callee"))
      .appendNamed("engine_logs", getEngineLogs())
      .finalize();
}

std::ostream &shared_model::interface::operator<<(std::ostream &os,
                                                  EngineReceipt const &r) {
  return os << r.toString();
}

std::string EngineReceipt::CallResult::toString() const {
  return detail::PrettyStringBuilder()
      .init("EngineContractCallResult")
      .appendNamed("callee", callee)
      .appendNamed("response_data", response_data)
      .finalize();
}

std::ostream &shared_model::interface::operator<<(
    std::ostream &os, EngineReceipt::CallResult const &r) {
  return os << r.toString();
}
