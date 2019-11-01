/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/plain/engine_response_record.hpp"

using namespace shared_model::interface::types;
using namespace shared_model::plain;

EngineResponseRecord::EngineResponseRecord(
    CommandIndexType cmd_index, const SmartContractCodeType &response)
    : cmd_index_(cmd_index), response_(response) {}

CommandIndexType EngineResponseRecord::commandIndex() const {
  return cmd_index_;
}

const SmartContractCodeType &EngineResponseRecord::response() const {
  return response_;
}
