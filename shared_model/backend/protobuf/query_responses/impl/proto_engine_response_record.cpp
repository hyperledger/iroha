/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_engine_response_record.hpp"

using namespace shared_model::proto;

EngineResponseRecord::EngineResponseRecord(const TransportType &proto)
    : proto_(proto) {}

EngineResponseRecord::EngineResponseRecord(const EngineResponseRecord &o)
    : EngineResponseRecord(o.proto_) {}

shared_model::interface::types::CommandIndexType
EngineResponseRecord::commandIndex() const {
  return proto_.command_index();
}

const shared_model::interface::types::SmartContractCodeType &
EngineResponseRecord::response() const {
  return proto_.response();
}
