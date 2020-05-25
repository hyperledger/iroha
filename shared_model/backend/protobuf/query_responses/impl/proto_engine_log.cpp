/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_engine_log.hpp"

using namespace shared_model::proto;

EngineLog::EngineLog(const TransportType &proto)
    : proto_(proto),
      topics_{proto.topics().begin(), proto.topics().end()}
// TODO: remove copy!!!
{}

EngineLog::EngineLog(const EngineLog &o) : EngineLog(o.proto_) {}

shared_model::interface::types::EvmAddressHexString const &
EngineLog::getAddress() const {
  return proto_.address();
}

shared_model::interface::types::EvmDataHexString const &EngineLog::getData()
    const {
  return proto_.data();
}

shared_model::interface::EngineLog::TopicsCollectionType const &
EngineLog::getTopics() const {
  return topics_;
}
