/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/engine_response_record.hpp"

#include "cryptography/hash.hpp"

using namespace shared_model::interface;

bool EngineReceipt::operator==(ModelType const &rhs) const {
    if (&rhs == static_cast<ModelType const*>(this)) {
        return true;
    }

    return getCaller() == rhs.getCaller() &&
            getPayloadType() == rhs.getPayloadType() &&
            getPayload() == rhs.getPayload() &&
            getEngineLogs() == rhs.getEngineLogs();
}

std::string EngineReceipt::toString() const {
  return detail::PrettyStringBuilder()
      .init("EngineReceipt")
      .appendNamed("from", getCaller())
      .appendNamed("payload_type", EngineReceipt::payloadTypeToStr(getPayloadType()))
      .appendNamed("payload", getPayload())
      .appendNamed("engine_logs", getEngineLogs())
      .finalize();
}
