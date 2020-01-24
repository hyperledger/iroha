/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/engine_response.hpp"

#include "interfaces/query_responses/engine_response_record.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {

    std::string EngineResponse::toString() const {
      return detail::PrettyStringBuilder()
          .init("EngineResponse")
          .append(engineResponseRecords())
          .finalize();
    }

    bool EngineResponse::operator==(const ModelType &rhs) const {
      return engineResponseRecords() == rhs.engineResponseRecords();
    }

  }  // namespace interface
}  // namespace shared_model
