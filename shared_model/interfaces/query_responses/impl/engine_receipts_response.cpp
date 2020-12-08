/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/engine_receipts_response.hpp"

#include <iostream>

#include "interfaces/query_responses/engine_receipt.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {

    std::string EngineReceiptsResponse::toString() const {
      return detail::PrettyStringBuilder()
          .init("EngineReceiptsResponse")
          .append(engineReceipts())
          .finalize();
    }

    bool EngineReceiptsResponse::operator==(const ModelType &rhs) const {
      return engineReceipts() == rhs.engineReceipts();
    }

    std::ostream &operator<<(std::ostream &os,
                             EngineReceiptsResponse const &r) {
      return os << r.toString();
    }

  }  // namespace interface
}  // namespace shared_model
