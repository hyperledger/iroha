/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/queries/get_engine_response.hpp"

#include "cryptography/hash.hpp"

namespace shared_model {
  namespace interface {

    std::string GetEngineResponse::toString() const {
      return detail::PrettyStringBuilder()
          .init("GetEngineResponse")
          .append("tx_hash", txHash())
          .finalize();
    }

    bool GetEngineResponse::operator==(const ModelType &rhs) const {
      return txHash() == rhs.txHash();
    }

  }  // namespace interface
}  // namespace shared_model
