/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/queries/get_engine_receipts.hpp"

#include "cryptography/hash.hpp"

namespace shared_model {
  namespace interface {

    std::string GetEngineReceipts::toString() const {
      return detail::PrettyStringBuilder()
          .init("GetEngineReceipts")
          .appendNamed("tx_hash", txHash())
          .finalize();
    }

    bool GetEngineReceipts::operator==(const ModelType &rhs) const {
      return txHash() == rhs.txHash();
    }

  }  // namespace interface
}  // namespace shared_model
