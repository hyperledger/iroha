/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multi_sig_transactions/hash.hpp"

#include <functional>
#include <string>

#include <boost/functional/hash.hpp>
#include "cryptography/blob.hpp"
#include "cryptography/public_key.hpp"
#include "interfaces/common_objects/peer.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"

namespace iroha {
  namespace model {

    size_t PointerBatchHasher::operator()(const DataType &batch) const {
      return std::hash<std::string>{}(batch->reducedHash().hex());
    }

  }  // namespace model
}  // namespace iroha
