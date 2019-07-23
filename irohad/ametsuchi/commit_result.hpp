/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_COMMIT_RESULT_HPP
#define IROHA_AMETSUCHI_COMMIT_RESULT_HPP

#include <memory>
#include <string>

#include "ametsuchi/ledger_state.hpp"
#include "common/result.hpp"

namespace iroha {
  namespace ametsuchi {

    using CommitResult =
        iroha::expected::Result<std::shared_ptr<const iroha::LedgerState>,
                                std::string>;
  }
}  // namespace iroha

#endif  // IROHA_AMETSUCHI_COMMIT_RESULT_HPP
