/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/transaction.hpp"

#include "interfaces/commands/command.hpp"
#include "interfaces/iroha_internal/batch_meta.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {

    std::string Transaction::toString() const {
      return detail::PrettyStringBuilder()
          .init("Transaction")
          .appendNamed("hash", hash().hex())
          .appendNamed("creatorAccountId", creatorAccountId())
          .appendNamed("createdTime", createdTime())
          .appendNamed("quorum", quorum())
          .appendNamed("commands", commands())
          .appendNamed("batch_meta", batchMeta())
          .appendNamed("reducedHash", reducedHash())
          .appendNamed("signatures", signatures())
          .finalize();
    }

  }  // namespace interface
}  // namespace shared_model
