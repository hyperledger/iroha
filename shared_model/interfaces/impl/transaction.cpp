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
          .append("hash", hash().hex())
          .append("creatorAccountId", creatorAccountId())
          .append("createdTime", std::to_string(createdTime()))
          .append("quorum", std::to_string(quorum()))
          .append("commands")
          .appendAll(commands(),
                     [](auto &command) { return command.toString(); })
          .append("batch_meta",
                  batchMeta() ? batchMeta()->get()->toString() : "")
          .append("reducedHash", reducedHash().toString())
          .append("signatures")
          .appendAll(signatures(), [](auto &sig) { return sig.toString(); })
          .finalize();
    }

  }  // namespace interface
}  // namespace shared_model
