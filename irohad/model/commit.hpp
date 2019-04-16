/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COMMIT_HPP
#define IROHA_COMMIT_HPP

#include <rxcpp/rx.hpp>

namespace iroha {
  using OldCommit = rxcpp::observable<model::Block>;
}  // namespace iroha

#endif  // IROHA_COMMIT_HPP
