/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_STORAGE_RESULT_HPP
#define IROHA_STORAGE_RESULT_HPP

#include <boost/variant.hpp>

namespace iroha::consensus::yac {
  struct CommitMessage;
  struct RejectMessage;
  struct FutureMessage;

  /**
   * Contains proof of supermajority for all purposes;
   */
  using Answer = boost::variant<CommitMessage, RejectMessage, FutureMessage>;

}  // namespace iroha::consensus::yac

#endif  // IROHA_STORAGE_RESULT_HPP
