/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_STORAGE_RESULT_HPP
#define IROHA_STORAGE_RESULT_HPP

#include <boost/variant.hpp>

namespace iroha {
  namespace consensus {
    namespace yac {

      struct CommitMessage;
      struct RejectMessage;

      /**
       * Contains proof of supermajority for all purposes;
       */
      using Answer = boost::variant<CommitMessage, RejectMessage>;

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
#endif  // IROHA_STORAGE_RESULT_HPP
