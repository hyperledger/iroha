/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ERROR_RESPONSE_HPP
#define IROHA_ERROR_RESPONSE_HPP

#include <string>
#include "model/query_response.hpp"

namespace iroha {
  namespace model {

    /**
     * Provide error answer with reason about error
     */
    struct ErrorResponse : public QueryResponse {
      /**
       * Reason of error
       */
      enum Reason {
        /**
         * signatures or created time are invalid
         */
        STATELESS_INVALID,
        /**
         * permissions are invalid
         */
        STATEFUL_INVALID,
        /**
         * when requested account does not exist
         */
        NO_ACCOUNT,
        /**
         * when requested asset does not exist
         */
        NO_ASSET,
        /**
         * No Roles found in the system
         */
        NO_ROLES,
        /**
         * when requested account asset does not exist
         */
        NO_ACCOUNT_ASSETS,
        /**
         * when requested account detail does not exist
         */
        NO_ACCOUNT_DETAIL,
        /**
         * when requested signatories does not exist
         */
        NO_SIGNATORIES,
        /**
         * when unidentified request was received
         */
        NOT_SUPPORTED
      };
      Reason reason{};
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_ERROR_RESPONSE_HPP
