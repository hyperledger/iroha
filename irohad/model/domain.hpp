/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_DOMAIN_HPP
#define IROHA_DOMAIN_HPP

#include <string>

namespace iroha {
  namespace model {

    /**
     * Domain Model
     */
    struct Domain {
      /**
       * Domain unique identifier (full name)
       */
      std::string domain_id;

      /**
       * Default role for users in this domain
       */
      std::string default_role;
    };
  }  // namespace model
}  // namespace iroha

#endif  // IROHA_DOMAIN_HPP
