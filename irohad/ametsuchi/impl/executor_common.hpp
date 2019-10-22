/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_EXECUTOR_COMMON_HPP
#define IROHA_AMETSUCHI_EXECUTOR_COMMON_HPP

#include "interfaces/common_objects/types.hpp"

namespace iroha {
  namespace ametsuchi {

    extern const std::string kRootRolePermStr;

    shared_model::interface::types::DomainIdType getDomainFromName(
        const shared_model::interface::types::AccountIdType &account_id);

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_AMETSUCHI_EXECUTOR_COMMON_HPP
