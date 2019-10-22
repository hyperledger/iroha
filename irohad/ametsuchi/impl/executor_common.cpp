/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/executor_common.hpp"

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include "interfaces/permissions.hpp"

namespace iroha {
  namespace ametsuchi {

    const std::string kRootRolePermStr{
        shared_model::interface::RolePermissionSet(
            {shared_model::interface::permissions::Role::kRoot})
            .toBitstring()};

    shared_model::interface::types::DomainIdType getDomainFromName(
        const shared_model::interface::types::AccountIdType &account_id) {
      // TODO 03.10.18 andrei: IR-1728 Move getDomainFromName to shared_model
      std::vector<std::string> res;
      boost::split(res, account_id, boost::is_any_of("@"));
      return res.at(1);
    }

  }  // namespace ametsuchi
}  // namespace iroha
