/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/commands/create_domain.hpp"

namespace shared_model {
  namespace interface {

    std::string CreateDomain::toString() const {
      return detail::PrettyStringBuilder()
          .init("CreateDomain")
          .appendNamed("domain_id", domainId())
          .appendNamed("user_default_role", userDefaultRole())
          .finalize();
    }

    bool CreateDomain::operator==(const ModelType &rhs) const {
      return domainId() == rhs.domainId()
          and userDefaultRole() == rhs.userDefaultRole();
    }

  }  // namespace interface
}  // namespace shared_model
