/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_create_domain.hpp"

namespace shared_model {
  namespace proto {

    CreateDomain::CreateDomain(iroha::protocol::Command &command)
        : create_domain_{command.create_domain()} {}

    const interface::types::DomainIdType &CreateDomain::domainId() const {
      return create_domain_.domain_id();
    }

    const interface::types::RoleIdType &CreateDomain::userDefaultRole() const {
      return create_domain_.default_role();
    }

  }  // namespace proto
}  // namespace shared_model
