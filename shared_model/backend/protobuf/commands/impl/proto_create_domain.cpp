/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_create_domain.hpp"

namespace shared_model {
  namespace proto {

    template <typename CommandType>
    CreateDomain::CreateDomain(CommandType &&command)
        : CopyableProto(std::forward<CommandType>(command)),
          create_domain_{proto_->create_domain()} {}

    template CreateDomain::CreateDomain(CreateDomain::TransportType &);
    template CreateDomain::CreateDomain(const CreateDomain::TransportType &);
    template CreateDomain::CreateDomain(CreateDomain::TransportType &&);

    CreateDomain::CreateDomain(const CreateDomain &o)
        : CreateDomain(o.proto_) {}

    CreateDomain::CreateDomain(CreateDomain &&o) noexcept
        : CreateDomain(std::move(o.proto_)) {}

    const interface::types::DomainIdType &CreateDomain::domainId() const {
      return create_domain_.domain_id();
    }

    const interface::types::RoleIdType &CreateDomain::userDefaultRole() const {
      return create_domain_.default_role();
    }

  }  // namespace proto
}  // namespace shared_model
