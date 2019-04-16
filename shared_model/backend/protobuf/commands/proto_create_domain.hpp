/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_CREATE_DOMAIN_HPP
#define IROHA_PROTO_CREATE_DOMAIN_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "commands.pb.h"
#include "interfaces/commands/create_domain.hpp"

namespace shared_model {
  namespace proto {

    class CreateDomain final : public CopyableProto<interface::CreateDomain,
                                                    iroha::protocol::Command,
                                                    CreateDomain> {
     public:
      template <typename CommandType>
      explicit CreateDomain(CommandType &&command);

      CreateDomain(const CreateDomain &o);

      CreateDomain(CreateDomain &&o) noexcept;

      const interface::types::DomainIdType &domainId() const override;

      const interface::types::RoleIdType &userDefaultRole() const override;

     private:
      const iroha::protocol::CreateDomain &create_domain_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_CREATE_DOMAIN_HPP
