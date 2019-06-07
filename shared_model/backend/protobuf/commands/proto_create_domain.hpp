/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_CREATE_DOMAIN_HPP
#define IROHA_PROTO_CREATE_DOMAIN_HPP

#include "interfaces/commands/create_domain.hpp"

#include "commands.pb.h"

namespace shared_model {
  namespace proto {

    class CreateDomain final : public interface::CreateDomain {
     public:
      explicit CreateDomain(iroha::protocol::Command &command);

      const interface::types::DomainIdType &domainId() const override;

      const interface::types::RoleIdType &userDefaultRole() const override;

     private:
      const iroha::protocol::CreateDomain &create_domain_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_CREATE_DOMAIN_HPP
