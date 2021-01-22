/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_DOMAIN_HPP
#define IROHA_SHARED_MODEL_PROTO_DOMAIN_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "interfaces/common_objects/domain.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class Domain final
        : public TrivialProto<interface::Domain, iroha::protocol::Domain> {
     public:
      template <typename DomainType>
      explicit Domain(DomainType &&domain)
          : TrivialProto(std::forward<DomainType>(domain)) {}

      Domain(const Domain &o) : Domain(o.proto_) {}

      Domain(Domain &&o) noexcept : Domain(std::move(o.proto_)) {}

      const interface::types::DomainIdType &domainId() const override {
        return proto_->domain_id();
      }

      const interface::types::RoleIdType &defaultRole() const override {
        return proto_->default_role();
      }
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_DOMAIN_HPP
