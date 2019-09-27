/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/plain/domain.hpp"

shared_model::plain::Domain::Domain(
    const shared_model::interface::types::DomainIdType &domain_id,
    const shared_model::interface::types::RoleIdType &default_role_id)
    : domain_id_(domain_id), default_role_id_(default_role_id) {}

const shared_model::interface::types::DomainIdType &
shared_model::plain::Domain::domainId() const {
  return domain_id_;
}

const shared_model::interface::types::RoleIdType &
shared_model::plain::Domain::defaultRole() const {
  return default_role_id_;
}
