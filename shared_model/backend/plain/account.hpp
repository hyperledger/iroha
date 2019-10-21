/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PLAIN_ACCOUNT_HPP
#define IROHA_SHARED_MODEL_PLAIN_ACCOUNT_HPP

#include "interfaces/common_objects/account.hpp"

#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace plain {

    class Account final : public interface::Account {
     public:
      Account(const interface::types::AccountIdType &account_id,
              const interface::types::DomainIdType &domain_id,
              interface::types::QuorumType quorum,
              const interface::types::JsonType &json_data);

      const interface::types::AccountIdType &accountId() const override;

      const interface::types::DomainIdType &domainId() const override;

      interface::types::QuorumType quorum() const override;

      const interface::types::JsonType &jsonData() const override;

     private:
      const interface::types::AccountIdType account_id_;
      const interface::types::DomainIdType domain_id_;
      interface::types::QuorumType quorum_;
      const interface::types::JsonType json_data_;
    };
  }  // namespace plain
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PLAIN_ACCOUNT_HPP
