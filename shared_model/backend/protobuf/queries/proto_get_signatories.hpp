/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_GET_SIGNATORIES_H
#define IROHA_PROTO_GET_SIGNATORIES_H

#include "interfaces/queries/get_signatories.hpp"

#include "queries.pb.h"

namespace shared_model {
  namespace proto {
    class GetSignatories final : public interface::GetSignatories {
     public:
      explicit GetSignatories(iroha::protocol::Query &query);

      const interface::types::AccountIdType &accountId() const override;

     private:
      // ------------------------------| fields |-------------------------------

      const iroha::protocol::GetSignatories &account_signatories_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_GET_SIGNATORIES_H
