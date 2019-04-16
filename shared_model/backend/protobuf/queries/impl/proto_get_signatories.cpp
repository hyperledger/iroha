/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_signatories.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryType>
    GetSignatories::GetSignatories(QueryType &&query)
        : CopyableProto(std::forward<QueryType>(query)),
          account_signatories_{proto_->payload().get_signatories()} {}

    template GetSignatories::GetSignatories(GetSignatories::TransportType &);
    template GetSignatories::GetSignatories(
        const GetSignatories::TransportType &);
    template GetSignatories::GetSignatories(GetSignatories::TransportType &&);

    GetSignatories::GetSignatories(const GetSignatories &o)
        : GetSignatories(o.proto_) {}

    GetSignatories::GetSignatories(GetSignatories &&o) noexcept
        : GetSignatories(std::move(o.proto_)) {}

    const interface::types::AccountIdType &GetSignatories::accountId() const {
      return account_signatories_.account_id();
    }

  }  // namespace proto
}  // namespace shared_model
