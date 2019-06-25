/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_account_detail.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryType>
    GetAccountDetail::GetAccountDetail(QueryType &&query)
        : CopyableProto(std::forward<QueryType>(query)),
          account_detail_{proto_->payload().get_account_detail()},
          pagination_meta_{[this]() -> decltype(pagination_meta_) {
            if (this->account_detail_.has_pagination_meta()) {
              return AccountDetailPaginationMeta{
                  *this->proto_->mutable_payload()
                       ->mutable_get_account_detail()
                       ->mutable_pagination_meta()};
            }
            return boost::none;
          }()} {}

    template GetAccountDetail::GetAccountDetail(
        GetAccountDetail::TransportType &);
    template GetAccountDetail::GetAccountDetail(
        const GetAccountDetail::TransportType &);
    template GetAccountDetail::GetAccountDetail(
        GetAccountDetail::TransportType &&);

    GetAccountDetail::GetAccountDetail(const GetAccountDetail &o)
        : GetAccountDetail(o.proto_) {}

    GetAccountDetail::GetAccountDetail(GetAccountDetail &&o) noexcept
        : GetAccountDetail(std::move(o.proto_)) {}

    const interface::types::AccountIdType &GetAccountDetail::accountId() const {
      return account_detail_.opt_account_id_case()
          ? account_detail_.account_id()
          : proto_->payload().meta().creator_account_id();
    }

    boost::optional<interface::types::AccountDetailKeyType>
    GetAccountDetail::key() const {
      return account_detail_.opt_key_case()
          ? boost::make_optional(account_detail_.key())
          : boost::none;
    }

    boost::optional<interface::types::AccountIdType> GetAccountDetail::writer()
        const {
      return account_detail_.opt_writer_case()
          ? boost::make_optional(account_detail_.writer())
          : boost::none;
    }

    boost::optional<const interface::AccountDetailPaginationMeta &>
    GetAccountDetail::paginationMeta() const {
      if (pagination_meta_) {
        return *pagination_meta_;
      }
      return boost::none;
    }

  }  // namespace proto
}  // namespace shared_model
