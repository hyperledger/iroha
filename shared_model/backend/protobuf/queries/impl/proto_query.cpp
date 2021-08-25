/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_query.hpp"

#include "backend/protobuf/common_objects/signature.hpp"
#include "backend/protobuf/queries/proto_get_account.hpp"
#include "backend/protobuf/queries/proto_get_account_asset_transactions.hpp"
#include "backend/protobuf/queries/proto_get_account_assets.hpp"
#include "backend/protobuf/queries/proto_get_account_detail.hpp"
#include "backend/protobuf/queries/proto_get_account_transactions.hpp"
#include "backend/protobuf/queries/proto_get_asset_info.hpp"
#include "backend/protobuf/queries/proto_get_block.hpp"
#include "backend/protobuf/queries/proto_get_engine_receipts.hpp"
#include "backend/protobuf/queries/proto_get_peers.hpp"
#include "backend/protobuf/queries/proto_get_pending_transactions.hpp"
#include "backend/protobuf/queries/proto_get_role_permissions.hpp"
#include "backend/protobuf/queries/proto_get_roles.hpp"
#include "backend/protobuf/queries/proto_get_signatories.hpp"
#include "backend/protobuf/queries/proto_get_transactions.hpp"
#include "backend/protobuf/util.hpp"
#include "common/report_abort.h"

namespace {
  /// type of proto variant
  using ProtoQueryVariantType =
      boost::variant<shared_model::proto::GetAccount,
                     shared_model::proto::GetSignatories,
                     shared_model::proto::GetAccountTransactions,
                     shared_model::proto::GetAccountAssetTransactions,
                     shared_model::proto::GetTransactions,
                     shared_model::proto::GetAccountAssets,
                     shared_model::proto::GetAccountDetail,
                     shared_model::proto::GetRoles,
                     shared_model::proto::GetRolePermissions,
                     shared_model::proto::GetAssetInfo,
                     shared_model::proto::GetPendingTransactions,
                     shared_model::proto::GetBlock,
                     shared_model::proto::GetPeers,
                     shared_model::proto::GetEngineReceipts>;
}  // namespace

#ifdef IROHA_BIND_TYPE
#error IROHA_BIND_TYPE defined.
#endif  // IROHA_BIND_TYPE
#define IROHA_BIND_TYPE(val, type, ...)                \
  case iroha::protocol::Query_Payload::QueryCase::val: \
    return ProtoQueryVariantType(shared_model::proto::type(__VA_ARGS__))

namespace shared_model::proto {

  struct Query::Impl {
    explicit Impl(TransportType &&ref) : proto_{std::move(ref)} {}
    explicit Impl(const TransportType &ref) : proto_{ref} {}

    TransportType proto_;

    ProtoQueryVariantType variant_{[this]() -> decltype(variant_) {
      auto &ar = proto_;
      switch (ar.payload().query_case()) {
        IROHA_BIND_TYPE(kGetAccount, GetAccount, ar);
        IROHA_BIND_TYPE(kGetAccountAssets, GetAccountAssets, ar);
        IROHA_BIND_TYPE(kGetAccountDetail, GetAccountDetail, ar);
        IROHA_BIND_TYPE(
            kGetAccountAssetTransactions, GetAccountAssetTransactions, ar);
        IROHA_BIND_TYPE(kGetSignatories, GetSignatories, ar);
        IROHA_BIND_TYPE(kGetAccountTransactions, GetAccountTransactions, ar);
        IROHA_BIND_TYPE(kGetTransactions, GetTransactions, ar);
        IROHA_BIND_TYPE(kGetRoles, GetRoles, ar);
        IROHA_BIND_TYPE(kGetAssetInfo, GetAssetInfo, ar);
        IROHA_BIND_TYPE(kGetRolePermissions, GetRolePermissions, ar);
        IROHA_BIND_TYPE(kGetPendingTransactions, GetPendingTransactions, ar);
        IROHA_BIND_TYPE(kGetBlock, GetBlock, ar);
        IROHA_BIND_TYPE(kGetPeers, GetPeers, ar);
        IROHA_BIND_TYPE(kGetEngineReceipts, GetEngineReceipts, ar);

        default:
        case iroha::protocol::Query_Payload::QueryCase::QUERY_NOT_SET:
          report_abort("Unexpected query case.");
      };
    }()};

    QueryVariantType ivariant_{variant_};

    interface::types::BlobType blob_{makeBlob(proto_)};

    interface::types::BlobType payload_{makeBlob(proto_.payload())};

    SignatureSetType<proto::Signature> signatures_{[this] {
      SignatureSetType<proto::Signature> set;
      if (proto_.has_signature()) {
        set.emplace(*proto_.mutable_signature());
      }
      return set;
    }()};

    interface::types::HashType hash_ = makeHash(payload_);
  };

  Query::Query(const Query &o) : Query(o.impl_->proto_) {}
  Query::Query(Query &&o) noexcept = default;

  Query::Query(const TransportType &ref) {
    impl_ = std::make_unique<Impl>(ref);
  }
  Query::Query(TransportType &&ref) {
    impl_ = std::make_unique<Impl>(std::move(ref));
  }

  Query::~Query() = default;

  const Query::QueryVariantType &Query::get() const {
    return impl_->ivariant_;
  }

  const interface::types::AccountIdType &Query::creatorAccountId() const {
    return impl_->proto_.payload().meta().creator_account_id();
  }

  interface::types::CounterType Query::queryCounter() const {
    return impl_->proto_.payload().meta().query_counter();
  }

  const interface::types::BlobType &Query::blob() const {
    return impl_->blob_;
  }

  const interface::types::BlobType &Query::payload() const {
    return impl_->payload_;
  }

  interface::types::SignatureRangeType Query::signatures() const {
    return impl_->signatures_;
  }

  bool Query::addSignature(
      interface::types::SignedHexStringView signed_blob,
      interface::types::PublicKeyHexStringView public_key) {
    if (impl_->proto_.has_signature()) {
      return false;
    }

    auto sig = impl_->proto_.mutable_signature();
    std::string_view const &signed_string{signed_blob};
    sig->set_signature(signed_string.data(), signed_string.size());
    std::string_view const &public_key_string{public_key};
    sig->set_public_key(public_key_string.data(), public_key_string.size());

    impl_->signatures_ =
        SignatureSetType<proto::Signature>{proto::Signature{*sig}};
    impl_->blob_ = makeBlob(impl_->proto_);

    return true;
  }

  const interface::types::HashType &Query::hash() const {
    return impl_->hash_;
  }

  interface::types::TimestampType Query::createdTime() const {
    return impl_->proto_.payload().meta().created_time();
  }

  const Query::TransportType &Query::getTransport() const {
    return impl_->proto_;
  }

}  // namespace shared_model::proto

#undef IROHA_BIND_TYPE
