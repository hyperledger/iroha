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
#include "backend/protobuf/queries/proto_get_peers.hpp"
#include "backend/protobuf/queries/proto_get_pending_transactions.hpp"
#include "backend/protobuf/queries/proto_get_role_permissions.hpp"
#include "backend/protobuf/queries/proto_get_roles.hpp"
#include "backend/protobuf/queries/proto_get_signatories.hpp"
#include "backend/protobuf/queries/proto_get_transactions.hpp"
#include "backend/protobuf/util.hpp"
#include "utils/variant_deserializer.hpp"

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
                     shared_model::proto::GetPeers>;

  /// list of types in proto variant
  using ProtoQueryListType = ProtoQueryVariantType::types;
}  // namespace

namespace shared_model {
  namespace proto {

    struct Query::Impl {
      explicit Impl(TransportType &&ref) : proto_{std::move(ref)} {}
      explicit Impl(const TransportType &ref) : proto_{ref} {}

      TransportType proto_;

      ProtoQueryVariantType variant_{[this] {
        auto &ar = proto_;
        int which = ar.payload()
                        .GetDescriptor()
                        ->FindFieldByNumber(ar.payload().query_case())
                        ->index_in_oneof();
        return shared_model::detail::variant_impl<
            ProtoQueryListType>::template load<ProtoQueryVariantType>(ar,
                                                                      which);
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

    bool Query::addSignature(const crypto::Signed &signed_blob,
                             const crypto::PublicKey &public_key) {
      if (impl_->proto_.has_signature()) {
        return false;
      }

      auto sig = impl_->proto_.mutable_signature();
      sig->set_signature(signed_blob.hex());
      sig->set_public_key(public_key.hex());

      impl_->signatures_ =
          SignatureSetType<proto::Signature>{proto::Signature{*sig}};
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

  }  // namespace proto
}  // namespace shared_model
