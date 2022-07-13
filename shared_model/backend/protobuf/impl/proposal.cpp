/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/proposal.hpp"

#include "backend/protobuf/transaction.hpp"
#include "backend/protobuf/util.hpp"

namespace shared_model {
  namespace proto {
    using namespace interface::types;

    struct Proposal::Impl {
      explicit Impl(TransportType &&ref) : proto_(std::move(ref)) {}

      explicit Impl(const TransportType &ref) : proto_(ref) {}

      TransportType proto_;

      const std::vector<proto::Transaction> transactions_{[this] {
        return std::vector<proto::Transaction>(
            proto_.mutable_transactions()->begin(),
            proto_.mutable_transactions()->end());
      }()};

      interface::types::BlobType blob_{[this] { return makeBlob(proto_); }()};

      const interface::types::HashType hash_{
          [this] { return crypto::DefaultHashProvider::makeHash(blob_); }()};
    };

    Proposal::Proposal(Proposal &&o) noexcept = default;

    Proposal::Proposal(const TransportType &ref) {
      impl_ = std::make_unique<Proposal::Impl>(ref);
    }

    Proposal::Proposal(TransportType &&ref) {
      impl_ = std::make_unique<Proposal::Impl>(std::move(ref));
    }

    interface::types::TransactionsCollectionType Proposal::mut_transactions() {
      return impl_->transactions_;
    }

    TransactionsCollectionType Proposal::transactions() const {
      return impl_->transactions_;
    }

    TimestampType Proposal::createdTime() const {
      return impl_->proto_.created_time();
    }

    HeightType Proposal::height() const {
      return impl_->proto_.height();
    }

    const interface::types::BlobType &Proposal::blob() const {
      return impl_->blob_;
    }

    const Proposal::TransportType &Proposal::getTransport() const {
      return impl_->proto_;
    }

    const interface::types::HashType &Proposal::hash() const {
      return impl_->hash_;
    }

    Proposal::~Proposal() = default;

  }  // namespace proto
}  // namespace shared_model
