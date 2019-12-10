/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/proposal.hpp"

#include <boost/range/adaptor/indirected.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include "backend/protobuf/transaction.hpp"
#include "backend/protobuf/util.hpp"
#include "common/result.hpp"

namespace shared_model {
  namespace proto {
    using namespace interface::types;

    struct Proposal::Impl {
      explicit Impl(TransportType &&ref) : proto_(std::move(ref)) {}

      explicit Impl(const TransportType &ref) : proto_(ref) {}

      TransportType proto_;

      const std::vector<std::unique_ptr<Transaction>> transactions_{
          boost::copy_range<std::vector<std::unique_ptr<Transaction>>>(
              *proto_.mutable_transactions()
              | boost::adaptors::transformed([](auto &proto) {
                  return Transaction::create(proto).assumeValue();
                }))};

      interface::types::BlobType blob_{[this] { return makeBlob(proto_); }()};

      const interface::types::HashType hash_{
          [this] { return crypto::DefaultHashProvider::makeHash(blob_); }()};
    };

    Proposal::Proposal(Proposal &&o) noexcept = default;

    iroha::expected::Result<std::unique_ptr<Proposal>, std::string>
    Proposal::create(const TransportType &ref) {
      try {
        return std::unique_ptr<Proposal>(
            new Proposal(std::make_unique<Impl>(ref)));
      } catch (const iroha::expected::ResultException &e) {
        return e.what();
      }
    }

    iroha::expected::Result<std::unique_ptr<Proposal>, std::string>
    Proposal::create(TransportType &&ref) {
      try {
        return std::unique_ptr<Proposal>(
            new Proposal(std::make_unique<Impl>(std::move(ref))));
      } catch (const iroha::expected::ResultException &e) {
        return e.what();
      }
    }

    Proposal::Proposal(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

    TransactionsCollectionType Proposal::transactions() const {
      return impl_->transactions_ | boost::adaptors::indirected;
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
