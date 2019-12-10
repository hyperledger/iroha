/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/transaction.hpp"

#include <boost/range/adaptor/indirected.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include "backend/protobuf/batch_meta.hpp"
#include "backend/protobuf/commands/proto_command.hpp"
#include "backend/protobuf/common_objects/signature.hpp"
#include "backend/protobuf/util.hpp"
#include "common/result.hpp"
#include "utils/reference_holder.hpp"

using iroha::expected::Result;
using iroha::expected::ResultException;

namespace shared_model {
  namespace proto {

    struct Transaction::Impl {
      explicit Impl(const TransportType &ref) : proto_{ref} {}

      explicit Impl(TransportType &&ref) : proto_{std::move(ref)} {}

      explicit Impl(TransportType &ref) : proto_{ref} {}

      detail::ReferenceHolder<TransportType> proto_;

      iroha::protocol::Transaction::Payload &payload_{
          *proto_->mutable_payload()};

      iroha::protocol::Transaction::Payload::ReducedPayload &reduced_payload_{
          *proto_->mutable_payload()->mutable_reduced_payload()};

      interface::types::BlobType blob_{[this] { return makeBlob(*proto_); }()};

      interface::types::BlobType payload_blob_{
          [this] { return makeBlob(payload_); }()};

      interface::types::BlobType reduced_payload_blob_{
          [this] { return makeBlob(reduced_payload_); }()};

      interface::types::HashType reduced_hash_{makeHash(reduced_payload_blob_)};

      std::vector<std::unique_ptr<proto::Command>> commands_{
          boost::copy_range<std::vector<std::unique_ptr<proto::Command>>>(
              *reduced_payload_.mutable_commands()
              | boost::adaptors::transformed([](auto &proto) {
                  return Command::create(proto).assumeValue();
                }))};

      boost::optional<std::shared_ptr<interface::BatchMeta>> meta_{
          [this]() -> boost::optional<std::shared_ptr<interface::BatchMeta>> {
            if (payload_.has_batch()) {
              return std::shared_ptr<interface::BatchMeta>{
                  BatchMeta::create(*payload_.mutable_batch()).assumeValue()};
            }
            return boost::none;
          }()};

      SignatureSetType<std::unique_ptr<Signature>> signatures_{
          boost::copy_range<decltype(signatures_)>(
              *proto_->mutable_signatures()
              | boost::adaptors::transformed([](auto &x) {
                  return Signature::create(x).assumeValue();
                }))};

      interface::types::HashType hash_{makeHash(payload_blob_)};
    };

    Result<std::unique_ptr<Transaction>, std::string> Transaction::create(
        const TransportType &ref) {
      try {
        return std::unique_ptr<Transaction>(
            new Transaction(std::make_unique<Impl>(ref)));
      } catch (const ResultException &e) {
        return e.what();
      }
    }

    Result<std::unique_ptr<Transaction>, std::string> Transaction::create(
        TransportType &&ref) {
      try {
        return std::unique_ptr<Transaction>(
            new Transaction(std::make_unique<Impl>(std::move(ref))));
      } catch (const ResultException &e) {
        return e.what();
      }
    }

    Transaction::Transaction(std::unique_ptr<Impl> impl)
        : impl_(std::move(impl)) {}

    // TODO [IR-1866] Akvinikym 13.11.18: remove the copy ctor and fix fallen
    // tests
    Transaction::Transaction(const Transaction &transaction)
        : impl_(std::make_unique<Impl>(
              static_cast<const TransportType &>(*transaction.impl_->proto_))) {
    }

    Transaction::Transaction(Transaction &&transaction) noexcept = default;

    Transaction::~Transaction() = default;

    const interface::types::AccountIdType &Transaction::creatorAccountId()
        const {
      return impl_->reduced_payload_.creator_account_id();
    }

    Transaction::CommandsType Transaction::commands() const {
      return impl_->commands_ | boost::adaptors::indirected;
    }

    const interface::types::BlobType &Transaction::blob() const {
      return impl_->blob_;
    }

    const interface::types::BlobType &Transaction::payload() const {
      return impl_->payload_blob_;
    }

    const interface::types::BlobType &Transaction::reducedPayload() const {
      return impl_->reduced_payload_blob_;
    }

    interface::types::SignatureRangeType Transaction::signatures() const {
      return impl_->signatures_ | boost::adaptors::indirected;
    }

    const interface::types::HashType &Transaction::reducedHash() const {
      return impl_->reduced_hash_;
    }

    bool Transaction::addSignature(const crypto::Signed &signed_blob,
                                   const crypto::PublicKey &public_key) {
      // if already has such signature
      if (std::find_if(impl_->signatures_.begin(),
                       impl_->signatures_.end(),
                       [&public_key](const auto &signature) {
                         return signature->publicKey() == public_key;
                       })
          != impl_->signatures_.end()) {
        return false;
      }

      auto sig = impl_->proto_->add_signatures();
      sig->set_signature(signed_blob.hex());
      sig->set_public_key(public_key.hex());

      return Signature::create(*sig).match(
          [this](auto &&val) {
            impl_->signatures_.emplace(std::move(val.value));
            impl_->blob_ = makeBlob(*impl_->proto_);
            return true;
          },
          [this](const auto &err) {
            impl_->proto_->mutable_signatures()->RemoveLast();
            return false;
          });
    }

    const interface::types::HashType &Transaction::hash() const {
      return impl_->hash_;
    }

    const Transaction::TransportType &Transaction::getTransport() const {
      return *impl_->proto_;
    }

    interface::types::TimestampType Transaction::createdTime() const {
      return impl_->reduced_payload_.created_time();
    }

    interface::types::QuorumType Transaction::quorum() const {
      return impl_->reduced_payload_.quorum();
    }

    boost::optional<std::shared_ptr<interface::BatchMeta>>
    Transaction::batchMeta() const {
      return impl_->meta_;
    }

    Transaction::ModelType *Transaction::clone() const {
      return new Transaction(*this);
    }

  }  // namespace proto
}  // namespace shared_model
