/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/block.hpp"

#include <boost/range/adaptors.hpp>
#include "backend/protobuf/common_objects/signature.hpp"
#include "backend/protobuf/transaction.hpp"
#include "backend/protobuf/util.hpp"
#include "block.pb.h"
#include "common/byteutils.hpp"

using iroha::expected::Result;
using iroha::expected::ResultException;
using shared_model::crypto::Blob;

namespace shared_model {
  namespace proto {

    struct Block::Impl {
      explicit Impl(TransportType &&ref) : proto_(std::move(ref)) {}
      explicit Impl(const TransportType &ref) : proto_(ref) {}
      Impl(Impl &&o) noexcept = delete;
      Impl &operator=(Impl &&o) noexcept = delete;

      TransportType proto_;
      iroha::protocol::Block_v1::Payload &payload_{*proto_.mutable_payload()};

      std::vector<std::unique_ptr<Transaction>> transactions_{
          boost::copy_range<std::vector<std::unique_ptr<Transaction>>>(
              *payload_.mutable_transactions()
              | boost::adaptors::transformed([](auto &proto) {
                  return Transaction::create(proto).assumeValue();
                }))};

      interface::types::BlobType blob_{[this] { return makeBlob(proto_); }()};

      interface::types::HashType prev_hash_{
          Blob::fromHexString(proto_.payload().prev_block_hash())
              .assumeValue()};

      SignatureSetType<std::unique_ptr<Signature>> signatures_{
          boost::copy_range<decltype(signatures_)>(
              *proto_.mutable_signatures()
              | boost::adaptors::transformed([](auto &proto) {
                  return proto::Signature::create(proto).assumeValue();
                }))};

      std::vector<interface::types::HashType> rejected_transactions_hashes_{
          boost::copy_range<std::vector<interface::types::HashType>>(
              *payload_.mutable_rejected_transactions_hashes()
              | boost::adaptors::transformed([](const auto &hash) {
                  return interface::types::HashType{
                      Blob::fromHexString(hash).assumeValue()};
                }))};

      interface::types::BlobType payload_blob_{
          [this] { return makeBlob(payload_); }()};

      interface::types::HashType hash_ = makeHash(payload_blob_);
    };

    Block::Block(Block &&o) noexcept = default;

    Result<std::unique_ptr<Block>, std::string> Block::create(
        const TransportType &ref) {
      try {
        return std::unique_ptr<Block>(new Block(std::make_unique<Impl>(ref)));
      } catch (const ResultException &e) {
        return e.what();
      }
    }

    Result<std::unique_ptr<Block>, std::string> Block::create(
        TransportType &&ref) {
      try {
        return std::unique_ptr<Block>(
            new Block(std::make_unique<Impl>(std::move(ref))));
      } catch (const ResultException &e) {
        return e.what();
      }
    }

    Block::Block(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

    interface::types::TransactionsCollectionType Block::transactions() const {
      return impl_->transactions_ | boost::adaptors::indirected;
    }

    interface::types::HeightType Block::height() const {
      return impl_->payload_.height();
    }

    const interface::types::HashType &Block::prevHash() const {
      return impl_->prev_hash_;
    }

    const interface::types::BlobType &Block::blob() const {
      return impl_->blob_;
    }

    interface::types::SignatureRangeType Block::signatures() const {
      return impl_->signatures_ | boost::adaptors::indirected;
    }

    bool Block::addSignature(const crypto::Signed &signed_blob,
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

      auto sig = impl_->proto_.add_signatures();
      sig->set_signature(signed_blob.blob().hex());
      sig->set_public_key(public_key.blob().hex());

      return Signature::create(*sig).match(
          [this](auto &&val) {
            impl_->signatures_.emplace(std::move(val.value));
            impl_->blob_ = makeBlob(impl_->proto_);
            return true;
          },
          [this](const auto &err) {
            impl_->proto_.mutable_signatures()->RemoveLast();
            return false;
          });
    }

    const interface::types::HashType &Block::hash() const {
      return impl_->hash_;
    }

    interface::types::TimestampType Block::createdTime() const {
      return impl_->payload_.created_time();
    }

    interface::types::TransactionsNumberType Block::txsNumber() const {
      return impl_->payload_.tx_number();
    }

    interface::types::HashCollectionType Block::rejected_transactions_hashes()
        const {
      return impl_->rejected_transactions_hashes_;
    }

    const interface::types::BlobType &Block::payload() const {
      return impl_->payload_blob_;
    }

    const iroha::protocol::Block_v1 &Block::getTransport() const {
      return impl_->proto_;
    }

    Block::ModelType *Block::clone() const {
      return new Block(std::make_unique<Impl>(impl_->proto_));
    }

    Block::~Block() = default;
  }  // namespace proto
}  // namespace shared_model
