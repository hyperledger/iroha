/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/block.hpp"

#include <boost/range/adaptors.hpp>

#include "backend/protobuf/common_objects/signature.hpp"
#include "backend/protobuf/transaction.hpp"
#include "backend/protobuf/util.hpp"
#include "common/byteutils.hpp"

namespace shared_model {
  namespace proto {

    struct Block::Impl {
      explicit Impl(TransportType &&ref) : proto_(std::move(ref)) {}
      explicit Impl(const TransportType &ref) : proto_(ref) {}
      Impl(Impl &&o) noexcept = delete;
      Impl &operator=(Impl &&o) noexcept = delete;

      TransportType proto_;
      iroha::protocol::Block_v1::Payload &payload_{*proto_.mutable_payload()};

      std::vector<proto::Transaction> transactions_{[this] {
        return std::vector<proto::Transaction>(
            payload_.mutable_transactions()->begin(),
            payload_.mutable_transactions()->end());
      }()};

      interface::types::BlobType blob_{[this] { return makeBlob(proto_); }()};

      interface::types::HashType prev_hash_{[this] {
        return interface::types::HashType(
            crypto::Hash::fromHexString(proto_.payload().prev_block_hash()));
      }()};

      SignatureSetType<proto::Signature> signatures_{[this] {
        auto signatures = *proto_.mutable_signatures()
            | boost::adaptors::transformed(
                  [](auto &x) { return proto::Signature(x); });
        return SignatureSetType<proto::Signature>(signatures.begin(),
                                                  signatures.end());
      }()};

      std::vector<interface::types::HashType> rejected_transactions_hashes_{
          [this] {
            std::vector<interface::types::HashType> hashes;
            for (const auto &hash :
                 *payload_.mutable_rejected_transactions_hashes()) {
              hashes.emplace_back(
                  shared_model::crypto::Hash::fromHexString(hash));
            }
            return hashes;
          }()};

      interface::types::BlobType payload_blob_{
          [this] { return makeBlob(payload_); }()};

      interface::types::HashType hash_ = makeHash(payload_blob_);
    };

    Block::Block(Block &&o) noexcept = default;

    Block::Block(const TransportType &ref) {
      impl_ = std::make_unique<Block::Impl>(ref);
    }

    Block::Block(TransportType &&ref) {
      impl_ = std::make_unique<Block::Impl>(std::move(ref));
    }

    interface::types::TransactionsCollectionType Block::transactions() const {
      return impl_->transactions_;
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
      return impl_->signatures_;
    }

    bool Block::addSignature(
        interface::types::SignedHexStringView signed_blob,
        interface::types::PublicKeyHexStringView public_key) {
      // if already has such signature
      if (std::find_if(impl_->signatures_.begin(),
                       impl_->signatures_.end(),
                       [&public_key](const auto &signature) {
                         return signature.publicKey() == public_key;
                       })
          != impl_->signatures_.end()) {
        return false;
      }

      auto sig = impl_->proto_.add_signatures();
      std::string_view const &signed_string{signed_blob};
      sig->set_signature(signed_string.data(), signed_string.size());
      std::string_view const &public_key_string{public_key};
      sig->set_public_key(public_key_string.data(), public_key_string.size());

      impl_->signatures_ = [this] {
        auto signatures = *impl_->proto_.mutable_signatures()
            | boost::adaptors::transformed(
                  [](auto &x) { return proto::Signature(x); });
        return SignatureSetType<proto::Signature>(signatures.begin(),
                                                  signatures.end());
      }();
      impl_->blob_ = makeBlob(impl_->proto_);

      return true;
    }

    const interface::types::HashType &Block::hash() const {
      return impl_->hash_;
    }

    interface::types::TimestampType Block::createdTime() const {
      return impl_->payload_.created_time();
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
      return new Block(impl_->proto_);
    }

    Block::~Block() = default;
  }  // namespace proto
}  // namespace shared_model
