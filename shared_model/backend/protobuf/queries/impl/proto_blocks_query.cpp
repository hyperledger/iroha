/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_blocks_query.hpp"

#include <boost/range/adaptor/indirected.hpp>
#include "backend/protobuf/util.hpp"
#include "common/result.hpp"

using namespace shared_model::proto;

namespace shared_model {
  namespace proto {

    iroha::expected::Result<std::unique_ptr<BlocksQuery>, std::string>
    BlocksQuery::create(TransportType proto) {
      using namespace iroha::expected;
      BlocksQuery::SignatureSet set;
      if (proto.has_signature()) {
        if (auto e = resultToOptionalError(
                Signature::create(proto.signature()) |
                    [&set](auto &&sig) -> Result<void, std::string> {
                  set.emplace(std::move(sig));
                  return {};
                })) {
          return e.value();
        }
      }
      return std::make_unique<BlocksQuery>(std::move(proto), std::move(set));
    }

    BlocksQuery::BlocksQuery(TransportType &&query, SignatureSet signatures)
        : proto_{std::move(query)},
          blob_{makeBlob(proto_)},
          payload_{makeBlob(proto_.meta())},
          signatures_(std::move(signatures)),
          hash_(makeHash(payload_)) {}

    const interface::types::AccountIdType &BlocksQuery::creatorAccountId()
        const {
      return proto_.meta().creator_account_id();
    }

    interface::types::CounterType BlocksQuery::queryCounter() const {
      return proto_.meta().query_counter();
    }

    const interface::types::BlobType &BlocksQuery::blob() const {
      return blob_;
    }

    const interface::types::BlobType &BlocksQuery::payload() const {
      return payload_;
    }

    interface::types::SignatureRangeType BlocksQuery::signatures() const {
      return signatures_ | boost::adaptors::indirected;
    }

    bool BlocksQuery::addSignature(const crypto::Signed &signed_blob,
                                   const crypto::PublicKey &public_key) {
      if (proto_.has_signature()) {
        return false;
      }

      auto sig = proto_.mutable_signature();
      sig->set_signature(signed_blob.blob().hex());
      sig->set_public_key(public_key.blob().hex());

      // TODO: nickaleks IR-120 12.12.2018 remove set
      return Signature::create(*sig).match(
          [this](auto &&val) {
            signatures_.emplace(std::move(val.value));
            blob_ = makeBlob(proto_);
            return true;
          },
          [](const auto &err) { return false; });
    }

    const interface::types::HashType &BlocksQuery::hash() const {
      return hash_;
    }

    interface::types::TimestampType BlocksQuery::createdTime() const {
      return proto_.meta().created_time();
    }

    const BlocksQuery::TransportType &BlocksQuery::getTransport() const {
      return proto_;
    }

  }  // namespace proto
}  // namespace shared_model
