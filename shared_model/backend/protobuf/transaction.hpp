/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_TRANSACTION_HPP
#define IROHA_SHARED_MODEL_PROTO_TRANSACTION_HPP

#include "common/result.hpp"
#include "interfaces/transaction.hpp"
#include "transaction.pb.h"

namespace shared_model {
  namespace proto {
    class Transaction final : public interface::Transaction {
     public:
      using TransportType = iroha::protocol::Transaction;

      static iroha::expected::Result<std::unique_ptr<Transaction>, std::string>
      create(const TransportType &ref);
      static iroha::expected::Result<std::unique_ptr<Transaction>, std::string>
      create(TransportType &&ref);

      Transaction(const Transaction &transaction);

      Transaction(Transaction &&o) noexcept;

      ~Transaction() override;

      const interface::types::AccountIdType &creatorAccountId() const override;

      Transaction::CommandsType commands() const override;

      const interface::types::BlobType &blob() const override;

      const interface::types::BlobType &payload() const override;

      const interface::types::BlobType &reducedPayload() const override;

      interface::types::SignatureRangeType signatures() const override;

      const interface::types::HashType &reducedHash() const override;

      bool addSignature(const crypto::Signed &signed_blob,
                        const crypto::PublicKey &public_key) override;

      const interface::types::HashType &hash() const override;

      const TransportType &getTransport() const;

      interface::types::TimestampType createdTime() const override;

      interface::types::QuorumType quorum() const override;

      boost::optional<std::shared_ptr<interface::BatchMeta>> batchMeta()
          const override;

     protected:
      Transaction::ModelType *clone() const override;

     private:
      struct Impl;
      Transaction(std::unique_ptr<Impl> impl);
      std::unique_ptr<Impl> impl_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_TRANSACTION_HPP
