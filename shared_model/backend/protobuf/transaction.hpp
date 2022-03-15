/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_TRANSACTION_HPP
#define IROHA_SHARED_MODEL_PROTO_TRANSACTION_HPP

#include "interfaces/transaction.hpp"
#include "transaction.pb.h"

namespace shared_model {
  namespace proto {
    class Transaction final : public interface::Transaction {
     public:
      using TransportType = iroha::protocol::Transaction;

      explicit Transaction(const TransportType &transaction);

      explicit Transaction(TransportType &&transaction);

      explicit Transaction(TransportType &transaction);

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

      bool addSignature(
          interface::types::SignedHexStringView signed_blob,
          interface::types::PublicKeyHexStringView public_key) override;

      const interface::types::HashType &hash() const override;

      std::unique_ptr<interface::Transaction> moveTo() override;

      const TransportType &getTransport() const;

      interface::types::TimestampType createdTime() const override;

      interface::types::QuorumType quorum() const override;

      std::optional<std::shared_ptr<interface::BatchMeta>> batchMeta()
          const override;

      void storeBatchHash(
          shared_model::interface::types::HashType const &hash) override;
      std::optional<shared_model::interface::types::HashType> const &
      getBatchHash() const override;

     protected:
      Transaction::ModelType *clone() const override;

     private:
      struct Impl;
      std::unique_ptr<Impl> impl_;
      std::optional<shared_model::interface::types::HashType> batch_hash_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_TRANSACTION_HPP
