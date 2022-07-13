/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_INTERFACE_MOCKS_HPP
#define IROHA_SHARED_MODEL_INTERFACE_MOCKS_HPP

#include <gmock/gmock.h>

#include "datetime/time.hpp"
#include "interfaces/commands/command.hpp"
#include "interfaces/common_objects/common_objects_factory.hpp"
#include "interfaces/common_objects/peer.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "interfaces/iroha_internal/block_json_converter.hpp"
#include "interfaces/iroha_internal/proposal.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "interfaces/iroha_internal/unsafe_proposal_factory.hpp"
#include "interfaces/query_responses/engine_receipt.hpp"
#include "interfaces/transaction.hpp"

// TODO: 2019-01-18 @muratovv Separate file by classes IR-229
struct MockBlock : public shared_model::interface::Block {
  MOCK_CONST_METHOD0(txsNumber,
                     shared_model::interface::types::TransactionsNumberType());
  MOCK_CONST_METHOD0(
      transactions,
      shared_model::interface::types::TransactionsCollectionType());
  MOCK_CONST_METHOD0(rejected_transactions_hashes,
                     shared_model::interface::types::HashCollectionType());
  MOCK_CONST_METHOD0(height, shared_model::interface::types::HeightType());
  MOCK_CONST_METHOD0(prevHash,
                     const shared_model::interface::types::HashType &());
  MOCK_CONST_METHOD0(signatures,
                     shared_model::interface::types::SignatureRangeType());
  MOCK_CONST_METHOD0(createdTime,
                     shared_model::interface::types::TimestampType());
  MOCK_CONST_METHOD0(payload,
                     const shared_model::interface::types::BlobType &());
  MOCK_CONST_METHOD0(blob, const shared_model::interface::types::BlobType &());
  MOCK_METHOD2(addSignature,
               bool(shared_model::interface::types::SignedHexStringView,
                    shared_model::interface::types::PublicKeyHexStringView));
  MOCK_CONST_METHOD0(hash, const shared_model::interface::types::HashType &());
  MOCK_CONST_METHOD0(clone, MockBlock *());
};

struct MockTransaction : public shared_model::interface::Transaction {
  MOCK_CONST_METHOD0(creatorAccountId,
                     const shared_model::interface::types::AccountIdType &());
  MOCK_CONST_METHOD0(quorum, shared_model::interface::types::QuorumType());
  MOCK_CONST_METHOD0(commands, CommandsType());
  MOCK_CONST_METHOD0(reducedHash,
                     const shared_model::interface::types::HashType &());
  MOCK_CONST_METHOD0(hash, const shared_model::interface::types::HashType &());
  MOCK_CONST_METHOD0(
      batch_meta,
      std::optional<std::shared_ptr<shared_model::interface::BatchMeta>>());
  MOCK_CONST_METHOD0(signatures,
                     shared_model::interface::types::SignatureRangeType());
  MOCK_CONST_METHOD0(createdTime,
                     shared_model::interface::types::TimestampType());
  MOCK_CONST_METHOD0(payload,
                     const shared_model::interface::types::BlobType &());
  MOCK_CONST_METHOD0(blob, const shared_model::interface::types::BlobType &());
  MOCK_METHOD2(addSignature,
               bool(shared_model::interface::types::SignedHexStringView,
                    shared_model::interface::types::PublicKeyHexStringView));
  MOCK_CONST_METHOD0(clone, MockTransaction *());
  MOCK_CONST_METHOD0(reducedPayload,
                     const shared_model::interface::types::BlobType &());
  MOCK_CONST_METHOD0(
      batchMeta,
      std::optional<std::shared_ptr<shared_model::interface::BatchMeta>>());
  MOCK_METHOD0(moveTo, std::unique_ptr<Transaction>());

  MOCK_METHOD1(storeBatchHash,
               void(shared_model::interface::types::HashType const &));
  MOCK_CONST_METHOD0(
      getBatchHash,
      std::optional<shared_model::interface::types::HashType> const &());
};

/**
 * Creates mock transaction with provided hash
 * @param hash -- const ref to hash to be returned by the transaction
 * @return shared_ptr for transaction
 */
inline auto createMockTransactionWithHash(
    const shared_model::interface::types::HashType &hash) {
  using ::testing::NiceMock;
  using ::testing::ReturnRefOfCopy;

  auto res = std::make_shared<NiceMock<MockTransaction>>();

  auto now = iroha::time::now();
  ON_CALL(*res, hash()).WillByDefault(ReturnRefOfCopy(hash));
  ON_CALL(*res, createdTime()).WillByDefault(testing::Return(now));

  return res;
}

struct MockTransactionBatch : public shared_model::interface::TransactionBatch {
  MOCK_CONST_METHOD0(
      transactions,
      const shared_model::interface::types::SharedTxsCollectionType &());
  MOCK_CONST_METHOD0(reducedHash,
                     const shared_model::interface::types::HashType &());
  MOCK_CONST_METHOD0(hasAllSignatures, bool());
  MOCK_METHOD3(addSignature,
               bool(size_t,
                    shared_model::interface::types::SignedHexStringView,
                    shared_model::interface::types::PublicKeyHexStringView));
  MOCK_CONST_METHOD1(Equals,
                     bool(const shared_model::interface::TransactionBatch &));
  virtual bool operator==(
      const shared_model::interface::TransactionBatch &rhs) const override {
    return Equals(rhs);
  }
  MOCK_CONST_METHOD1(NotEquals,
                     bool(const shared_model::interface::TransactionBatch &));
  MOCK_CONST_METHOD0(clone, MockTransactionBatch *());
};

namespace shared_model {
  namespace interface {
    inline std::ostream &operator<<(std::ostream &os,
                                    const TransactionBatch &resp) {
      return os << resp.toString();
    }
  }  // namespace interface
}  // namespace shared_model

/**
 * Creates mock batch with provided hash
 * @param hash -- const ref to reduced hash to be returned by the batch
 * @return shared_ptr for batch
 */
inline auto createMockBatchWithHash(
    const shared_model::interface::types::HashType &hash) {
  using ::testing::NiceMock;
  using ::testing::ReturnRefOfCopy;

  auto res = std::make_shared<NiceMock<MockTransactionBatch>>();

  ON_CALL(*res, reducedHash()).WillByDefault(ReturnRefOfCopy(hash));

  return res;
}

/**
 * Creates mock batch with provided transactions
 * @param txs -- list of transactions in the batch
 * @param hash -- const ref to hash to be returned by the batch
 * @return shared_ptr for batch
 */
inline auto createMockBatchWithTransactions(
    const shared_model::interface::types::SharedTxsCollectionType &txs,
    std::string hash) {
  using ::testing::NiceMock;
  using ::testing::ReturnRefOfCopy;

  auto res = std::make_shared<NiceMock<MockTransactionBatch>>();

  ON_CALL(*res, transactions()).WillByDefault(ReturnRefOfCopy(txs));

  ON_CALL(*res, reducedHash())
      .WillByDefault(ReturnRefOfCopy(shared_model::crypto::Hash{hash}));

  return res;
}

struct MockSignature : public shared_model::interface::Signature {
  MOCK_CONST_METHOD0(publicKey, const std::string &());
  MOCK_CONST_METHOD0(signedData, const std::string &());
  MOCK_CONST_METHOD0(clone, MockSignature *());
};

struct MockProposal : public shared_model::interface::Proposal {
  MOCK_CONST_METHOD0(
      transactions,
      shared_model::interface::types::TransactionsCollectionType());
  MOCK_CONST_METHOD0(height, shared_model::interface::types::HeightType());
  MOCK_CONST_METHOD0(createdTime,
                     shared_model::interface::types::TimestampType());
  MOCK_CONST_METHOD0(blob, const shared_model::interface::types::BlobType &());
  MOCK_CONST_METHOD0(hash, const shared_model::interface::types::HashType &());
  MOCK_CONST_METHOD0(clone, MockProposal *());
  MOCK_CONST_METHOD0(toString, std::string());
  MOCK_METHOD0(mut_transactions,
               shared_model::interface::types::TransactionsCollectionType());
};

struct MockPeer : public shared_model::interface::Peer {
  MOCK_CONST_METHOD0(address,
                     const shared_model::interface::types::AddressType &());
  MOCK_CONST_METHOD0(pubkey, const std::string &());
  MOCK_CONST_METHOD0(
      tlsCertificate,
      const std::optional<shared_model::interface::types::TLSCertificateType>
          &());
  MOCK_CONST_METHOD0(clone, MockPeer *());
  MOCK_CONST_METHOD0(isSyncingPeer, bool());
};

inline auto makePeer(
    std::string_view address,
    shared_model::interface::types::PublicKeyHexStringView pub_key,
    const std::optional<shared_model::interface::types::TLSCertificateType>
        &tls_certificate = std::nullopt) {
  auto peer = std::make_unique<MockPeer>();
  EXPECT_CALL(*peer, address())
      .WillRepeatedly(testing::ReturnRefOfCopy(std::string{address}));
  EXPECT_CALL(*peer, pubkey())
      .WillRepeatedly(testing::ReturnRefOfCopy(std::string{pub_key}));
  EXPECT_CALL(*peer, tlsCertificate())
      .WillRepeatedly(testing::ReturnRefOfCopy(tls_certificate));
  return peer;
}

struct MockUnsafeProposalFactory
    : public shared_model::interface::UnsafeProposalFactory {
  MOCK_METHOD3(unsafeCreateProposal,
               std::unique_ptr<shared_model::interface::Proposal>(
                   shared_model::interface::types::HeightType,
                   shared_model::interface::types::TimestampType,
                   TransactionsCollectionType));
};

struct MockCommonObjectsFactory
    : public shared_model::interface::CommonObjectsFactory {
  MOCK_METHOD(
      (FactoryResult<std::unique_ptr<shared_model::interface::Peer>>),
      createPeer,
      (const shared_model::interface::types::AddressType &,
       shared_model::interface::types::PublicKeyHexStringView,
       const std::optional<shared_model::interface::types::TLSCertificateType>
           &),
      (override));

  MOCK_METHOD4(createAccount,
               FactoryResult<std::unique_ptr<shared_model::interface::Account>>(
                   const shared_model::interface::types::AccountIdType &,
                   const shared_model::interface::types::DomainIdType &,
                   shared_model::interface::types::QuorumType,
                   const shared_model::interface::types::JsonType &));

  MOCK_METHOD3(
      createAccountAsset,
      FactoryResult<std::unique_ptr<shared_model::interface::AccountAsset>>(
          const shared_model::interface::types::AccountIdType &,
          const shared_model::interface::types::AssetIdType &,
          const shared_model::interface::Amount &));

  MOCK_METHOD3(createAsset,
               FactoryResult<std::unique_ptr<shared_model::interface::Asset>>(
                   const shared_model::interface::types::AssetIdType &,
                   const shared_model::interface::types::DomainIdType &,
                   shared_model::interface::types::PrecisionType));

  MOCK_METHOD2(createDomain,
               FactoryResult<std::unique_ptr<shared_model::interface::Domain>>(
                   const shared_model::interface::types::DomainIdType &,
                   const shared_model::interface::types::RoleIdType &));

  MOCK_METHOD(
      (FactoryResult<std::unique_ptr<shared_model::interface::Signature>>),
      createSignature,
      (shared_model::interface::types::PublicKeyHexStringView,
       shared_model::interface::types::SignedHexStringView),
      (override));
};

struct MockDomain : public shared_model::interface::Domain {
  MOCK_CONST_METHOD0(domainId,
                     shared_model::interface::types::DomainIdType &());
  MOCK_CONST_METHOD0(defaultRole,
                     shared_model::interface::types::RoleIdType &());
  MOCK_CONST_METHOD0(clone, MockDomain *());
};

struct MockAccount : public shared_model::interface::Account {
  MOCK_CONST_METHOD0(accountId,
                     shared_model::interface::types::AccountIdType &());
  MOCK_CONST_METHOD0(domainId,
                     shared_model::interface::types::DomainIdType &());
  MOCK_CONST_METHOD0(quorum, shared_model::interface::types::QuorumType());
  MOCK_CONST_METHOD0(jsonData, shared_model::interface::types::JsonType &());
  MOCK_CONST_METHOD0(clone, MockAccount *());
};

struct MockBlockJsonConverter
    : public shared_model::interface::BlockJsonConverter {
  MOCK_CONST_METHOD1(
      serialize,
      iroha::expected::Result<shared_model::interface::types::JsonType,
                              std::string>(
          const shared_model::interface::Block &block));
  MOCK_CONST_METHOD1(
      deserialize,
      iroha::expected::Result<std::unique_ptr<shared_model::interface::Block>,
                              std::string>(
          const shared_model::interface::types::JsonType &json));
};

#endif  // IROHA_SHARED_MODEL_INTERFACE_MOCKS_HPP
