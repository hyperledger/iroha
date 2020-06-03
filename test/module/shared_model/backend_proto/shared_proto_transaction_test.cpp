/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/transaction.hpp"

#include <gtest/gtest.h>
#include "builders/protobuf/transaction.hpp"
#include "cryptography/crypto_provider/crypto_signer.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"

// common data for tests
auto created_time = iroha::time::now();
std::string creator_account_id = "admin@test";

/**
 * generates sample transaction without commands
 * @return generated transaction
 */
iroha::protocol::Transaction generateEmptyTransaction() {
  iroha::protocol::Transaction proto_tx;
  auto &payload = *proto_tx.mutable_payload()->mutable_reduced_payload();
  payload.set_creator_account_id(creator_account_id);
  payload.set_created_time(created_time);
  payload.set_quorum(1);

  return proto_tx;
}

/**
 * Helper function to generate AddAssetQuantityCommand
 * @param asset_id asset id to add value to
 * @return AddAssetQuantity protocol command
 */
iroha::protocol::AddAssetQuantity generateAddAssetQuantity(
    std::string asset_id) {
  iroha::protocol::AddAssetQuantity command;

  command.set_asset_id(asset_id);
  command.set_amount("10.00");

  return command;
}

/**
 * @given transaction field values and sample command values, reference tx
 * @when create transaction with sample command using transaction builder
 * @then transaction is built correctly
 */
TEST(ProtoTransaction, Builder) {
  iroha::protocol::Transaction proto_tx = generateEmptyTransaction();

  std::string account_id = "admin@test", asset_id = "coin#test",
              amount = "10.00";
  auto command = proto_tx.mutable_payload()
                     ->mutable_reduced_payload()
                     ->add_commands()
                     ->mutable_add_asset_quantity();

  command->CopyFrom(generateAddAssetQuantity(asset_id));

  auto keypair =
      shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();
  auto signature_hex = shared_model::crypto::CryptoSigner::sign(
      shared_model::crypto::Blob(proto_tx.payload().SerializeAsString()),
      keypair);

  auto sig = proto_tx.add_signatures();
  sig->set_public_key(keypair.publicKey());
  sig->set_signature(signature_hex);

  auto tx = shared_model::proto::TransactionBuilder()
                .creatorAccountId(creator_account_id)
                .addAssetQuantity(asset_id, amount)
                .createdTime(created_time)
                .quorum(1)
                .build();

  auto signedTx = tx.signAndAddSignature(keypair).finish();
  auto &proto = signedTx.getTransport();

  ASSERT_EQ(proto_tx.SerializeAsString(), proto.SerializeAsString());
}

/**
 * @given transaction field values and sample command values with wrongly set
 * values
 * @when create transaction with sample command using transaction builder
 * @then transaction throws exception due to badly formed fields in commands
 */
TEST(ProtoTransaction, BuilderWithInvalidTx) {
  std::string invalid_account_id = "admintest";  // invalid account_id without @
  std::string invalid_asset_id = "cointest",     // invalid asset_id without #
      amount = "10.00";

  ASSERT_THROW(shared_model::proto::TransactionBuilder()
                   .creatorAccountId(invalid_account_id)
                   .addAssetQuantity(invalid_asset_id, amount)
                   .createdTime(created_time)
                   .quorum(1)
                   .build(),
               std::invalid_argument);
}
