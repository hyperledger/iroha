/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "model/block.hpp"
#include "model/commands/add_asset_quantity.hpp"
#include "model/commands/add_peer.hpp"
#include "model/commands/add_signatory.hpp"
#include "model/commands/append_role.hpp"
#include "model/commands/create_account.hpp"
#include "model/commands/create_asset.hpp"
#include "model/commands/create_domain.hpp"
#include "model/commands/create_role.hpp"
#include "model/commands/detach_role.hpp"
#include "model/commands/grant_permission.hpp"
#include "model/commands/remove_signatory.hpp"
#include "model/commands/revoke_permission.hpp"
#include "model/commands/set_quorum.hpp"
#include "model/commands/subtract_asset_quantity.hpp"
#include "model/commands/transfer_asset.hpp"
#include "model/sha3_hash.hpp"
#include "model/transaction.hpp"

using namespace iroha::model;

// -----|AddPeer|-----

AddPeer createAddPeer() {
  AddPeer addPeer;
  addPeer.peer.address = "localhost";
  std::fill(addPeer.peer.pubkey.begin(), addPeer.peer.pubkey.end(), 0x1);
  return addPeer;
}

TEST(ModelOperatorTest, AddPeerTest) {
  AddPeer first = createAddPeer();
  AddPeer second = createAddPeer();
  ASSERT_EQ(first, second);
  second.peer.address = "127.0.0.1";
  ASSERT_NE(first, second);
}

// -----|AddAssetQuantity|-----

AddAssetQuantity createAddAssetQuantity() {
  AddAssetQuantity aaq;
  aaq.amount = "10.10";
  aaq.asset_id = "123";
  aaq.description = "testdescription";
  return aaq;
}

TEST(ModelOperatorTest, AddAssetQuantityTest) {
  auto first = createAddAssetQuantity();
  auto second = createAddAssetQuantity();

  ASSERT_EQ(first, second);
  second.asset_id = "22";
  ASSERT_NE(first, second);
}

// -----|SubtractAssetQuantity|-----

SubtractAssetQuantity createSubtractAssetQuantity() {
  SubtractAssetQuantity saq;
  saq.amount = "10.10";
  saq.asset_id = "ast";
  saq.description = "testdescription";
  return saq;
}

/**
 * @given SubtractAssetQuantity
 * @when Same data
 * @then Return true.
 */
TEST(ModelOperatorTest, SubtractAssetQuantityTest) {
  auto first = createSubtractAssetQuantity();
  auto second = createSubtractAssetQuantity();

  ASSERT_EQ(first, second);
  second.asset_id = "22";
  ASSERT_NE(first, second);
}

// -----|AddSignatory|-----

AddSignatory createAddSignatory() {
  AddSignatory add_signatory;
  add_signatory.account_id = "123";
  std::fill(add_signatory.pubkey.begin(), add_signatory.pubkey.end(), 0x23);
  return add_signatory;
}

TEST(ModelOperatorTest, AddSignatoryTest) {
  auto first = createAddSignatory();
  auto second = createAddSignatory();

  ASSERT_EQ(first, second);
  second.account_id = "22";
  ASSERT_NE(first, second);
}

// -----|CreateAccount|-----

CreateAccount createCreateAccount() {
  CreateAccount createAccount;
  createAccount.domain_id = "123";
  createAccount.account_name = "kek";
  std::fill(createAccount.pubkey.begin(), createAccount.pubkey.end(), 0x23);
  return createAccount;
}

TEST(ModelOperatorTest, CreateAccountTest) {
  auto first = createCreateAccount();
  auto second = createCreateAccount();

  ASSERT_EQ(first, second);
  second.account_name = "cheburek";
  ASSERT_NE(first, second);
}

// -----|CreateAsset|-----

CreateAsset createCreateAsset() {
  CreateAsset createAsset;
  createAsset.domain_id = "localhost";
  createAsset.asset_name = "rub";
  createAsset.precision = 2;
  return createAsset;
}

TEST(ModelOperatorTest, CreateAssetTest) {
  auto first = createCreateAsset();
  auto second = createCreateAsset();

  ASSERT_EQ(first, second);
  second.asset_name = "usd";
  ASSERT_NE(first, second);
}

// -----|CreateDomain|-----

CreateDomain createCreateDomain() {
  CreateDomain createDomain;
  createDomain.domain_id = "rus";
  createDomain.user_default_role = "test";
  return createDomain;
}

TEST(ModelOperatorTest, CreateDomainTest) {
  auto first = createCreateDomain();
  auto second = createCreateDomain();

  ASSERT_EQ(first, second);
  second.domain_id = "jp";
  ASSERT_NE(first, second);
}

// -----|RemoveSignatory|-----

RemoveSignatory createRemoveSignatory() {
  RemoveSignatory removeSignatory;
  removeSignatory.account_id = "123";
  std::fill(removeSignatory.pubkey.begin(), removeSignatory.pubkey.end(), 0x23);
  return removeSignatory;
}

TEST(ModelOperatorTest, RemoveSignatoryTest) {
  auto first = createRemoveSignatory();
  auto second = createRemoveSignatory();

  ASSERT_EQ(first, second);
  second.account_id = "22";
  ASSERT_NE(first, second);
}

// -----|SetQuorum|-----

SetQuorum createSetQuorum() {
  SetQuorum setQuorum;
  setQuorum.account_id = "123";
  setQuorum.new_quorum = 23;
  return setQuorum;
}

TEST(ModelOperatorTest, SetQuorumTest) {
  auto first = createSetQuorum();
  auto second = createSetQuorum();

  ASSERT_EQ(first, second);
  second.account_id = "22";
  ASSERT_NE(first, second);
}

// -----|TransferAsset|-----

TransferAsset createTransferAsset() {
  TransferAsset transferAsset;
  transferAsset.asset_id = "123";
  transferAsset.amount = "10.10";
  transferAsset.src_account_id = "1";
  transferAsset.dest_account_id = "2";
  transferAsset.description = "test";
  return transferAsset;
}

TEST(ModelOperatorTest, TransferAssetTest) {
  auto first = createTransferAsset();
  auto second = createTransferAsset();

  ASSERT_EQ(first, second);
  second.asset_id = "22";
  ASSERT_NE(first, second);
}

// -----|CreateRole|-----

TEST(ModelOperatorTest, CreateRoleTest) {
  auto first = CreateRole("master", {"CanDoMagic"});
  auto second = CreateRole("master", {"CanDoMagic"});

  ASSERT_EQ(first, second);
  second.role_name = "padawan";
  ASSERT_NE(first, second);
}

// -----|AppendRole|-----

TEST(ModelOperatorTest, AppendRoleTest) {
  auto first = AppendRole("yoda", "master");
  auto second = AppendRole("yoda", "master");

  ASSERT_EQ(first, second);
  second.account_id = "obi";
  ASSERT_NE(first, second);
}

// -----|AppendRole|-----

TEST(ModelOperatorTest, DetachRoleTest) {
  auto first = DetachRole("yoda", "master");
  auto second = DetachRole("yoda", "master");

  ASSERT_EQ(first, second);
  second.account_id = "obi";
  ASSERT_NE(first, second);
}

// -----|GrantPermission|-----

TEST(ModelOperatorTest, GrantPermissionTest) {
  auto first = GrantPermission("admin", "can_read");
  auto second = GrantPermission("admin", "can_read");

  ASSERT_EQ(first, second);
  second.account_id = "non-admin";
  ASSERT_NE(first, second);
}

// -----|RevokePermission|-----

TEST(ModelOperatorTest, RevokePermissionTest) {
  auto first = RevokePermission("admin", "can_read");
  auto second = RevokePermission("admin", "can_read");

  ASSERT_EQ(first, second);
  second.account_id = "non-admin";
  ASSERT_NE(first, second);
}

// -----|Signature|-----

Signature createSignature() {
  Signature sig{};
  std::fill(sig.pubkey.begin(), sig.pubkey.end(), 0x1);
  std::fill(sig.signature.begin(), sig.signature.end(), 0x1);
  return sig;
}

TEST(ModelOperatorTest, SignatureTest) {
  auto sig1 = createSignature();
  auto sig2 = createSignature();

  ASSERT_EQ(sig1, sig2);
  sig1.signature[0] = 0x23;

  // equals because public keys are same
  ASSERT_EQ(sig1, sig2);

  auto sig3 = createSignature();
  sig3.pubkey[0] = 0x23;

  // not equals because public keys are different
  ASSERT_NE(sig1, sig3);
}

// -----|Transaction|-----

Transaction createTransaction() {
  Transaction transaction;
  transaction.created_ts = 1;
  transaction.quorum = 1;
  transaction.creator_account_id = "132";
  transaction.signatures.push_back(createSignature());

  // commands
  transaction.commands.push_back(
      std::make_shared<AddAssetQuantity>(createAddAssetQuantity()));
  transaction.commands.push_back(
      std::make_shared<SubtractAssetQuantity>(createSubtractAssetQuantity()));
  transaction.commands.push_back(std::make_shared<AddPeer>(createAddPeer()));
  transaction.commands.push_back(
      std::make_shared<AddSignatory>(createAddSignatory()));
  transaction.commands.push_back(
      std::make_shared<CreateAccount>(createCreateAccount()));
  transaction.commands.push_back(
      std::make_shared<CreateAsset>(createCreateAsset()));
  transaction.commands.push_back(
      std::make_shared<CreateDomain>(createCreateDomain()));
  transaction.commands.push_back(
      std::make_shared<RemoveSignatory>(createRemoveSignatory()));
  transaction.commands.push_back(
      std::make_shared<TransferAsset>(createTransferAsset()));
  return transaction;
}

TEST(ModelOperatorTest, TransactionTest) {
  auto tx1 = createTransaction();
  auto tx2 = createTransaction();

  ASSERT_EQ(tx1, tx2);
  tx1.signatures.push_back(createSignature());
  ASSERT_EQ(tx1, tx2);  // signatures not affect on equality
}

// -----|Block|-----

Block createBlock() {
  Block block;
  block.created_ts = 1;
  block.txs_number = 2;
  std::fill(block.prev_hash.begin(), block.prev_hash.end(), 0x23);
  block.sigs.push_back(createSignature());
  block.transactions.push_back(createTransaction());
  Block::HashType rejected_tx_hash;
  std::fill(rejected_tx_hash.begin(), rejected_tx_hash.end(), 0x24);
  block.rejected_transactions_hashes.emplace_back(std::move(rejected_tx_hash));
  block.height = 123;

  block.hash = iroha::hash(block);
  return block;
}

TEST(ModelOperatorTest, BlockTest) {
  auto first = createBlock();
  auto second = createBlock();

  ASSERT_EQ(first, second);
  second.height += 1;
  ASSERT_NE(first, second);
}
