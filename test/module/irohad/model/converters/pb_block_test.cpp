/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "commands.pb.h"
#include "cryptography/ed25519_sha3_impl/internal/sha3_hash.hpp"
#include "model/block.hpp"
#include "model/converters/pb_block_factory.hpp"
#include "model/sha3_hash.hpp"

#include "model/commands/add_asset_quantity.hpp"
#include "model/commands/add_peer.hpp"
#include "model/commands/add_signatory.hpp"
#include "model/commands/create_account.hpp"
#include "model/commands/create_asset.hpp"
#include "model/commands/create_domain.hpp"
#include "model/commands/remove_signatory.hpp"
#include "model/commands/set_quorum.hpp"
#include "model/commands/transfer_asset.hpp"

TEST(BlockTest, bl_test) {
  auto orig_tx = iroha::model::Transaction();
  orig_tx.creator_account_id = "andr@kek";
  auto siga = iroha::model::Signature();
  std::fill(siga.pubkey.begin(), siga.pubkey.end(), 0x22);
  std::fill(siga.signature.begin(), siga.signature.end(), 0x10);
  orig_tx.signatures = {siga};

  orig_tx.created_ts = 2;

  auto c1 = iroha::model::CreateDomain();
  c1.domain_id = "keker";
  auto c2 = iroha::model::CreateAsset();
  c2.domain_id = "keker";
  c2.precision = 2;
  c2.asset_name = "fedor-coin";

  orig_tx.commands = {std::make_shared<iroha::model::CreateDomain>(c1),
                      std::make_shared<iroha::model::CreateAsset>(c2)};

  auto orig_block = iroha::model::Block();
  orig_block.created_ts = 1;

  std::fill(orig_block.prev_hash.begin(), orig_block.prev_hash.end(), 0x3);
  orig_block.sigs = {siga};

  orig_block.height = 3;
  orig_block.txs_number = 1;
  orig_block.transactions = {orig_tx};

  orig_block.hash = iroha::hash(orig_block);

  auto factory = iroha::model::converters::PbBlockFactory();
  auto proto_block = factory.serialize(orig_block);
  auto serial_block = factory.deserialize(proto_block);
  ASSERT_EQ(orig_block.created_ts, serial_block.created_ts);
  ASSERT_EQ(orig_block.transactions, serial_block.transactions);
  ASSERT_EQ(orig_block.sigs, serial_block.sigs);
  ASSERT_EQ(orig_block.hash, serial_block.hash);
  ASSERT_EQ(orig_block.prev_hash, serial_block.prev_hash);
  ASSERT_EQ(orig_block.txs_number, serial_block.txs_number);
  ASSERT_EQ(orig_block, serial_block);
}
