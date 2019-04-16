/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "commands.pb.h"
#include "model/converters/pb_transaction_factory.hpp"
#include "model/transaction.hpp"

#include "model/commands/add_asset_quantity.hpp"
#include "model/commands/add_peer.hpp"
#include "model/commands/add_signatory.hpp"
#include "model/commands/create_account.hpp"
#include "model/commands/create_asset.hpp"
#include "model/commands/create_domain.hpp"
#include "model/commands/remove_signatory.hpp"
#include "model/commands/set_quorum.hpp"
#include "model/commands/transfer_asset.hpp"

TEST(TransactionTest, tx_test) {
  auto orig_tx = iroha::model::Transaction();
  orig_tx.creator_account_id = "andr@kek";
  auto siga = iroha::model::Signature();
  std::fill(siga.pubkey.begin(), siga.pubkey.end(), 0x22);
  std::fill(siga.signature.begin(), siga.signature.end(), 0x10);
  orig_tx.signatures = {siga};

  orig_tx.created_ts = 2;
  orig_tx.quorum = 3;
  auto c1 = iroha::model::CreateDomain();
  c1.domain_id = "keker";
  auto c2 = iroha::model::CreateAsset();
  c2.domain_id = "keker";
  c2.precision = 2;
  c2.asset_name = "fedor-coin";

  orig_tx.commands = {std::make_shared<iroha::model::CreateDomain>(c1),
                      std::make_shared<iroha::model::CreateAsset>(c2)};

  auto factory = iroha::model::converters::PbTransactionFactory();
  auto proto_tx = factory.serialize(orig_tx);
  auto serial_tx = factory.deserialize(proto_tx);
  ASSERT_EQ(orig_tx, *serial_tx);
}
