/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"
#include "transaction.pb.h"

using namespace integration_framework;
using namespace shared_model;
using namespace common_constants;

class InvalidField : public AcceptanceFixture {
 public:
  std::shared_ptr<iroha::Subscription> se_ = iroha::getSubscription();
  ~InvalidField() {
    se_->dispose();
  }
};

/**
 * TODO mboldyrev 18.01.2019 IR-217 remove, covered by field validator test
 *
 * @given tx with CreateAccount command and invalid signature size
 * @when send it
 * @then Torii returns stateless fail
 */
TEST_F(InvalidField, Signature) {
  auto tx = complete(baseTx()).getTransport();
  // extend signature to invalid size
  auto sig = tx.mutable_signatures(0)->mutable_signature();
  sig->resize(sig->size() + 1, 'a');

  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(proto::Transaction(tx), CHECK_STATELESS_INVALID);
}

/**
 * TODO mboldyrev 18.01.2019 IR-217 remove, covered by field validator test
 *
 * @given tx with CreateAccount command and invalid pub key size
 * @when send it
 * @then Torii returns stateless fail
 */
TEST_F(InvalidField, Pubkey) {
  auto tx = complete(baseTx()).getTransport();
  // extend public key to invalid size
  auto pkey = tx.mutable_signatures(0)->mutable_public_key();
  pkey->resize(pkey->size() + 1, 'a');

  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(proto::Transaction(tx), CHECK_STATELESS_INVALID);
}
