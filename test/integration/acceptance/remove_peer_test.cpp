/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/acceptance/fake_peer_fixture.hpp"

#include "ametsuchi/block_query.hpp"
#include "ametsuchi/storage.hpp"
#include "builders/protobuf/transaction.hpp"
#include "consensus/yac/vote_message.hpp"
#include "consensus/yac/yac_hash_provider.hpp"
#include "framework/integration_framework/fake_peer/behaviour/honest.hpp"
#include "framework/integration_framework/fake_peer/block_storage.hpp"
#include "framework/integration_framework/iroha_instance.hpp"
#include "framework/integration_framework/test_irohad.hpp"
#include "framework/test_logger.hpp"
#include "main/subscription.hpp"
#include "module/shared_model/builders/protobuf/block.hpp"
#include "ordering/impl/on_demand_common.cpp"

using namespace common_constants;
using namespace shared_model;
using namespace integration_framework;
using namespace iroha;
using namespace shared_model::interface::permissions;

using interface::types::PublicKeyHexStringView;

static constexpr std::chrono::seconds kSynchronizerWaitingTime(20);

struct RemovePeerTest : FakePeerFixture {};
INSTANTIATE_TEST_SUITE_P_DifferentStorageTypes(RemovePeerTest);
