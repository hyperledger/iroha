/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <tuple>
#include "cryptography/keypair.hpp"
#include "datetime/time.hpp"
#include "framework/test_logger.hpp"
#include "framework/test_subscriber.hpp"
#include "logger/logger.hpp"
#include "module/irohad/multi_sig_transactions/mst_mocks.hpp"
#include "module/irohad/multi_sig_transactions/mst_test_helpers.hpp"
#include "module/shared_model/interface_mocks.hpp"
#include "multi_sig_transactions/mst_processor_impl.hpp"
#include "multi_sig_transactions/storage/mst_storage_impl.hpp"

auto log_ = getTestLogger("MstProcessorTest");

using namespace iroha;
using namespace framework::test_subscriber;

using testing::_;
using testing::Return;

shared_model::crypto::PublicKey kAnotherPeerKey{
    iroha::createPublicKey("another_pubkey")};

class MstProcessorTest : public testing::Test {
 public:
  // --------------------------------| fields |---------------------------------

  /// propagation subject, useful for propagation control
  rxcpp::subjects::subject<PropagationStrategy::PropagationData>
      propagation_subject;
  /// use effective implementation of storage
  std::shared_ptr<MstStorage> storage;
  std::shared_ptr<FairMstProcessor> mst_processor;

  // ---------------------------------| mocks |---------------------------------

  std::shared_ptr<MockMstTransport> transport;
  std::shared_ptr<MockPropagationStrategy> propagation_strategy;
  std::shared_ptr<MockTimeProvider> time_provider;

  const shared_model::interface::types::CounterType time_now =
      iroha::time::now();
  const shared_model::interface::types::CounterType time_before = time_now - 1;
  const shared_model::interface::types::CounterType time_after = time_now + 1;

 protected:
  void SetUp() override {
    transport = std::make_shared<MockMstTransport>();
    storage =
        std::make_shared<MstStorageStateImpl>(std::make_shared<TestCompleter>(),
                                              getTestLogger("MstState"),
                                              getTestLogger("MstStorage"));

    propagation_strategy = std::make_shared<MockPropagationStrategy>();
    EXPECT_CALL(*propagation_strategy, emitter())
        .WillOnce(Return(propagation_subject.get_observable()));

    time_provider = std::make_shared<MockTimeProvider>();
    EXPECT_CALL(*time_provider, getCurrentTime())
        .WillRepeatedly(Return(time_now));

    mst_processor =
        std::make_shared<FairMstProcessor>(transport,
                                           storage,
                                           propagation_strategy,
                                           time_provider,
                                           getTestLogger("FairMstProcessor"));
  }
};

/*
 * Initialize observables of mst processor
 */
auto initObservers(std::shared_ptr<FairMstProcessor> mst_processor,
                   int a,
                   int b,
                   int c) {
  auto obs = std::make_tuple(
      make_test_subscriber<CallExact>(mst_processor->onStateUpdate(), a),
      make_test_subscriber<CallExact>(mst_processor->onPreparedBatches(), b),
      make_test_subscriber<CallExact>(mst_processor->onExpiredBatches(), c));
  std::get<0>(obs).subscribe();
  std::get<1>(obs).subscribe();
  std::get<2>(obs).subscribe();
  return obs;
}

/*
 * Make sure that observables in the valid state
 */
template <typename T>
void check(T &t) {
  ASSERT_TRUE(std::get<0>(t).validate())
      << "onStateUpdate" << std::get<0>(t).reason();
  ASSERT_TRUE(std::get<1>(t).validate())
      << "onPreparedBatches" << std::get<1>(t).reason();
  ASSERT_TRUE(std::get<2>(t).validate())
      << "onExpiredBatches" << std::get<2>(t).reason();
}

/**
 * @given initialised mst processor
 * AND wrappers on mst observables
 * AND uncompleted batch in mst
 *
 * @when the same signature for that batch is received
 *
 * @then check that:
 * absent state update transactions
 * AND absent prepared transactions
 * AND absent expired transactions
 */
TEST_F(MstProcessorTest, receivedSameSignatures) {
  // ---------------------------------| given |---------------------------------
  auto same_key = makeKey();
  mst_processor->propagateBatch(addSignaturesFromKeyPairs(
      makeTestBatch(txBuilder(1, time_now, 2)), 0, same_key));

  auto observers = initObservers(mst_processor, 0, 0, 0);

  // ---------------------------------| when |----------------------------------
  mst_processor->propagateBatch(addSignaturesFromKeyPairs(
      makeTestBatch(txBuilder(1, time_now, 2)), 0, same_key));

  // ---------------------------------| then |----------------------------------
  check(observers);
}

/**
 * @given initialised mst processor
 * AND wrappers on mst observables
 *
 * @when an incomplete batch is inserted
 *
 * @then check that:
 * notification about new batch is sent
 * AND absent prepared transactions
 * AND absent expired transactions
 */
TEST_F(MstProcessorTest, notCompletedTransactionUsecase) {
  // ---------------------------------| given |---------------------------------
  auto observers = initObservers(mst_processor, 1, 0, 0);

  // ---------------------------------| when |----------------------------------
  mst_processor->propagateBatch(
      addSignaturesFromKeyPairs(makeTestBatch(txBuilder(1)), 0, makeKey()));

  // ---------------------------------| then |----------------------------------
  check(observers);
}

/**
 * @given initialised mst processor
 * AND wrappers on mst observables
 * AND uncompleted batch in mst
 *
 * @when new signature for that batch is received, but total number of them is
 * still not enough
 *
 * @then check that:
 * state update observer is called
 * AND absent prepared transactions
 * AND absent expired transactions
 */
TEST_F(MstProcessorTest, newSignatureNotCompleted) {
  // ---------------------------------| given |---------------------------------
  auto same_key = makeKey();
  mst_processor->propagateBatch(addSignaturesFromKeyPairs(
      makeTestBatch(txBuilder(1, time_now, 3)), 0, makeKey()));

  auto observers = initObservers(mst_processor, 1, 0, 0);

  // ---------------------------------| when |----------------------------------
  mst_processor->propagateBatch(addSignaturesFromKeyPairs(
      makeTestBatch(txBuilder(1, time_now, 3)), 0, makeKey()));

  // ---------------------------------| then |----------------------------------
  check(observers);
}

/**
 * @given initialised mst processor
 * AND wrappers on mst observables
 *
 * @when the same transaction arrives with different signatures
 * AND the resulting set of signatures satisfies the account quorum number
 *
 * @then check that:
 * state is updated the same number of times as transaction arrival minus one
 * AND 1 prepared transaction
 * AND absent expired transactions
 */
TEST_F(MstProcessorTest, completedTransactionUsecase) {
  // ---------------------------------| given |---------------------------------
  auto observers = initObservers(mst_processor, 2, 1, 0);

  // ---------------------------------| when |----------------------------------
  mst_processor->propagateBatch(addSignaturesFromKeyPairs(
      makeTestBatch(txBuilder(1, time_now, 3)), 0, makeKey()));
  mst_processor->propagateBatch(addSignaturesFromKeyPairs(
      makeTestBatch(txBuilder(1, time_now, 3)), 0, makeKey()));
  mst_processor->propagateBatch(addSignaturesFromKeyPairs(
      makeTestBatch(txBuilder(1, time_now, 3)), 0, makeKey()));

  // ---------------------------------| then |----------------------------------
  check(observers);
}

/**
 * @given initialised mst processor
 * AND wrappers on mst observables
 *
 * @when insert (by propagate_batch method) batch that already
 * expired with quorum one
 *
 * @then check that:
 * state is updated
 * AND 0 prepared transaction (although quorum 1)
 * AND 1 expired transactions
 */
TEST_F(MstProcessorTest, expiredTransactionUsecase) {
  // ---------------------------------| given |---------------------------------
  auto observers = initObservers(mst_processor, 1, 0, 1);

  // ---------------------------------| when |----------------------------------
  auto quorum = 1u;
  mst_processor->propagateBatch(addSignaturesFromKeyPairs(
      makeTestBatch(txBuilder(1, time_before, quorum)), 0, makeKey()));

  // ---------------------------------| then |----------------------------------
  check(observers);
}

/**
 * @given initialised mst processor
 * AND our state contains one transactions TX with quorum 2
 * AND wrappers on mst observables
 *
 * @when received new state from other peer via transport,
 * that contains TX with another signature
 *
 * @then check that:
 * state observer is not called
 * AND 1 prepared transaction
 * AND 0 expired transactions
 */
TEST_F(MstProcessorTest, onUpdateFromTransportUsecase) {
  // ---------------------------------| given |---------------------------------
  auto quorum = 2;
  mst_processor->propagateBatch(addSignaturesFromKeyPairs(
      makeTestBatch(txBuilder(1, time_now, quorum)), 0, makeKey()));

  auto observers = initObservers(mst_processor, 0, 1, 0);

  // ---------------------------------| when |----------------------------------
  auto transported_state = MstState::empty(getTestLogger("MstState"),
                                           std::make_shared<TestCompleter>());
  transported_state += addSignaturesFromKeyPairs(
      makeTestBatch(txBuilder(1, time_now, quorum)), 0, makeKey());
  mst_processor->onNewState(kAnotherPeerKey, transported_state);

  // ---------------------------------| then |----------------------------------
  check(observers);
}

/**
 * @given initialised mst processor
 * AND our state contains one transaction
 *
 * @when received notification about new propagation
 *
 * @then check that:
 * transport invoked for all peers
 */

TEST_F(MstProcessorTest, onNewPropagationUsecase) {
  // ---------------------------------| given |---------------------------------
  auto quorum = 2u;
  mst_processor->propagateBatch(addSignaturesFromKeyPairs(
      makeTestBatch(txBuilder(1, time_after, quorum)), 0, makeKey()));
  EXPECT_CALL(*transport, sendState(_, _)).Times(2);

  // ---------------------------------| when |----------------------------------
  std::vector<std::shared_ptr<shared_model::interface::Peer>> peers{
      makePeer("one", iroha::createPublicKey("one")),
      makePeer("two", iroha::createPublicKey("two"))};
  propagation_subject.get_subscriber().on_next(peers);
}

/**
 * @given initialized mst processor
 * AND our state contains one transaction
 * AND one peer with the same state as our
 *
 * @when received notification about new propagation
 *
 * @then check that transport was not invoked
 */
TEST_F(MstProcessorTest, emptyStatePropagation) {
  // ---------------------------------| then |----------------------------------
  EXPECT_CALL(*transport, sendState(_, _)).Times(0);

  // ---------------------------------| given |---------------------------------
  auto another_peer = makePeer("another", iroha::createPublicKey());

  auto another_peer_state = MstState::empty(
      getTestLogger("MstState"),
      std::make_shared<iroha::DefaultCompleter>(std::chrono::minutes(0)));
  another_peer_state += makeTestBatch(txBuilder(1));

  storage->apply(another_peer->pubkey(), another_peer_state);
  ASSERT_TRUE(
      storage->getDiffState(another_peer->pubkey(), time_now).isEmpty());

  // ---------------------------------| when |----------------------------------
  std::vector<std::shared_ptr<shared_model::interface::Peer>> peers{
      std::move(another_peer)};
  propagation_subject.get_subscriber().on_next(peers);
}

/**
 * @given initialized mst processor with empty state
 *
 * @when received other peer's state containing an outdated batch
 *
 * @then check that transport was not invoked
 * @and queues are not pushed to
 * @and the batch does not get into our state
 */
TEST_F(MstProcessorTest, receivedOutdatedState) {
  // ---------------------------------| then |----------------------------------
  EXPECT_CALL(*transport, sendState(_, _)).Times(0);
  auto observers = initObservers(mst_processor, 0, 0, 0);

  // ---------------------------------| when |----------------------------------
  auto transported_state = MstState::empty(getTestLogger("MstState"),
                                           std::make_shared<TestCompleter>());
  const auto expired_batch = makeTestBatch(txBuilder(1, time_before, 3));
  transported_state += addSignaturesFromKeyPairs(expired_batch, 0, makeKey());
  mst_processor->onNewState(kAnotherPeerKey, transported_state);

  // ---------------------------------| then |----------------------------------
  EXPECT_FALSE(storage->batchInStorage(expired_batch));
  check(observers);
}

/**
 * @given initialized mst processor with two incomplete transactions in the
 * state
 *
 * @when one of them is received from another peer
 *
 * @then no observables are triggered
 */
TEST_F(MstProcessorTest, receivedOneOfExistingTxs) {
  const auto batch = addSignaturesFromKeyPairs(
      makeTestBatch(txBuilder(1, time_now, 2)), 0, makeKey());
  mst_processor->propagateBatch(batch);
  mst_processor->propagateBatch(addSignaturesFromKeyPairs(
      makeTestBatch(txBuilder(2, time_now, 2)), 0, makeKey()));

  auto received_state = MstState::empty(getTestLogger("MstState"),
                                        std::make_shared<TestCompleter>());
  received_state += batch;
  auto observers = initObservers(mst_processor, 0, 0, 0);
  mst_processor->onNewState(kAnotherPeerKey, received_state);

  check(observers);
}
