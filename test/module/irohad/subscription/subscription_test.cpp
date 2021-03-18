/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/subscription.hpp"

#include <gtest/gtest.h>
#include <vector>

#include "module/irohad/subscription/subscription_mocks.hpp"

using namespace iroha;

class SubscriptionTest : public ::testing::Test {
 public:
  template<uint32_t ThreadsCount>
  auto createSubscriptionManager() {
    using Manager = subscription::SubscriptionManager<ThreadsCount>;
    return std::make_shared<Manager>();
  }

  template<uint32_t Tid, uint64_t Event, typename EventData, typename ObjectType, typename Manager, typename F>
  auto createSubscriber(std::shared_ptr<Manager> const &manager, ObjectType &&initial, F &&f) {
    using Dispatcher = typename Manager::Dispatcher;
    using Subscriber = subscription::
        SubscriberImpl<uint64_t, Dispatcher, ObjectType, EventData>;

    auto subscriber = std::make_shared<Subscriber>(
        manager->template getEngine<uint64_t, EventData>(), std::move(initial));

    subscriber->setCallback([f(std::forward<F>(f))](auto, ObjectType &obj, uint64_t key, EventData data) mutable {
      ASSERT_EQ(key, Event);
      std::forward<F>(f)(obj, std::move(data));
    });
    subscriber->template subscribe<Tid>(0, Event);

    return subscriber;
  }

  using MockDispatcher = subscription::MockDispatcher;
  using MockSubscriber = subscription::MockSubscriber<uint32_t, MockDispatcher, std::string>;
  using TestEngine     = subscription::SubscriptionEngine<uint32_t, MockDispatcher, subscription::Subscriber<uint32_t, MockDispatcher, std::string>>;

  auto createMockSubscriber(std::shared_ptr<TestEngine> const &engine) {
    return std::make_shared<MockSubscriber>(engine);
  }

  auto createTestEngine(std::shared_ptr<MockDispatcher> const &dispatcher) {
    return std::make_shared<TestEngine>(dispatcher);
  }

  auto createDispatcher() {
    return std::make_shared<MockDispatcher>();
  }
};

/**
 * @given subscription engine
 * @when subscriber is present
 * @and notification is called
 * @then subscriber must receive correct data from notification
 */
TEST_F(SubscriptionTest, SimpleExecutionTest) {
  auto manager = createSubscriptionManager<1>();
  utils::WaitForSingleObject complete;

  std::string test_value = "the fast and the furious";
  auto subscriber = createSubscriber<0ul, 1ul, std::string>(
      manager, false, [&complete, test_value](auto, std::string value) {
        ASSERT_EQ(test_value, value);
        complete.set();
      });

  manager->notify(1ul, test_value);
  ASSERT_TRUE(complete.wait(std::chrono::minutes(1ull)));
}

/**
 * @given subscription engine
 * @when 2 subscribers are present
 * @and they subscribe on a single event in a single thread
 * @then they must be called in the same order
 */
TEST_F(SubscriptionTest, DoubleExecutionTest) {
  auto manager = createSubscriptionManager<1>();
  utils::WaitForSingleObject complete;

  uint32_t counter = 0ul;
  std::string test_value = "the fast and the furious";
  auto subscriber_1 = createSubscriber<0ul, 1ul, std::string>(
      manager, false, [&counter, test_value](auto, std::string value) {
        ASSERT_EQ(test_value, value);
        ASSERT_EQ(counter, 0ul);
        ++counter;
      });

  auto subscriber_2 = createSubscriber<0ul, 1ul, std::string>(
      manager, false, [&complete, &counter, test_value](auto, std::string value) {
        ASSERT_EQ(test_value, value);
        ASSERT_EQ(counter, 1ul);
        complete.set();
      });

  manager->notify(1ul, test_value);
  ASSERT_TRUE(complete.wait(std::chrono::minutes(1ull)));
}

/**
 * @given subscription engine
 * @when 2 subscribers are present
 * @and they subscribe on a different events in a single thread
 * @and both events are notified
 * @then the handlers of each subscriber must be called once
 */
TEST_F(SubscriptionTest, XExecutionTest) {
  auto manager = createSubscriptionManager<1>();
  utils::WaitForSingleObject complete[2];
  uint32_t counter[2] = {0ul};

  [[maybe_unused]] auto subscriber_1 = createSubscriber<0ul, 1ul, bool>(
      manager, false, [&](auto, auto) {
        ASSERT_EQ(counter[0], 0ul);
        ++counter[0];
        complete[0].set();
      });

  [[maybe_unused]] auto subscriber_2 = createSubscriber<0ul, 2ul, bool>(
      manager, false, [&](auto, auto) {
        ASSERT_EQ(counter[1], 0ul);
        ++counter[1];
        complete[1].set();
      });

  manager->notify(1ul, false);
  manager->notify(2ul, false);
  ASSERT_TRUE(complete[0].wait(std::chrono::minutes(1ull)));
  ASSERT_TRUE(complete[1].wait(std::chrono::minutes(1ull)));

  ASSERT_EQ(counter[0], 1ul);
  ASSERT_EQ(counter[1], 1ul);
}

/**
 * @given subscription engine
 * @when 4 subscribers are present
 * @and they subscribe on a single event in a different threads
 * @then each handler must be called once in his thread
 */
TEST_F(SubscriptionTest, ParallelExecutionTest) {
  auto manager = createSubscriptionManager<4>();
  utils::WaitForSingleObject complete[4];

  using SharedObject = utils::ReadWriteObject<std::map<std::thread::id, uint32_t>>;
  using SharedObjectRef = std::reference_wrapper<SharedObject>;

  SharedObject shared_object;

  [[maybe_unused]] auto subscriber_0 = createSubscriber<0ul, 1ul, bool>(
      manager, SharedObjectRef(shared_object), [&](SharedObjectRef object, auto) {
        object.get().exclusiveAccess([](auto &data){
          ++data[std::this_thread::get_id()];
        });
        complete[0].set();
      });
  [[maybe_unused]] auto subscriber_1 = createSubscriber<1ul, 1ul, bool>(
      manager, SharedObjectRef(shared_object), [&](SharedObjectRef object, auto) {
        object.get().exclusiveAccess([](auto &data){
          ++data[std::this_thread::get_id()];
        });
        complete[1].set();
      });
  [[maybe_unused]] auto subscriber_2 = createSubscriber<2ul, 1ul, bool>(
      manager, SharedObjectRef(shared_object), [&](SharedObjectRef object, auto) {
        object.get().exclusiveAccess([](auto &data){
          ++data[std::this_thread::get_id()];
        });
        complete[2].set();
      });
  [[maybe_unused]] auto subscriber_3 = createSubscriber<3ul, 1ul, bool>(
      manager, SharedObjectRef(shared_object), [&](SharedObjectRef object, auto) {
        object.get().exclusiveAccess([](auto &data){
          ++data[std::this_thread::get_id()];
        });
        complete[3].set();
      });

  manager->notify(1ul, false);
  for (auto &c : complete)
    ASSERT_TRUE(c.wait(std::chrono::minutes(1ull)));

  shared_object.sharedAccess([](auto const &values) {
    ASSERT_EQ(values.size(), 4);
    for (auto &value : values)
      ASSERT_TRUE(value.second == 1);
  });
}

/**
 * @given subscription engine
 * @when 2 subscribers are present
 * @and they subscribe on a different events in a different threads
 * @and each of them generate event for the other
 * @then each handler must be called one by one
 */
TEST_F(SubscriptionTest, PingPongExecutionTest) {
  auto manager = createSubscriptionManager<2>();
  utils::WaitForSingleObject complete;

  [[maybe_unused]] auto subscriber_0 = createSubscriber<0ul, 0ul, uint32_t, uint32_t>(
      manager, 0ul, [&](uint32_t &obj, uint32_t value) {
        obj = value;
        manager->notify<uint64_t, uint32_t>(1ul, value + 7ul);
      });
  [[maybe_unused]] auto subscriber_1 = createSubscriber<1ul, 1ul, uint32_t, uint32_t>(
      manager, 0ul, [&](uint32_t &obj, uint32_t value) {
        obj = value;
        if (value > 40ul)
          complete.set();
        else
          manager->notify<uint64_t, uint32_t>(0ul, (value << 1ul));
      });

  manager->notify<uint64_t, uint32_t>(0ul, 0ul);
  ASSERT_TRUE(complete.wait(std::chrono::minutes(1ull)));
  ASSERT_EQ(subscriber_0->get(), 42ul);
  ASSERT_EQ(subscriber_1->get(), 49ul);
}

/**
 * @given subscription engine
 * @when 3 subscribers are present
 * @and they subscribe on a single event
 * @and this event notifies several times in order A-B-C
 * @then no rotation is present: first all handlers will process A, then B, then C
 */
TEST_F(SubscriptionTest, RotationExecutionTest_1) {
  auto manager = createSubscriptionManager<1>();

  std::atomic<uint32_t> counter = 0;
  std::string result;
  [[maybe_unused]] auto subscriber_0 = createSubscriber<0ul, 0ul, std::string>(
      manager, false, [&](auto, std::string value) {
        result += value;
        ++counter;
      });
  [[maybe_unused]] auto subscriber_1 = createSubscriber<0ul, 0ul, std::string>(
      manager, false, [&](auto, std::string value) {
        result += value;
        ++counter;
      });
  [[maybe_unused]] auto subscriber_2 = createSubscriber<0ul, 0ul, std::string>(
      manager, false, [&](auto, std::string value) {
        result += value;
        ++counter;
      });

  manager->notify(0ul, std::string("A"));
  manager->notify(0ul, std::string("B"));
  manager->notify(0ul, std::string("C"));

  while (counter.load(std::memory_order_relaxed) < 9)
    std::this_thread::sleep_for(std::chrono::milliseconds(1ull));

  ASSERT_EQ(result, "AAABBBCCC");
}

/**
 * @given subscription engine
 * @when 3 subscribers are present
 * @and they subscribe on a single event
 * @and this event notifies several times
 * @then no rotation is present: handlers will be called in a subscription order
 */
TEST_F(SubscriptionTest, RotationExecutionTest_2) {
  auto manager = createSubscriptionManager<1>();

  std::atomic<uint32_t> counter = 0;
  std::string result;
  [[maybe_unused]] auto subscriber_0 = createSubscriber<0ul, 0ul, bool>(
      manager, false, [&](auto, auto value) {
        result += 'A';
        ++counter;
      });
  [[maybe_unused]] auto subscriber_1 = createSubscriber<0ul, 0ul, bool>(
      manager, false, [&](auto, auto value) {
        result += 'B';
        ++counter;
      });
  [[maybe_unused]] auto subscriber_2 = createSubscriber<0ul, 0ul, bool>(
      manager, false, [&](auto, auto value) {
        result += 'C';
        ++counter;
      });

  manager->notify(0ul, false);
  manager->notify(0ul, false);
  manager->notify(0ul, false);

  while (counter.load(std::memory_order_relaxed) < 9)
    std::this_thread::sleep_for(std::chrono::milliseconds(1ull));

  ASSERT_EQ(result, "ABCABCABC");
}

/**
 * @given subscription engine
 * @when subscriber is present
 * @and notifications generate with delay
 * @then the handlers must be called in a delay order
 */
TEST_F(SubscriptionTest, RotationExecutionTest_3) {
  auto manager = createSubscriptionManager<1>();

  std::atomic<uint32_t> counter = 0;
  std::string result;
  [[maybe_unused]] auto subscriber_0 = createSubscriber<0ul, 0ul, std::string>(
      manager, false, [&](auto, auto value) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5ull));
        result += value;
        ++counter;
      });

  manager->notifyDelayed(std::chrono::milliseconds(100ull), 0ul, std::string("E"));
  manager->notifyDelayed(std::chrono::milliseconds(30ull), 0ul, std::string("C"));
  manager->notifyDelayed(std::chrono::milliseconds(50ull), 0ul, std::string("D"));
  manager->notify(0ul, std::string("A"));
  manager->notify(0ul, std::string("B"));

  while (counter.load(std::memory_order_relaxed) < 5)
    std::this_thread::sleep_for(std::chrono::milliseconds(10ull));

  ASSERT_EQ(result, "ABCDE");
}

/**
 * @given subscription engine
 * @when 5 subscribers are present
 * @and notifications generate one for the next one
 * @then the handlers must be called in a determined order
 */
TEST_F(SubscriptionTest, StarExecutionTest) {
  auto manager = createSubscriptionManager<5>();
  utils::WaitForSingleObject complete;
  std::string result;
  [[maybe_unused]] auto subscriber_0 = createSubscriber<0ul, 0ul, std::string>(
      manager, false, [&](auto, auto value) {
        result += value;
        manager->notify(1ul, std::string("t"));
      });
  [[maybe_unused]] auto subscriber_1 = createSubscriber<1ul, 1ul, std::string>(
      manager, false, [&](auto, auto value) {
        result += value;
        manager->notify(2ul, std::string("a"));
      });
  [[maybe_unused]] auto subscriber_2 = createSubscriber<2ul, 2ul, std::string>(
      manager, false, [&](auto, auto value) {
        result += value;
        manager->notify(3ul, std::string("r"));
      });
  [[maybe_unused]] auto subscriber_3 = createSubscriber<3ul, 3ul, std::string>(
      manager, false, [&](auto, auto value) {
        result += value;
        manager->notify(4ul, std::string("!"));
      });
  [[maybe_unused]] auto subscriber_4 = createSubscriber<4ul, 4ul, std::string>(
      manager, false, [&](auto, auto value) {
        result += value;
        std::cout << "4" << std::endl;
        complete.set();
      });

  manager->notify(0ul, std::string("S"));
  ASSERT_TRUE(complete.wait(std::chrono::seconds(10ull)));

  ASSERT_EQ(result, "Star!");
}

/**
 * @given subscription engine
 * @when 2 subscribers are present
 * @and the first make unsubscribe
 * @then his handler must be skipped
 */
TEST_F(SubscriptionTest, UnsubExecutionTest) {
  auto manager = createSubscriptionManager<1>();
  utils::WaitForSingleObject complete;

  [[maybe_unused]] auto subscriber_0 = createSubscriber<0ul, 0ul, bool>(
      manager, false, [&](auto, auto) {
        ASSERT_FALSE("Must not be called!");
      });
  [[maybe_unused]] auto subscriber_1 = createSubscriber<0ul, 0ul, bool>(
      manager, false, [&](auto, auto) {
        complete.set();
      });

  subscriber_0->unsubscribe();
  manager->notify(0ul, false);
  ASSERT_TRUE(complete.wait(std::chrono::seconds(10ull)));
}

/**
 * @given subscription engine
 * @when 2 subscribers are present
 * @and the first make unsubscribe
 * @then his handler must be skipped
 */
TEST_F(SubscriptionTest, UnsubExecutionTest_1) {
  auto manager = createSubscriptionManager<1>();
  utils::WaitForSingleObject complete;

  [[maybe_unused]] auto subscriber_0 = createSubscriber<0ul, 0ul, bool>(
      manager, false, [&](auto, auto) {
        ASSERT_FALSE("Must not be called!");
      });
  [[maybe_unused]] auto subscriber_1 = createSubscriber<0ul, 0ul, bool>(
      manager, false, [&](auto, auto) {
        complete.set();
      });

  subscriber_0->unsubscribe(0ul);
  manager->notify(0ul, false);
  ASSERT_TRUE(complete.wait(std::chrono::seconds(10ull)));
}

/**
 * @given subscription engine
 * @when 2 subscribers are present
 * @and the first make unsubscribe
 * @then his handler must be skipped
 */
TEST_F(SubscriptionTest, UnsubExecutionTest_2) {
  auto manager = createSubscriptionManager<1>();
  utils::WaitForSingleObject complete;

  [[maybe_unused]] auto subscriber_0 = createSubscriber<0ul, 1ul, bool>(
      manager, false, [&](auto, auto) {
        ASSERT_FALSE("Must not be called!");
      });
  [[maybe_unused]] auto subscriber_1 = createSubscriber<0ul, 1ul, bool>(
      manager, false, [&](auto, auto) {
        complete.set();
      });

  subscriber_0->unsubscribe(0ul, 1ul);
  manager->notify(1ul, false);
  ASSERT_TRUE(complete.wait(std::chrono::seconds(10ull)));
}

/**
 * @given subscription engine
 * @when 2 subscribers are present
 * @and the first make unsubscribe from events he wasn't been subscribed
 * @then his handler must called, because he is still subscribed
 */
TEST_F(SubscriptionTest, UnsubExecutionTest_3) {
  auto manager = createSubscriptionManager<1>();
  utils::WaitForSingleObject complete;

  std::atomic_flag flag;
  flag.clear();

  [[maybe_unused]] auto subscriber_0 = createSubscriber<0ul, 1ul, bool>(
      manager, false, [&](auto, auto) {
        flag.test_and_set();
      });
  [[maybe_unused]] auto subscriber_1 = createSubscriber<0ul, 1ul, bool>(
      manager, false, [&](auto, auto) {
        complete.set();
      });

  subscriber_0->unsubscribe(1ul);
  subscriber_0->unsubscribe(0ul, 2ul);
  manager->notify(1ul, false);
  ASSERT_TRUE(complete.wait(std::chrono::seconds(10ull)));
  ASSERT_TRUE(flag.test_and_set());
}

/**
 * @given subscription engine
 * @when 2 subscribers are present
 * @and the first make unsubscribe from events he wasn't been subscribed
 * @then his handler must called, because he is still subscribed
 */
TEST_F(SubscriptionTest, Notify) {
  auto dispatcher = createDispatcher();
  auto engine = createTestEngine(dispatcher);
  auto subscriber = createMockSubscriber(engine);

  std::string test_data("test_data");
  uint32_t event_id = 10ul;

  subscriber->subscribe<1ull>(event_id);
  EXPECT_CALL(*subscriber, on_notify(0ull, event_id, std::string(test_data)))
      .Times(1);
  engine->notify(event_id, test_data);
}