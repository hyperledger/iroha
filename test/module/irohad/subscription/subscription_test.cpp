/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/subscription.hpp"

#include <gtest/gtest.h>
#include <atomic>
#include <vector>

#include "module/irohad/subscription/subscription_mocks.hpp"
#include "subscription/async_dispatcher_impl.hpp"

using namespace iroha;

class SubscriptionTest : public ::testing::Test {
 public:
  template <uint32_t ThreadsCount>
  auto createSubscriptionManager() {
    using Manager = subscription::SubscriptionManager<ThreadsCount, 1u>;
    return std::make_shared<Manager>(
        std::make_shared<subscription::AsyncDispatcher<ThreadsCount, 1u>>());
  }

  template <uint64_t Event,
            typename EventData,
            typename ObjectType,
            typename Manager,
            typename F>
  auto createSubscriber(uint32_t Tid,
                        std::shared_ptr<Manager> const &manager,
                        ObjectType &&initial,
                        F &&f) {
    using Dispatcher = typename Manager::Dispatcher;
    using Subscriber = subscription::
        SubscriberImpl<uint64_t, Dispatcher, ObjectType, EventData>;

    auto subscriber = Subscriber::create(
        manager->template getEngine<uint64_t, EventData>(), std::move(initial));

    subscriber->setCallback(
        [f(std::forward<F>(f))](
            auto, ObjectType &obj, uint64_t key, EventData data) mutable {
          ASSERT_EQ(key, Event);
          std::forward<F>(f)(obj, std::move(data));
        });
    subscriber->subscribe(0, Event, Tid);
    return subscriber;
  }

  using MockDispatcher = subscription::MockDispatcher;
  using MockSubscriber =
      subscription::MockSubscriber<uint32_t, MockDispatcher, std::string>;
  using TestEngine = subscription::SubscriptionEngine<
      uint32_t,
      MockDispatcher,
      subscription::Subscriber<uint32_t, MockDispatcher, std::string>>;

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

struct StatusTrackTest {
  StatusTrackTest() = default;
  StatusTrackTest &operator=(StatusTrackTest const &) {
    throw std::runtime_error("Unexpected copy call.");
  }
  StatusTrackTest(StatusTrackTest const &) {
    throw std::runtime_error("Unexpected copy call.");
  }
  StatusTrackTest(StatusTrackTest &&) = default;
  StatusTrackTest &operator=(StatusTrackTest &&) = default;
};

/**
 * @given subscription engine
 * @when put task that must repeat N times
 * @then task must NOT be copied
 */
TEST_F(SubscriptionTest, RepeatCopyControl) {
  auto manager = createSubscriptionManager<1>();
  utils::WaitForSingleObject complete;

  std::atomic<uint32_t> counter = 0ul;
  std::atomic<bool> work = true;

  StatusTrackTest t;
  manager->dispatcher()->repeat(
      0ull,
      std::chrono::milliseconds(0),
      [&work, &counter, t(std::move(t))]() {
        ++counter;
        if (!work)
          throw std::runtime_error("Unexpected execution.");
      },
      [&]() {
        if (counter.load() < 5ul)
          return true;

        work = false;
        complete.set();
        return false;
      });

  ASSERT_TRUE(complete.wait(std::chrono::minutes(1ull)));
  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  ASSERT_TRUE(counter.load() == 5ul);
  manager->dispose();
}

/**
 * @given subscription engine
 * @when put task that must repeat untill counter less than 10
 * @and check it in predicate
 * @then task must be executed 10 times
 */
TEST_F(SubscriptionTest, RepeatCounter) {
  auto manager = createSubscriptionManager<1>();
  utils::WaitForSingleObject complete;

  std::atomic<uint32_t> counter = 0ul;
  std::atomic<bool> work = true;

  manager->dispatcher()->repeat(
      0ull,
      std::chrono::microseconds(0),
      [&]() {
        ++counter;
        if (!work)
          throw std::runtime_error("Unexpected execution.");
      },
      [&]() {
        if (counter.load() < 10ul)
          return true;

        work = false;
        complete.set();
        return false;
      });

  ASSERT_TRUE(complete.wait(std::chrono::minutes(1ull)));
  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  ASSERT_TRUE(counter.load() == 10ul);
  manager->dispose();
}

/**
 * @given subscription engine
 * @when put task that must repeat without predicate check
 * @then this task must be executed 1 time
 */
TEST_F(SubscriptionTest, RepeatNoPredicate) {
  auto manager = createSubscriptionManager<1>();
  utils::WaitForSingleObject complete;

  std::atomic<uint32_t> counter = 0ul;
  manager->dispatcher()->repeat(0ull,
                                std::chrono::microseconds(0),
                                [&]() {
                                  ++counter;
                                  complete.set();
                                },
                                nullptr);

  ASSERT_TRUE(complete.wait(std::chrono::minutes(1ull)));
  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  ASSERT_TRUE(counter.load() == 1ul);
  manager->dispose();
}

/**
 * @given subscription engine
 * @when put task that must repeat N times with 10ms delay untill counter less
 * than 5
 * @and check it in predicate
 * @then task must be executed 5 times and spent not less than 50ms on it
 */
TEST_F(SubscriptionTest, RepeatNTimes) {
  auto manager = createSubscriptionManager<1>();
  utils::WaitForSingleObject complete;

  std::atomic<uint32_t> counter = 0ul;
  std::atomic<bool> work = true;

  auto const start = std::chrono::high_resolution_clock::now();
  manager->dispatcher()->repeat(
      0ull,
      std::chrono::milliseconds(10),
      [&]() {
        ++counter;
        if (!work)
          throw std::runtime_error("Unexpected execution.");
      },
      [&]() {
        if (counter.load() < 5ul)
          return true;

        work = false;
        complete.set();
        return false;
      });

  ASSERT_TRUE(complete.wait(std::chrono::minutes(1ull)));
  auto const end = std::chrono::high_resolution_clock::now();
  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  auto const elapsed =
      std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

  ASSERT_TRUE(elapsed >= std::chrono::milliseconds(50));
  ASSERT_TRUE(counter.load() == 5ul);
  manager->dispose();
}

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
  auto subscriber = createSubscriber<1ull, std::string>(
      0ul, manager, false, [&complete, test_value](auto, std::string value) {
        ASSERT_EQ(test_value, value);
        complete.set();
      });

  manager->notify(1ull, test_value);
  ASSERT_TRUE(complete.wait(std::chrono::minutes(1ull)));

  manager->dispose();
}

/**
 * @given subscription engine
 * @when subscriber is present in pool threads
 * @and notification is called
 * @then subscriber must receive correct data from notification
 */
TEST_F(SubscriptionTest, PoolSimpleExecutionTest) {
  auto manager = createSubscriptionManager<1>();
  utils::WaitForSingleObject complete;

  std::string test_value = "the fast and the furious";
  auto subscriber = createSubscriber<1ull, std::string>(
      std::numeric_limits<uint32_t>::max(),
      manager,
      false,
      [&complete, test_value](auto, std::string value) {
        ASSERT_EQ(test_value, value);
        complete.set();
      });

  manager->notify(1ull, test_value);
  ASSERT_TRUE(complete.wait(std::chrono::minutes(1ull)));

  manager->dispose();
}

/**
 * @given subscription engine with busy pool
 * @when subscriber is present in pool threads
 * @and notification is called
 * @then subscriber must receive correct data from notification
 */
TEST_F(SubscriptionTest, BusyPoolSimpleExecutionTest) {
  auto manager = createSubscriptionManager<1>();

  utils::WaitForSingleObject complete;
  utils::WaitForSingleObject complete1;
  auto subscriber1 =
      createSubscriber<1ull, bool>(std::numeric_limits<uint32_t>::max(),
                                   manager,
                                   false,
                                   [&complete, &complete1](auto, auto) {
                                     complete1.set();
                                     complete.wait();
                                     complete.set();
                                   });

  std::string test_value = "the fast and the furious";
  auto subscriber2 = createSubscriber<2ull, std::string>(
      std::numeric_limits<uint32_t>::max(),
      manager,
      false,
      [&complete, test_value](auto, std::string value) {
        ASSERT_EQ(test_value, value);
        complete.set();
      });

  manager->notify(1ull, false);
  complete1.wait();
  manager->notify(2ull, test_value);

  ASSERT_TRUE(complete.wait(std::chrono::minutes(1ull)));
  complete.set();
  manager->dispose();
}

/**
 * @given subscription engine
 * @when 2 subscribers are present
 * @and they subscribe to a single event in a single thread
 * @then they must be called in the same order
 */
TEST_F(SubscriptionTest, DoubleExecutionTest) {
  auto manager = createSubscriptionManager<1>();
  utils::WaitForSingleObject complete;

  uint32_t counter = 0ul;
  std::string test_value = "the fast and the furious";
  auto subscriber_1 = createSubscriber<1ull, std::string>(
      0ul, manager, false, [&counter, test_value](auto, std::string value) {
        ASSERT_EQ(test_value, value);
        ASSERT_EQ(counter, 0ul);
        ++counter;
      });

  auto subscriber_2 = createSubscriber<1ull, std::string>(
      0ul,
      manager,
      false,
      [&complete, &counter, test_value](auto, std::string value) {
        ASSERT_EQ(test_value, value);
        ASSERT_EQ(counter, 1ul);
        complete.set();
      });

  manager->notify(1ull, test_value);
  ASSERT_TRUE(complete.wait(std::chrono::minutes(1ull)));

  manager->dispose();
}

/**
 * @given subscription engine
 * @when 2 subscribers are present
 * @and they subscribe to different events in a single thread
 * @and both events are notified
 * @then the handlers of each subscriber must be called once
 */
TEST_F(SubscriptionTest, XExecutionTest) {
  auto manager = createSubscriptionManager<1>();
  utils::WaitForSingleObject complete[2];
  uint32_t counter[2] = {0ul};

  [[maybe_unused]] auto subscriber_1 =
      createSubscriber<1ull, bool>(0ul, manager, false, [&](auto, auto) {
        ASSERT_EQ(counter[0], 0ul);
        ++counter[0];
        complete[0].set();
      });

  [[maybe_unused]] auto subscriber_2 =
      createSubscriber<2ull, bool>(0ul, manager, false, [&](auto, auto) {
        ASSERT_EQ(counter[1], 0ul);
        ++counter[1];
        complete[1].set();
      });

  manager->notify(1ull, false);
  manager->notify(2ull, false);
  ASSERT_TRUE(complete[0].wait(std::chrono::minutes(1ull)));
  ASSERT_TRUE(complete[1].wait(std::chrono::minutes(1ull)));

  ASSERT_EQ(counter[0], 1ul);
  ASSERT_EQ(counter[1], 1ul);

  manager->dispose();
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

  using SharedObject =
      utils::ReadWriteObject<std::map<std::thread::id, uint32_t>>;
  using SharedObjectRef = std::reference_wrapper<SharedObject>;

  SharedObject shared_object;

  [[maybe_unused]] auto subscriber_0 = createSubscriber<1ull, bool>(
      0ul,
      manager,
      SharedObjectRef(shared_object),
      [&](SharedObjectRef object, auto) {
        object.get().exclusiveAccess(
            [](auto &data) { ++data[std::this_thread::get_id()]; });
        complete[0].set();
      });
  [[maybe_unused]] auto subscriber_1 = createSubscriber<1ull, bool>(
      1ul,
      manager,
      SharedObjectRef(shared_object),
      [&](SharedObjectRef object, auto) {
        object.get().exclusiveAccess(
            [](auto &data) { ++data[std::this_thread::get_id()]; });
        complete[1].set();
      });
  [[maybe_unused]] auto subscriber_2 = createSubscriber<1ull, bool>(
      2ul,
      manager,
      SharedObjectRef(shared_object),
      [&](SharedObjectRef object, auto) {
        object.get().exclusiveAccess(
            [](auto &data) { ++data[std::this_thread::get_id()]; });
        complete[2].set();
      });
  [[maybe_unused]] auto subscriber_3 = createSubscriber<1ull, bool>(
      3ul,
      manager,
      SharedObjectRef(shared_object),
      [&](SharedObjectRef object, auto) {
        object.get().exclusiveAccess(
            [](auto &data) { ++data[std::this_thread::get_id()]; });
        complete[3].set();
      });

  manager->notify(1ull, false);
  for (auto &c : complete) ASSERT_TRUE(c.wait(std::chrono::minutes(1ull)));

  shared_object.sharedAccess([](auto const &values) {
    ASSERT_EQ(values.size(), 4ull);
    for (auto &value : values) ASSERT_TRUE(value.second == 1);
  });

  manager->dispose();
}

/**
 * @given subscription engine
 * @when 2 subscribers are present
 * @and they subscribe to different events in a different threads
 * @and each of them generate event for the other
 * @then each handler must be called one by one
 */
TEST_F(SubscriptionTest, PingPongExecutionTest) {
  auto manager = createSubscriptionManager<2>();
  utils::WaitForSingleObject complete;

  [[maybe_unused]] auto subscriber_0 =
      createSubscriber<0ull, uint32_t, uint32_t>(
          0ul, manager, 0ul, [&](uint32_t &obj, uint32_t value) {
            obj = value;
            manager->notify<uint64_t, uint32_t>(1ull, value + 7ul);
          });
  [[maybe_unused]] auto subscriber_1 =
      createSubscriber<1ull, uint32_t, uint32_t>(
          1ul, manager, 0ul, [&](uint32_t &obj, uint32_t value) {
            obj = value;
            if (value > 40ul)
              complete.set();
            else
              manager->notify<uint64_t, uint32_t>(0ull, (value << 1ul));
          });

  manager->notify<uint64_t, uint32_t>(0ull, 0ul);
  ASSERT_TRUE(complete.wait(std::chrono::minutes(1ull)));
  ASSERT_EQ(subscriber_0->get(), 42ul);
  ASSERT_EQ(subscriber_1->get(), 49ul);

  manager->dispose();
}

/**
 * @given subscription engine
 * @when 3 subscribers are present
 * @and they subscribe on a single event
 * @and this event notifies several times in order A-B-C
 * @then no rotation is present: first all handlers will process A, then B, then
 * C
 */
TEST_F(SubscriptionTest, RotationExecutionTest_1) {
  auto manager = createSubscriptionManager<1>();

  std::atomic<uint32_t> counter = 0;
  std::string result;
  [[maybe_unused]] auto subscriber_0 = createSubscriber<0ull, std::string>(
      0ul, manager, false, [&](auto, std::string value) {
        result += value;
        ++counter;
      });
  [[maybe_unused]] auto subscriber_1 = createSubscriber<0ull, std::string>(
      0ul, manager, false, [&](auto, std::string value) {
        result += value;
        ++counter;
      });
  [[maybe_unused]] auto subscriber_2 = createSubscriber<0ull, std::string>(
      0ul, manager, false, [&](auto, std::string value) {
        result += value;
        ++counter;
      });

  manager->notify(0ull, std::string("A"));
  manager->notify(0ull, std::string("B"));
  manager->notify(0ull, std::string("C"));

  while (counter.load(std::memory_order_relaxed) < 9)
    std::this_thread::sleep_for(std::chrono::milliseconds(1ull));

  ASSERT_EQ(result, "AAABBBCCC");
  manager->dispose();
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
  [[maybe_unused]] auto subscriber_0 =
      createSubscriber<0ull, bool>(0ul, manager, false, [&](auto, auto value) {
        result += 'A';
        ++counter;
      });
  [[maybe_unused]] auto subscriber_1 =
      createSubscriber<0ull, bool>(0ul, manager, false, [&](auto, auto value) {
        result += 'B';
        ++counter;
      });
  [[maybe_unused]] auto subscriber_2 =
      createSubscriber<0ull, bool>(0ul, manager, false, [&](auto, auto value) {
        result += 'C';
        ++counter;
      });

  manager->notify(0ull, false);
  manager->notify(0ull, false);
  manager->notify(0ull, false);

  while (counter.load(std::memory_order_relaxed) < 9)
    std::this_thread::sleep_for(std::chrono::milliseconds(1ull));

  ASSERT_EQ(result, "ABCABCABC");
  manager->dispose();
}

/**
 * @given subscription engine
 * @when subscriber is present
 * @and notifications are generated with delay
 * @then the handlers must be called in a delay order
 */
TEST_F(SubscriptionTest, RotationExecutionTest_3) {
  auto manager = createSubscriptionManager<1>();

  std::atomic<uint32_t> counter = 0;
  std::string result;
  [[maybe_unused]] auto subscriber_0 = createSubscriber<0ull, std::string>(
      0ul, manager, false, [&](auto, auto value) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5ull));
        result += value;
        ++counter;
      });

  manager->notifyDelayed(
      std::chrono::milliseconds(100ull), 0ull, std::string("E"));
  manager->notifyDelayed(
      std::chrono::milliseconds(30ull), 0ull, std::string("C"));
  manager->notifyDelayed(
      std::chrono::milliseconds(50ull), 0ull, std::string("D"));
  manager->notify(0ull, std::string("A"));
  manager->notify(0ull, std::string("B"));

  while (counter.load(std::memory_order_relaxed) < 5)
    std::this_thread::sleep_for(std::chrono::milliseconds(10ull));

  ASSERT_EQ(result, "ABCDE");
  manager->dispose();
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
  [[maybe_unused]] auto subscriber_0 = createSubscriber<0ull, std::string>(
      0ul, manager, false, [&](auto, auto value) {
        result += value;
        manager->notify(1ull, std::string("t"));
      });
  [[maybe_unused]] auto subscriber_1 = createSubscriber<1ull, std::string>(
      1ul, manager, false, [&](auto, auto value) {
        result += value;
        manager->notify(2ull, std::string("a"));
      });
  [[maybe_unused]] auto subscriber_2 = createSubscriber<2ull, std::string>(
      2ul, manager, false, [&](auto, auto value) {
        result += value;
        manager->notify(3ull, std::string("r"));
      });
  [[maybe_unused]] auto subscriber_3 = createSubscriber<3ull, std::string>(
      3ul, manager, false, [&](auto, auto value) {
        result += value;
        manager->notify(4ull, std::string("!"));
      });
  [[maybe_unused]] auto subscriber_4 = createSubscriber<4ull, std::string>(
      4ul, manager, false, [&](auto, auto value) {
        result += value;
        complete.set();
      });

  manager->notify(0ull, std::string("S"));
  ASSERT_TRUE(complete.wait(std::chrono::seconds(10ull)));

  ASSERT_EQ(result, "Star!");
  manager->dispose();
}

/**
 * @given subscription engine
 * @when 2 subscribers are present
 * @and the first unsubscribes from all events
 * @then his handler must be skipped
 */
TEST_F(SubscriptionTest, UnsubExecutionTest) {
  auto manager = createSubscriptionManager<1>();
  utils::WaitForSingleObject complete;

  [[maybe_unused]] auto subscriber_0 =
      createSubscriber<0ull, bool>(0ul, manager, false, [&](auto, auto) {
        ASSERT_FALSE("Must not be called!");
      });
  [[maybe_unused]] auto subscriber_1 = createSubscriber<0ull, bool>(
      0ul, manager, false, [&](auto, auto) { complete.set(); });

  subscriber_0->unsubscribe();
  manager->notify(0ull, false);
  ASSERT_TRUE(complete.wait(std::chrono::seconds(10ull)));
  manager->dispose();
}

/**
 * @given subscription engine
 * @when 2 subscribers are present
 * @and the first unsubscribes from a specific set
 * @then his handler must be skipped
 */
TEST_F(SubscriptionTest, UnsubExecutionTest_1) {
  auto manager = createSubscriptionManager<1>();
  utils::WaitForSingleObject complete;

  [[maybe_unused]] auto subscriber_0 =
      createSubscriber<0ull, bool>(0ul, manager, false, [&](auto, auto) {
        ASSERT_FALSE("Must not be called!");
      });
  [[maybe_unused]] auto subscriber_1 = createSubscriber<0ull, bool>(
      0ul, manager, false, [&](auto, auto) { complete.set(); });

  subscriber_0->unsubscribe(0ul);
  manager->notify(0ull, false);
  ASSERT_TRUE(complete.wait(std::chrono::seconds(10ull)));
  manager->dispose();
}

/**
 * @given subscription engine
 * @when 2 subscribers are present
 * @and the first unsubscribes from a specific set and event
 * @then his handler must be skipped
 */
TEST_F(SubscriptionTest, UnsubExecutionTest_2) {
  auto manager = createSubscriptionManager<1>();
  utils::WaitForSingleObject complete;

  [[maybe_unused]] auto subscriber_0 =
      createSubscriber<1ull, bool>(0ul, manager, false, [&](auto, auto) {
        ASSERT_FALSE("Must not be called!");
      });
  [[maybe_unused]] auto subscriber_1 = createSubscriber<1ull, bool>(
      0ul, manager, false, [&](auto, auto) { complete.set(); });

  subscriber_0->unsubscribe(0ul, 1ull);
  manager->notify(1ull, false);
  ASSERT_TRUE(complete.wait(std::chrono::seconds(10ull)));
  manager->dispose();
}

/**
 * @given subscription engine
 * @when 2 subscribers are present
 * @and the first unsubscribes from events he didn't subscribe to
 * @then his handler must be called, because he is still subscribed
 */
TEST_F(SubscriptionTest, UnsubExecutionTest_3) {
  auto manager = createSubscriptionManager<1>();
  utils::WaitForSingleObject complete;

  std::atomic_flag flag;
  flag.clear();

  [[maybe_unused]] auto subscriber_0 = createSubscriber<1ull, bool>(
      0ul, manager, false, [&](auto, auto) { flag.test_and_set(); });
  [[maybe_unused]] auto subscriber_1 = createSubscriber<1ull, bool>(
      0ul, manager, false, [&](auto, auto) { complete.set(); });

  subscriber_0->unsubscribe(1ul);
  subscriber_0->unsubscribe(0ul, 2ull);
  manager->notify(1ull, false);
  ASSERT_TRUE(complete.wait(std::chrono::seconds(10ull)));
  ASSERT_TRUE(flag.test_and_set());
  manager->dispose();
}

/**
 * @given subscription engine
 * @when subscriber is present by a notification type 1
 * @and this notification takes place
 * @then his handler must be called
 */
TEST_F(SubscriptionTest, Notify) {
  auto dispatcher = createDispatcher();
  auto engine = createTestEngine(dispatcher);
  auto subscriber = createMockSubscriber(engine);

  std::string test_data("test_data");
  uint32_t event_id = 10ul;

  subscriber->subscribe(1u, event_id);
  EXPECT_CALL(*subscriber, on_notify(0ull, event_id, std::string(test_data)))
      .Times(1);
  engine->notify(event_id, test_data);
}

/**
 * @given subscription engine
 * @when subscriber is present by a notification type 1
 * @and this notification takes place with delay
 * @then his handler must be called
 */
TEST_F(SubscriptionTest, NotifyDelayed) {
  auto dispatcher = createDispatcher();
  auto engine = createTestEngine(dispatcher);
  auto subscriber = createMockSubscriber(engine);

  std::string test_data("test_data");
  uint32_t event_id = 10ul;

  subscriber->subscribe(1u, event_id);
  EXPECT_CALL(*subscriber, on_notify(0ull, event_id, std::string(test_data)))
      .Times(1);
  engine->notifyDelayed(std::chrono::microseconds(10ull), event_id, test_data);
}

/**
 * @given subscription engine
 * @when subscribers are present by notification types 1 and 2
 * @and this notification 1 takes place
 * @then only 1 subscriber must be executed
 */
TEST_F(SubscriptionTest, Notify_1) {
  auto dispatcher = createDispatcher();
  auto engine = createTestEngine(dispatcher);
  auto subscriber1 = createMockSubscriber(engine);
  auto subscriber2 = createMockSubscriber(engine);

  std::string test_data("test_data");
  uint32_t event_id = 10ul;
  uint32_t event_id_fake = 11ul;

  subscriber1->subscribe(1u, event_id);
  subscriber2->subscribe(1u, event_id_fake);

  EXPECT_CALL(*subscriber1, on_notify(0ull, event_id, std::string(test_data)))
      .Times(1);
  EXPECT_CALL(*subscriber2,
              on_notify(0ull, event_id_fake, std::string(test_data)))
      .Times(0);
  engine->notify(event_id, test_data);
}

/**
 * @given subscription engine
 * @when subscribers are present by the same notification
 * @and this notification takes place
 * @then both of the subscribers must be executed
 */
TEST_F(SubscriptionTest, Notify_2) {
  auto dispatcher = createDispatcher();
  auto engine = createTestEngine(dispatcher);
  auto subscriber1 = createMockSubscriber(engine);
  auto subscriber2 = createMockSubscriber(engine);

  std::string test_data("test_data");
  uint32_t event_id = 10ul;

  subscriber1->subscribe(1u, event_id);
  subscriber2->subscribe(1u, event_id);

  EXPECT_CALL(*subscriber1, on_notify(0ull, event_id, std::string(test_data)))
      .Times(1);
  EXPECT_CALL(*subscriber2, on_notify(0ull, event_id, std::string(test_data)))
      .Times(1);
  engine->notify(event_id, test_data);
}

/**
 * @given subscription engine and scheduler
 * @when 2 subscribers are present
 * @and they subscribe to different events in a single current scheduler
 * @and both events are notified followed by dispose and process
 * @then the fist handler must be called once and process finish
 * its loop
 */
TEST_F(SubscriptionTest, InThreadDispatcherTest) {
  auto manager = createSubscriptionManager<1>();
  auto scheduler = std::make_shared<subscription::SchedulerBase>();

  auto const current_thread_id = std::this_thread::get_id();
  auto tid = manager->dispatcher()->bind(scheduler);
  ASSERT_TRUE(tid);

  uint32_t counter[2] = {0ul};

  [[maybe_unused]] auto subscriber_2 =
      createSubscriber<2ull, bool>(*tid, manager, false, [&](auto, auto) {
        ASSERT_EQ(counter[0], 1ul);
        ASSERT_EQ(counter[1], 0ul);
        ASSERT_EQ(current_thread_id, std::this_thread::get_id());
        ++counter[1];
      });

  [[maybe_unused]] auto subscriber_1 =
      createSubscriber<1ull, bool>(*tid, manager, false, [&](auto, auto) {
        ASSERT_EQ(counter[0], 0ul);
        ASSERT_EQ(counter[1], 0ul);
        ASSERT_EQ(current_thread_id, std::this_thread::get_id());
        ++counter[0];
      });

  manager->notify(1ull, false);
  manager->notify(2ull, false);

  scheduler->dispose();
  scheduler->process();

  ASSERT_EQ(counter[0], 1ul);
  ASSERT_EQ(counter[1], 0ul);

  manager->dispatcher()->unbind(*tid);
  manager->dispose();
}

/**
 * @given subscription engine
 * @when add tasks in dispatcher from the loop
 * @and no delay
 * @and execute in thread pool
 * @then each task will be executed in a different thread
 */
TEST_F(SubscriptionTest, ThreadPoolBalancer) {
  auto manager = createSubscriptionManager<1>();
  static constexpr size_t tests_count = 10;

  utils::ReadWriteObject<std::set<std::thread::id>> ids;
  utils::WaitForSingleObject complete[tests_count];

  for (size_t ix = 0; ix < tests_count; ++ix)
    manager->dispatcher()->add(
        subscription::IDispatcher::kExecuteInPool, [&, ix]() {
          ids.exclusiveAccess(
              [](auto &ids) { ids.insert(std::this_thread::get_id()); });
          complete[ix].set();

          for (auto &comp : complete) {
            ASSERT_TRUE(comp.wait(std::chrono::minutes(1ull)));
            comp.set();
          }
        });

  for (auto &comp : complete) {
    ASSERT_TRUE(comp.wait(std::chrono::minutes(1ull)));
    comp.set();
  }

  ids.sharedAccess([](auto const &ids) { ASSERT_EQ(ids.size(), tests_count); });
  manager->dispose();
}
