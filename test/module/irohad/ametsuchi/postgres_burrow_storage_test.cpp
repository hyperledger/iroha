/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_burrow_storage.hpp"

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

#include <gmock/gmock-matchers.h>
#include <gtest/gtest.h>
#include <soci/postgresql/soci-postgresql.h>
#include <soci/soci.h>
#include "ametsuchi/impl/soci_std_optional.hpp"
#include "ametsuchi/impl/soci_string_view.hpp"
#include "common/result.hpp"
#include "framework/call_engine_tests_common.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "framework/test_db_manager.hpp"
#include "framework/test_logger.hpp"
#include "logger/logger_manager.hpp"

using namespace std::literals;
using namespace iroha::ametsuchi;
using namespace iroha::expected;

using iroha::integration_framework::TestDbManager;

static const std::string kTxHash{"tx hash"};
static const shared_model::interface::types::CommandIndexType kCmdIdx{418};

testing::Matcher<LogData const &> logIs(LogData const &log) {
  using namespace testing;
  return AllOf(Field(&LogData::address, log.address),
               Field(&LogData::data, log.data),
               Field(&LogData::topics, UnorderedElementsAreArray(log.topics)));
}

class PostgresBurrowStorageTest : public testing::Test {
 protected:
  void checkEngineCalls() {
    size_t count = 0;
    std::string tx_hash;
    size_t cmd_index;
    *sql_ << "select "
             "    count(1)"
             "  , string_agg(tx_hash, ', ')"
             "  , sum(cmd_index) "
             "from engine_calls",
        soci::into(count), soci::into(tx_hash), soci::into(cmd_index);
    EXPECT_EQ(count, 1) << "There must be exactly 1 engine call record.";
    EXPECT_EQ(tx_hash, kTxHash);
    EXPECT_EQ(cmd_index, kCmdIdx);
  }

  std::vector<std::string> fetchTopics(size_t log_idx) {
    std::vector<std::string> topics;
    std::string topic;
    soci::statement topic_stmt = (sql_->prepare << "select topic "
                                                   "from burrow_tx_logs_topics "
                                                   "where log_idx = :log_idx",
                                  soci::into(topic),
                                  soci::use(log_idx, "log_idx"));
    topic_stmt.execute();
    while (topic_stmt.fetch()) {
      topics.emplace_back(topic);
    }
    return topics;
  }

  std::vector<LogData> fetchLogs() {
    std::vector<LogData> logs;
    size_t log_idx = 0;
    std::string address;
    std::string data;
    soci::statement log_stmt =
        (sql_->prepare << "select log_idx, address, data "
                          "from burrow_tx_logs",
         soci::into(log_idx),
         soci::into(address),
         soci::into(data));
    log_stmt.execute();
    while (log_stmt.fetch()) {
      logs.emplace_back(address, data, fetchTopics(log_idx));
    }
    return logs;
  }

  void checkLogs(std::vector<LogData> logs) {
    std::vector<testing::Matcher<LogData const &>> matchers;
    std::transform(
        logs.begin(), logs.end(), std::back_inserter(matchers), &logIs);
    EXPECT_THAT(fetchLogs(), UnorderedElementsAreArray(matchers));
  }

  Result<void, std::string> storeLog(LogData const &log) {
    std::vector<std::string_view> topics_sv;
    std::transform(log.topics.begin(),
                   log.topics.end(),
                   std::back_inserter(topics_sv),
                   [](auto const &s) { return std::string_view{s}; });
    return storage_.storeLog(log.address, log.data, topics_sv);
  }

  std::unique_ptr<TestDbManager> test_db_manager_{
      TestDbManager::createWithRandomDbName(
          1, getTestLoggerManager()->getChild("TestDbManager"))
          .assumeValue()};
  std::unique_ptr<soci::session> sql_{test_db_manager_->getSession()};
  PostgresBurrowStorage storage_{*sql_, kTxHash, kCmdIdx};
};

TEST_F(PostgresBurrowStorageTest, Store2LogsWithNoTopics) {
  // given
  const std::string addr{"mytischi"};
  const std::string data1{"achtung"};
  const std::string data2{"semki"};

  const LogData log1{addr, data1, {}};
  const LogData log2{addr, data2, {}};

  // when
  IROHA_ASSERT_RESULT_VALUE(storeLog(log1));
  IROHA_ASSERT_RESULT_VALUE(storeLog(log2));

  // then
  checkEngineCalls();
  checkLogs({log1, log2});
}

TEST_F(PostgresBurrowStorageTest, StoreLogWith3Topics) {
  // given
  const std::string addr{"mytischi"};
  const std::string data{"achtung"};
  const std::string topic1{"gop"};
  const std::string topic2{"stop"};
  const std::string topic3{"musorok"};

  const LogData log1{addr, data, {topic1, topic2, topic3}};

  // when
  IROHA_ASSERT_RESULT_VALUE(storeLog(log1));

  // then
  checkEngineCalls();
  checkLogs({log1});
}
