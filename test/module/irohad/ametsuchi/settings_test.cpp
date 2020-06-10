/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_setting_query.hpp"

#include <gmock/gmock.h>
#include "ametsuchi/impl/postgres_specific_query_executor.hpp"
#include "framework/result_fixture.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "framework/test_logger.hpp"
#include "interfaces/iroha_internal/query_response_factory.hpp"
#include "module/irohad/ametsuchi/ametsuchi_fixture.hpp"
#include "module/shared_model/interface_mocks.hpp"
#include "module/shared_model/mock_objects_factories/mock_command_factory.hpp"

namespace iroha {
  namespace ametsuchi {
    using namespace framework::expected;

    class SettingsTest : public AmetsuchiTest {
     public:
      void SetUp() override {
        AmetsuchiTest::SetUp();

        executor = std::make_unique<PostgresCommandExecutor>(
            std::make_unique<soci::session>(*soci::factory_postgresql(),
                                            pgopt_),
            perm_converter,
            std::make_shared<PostgresSpecificQueryExecutor>(
                *sql,
                *block_storage_,
                std::make_shared<MockPendingTransactionStorage>(),
                std::make_shared<
                    shared_model::proto::ProtoQueryResponseFactory>(),
                perm_converter,
                getTestLoggerManager()
                    ->getChild("SpecificQueryExecutor")
                    ->getLogger()),
            std::nullopt);

        setting_query = std::make_unique<PostgresSettingQuery>(
            std::make_unique<soci::session>(*soci::factory_postgresql(),
                                            pgopt_),
            getTestLogger("SettingQuery"));
      }

      /**
       * Execute a given command and optionally check its result
       * @tparam CommandType - type of the command
       * @param command - the command to CHECK_SUCCESSFUL_RESULT(execute
       * @param do_validation - of the command should be validated
       * @param creator - creator of the command
       * @return result of command execution
       */
      template <typename CommandType>
      CommandResult execute(CommandType &&command,
                            bool do_validation = false,
                            const shared_model::interface::types::AccountIdType
                                &creator = "id@domain") {
        // TODO igor-egorov 15.04.2019 IR-446 Refactor postgres_executor_test
        shared_model::interface::Command::CommandVariantType variant{
            std::forward<CommandType>(command)};
        shared_model::interface::MockCommand cmd;
        EXPECT_CALL(cmd, get()).WillRepeatedly(::testing::ReturnRef(variant));
        return executor->execute(cmd, creator, {}, 0, not do_validation);
      }

      void TearDown() override {
        AmetsuchiTest::TearDown();
      }

      std::unique_ptr<CommandExecutor> executor;
      std::shared_ptr<shared_model::interface::PermissionToString>
          perm_converter =
              std::make_shared<shared_model::proto::ProtoPermissionToString>();

      std::unique_ptr<SettingQuery> setting_query;
      std::unique_ptr<shared_model::interface::MockCommandFactory>
          mock_command_factory =
              std::make_unique<shared_model::interface::MockCommandFactory>();
    };

    /**
     * @given settings
     * @when trying to get setting with the key that doesn't exist
     * @then settings return default value
     */
    TEST_F(SettingsTest, NoSuchSetting) {
      auto result = setting_query->get();
      IROHA_ASSERT_RESULT_VALUE(result);

      auto settings = std::move(val(result).value().value);
      ASSERT_EQ(settings->max_description_size,
                shared_model::validation::kDefaultDescriptionSize);
    }

    /**
     * @given settings
     * @when trying to get setting with the key that has invalid value
     * @then settings return default value
     */
    TEST_F(SettingsTest, InvalidSettingValue) {
      std::string value = "two";
      execute(*mock_command_factory->constructSetSettingValue(
                  iroha::ametsuchi::kMaxDescriptionSizeKey, value),
              true);

      ASSERT_TRUE(expected::hasError(setting_query->get()));
    }

    /**
     * @given settings
     * @when trying to get setting
     * @then settings return custom value
     */
    TEST_F(SettingsTest, ValidSettingValue) {
      std::string value = "255";
      execute(*mock_command_factory->constructSetSettingValue(
                  iroha::ametsuchi::kMaxDescriptionSizeKey, value),
              true);

      auto result = setting_query->get();
      IROHA_ASSERT_RESULT_VALUE(result);
      auto settings = std::move(val(result).value().value);
      ASSERT_EQ(settings->max_description_size, 255);
    }

  }  // namespace ametsuchi
}  // namespace iroha
