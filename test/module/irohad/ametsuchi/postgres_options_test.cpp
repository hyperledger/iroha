/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_options.hpp"

#include <gtest/gtest.h>
#include "framework/test_logger.hpp"
#include "logger/logger_manager.hpp"

using namespace iroha::ametsuchi;

static const logger::LoggerPtr test_log =
    getTestLoggerManager()->getChild("PostgresOptions")->getLogger();

static const std::string default_dbname{"default_dbname"};

/**
 * @given pg_opt string with param1, param2 and dbname
 * @when PostgresOptions object is created from given pg_opt string
 * @then PostgresOptions contains dbname with
 * AND optionsString is equal to given pg_opt string
 * AND optionsStringWithoutDbName is equal to pg_opt string without dbname param
 */
TEST(PostgresOptionsTest, DBnameParamExist) {
  std::string dbname = "irohadb";
  std::string pg_opt_string = "param1=val1 dbname=" + dbname + " param2=val2";
  auto pg_opt = PostgresOptions(pg_opt_string, default_dbname, test_log);

  EXPECT_EQ(pg_opt.dbname(), dbname);
  EXPECT_EQ(pg_opt.optionsString(), pg_opt_string);
  EXPECT_EQ(pg_opt.optionsStringWithoutDbName(), "param1=val1 param2=val2");
}

/**
 * @given pg_opt string param1 and param2
 * @when PostgresOptions object is created from given pg_opt string
 * @then PostgresOptions does not contain dbname
 * AND optionsString equals to given pg_opt string
 * AND optionsStringWithoutDbName also equal pg_opt string
 */
TEST(PostgresOptionsTest, DBnameParamNotExist) {
  std::string pg_opt_string = "param1=val1 param2=val2";
  auto pg_opt = PostgresOptions(pg_opt_string, default_dbname, test_log);

  EXPECT_EQ(pg_opt.dbname(), default_dbname);
  EXPECT_EQ(pg_opt.optionsString(), pg_opt_string);
  EXPECT_EQ(pg_opt.optionsStringWithoutDbName(), pg_opt_string);
}
