/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_options.hpp"

#include <gtest/gtest.h>

using namespace iroha::ametsuchi;

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
  auto pg_opt = PostgresOptions(pg_opt_string);

  auto obtained_dbname = pg_opt.dbname();
  ASSERT_TRUE(obtained_dbname);
  ASSERT_EQ(obtained_dbname.value(), dbname);
  ASSERT_EQ(pg_opt.optionsString(), pg_opt_string);
  ASSERT_EQ(pg_opt.optionsStringWithoutDbName(), "param1=val1 param2=val2");
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
  auto pg_opt = PostgresOptions(pg_opt_string);

  auto obtained_dbname = pg_opt.dbname();
  ASSERT_FALSE(obtained_dbname);
  ASSERT_EQ(pg_opt.optionsString(), pg_opt_string);
  ASSERT_EQ(pg_opt.optionsStringWithoutDbName(), pg_opt_string);
}
