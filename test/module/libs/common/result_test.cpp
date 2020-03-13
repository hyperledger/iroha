/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "common/result.hpp"

#include <gtest/gtest.h>
#include "framework/result_gtest_checkers.hpp"

using namespace iroha::expected;

constexpr auto kErrorCaseMessage = "Unexpected error case";
constexpr auto kValueCaseMessage = "Unexpected value case";
constexpr auto kFirstFunctionCallMessage = "first function";
constexpr auto kErrorMessage = "error message";

// Function which returns function which when invoked, fails the test
template <typename T>
auto makeFailCase(const std::string &error_message) {
  return [&error_message](T t) { FAIL() << error_message; };
}

// Function which, when invoked successfully passes test
auto correct = [](auto t) { SUCCEED(); };

/**
 * @given Result constructed with valid value
 * @when match function is invoked
 * @then match executes value case
 */
TEST(ResultTest, ResultValueConstruction) {
  Result<int, std::string> result = makeValue(5);
  result.match(correct, makeFailCase<Error<std::string>>(kErrorCaseMessage));
}

/**
 * @given Result constructed with error value
 * @when match function is invoked
 * @then match executes error case
 */
TEST(ResultTest, ResultErrorConstruction) {
  Result<int, std::string> result = makeError("error message");
  result.match(makeFailCase<Value<int>>(kValueCaseMessage), correct);
}

/**
 * @given Result constructed with the same type of value and error
 * @when match function is invoked
 * @then match executes successful case
 */
TEST(ResultTest, ResultSameTypeValueConstruction) {
  Result<int, int> result = makeValue(5);
  result.match(correct, makeFailCase<Error<int>>(kErrorCaseMessage));
}

/**
 * @given Result constructed with the same type of value and error
 * @when match function is invoked
 * @then match executes error case
 */
TEST(ResultTest, ResultSameTypeErrorConstruction) {
  Result<int, int> result = makeError(10);
  result.match(makeFailCase<Value<int>>(kValueCaseMessage), correct);
}

/**
 * @given Two functions which return result
 * @when bind operator is used to chain these 2 functions and they both return
 *       valid values
 * @then result of a bind contains valid value.
 */
TEST(ResultTest, ResultBindOperatorSuccesfulCase) {
  auto get_int = []() -> Result<int, std::string> { return makeValue(10); };
  auto negate_int = [](int a) -> Result<int, std::string> {
    return makeValue(-1 * a);
  };

  auto result = get_int() | negate_int;

  result.match([](Value<int> v) { ASSERT_EQ(-10, v.value); },
               makeFailCase<Error<std::string>>(kErrorCaseMessage));
}

// function which must not be called for test to pass
auto never_used_negate_int = [](int a) -> Result<int, std::string> {
  EXPECT_TRUE(false);
  return makeValue(-1 * a);
};

auto error_get_int = []() -> Result<int, std::string> {
  return makeError(kFirstFunctionCallMessage);
};

/**
 * @given two functions which return result
 * @when bind operator is used to chain these 2 functions and first one return
 *       error
 * @then result of bind contains error and second function is not invoked
 */
TEST(ResultTest, ResultBindOperatorErrorFirstFunction) {
  auto result = error_get_int() | never_used_negate_int;

  result.match(makeFailCase<Value<int>>(kValueCaseMessage),
               [](Error<std::string> e) {
                 ASSERT_EQ(kFirstFunctionCallMessage, e.error);
               });
}

/**
 * @given two functions which return different results, but value and error
 *        types can be cast to each other
 * @when bind operator is used to chain these 2 functions
 * @then result type is properly deduced
 */
TEST(ResultTest, ResultBindOperatorCompatibleTypes) {
  auto result = error_get_int() | never_used_negate_int;

  static_assert(
      std::is_same<decltype(result), decltype(never_used_negate_int(1))>::value,
      "Result type does not match function return type");

  result.match(makeFailCase<Value<int>>(kValueCaseMessage),
               [](Error<std::string> e) {
                 ASSERT_EQ(kFirstFunctionCallMessage, e.error);
               });
}

/**
 * @given Result with void value
 * @when match function is invoked
 * @then void type is correctly handled by compiler
 */
TEST(ResultTest, ResultVoidValue) {
  Result<void, std::string> result = makeError(kErrorMessage);
  result.match(makeFailCase<Value<void>>(kValueCaseMessage),
               [](Error<std::string> e) { ASSERT_EQ(kErrorMessage, e.error); });
}

/**
 * @given Result with void error
 * @when match function is invoked
 * @then void type is correctly handled by compiler
 */
TEST(ResultTest, ResultVoidError) {
  Result<int, void> result = makeValue(5);
  result.match([](Value<int> v) { ASSERT_EQ(5, v.value); },
               makeFailCase<Error<void>>(kErrorCaseMessage));
}

/**
 * @given Pair of results with some values
 * @when and_res function is invoked
 * @then result contains the last value
 */
TEST(ResultTest, AndResWithValVal) {
  Result<int, void> result = makeValue(5);
  Result<int, void> new_res = makeValue(4);
  result.and_res(new_res).match([](Value<int> v) { ASSERT_EQ(4, v.value); },
                                makeFailCase<Error<void>>(kErrorCaseMessage));
}

/**
 * @given Pair of results: first with error, second with value
 * @when and_res function is invoked
 * @then result contains the first error
 */
TEST(ResultTest, AndResWithErrVal) {
  Result<int, int> result = makeError(5);
  Result<int, int> new_res = makeValue(4);
  result.and_res(new_res).match(makeFailCase<Value<int>>(kValueCaseMessage),
                                [](Error<int> e) { ASSERT_EQ(5, e.error); });
}

/**
 * @given Pair of results: first with value, second with error
 * @when and_res function is invoked
 * @then result contains the second error
 */
TEST(ResultTest, AndResWithValErr) {
  Result<int, int> result = makeValue(5);
  Result<int, int> new_res = makeError(4);
  result.and_res(new_res).match(makeFailCase<Value<int>>(kValueCaseMessage),
                                [](Error<int> e) { ASSERT_EQ(4, e.error); });
}

/**
 * @given Pair of results with some values
 * @when or_res function is invoked
 * @then result contains the first value
 */
TEST(ResultTest, OrResWithValVal) {
  Result<int, void> result = makeValue(5);
  Result<int, void> new_res = makeValue(4);
  result.or_res(new_res).match([](Value<int> v) { ASSERT_EQ(5, v.value); },
                               makeFailCase<Error<void>>(kErrorCaseMessage));
}

/**
 * @given Pair of results: first with error, second with value
 * @when or_res function is invoked
 * @then result contains the second value
 */
TEST(ResultTest, OrResWithErrVal) {
  Result<int, int> result = makeError(5);
  Result<int, int> new_res = makeValue(4);
  result.or_res(new_res).match([](Value<int> v) { ASSERT_EQ(4, v.value); },
                               makeFailCase<Error<int>>(kErrorCaseMessage));
}

/**
 * @given Pair of results with some errors
 * @when or_res function is invoked
 * @then result contains the last value
 */
TEST(ResultTest, OrResWithErrErr) {
  Result<int, int> result = makeError(5);
  Result<int, int> new_res = makeError(4);
  result.or_res(new_res).match(makeFailCase<Value<int>>(kValueCaseMessage),
                               [](Error<int> e) { ASSERT_EQ(4, e.error); });
}

/**
 * @given Result with some error and some function
 * @when map_error function is invoked
 * @then result contains error after function application
 */
TEST(ResultTest, MapError) {
  Result<void, int> result = makeError(5);
  map_error<int>(result, [](auto i) { return i * 2; })
      .match(makeFailCase<Value<void>>(kValueCaseMessage),
             [](Error<int> e) { ASSERT_EQ(10, e.error); });
}

/**
 * @given Result with some error and some function
 * @when map_error function is invoked
 * @then result contains the same error
 */
TEST(ResultTest, MapErrorBlank) {
  Result<int, int> result = makeValue(5);
  map_error<int>(result, [](auto i) { return i * 2; })
      .match([](Value<int> v) { ASSERT_EQ(5, v.value); },
             makeFailCase<Error<int>>(kErrorCaseMessage));
}

using NonCopyable = std::unique_ptr<int>;

/**
 * @given a result with a non-copyable object value reference
 * @when assumeValue and assumeError are called
 * @then assumeValue does not throw and returns same value object reference
 *  @and assumeError does throw a ResultException
 */
TEST(ResultTest, AssumeValueReference) {
  NonCopyable value = std::make_unique<int>(18);
  Result<NonCopyable &, int> result(value);
  IROHA_ASSERT_RESULT_VALUE(result);
  EXPECT_NO_THROW(EXPECT_EQ(result.assumeValue(), value));
  EXPECT_THROW(result.assumeError(), ResultException);
}

/**
 * @given a result with a non-copyable object error reference
 * @when assumeError and assumeValue are called
 * @then assumeError does not throw and returns same error object reference
 *  @and assumeValue does throw a ResultException
 */
TEST(ResultTest, AssumeErrorReference) {
  NonCopyable value = std::make_unique<int>(18);
  Result<int, NonCopyable &> result(value);
  IROHA_ASSERT_RESULT_ERROR(result);
  EXPECT_NO_THROW(EXPECT_EQ(result.assumeError(), value));
  EXPECT_THROW(result.assumeValue(), ResultException);
}

/**
 * @given a result with a non-copyable object value
 * @when assumeValue and assumeError are called
 * @then assumeValue does not throw and returns same value object
 *  @and assumeError does throw a ResultException
 */
TEST(ResultTest, AssumeValue) {
  auto value = new NonCopyable::element_type(18);
  Result<NonCopyable, int> result(value);
  IROHA_ASSERT_RESULT_VALUE(result);
  NonCopyable extracted_value;
  EXPECT_NO_THROW(extracted_value = std::move(result).assumeValue());
  EXPECT_EQ(extracted_value.get(), value);
  int extracted_error = 23;
  EXPECT_THROW(extracted_error = std::move(result).assumeError(),
               ResultException);
  EXPECT_EQ(extracted_error, 23);
}

/**
 * @given a result with a non-copyable object error
 * @when assumeError and assumeValue are called
 * @then assumeError does not throw and returns same error object
 *  @and assumeValue does throw a ResultException
 */
TEST(ResultTest, AssumeError) {
  auto error = new NonCopyable::element_type(18);
  Result<int, NonCopyable> result(error);
  IROHA_ASSERT_RESULT_ERROR(result);
  NonCopyable extracted_error;
  EXPECT_NO_THROW(extracted_error = std::move(result).assumeError());
  EXPECT_EQ(extracted_error.get(), error);
  int extracted_value = 23;
  EXPECT_THROW(extracted_value = std::move(result).assumeValue(),
               ResultException);
  EXPECT_EQ(extracted_value, 23);
}

struct A {};

struct ConstructibleFromA {
  ConstructibleFromA(A &&) {}
};

struct NotConstructibleFromA {};

/**
 * @given an object a of type A
 * @when construct a Result<ConstructibleFromA, NotConstructibleFromA> from a
 * @then result contains value constructed from a
 */
TEST(ResultTest, AutoValueConstruction) {
  IROHA_ASSERT_RESULT_VALUE(
      (Result<ConstructibleFromA, NotConstructibleFromA>{A{}}));
}

/**
 * @given an object a of type A
 * @when construct a Result<NotConstructibleFromA, ConstructibleFromA> from a
 * @then result contains error constructed from a
 */
TEST(ResultTest, AutoErrorConstruction) {
  IROHA_ASSERT_RESULT_ERROR(
      (Result<NotConstructibleFromA, ConstructibleFromA>{A{}}));
}

/**
 * @given a result object of type Result<A, NotConstructibleFromA> containing a
 * value
 * @when construct a Result<ConstructibleFromA, NotConstructibleFromA> from it
 * @then result contains value constructed from initial result
 */
TEST(ResultTest, AutoValueConstructionFromResult) {
  Result<A, NotConstructibleFromA> result(A{});
  IROHA_ASSERT_RESULT_VALUE(result);
  IROHA_ASSERT_RESULT_VALUE(
      (Result<ConstructibleFromA, NotConstructibleFromA>{result}));
}

/**
 * @given a result object of type Result<NotConstructibleFromA, A> containing an
 * error
 * @when construct a Result<NotConstructibleFromA, ConstructibleFromA> from it
 * @then result contains error constructed from initial result
 */
TEST(ResultTest, AutoErrorConstructionFromResult) {
  Result<NotConstructibleFromA, A> result(A{});
  IROHA_ASSERT_RESULT_ERROR(result);
  IROHA_ASSERT_RESULT_ERROR(
      (Result<NotConstructibleFromA, ConstructibleFromA>{result}));
}
