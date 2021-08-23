/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_RESULT_HPP
#define IROHA_RESULT_HPP

#include "common/result_fwd.hpp"

#include <ciso646>
#include <string>
#include <type_traits>

#include <boost/optional.hpp>
#include <boost/variant.hpp>

#include "common/visitor.hpp"

/*
 * Result is a type which represents value or an error, and values and errors
 * are template parametrized. Working with value wrapped in result is done using
 * match() function, which accepts 2 functions: for value and error cases. No
 * accessor functions are provided.
 */

namespace iroha {
  namespace expected {

    /*
     * Value and error types can be constructed from any value or error, if
     * underlying types are constructible. Example:
     *
     * @code
     * Value<std::string> v = Value<const char *>("hello");
     * @nocode
     */

    struct ValueBase {};

    template <typename T>
    struct Value : ValueBase {
      using type = T;
      template <
          typename... Args,
          typename = std::enable_if_t<std::is_constructible<T, Args...>::value>>
      Value(Args &&... args) : value(std::forward<Args>(args)...) {}
      T value;
      template <typename V>
      operator Value<V>() {
        return {value};
      }
    };

    template <>
    struct Value<void> {};

    struct ErrorBase {};

    template <typename E>
    struct Error : ErrorBase {
      using type = E;
      template <
          typename... Args,
          typename = std::enable_if_t<std::is_constructible<E, Args...>::value>>
      Error(Args &&... args) : error(std::forward<Args>(args)...) {}
      E error;
      template <typename V>
      operator Error<V>() {
        return {error};
      }
    };

    template <>
    struct Error<void> {};

    class ResultException : public std::runtime_error {
      using std::runtime_error::runtime_error;
    };

    struct ResultBase {};

    /**
     * Result is a specialization of a variant type with value or error
     * semantics.
     * @tparam V type of value
     * @tparam E error type
     */
    template <typename V, typename E = std::string>
    class Result : ResultBase, public boost::variant<Value<V>, Error<E>> {
      template <typename OV, typename OE>
      friend class Result;

      using variant_type = boost::variant<Value<V>, Error<E>>;
      using variant_type::variant_type;  // inherit constructors

     public:
      using ValueType = Value<V>;
      using ErrorType = Error<E>;

      using ValueInnerType = V;
      using ErrorInnerType = E;

      Result() = default;

      template <typename OV, typename OE>
      Result(Result<OV, OE> r)
          : Result(visit_in_place(std::move(r),
                                  [](Value<OV> &v) -> Result<V, E> {
                                    return ValueType{std::move(v.value)};
                                  },
                                  [](Value<OV> &&v) -> Result<V, E> {
                                    return ValueType{std::move(v.value)};
                                  },
                                  [](Error<OE> &e) -> Result<V, E> {
                                    return ErrorType{std::move(e.error)};
                                  },
                                  [](Error<OE> &&e) -> Result<V, E> {
                                    return ErrorType{std::move(e.error)};
                                  })) {}

      /**
       * match is a function which allows working with result's underlying
       * types, you must provide 2 functions to cover success and failure cases.
       * Return type of both functions must be the same. Example usage:
       * @code
       * result.match([](Value<int> v) { std::cout << v.value; },
       *              [](Error<std::string> e) { std::cout << e.error; });
       * @nocode
       */
      template <typename ValueMatch, typename ErrorMatch>
      constexpr auto match(ValueMatch &&value_func, ErrorMatch &&error_func) & {
        return visit_in_place(*this,
                              [f = std::forward<ValueMatch>(value_func)](
                                  ValueType &v) { return f(v); },
                              [f = std::forward<ErrorMatch>(error_func)](
                                  ErrorType &e) { return f(e); });
      }

      /**
       * Move alternative for match function
       */
      template <typename ValueMatch, typename ErrorMatch>
      constexpr auto match(ValueMatch &&value_func,
                           ErrorMatch &&error_func) && {
        return visit_in_place(*this,
                              [f = std::forward<ValueMatch>(value_func)](
                                  ValueType &v) { return f(std::move(v)); },
                              [f = std::forward<ErrorMatch>(error_func)](
                                  ErrorType &e) { return f(std::move(e)); });
      }

      /**
       * Const alternative for match function
       */
      template <typename ValueMatch, typename ErrorMatch>
      constexpr auto match(ValueMatch &&value_func,
                           ErrorMatch &&error_func) const & {
        return visit_in_place(*this,
                              [f = std::forward<ValueMatch>(value_func)](
                                  const ValueType &v) { return f(v); },
                              [f = std::forward<ErrorMatch>(error_func)](
                                  const ErrorType &e) { return f(e); });
      }

      /**
       * Error AND-chaining
       * Works by the following table (aka boolean lazy AND):
       * err1 * any  -> err1
       * val1 * err2 -> err2
       * val1 * val2 -> val2
       *
       * @param new_res second chain argument
       * @return new_res if this Result contains a value
       *         otherwise return this
       */
      template <typename Value>
      constexpr Result<Value, E> and_res(const Result<Value, E> &new_res) const
          noexcept {
        return visit_in_place(
            *this,
            [res = new_res](ValueType) { return res; },
            [](ErrorType err) -> Result<Value, E> { return err; });
      }

      /**
       * Error OR-chaining
       * Works by the following table (aka boolean lazy OR):
       * val1 * any  -> val1
       * err1 * val2 -> val2
       * err1 * err2 -> err2
       *
       * @param new_res second chain argument
       * @return new_res if this Result contains a error
       *         otherwise return this
       */
      template <typename Value>
      constexpr Result<Value, E> or_res(const Result<Value, E> &new_res) const
          noexcept {
        return visit_in_place(
            *this,
            [](ValueType val) -> Result<Value, E> { return val; },
            [res = new_res](ErrorType) { return res; });
      }

      using AssumeValueHelper =
          std::conditional_t<std::is_void<ValueInnerType>::value,
                             void *,
                             ValueInnerType>;

      /// @return value if present, otherwise throw ResultException
      template <typename ReturnType = const AssumeValueHelper &>
      std::enable_if_t<not std::is_void<ValueInnerType>::value, ReturnType>
      assumeValue() const & {
        const auto *val = boost::get<ValueType>(this);
        if (val != nullptr) {
          return val->value;
        }
        throw ResultException("Value expected, but got an Error.");
      }

      /// @return value if present, otherwise throw ResultException
      template <typename ReturnType = AssumeValueHelper &>
      std::enable_if_t<not std::is_void<ValueInnerType>::value, ReturnType>
      assumeValue() & {
        auto val = boost::get<ValueType>(this);
        if (val != nullptr) {
          return val->value;
        }
        throw ResultException("Value expected, but got an Error.");
      }

      /// @return value if present, otherwise throw ResultException
      template <typename ReturnType = AssumeValueHelper &&>
      std::enable_if_t<not std::is_void<ValueInnerType>::value, ReturnType>
      assumeValue() && {
        auto val = boost::get<ValueType>(this);
        if (val != nullptr) {
          return std::move(val->value);
        }
        throw ResultException("Value expected, but got an Error.");
      }

      using AssumeErrorHelper =
          std::conditional_t<std::is_void<ErrorInnerType>::value,
                             void *,
                             ErrorInnerType>;

      /// @return error if present, otherwise throw ResultException
      template <typename ReturnType = const AssumeErrorHelper &>
      std::enable_if_t<not std::is_void<ErrorInnerType>::value, ReturnType>
      assumeError() const & {
        const auto *err = boost::get<ErrorType>(this);
        if (err != nullptr) {
          return err->error;
        }
        throw ResultException("Error expected, but got a Value.");
      }

      /// @return error if present, otherwise throw ResultException
      template <typename ReturnType = AssumeErrorHelper &>
      std::enable_if_t<not std::is_void<ErrorInnerType>::value, ReturnType>
      assumeError() & {
        auto err = boost::get<ErrorType>(this);
        if (err != nullptr) {
          return err->error;
        }
        throw ResultException("Error expected, but got a Value.");
      }

      /// @return error if present, otherwise throw ResultException
      template <typename ReturnType = AssumeErrorHelper &&>
      std::enable_if_t<not std::is_void<ErrorInnerType>::value, ReturnType>
      assumeError() && {
        auto err = boost::get<ErrorType>(this);
        if (err != nullptr) {
          return std::move(err->error);
        }
        throw ResultException("Error expected, but got a Value.");
      }
    };

    template <typename ResultType>
    using ValueOf = typename std::decay_t<ResultType>::ValueType;
    template <typename ResultType>
    using ErrorOf = typename std::decay_t<ResultType>::ErrorType;

    template <typename ResultType>
    using InnerValueOf = typename std::decay_t<ResultType>::ValueInnerType;
    template <typename ResultType>
    using InnerErrorOf = typename std::decay_t<ResultType>::ErrorInnerType;

    /**
     * Get a new result with the copied value or mapped error
     * @param res base Result for getting new one
     * @param map callback for error mapping
     * @return result with changed error
     */
    template <typename Err1, typename Err2, typename V, typename Fn>
    Result<V, Err1> map_error(const Result<V, Err2> &res, Fn &&map) noexcept {
      return visit_in_place(res,
                            [](Value<V> val) -> Result<V, Err1> { return val; },
                            [map](Error<Err2> err) -> Result<V, Err1> {
                              return Error<Err1>{map(err.error)};
                            });
    }

    // Factory methods for avoiding type specification
    inline Value<void> makeValue() {
      return Value<void>{};
    }

    template <typename T>
    Value<T> makeValue(T &&value) {
      return Value<T>{std::forward<T>(value)};
    }

    inline Error<void> makeError() {
      return Error<void>{};
    }

    template <typename E>
    Error<E> makeError(E &&error) {
      return Error<E>{std::forward<E>(error)};
    }

    template <typename T>
    constexpr bool isResult =
        std::is_base_of<ResultBase, std::decay_t<T>>::value;
    template <typename T>
    constexpr bool isValue = std::is_base_of<ValueBase, std::decay_t<T>>::value;
    template <typename T>
    constexpr bool isError = std::is_base_of<ErrorBase, std::decay_t<T>>::value;

    /**
     * A struct that provides the result type conversion for bind operator.
     * @tparam Transformed The type returned by value transformation function.
     * @tparam ErrorType The type of former result's error
     * The struct provides Result type, which is a combination of transformation
     * function outcome and former Result error type, and a method to convert
     * transformation function outcome to this type.
     */
    template <typename Transformed, typename ErrorType, typename = void>
    struct BindReturnType;

    /// Case when transformation function returns unwrapped value.
    template <typename Transformed, typename ErrorType>
    struct BindReturnType<
        Transformed,
        ErrorType,
        typename std::enable_if_t<
            not isResult<Transformed> and not isValue<Transformed>>> {
      using ReturnType = Result<Transformed, ErrorType>;
      static ReturnType makeValue(Transformed &&result) {
        return iroha::expected::makeValue(std::move(result));
      }
    };

    /// Case when transformation function returns Result.
    template <typename Transformed, typename ErrorType>
    struct BindReturnType<Transformed,
                          ErrorType,
                          std::enable_if_t<isResult<Transformed>>> {
      using ReturnType = Transformed;
      static ReturnType makeValue(Transformed &&result) {
        return std::move(result);
      }
    };

    /// Case when transformation function returns Value.
    template <typename Transformed, typename ErrorType>
    struct BindReturnType<Transformed,
                          ErrorType,
                          std::enable_if_t<isValue<Transformed>>> {
      using ReturnType = Result<typename Transformed::type, ErrorType>;
      static ReturnType makeValue(Transformed &&result) {
        return std::move(result);
      }
    };

    /// Case when transformation function returns void.
    template <typename ErrorType>
    struct BindReturnType<void, ErrorType> {
      using ReturnType = Result<void, ErrorType>;
    };

    template <typename ValueTransformer, typename Value, typename Error>
    using BindReturnTypeHelper = typename std::enable_if_t<
        not std::is_same<Value, void>::value,
        BindReturnType<decltype(std::declval<ValueTransformer>()(
                           std::declval<Value>())),
                       Error>>;

    /**
     * Bind operator allows chaining several functions which return result. If
     * result contains error, it returns this error, if it contains value,
     * function f is called.
     * @param f function which return type must be compatible with original
     * result
     */

    /// constref version
    template <typename V,
              typename E,
              typename Transform,
              typename TypeHelper = BindReturnTypeHelper<Transform, V, E>,
              typename ReturnType = typename TypeHelper::ReturnType>
    constexpr auto operator|(const Result<V, E> &r, Transform &&f)
        -> ReturnType {
      return r.match(
          [&f](const auto &v) { return TypeHelper::makeValue(f(v.value)); },
          [](const auto &e) { return ReturnType(makeError(e.error)); });
    }

    /// rvalue version
    template <typename V,
              typename E,
              typename Transform,
              typename TypeHelper = BindReturnTypeHelper<Transform, V, E>,
              typename ReturnType = typename TypeHelper::ReturnType>
    constexpr auto operator|(Result<V, E> &&r, Transform &&f) -> ReturnType {
      static_assert(isResult<ReturnType>, "wrong return_type");
      return std::move(r).match(
          [&f](auto &&v) {
            return TypeHelper::makeValue(f(std::move(v.value)));
          },
          [](auto &&e) { return ReturnType(makeError(std::move(e.error))); });
    }

    /**
     * Bind operator overload for functions which do not accept anything as a
     * parameter. Allows execution of a sequence of unrelated functions, given
     * that all of them return Result
     * @param f function which accepts no parameters and returns result
     */

    /// constref version
    template <typename T,
              typename E,
              typename Procedure,
              typename TypeHelper =
                  BindReturnType<decltype(std::declval<Procedure>()()), E>,
              typename ReturnType = typename TypeHelper::ReturnType>
    constexpr auto operator|(const Result<T, E> &r, Procedure f) ->
        typename std::enable_if<not std::is_same<decltype(f()), void>::value,
                                ReturnType>::type {
      return r.match(
          [&f](const Value<T> &) { return TypeHelper::makeValue(f()); },
          [](const Error<E> &e) { return ReturnType(makeError(e.error)); });
    }

    /// rvalue ref version
    template <typename V,
              typename E,
              typename Procedure,
              typename TypeHelper =
                  BindReturnType<decltype(std::declval<Procedure>()()), E>,
              typename ReturnType = typename TypeHelper::ReturnType>
    constexpr auto operator|(Result<V, E> &&r, Procedure f) ->
        typename std::enable_if<not std::is_same<decltype(f()), void>::value,
                                ReturnType>::type {
      return std::move(r).match(
          [&f](const auto &) { return TypeHelper::makeValue(f()); },
          [](auto &&e) { return ReturnType(makeError(std::move(e.error))); });
    }

    /// operator |= is a shortcut for `Result = Result | function'
    template <typename R, typename F>
    constexpr auto operator|=(R &r, F &&f) -> decltype(r = r | f) {
      return r = r | std::forward<F>(f);
    }

    /**
     * Checkers of the Result type.
     */

    template <typename ResultType,
              typename = std::enable_if_t<isResult<ResultType>>>
    bool hasValue(const ResultType &result) {
      return boost::get<ValueOf<ResultType>>(&result);
    }

    template <typename ResultType,
              typename = std::enable_if_t<isResult<ResultType>>>
    bool hasError(const ResultType &result) {
      return boost::get<ErrorOf<ResultType>>(&result);
    }

    /**
     * Converters from Result to boost::optional. Can be used when only certain
     * part of result is honored (generally a Value), to smoothly convert it to
     * optional representation.
     */

    /// @return optional with value if present, otherwise none
    template <typename ResultType,
              typename = std::enable_if_t<isResult<ResultType>>>
    boost::optional<InnerValueOf<ResultType>> resultToOptionalValue(
        ResultType &&res) noexcept {
      if (hasValue(res)) {
        return boost::get<ValueOf<ResultType>>(std::forward<ResultType>(res))
            .value;
      }
      return {};
    }

    /// @return optional with error if present, otherwise none
    template <typename ResultType,
              typename = std::enable_if_t<isResult<ResultType>>>
    boost::optional<InnerErrorOf<ResultType>> resultToOptionalError(
        ResultType &&res) noexcept {
      if (hasError(res)) {
        return boost::get<ErrorOf<ResultType>>(std::forward<ResultType>(res))
            .error;
      }
      return {};
    }

    template <typename E, typename V>
    Result<typename V::value_type, std::decay_t<E>> optionalValueToResult(
        V &&value, E &&error) {
      if (value) {
        return makeValue(std::move(value).value());
      }
      return makeError(std::move(error));
    }

    template <typename V, typename E>
    Result<std::decay_t<V>, typename E::value_type> optionalErrorToResult(
        E &&error, V &&value) {
      if (error) {
        return makeError(std::move(error).value());
      }
      return makeValue(std::move(value));
    }
  }  // namespace expected
}  // namespace iroha
#endif  // IROHA_RESULT_HPP
