/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/common_objects/amount.hpp"

#include <boost/algorithm/string/classification.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include "utils/string_builder.hpp"

static const char kDecimalSeparator = '.';
static const char *kDigits = "0123456789";
static const char kZero = kDigits[0];

using namespace shared_model::interface;

struct Amount::Impl {
  Impl(std::string_view amount)
      : string_repr_("NaN"), precision_(0), multiprecision_repr_(0) {
    const char *const start = amount.data();
    const char *const end = start + amount.size();

    const char *first_nonzero_digit_pos = end;
    const char *dot_pos = end;
    for (auto *c = start; c < end; ++c) {
      static const auto is_digit = boost::is_any_of(kDigits);
      if (*c == kDecimalSeparator and dot_pos == end) {
        dot_pos = c;
      } else if (is_digit(*c)) {
        if (first_nonzero_digit_pos == end and *c != kZero) {
          first_nonzero_digit_pos = c;
        }
      } else {
        // invalid character
        return;
      }
    }

    if (dot_pos == start) {
      // not allowed to start with a dot
      return;
    }

    auto precision = dot_pos == end ? 0 : end - dot_pos - 1;
    if (precision > 255) {
      return;
    }

    if (dot_pos == end) {
      if (first_nonzero_digit_pos == end) {
        string_repr_.clear();
        string_repr_.push_back(kZero);
      } else {
        // we have nonzero digits and no dot. reuse the original string.
        try {
          multiprecision_repr_ =
              boost::multiprecision::checked_uint256_t(std::string_view(
                  first_nonzero_digit_pos, end - first_nonzero_digit_pos));
        } catch (std::overflow_error const &) {
          return;
        }
        string_repr_.clear();
        string_repr_.append(first_nonzero_digit_pos, end);
      }
    } else if (first_nonzero_digit_pos > dot_pos) {
      // we have a dot preceded by zeroes only. reuse the original string.
      assert(dot_pos > start and dot_pos < end);
      try {
        multiprecision_repr_ =
            boost::multiprecision::checked_uint256_t(std::string_view(
                first_nonzero_digit_pos, end - first_nonzero_digit_pos));
      } catch (std::overflow_error const &) {
        return;
      }
      string_repr_.clear();
      string_repr_.append(dot_pos - 1, end);
    } else {
      // we have a decimal separator with at least one nonzero digit before it.
      assert(dot_pos < end);
      assert(first_nonzero_digit_pos < dot_pos);
      // build a copy of amount string, starting with nonzero digit and having
      // no decimal separator
      std::string amount_without_dot;
      amount_without_dot.append(first_nonzero_digit_pos, dot_pos);
      amount_without_dot.append(dot_pos + 1, end);
      try {
        multiprecision_repr_ =
            boost::multiprecision::checked_uint256_t(amount_without_dot);
      } catch (std::overflow_error const &) {
        return;
      }
      string_repr_.clear();
      string_repr_.append(first_nonzero_digit_pos, end);
    }
    precision_ = precision;
  }

  Impl(types::PrecisionType precision)
      : string_repr_("0"), precision_(precision), multiprecision_repr_(0) {}

  std::string string_repr_;
  interface::types::PrecisionType precision_;
  boost::multiprecision::checked_uint256_t multiprecision_repr_;
};

Amount::Amount(std::string_view amount)
    : impl_(std::make_unique<Impl>(amount)) {}

Amount::Amount(types::PrecisionType precision)
    : impl_(std::make_unique<Impl>(precision)) {}

Amount::Amount(Amount const &other)
    : impl_(std::make_unique<Impl>(*other.impl_)) {}

Amount::Amount(Amount &&other) noexcept
    : impl_(std::exchange(other.impl_, nullptr)) {}

Amount &Amount::operator=(Amount const &other) {
  return *this = Amount(other);
}

Amount &Amount::operator=(Amount &&other) noexcept {
  std::swap(impl_, other.impl_);
  return *this;
}

Amount::~Amount() = default;

int Amount::sign() const {
  return impl_->multiprecision_repr_.sign();
}

types::PrecisionType Amount::precision() const {
  return impl_->precision_;
}

std::string const &Amount::toStringRepr() const {
  return impl_->string_repr_;
}

Amount &Amount::operator+=(Amount const &other) {
  if (other.impl_->precision_ > impl_->precision_) {
    impl_ = std::make_unique<Impl>("");
    return *this;
  }

  try {
    impl_->multiprecision_repr_ = impl_->multiprecision_repr_
        + other.impl_->multiprecision_repr_
            * boost::multiprecision::pow(
                  boost::multiprecision::checked_uint256_t(10),
                  (impl_->precision_ - other.impl_->precision_));
  } catch (std::overflow_error const &) {
    impl_ = std::make_unique<Impl>("");
    return *this;
  }

  auto string_repr = impl_->multiprecision_repr_.str();
  if (impl_->precision_ >= string_repr.size()) {
    string_repr = std::string(impl_->precision_ - string_repr.size() + 1, '0')
                      .append(string_repr);
  }
  impl_->string_repr_ =
      string_repr.insert(string_repr.size() - impl_->precision_, ".");

  return *this;
}

Amount &Amount::operator-=(Amount const &other) {
  if (other.impl_->precision_ > impl_->precision_) {
    impl_ = std::make_unique<Impl>("");
    return *this;
  }

  try {
    impl_->multiprecision_repr_ = impl_->multiprecision_repr_
        - other.impl_->multiprecision_repr_
            * boost::multiprecision::pow(
                  boost::multiprecision::checked_uint256_t(10),
                  (impl_->precision_ - other.impl_->precision_));
  } catch (std::range_error const &) {
    impl_ = std::make_unique<Impl>("");
    return *this;
  }

  auto string_repr = impl_->multiprecision_repr_.str();
  if (impl_->precision_ >= string_repr.size()) {
    string_repr = std::string(impl_->precision_ - string_repr.size() + 1, '0')
                      .append(string_repr);
  }
  impl_->string_repr_ =
      string_repr.insert(string_repr.size() - impl_->precision_, ".");

  return *this;
}

bool Amount::operator==(const ModelType &rhs) const {
  auto lhs_precision = impl_->precision_;
  auto rhs_precision = rhs.impl_->precision_;
  auto lhs_repr = impl_->multiprecision_repr_;
  auto rhs_repr = rhs.impl_->multiprecision_repr_;
  if (lhs_precision < rhs_precision) {
    std::swap(lhs_precision, rhs_precision);
    std::swap(lhs_repr, rhs_repr);
  }
  try {
    rhs_repr *=
        boost::multiprecision::pow(boost::multiprecision::checked_uint256_t(10),
                                   (lhs_precision - rhs_precision));
  } catch (std::overflow_error const &) {
    return false;
  }
  return lhs_repr == rhs_repr;
}

std::string Amount::toString() const {
  return detail::PrettyStringBuilder()
      .init("Amount")
      .append(impl_->string_repr_)
      .finalize();
}
