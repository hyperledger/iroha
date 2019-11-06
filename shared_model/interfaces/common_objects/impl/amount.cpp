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
  Impl(const std::string &amount)
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

    if (dot_pos == start or dot_pos == end - 1) {
      // not allowed to start or end with a dot
      return;
    }

    string_repr_.clear();
    if (dot_pos == end) {
      if (first_nonzero_digit_pos == end) {
        string_repr_.push_back(kZero);
      } else {
        // we have nonzero digits and no dot. reuse the original string.
        string_repr_.append(first_nonzero_digit_pos, end);
        multiprecision_repr_ =
            boost::multiprecision::uint256_t(first_nonzero_digit_pos);
      }
    } else if (first_nonzero_digit_pos > dot_pos) {
      // we have a dot preceded by zeroes only. reuse the original string.
      assert(dot_pos > start and dot_pos < end);
      string_repr_.append(dot_pos - 1, end);
      multiprecision_repr_ =
          boost::multiprecision::uint256_t(first_nonzero_digit_pos);
    } else {
      // we have a decimal separator with at least one nonzero digit before it.
      assert(dot_pos < end);
      assert(first_nonzero_digit_pos < dot_pos);
      // build a copy of amount string, starting with nonzero digit and having
      // no decimal separator
      string_repr_.append(first_nonzero_digit_pos, end);
      std::string amount_without_dot;
      amount_without_dot.append(first_nonzero_digit_pos, dot_pos);
      amount_without_dot.append(dot_pos + 1, end);
      multiprecision_repr_ =
          boost::multiprecision::uint256_t(amount_without_dot);
    }
    precision_ = dot_pos == end ? 0 : end - dot_pos - 1;
  }

  std::string string_repr_;
  interface::types::PrecisionType precision_;
  boost::multiprecision::uint256_t multiprecision_repr_;
};

Amount::Amount(const std::string &amount)
    : impl_(std::make_shared<Impl>(amount)) {}

int Amount::sign() const {
  return impl_->multiprecision_repr_.sign();
}

types::PrecisionType Amount::precision() const {
  return impl_->precision_;
}

std::string Amount::toStringRepr() const {
  return impl_->string_repr_;
}

bool Amount::operator==(const ModelType &rhs) const {
  return impl_->precision_ == rhs.impl_->precision_
      and impl_->multiprecision_repr_ == rhs.impl_->multiprecision_repr_;
}

std::string Amount::toString() const {
  return detail::PrettyStringBuilder()
      .init("Amount")
      .append(impl_->string_repr_)
      .finalize();
}
