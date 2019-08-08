/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/common_objects/amount.hpp"

#include <regex>

#include "utils/string_builder.hpp"

static const char kDecimalSeparator = '.';
static const char *kDigits = "0123456789";

using namespace shared_model::interface;

struct Amount::Impl {
  Impl(const std::string &amount)
      : string_repr_("NaN"), precision_(0), multiprecision_repr_(0) {
    const auto dot_pos = amount.find_first_not_of(kDigits);
    if (dot_pos != std::string::npos) {
      // fail, if:
      if (amount[dot_pos]
              != kDecimalSeparator  // string contains an invalid character
          or amount.find_first_not_of(kDigits, dot_pos + 1)
              != std::string::npos  // string contains more than one non-digit
          or dot_pos == 0  // dot is the first symbol (for compatibility)
          or dot_pos == amount.size() - 1  // dot is the last symbol
      ) {
        return;
      }
      std::string amount_without_dot = amount.substr(0, dot_pos);
      amount_without_dot.append(amount.substr(dot_pos + 1));
      precision_ = amount.size() - dot_pos - 1;
      multiprecision_repr_ =
          boost::multiprecision::uint256_t(amount_without_dot);
    } else {
      multiprecision_repr_ = boost::multiprecision::uint256_t(amount);
    }

    // make the string representation
    std::stringstream ss;
    ss << std::setw(precision_ + 1) << std::setfill('0')
       << std::setiosflags(std::ios::right) << multiprecision_repr_;
    string_repr_ = ss.str();
    if (precision_ > 0) {
      const auto dot_pos = string_repr_.end() - precision_;
      string_repr_.insert(dot_pos, '.');
    }
  }

  std::string string_repr_;
  interface::types::PrecisionType precision_;
  boost::multiprecision::uint256_t multiprecision_repr_;
};

Amount::Amount(const std::string &amount)
    : impl_(std::make_shared<Impl>(amount)) {}

const boost::multiprecision::uint256_t &Amount::intValue() const {
  return impl_->multiprecision_repr_;
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

Amount::Amount(std::shared_ptr<const Impl> impl) : impl_(std::move(impl)) {}

Amount *Amount::clone() const {
  return new Amount(impl_);
}
