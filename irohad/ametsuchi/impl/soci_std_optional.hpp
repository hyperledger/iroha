/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SOCI_STD_OPTIONAL_HPP
#define IROHA_SOCI_STD_OPTIONAL_HPP

#include <soci/type-conversion-traits.h>

#include <optional>

namespace soci {

  // simple fall-back for std::optional
  template <typename T>
  struct type_conversion<std::optional<T>> {
    typedef typename type_conversion<T>::base_type base_type;

    static void from_base(base_type const &in,
                          indicator ind,
                          std::optional<T> &out) {
      if (ind == i_null) {
        out.reset();
      } else {
        T tmp = T();
        type_conversion<T>::from_base(in, ind, tmp);
        out = tmp;
      }
    }

    static void to_base(std::optional<T> const &in,
                        base_type &out,
                        indicator &ind) {
      if (in) {
        type_conversion<T>::to_base(in.value(), out, ind);
      } else {
        ind = i_null;
      }
    }
  };

  template <>
  struct type_conversion<std::nullopt_t> {
    typedef int base_type;

    static void from_base(base_type const & /*in*/,
                          indicator /*ind*/,
                          std::nullopt_t & /*out*/) {}

    static void to_base(std::nullopt_t const & /*in*/,
                        base_type & /*out*/,
                        indicator &ind) {
      ind = i_null;
    }
  };

}  // namespace soci

#endif  // IROHA_SOCI_STD_OPTIONAL_HPP
