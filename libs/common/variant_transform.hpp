/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_VARIANT_TRANSFORM_HPP
#define IROHA_VARIANT_TRANSFORM_HPP

#include <boost/mpl/transform.hpp>
#include <boost/variant/variant.hpp>

namespace iroha {
  namespace metafunctions {

    template <class T>
    struct ConstrefToUniquePointer {
      using type =
          std::unique_ptr<std::remove_const_t<std::remove_reference_t<T>>>;
    };

  }  // namespace metafunctions

  template <typename Variant, template <typename> class Metafunction>
  using TransformedVariant = typename boost::make_variant_over<
      typename boost::mpl::transform<typename Variant::types,
                                     Metafunction<boost::mpl::_1>>::type>::type;

}  // namespace iroha

#endif
