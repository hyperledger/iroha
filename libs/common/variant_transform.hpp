/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_VARIANT_TRANSFORM_HPP
#define IROHA_VARIANT_TRANSFORM_HPP

#include <boost/mpl/transform.hpp>
#include <boost/variant/variant.hpp>
#include "common/result_fwd.hpp"

namespace iroha {
  namespace metafunctions {

    template <class T>
    struct ConstrefToUniquePointer {
      using type =
          std::unique_ptr<std::remove_const_t<std::remove_reference_t<T>>>;
    };

    template <typename TOther>
    struct ToResultWith {
      template <class T>
      struct AsValue {
        using type = iroha::expected::Result<iroha::expected::Value<TOther>,
                                             iroha::expected::Error<T>>;
      };
      template <class T>
      struct AsError {
        using type = iroha::expected::Result<iroha::expected::Value<T>,
                                             iroha::expected::Error<TOther>>;
      };
    };

    template <class T>
    struct ToResultValues {
      using type = iroha::expected::Value<T>;
    };

  }  // namespace metafunctions

  template <typename Variant, template <typename> class Metafunction>
  using TransformedVariant = typename boost::make_variant_over<
      typename boost::mpl::transform<typename Variant::types,
                                     Metafunction<boost::mpl::_1>>::type>::type;

  template <typename ResultType>
  const auto indirecting_visitor =
      [](const auto &pointer) -> ResultType { return *pointer; };

  template <typename Values, typename Error>
  using AggregateValueResult =
      typename boost::make_variant_over<typename boost::mpl::push_front<
          typename boost::mpl::transform<
              Values,
              metafunctions::ToResultValues<boost::mpl::_1>>::type,
          iroha::expected::Error<Error>>::type>::type;

}  // namespace iroha

#endif
