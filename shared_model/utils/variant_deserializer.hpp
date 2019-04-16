/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_VARIANT_DESERIALIZER_HPP
#define IROHA_VARIANT_DESERIALIZER_HPP

#include <boost/serialization/variant.hpp>

#define NORETURN [[noreturn]]

namespace shared_model {
  namespace detail {
    /**
     * Helper for variant deserialization
     * Iterate through type list to use type specified by type index in list
     * @tparam S list of types
     */
    template <class S>
    struct variant_impl {
      /**
       * Dummy deserializer for empty list
       */
      struct load_null {
        /**
         * Dummy deserializer
         * @tparam V variant type for deserialization
         * @tparam Archive container type
         */
        template <class V, class Archive>
        NORETURN static V invoke(Archive &&, int) {
          BOOST_ASSERT_MSG(false, "Required type not found");
          std::abort();
        }
      };

      /**
       * Deserializer implementation
       */
      struct load_impl {
        /**
         * Deserialize container in variant using type in list by specified
         * index
         * If type selector is 0, head type is required type, and it is used
         * Otherwise call helper without front element in type list
         * @tparam V variant type for deserialization
         * @tparam Archive container type
         * @param ar container to be deserialized
         * @param which type index in list
         * @param v result variant
         */
        template <class V, class Archive>
        static V invoke(Archive &&ar, int which) {
          if (which == 0) {
            using head_type = typename boost::mpl::front<S>::type;
            return head_type(std::forward<Archive>(ar));
          } else {
            using type = typename boost::mpl::pop_front<S>::type;
            return variant_impl<type>::template load<V>(
                std::forward<Archive>(ar), which - 1);
          }
        }
      };

      /**
       * Deserialize container in variant using type in list by specified index
       * Choose dummy or concrete deserializer depending on type list size
       * @tparam V variant type for deserialization
       * @tparam Archive container type
       * @param ar container to be deserialized
       * @param which type index in list
       * @param v result variant
       */
      template <class V, class Archive>
      static V load(Archive &&ar, int which) {
        using typex =
            typename boost::mpl::eval_if<boost::mpl::empty<S>,
                                         boost::mpl::identity<load_null>,
                                         boost::mpl::identity<load_impl>>::type;
        return typex::template invoke<V>(std::forward<Archive>(ar), which);
      }
    };
  }  // namespace detail
}  // namespace shared_model

#endif  // IROHA_VARIANT_DESERIALIZER_HPP
