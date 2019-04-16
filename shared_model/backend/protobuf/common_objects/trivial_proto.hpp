/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_TRIVIAL_PROTO_HPP
#define IROHA_SHARED_MODEL_TRIVIAL_PROTO_HPP

#include "utils/reference_holder.hpp"

namespace shared_model {
  namespace proto {
    /**
     * Simple generic class for handling proto objects
     * @tparam Iface is interface to inherit from
     * @tparam Proto is protobuf container
     */
    template <typename Iface, typename Proto>
    class TrivialProto final : public Iface {
     public:
      /**
       * @tparm ProtoLoader generic param so it can be handled
       *                    in the load for the boost::variant
       */
      template <typename ProtoLoader>
      explicit TrivialProto(ProtoLoader &&ref)
          : proto_(std::forward<ProtoLoader>(ref)) {}

     protected:
      typename Iface::ModelType *clone() const override {
        return new TrivialProto(Proto(*proto_));
      }

     private:
      detail::ReferenceHolder<Proto> proto_;
    };

    /**
     * Simple generic class for handling proto objects
     * @tparam Iface is interface to inherit from
     * @tparam Proto is protobuf container
     * @tparam Impl is implementation of Iface
     */
    template <typename Iface, typename Proto, typename Impl>
    class CopyableProto : public Iface {
     public:
      /**
       * @tparm ProtoLoader generic param so it can be handled
       *                    in the load for the boost::variant
       */
      template <typename ProtoLoader>
      explicit CopyableProto(ProtoLoader &&ref)
          : proto_(std::forward<ProtoLoader>(ref)) {}

      using TransportType = Proto;

      const Proto &getTransport() const {
        return *proto_;
      }

     protected:
      typename Iface::ModelType *clone() const override final {
        return new Impl(Proto(*proto_));
      }
      detail::ReferenceHolder<Proto> proto_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_TRIVIAL_PROTO_HPP
