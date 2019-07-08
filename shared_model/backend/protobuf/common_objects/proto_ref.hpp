/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_REF_HPP
#define IROHA_SHARED_MODEL_PROTO_REF_HPP

namespace shared_model {
  namespace proto {
    /**
     * Generic class for handling references to proto objects.
     * @tparam Iface is interface to inherit from
     * @tparam Proto is protobuf container
     */
    template <typename Iface, typename Proto>
    class ProtoRef : public Iface {
     public:
      using TransportType = Proto;

      /*
       * Construct object from transport.
       */
      explicit ProtoRef(Proto &ref) : proto_(ref) {}

      Proto &proto_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_REF_HPP
