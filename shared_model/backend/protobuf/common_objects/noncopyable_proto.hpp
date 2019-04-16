/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_NONCOPYABLE_PROTO_HPP
#define IROHA_NONCOPYABLE_PROTO_HPP

/**
 * Generic class for handling proto objects which are not intended to be copied.
 * @tparam Iface is interface to inherit from
 * @tparam Proto is protobuf container
 * @tparam Impl is implementation of Iface
 */
template <typename Iface, typename Proto, typename Impl>
class NonCopyableProto : public Iface {
 public:
  using TransportType = Proto;

  /*
   * Construct object from transport. Transport can be moved or copied.
   */
  template <typename Transport>
  NonCopyableProto(Transport &&ref) : proto_(std::forward<Transport>(ref)){}

  NonCopyableProto(const NonCopyableProto &o) = delete;
  NonCopyableProto &operator=(const NonCopyableProto &o) = delete;

  const Proto &getTransport() const {
    return proto_;
  }

 protected:
  typename Iface::ModelType *clone() const override final {
    return new Impl(proto_);
  }

  Proto proto_;
};

#endif  // IROHA_NONCOPYABLE_PROTO_HPP
