/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COMMON_RING_BUFFER_HPP
#define IROHA_COMMON_RING_BUFFER_HPP

namespace iroha {
  namespace containers {
    /**
     * Ring buffer implementation with static array layout.
     * Can be used on stack.
     * @tparam T - type of element of the buffer
     * @tparam Count - number of the elements in the buffer
     */
    template <typename T, size_t Count>
    class RingBuffer final {
     public:
      using Type = T;
      using Handle = size_t;

     private:
      static_assert(Count > 0, "Unexpected count value. It must be above 0.");
      static_assert(Count <= (std::numeric_limits<size_t>::max() >> 1),
                    "To prevent overflow");

      enum { kTypeSize = sizeof(Type) };

      /**
       * It is a real buffer size. kActualLimit will be allocated in memory.
       */
      enum { kActualLimit = Count };

      /**
       * We map the set of indexes of the buffer to the set of a larger size,
       * and a multiple of it. We do this to distinguish the case when the
       *buffer is empty from the case when it is completely full. It means that
       *buffer index can be [0, 2*BufferSize) and (end - begin) <= BufferSize.
       **/
      enum { kVirtualLimit = 2 * kActualLimit };

      struct Node {
        uint8_t data[kTypeSize];
      } data_[Count];

      Handle begin_;
      Handle end_;

      inline size_t internalSizeFromPosition(Handle h) const {
        return (((h + kVirtualLimit) - end_) % kVirtualLimit);
      }

      inline bool handleInBound(Handle h) const {
        /**
         * this code is only for debug purpose
         **/
        auto const sz_handle = internalSizeFromPosition(h);
        auto const sz_begin = internalSizeFromPosition(begin_);
        return (sz_handle < sz_begin);
      }

      inline size_t incrementAndNormalize(size_t val) const {
        return (++val % kVirtualLimit);
      }

      inline size_t handleToPosition(Handle h) const {
        return (h % kActualLimit);
      }

      inline size_t internalSize() const {
        auto const normalized_size = internalSizeFromPosition(begin_);
        assert(normalized_size <= kActualLimit);
        return normalized_size;
      }

      inline bool internalEmpty() const {
        return (begin_ == end_);
      }

      inline Type &internalGetItem(Node &node) {
        return *reinterpret_cast<Type *>(node.data);
      }

      inline Type const &internalGetItem(Node const &node) const {
        return *reinterpret_cast<Type const *>(node.data);
      }

      inline void destruct(Node &node) {
        assert(!internalEmpty());

        auto &item = internalGetItem(node);
        item.~Type();
      }

      template <typename FuncOnRemove>
      inline void destructLast(FuncOnRemove &&on_remove) {
        auto &node = internalToNode(end_);
        on_remove(end_, internalGetItem(node));

        destruct(node);
        end_ = incrementAndNormalize(end_);
      }

      template <typename... Args>
      inline void construct(Node &node, Args &&... args) {
        assert(internalSize() < kActualLimit);
        new (node.data) Type(std::forward<Args>(args)...);
      }

      template <typename FuncOnAdd, typename... Args>
      inline void constructFirst(FuncOnAdd &&on_add, Args &&... args) {
        auto &node = internalToNode(begin_);
        auto const constructed_h = begin_;

        construct(node, std::forward<Args>(args)...);
        begin_ = incrementAndNormalize(begin_);

        on_add(constructed_h, internalGetItem(node));
      }

      inline Node &internalToNode(Handle h) {
        assert(h < kVirtualLimit);
        return data_[handleToPosition(h)];
      }

      inline Node const &internalToNode(Handle h) const {
        assert(h < kVirtualLimit);
        return data_[handleToPosition(h)];
      }

     public:
      RingBuffer() : begin_(0ull), end_(0ull) {}

      ~RingBuffer() {
        while (!internalEmpty()) pop([](Handle, Type const &) {});
      }

      template <typename FuncOnAdd, typename FuncOnRemove, typename... Args>
      void push(FuncOnAdd &&on_add, FuncOnRemove &&on_remove, Args &&... args) {
        assert(internalSize() <= kActualLimit);
        if (internalSize() == kActualLimit) {
          destructLast(std::move(on_remove));
        }
        constructFirst(std::move(on_add), std::forward<Args>(args)...);
      }

      template <typename FuncOnRemove>
      void pop(FuncOnRemove &&on_remove) {
        if (!internalEmpty()) {
          destructLast(std::move(on_remove));
        }
      }

      template <typename Func>
      void foreach (Func &&f) const {
        for (auto it = end_; it != begin_; it = incrementAndNormalize(it))
          if (!std::forward<Func>(f)(it, internalGetItem(internalToNode(it))))
            break;
      }

      Type &getItem(Handle h) {
        assert(handleInBound(h));
        return internalGetItem(internalToNode(h));
      }

      Type const &getItem(Handle h) const {
        assert(handleInBound(h));
        return internalGetItem(internalToNode(h));
      }

      bool empty() const {
        return internalEmpty();
      }

      size_t size() const {
        return internalSize();
      }
    };
  }  // namespace containers
}  // namespace iroha

#endif  // IROHA_COMMON_RING_BUFFER_HPP
