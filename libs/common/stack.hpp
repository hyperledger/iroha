/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_STACK_HPP
#define IROHA_STACK_HPP

#include <assert.h>
#include "common/macro.hpp"

namespace iroha { namespace containers {

template<typename Type, size_t Size, size_t Align> class Stack final {
public:
    using ValueType = Type;

private:
    enum : size_t { kAlignment = Align };
    static_assert(kAlignment > 0,
        "Alignment must be more than 0.");
    static_assert((kAlignment & (kAlignment - 1)) == 0,
        "Alignment must be power of 2.");

    enum : size_t { kCount = Size };
    enum : size_t { kBufferSize = kCount * sizeof(ValueType) + (kAlignment - 1) };
    enum : size_t { kEnd = kCount };

    uint8_t buffer_[kBufferSize];
    ValueType * const ptr_begin_;
    ValueType * const ptr_end_;
    ValueType *ptr_current_;

public:
    Stack()
    : ptr_begin_((ValueType*)IROHA_ALIGN_MEM(buffer_, kAlignment))
    , ptr_end_(ptr_begin_ + kCount)
    , ptr_current_(ptr_end_) {
        static_assert(offsetof(Stack, ptr_begin_) < offsetof(Stack, ptr_end_),
            "Check initialization order.");
        static_assert(offsetof(Stack, ptr_end_) < offsetof(Stack, ptr_current_),
            "Check initialization order.");
    }

    ~Stack() {
        while(!empty())
            pop();
    }

    template<typename...Args> ValueType& push(Args&&...args) {
        assert(ptr_current_ > ptr_begin_);
        return *(new(--ptr_current_) ValueType(std::forward<Args>(args)...));
    }

    void pop() {
        assert(ptr_current_ < ptr_end_);
        ptr_current_->~ValueType();
        ++ptr_current_;
    }

    ValueType& get() {
        assert(ptr_current_ >= ptr_begin_);
        assert(ptr_current_ < ptr_end_);
        return *ptr_current_;
    }

    size_t size() const {
        return (ptr_end_ - ptr_current_);
    }

    bool empty() const {
        return (ptr_current_ == ptr_end_);
    }
};

}}

#endif//IROHA_STACK_HPP
