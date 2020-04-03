/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SPIN_LOCK_HPP
#define IROHA_SPIN_LOCK_HPP

namespace iroha { namespace thread_concurrency {

class SpinLock final {
    std::atomic_flag blocker_;

public:
#   ifdef __GNUG__
    SpinLock() : blocker_(ATOMIC_FLAG_INIT) {
    }
#   elif _WIN32
    SpinLock() {
        blocker_.clear();
    }
#   endif

    void lock() {
        while (blocker_.test_and_set(std::memory_order_acquire));
    }
    bool tryLock() {
        return !blocker_.test_and_set(std::memory_order_acquire);
    }
    void unlock() {
        blocker_.clear(std::memory_order_release);
    }
};

class SpinLockInfinite final {
    SpinLockInfinite(const SpinLockInfinite &)  = delete;
    SpinLockInfinite(const SpinLockInfinite &&) = delete;

    SpinLockInfinite & operator=(const SpinLockInfinite &)  = delete;
    SpinLockInfinite & operator=(const SpinLockInfinite &&) = delete;

    SpinLock& blocker_;

public:
    SpinLockInfinite(SpinLock& blocker) : blocker_(blocker) {
        blocker_.lock();
    }
    ~SpinLockInfinite() {
        blocker_.unlock();
    }
};

class SpinLockTry final {
    SpinLockTry(const SpinLockTry &)  = delete;
    SpinLockTry(const SpinLockTry &&) = delete;

    SpinLockTry & operator=(const SpinLockTry &)  = delete;
    SpinLockTry & operator=(const SpinLockTry &&) = delete;

    SpinLock& blocker_;
    bool      me_locked_;

public:
    SpinLockTry(SpinLock& blocker) : blocker_(blocker) {
        me_locked_ = blocker_.tryLock();
    }
    ~SpinLockTry() {
        if (me_locked_) {
            blocker_.unlock();
        }
    }
    bool meLocked() {
        return me_locked_;
    }
};

}}

#endif//IROHA_SPIN_LOCK_HPP