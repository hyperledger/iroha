/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_PROFILER_HPP
#define IROHA_PROFILER_HPP

#include <cstdint>
#include <time.h>
#include <assert.h>
#include <iostream>
#include <unordered_map>
#include <thread>

#include "common/murmur2.h"

namespace iroha { namespace performance_tools {

enum ReferencePointers {
    kRefPoint_0 = 0,
    kRefPoint_1,
    kRefPoint_2,
    kRefPoint_3,
    kRefPoint_4,
    kRefPointsCount
};

enum struct SortType : uint32_t {
    kSortByEntries = 0,
    kSortByCounter,
};

using Hash = uint32_t;
using PerformanceCounter = uint64_t;

class IReportStackIterator {
public:
    virtual ~IReportStackIterator() {}
    virtual std::string& printStacks(std::string& dst) = 0;

    virtual bool stackFirst() = 0;
    virtual bool stackNext() = 0;

    virtual bool unwindStackFirst() = 0;
    virtual bool unwindStackNext() = 0;

    virtual void sortStacks(SortType type, bool asc) = 0;
    virtual bool getStackFrameName(char const *&name, Hash &id) const = 0;
    virtual bool getStackFrameEntries(uint64_t &entries) const = 0;
    virtual bool getStackFrameCounter(uint64_t &counter) const = 0;
};

class IReportMethodIterator {
public:
    virtual ~IReportMethodIterator() {}
    virtual std::string& printMethods(std::string& dst) = 0;

    virtual bool methodFirst() = 0;
    virtual bool methodNext() = 0;

    virtual void sortMethods(SortType type, bool asc) = 0;
    virtual bool getMethodId(Hash &id) const = 0;
    virtual bool getMethodName(char const *&name) const = 0;
    virtual bool getMethodEntries(uint64_t &entries) const = 0;
    virtual bool getMethodCounter(uint64_t &counter) const = 0;
    virtual bool getMethodPointCounter(ReferencePointers pt, uint64_t &counter) const = 0;
};

class IReportThreadIterator {
public:
    virtual ~IReportThreadIterator() {}

    virtual bool threadAtMergedThreadData() = 0;
    virtual bool threadFirst() = 0;
    virtual bool threadNext() = 0;

    virtual IReportMethodIterator& getMethodIterator() = 0;
    virtual IReportStackIterator& getStackIterator() = 0;
};

class IReportViewer {
public:
    virtual ~IReportViewer() {}
    virtual void mergeThreadData() = 0;

    virtual IReportThreadIterator& getThreadIterator() = 0;
};

/// initialization
extern void initThreadProfiler();
extern void deinitThreadProfiler();

/// functions performance profiling
extern void pushFunctionEntry(Hash f_hash);
extern void popFunctionEntry(PerformanceCounter value, char const* tag);
extern void setPointValue(ReferencePointers point, PerformanceCounter value, char const* tag);

/// reporting
extern void prepareThreadReport();
extern void getThreadReport(std::unique_ptr<IReportViewer>& report);

class ProfilerMarker final {
    char const* const tag_;
    timespec begin_;

    ProfilerMarker(ProfilerMarker const&) = delete;
    ProfilerMarker(ProfilerMarker&&) = delete;

    ProfilerMarker& operator=(ProfilerMarker const&) = delete;
    ProfilerMarker& operator=(ProfilerMarker&&) = delete;

    inline PerformanceCounter getCounter() const {
        timespec end;
        clock_gettime(CLOCK_MONOTONIC_RAW, &end);

        return ((end.tv_sec - begin_.tv_sec) * 1000000000ull +
            (end.tv_nsec - begin_.tv_nsec));
    }

public:
    ProfilerMarker(Hash f_hash, char const *tag) : tag_(tag) {
        assert(nullptr != tag_);
        pushFunctionEntry(f_hash);
        clock_gettime(CLOCK_MONOTONIC_RAW, &begin_);
    }
    ~ProfilerMarker() {
        popFunctionEntry(getCounter(), tag_);
    }
    PerformanceCounter getValue() const {
        return getCounter();
    }
};

}}

#ifdef PROFILER_ADD_FUNCTION
#   error PROFILER_ADD_FUNCTION already defined
#endif//PROFILER_ADD_FUNCTION
#ifdef ENABLE_PROFILER
#   define PROFILER_ADD_FUNCTION \
        enum { kProfilerFunctionMarker = CT_MURMUR2(__PRETTY_FUNCTION__) }; \
        ::iroha::performance_tools::ProfilerMarker __profiler_marker__ (kProfilerFunctionMarker, __PRETTY_FUNCTION__)
#else//ENABLE_PROFILER
#   define PROFILER_ADD_FUNCTION (void)0
#endif//ENABLE_PROFILER

#ifdef PROFILER_ADD_POINT
#   error PROFILER_ADD_POINT already defined
#endif//PROFILER_ADD_POINT
#ifdef ENABLE_PROFILER
#   define PROFILER_ADD_POINT(pt) ::iroha::performance_tools::setPointValue(pt, __profiler_marker__.getValue(), __PRETTY_FUNCTION__);
#else//ENABLE_PROFILER
#   define PROFILER_ADD_POINT(pt) (void)0
#endif//ENABLE_PROFILER

#ifdef PROFILER_ADD_POINT_0
#   error PROFILER_ADD_POINT_0 already defined
#endif//PROFILER_ADD_POINT_0
#define PROFILER_ADD_POINT_0 PROFILER_ADD_POINT(::iroha::performance_tools::ReferencePointers::kRefPoint_0)

#ifdef PROFILER_ADD_POINT_1
#   error PROFILER_ADD_POINT_1 already defined
#endif//PROFILER_ADD_POINT_1
#define PROFILER_ADD_POINT_1 PROFILER_ADD_POINT(::iroha::performance_tools::ReferencePointers::kRefPoint_1)

#ifdef PROFILER_ADD_POINT_2
#   error PROFILER_ADD_POINT_2 already defined
#endif//PROFILER_ADD_POINT_2
#define PROFILER_ADD_POINT_2 PROFILER_ADD_POINT(::iroha::performance_tools::ReferencePointers::kRefPoint_2)

#ifdef PROFILER_ADD_POINT_3
#   error PROFILER_ADD_POINT_3 already defined
#endif//PROFILER_ADD_POINT_3
#define PROFILER_ADD_POINT_3 PROFILER_ADD_POINT(::iroha::performance_tools::ReferencePointers::kRefPoint_3)

#ifdef PROFILER_ADD_POINT_4
#   error PROFILER_ADD_POINT_4 already defined
#endif//PROFILER_ADD_POINT_4
#define PROFILER_ADD_POINT_4 PROFILER_ADD_POINT(::iroha::performance_tools::ReferencePointers::kRefPoint_4)

#endif//IROHA_PROFILER_HPP
