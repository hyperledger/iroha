/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/profiling.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

#if PROFILING_CPU
#include <gperftools/profiler.h>
#endif
#if PROFILING_HEAP
#include <gperftools/heap-profiler.h>
#endif
#include <boost/filesystem.hpp>

namespace iroha {
  namespace debug {
    static bool is_profiled = false;
    static boost::filesystem::path profiling_path_cpu;
    static boost::filesystem::path profiling_path_mem;

    static std::string getDateTime(const char *format) {
      std::time_t t = std::time(nullptr);
      std::tm tm = *std::localtime(&t);
      std::stringstream time_ss;
      time_ss << std::put_time(&tm, "%FT%T");
      return std::move(time_ss).str();
    }

    static std::string nextCpuProfilePath() {
      static size_t counter = 1;
      static auto start_time = std::chrono::system_clock::now();
      const auto ms_elapsed = (std::chrono::system_clock::now() - start_time)
          / std::chrono::milliseconds(1);
      std::ostringstream ss;
      ss << "." << std::setfill('0') << std::setw(4) << counter++ << "."
         << std::setw(0) << ms_elapsed << ".prof";
      return profiling_path_cpu.string() + ss.str();
    }

    void flushCpuProfile() {
#if PROFILING_CPU
      if (is_profiled) {
        ProfilerFlush();
        ProfilerStop();
        ProfilerStart(nextCpuProfilePath().c_str());
      }
#endif
    }

    void flushMemProfile() {
#if PROFILING_HEAP
      if (is_profiled) {
        ProfilerFlush();
        HeapProfilerDump("flush");
      }
#endif
    }

    void startProfiling(std::string path_to_profiles) {
      boost::filesystem::path profiling_path = path_to_profiles;
      profiling_path /= getDateTime("%FT%T");
      boost::filesystem::create_directory(profiling_path);
      profiling_path_cpu = profiling_path / "cpu";
      profiling_path_mem = profiling_path / "mem";
      is_profiled = true;

#if PROFILING_CPU
      ProfilerStart(nextCpuProfilePath().c_str());
#endif
#if PROFILING_HEAP
      HeapProfilerStart(profiling_path_mem.string().c_str());
#endif
    }

    void stopProfiling() {
      if (is_profiled) {
#if PROFILING_CPU
        flushCpuProfile();
        ProfilerStop();
        std::cerr << "CPU profiles are available at " << profiling_path_cpu
                  << "." << std::endl;
#endif
#if PROFILING_HEAP
        flushMemProfile();
        HeapProfilerStop();
        std::cerr << "Heap profiles are available at " << profiling_path_mem
                  << "." << std::endl;
#endif
      }
    }
  }  // namespace debug
}  // namespace iroha
