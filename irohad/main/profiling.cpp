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
    static boost::filesystem::path profiling_path;
    static const std::string mem_profile_prefix = "mem";
    static std::chrono::system_clock::time_point cpu_start_time;
    static std::string current_cpu_profile_path;

    static std::string getDateTime(const char *format) {
      std::time_t t = std::time(nullptr);
      std::tm tm = *std::localtime(&t);
      std::stringstream time_ss;
      time_ss << std::put_time(&tm, format);
      return std::move(time_ss).str();
    }

    static boost::filesystem::path nextCpuProfilePath(size_t ms_elapsed) {
      static size_t counter = 1;
      std::ostringstream ss;
      ss << "cpu." << std::setfill('0') << std::setw(4) << counter++ << "."
         << ms_elapsed << ".prof";
      return profiling_path / ss.str();
    }

    void flushCpuProfile() {
#if PROFILING_CPU
      if (is_profiled) {
        ProfilerFlush();
        ProfilerStop();

        const auto ms_elapsed =
            (std::chrono::system_clock::now() - cpu_start_time)
            / std::chrono::milliseconds(1);
        boost::filesystem::rename(current_cpu_profile_path,
                                  nextCpuProfilePath(ms_elapsed));

        cpu_start_time = std::chrono::system_clock::now();
        ProfilerStart(current_cpu_profile_path.c_str());
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
      profiling_path = path_to_profiles;
      profiling_path /= getDateTime("%FT%T");
      boost::filesystem::create_directory(profiling_path);
      current_cpu_profile_path = (profiling_path / "cpu_in_progress").string();
      is_profiled = true;

#if PROFILING_CPU
      cpu_start_time = std::chrono::system_clock::now();
      ProfilerStart(current_cpu_profile_path.c_str());
#endif
#if PROFILING_HEAP
      HeapProfilerStart(
          (profiling_path / mem_profile_prefix).string().c_str());
#endif
    }

    void stopProfiling() {
      if (is_profiled) {
#if PROFILING_CPU
        flushCpuProfile();
        ProfilerStop();
        std::cerr << "CPU profiles are available at " << profiling_path << "."
                  << std::endl;
#endif
#if PROFILING_HEAP
        flushMemProfile();
        HeapProfilerStop();
        std::cerr << "Heap profiles are available at " << profiling_path << "."
                  << std::endl;
#endif
      }
    }
  }  // namespace debug
}  // namespace iroha
