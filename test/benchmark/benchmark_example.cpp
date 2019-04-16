/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

///
/// Documentation is at https://github.com/google/benchmark
///
/// General recommendations:
///  - build with -DCMAKE_BUILD_TYPE=Release
///  - disable CPU scaling (frequency changes depending on workload)
///  - put initialization code in fixtures
///  - write meaningful names for benchmarks
///

#include <benchmark/benchmark.h>
#include <string>

/// Test how long is empty std::string creation
// define a static function, which accepts 'state'
// function's name = benchmark's name
static void BM_StringCreation(benchmark::State &state) {
  // define main benchmark loop
  while (state.KeepRunning()) {
    // define the code to be tested
    std::string empty_string;
  }
}
// define benchmark
BENCHMARK(BM_StringCreation);

/// That's all. More in documentation.

// don't forget to include this:
BENCHMARK_MAIN();
