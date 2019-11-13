/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ed25519/ed25519.h>

#include <cstdlib>
#include <vector>

#include <benchmark/benchmark.h>

auto ConstructRandomVector(size_t size) {
  using T = unsigned char;
  std::vector<T> v;
  v.reserve(size);
  for (size_t i = 0; i < size; ++i) {
    v.push_back(static_cast<T>(std::rand() % size));
  }
  return v;
}

static void BM_CreateKeypair(benchmark::State &state) {
  public_key_t pub{};
  private_key_t priv{};

  while (state.KeepRunning()) {
    ed25519_create_keypair(&priv, &pub);
  }
}
BENCHMARK(BM_CreateKeypair);

static void BM_Sign(benchmark::State &state) {
  public_key_t pub{};
  private_key_t priv{};
  signature_t sig{};

  ed25519_create_keypair(&priv, &pub);

  while (state.KeepRunning()) {
    state.PauseTiming();
    auto data = ConstructRandomVector(state.range(0));
    state.ResumeTiming();

    ed25519_sign(&sig, data.data(), data.size(), &pub, &priv);
  }
}
BENCHMARK(BM_Sign)->RangeMultiplier(2)->Range(1 << 10, 1 << 18);

static void BM_Verify(benchmark::State &state) {
  public_key_t pub{};
  private_key_t priv{};
  signature_t sig{};

  ed25519_create_keypair(&priv, &pub);

  while (state.KeepRunning()) {
    state.PauseTiming();
    auto data = ConstructRandomVector(state.range(0));
    ed25519_sign(&sig, data.data(), data.size(), &pub, &priv);
    state.ResumeTiming();

    ed25519_verify(&sig, data.data(), data.size(), &pub);
  }
}
BENCHMARK(BM_Verify)->RangeMultiplier(2)->Range(1 << 10, 1 << 18);

BENCHMARK_MAIN();
