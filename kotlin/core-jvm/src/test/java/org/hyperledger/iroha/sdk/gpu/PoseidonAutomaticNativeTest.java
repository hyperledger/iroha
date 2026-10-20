package org.hyperledger.iroha.sdk.gpu;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.function.Function;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Automatic native Poseidon parity; successful CPU fallback never qualifies CUDA hardware. */
final class PoseidonAutomaticNativeTest {
  private static Accelerators accelerators;

  @BeforeAll
  static void loadRebuiltHostBridge() {
    String directory = System.getProperty("java.library.path");
    assertNotNull(directory);
    File library = new File(directory, System.mapLibraryName("connect_norito_bridge"));
    assertTrue(library.isAbsolute());
    assertTrue(library.isFile(), "Build the host bridge before native parity tests");
    accelerators = Accelerators.loadNative(library.getAbsolutePath());
  }

  @Test
  void poseidon2MatchesCpuGoldensInBatchesAndSingleItemBatches() {
    // Independent circomlib v0.1.7 tables with canonical arity-domain sponge/output1;
    // mirrored by crates/ivm/tests/poseidon_simd.rs, POSEIDON2_VECTORS.
    // Negative Java longs retain the Rust u64 bit pattern.
    long[][] inputs = {{0, 0}, {1, 0}, {0, 1}, {1, 1}, {-1L, -1L}};
    long[] expected = {
        0x291ef55ced504e95L, 0x7e84e4660f9c8602L, 0xbe233ae487cc493cL,
        0xc129be072c4b4483L, 0xc389da81dbddae68L
    };
    assertPoseidonBatch(inputs, expected, accelerators::poseidon2);
  }

  @Test
  void poseidon6MatchesCpuGoldensInBatchesAndSingleItemBatches() {
    // Same independent profile, two additive rate-five blocks and output1;
    // mirrored by crates/ivm/tests/poseidon_simd.rs, POSEIDON6_VECTORS.
    long[][] inputs = {
        {0, 0, 0, 0, 0, 0}, {1, 2, 3, 4, 5, 6}, {1, 0, 0, 0, 0, 0},
        {0, 1, 0, 0, 0, 0}, {-1L, -1L, -1L, -1L, -1L, -1L}
    };
    long[] expected = {
        0xb5284c49a2aa43ddL, 0xea5537703da851ecL, 0x44126d1870284f85L,
        0x741cdca6d19888b3L, 0x732ec89a4e972a38L
    };
    assertPoseidonBatch(inputs, expected, accelerators::poseidon6);
  }

  private static void assertPoseidonBatch(
      long[][] inputs, long[] expected, Function<long[][], long[]> operation) {
    long[] batch = operation.apply(inputs);
    assertNotNull(batch, "Native backend must compute the complete Poseidon batch successfully");
    assertArrayEquals(expected, batch, "Native output must equal the CPU golden bit patterns");
    for (int index = 0; index < inputs.length; index++) {
      long[] single = operation.apply(new long[][] {inputs[index]});
      assertNotNull(single, "Native backend must compute every single-item Poseidon batch");
      assertArrayEquals(new long[] {batch[index]}, single, "batch order and size-one equivalence");
      }
  }


}
