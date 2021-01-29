package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.Metrics.Memory;

/**
 * SCALE reader for Metrics.Memory
 */
public class MemoryReader implements ScaleReader<Memory> {

  @Override
  public Memory read(ScaleCodecReader reader) {
    return new Memory(reader.readString(), reader.readString());
  }

}
