package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.Metrics.Cpu.Load;

/**
 * SCALE reader for Metrics.Cpu.Load
 */
public class LoadReader implements ScaleReader<Load> {

  @Override
  public Load read(ScaleCodecReader reader) {
    return new Load(reader.readString(), reader.readString(), reader.readString());
  }

}
