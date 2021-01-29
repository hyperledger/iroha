package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.Metrics.Cpu;

/**
 * SCALE reader for Metrics.Cpu
 */
public class CpuReader implements ScaleReader<Cpu> {

  @Override
  public Cpu read(ScaleCodecReader reader) {
    return new Cpu(reader.read(new LoadReader()));
  }

}
