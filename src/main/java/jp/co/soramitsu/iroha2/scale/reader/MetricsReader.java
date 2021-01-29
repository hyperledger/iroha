package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.Metrics;

/**
 * SCALE reader for Metrics
 */
public class MetricsReader implements ScaleReader<Metrics> {

  @Override
  public Metrics read(ScaleCodecReader reader) {
    return new Metrics(reader.read(new CpuReader()), reader.read(new DiskReader()),
        reader.read(new MemoryReader()));
  }

}
