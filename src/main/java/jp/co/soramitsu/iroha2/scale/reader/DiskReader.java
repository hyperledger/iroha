package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.Metrics.Disk;

/**
 * SCALE reader for Metrics.Disk
 */
public class DiskReader implements ScaleReader<Disk> {

  @Override
  public Disk read(ScaleCodecReader reader) {
    return new Disk(reader.readUint32(), reader.readString());
  }

}
