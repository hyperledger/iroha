package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.Raw;

public class RawReader implements ScaleReader<Raw> {

  private static final ValueReader VALUE_READER = new ValueReader();

  @Override
  public Raw read(ScaleCodecReader reader) {
    return new Raw(reader.read(VALUE_READER));
  }
}
