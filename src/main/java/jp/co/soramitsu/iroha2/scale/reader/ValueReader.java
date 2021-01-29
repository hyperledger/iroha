package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.Value;

public class ValueReader implements ScaleReader<Value> {

  private static final ValueBoxReader VALUE_BOX_READER = new ValueBoxReader();

  @Override
  public Value read(ScaleCodecReader reader) {
    return new Value(reader.read(VALUE_BOX_READER));
  }

}
