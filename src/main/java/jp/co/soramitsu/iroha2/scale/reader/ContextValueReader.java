package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.ContextValue;

public class ContextValueReader implements ScaleReader<ContextValue> {

  @Override
  public ContextValue read(ScaleCodecReader reader) {
    return new ContextValue(reader.readString());
  }
}
