package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.Bool;

public class BoolReader implements ScaleReader<Bool> {

  @Override
  public Bool read(ScaleCodecReader reader) {
    return new Bool(reader.readBoolean());
  }

}
