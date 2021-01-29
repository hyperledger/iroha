package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import io.emeraldpay.polkaj.scale.reader.ListReader;
import jp.co.soramitsu.iroha2.model.Value;
import jp.co.soramitsu.iroha2.model.Vector;

public class VectorReader implements ScaleReader<Vector> {

  private static final ListReader<Value> LIST_READER = new ListReader<>(new ValueReader());

  @Override
  public Vector read(ScaleCodecReader reader) {
    return new Vector(LIST_READER.read(reader));
  }

}
