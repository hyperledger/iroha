package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.Not;

public class NotReader implements ScaleReader<Not> {

  private static final ExpressionReader EXPRESSION_READER = new ExpressionReader();

  @Override
  public Not read(ScaleCodecReader reader) {
    return new Not(reader.read(EXPRESSION_READER));
  }
}
