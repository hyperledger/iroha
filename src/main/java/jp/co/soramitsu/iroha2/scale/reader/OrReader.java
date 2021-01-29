package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.Or;

public class OrReader implements ScaleReader<Or> {

  private static final ExpressionReader EXPRESSION_READER = new ExpressionReader();

  @Override
  public Or read(ScaleCodecReader reader) {
    return new Or(reader.read(EXPRESSION_READER), reader.read(EXPRESSION_READER));
  }
}
