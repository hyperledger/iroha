package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.Add;

public class AddReader implements ScaleReader<Add> {

  private static final ExpressionReader EXPRESSION_READER = new ExpressionReader();

  @Override
  public Add read(ScaleCodecReader reader) {
    return new Add(reader.read(EXPRESSION_READER), reader.read(EXPRESSION_READER));
  }
}
