package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.Contains;

public class ContainsReader implements ScaleReader<Contains> {

  private static final ExpressionReader EXPRESSION_READER = new ExpressionReader();

  @Override
  public Contains read(ScaleCodecReader reader) {
    return new Contains(reader.read(EXPRESSION_READER), reader.read(EXPRESSION_READER));
  }
}
