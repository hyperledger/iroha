package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.Less;

public class LessReader implements ScaleReader<Less> {

  private static final ExpressionReader EXPRESSION_READER = new ExpressionReader();

  @Override
  public Less read(ScaleCodecReader reader) {
    return new Less(reader.read(EXPRESSION_READER), reader.read(EXPRESSION_READER));
  }
}
