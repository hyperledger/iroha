package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.And;

public class AndReader implements ScaleReader<And> {

  private static final ExpressionReader EXPRESSION_READER = new ExpressionReader();

  @Override
  public And read(ScaleCodecReader reader) {
    return new And(reader.read(EXPRESSION_READER), reader.read(EXPRESSION_READER));
  }
}
