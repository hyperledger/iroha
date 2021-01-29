package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.Identifiable;

public class IdentifiableReader implements ScaleReader<Identifiable> {

  private static final IdentifiableBoxReader IDENTIFIABLE_BOX_READER = new IdentifiableBoxReader();

  @Override
  public Identifiable read(ScaleCodecReader reader) {
    return new Identifiable(reader.read(IDENTIFIABLE_BOX_READER));
  }
}
