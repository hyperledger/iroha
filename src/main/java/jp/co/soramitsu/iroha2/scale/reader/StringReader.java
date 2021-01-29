package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;

public class StringReader implements ScaleReader<String> {

  @Override
  public String read(ScaleCodecReader reader) {
    return reader.readString();
  }
}
