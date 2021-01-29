package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;

public class StringWriter implements ScaleWriter<String> {

  @Override
  public void write(ScaleCodecWriter writer, String value) throws IOException {
    writer.writeAsList(value.getBytes());
  }

}
