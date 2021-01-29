package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.Parameter;

public class ParameterWriter implements ScaleWriter<Parameter> {

  private static final ParameterBoxWriter PARAMETER_BOX_WRITER = new ParameterBoxWriter();

  @Override
  public void write(ScaleCodecWriter writer, Parameter value) throws IOException {
    writer.write(PARAMETER_BOX_WRITER, value.getValue());
  }

}
