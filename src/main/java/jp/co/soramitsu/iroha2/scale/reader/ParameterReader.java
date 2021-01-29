package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.Parameter;

public class ParameterReader implements ScaleReader<Parameter> {

  private static final ParameterBoxReader PARAMETER_BOX_READER = new ParameterBoxReader();

  @Override
  public Parameter read(ScaleCodecReader reader) {
    return new Parameter(reader.read(PARAMETER_BOX_READER));
  }

}
