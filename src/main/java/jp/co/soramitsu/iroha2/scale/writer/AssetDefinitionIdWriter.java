package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.AssetDefinitionId;

public class AssetDefinitionIdWriter implements ScaleWriter<AssetDefinitionId> {

  private static final DefinitionIdWriter DEFINITION_ID_WRITER = new DefinitionIdWriter();

  @Override
  public void write(ScaleCodecWriter writer, AssetDefinitionId value) throws IOException {
    writer.write(DEFINITION_ID_WRITER, value.getAssetDefinitionId());
  }
}
