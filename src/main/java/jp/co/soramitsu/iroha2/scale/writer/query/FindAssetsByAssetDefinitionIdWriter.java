package jp.co.soramitsu.iroha2.scale.writer.query;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.query.FindAssetsByAssetDefinitionId;
import jp.co.soramitsu.iroha2.scale.writer.DefinitionIdWriter;

class FindAssetsByAssetDefinitionIdWriter implements ScaleWriter<FindAssetsByAssetDefinitionId> {

  private static final DefinitionIdWriter DEFINITION_ID_WRITER = new DefinitionIdWriter();

  @Override
  public void write(ScaleCodecWriter writer, FindAssetsByAssetDefinitionId value)
      throws IOException {
    DEFINITION_ID_WRITER.write(writer, value.getAssetDefinitionId());
  }
}
