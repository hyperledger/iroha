package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import io.emeraldpay.polkaj.scale.reader.UnionReader;
import jp.co.soramitsu.iroha2.model.IdBox;

public class IdBoxReader implements ScaleReader<IdBox> {

  private static final UnionReader<IdBox> ID_BOX_READER = new UnionReader<>(
      new AccountIdReader(), // 0 AccountId
      new AssetIdReader(), // 1 AssetId
      new AssetDefinitionIdReader(), // 2 AssetDefinitionId
      new DomainNameReader(), // 3 DomainName
      new PeerIdReader(), // 4 PeerIdReader
      new WorldIdReader() // 5 WorldId
  );

  @Override
  public IdBox read(ScaleCodecReader reader) {
    return reader.read(ID_BOX_READER).getValue();
  }
}
