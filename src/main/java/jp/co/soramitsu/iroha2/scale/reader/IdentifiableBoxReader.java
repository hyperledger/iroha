package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import io.emeraldpay.polkaj.scale.reader.UnionReader;
import jp.co.soramitsu.iroha2.model.IdentifiableBox;

public class IdentifiableBoxReader implements ScaleReader<IdentifiableBox> {

  private static final UnionReader<IdentifiableBox> IDENTIFIABLE_BOX_UNION_READER = new UnionReader<>(
      new AccountReader(), // 0 Account
      new AssetReader(), // 1 Asset
      new AssetDefinitionReader(), // 2 AssetDefinition
      new DomainReader(), // 3 Domain
      new PeerReader(), // 4 Peer
      new WorldReader() // 5 World
  );

  @Override
  public IdentifiableBox read(ScaleCodecReader reader) {
    return reader.read(IDENTIFIABLE_BOX_UNION_READER).getValue();
  }
}
