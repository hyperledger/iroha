package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.Asset;

public class AssetReader implements ScaleReader<Asset> {

  private static final AssetIdReader ASSET_ID_READER = new AssetIdReader();
  private static final U32Reader U_32_READER = new U32Reader();
  private static final U128Reader U_128_READER = new U128Reader();
  private static final StringReader STRING_READER = new StringReader();
  private static final MapReader<String, String> MAP_READER = new MapReader<>(STRING_READER,
      STRING_READER);

  @Override
  public Asset read(ScaleCodecReader reader) {
    return new Asset(ASSET_ID_READER.read(reader), U_32_READER.read(reader),
        U_128_READER.read(reader), MAP_READER.read(reader));
  }
}
