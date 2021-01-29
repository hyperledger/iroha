package jp.co.soramitsu.iroha2;

import java.security.KeyPair;
import javax.xml.bind.DatatypeConverter;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

public class Utils {

  public static KeyPair EdDSAKeyPairFromHexPrivateKey(String hex) {
    byte[] privateKeyBytes = DatatypeConverter.parseHexBinary(hex);
    EdDSANamedCurveSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
    EdDSAPrivateKey privateKey = new EdDSAPrivateKey(
        new EdDSAPrivateKeySpec(privateKeyBytes, spec));
    EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(privateKey.getA(), spec);
    return new KeyPair(new EdDSAPublicKey(pubKey), privateKey);
  }

  /**
   * Public key is ASN.1 DER encoded and has 44 bytes, the `actual` public key is only last 32
   * bytes
   *
   * @param publicKeyBytes - ASN.1 DER encoded public key bytes
   * @return actual public key bytes
   */
  public static byte[] getActualPublicKey(byte[] publicKeyBytes) {
    byte[] actualPubkeyBytes = new byte[32];
    System.arraycopy(publicKeyBytes, 12, actualPubkeyBytes, 0, 32);
    return actualPubkeyBytes;
  }

}
