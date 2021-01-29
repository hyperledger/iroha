package jp.co.soramitsu.iroha2.scale.writer;

public class ScaleWriterFixture {

  /**
   * Encodes byte array to JSON list of unsigned bytes.
   *
   * @param bytes to compare
   * @return JSON string
   */
  protected String bytesToJsonString(byte[] bytes) {
    if (bytes.length == 0) {
      return "[]";
    }
    StringBuilder sb = new StringBuilder("[");
    for (int i = 0; i < bytes.length - 1; i++) {
      sb.append(Byte.toUnsignedInt(bytes[i]));
      sb.append(',');
    }
    sb.append(Byte.toUnsignedInt(bytes[bytes.length - 1]));
    sb.append(']');
    return sb.toString();
  }

}
