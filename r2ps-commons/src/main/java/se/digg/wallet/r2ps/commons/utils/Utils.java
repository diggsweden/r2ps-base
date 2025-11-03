package se.digg.wallet.r2ps.commons.utils;

import java.io.IOException;
import org.bouncycastle.util.encoders.Hex;
import se.digg.wallet.r2ps.commons.StaticResources;

public class Utils {

  /**
   * Formats a byte array into a human-readable string. Attempts to interpret the byte array as
   * JSON, and if successful, returns the pretty-printed JSON string. If the byte array does not
   * represent valid JSON but is printable ASCII, it converts and returns the byte array as a
   * string. Otherwise, returns the hexadecimal representation of the byte array.
   *
   * @param decryptedPayload the byte array to be formatted
   * @return a human-readable string representation of the byte array, either as pretty-printed
   *         JSON, plain text if printable, or hexadecimal if non-printable
   */
  public static String prettyPrintByteArray(final byte[] decryptedPayload) {
    try {
      // Try JSON format
      return StaticResources.TIME_STAMP_SECONDS_MAPPER
          .writerWithDefaultPrettyPrinter()
          .writeValueAsString(StaticResources.TIME_STAMP_SECONDS_MAPPER.readTree(decryptedPayload));
    } catch (IOException e) {
      if (isPrintable(decryptedPayload)) {
        return new String(decryptedPayload);
      }
      return Hex.toHexString(decryptedPayload);
    }
  }

  public static boolean isPrintable(byte[] bytes) {
    for (byte b : bytes) {
      // ASCII printable characters range from 32 (space) to 126 (~)
      if (b < 32 || b > 126) {
        return false;
      }
    }
    return true;
  }
}
