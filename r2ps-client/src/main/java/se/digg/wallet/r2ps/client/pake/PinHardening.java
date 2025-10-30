package se.digg.wallet.r2ps.client.pake;

import java.security.PrivateKey;

public interface PinHardening {

  /**
   * Hardens a PIN by processing the provided PIN, private key, and desired output byteLength.
   *
   * @param pin the input PIN as a byte array
   * @param privateKey the private key used for the hardening process
   * @param byteLength the desired byteLength of the resulting hardened PIN byte array
   * @return a byte array containing the hardened PIN
   */
  byte[] process(String pin, PrivateKey privateKey, int byteLength);
}
