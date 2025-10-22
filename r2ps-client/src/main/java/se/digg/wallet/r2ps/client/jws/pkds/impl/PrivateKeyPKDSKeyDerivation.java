package se.digg.wallet.r2ps.client.jws.pkds.impl;

import com.nimbusds.jose.JOSEException;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSSuite;

import javax.crypto.KeyAgreement;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class PrivateKeyPKDSKeyDerivation extends AbstractEcdhHkdfKeyDerivation {

  private final ECPrivateKey dhPrivateKey;

  public PrivateKeyPKDSKeyDerivation(final ECPrivateKey dhPrivateKey) {
    this.dhPrivateKey = dhPrivateKey;
  }

  @Override
  public boolean supports(final PKDSSuite suite) {
    return PKDSSuite.ECDH_HKDF_SHA256.equals(suite);
  }

  @Override
  protected byte[] diffieHellman(final ECPublicKey publicKey)
      throws JOSEException {
    try {
      KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
      keyAgreement.init(dhPrivateKey);
      keyAgreement.doPhase(publicKey, true);
      return keyAgreement.generateSecret();
    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      throw new JOSEException("Failed to derive Diffie-Hellman shared secret", e);
    }
  }
}
