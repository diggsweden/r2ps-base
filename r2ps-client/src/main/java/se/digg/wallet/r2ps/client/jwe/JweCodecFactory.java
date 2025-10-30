package se.digg.wallet.r2ps.client.jwe;

import com.nimbusds.jose.EncryptionMethod;
import java.security.interfaces.ECPrivateKey;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import se.digg.wallet.r2ps.client.api.ClientContextConfiguration;
import se.digg.wallet.r2ps.client.pake.opaque.ClientPakeRecord;
import se.digg.wallet.r2ps.commons.jwe.AsymmetricJweDecryptor;
import se.digg.wallet.r2ps.commons.jwe.AsymmetricJweEncryptor;
import se.digg.wallet.r2ps.commons.jwe.JweCodec;
import se.digg.wallet.r2ps.commons.jwe.SymmetricJweCipher;

public class JweCodecFactory {
  private final EncryptionMethod encryptionMethod;

  public JweCodecFactory(EncryptionMethod encryptionMethod) {
    this.encryptionMethod = encryptionMethod;
  }

  /**
   * Creates a JweCodec for (asymmetric) device authentication.
   *
   * @param clientContextConfiguration the client context configuration.
   * @return JweCodec with asymmetric encryptor and decryptor.
   */
  public JweCodec forDeviceAuthentication(ClientContextConfiguration clientContextConfiguration) {
    AsymmetricJweEncryptor encryptor =
        new AsymmetricJweEncryptor(
            clientContextConfiguration.getServerPublicKey(), encryptionMethod);

    AsymmetricJweDecryptor decryptor =
        new AsymmetricJweDecryptor(
            (ECPrivateKey) clientContextConfiguration.getContextKeyPair().getPrivate());

    return new JweCodec(encryptor, decryptor);
  }

  /**
   * Creates a JweCodec for (symmetric) user authentication.
   *
   * @param pakeSession the client's PAKE session record.
   * @return JweCodec with symmetric encryptor and decryptor.
   */
  public JweCodec forUserAuthentication(ClientPakeRecord pakeSession) {
    if (pakeSession.getSessionKey() == null) {
      throw new IllegalStateException("Session key is null. Cannot create JweCodec");
    }

    SecretKey secretKey = new SecretKeySpec(pakeSession.getSessionKey(), "AES");
    SymmetricJweCipher cipher = new SymmetricJweCipher(secretKey, encryptionMethod);
    return new JweCodec(cipher, cipher);
  }
}
