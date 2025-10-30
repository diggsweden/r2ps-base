package se.digg.wallet.r2ps.commons.jwe;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.EncryptionMethod;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import se.digg.crypto.opaque.OpaqueUtils;

class SymmetricJweCipherTest {
  @Test
  void testSymmetricEncryptionDecryption() throws Exception {
    SecretKey secretKey = new SecretKeySpec(OpaqueUtils.random(32), "AES");
    SymmetricJweCipher jweCipher = new SymmetricJweCipher(secretKey, EncryptionMethod.A256GCM);

    byte[] plainText = "1234".getBytes();
    final byte[] encryptedData = jweCipher.encrypt(plainText);
    final byte[] decryptedData = jweCipher.decrypt(encryptedData);

    assertArrayEquals(plainText, decryptedData);
  }
}
