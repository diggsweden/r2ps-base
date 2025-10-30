package se.digg.wallet.r2ps.commons.jwe;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import com.nimbusds.jose.EncryptionMethod;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import org.junit.jupiter.api.Test;
import se.digg.wallet.r2ps.test.data.TestCredentials;

class AsymmetricEncryptionTest {
  @Test
  void testAsymmetricEncryptionDecryption() throws Exception {
    ECPublicKey recipientPublicKey = (ECPublicKey) TestCredentials.serverOprfKeyPair.getPublic();
    ECPrivateKey recipientPrivateKey =
        (ECPrivateKey) TestCredentials.serverOprfKeyPair.getPrivate();

    AsymmetricJweEncryptor jweEncryptor =
        new AsymmetricJweEncryptor(recipientPublicKey, EncryptionMethod.A256GCM);

    AsymmetricJweDecryptor jweDecryptor = new AsymmetricJweDecryptor(recipientPrivateKey);

    byte[] plainText = "1234".getBytes();
    final byte[] encryptedData = jweEncryptor.encrypt(plainText);
    final byte[] decryptedData = jweDecryptor.decrypt(encryptedData);

    assertArrayEquals(plainText, decryptedData);
  }
}
