package se.digg.wallet.r2ps.commons.utils;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.EncryptionMethod;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.crypto.opaque.OpaqueUtils;
import se.digg.wallet.r2ps.commons.dto.JWEEncryptionParams;
import se.digg.wallet.r2ps.test.data.TestCredentials;

@Slf4j
class UtilsTest {

  @BeforeAll
  static void setUp() throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
  }

  @Test
  void testJwe() throws Exception {
    SecretKey secretKey = new SecretKeySpec(OpaqueUtils.random(32), "AES");
    JWEEncryptionParams encryptionParams =
        new JWEEncryptionParams(secretKey, EncryptionMethod.A256GCM);
    byte[] plainText = "1234".getBytes();
    log.debug("Plaintext: {}", new String(plainText, "UTF-8"));
    final byte[] encryptedData = Utils.encryptJWE(plainText, encryptionParams);
    log.debug("Encrypted data: {}", new String(encryptedData, "UTF-8"));
    final byte[] decryptedData = Utils.decryptJWE(encryptedData, encryptionParams);
    log.debug("Decrypted data: {}", new String(decryptedData, "UTF-8"));
    assertArrayEquals(plainText, decryptedData);
  }

  @Test
  void testJweECDH() throws Exception {
    ECPublicKey recipientPublicKey = (ECPublicKey) TestCredentials.serverOprfKeyPair.getPublic();
    ECPrivateKey recipientPrivateKey =
        (ECPrivateKey) TestCredentials.serverOprfKeyPair.getPrivate();
    JWEEncryptionParams encryptionParams =
        new JWEEncryptionParams(recipientPublicKey, EncryptionMethod.A256GCM);
    JWEEncryptionParams decryptionParams =
        new JWEEncryptionParams(recipientPrivateKey, EncryptionMethod.A256GCM);
    byte[] plainText = "1234".getBytes();
    log.debug("Plaintext: {}", new String(plainText, "UTF-8"));
    final byte[] encryptedData = Utils.encryptJWEECDH(plainText, encryptionParams);
    log.debug("Encrypted data: {}", new String(encryptedData, "UTF-8"));
    final byte[] decryptedData =
        Utils.decryptJWEECDH(encryptedData, decryptionParams.staticPrivateRecipientKey());
    log.debug("Decrypted data: {}", new String(decryptedData, "UTF-8"));
    assertArrayEquals(plainText, decryptedData);
  }
}
