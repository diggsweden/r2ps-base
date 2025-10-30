package se.digg.wallet.r2ps.commons.jwe;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import java.security.interfaces.ECPublicKey;

public final class AsymmetricJweEncryptor implements JweEncryptor {
  private final ECPublicKey staticPublicRecipientKey;
  private final EncryptionMethod algorithm;

  public AsymmetricJweEncryptor(ECPublicKey staticPublicRecipientKey, EncryptionMethod algorithm) {
    this.staticPublicRecipientKey = staticPublicRecipientKey;
    this.algorithm = algorithm;
  }

  @Override
  public byte[] encrypt(byte[] plaintext) throws JOSEException {
    JWEHeader header =
        new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, algorithm)
            .contentType("application/octet-stream") // Optional
            .build();

    JWEObject jweObject = new JWEObject(header, new Payload(plaintext));

    JWEEncrypter encrypter = new ECDHEncrypter(staticPublicRecipientKey);
    jweObject.encrypt(encrypter);

    return jweObject.serialize().getBytes();
  }
}
