package se.digg.wallet.r2ps.commons.jwe;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import java.text.ParseException;
import javax.crypto.SecretKey;

public class SymmetricJweCipher implements JweEncryptor, JweDecryptor {
  private final SecretKey key;
  private final EncryptionMethod algorithm;

  public SymmetricJweCipher(SecretKey key, EncryptionMethod algorithm) {
    this.key = key;
    this.algorithm = algorithm;
  }

  @Override
  public byte[] encrypt(byte[] data) throws JOSEException {
    JWEEncrypter encrypter = new DirectEncrypter(key);
    JWEHeader jweHeader = new JWEHeader.Builder(JWEAlgorithm.DIR, algorithm).build();
    JWEObject jweObject = new JWEObject(jweHeader, new Payload(data));
    jweObject.encrypt(encrypter);
    return jweObject.serialize().getBytes();
  }

  @Override
  public byte[] decrypt(byte[] jweData) throws JOSEException, ParseException {
    JWEObject jweObject = JWEObject.parse(new String(jweData));
    JWEDecrypter decrypter = new DirectDecrypter(key);
    jweObject.decrypt(decrypter);
    return jweObject.getPayload().toBytes();
  }
}
