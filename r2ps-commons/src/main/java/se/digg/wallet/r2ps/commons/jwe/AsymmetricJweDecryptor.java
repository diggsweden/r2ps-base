package se.digg.wallet.r2ps.commons.jwe;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import java.security.interfaces.ECPrivateKey;
import java.text.ParseException;

public class AsymmetricJweDecryptor implements JweDecryptor {
  private final ECPrivateKey staticPrivateRecipientKey;

  public AsymmetricJweDecryptor(ECPrivateKey staticPrivateRecipientKey) {
    this.staticPrivateRecipientKey = staticPrivateRecipientKey;
  }

  public byte[] decrypt(byte[] jweData) throws JOSEException, ParseException {
    JWEObject jweObject = JWEObject.parse(new String(jweData));
    JWEDecrypter decrypter = new ECDHDecrypter(staticPrivateRecipientKey);
    jweObject.decrypt(decrypter);
    return jweObject.getPayload().toBytes();
  }
}
