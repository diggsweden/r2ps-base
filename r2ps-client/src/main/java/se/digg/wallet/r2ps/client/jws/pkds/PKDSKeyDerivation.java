package se.digg.wallet.r2ps.client.jws.pkds;

import com.nimbusds.jose.JOSEException;
import java.security.interfaces.ECPublicKey;

public interface PKDSKeyDerivation {

  boolean supports(PKDSSuite suite);

  byte[] deriveKey(PKDSHeaderParam pkdsHeaderParam, ECPublicKey publicKey, int minimumKeyByteLen)
      throws JOSEException;
}
