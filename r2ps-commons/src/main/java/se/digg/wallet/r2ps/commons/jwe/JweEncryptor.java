package se.digg.wallet.r2ps.commons.jwe;

import com.nimbusds.jose.JOSEException;

public interface JweEncryptor {

  byte[] encrypt(byte[] data) throws JOSEException;
}
