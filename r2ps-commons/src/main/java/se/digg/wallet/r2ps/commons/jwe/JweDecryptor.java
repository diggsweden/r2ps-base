package se.digg.wallet.r2ps.commons.jwe;

import com.nimbusds.jose.JOSEException;
import java.text.ParseException;

public interface JweDecryptor {

  byte[] decrypt(byte[] data) throws JOSEException, ParseException;
}
