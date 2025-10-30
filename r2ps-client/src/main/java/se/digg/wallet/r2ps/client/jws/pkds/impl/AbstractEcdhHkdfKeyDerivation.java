package se.digg.wallet.r2ps.client.jws.pkds.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.Base64URL;
import java.security.interfaces.ECPublicKey;
import java.util.Optional;
import lombok.NoArgsConstructor;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.util.DigestFactory;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSHeaderParam;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSKeyDerivation;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSParams;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSSuite;

@NoArgsConstructor
public abstract class AbstractEcdhHkdfKeyDerivation implements PKDSKeyDerivation {

  public static final String DEFAULT_HKDF_INFO = "HS256-PKDS-v1";

  @Override
  public byte[] deriveKey(
      PKDSHeaderParam pkdsHeaderParam, ECPublicKey publicKey, int minimumKeyByteLen)
      throws JOSEException {
    // Extract pkds parameters
    final PKDSParams pkdsParams =
        Optional.ofNullable(pkdsHeaderParam.getParams()).orElse(PKDSParams.builder().build());
    final Base64URL info =
        Optional.ofNullable(pkdsParams.getInfo())
            .orElse(Base64URL.encode(DEFAULT_HKDF_INFO.getBytes()));
    final Base64URL salt = pkdsParams.getSalt();
    final int length = Optional.ofNullable(pkdsHeaderParam.getLength()).orElse(minimumKeyByteLen);
    final PKDSSuite suite = pkdsHeaderParam.getSuite();
    Digest digest = DigestFactory.cloneDigest(suite.getDigest());
    byte[] dhSharedSecret = diffieHellman(publicKey);

    // Do HKDF
    HKDFBytesGenerator hkdf = new HKDFBytesGenerator(digest);
    HKDFParameters params =
        new HKDFParameters(dhSharedSecret, salt != null ? salt.decode() : null, info.decode());
    hkdf.init(params);
    byte[] encKey = new byte[length];
    hkdf.generateBytes(encKey, 0, length);
    // Set the secret key in the HMAC Signer
    return encKey;
  }

  protected abstract byte[] diffieHellman(ECPublicKey publicKey) throws JOSEException;
}
