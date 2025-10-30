package se.digg.wallet.r2ps.client.jws.pkds;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.BaseJWSProvider;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.jose.util.StandardCharset;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.Setter;

public class HSPKDSProvider extends BaseJWSProvider {

  public static final String PKDS_HEADER_PARAM = "pkds";
  public static final JWSAlgorithm HS256_PKDS_ALGORITHM = HSPKDSAlgorithm.HS256_PKDS.getAlg();
  public static final JWSAlgorithm HS384_PKDS_ALGORITHM = HSPKDSAlgorithm.HS384_PKDS.getAlg();
  public static final JWSAlgorithm HS512_PKDS_ALGORITHM = HSPKDSAlgorithm.HS512_PKDS.getAlg();

  /** The supported JWS algorithms by the HS-PKDS provider class. */
  public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;

  public static final Set<PKDSSuite> SUPPORTED_PKDSSUITES;

  static {
    Set<JWSAlgorithm> algs = new LinkedHashSet<>();
    algs.add(HS256_PKDS_ALGORITHM);
    algs.add(HS384_PKDS_ALGORITHM);
    algs.add(HS512_PKDS_ALGORITHM);
    SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
    Set<PKDSSuite> pkdsSuites = new LinkedHashSet<>();
    pkdsSuites.add(PKDSSuite.ECDH_HKDF_SHA256);
    SUPPORTED_PKDSSUITES = Collections.unmodifiableSet(pkdsSuites);
  }

  /** The secret, {@code null} if specified as {@link SecretKey}. */
  @Setter private byte[] secret;

  /** The secret key, {@code null} if specified as byte array. */
  @Setter private SecretKey secretKey;

  public HSPKDSProvider(final JWSAlgorithm alg) throws JOSEException {

    super(Collections.singleton(alg));

    if (!SUPPORTED_ALGORITHMS.contains(alg)) {
      throw new JOSEException("Unsupported EC DSA algorithm: " + alg);
    }
  }

  /**
   * Retrieves the public key from the provided PKDSPublicKey instance. The public key can be
   * extracted from the JSON Web Key (JWK) or the X.509 certificate contained in the PKDSPublicKey.
   *
   * @param pkdsPublicKey the PKDSPublicKey instance containing the key information, such as a JWK
   *     or X.509 certificate. Must not be null.
   * @return the extracted public key as a {@code PublicKey} object, or {@code null} if neither the
   *     JWK nor the X.509 certificate is present.
   * @throws JOSEException if an error occurs during the key extraction process, such as issues with
   *     the provided JWK or certificate.
   */
  public static PublicKey getPkdsPublicKey(final PKDSPublicKey pkdsPublicKey) throws JOSEException {
    try {
      final JWK jwk = pkdsPublicKey.getJwk();
      if (jwk != null) {
        if (jwk instanceof RSAKey) {
          return ((RSAKey) jwk).toRSAPublicKey();
        }
        if (jwk instanceof ECKey) {
          return ((ECKey) jwk).toECPublicKey();
        }
        throw new JOSEException("Unsupported JWK type");
      }
      final X509Certificate x509Certificate = pkdsPublicKey.getX509Certificate();
      if (x509Certificate != null) {
        return x509Certificate.getPublicKey();
      }
    } catch (Exception e) {
      throw new JOSEException("Failed to get recipient public key", e);
    }
    return null;
  }

  /**
   * Returns the compatible JWS HMAC algorithms for the specified secret length.
   *
   * @param secretLength The secret length in bits. Must not be negative.
   * @return The compatible HMAC algorithms, empty set if the secret length is too short for any
   *     algorithm.
   */
  public static Set<JWSAlgorithm> getCompatibleAlgorithms(final int secretLength) {

    Set<JWSAlgorithm> hmacAlgs = new LinkedHashSet<>();

    if (secretLength >= 256) {
      hmacAlgs.add(HS256_PKDS_ALGORITHM);
    }

    if (secretLength >= 384) {
      hmacAlgs.add(HS384_PKDS_ALGORITHM);
    }

    if (secretLength >= 512) {
      hmacAlgs.add(HS512_PKDS_ALGORITHM);
    }

    return Collections.unmodifiableSet(hmacAlgs);
  }

  /**
   * Returns the minimal required secret length for the specified HMAC JWS algorithm.
   *
   * @param alg The HMAC JWS algorithm. Must be {@link #SUPPORTED_ALGORITHMS supported} and not
   *     {@code null}.
   * @return The minimal required secret length, in bits.
   * @throws JOSEException If the algorithm is not supported.
   */
  public static int getMinRequiredSecretLength(final JWSAlgorithm alg) throws JOSEException {

    if (HS256_PKDS_ALGORITHM.equals(alg)) {
      return 256;
    } else if (HS384_PKDS_ALGORITHM.equals(alg)) {
      return 384;
    } else if (HS512_PKDS_ALGORITHM.equals(alg)) {
      return 512;
    } else {
      throw new JOSEException(
          AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, SUPPORTED_ALGORITHMS));
    }
  }

  /**
   * Gets the matching Java Cryptography Architecture (JCA) algorithm name for the specified
   * HMAC-based JSON Web Algorithm (JWA).
   *
   * @param alg The JSON Web Algorithm (JWA). Must be supported and not {@code null}.
   * @return The matching JCA algorithm name.
   * @throws JOSEException If the algorithm is not supported.
   */
  protected static String getJCAAlgorithmName(final JWSAlgorithm alg) throws JOSEException {

    if (alg.equals(HS256_PKDS_ALGORITHM)) {
      return "HMACSHA256";
    } else if (alg.equals(HS384_PKDS_ALGORITHM)) {
      return "HMACSHA384";
    } else if (alg.equals(HS512_PKDS_ALGORITHM)) {
      return "HMACSHA512";
    } else {
      throw new JOSEException(
          AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, SUPPORTED_ALGORITHMS));
    }
  }

  /**
   * Gets the secret key.
   *
   * @return The secret key.
   */
  public SecretKey getSecretKey() {
    if (this.secretKey != null) {
      return secretKey;
    } else if (secret != null) {
      return new SecretKeySpec(secret, "MAC");
    } else {
      throw new IllegalStateException("Unexpected state");
    }
  }

  /**
   * Gets the secret bytes.
   *
   * @return The secret bytes, {@code null} if this provider was constructed with a {@link
   *     SecretKey} that doesn't expose the key material.
   */
  public byte[] getSecret() {
    if (this.secretKey != null) {
      return secretKey.getEncoded();
    } else if (secret != null) {
      return secret;
    } else {
      throw new IllegalStateException("Unexpected state");
    }
  }

  /**
   * Gets the secret as a UTF-8 encoded string.
   *
   * @return The secret as a UTF-8 encoded string, {@code null} if this provider was constructed
   *     with a {@link SecretKey} that doesn't expose the key material.
   */
  public String getSecretString() {

    byte[] secret = getSecret();

    if (secret == null) {
      return null;
    }

    return new String(secret, StandardCharset.UTF_8);
  }

  /**
   * Ensures the secret length satisfies the minimum required for the specified HMAC JWS algorithm.
   *
   * @param alg The HMAC JWS algorithm. Must be {@link #SUPPORTED_ALGORITHMS supported} and not
   *     {@code null}.
   * @throws JOSEException If the algorithm is not supported.
   * @throws KeyLengthException If the secret length is shorter than the minimum required.
   */
  protected void ensureSecretLengthSatisfiesAlgorithm(final JWSAlgorithm alg) throws JOSEException {

    if (getSecret() == null) {
      // Secret not available (HSM)
      return;
    }

    final int minRequiredBitLength = getMinRequiredSecretLength(alg);

    if (ByteUtils.bitLength(getSecret()) < minRequiredBitLength) {
      throw new KeyLengthException(
          "The secret length for " + alg + " must be at least " + minRequiredBitLength + " bits");
    }
  }
}
