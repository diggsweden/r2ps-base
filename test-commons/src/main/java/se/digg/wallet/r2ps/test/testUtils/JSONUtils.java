// SPDX-FileCopyrightText: 2024 diggsweden/eudiw-wallet-token-lib
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.r2ps.test.testUtils;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Base64;

/** Utility class providing methods related to JSON data processing. */
public class JSONUtils {

  /**
   * A globally accessible and preconfigured instance of the Jackson {@code ObjectMapper} for
   * handling JSON serialization and deserialization.
   *
   * <ul>
   *   <li>Configured to disable writing dates as timestamps ({@code
   *       SerializationFeature.WRITE_DATES_AS_TIMESTAMPS}).
   *   <li>Supports Java 8 date and time types through the registration of {@code JavaTimeModule}.
   *   <li>Excludes properties with {@code null} values during serialization, using {@code
   *       JsonInclude.Include.NON_NULL}.
   * </ul>
   *
   * This object is intended to be reused anywhere in the application to ensure consistent JSON
   * processing behavior.
   */
  public static final ObjectMapper JSON_MAPPER =
      new ObjectMapper()
          .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
          .registerModule(new JavaTimeModule())
          .setSerializationInclusion(JsonInclude.Include.NON_NULL);

  /**
   * Encodes the given byte array into a Base64 URL-encoded string without padding.
   *
   * @param bytes the byte array to be encoded
   * @return a Base64 URL-encoded string representation of the input byte array
   */
  public static String base64URLString(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  /**
   * Computes the hash of the given byte array using the specified hashing algorithm.
   *
   * @param input the input byte array to be hashed
   * @param algo the name of the hashing algorithm to use (e.g., "SHA-256")
   * @return a byte array representing the hash of the input
   * @throws NoSuchAlgorithmException if the specified hashing algorithm is not available
   */
  public static byte[] hash(byte[] input, String algo) throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance(algo);
    return digest.digest(input);
  }

  /**
   * Computes a Base64 URL-encoded hash string of the given byte array input using the specified
   * hashing algorithm.
   *
   * @param input the byte array to be hashed
   * @param alg the name of the hashing algorithm to use (e.g., "SHA-256")
   * @return a Base64 URL-encoded string representation of the computed hash
   * @throws NoSuchAlgorithmException if the specified hashing algorithm is not available
   */
  public static String b64UrlHash(byte[] input, String alg) throws NoSuchAlgorithmException {
    return base64URLString(hash(input, alg));
  }

  /**
   * Converts a given public key into a JSON Web Key (JWK) representation.
   *
   * @param publicKey the public key to convert, which can be either an RSA or EC public key
   * @return the JWK representation of the given public key
   * @throws NoSuchAlgorithmException if the type of the provided public key is not supported
   */
  public static JWK getJWKfromPublicKey(PublicKey publicKey) throws NoSuchAlgorithmException {
    if (publicKey instanceof RSAPublicKey) {
      return new RSAKey.Builder((RSAPublicKey) publicKey).build();
    }
    if (publicKey instanceof ECPublicKey ecPublicKey) {
      ECParameterSpec params = ecPublicKey.getParams();
      return new ECKey.Builder(Curve.forECParameterSpec(params), (ECPublicKey) publicKey).build();
    }
    throw new NoSuchAlgorithmException("Public key type not supported");
  }

  /**
   * Retrieves a public key from the given JSON Web Key (JWK) object. The JWK can either be of type
   * RSAKey or ECKey.
   *
   * @param jwk the JSON Web Key (JWK) object from which the public key should be extracted. Must be
   *     an instance of RSAKey or ECKey.
   * @return the extracted public key as a {@code PublicKey} object.
   * @throws JOSEException if an error occurs during the public key extraction process.
   * @throws IllegalArgumentException if the provided JWK is of an unsupported type.
   */
  public static PublicKey getPublicKeyFromJWK(JWK jwk) throws JOSEException {
    if (jwk instanceof RSAKey) {
      return ((RSAKey) jwk).toRSAPublicKey();
    }
    if (jwk instanceof ECKey) {
      return ((ECKey) jwk).toECPublicKey();
    }
    throw new IllegalArgumentException("Unsupported JWK type");
  }
}
