package se.digg.wallet.r2ps.commons.utils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import java.io.IOException;
import java.security.interfaces.ECPrivateKey;
import java.text.ParseException;
import org.bouncycastle.util.encoders.Hex;
import se.digg.wallet.r2ps.commons.StaticResources;
import se.digg.wallet.r2ps.commons.dto.JWEEncryptionParams;

public class Utils {

  public static byte[] decryptJWE(byte[] jweData, JWEEncryptionParams decryptionParams)
      throws JOSEException, ParseException {
    JWEObject jweObject = JWEObject.parse(new String(jweData));
    JWEDecrypter decrypter = new DirectDecrypter(decryptionParams.key());
    jweObject.decrypt(decrypter);
    return jweObject.getPayload().toBytes();
  }

  public static byte[] encryptJWE(byte[] jweData, JWEEncryptionParams encryptionParams)
      throws JOSEException {
    JWEEncrypter encrypter = new DirectEncrypter(encryptionParams.key());
    JWEHeader jweHeader =
        new JWEHeader.Builder(JWEAlgorithm.DIR, encryptionParams.algorithm()).build();
    JWEObject jweObject = new JWEObject(jweHeader, new Payload(jweData));
    jweObject.encrypt(encrypter);
    return jweObject.serialize().getBytes();
  }

  // Encrypt using ECDH-ES + AES-GCM with server’s static EC public key
  public static byte[] encryptJWE_ECDH(byte[] plaintext, JWEEncryptionParams encryptionParams)
      throws JOSEException {
    // Create JWE header with ECDH-ES algorithm and encryption method
    JWEHeader header =
        new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, encryptionParams.algorithm())
            .contentType("application/octet-stream") // Optional
            .build();

    // Create the JWE object with payload
    JWEObject jweObject = new JWEObject(header, new Payload(plaintext));

    // Encrypt with recipient’s public key (ephemeral key pair is generated internally)
    JWEEncrypter encrypter = new ECDHEncrypter(encryptionParams.staticPublicRecipientKey());
    jweObject.encrypt(encrypter);

    return jweObject.serialize().getBytes();
  }

  // Decrypt using server’s static EC private key
  public static byte[] decryptJWE_ECDH(byte[] jweData, ECPrivateKey privateKey)
      throws JOSEException, ParseException {
    JWEObject jweObject = JWEObject.parse(new String(jweData));
    JWEDecrypter decrypter = new ECDHDecrypter(privateKey);
    jweObject.decrypt(decrypter);
    return jweObject.getPayload().toBytes();
  }

  /**
   * Formats a byte array into a human-readable string. Attempts to interpret the byte array as
   * JSON, and if successful, returns the pretty-printed JSON string. If the byte array does not
   * represent valid JSON but is printable ASCII, it converts and returns the byte array as a
   * string. Otherwise, returns the hexadecimal representation of the byte array.
   *
   * @param decryptedPayload the byte array to be formatted
   * @return a human-readable string representation of the byte array, either as pretty-printed
   *     JSON, plain text if printable, or hexadecimal if non-printable
   */
  public static String prettyPrintByteArray(final byte[] decryptedPayload) {
    try {
      // Try JSON format
      return StaticResources.TIME_STAMP_SECONDS_MAPPER
          .writerWithDefaultPrettyPrinter()
          .writeValueAsString(StaticResources.TIME_STAMP_SECONDS_MAPPER.readTree(decryptedPayload));
    } catch (IOException e) {
      if (isPrintable(decryptedPayload)) {
        return new String(decryptedPayload);
      }
      return Hex.toHexString(decryptedPayload);
    }
  }

  public static boolean isPrintable(byte[] bytes) {
    for (byte b : bytes) {
      // ASCII printable characters range from 32 (space) to 126 (~)
      if (b < 32 || b > 126) {
        return false;
      }
    }
    return true;
  }
}
