package se.digg.wallet.r2ps.commons.dto;

import com.nimbusds.jose.EncryptionMethod;

import javax.crypto.SecretKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public record JWEEncryptionParams(
    SecretKey key,
    ECPublicKey staticPublicRecipientKey,
    ECPrivateKey staticPrivateRecipientKey,
    EncryptionMethod algorithm
) {
  public JWEEncryptionParams(final SecretKey key, final EncryptionMethod algorithm) {
    this(key, null, null, algorithm);
  }

  public JWEEncryptionParams(final ECPublicKey staticPublicRecipientKey,
      final EncryptionMethod algorithm) {
    this(null, staticPublicRecipientKey, null, algorithm);
  }

  public JWEEncryptionParams(final ECPrivateKey staticPrivateRecipientKey,
      final EncryptionMethod algorithm) {
    this(null, null, staticPrivateRecipientKey, algorithm);
  }
}
