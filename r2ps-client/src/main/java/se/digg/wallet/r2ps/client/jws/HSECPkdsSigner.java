package se.digg.wallet.r2ps.client.jws;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.impl.HMAC;
import com.nimbusds.jose.util.Base64URL;
import se.digg.wallet.r2ps.client.jws.pkds.HSPKDSAlgorithm;
import se.digg.wallet.r2ps.client.jws.pkds.HSPKDSProvider;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSHeaderParam;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSKeyDerivation;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSPublicKey;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSSuite;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class HSECPkdsSigner extends HSPKDSProvider implements JWSSigner {

  private final List<PKDSKeyDerivation> supportedKeyDerivations;
  public ECPublicKey recipientPublicKey;

  public HSECPkdsSigner(final HSPKDSAlgorithm hsPkdsAlgorithm,
      List<PKDSKeyDerivation> supportedKeyDerivations,
      ECPublicKey recipientKey) throws JOSEException {
    super(hsPkdsAlgorithm.getAlg());
    this.supportedKeyDerivations = supportedKeyDerivations;
    this.recipientPublicKey = recipientKey;
  }

  public HSECPkdsSigner(final HSPKDSAlgorithm hsPkdsAlgorithm,
      PKDSKeyDerivation supportedKeyDerivations,
      ECPublicKey recipientKey) throws JOSEException {
    this(hsPkdsAlgorithm, List.of(supportedKeyDerivations), recipientKey);
  }

  public HSECPkdsSigner(final HSPKDSAlgorithm hsPkdsAlgorithm,
      List<PKDSKeyDerivation> supportedKeyDerivations)
      throws JOSEException {
    this(hsPkdsAlgorithm, supportedKeyDerivations, null);
  }

  public HSECPkdsSigner(final HSPKDSAlgorithm hsPkdsAlgorithm,
      PKDSKeyDerivation supportedKeyDerivation)
      throws JOSEException {
    this(hsPkdsAlgorithm, List.of(supportedKeyDerivation), null);
  }

  public ECPublicKey getRecipientKey(final PKDSHeaderParam pkdsHeaderParam) throws JOSEException {
    final PKDSPublicKey pkdsPublicKey = Optional.ofNullable(pkdsHeaderParam.getRecipientPublicKey())
        .orElseThrow(() -> new IllegalArgumentException("Recipient public key must be provided"));
    PublicKey publicKey = getPkdsPublicKey(pkdsPublicKey);
    if (publicKey == null) {
      throw new JOSEException("Failed to get recipient public key");
    }
    if (publicKey instanceof ECPublicKey) {
      return (ECPublicKey) publicKey;
    }
    throw new JOSEException("Unsupported public key type");
  }

  /** {@inheritDoc} */
  @Override
  public Base64URL sign(final JWSHeader header, final byte[] signingInput) throws JOSEException {
    try {
      // Get PKDS Header params
      if (header.getCustomParam(PKDS_HEADER_PARAM) == null) {
        throw new IllegalArgumentException("PKDS header parameter not found");
      }
      final PKDSHeaderParam pkdsHeaderParam =
          PKDSHeaderParam.parse((Map<?, ?>) header.getCustomParam(PKDS_HEADER_PARAM));
      // If the recipient public key was not provided, extract it from the pkds header.
      if (this.recipientPublicKey == null) {
        this.recipientPublicKey = getRecipientKey(pkdsHeaderParam);
      }

      final PKDSSuite suite = pkdsHeaderParam.getSuite();
      final PKDSKeyDerivation pkdsKeyDerivation = supportedKeyDerivations.stream()
          .filter(keyDerivation -> keyDerivation.supports(suite))
          .findFirst()
          .orElseThrow(() -> new JOSEException("Unsupported PKDS suite: " + suite));

      setSecret(pkdsKeyDerivation.deriveKey(pkdsHeaderParam, recipientPublicKey,
          getMinRequiredSecretLength(header.getAlgorithm()) / 8));
      // Check key length
      ensureSecretLengthSatisfiesAlgorithm(header.getAlgorithm());
      // Sign
      String jcaAlg = getJCAAlgorithmName(header.getAlgorithm());
      byte[] hmac =
          HMAC.compute(jcaAlg, getSecretKey(), signingInput, getJCAContext().getProvider());
      // Return signature value
      return Base64URL.encode(hmac);
    } catch (Exception e) {
      throw new JOSEException("ECDH key agreement failed", e);
    }
  }

}
