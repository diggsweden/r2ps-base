package se.digg.wallet.r2ps.client.jws;

import com.nimbusds.jose.CriticalHeaderParamsAware;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.impl.HMAC;
import com.nimbusds.jose.util.Base64URL;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import lombok.Setter;
import se.digg.wallet.r2ps.client.jws.pkds.HSPKDSAlgorithm;
import se.digg.wallet.r2ps.client.jws.pkds.HSPKDSProvider;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSHeaderParam;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSKeyDerivation;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSPublicKey;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSSuite;

public class HSECPkdsVerifier extends HSPKDSProvider
    implements JWSVerifier, CriticalHeaderParamsAware {
  @Setter
  Set<String> deferredCriticalHeaderParams;
  private final List<PKDSKeyDerivation> supportedKeyDerivations;
  protected ECPublicKey producerPublicKey;

  public HSECPkdsVerifier(
      final HSPKDSAlgorithm alg,
      List<PKDSKeyDerivation> supportedKeyDerivations,
      ECPublicKey producerPublicKey)
      throws JOSEException {
    super(alg.getAlg());
    this.deferredCriticalHeaderParams = Set.of();
    this.producerPublicKey = producerPublicKey;
    this.supportedKeyDerivations = supportedKeyDerivations;
  }

  public HSECPkdsVerifier(
      final HSPKDSAlgorithm alg,
      PKDSKeyDerivation supportedKeyDerivation,
      ECPublicKey producerPublicKey)
      throws JOSEException {
    this(alg, List.of(supportedKeyDerivation), producerPublicKey);
  }

  public HSECPkdsVerifier(
      final HSPKDSAlgorithm alg, List<PKDSKeyDerivation> supportedKeyDerivations)
      throws JOSEException {
    this(alg, supportedKeyDerivations, null);
  }

  public HSECPkdsVerifier(final HSPKDSAlgorithm alg, PKDSKeyDerivation supportedKeyDerivation)
      throws JOSEException {
    this(alg, List.of(supportedKeyDerivation), null);
  }

  @Override
  public Set<String> getProcessedCriticalHeaderParams() {
    return Set.of(PKDS_HEADER_PARAM);
  }

  @Override
  public Set<String> getDeferredCriticalHeaderParams() {
    return this.deferredCriticalHeaderParams != null ? this.deferredCriticalHeaderParams : Set.of();
  }

  @Override
  public boolean verify(
      final JWSHeader header, final byte[] signingInput, final Base64URL signature)
      throws JOSEException {
    try {
      // Get PKDS Header params
      if (header.getCustomParam(PKDS_HEADER_PARAM) == null) {
        throw new IllegalArgumentException("PKDS header parameter not found");
      }
      final PKDSHeaderParam pkdsHeaderParam =
          PKDSHeaderParam.parse((Map<?, ?>) header.getCustomParam(PKDS_HEADER_PARAM));
      // If the recipient public key was not provided, extract it from the pkds header.
      if (this.producerPublicKey == null) {
        this.producerPublicKey = getProducerKey(pkdsHeaderParam);
      }

      final PKDSSuite suite = pkdsHeaderParam.getSuite();
      final PKDSKeyDerivation pkdsKeyDerivation =
          supportedKeyDerivations.stream()
              .filter(keyDerivation -> keyDerivation.supports(suite))
              .findFirst()
              .orElseThrow(() -> new JOSEException("Unsupported PKDS suite: " + suite));

      setSecret(
          pkdsKeyDerivation.deriveKey(
              pkdsHeaderParam,
              producerPublicKey,
              getMinRequiredSecretLength(header.getAlgorithm()) / 8));
      // Check key length
      ensureSecretLengthSatisfiesAlgorithm(header.getAlgorithm());
      // Sign
      String jcaAlg = getJCAAlgorithmName(header.getAlgorithm());
      byte[] hmacSignature =
          HMAC.compute(jcaAlg, getSecretKey(), signingInput, getJCAContext().getProvider());
      return Arrays.equals(hmacSignature, signature.decode());
    } catch (Exception e) {
      throw new JOSEException("Error validating signature", e);
    }
  }

  protected ECPublicKey getProducerKey(final PKDSHeaderParam pkdsHeaderParam) throws JOSEException {
    final PKDSPublicKey pkdsPublicKey =
        Optional.ofNullable(pkdsHeaderParam.getProducerPublicKey())
            .orElseThrow(
                () -> new IllegalArgumentException("Producer public key must be provided"));
    PublicKey publicKey = getPkdsPublicKey(pkdsPublicKey);
    if (publicKey == null) {
      throw new JOSEException("Failed to get producer public key");
    }
    if (publicKey instanceof ECPublicKey) {
      return (ECPublicKey) publicKey;
    }
    throw new JOSEException("Unsupported public key type");
  }
}
