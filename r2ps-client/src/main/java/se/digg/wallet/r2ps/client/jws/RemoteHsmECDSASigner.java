package se.digg.wallet.r2ps.client.jws;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.impl.ECDSAProvider;
import com.nimbusds.jose.util.Base64URL;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import se.digg.wallet.r2ps.client.api.R2PSClientApi;
import se.digg.wallet.r2ps.commons.dto.payload.ByteArrayPayload;
import se.digg.wallet.r2ps.commons.dto.payload.SignRequestPayload;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceType;
import se.digg.wallet.r2ps.commons.exception.PakeAuthenticationException;
import se.digg.wallet.r2ps.commons.exception.PakeSessionException;
import se.digg.wallet.r2ps.commons.exception.PayloadParsingException;
import se.digg.wallet.r2ps.commons.exception.ServiceRequestException;
import se.digg.wallet.r2ps.commons.exception.ServiceResponseException;
import se.digg.wallet.r2ps.commons.pake.ECUtils;

@Slf4j
public class RemoteHsmECDSASigner extends ECDSAProvider implements JWSSigner {

  private final R2PSClientApi clientApi;
  private final String hsmContext;
  private final String hsmKeyIdentifier;
  private final String sessionId;

  public RemoteHsmECDSASigner(
      final R2PSClientApi clientApi,
      final String hsmContext,
      final String hsmKeyIdentifier,
      JWSAlgorithm jwsAlgorithm,
      final String sessionId)
      throws JsonProcessingException, JOSEException {
    super(jwsAlgorithm);
    this.clientApi = clientApi;
    this.hsmContext = hsmContext;
    this.hsmKeyIdentifier = hsmKeyIdentifier;
    this.sessionId = sessionId;
  }

  @Override
  public Base64URL sign(final JWSHeader header, final byte[] signingInput) throws JOSEException {

    log.debug(
        "ECDSA Signing with JWS remote signer using kid {}, context {} and signed data hash {}",
        hsmKeyIdentifier,
        hsmContext,
        Hex.toHexString(signingInput));
    try {
      final String algorithmName = header.getAlgorithm().getName();
      final int signaturePartLength = getSignaturePartLength(algorithmName);
      String digestAlgorithm = getDigestAlgorithm(algorithmName);
      final SignRequestPayload ecdsaSignRequest =
          SignRequestPayload.builder()
              .kid(hsmKeyIdentifier)
              .tbsHash(signingInput, digestAlgorithm)
              .build();
      byte[] signatureValue =
          clientApi
              .userAuthenticatedService(
                  ServiceType.HSM_ECDSA, ecdsaSignRequest, hsmContext, sessionId)
              .getPayload(ByteArrayPayload.class)
              .getByteArrayValue();
      log.debug("Produced ASN.1 formatted ECDSA signature: {}", Hex.toHexString(signatureValue));
      return Base64URL.encode(
          ECUtils.ecdsaSignatureAsn1ToConcat(signatureValue, signaturePartLength));
    } catch (PakeSessionException
        | ServiceResponseException
        | IOException
        | PayloadParsingException
        | NoSuchAlgorithmException
        | PakeAuthenticationException
        | ServiceRequestException e) {
      throw new JOSEException(e);
    }
  }

  private String getDigestAlgorithm(final String algorithm) throws JOSEException {
    return switch (algorithm) {
      case "ES256" -> "SHA-256";
      case "ES384" -> "SHA-384";
      case "ES512" -> "SHA-512";
      default -> throw new JOSEException("Unsupported JWS algorithm: " + algorithm);
    };
  }

  public static int getSignaturePartLength(final String algorithm) throws JOSEException {
    return switch (algorithm) {
      case "ES256" -> 32;
      case "ES384" -> 48;
      case "ES512" -> 66;
      default -> throw new JOSEException("Unsupported JWS algorithm: " + algorithm);
    };
  }
}
