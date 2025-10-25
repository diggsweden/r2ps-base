package se.digg.wallet.r2ps.client.jws.pkds.impl;

import com.nimbusds.jose.JOSEException;
import se.digg.wallet.r2ps.client.api.R2PSClientApi;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSSuite;
import se.digg.wallet.r2ps.commons.dto.payload.ByteArrayPayload;
import se.digg.wallet.r2ps.commons.dto.payload.DHRequestPayload;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceType;
import se.digg.wallet.r2ps.commons.exception.PakeAuthenticationException;
import se.digg.wallet.r2ps.commons.exception.PakeSessionException;
import se.digg.wallet.r2ps.commons.exception.PayloadParsingException;
import se.digg.wallet.r2ps.commons.exception.ServiceRequestException;
import se.digg.wallet.r2ps.commons.exception.ServiceResponseException;

import java.security.interfaces.ECPublicKey;

public class RemoteHsmPKDSKeyDerivation extends AbstractEcdhHkdfKeyDerivation {

  private final R2PSClientApi clientApi;
  private final String hsmContext;
  private final String hsmKeyIdentifier;
  private final String sessionId;

  public RemoteHsmPKDSKeyDerivation(final R2PSClientApi clientApi, final String hsmContext,
      final String hsmKeyIdentifier,
      final String sessionId) {
    this.clientApi = clientApi;
    this.hsmContext = hsmContext;
    this.hsmKeyIdentifier = hsmKeyIdentifier;
    this.sessionId = sessionId;
  }

  @Override
  public boolean supports(final PKDSSuite suite) {
    return PKDSSuite.ECDH_HKDF_SHA256.equals(suite);
  }

  @Override
  protected byte[] diffieHellman(final ECPublicKey recipientPublicKey)
      throws JOSEException {
    try {
      return clientApi.userAuthenticatedService(ServiceType.HSM_ECDH,
          DHRequestPayload.builder()
              .kid(hsmKeyIdentifier)
              .publicKey(recipientPublicKey)
              .build(),
          hsmContext, sessionId).getPayload(ByteArrayPayload.class).getByteArrayValue();
    } catch (PakeAuthenticationException | ServiceRequestException | PakeSessionException |
        PayloadParsingException |
        ServiceResponseException e) {
      throw new JOSEException("Failed to perform Remote HSM Diffie-Hellman", e);
    }
  }
}
