package se.digg.wallet.r2ps.client.jws;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64URL;
import se.digg.wallet.r2ps.client.api.R2PSClientApi;
import se.digg.wallet.r2ps.client.jws.pkds.HSPKDSAlgorithm;
import se.digg.wallet.r2ps.client.jws.pkds.HSPKDSProvider;

public class RemoteHsPkdsSigner extends HSPKDSProvider implements JWSSigner {

  private final R2PSClientApi clientApi;
  private final String hsmContext;
  private final String hsmKeyIdentifier;
  private final String sessionId;

  public RemoteHsPkdsSigner(
      final HSPKDSAlgorithm hsPkdsAlgorithm,
      final R2PSClientApi clientApi,
      final String hsmContext,
      final String hsmKeyIdentifier,
      final String sessionId)
      throws JOSEException {
    super(hsPkdsAlgorithm.getAlg());
    this.clientApi = clientApi;
    this.hsmContext = hsmContext;
    this.hsmKeyIdentifier = hsmKeyIdentifier;
    this.sessionId = sessionId;
  }

  @Override
  public Base64URL sign(final JWSHeader header, final byte[] signingInput) throws JOSEException {
    return null;
  }
}
