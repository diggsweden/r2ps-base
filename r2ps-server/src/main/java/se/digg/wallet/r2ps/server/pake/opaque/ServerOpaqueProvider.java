package se.digg.wallet.r2ps.server.pake.opaque;

import lombok.Getter;
import org.bouncycastle.util.encoders.Hex;
import se.digg.crypto.opaque.OpaqueUtils;
import se.digg.crypto.opaque.dto.KE2;
import se.digg.crypto.opaque.dto.RegistrationResponse;
import se.digg.crypto.opaque.error.ClientAuthenticationException;
import se.digg.crypto.opaque.error.DeriveKeyPairErrorException;
import se.digg.crypto.opaque.error.DeserializationException;
import se.digg.crypto.opaque.error.InvalidInputException;
import se.digg.crypto.opaque.server.ServerState;
import se.digg.wallet.r2ps.commons.exception.PakeSessionException;
import se.digg.wallet.r2ps.commons.pake.opaque.PakeSessionRegistry;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

public class ServerOpaqueProvider {

  private final ServerOpaqueEntity serverOpaqueEntity;
  @Getter
  private final PakeSessionRegistry<ServerPakeRecord> pakeSessionRegistry;
  private final ClientRecordRegistry clientRecordRegistry;
  private final Duration recordDuration;
  /**
   * The duration before an authentication evaluation must be finalized before it is considered
   * expired.
   */
  private final Duration finalizedDuration;
  @Getter
  private Duration lastUpdated = Duration.ofMinutes(10);

  public ServerOpaqueProvider(final ServerOpaqueEntity serverOpaqueEntity,
      final PakeSessionRegistry<ServerPakeRecord> pakeSessionRegistry,
      final ClientRecordRegistry clientRecordRegistry,
      final Duration recordDuration, final Duration finalizedDuration) {
    this.pakeSessionRegistry = pakeSessionRegistry;
    this.serverOpaqueEntity = serverOpaqueEntity;
    this.clientRecordRegistry = clientRecordRegistry;
    this.recordDuration = recordDuration;
    this.finalizedDuration = Optional.ofNullable(finalizedDuration).orElse(Duration.ofSeconds(10));
  }

  public RegistrationResponse registrationResponse(byte[] registrationRequest, String kid)
      throws DeriveKeyPairErrorException, DeserializationException {
    return serverOpaqueEntity.getOpaqueServer().createRegistrationResponse(registrationRequest,
        serverOpaqueEntity.getServerOpaquePublicKey(), kid.getBytes(StandardCharsets.UTF_8),
        serverOpaqueEntity.getOprfSeed());
  }

  public void registrationFinalize(String clientId, String kid, byte[] registrationRecord) {
    clientRecordRegistry.setClientRecord(clientId, kid, registrationRecord);
  }

  public EvaluationResponseResult evaluateAuthRequest(byte[] ke1, String clientId, String kid,
      String context)
      throws InvalidInputException, DeriveKeyPairErrorException, DeserializationException {
    final String pakeSessionId = Hex.toHexString(OpaqueUtils.random(32));
    ServerState serverState = new ServerState();
    try {
      final KE2 ke2 = serverOpaqueEntity.getOpaqueServer().generateKe2(
          serverOpaqueEntity.getServerIdentity().getBytes(StandardCharsets.UTF_8),
          serverOpaqueEntity.getServerOpaquePrivateKey(),
          serverOpaqueEntity.getServerOpaquePublicKey(),
          clientRecordRegistry.getClientRecord(clientId, kid),
          kid.getBytes(StandardCharsets.UTF_8), serverOpaqueEntity.getOprfSeed(), ke1,
          clientId.getBytes(StandardCharsets.UTF_8), serverState);

      ServerPakeRecord pakeSession = ServerPakeRecord.builder()
          .pakeSessionId(pakeSessionId)
          .clientId(clientId)
          .kid(kid)
          .context(context)
          .expiryDuration(finalizedDuration)
          .serverState(serverState)
          .build();

      pakeSessionRegistry.addPakeSession(pakeSession);
      return new EvaluationResponseResult(ke2, pakeSessionId);
    } catch (DeriveKeyPairErrorException | DeserializationException | InvalidInputException e) {
      pakeSessionRegistry.deletePakeSession(pakeSessionId);
      throw e;
    }
  }

  public FinalizeResponse finalizeAuthRequest(byte[] ke3, String pakeSessionId)
      throws PakeSessionException,
      ClientAuthenticationException {
    final ServerPakeRecord pakeSession = pakeSessionRegistry.getPakeSession(pakeSessionId);
    if (pakeSession == null) {
      throw new PakeSessionException("No such PAKE session found");
    }
    try {
      final byte[] sessionKey =
          serverOpaqueEntity.getOpaqueServer().serverFinish(ke3, pakeSession.getServerState());

      pakeSession.setSessionKey(sessionKey);
      pakeSession.setServerState(null);
      pakeSession.setExpirationTime(Instant.now().plus(recordDuration));
      pakeSessionRegistry.updatePakeSession(pakeSession);

      return new FinalizeResponse(pakeSessionId, pakeSession.getExpirationTime());
    } catch (ClientAuthenticationException e) {
      pakeSessionRegistry.deletePakeSession(pakeSessionId);
      throw new PakeSessionException("Failed to finalize PAKE session");
    }
  }
}

