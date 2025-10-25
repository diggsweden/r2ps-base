package se.digg.wallet.r2ps.server.pake.opaque;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import se.digg.crypto.opaque.OpaqueUtils;
import se.digg.crypto.opaque.dto.KE2;
import se.digg.crypto.opaque.dto.RegistrationResponse;
import se.digg.crypto.opaque.error.ClientAuthenticationException;
import se.digg.crypto.opaque.error.DeriveKeyPairErrorException;
import se.digg.crypto.opaque.error.DeserializationException;
import se.digg.crypto.opaque.error.InvalidInputException;
import se.digg.crypto.opaque.server.ServerState;
import se.digg.wallet.r2ps.commons.dto.servicetype.SessionTask;
import se.digg.wallet.r2ps.commons.dto.servicetype.SessionTaskRegistry;
import se.digg.wallet.r2ps.commons.exception.PakeSessionException;
import se.digg.wallet.r2ps.commons.pake.opaque.PakeSessionRegistry;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

@Slf4j
public class ServerOpaqueProvider {

  private final ServerOpaqueEntity serverOpaqueEntity;
  @Getter
  private final PakeSessionRegistry<ServerPakeRecord> pakeSessionRegistry;
  private final ClientRecordRegistry clientRecordRegistry;
  private final Duration defaultMaxRecordDuration;
  private final SessionTaskRegistry sessionTaskRegistry;
  /**
   * The duration before an authentication evaluation must be finalized before it is considered
   * expired.
   */
  private final Duration finalizedDuration;
  @Getter
  private Duration lastUpdated = Duration.ofMinutes(10);

  public ServerOpaqueProvider(final ServerOpaqueEntity serverOpaqueEntity,
      final PakeSessionRegistry<ServerPakeRecord> pakeSessionRegistry,
      final ClientRecordRegistry clientRecordRegistry, SessionTaskRegistry sessionTaskRegistry,
      final Duration defaultMaxRecordDuration, final Duration finalizedDuration) {
    this.pakeSessionRegistry = pakeSessionRegistry;
    this.serverOpaqueEntity = serverOpaqueEntity;
    this.clientRecordRegistry = clientRecordRegistry;
    this.sessionTaskRegistry = sessionTaskRegistry;
    this.defaultMaxRecordDuration = defaultMaxRecordDuration;
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

  /**
   * Finalizes an authentication request by completing the PAKE (Password Authenticated Key Exchange) session.
   * This method validates the provided cryptographic proof and updates the corresponding PAKE session record.
   *
   * @param ke3 the cryptographic proof provided by the client to finalize the PAKE session
   * @param pakeSessionId the unique identifier of the PAKE session to finalize
   * @return a {@code FinalizeResponse} object containing the finalized session details such as session ID,
   *         expiration time, and the associated session task
   * @throws PakeSessionException if the PAKE session could not be completed or the session record is invalid
   * @throws ClientAuthenticationException if the provided cryptographic proof fails to authenticate the client
   */
  public FinalizeResponse finalizeAuthRequest(final byte[] ke3, String pakeSessionId)
      throws PakeSessionException,
      ClientAuthenticationException {
    return finalizeAuthRequest(ke3, pakeSessionId, null, null);
  }

  /**
   * Finalizes an authentication request by completing the PAKE (Password Authenticated Key Exchange) session.
   * This method validates the provided cryptographic proof, updates the PAKE session record, and sets
   * the session expiration time and task details.
   *
   * @param ke3 the cryptographic proof provided by the client to finalize the PAKE session
   * @param pakeSessionId the unique identifier of the PAKE session to finalize
   * @param sessionTaskId the unique identifier of the session task, if applicable
   * @param requestedSessionDuration the duration requested for the authenticated session
   * @return a {@code FinalizeResponse} object containing the finalized session details such as session ID,
   *         expiration time, and associated session task
   * @throws PakeSessionException if the PAKE session could not be completed or session record is invalid
   * @throws ClientAuthenticationException if the provided cryptographic proof fails to authenticate the client
   */
  public FinalizeResponse finalizeAuthRequest(final byte[] ke3, String pakeSessionId, final String sessionTaskId, final Duration requestedSessionDuration)
      throws PakeSessionException,
      ClientAuthenticationException {
    final ServerPakeRecord pakeSession = pakeSessionRegistry.getPakeSession(pakeSessionId);
    if (pakeSession == null) {
      throw new PakeSessionException("No such PAKE session found");
    }
    try {
      final byte[] sessionKey =
          serverOpaqueEntity.getOpaqueServer().serverFinish(ke3, pakeSession.getServerState());

      String matchedSessionTaskId = null;
      SessionTask sessionTask = sessionTaskRegistry.getSessionTaskById(sessionTaskId);
      if (sessionTask == null) {
        log.debug("No session task found for id {}", sessionTaskId);
      } else {
        matchedSessionTaskId = sessionTaskId;
        log.debug("Found requested session task {} in registry", sessionTaskId);
      }
      Instant sessionExpirationTime = getSessionExpirationTime(sessionTask, requestedSessionDuration);

      pakeSession.setSessionKey(sessionKey);
      pakeSession.setServerState(null);
      pakeSession.setExpirationTime(sessionExpirationTime);
      // Store the requested session task if it exists in the registry
      pakeSession.setSessionTask(matchedSessionTaskId);
      pakeSessionRegistry.updatePakeSession(pakeSession);

      return new FinalizeResponse(pakeSessionId, pakeSession.getExpirationTime(), pakeSession.getSessionTask());
    } catch (ClientAuthenticationException e) {
      pakeSessionRegistry.deletePakeSession(pakeSessionId);
      throw new PakeSessionException("Failed to finalize PAKE session");
    }
  }

  private Instant getSessionExpirationTime(final SessionTask sessionTask, final Duration requestedSessionDuration) {
    Duration maxDuration = sessionTask == null
        ? defaultMaxRecordDuration
        : sessionTask.maxDuration();
    if (maxDuration == null) {
      log.warn("Session task {} does not have a max duration. Using default max duration {}", sessionTask, defaultMaxRecordDuration);
      maxDuration = defaultMaxRecordDuration;
    }
    if (requestedSessionDuration == null) {
      log.debug("Requested session duration is null. Setting session expiration time to max duration.");
      return Instant.now().plus(maxDuration);
    }
    if (requestedSessionDuration.compareTo(maxDuration) > 0) {
      log.debug("Requested session duration {} exceeds maximum session duration {}. Setting session expiration time to max duration.",
          requestedSessionDuration, maxDuration);
      return Instant.now().plus(maxDuration);
    }
    log.debug("Accepting requested session duration");
    return Instant.now().plus(requestedSessionDuration);
  }
}

