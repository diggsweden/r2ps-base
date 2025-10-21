package se.digg.wallet.r2ps.server.service;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWSAlgorithm;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceTypeRegistry;
import se.digg.wallet.r2ps.commons.pake.opaque.OpaqueConfiguration;
import se.digg.wallet.r2ps.commons.pake.opaque.PakeSessionRegistry;
import se.digg.wallet.r2ps.server.pake.opaque.ClientRecordRegistry;
import se.digg.wallet.r2ps.server.pake.opaque.ServerPakeRecord;
import se.digg.wallet.r2ps.server.service.pinauthz.PinAuthorization;
import se.digg.wallet.r2ps.server.service.servicehandlers.ServiceTypeHandler;

import java.security.KeyPair;
import java.time.Duration;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OpaqueServiceRequestHandlerConfiguration {

  /** OPAQUE configuration */
  private OpaqueConfiguration opaqueConfiguration;
  /** Server identity */
  private String serverIdentity;
  /** OPRF seed for OPAQUE server OPRF evaluate function */
  private byte[] oprfSeed;
  /** Optional HSM key pair for OPRF evaluation */
  private KeyPair serverHsmKeyPair;
  /** Static OPAQUE server key pair */
  private KeyPair serverOpaqueKeyPair;
  /** Encryption method for service data encryption. Default AES GCM 256 */
  private EncryptionMethod encryptionMethod;
  /** Registry over current active PAKE sessions for client service requests */
  private PakeSessionRegistry<ServerPakeRecord> serverPakeSessionRegistry;
  /** The default duration for PAKE sessions before they expire */
  private Duration sessionDuration;
  /** The duration before an authentication evaluation must be finalized before the session expires */
  private Duration fianlizeDuration;
  /** Registry over authorized client public keys */
  private ClientPublicKeyRegistry clientPublicKeyRegistry;
  /** Service request handlers for one or more service types */
  private List<ServiceTypeHandler> serviceTypeHandlers;
  /** The JWS algorithm used by the server when signing responses */
  private JWSAlgorithm serverJwsAlgorithm;
  /** Dispatchers for dispatching requests for security contexts handled by a downstream server */
  private List<ServiceRequestDispatcher> serviceRequestDispatchers;
  /** Registry for client PIN validation records */
  private ClientRecordRegistry clientRecordRegistry;
  /** Replay checker to determine if a request is a replay of old request */
  private ReplayChecker replayChecker;
  /** Registry over service types */
  private ServiceTypeRegistry serviceTypeRegistry;
  /**
   * PIN authorization code checker. Defaults to CodeMatchPinAuthorization based on the
   * clientPublicKeyRecord
   */
  private PinAuthorization pinAuthorization;
}
