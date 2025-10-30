package se.digg.wallet.r2ps.server.service;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWSAlgorithm;
import java.security.KeyPair;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceTypeRegistry;
import se.digg.wallet.r2ps.commons.pake.opaque.PakeSessionRegistry;
import se.digg.wallet.r2ps.server.pake.opaque.ServerPakeRecord;
import se.digg.wallet.r2ps.server.service.servicehandlers.ServiceTypeHandler;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OpaqueServiceRequestHandlerConfiguration {

  /** Static OPAQUE server key pair */
  private KeyPair serverKeyPair;

  /** Encryption method for service data encryption. Default AES GCM 256 */
  private EncryptionMethod encryptionMethod;

  /** Registry over current active PAKE sessions for client service requests */
  private PakeSessionRegistry<ServerPakeRecord> serverPakeSessionRegistry;

  /** Registry over authorized client public keys */
  private ClientPublicKeyRegistry clientPublicKeyRegistry;

  /** Service request handlers for one or more service types */
  private List<ServiceTypeHandler> serviceTypeHandlers;

  /** The JWS algorithm used by the server when signing responses */
  private JWSAlgorithm serverJwsAlgorithm;

  /** Replay checker to determine if a request is a replay of old request */
  private ReplayChecker replayChecker;

  /** Registry over service types */
  private ServiceTypeRegistry serviceTypeRegistry;
}
