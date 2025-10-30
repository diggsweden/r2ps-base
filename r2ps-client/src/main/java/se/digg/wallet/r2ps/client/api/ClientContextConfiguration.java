package se.digg.wallet.r2ps.client.api;

import com.nimbusds.jose.JWSVerifier;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.digg.wallet.r2ps.commons.dto.JWSSigningParams;

/**
 * Represents contextual information used for cryptographic operations and secure service exchanges
 * in a protected environment.
 *
 * <p>A context represents a certain class of purpose of the protected protocol represented by a
 * specific client key pair. The primary role of separation of contexts is to allow the server
 * infrastructure to separate cryptographic operations based on the purpose of the protected
 * service, as well as to route protected objects to the appropriate server for processing.
 *
 * <p>Attributes: - kid: Represents the key identifier, typically used for identifying cryptographic
 * keys in a secure context. - signingParams: Encapsulates parameters required for JWS (JSON Web
 * Signature) signing, including the signer and algorithm details. - contextKeyPair: Contains the
 * cryptographic key pair associated with this context, including both the private and public keys
 * required for encryption, decryption, or signing operations.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ClientContextConfiguration {
  private String kid;
  private JWSSigningParams signingParams;
  private KeyPair contextKeyPair;
  private String serverIdentity;
  private JWSVerifier serverVerifier;
  private ECPublicKey serverPublicKey;
}
