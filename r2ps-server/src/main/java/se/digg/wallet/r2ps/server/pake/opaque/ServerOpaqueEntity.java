package se.digg.wallet.r2ps.server.pake.opaque;

import java.security.KeyPair;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.digg.crypto.opaque.crypto.OprfPrivateKey;
import se.digg.crypto.opaque.server.OpaqueServer;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ServerOpaqueEntity {

  private byte[] oprfSeed;
  private KeyPair serverHsmKeyPair;
  private OprfPrivateKey serverOpaquePrivateKey;
  private byte[] serverOpaquePublicKey;
  private String serverIdentity;
  private OpaqueServer opaqueServer;
}
