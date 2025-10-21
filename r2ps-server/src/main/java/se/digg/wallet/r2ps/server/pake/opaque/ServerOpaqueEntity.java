package se.digg.wallet.r2ps.server.pake.opaque;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.digg.crypto.opaque.crypto.OprfPrivateKey;
import se.digg.crypto.opaque.server.OpaqueServer;

import java.security.KeyPair;

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
