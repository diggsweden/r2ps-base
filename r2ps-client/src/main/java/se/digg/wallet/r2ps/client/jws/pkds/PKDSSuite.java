package se.digg.wallet.r2ps.client.jws.pkds;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

@Getter
@AllArgsConstructor
public enum PKDSSuite {
  ECDH_HKDF_SHA256("ECDH-HKDF-SHA256", new SHA256Digest());

  private final String id;
  private final Digest digest;
}
