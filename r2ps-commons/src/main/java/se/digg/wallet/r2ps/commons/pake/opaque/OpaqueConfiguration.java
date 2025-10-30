package se.digg.wallet.r2ps.commons.pake.opaque;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jce.ECNamedCurveTable;
import se.digg.crypto.hashtocurve.data.HashToCurveProfile;
import se.digg.crypto.opaque.client.OpaqueClient;
import se.digg.crypto.opaque.client.impl.DefaultOpaqueClient;
import se.digg.crypto.opaque.crypto.DstContext;
import se.digg.crypto.opaque.crypto.HashFunctions;
import se.digg.crypto.opaque.crypto.KeyDerivationFunctions;
import se.digg.crypto.opaque.crypto.OpaqueCurve;
import se.digg.crypto.opaque.crypto.OprfFunctions;
import se.digg.crypto.opaque.crypto.impl.ArgonStretch;
import se.digg.crypto.opaque.crypto.impl.DefaultOpaqueCurve;
import se.digg.crypto.opaque.crypto.impl.DefaultOprfFunction;
import se.digg.crypto.opaque.crypto.impl.HKDFKeyDerivation;
import se.digg.crypto.opaque.server.OpaqueServer;
import se.digg.crypto.opaque.server.impl.DefaultOpaqueServer;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OpaqueConfiguration {

  public static OpaqueConfiguration defaultConfiguration() {
    return OpaqueConfiguration.builder()
        .curveName("P-256")
        .opaqueDigestAlgorithm(new SHA256Digest())
        .hashToCurveProfile(HashToCurveProfile.P256_XMD_SHA_256_SSWU_RO_)
        .stretchProfile(ArgonStretch.ARGON_PROFILE_DEFAULT)
        .opaqueDstContext(DstContext.IDENTIFIER_P256_SHA256)
        .applicationContextDst("RPS-Ops")
        .build();
  }

  /** The Bouncycastle registered OPAQUE curve name. Default is P-256. */
  private String curveName;

  /** The Bouncycastle registered OPAQUE digest algorithm. Default is SHA-256. */
  private Digest opaqueDigestAlgorithm;

  /** The OPAQUE HashToCurveProfile. Default is P256_XMD_SHA_256_SSWU_RO_. */
  private HashToCurveProfile hashToCurveProfile;

  /** The OPAQUE stretch profile. Default is ARGON_PROFILE_DEFAULT. */
  private String stretchProfile;

  /** The OPAQUE DST context. Default is P256_SHA256. */
  private String opaqueDstContext;

  /** The application context DST. Default is RPS-Ops. */
  private String applicationContextDst;

  public OpaqueServer getOpaqueServer() {
    return new DefaultOpaqueServer(
        getOprfFunctions(), getKeyDerivationFunctions(), getHashFunctions());
  }

  public OpaqueClient getOpaqueClient() {
    return new DefaultOpaqueClient(
        getOprfFunctions(), getKeyDerivationFunctions(), getHashFunctions());
  }

  public HashFunctions getHashFunctions() {
    return new HashFunctions(
        DigestFactory.cloneDigest(opaqueDigestAlgorithm), new ArgonStretch(getStretchProfile()));
  }

  public OpaqueCurve getOpaqueCurve() {
    return new DefaultOpaqueCurve(
        ECNamedCurveTable.getParameterSpec(curveName),
        hashToCurveProfile,
        new DstContext(opaqueDstContext));
  }

  public OprfFunctions getOprfFunctions() {
    return new DefaultOprfFunction(getOpaqueCurve(), getHashFunctions(), applicationContextDst);
  }

  public KeyDerivationFunctions getKeyDerivationFunctions() {
    return new HKDFKeyDerivation(getHashFunctions());
  }
}
