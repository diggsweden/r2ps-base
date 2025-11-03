package se.digg.wallet.r2ps.client.pake.impl;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.KeyAgreement;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import se.digg.crypto.hashtocurve.HashToEllipticCurve;
import se.digg.crypto.hashtocurve.HashToField;
import se.digg.crypto.hashtocurve.MapToCurve;
import se.digg.crypto.hashtocurve.MessageExpansion;
import se.digg.crypto.hashtocurve.data.HashToCurveProfile;
import se.digg.crypto.hashtocurve.impl.GenericCurveProcessor;
import se.digg.crypto.hashtocurve.impl.GenericHashToField;
import se.digg.crypto.hashtocurve.impl.ShallueVanDeWoestijneMapToCurve;
import se.digg.crypto.hashtocurve.impl.XmdMessageExpansion;
import se.digg.wallet.r2ps.client.pake.PinHardening;
import se.digg.wallet.r2ps.commons.pake.ECUtils;

/**
 * The ECPrivateKeyDHPinHardening class provides functionality for seeding a PIN based on elliptic
 * curve cryptography. It implements the PinHardening interface and utilizes hash-to-curve
 * operations, elliptic curve point generation, and key derivation to produce a securely derived
 * hardened PIN. The class is parameterized by a hash-to-curve profile that determines which
 * elliptic curve and cryptographic primitives are used.
 */
public class ECPrivateKeyDHPinHardening implements PinHardening {

  private static final byte[] DEFAULT_DST =
      "SE_EIDAS_WALLET_PIN_HARDENING".getBytes(StandardCharsets.UTF_8);
  private static final byte[] DEFAULT_SALT = null;
  private static final byte[] DEFAULT_INFO = new byte[0];

  private final HashToCurveProfile profile;
  private final HashToEllipticCurve hashToEllipticCurve;
  private final ECParameterSpec ecParameterSpec;
  private final byte[] salt;
  private final byte[] info;

  /**
   * Constructs an ECPrivateKeyPinSeeder instance using the specified hash-to-curve profile and a
   * default domain separation tag (DST). The instance will also utilize default salt and info
   * values for initialization.
   *
   * @param profile the hash-to-curve profile that defines the elliptic curve, hashing, and mapping
   *        parameters to be used
   */
  public ECPrivateKeyDHPinHardening(final HashToCurveProfile profile) {
    this(profile, DEFAULT_DST);
  }

  /**
   * Constructs an ECPrivateKeyPinSeeder instance, initializing it with the specified parameters
   * using default salt and info values.
   *
   * @param profile the hash-to-curve profile that defines the elliptic curve, hashing, and mapping
   *        parameters to be used
   * @param dst the domain separation tag (DST), used to uniquely distinguish applications of a
   *        hash-to-curve operation
   */
  public ECPrivateKeyDHPinHardening(final HashToCurveProfile profile, byte[] dst) {
    this(profile, dst, DEFAULT_SALT, DEFAULT_INFO);
  }

  /**
   * Constructs an ECPrivateKeyPinSeeder instance, initializing it with the specified parameters.
   *
   * @param profile the hash-to-curve profile that defines the elliptic curve, hashing, and mapping
   *        parameters to be used
   * @param dst the domain separation tag (DST), used to uniquely distinguish applications of a
   *        hash-to-curve operation
   * @param salt the optional salt value used during key derivation
   * @param info additional context-specific information used during key derivation
   */
  public ECPrivateKeyDHPinHardening(
      final HashToCurveProfile profile, byte[] dst, byte[] salt, byte[] info) {
    this.profile = profile;
    this.salt = salt;
    this.info = info;
    this.ecParameterSpec = ECUtils.getECParameterSpecFromProfile(profile);
    Digest digestAlgorithm = ECUtils.getDigestAlgorithmFromProfile(profile);
    MessageExpansion messageExpansion = new XmdMessageExpansion(digestAlgorithm, profile.getK());
    HashToField hashToField =
        new GenericHashToField(dst, ecParameterSpec, messageExpansion, profile.getL());
    MapToCurve mapToCurve = new ShallueVanDeWoestijneMapToCurve(ecParameterSpec, profile.getZ());
    this.hashToEllipticCurve =
        new HashToEllipticCurve(
            hashToField, mapToCurve, new GenericCurveProcessor(ecParameterSpec));
  }

  /** {@inheritDoc} */
  @Override
  public byte[] process(final String pin, final PrivateKey privateKey, int byteLength) {
    try {
      final ECPoint ecPoint =
          hashToEllipticCurve.hashToEllipticCurve(pin.getBytes(StandardCharsets.UTF_8));
      final PublicKey pinPublicKey = ECUtils.getPublicKey(ecPoint, ecParameterSpec);
      KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
      keyAgreement.init(privateKey);
      keyAgreement.doPhase(pinPublicKey, true);
      final byte[] ikm = keyAgreement.generateSecret();

      HKDFBytesGenerator hkdf =
          new HKDFBytesGenerator(ECUtils.getDigestAlgorithmFromProfile(profile));
      HKDFParameters hkdfParameters = new HKDFParameters(ikm, salt, info);
      hkdf.init(hkdfParameters);

      byte[] seededPin = new byte[byteLength];
      hkdf.generateBytes(seededPin, 0, byteLength);

      return seededPin;
    } catch (NoSuchAlgorithmException
        | InvalidKeySpecException
        | NoSuchProviderException
        | InvalidKeyException e) {
      throw new RuntimeException("Pin seeding error", e);
    }
  }
}
