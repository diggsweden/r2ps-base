package se.digg.wallet.r2ps.commons.pake;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import se.digg.crypto.hashtocurve.data.HashToCurveProfile;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class ECUtils {

  public static ECParameterSpec getECParameterSpecFromProfile(HashToCurveProfile profile) {
    return switch (profile) {
      case P256_XMD_SHA_256_SSWU_RO_ -> ECNamedCurveTable.getParameterSpec("P-256");
      case P384_XMD_SHA_384_SSWU_RO_ -> ECNamedCurveTable.getParameterSpec("P-384");
      case P521_XMD_SHA_512_SSWU_RO_ -> ECNamedCurveTable.getParameterSpec("P-521");
      case curve25519_XMD_SHA_512_ELL2_RO_ -> ECNamedCurveTable.getParameterSpec("curve25519");
    };
  }

  public static Digest getDigestAlgorithmFromProfile(HashToCurveProfile profile) {
    return switch (profile) {
      case P256_XMD_SHA_256_SSWU_RO_ -> new SHA256Digest();
      case P384_XMD_SHA_384_SSWU_RO_ -> new SHA384Digest();
      case P521_XMD_SHA_512_SSWU_RO_ -> new SHA512Digest();
      case curve25519_XMD_SHA_512_ELL2_RO_ -> new SHA512Digest();
    };
  }

  public static PublicKey getPublicKey(ECPoint ecPoint, ECParameterSpec ecParameterSpec)
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
    ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
    KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
    return keyFactory.generatePublic(publicKeySpec);
  }

  public static boolean isValidCurveName(String curveName) {
    try {
      return ECNamedCurveTable.getParameterSpec(curveName) != null;
    } catch (IllegalArgumentException e) {
      return false;
    }
  }

  public static byte[] serializePublicKey(PublicKey publicKey) {
    try {
      KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
      X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
      ECPublicKey bcECPublicKey = (ECPublicKey) keyFactory.generatePublic(publicKeySpec);
      return bcECPublicKey.getQ().getEncoded(true);
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
      throw new RuntimeException(e);
    }
  }

  public static byte[] ecdsaSignatureAsn1ToConcat(byte[] derSignature, int partLength)
      throws IOException {
    ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(derSignature);
    BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getValue();
    BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getValue();

    byte[] rBytes = toFixedLengthBytes(r, partLength);
    byte[] sBytes = toFixedLengthBytes(s, partLength);

    byte[] concat = new byte[partLength * 2];
    System.arraycopy(rBytes, 0, concat, 0, partLength);
    System.arraycopy(sBytes, 0, concat, partLength, partLength);
    return concat;
  }

  private static byte[] toFixedLengthBytes(BigInteger value, int length) {
    byte[] raw = value.toByteArray();
    // Remove possible leading zero byte (sign byte)
    if (raw.length > length) {
      return Arrays.copyOfRange(raw, raw.length - length, raw.length);
    } else if (raw.length < length) {
      byte[] padded = new byte[length];
      System.arraycopy(raw, 0, padded, length - raw.length, raw.length);
      return padded;
    } else {
      return raw;
    }
  }


}
