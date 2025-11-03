package se.digg.wallet.r2ps.test.data;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;

public class TestCredentials {

  public static final KeyPair p256keyPair;
  public static final X509Certificate p256Certificate;
  public static final KeyPair walletHsmAccessP256keyPair;
  public static final X509Certificate walletHsmAccessP256Certificate;
  public static final KeyPair serverKeyPair;
  public static final X509Certificate serverCertificate;
  public static final KeyPair serverOprfKeyPair;
  public static final X509Certificate serverOprfCertificate;

  static {
    try {
      KeyStore p256KeyStore = KeyStore.getInstance("JKS");
      p256KeyStore.load(
          TestCredentials.class.getClassLoader().getResourceAsStream("p256.jks"),
          "Test1234".toCharArray());
      p256keyPair =
          new KeyPair(
              p256KeyStore.getCertificate("p256").getPublicKey(),
              (ECPrivateKey) p256KeyStore.getKey("p256", "Test1234".toCharArray()));
      KeyStore walletHsmAccessKeyStore = KeyStore.getInstance("JKS");
      walletHsmAccessKeyStore.load(
          TestCredentials.class.getClassLoader().getResourceAsStream("wallet-hsm-access.jks"),
          "Test1234".toCharArray());
      walletHsmAccessP256keyPair =
          new KeyPair(
              walletHsmAccessKeyStore.getCertificate("wallet-hsm-access").getPublicKey(),
              (ECPrivateKey) walletHsmAccessKeyStore.getKey("wallet-hsm-access",
                  "Test1234".toCharArray()));
      KeyStore serverKeyStore = KeyStore.getInstance("JKS");
      serverKeyStore.load(
          TestCredentials.class.getClassLoader().getResourceAsStream("server-p256.jks"),
          "Test1234".toCharArray());
      serverKeyPair =
          new KeyPair(
              serverKeyStore.getCertificate("server").getPublicKey(),
              (ECPrivateKey) serverKeyStore.getKey("server", "Test1234".toCharArray()));
      KeyStore serverOprfKeyStore = KeyStore.getInstance("JKS");
      serverOprfKeyStore.load(
          TestCredentials.class.getClassLoader().getResourceAsStream("server-oprf-p256.jks"),
          "Test1234".toCharArray());
      serverOprfKeyPair =
          new KeyPair(
              serverOprfKeyStore.getCertificate("oprf").getPublicKey(),
              (ECPrivateKey) serverOprfKeyStore.getKey("oprf", "Test1234".toCharArray()));

      // Get certs
      p256Certificate = (X509Certificate) p256KeyStore.getCertificate("p256");
      walletHsmAccessP256Certificate =
          (X509Certificate) walletHsmAccessKeyStore.getCertificate("wallet-hsm-access");
      serverCertificate = (X509Certificate) serverKeyStore.getCertificate("server");
      serverOprfCertificate = (X509Certificate) serverOprfKeyStore.getCertificate("oprf");
    } catch (KeyStoreException
        | CertificateException
        | IOException
        | NoSuchAlgorithmException
        | UnrecoverableKeyException e) {
      throw new RuntimeException(e);
    }
  }
}
