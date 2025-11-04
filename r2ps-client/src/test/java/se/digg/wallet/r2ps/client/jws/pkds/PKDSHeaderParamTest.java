package se.digg.wallet.r2ps.client.jws.pkds;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Security;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import se.digg.wallet.r2ps.commons.StaticResources;
import se.digg.wallet.r2ps.test.data.TestCredentials;
import se.digg.wallet.r2ps.test.testutils.JSONUtils;

@Slf4j
class PKDSHeaderParamTest {

  static ObjectMapper objectMapper = StaticResources.OBJECT_MAPPER;

  // Client keys
  private static byte[] clientCertHash;
  private static JWK clientJwk;

  // Server keys
  private static JWK serverJwk;
  private static byte[] serverCertHash;

  @BeforeAll
  static void setUp() throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    MessageDigest md = MessageDigest.getInstance("SHA-256");

    // Client keys
    KeyPair clientKey = TestCredentials.p256keyPair;
    clientJwk = JSONUtils.getJWKfromPublicKey(clientKey.getPublic());
    clientCertHash = md.digest(TestCredentials.p256Certificate.getEncoded());

    // Server keys
    KeyPair serverKey = TestCredentials.p256keyPair;
    serverJwk = JSONUtils.getJWKfromPublicKey(serverKey.getPublic());
    serverCertHash = md.digest(TestCredentials.serverCertificate.getEncoded());
  }

  private static Stream<Arguments> pkdsHeaderProvider() {
    return Stream.of(
        Arguments.of(
            "JWK PKDS",
            PKDSHeaderParam.builder()
                .suite(PKDSSuite.ECDH_HKDF_SHA256)
                .recipientPublicKey(PKDSPublicKey.builder().jwk(serverJwk).build())
                .producerPublicKey(PKDSPublicKey.builder().jwk(clientJwk).build())
                .params(
                    PKDSParams.builder()
                        .info(Base64URL.encode("info"))
                        .salt(Base64URL.encode("salt"))
                        .build())
                .length(32)
                .build()),
        Arguments.of(
            "JWK PKDS with recipient KeyID",
            PKDSHeaderParam.builder()
                .suite(PKDSSuite.ECDH_HKDF_SHA256)
                .recipientPublicKey(PKDSPublicKey.builder().keyId("recipientKeyId").build())
                .producerPublicKey(PKDSPublicKey.builder().jwk(clientJwk).build())
                .params(
                    PKDSParams.builder()
                        .info(Base64URL.encode("info"))
                        .salt(Base64URL.encode("salt"))
                        .build())
                .length(32)
                .build()),
        Arguments.of(
            "JWK PKDS with recipient Cert",
            PKDSHeaderParam.builder()
                .suite(PKDSSuite.ECDH_HKDF_SHA256)
                .recipientPublicKey(
                    PKDSPublicKey.builder()
                        .x509Certificate(TestCredentials.serverCertificate)
                        .build())
                .producerPublicKey(PKDSPublicKey.builder().jwk(clientJwk).build())
                .params(
                    PKDSParams.builder()
                        .info(Base64URL.encode("info"))
                        .salt(Base64URL.encode("salt"))
                        .build())
                .length(32)
                .build()),
        Arguments.of(
            "JWK PKDS with recipient cert hash",
            PKDSHeaderParam.builder()
                .suite(PKDSSuite.ECDH_HKDF_SHA256)
                .recipientPublicKey(
                    PKDSPublicKey.builder()
                        .x509CertificateSHA256Thumbprint(Base64URL.encode(serverCertHash))
                        .build())
                .producerPublicKey(PKDSPublicKey.builder().jwk(clientJwk).build())
                .params(
                    PKDSParams.builder()
                        .info(Base64URL.encode("info"))
                        .salt(Base64URL.encode("salt"))
                        .build())
                .length(32)
                .build()),
        Arguments.of(
            "JWK PKDS with all public key alternatives",
            PKDSHeaderParam.builder()
                .suite(PKDSSuite.ECDH_HKDF_SHA256)
                .recipientPublicKey(
                    PKDSPublicKey.builder()
                        .keyId("recipientKeyId")
                        .x509Certificate(TestCredentials.serverCertificate)
                        .jwk(serverJwk)
                        .x509CertificateSHA256Thumbprint(Base64URL.encode(serverCertHash))
                        .build())
                .producerPublicKey(
                    PKDSPublicKey.builder()
                        .jwk(clientJwk)
                        .keyId("producerKeyId")
                        .x509Certificate(TestCredentials.p256Certificate)
                        .x509CertificateSHA256Thumbprint(Base64URL.encode(clientCertHash))
                        .build())
                .params(
                    PKDSParams.builder()
                        .info(Base64URL.encode("info"))
                        .salt(Base64URL.encode("salt"))
                        .build())
                .length(32)
                .build()));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("pkdsHeaderProvider")
  void testJsonRoundTrip(String testDescription, PKDSHeaderParam pkds) throws Exception {
    // Arrange & Act
    final String jwkPkdsJson =
        objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(pkds.toJsonObject());

    PKDSHeaderParam parsedJwkPkds = PKDSHeaderParam.parse(jwkPkdsJson);

    // Assert
    assertEquals(pkds, parsedJwkPkds);
  }
}
