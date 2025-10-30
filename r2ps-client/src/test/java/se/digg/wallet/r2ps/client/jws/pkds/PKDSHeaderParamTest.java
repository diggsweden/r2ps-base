package se.digg.wallet.r2ps.client.jws.pkds;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Security;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.wallet.r2ps.commons.StaticResources;
import se.digg.wallet.r2ps.test.data.TestCredentials;
import se.digg.wallet.r2ps.test.testutils.JSONUtils;

@Slf4j
class PKDSHeaderParamTest {

  static ObjectMapper objectMapper = StaticResources.OBJECT_MAPPER;

  @BeforeAll
  static void setUp() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  void testPKDSHeaderParam() throws Exception {

    // Client keys
    KeyPair clientKey = TestCredentials.p256keyPair;
    JWK clientJwk = JSONUtils.getJWKfromPublicKey(clientKey.getPublic());
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    final byte[] clientCertHash = md.digest(TestCredentials.p256Certificate.getEncoded());

    // Server keys
    KeyPair serverKey = TestCredentials.p256keyPair;
    JWK serverJwk = JSONUtils.getJWKfromPublicKey(serverKey.getPublic());
    md = MessageDigest.getInstance("SHA-256");
    final byte[] serverCertHash = md.digest(TestCredentials.serverCertificate.getEncoded());

    logPkdsHeaderParam(
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
            .build());

    logPkdsHeaderParam(
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
            .build());

    logPkdsHeaderParam(
        "JWK PKDS with recipient Cert",
        PKDSHeaderParam.builder()
            .suite(PKDSSuite.ECDH_HKDF_SHA256)
            .recipientPublicKey(
                PKDSPublicKey.builder().x509Certificate(TestCredentials.serverCertificate).build())
            .producerPublicKey(PKDSPublicKey.builder().jwk(clientJwk).build())
            .params(
                PKDSParams.builder()
                    .info(Base64URL.encode("info"))
                    .salt(Base64URL.encode("salt"))
                    .build())
            .length(32)
            .build());

    logPkdsHeaderParam(
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
            .build());

    logPkdsHeaderParam(
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
            .build());
  }

  void logPkdsHeaderParam(String message, PKDSHeaderParam pkds) throws Exception {
    log.info(message);

    final String jwkPkdsJson =
        objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(pkds.toJsonObject());
    log.info("PKDS: {}", jwkPkdsJson);

    PKDSHeaderParam parsedJwkPkds = PKDSHeaderParam.parse(jwkPkdsJson);
    assertEquals(
        jwkPkdsJson,
        PKDSHeaderParam.OBJECT_MAPPER
            .writerWithDefaultPrettyPrinter()
            .writeValueAsString(parsedJwkPkds.toJsonObject()));
  }
}
