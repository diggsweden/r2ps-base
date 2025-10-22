package se.digg.wallet.r2ps.client.jws;

import static org.junit.jupiter.api.Assertions.*;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.wallet.r2ps.client.jws.pkds.HSPKDSAlgorithm;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSHeaderParam;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSKeyDerivation;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSParams;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSPublicKey;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSSuite;
import se.digg.wallet.r2ps.client.jws.pkds.impl.PrivateKeyPKDSKeyDerivation;
import se.digg.wallet.r2ps.commons.StaticResources;
import se.digg.wallet.r2ps.test.data.TestCredentials;
import se.digg.wallet.r2ps.test.data.TestMessage;
import se.digg.wallet.r2ps.test.testUtils.JSONUtils;

@Slf4j
class HSECPkdsSignerTest {

  // Client keys
  static KeyPair clientKey;
  static JWK clientJwk;
  static byte[] clientCertHash;

  // Server keys
  static KeyPair serverKey;
  static JWK serverJwk;
  static byte[] serverCertHash;

  @BeforeAll
  static void setUp() throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    // Client keys
    clientKey = TestCredentials.p256keyPair;
    clientJwk = JSONUtils.getJWKfromPublicKey(clientKey.getPublic());
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    clientCertHash = md.digest(TestCredentials.p256Certificate.getEncoded());

    // Server keys
    serverKey = TestCredentials.p256keyPair;
    serverJwk = JSONUtils.getJWKfromPublicKey(serverKey.getPublic());
    md = MessageDigest.getInstance("SHA-256");
    serverCertHash = md.digest(TestCredentials.serverCertificate.getEncoded());
  }


  @Test
  void testHS256PKDS() throws Exception {

    final PKDSHeaderParam pkdsParam = PKDSHeaderParam.builder()
        .suite(PKDSSuite.ECDH_HKDF_SHA256)
        .recipientPublicKey(PKDSPublicKey.builder()
            .jwk(serverJwk)
            .build())
        .producerPublicKey(PKDSPublicKey.builder()
            .jwk(clientJwk)
            .build())
        .build();

    JWSSigner signer = new HSECPkdsSigner(HSPKDSAlgorithm.HS256_PKDS,
        new PrivateKeyPKDSKeyDerivation((ECPrivateKey) clientKey.getPrivate()));

    String payload = StaticResources.OBJECT_MAPPER.writeValueAsString(TestMessage.builder()
        .message("Hello World!")
        .build());
    JWSHeader jwsHeader = new JWSHeader.Builder(HSPKDSAlgorithm.HS256_PKDS.getAlg())
        .customParam(HSECPkdsSigner.PKDS_HEADER_PARAM, pkdsParam.toJsonObject())
        .build();
    JWSObject jwsObject = new JWSObject(jwsHeader, new Payload(payload));
    jwsObject.sign(signer);

    log.info("Signed JWS using HS256_PKDS: {}", jwsObject.serialize());
    log.info("Header:\n{}", StaticResources.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
        .writeValueAsString(jwsObject.getHeader().toJSONObject()));
    log.info("Payload:\n{}", StaticResources.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
        .writeValueAsString(jwsObject.getPayload().toJSONObject()));
    log.info("Signature:\n{}", jwsObject.getSignature());

  }

  @Test
  void testHSPKDSSign() throws Exception {

    sighWithHSPKDS("JWK HS256_PKDS",
        PKDSHeaderParam.builder()
            .suite(PKDSSuite.ECDH_HKDF_SHA256)
            .recipientPublicKey(PKDSPublicKey.builder()
                .jwk(serverJwk)
                .build())
            .producerPublicKey(PKDSPublicKey.builder()
                .jwk(clientJwk)
                .build())
            .build(),
        HSPKDSAlgorithm.HS256_PKDS);

    sighWithHSPKDS("JWK HS256_PKDS, with info salt and length",
        PKDSHeaderParam.builder()
            .suite(PKDSSuite.ECDH_HKDF_SHA256)
            .recipientPublicKey(PKDSPublicKey.builder()
                .jwk(serverJwk)
                .build())
            .producerPublicKey(PKDSPublicKey.builder()
                .jwk(clientJwk)
                .build())
            .params(PKDSParams.builder()
                .info(new Base64URL("info"))
                .salt(new Base64URL("salt"))
                .build())
            .length(32)
            .build(),
        HSPKDSAlgorithm.HS256_PKDS);

    sighWithHSPKDS("JWK HS384_PKDS",
        PKDSHeaderParam.builder()
            .suite(PKDSSuite.ECDH_HKDF_SHA256)
            .recipientPublicKey(PKDSPublicKey.builder()
                .jwk(serverJwk)
                .build())
            .producerPublicKey(PKDSPublicKey.builder()
                .jwk(clientJwk)
                .build())
            .build(),
        HSPKDSAlgorithm.HS384_PKDS);

    sighWithHSPKDS("JWK HS512_PKDS",
        PKDSHeaderParam.builder()
            .suite(PKDSSuite.ECDH_HKDF_SHA256)
            .recipientPublicKey(PKDSPublicKey.builder()
                .jwk(serverJwk)
                .build())
            .producerPublicKey(PKDSPublicKey.builder()
                .jwk(clientJwk)
                .build())
            .build(),
        HSPKDSAlgorithm.HS512_PKDS);

  }

  void sighWithHSPKDS(String message, PKDSHeaderParam pkdsHeaderParam, HSPKDSAlgorithm algorithm)
      throws Exception {
    log.info(message);
    PKDSKeyDerivation signerKeyDerivation =
        new PrivateKeyPKDSKeyDerivation((ECPrivateKey) clientKey.getPrivate());
    JWSSigner signer = new HSECPkdsSigner(algorithm, signerKeyDerivation);

    String payload = StaticResources.OBJECT_MAPPER.writeValueAsString(TestMessage.builder()
        .message("Hello World!")
        .build());
    JWSHeader jwsHeader = new JWSHeader.Builder(algorithm.getAlg())
        .customParam(HSECPkdsSigner.PKDS_HEADER_PARAM, pkdsHeaderParam.toJsonObject())
        .build();
    JWSObject jwsObject = new JWSObject(jwsHeader, new Payload(payload));
    jwsObject.sign(signer);
    String signedJWS = jwsObject.serialize();

    assertNotNull(signedJWS);
    assertEquals(3, signedJWS.split("\\.").length);

    log.info("Signed JWS using HS256_PKDS: {}", signedJWS);
    log.info("Header:\n{}", StaticResources.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
        .writeValueAsString(jwsObject.getHeader().toJSONObject()));
    log.info("Payload:\n{}", StaticResources.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
        .writeValueAsString(jwsObject.getPayload().toJSONObject()));
    log.info("Signature:\n{}", jwsObject.getSignature());

    PKDSKeyDerivation verifierKeyDerivation =
        new PrivateKeyPKDSKeyDerivation((ECPrivateKey) serverKey.getPrivate());
    JWSVerifier verifier = new HSECPkdsVerifier(algorithm, verifierKeyDerivation);
    final boolean verify = jwsObject.verify(verifier);
    log.info("Verified: {}", verify);
    assertTrue(verify);
  }

}
