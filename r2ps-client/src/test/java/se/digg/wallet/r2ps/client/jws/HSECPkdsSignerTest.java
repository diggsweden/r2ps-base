package se.digg.wallet.r2ps.client.jws;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
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
import se.digg.wallet.r2ps.test.testutils.JSONUtils;

@Slf4j
class HSECPkdsSignerTest {

  // Client keys
  static KeyPair clientKey;
  static JWK clientJwk;

  // Server keys
  static KeyPair serverKey;
  static JWK serverJwk;

  @BeforeAll
  static void setUp() throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    // Client keys
    clientKey = TestCredentials.p256keyPair;
    clientJwk = JSONUtils.getJWKfromPublicKey(clientKey.getPublic());

    // Server keys
    serverKey = TestCredentials.p256keyPair;
    serverJwk = JSONUtils.getJWKfromPublicKey(serverKey.getPublic());
  }

  private static Stream<Arguments> hspkdsTestProvider() {

    return Stream.of(
        Arguments.of("JWK HS256_PKDS", createPkdsHeaderParam(), HSPKDSAlgorithm.HS256_PKDS),
        Arguments.of(
            "JWK HS256_PKDS, with info salt and length",
            createPkdsHeaderParamsWithInfoSaltAndLength(),
            HSPKDSAlgorithm.HS256_PKDS),
        Arguments.of("JWK HS384_PKDS", createPkdsHeaderParam(), HSPKDSAlgorithm.HS384_PKDS),
        Arguments.of("JWK HS512_PKDS", createPkdsHeaderParam(), HSPKDSAlgorithm.HS512_PKDS));
  }

  private static PKDSHeaderParam createPkdsHeaderParam() {
    return PKDSHeaderParam.builder()
        .suite(PKDSSuite.ECDH_HKDF_SHA256)
        .recipientPublicKey(PKDSPublicKey.builder().jwk(serverJwk).build())
        .producerPublicKey(PKDSPublicKey.builder().jwk(clientJwk).build())
        .build();
  }

  private static PKDSHeaderParam createPkdsHeaderParamsWithInfoSaltAndLength() {
    return PKDSHeaderParam.builder()
        .suite(PKDSSuite.ECDH_HKDF_SHA256)
        .recipientPublicKey(PKDSPublicKey.builder().jwk(serverJwk).build())
        .producerPublicKey(PKDSPublicKey.builder().jwk(clientJwk).build())
        .params(
            PKDSParams.builder().info(new Base64URL("info")).salt(new Base64URL("salt")).build())
        .length(32)
        .build();
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("hspkdsTestProvider")
  void testHSPKDSSign(
      String testDescription, PKDSHeaderParam pkdsHeaderParam, HSPKDSAlgorithm algorithm)
      throws Exception {

    // Arrange
    JWSSigner signer = createSigner(algorithm);
    JWSObject jwsObject = createJwsObject(pkdsHeaderParam, algorithm);

    // Act
    jwsObject.sign(signer);
    String signedJWS = jwsObject.serialize();

    // Assert
    assertNotNull(signedJWS);
    assertEquals(3, signedJWS.split("\\.").length);

    JWSVerifier verifier = createJwsVerifier(algorithm);
    assertTrue(jwsObject.verify(verifier));
  }

  private JWSSigner createSigner(HSPKDSAlgorithm algorithm) throws JOSEException {
    PKDSKeyDerivation signerKeyDerivation =
        new PrivateKeyPKDSKeyDerivation((ECPrivateKey) clientKey.getPrivate());
    return new HSECPkdsSigner(algorithm, signerKeyDerivation);
  }

  private JWSObject createJwsObject(PKDSHeaderParam pkdsHeaderParam, HSPKDSAlgorithm algorithm)
      throws JsonProcessingException {
    JWSHeader jwsHeader =
        new JWSHeader.Builder(algorithm.getAlg())
            .customParam(HSECPkdsSigner.PKDS_HEADER_PARAM, pkdsHeaderParam.toJsonObject())
            .build();
    Payload payload =
        new Payload(
            StaticResources.OBJECT_MAPPER.writeValueAsString(
                TestMessage.builder().message("Hello World!").build()));
    return new JWSObject(jwsHeader, payload);
  }

  private JWSVerifier createJwsVerifier(HSPKDSAlgorithm algorithm) throws JOSEException {
    PKDSKeyDerivation verifierKeyDerivation =
        new PrivateKeyPKDSKeyDerivation((ECPrivateKey) serverKey.getPrivate());
    return new HSECPkdsVerifier(algorithm, verifierKeyDerivation);
  }
}
