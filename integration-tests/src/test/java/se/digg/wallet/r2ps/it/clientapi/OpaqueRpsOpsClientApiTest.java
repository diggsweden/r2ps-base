package se.digg.wallet.r2ps.it.clientapi;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.crypto.opaque.OpaqueUtils;
import se.digg.wallet.r2ps.client.api.RpsOpsClientApi;
import se.digg.wallet.r2ps.client.api.ServiceExchangeConnector;
import se.digg.wallet.r2ps.client.api.ServiceResult;
import se.digg.wallet.r2ps.client.api.impl.OpaqueRpsOpsClientApi;
import se.digg.wallet.r2ps.client.api.impl.OpaqueRpsOpsConfiguration;
import se.digg.wallet.r2ps.commons.dto.payload.ByteArrayPayload;
import se.digg.wallet.r2ps.commons.dto.payload.DHRequestPayload;
import se.digg.wallet.r2ps.commons.dto.payload.HSMParams;
import se.digg.wallet.r2ps.commons.dto.payload.JsonPayload;
import se.digg.wallet.r2ps.commons.dto.payload.ListKeysResponsePayload;
import se.digg.wallet.r2ps.commons.dto.payload.SignRequestPayload;
import se.digg.wallet.r2ps.commons.dto.payload.StringPayload;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceType;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceTypeRegistry;
import se.digg.wallet.r2ps.commons.exception.PakeAuthenticationException;
import se.digg.wallet.r2ps.commons.pake.ECUtils;
import se.digg.wallet.r2ps.commons.pake.opaque.InMemoryPakeSessionRegistry;
import se.digg.wallet.r2ps.commons.pake.opaque.OpaqueConfiguration;
import se.digg.wallet.r2ps.commons.pake.opaque.PakeSessionRegistry;
import se.digg.wallet.r2ps.it.testimpl.TestConnector;
import se.digg.wallet.r2ps.it.testimpl.TestHsmServiceHandler;
import se.digg.wallet.r2ps.it.testimpl.TestReplayChecker;
import se.digg.wallet.r2ps.server.pake.opaque.ClientRecordRegistry;
import se.digg.wallet.r2ps.server.pake.opaque.ServerPakeRecord;
import se.digg.wallet.r2ps.server.pake.opaque.impl.FileBackedClientRecordRegistry;
import se.digg.wallet.r2ps.server.service.ClientPublicKeyRecord;
import se.digg.wallet.r2ps.server.service.ClientPublicKeyRegistry;
import se.digg.wallet.r2ps.server.service.OpaqueServiceRequestHandlerConfiguration;
import se.digg.wallet.r2ps.commons.StaticResources;
import se.digg.wallet.r2ps.server.service.impl.FileBackedClientPublicKeyRegistry;
import se.digg.wallet.r2ps.server.service.impl.DefaultServiceRequestHandler;
import se.digg.wallet.r2ps.client.jws.HSECPkdsSigner;
import se.digg.wallet.r2ps.client.jws.HSECPkdsVerifier;
import se.digg.wallet.r2ps.client.jws.RemoteHsmECDSASigner;
import se.digg.wallet.r2ps.client.jws.pkds.HSPKDSAlgorithm;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSHeaderParam;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSPublicKey;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSSuite;
import se.digg.wallet.r2ps.client.jws.pkds.impl.PrivateKeyPKDSKeyDerivation;
import se.digg.wallet.r2ps.client.jws.pkds.impl.RemoteHsmPKDSKeyDerivation;
import se.digg.wallet.r2ps.server.service.pinauthz.impl.CodeMatchPinAuthorization;
import se.digg.wallet.r2ps.server.service.servicehandlers.OpaqueServiceHandler;
import se.digg.wallet.r2ps.server.service.servicehandlers.ServiceTypeHandler;
import se.digg.wallet.r2ps.server.service.servicehandlers.SessionServiceHandler;
import se.digg.wallet.r2ps.test.data.TestCredentials;
import se.digg.wallet.r2ps.test.data.TestMessage;
import se.digg.wallet.r2ps.test.testUtils.JSONUtils;

import javax.crypto.KeyAgreement;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Slf4j
class OpaqueRpsOpsClientApiTest {

  static RpsOpsClientApi clientApi;
  static ServiceTypeRegistry serviceTypeRegistry;
  static String clientIdentity;
  static String serverIdentity;
  static ClientPublicKeyRegistry clientPublicKeyRegistry;
  static String kid;
  static String kidHsm;

  @BeforeAll
  static void setUp() throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
    clientIdentity = "https://example.com/wallet/1";
    serverIdentity = "https://example.com/oaque/server";
    kid =
        Base64.toBase64String(ECUtils.serializePublicKey(TestCredentials.p256keyPair.getPublic()));
    kidHsm = Base64.toBase64String(
        ECUtils.serializePublicKey(TestCredentials.walletHsmAccessP256keyPair.getPublic()));
    serviceTypeRegistry = new ServiceTypeRegistry();

    clientApi = new OpaqueRpsOpsClientApi(OpaqueRpsOpsConfiguration.builder()
        .clientIdentity(clientIdentity)
        .contextSessionDuration(Duration.ofMinutes(5))
        .serviceExchangeConnector(createTestConnector())
        .serviceTypeRegistry(serviceTypeRegistry)
        .addContext("test", kid, TestCredentials.p256keyPair, JWSAlgorithm.ES256, serverIdentity,
            TestCredentials.serverOprfKeyPair.getPublic())
        .addContext("hsm", kidHsm, TestCredentials.walletHsmAccessP256keyPair, JWSAlgorithm.ES256,
            serverIdentity,
            TestCredentials.serverOprfKeyPair.getPublic())
        .build());
  }

  /**
   * Creates a test implementation of the {@link ServiceExchangeConnector} using the specified
   * {@link OpaqueConfiguration}. This method sets up a test environment including service handlers
   * and configuration needed to process secure service exchanges.
   *
   * @return an instance of {@link ServiceExchangeConnector}, specifically a test implementation
   * @throws Exception if any error occurs during the creation or configuration of the test
   *                   connector
   */
  private static ServiceExchangeConnector createTestConnector()
      throws Exception {

    // Create a public key registry initiated for each test with no authorization codes.
    clientPublicKeyRegistry = new FileBackedClientPublicKeyRegistry(null);
    clientPublicKeyRegistry.registerClientPublicKey(clientIdentity, ClientPublicKeyRecord.builder()
        .kid(kid)
        .publicKey(TestCredentials.p256keyPair.getPublic())
        .supportedContexts(List.of("test")).build());
    clientPublicKeyRegistry.registerClientPublicKey(clientIdentity, ClientPublicKeyRecord.builder()
        .kid(kidHsm)
        .publicKey(TestCredentials.walletHsmAccessP256keyPair.getPublic())
        .supportedContexts(List.of("hsm")).build());

    PakeSessionRegistry<ServerPakeRecord> serverPakeSessionRegistry =
        new InMemoryPakeSessionRegistry<>();
    List<ServiceTypeHandler> serviceTypeHandlerList = new ArrayList<>();
    serviceTypeHandlerList.add(
        new TestHsmServiceHandler(List.of("P-256", "P-384", "P-521"), List.of("hsm")));

    ClientRecordRegistry clientRecordRegistry = new FileBackedClientRecordRegistry(null);

    final byte[] oprfSeed = OpaqueUtils.random(32);
    log.info("Server OPRFSeed: {}", Hex.toHexString(oprfSeed));

    serviceTypeHandlerList.add(
        new OpaqueServiceHandler(List.of("hsm", "test"), new CodeMatchPinAuthorization(clientPublicKeyRegistry),
            OpaqueConfiguration.defaultConfiguration(), serverIdentity, oprfSeed, TestCredentials.serverOprfKeyPair,
            serverPakeSessionRegistry, clientRecordRegistry , Duration.ofMinutes(15), Duration.ofSeconds(5)));

    serviceTypeHandlerList.add(
        new SessionServiceHandler(serverPakeSessionRegistry));

    // Create a service request handler that can process service requests from the client
    DefaultServiceRequestHandler opaqueServiceRequestHandler =
        new DefaultServiceRequestHandler(OpaqueServiceRequestHandlerConfiguration.builder()
            .serverKeyPair(TestCredentials.serverOprfKeyPair)
            .serverJwsAlgorithm(JWSAlgorithm.ES256)
            .serverPakeSessionRegistry(serverPakeSessionRegistry)
            .clientPublicKeyRegistry(clientPublicKeyRegistry)
            .serviceTypeRegistry(serviceTypeRegistry)
            .serviceTypeHandlers(serviceTypeHandlerList)
            .replayChecker(new TestReplayChecker())
            .build());

    // Create an HTTP connector that produces service responses using an internal request handler instead of sending them to a server
    return new TestConnector(opaqueServiceRequestHandler);
  }

  @Test
  void testFailedLoginAttempt() throws Exception {
    // Set authorization codes for PIN registration
    clientPublicKeyRegistry.setAuthorizationCode(clientIdentity, kid, "123456".getBytes());
    clientPublicKeyRegistry.setAuthorizationCode(clientIdentity, kidHsm, "987654321".getBytes());

    clientApi.registerPin("1234", "test", "123456".getBytes());

    // login with wrong PIN
    assertThrows(
        PakeAuthenticationException.class, () -> clientApi.createSession("111111", "test"));
  }

  @Test
  void createKeyAndRemoteSignAndDH() throws Exception {
    // Set authorization codes for PIN registration
    clientPublicKeyRegistry.setAuthorizationCode(clientIdentity, kid, "123456".getBytes());
    clientPublicKeyRegistry.setAuthorizationCode(clientIdentity, kidHsm, "987654321".getBytes());

    // Register new PIN
    clientApi.registerPin("1234", "test", "123456".getBytes());
    clientApi.registerPin("1234", "hsm", "987654321".getBytes());

    // Change PIN
    clientApi.changePin("4321", "test", "1234");
    clientApi.changePin("4321", "hsm", "1234");

    // Authenticate with the changed PIN
    final String testSessionId = clientApi.createSession("4321", "test").getPakeSessionId();
    final String hsmSessionId = clientApi.createSession("4321", "hsm").getPakeSessionId();

    // List available HSM keys
    final List<ListKeysResponsePayload.KeyInfo> keyInfo0 =
        clientApi.userAuthenticatedService(ServiceType.HSM_LIST_KEYS, JsonPayload.builder()
                .add(HSMParams.CURVE, List.of())
                .build(),
            "hsm", hsmSessionId).getPayload(ListKeysResponsePayload.class).getKeyInfo();
    assertEquals(0, keyInfo0.size());
    clientApi.userAuthenticatedService(ServiceType.HSM_KEYGEN, JsonPayload.builder()
        .add(HSMParams.CURVE, "P-256")
        .build(), "hsm", hsmSessionId);
    final List<ListKeysResponsePayload.KeyInfo> keyInfo1 =
        clientApi.userAuthenticatedService(ServiceType.HSM_LIST_KEYS, JsonPayload.builder()
                .add(HSMParams.CURVE, List.of())
                .build(),
            "hsm", hsmSessionId).getPayload(ListKeysResponsePayload.class).getKeyInfo();
    assertEquals(1, keyInfo1.size());
    log.info("Available HSM keys:\n{}",
        StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
            .writeValueAsString(keyInfo1));

    String hsmKidP256 = keyInfo1.getFirst().getKid();

    // Test DH
    byte[] sharedSecret =
        clientApi.userAuthenticatedService(ServiceType.HSM_ECDH,
            DHRequestPayload.builder()
                .kid(hsmKidP256)
                .publicKey(TestCredentials.p256keyPair.getPublic())
                .build(),
            "hsm", hsmSessionId).getPayload(ByteArrayPayload.class).getByteArrayValue();

    PublicKey hsmPublic = keyInfo1.getFirst().getPublicKey();
    PrivateKey clientPrivate = TestCredentials.p256keyPair.getPrivate();

    KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
    keyAgreement.init(clientPrivate);
    keyAgreement.doPhase(hsmPublic, true);
    byte[] clientSharedSecret = keyAgreement.generateSecret();

    Assertions.assertArrayEquals(sharedSecret, clientSharedSecret);

    // Test signature
    byte[] message = "This message will be signed".getBytes();

    // Sign
    byte[] signatureValue =
        clientApi.userAuthenticatedService(ServiceType.HSM_ECDSA,
                SignRequestPayload.builder()
                    .kid(hsmKidP256)
                    .tbsHash(message, "SHA-256")
                    .build(), "hsm", hsmSessionId).getPayload(ByteArrayPayload.class)
            .getByteArrayValue();
    // Verify
    Signature sig = Signature.getInstance("SHA256withECDSA", "BC");
    sig.initVerify(keyInfo1.getFirst().getPublicKey());
    sig.update(message);
    assertTrue(sig.verify(signatureValue));

    // Check context protection
    final ServiceResult failureResult = clientApi.userAuthenticatedService(ServiceType.HSM_ECDSA,
        SignRequestPayload.builder()
            .kid(hsmKidP256)
            .tbsHash(message, "SHA-256")
            .build(), "test", testSessionId);
    assertFalse(failureResult.success());
    log.info("Context protection failed as expected with error code {} and message: {}",
        failureResult.errorResponse().getErrorCode(), failureResult.errorResponse().getMessage());
  }

  @Test
  void remoteJwsSign() throws Exception {
    // Set authorization codes for PIN registration
    clientPublicKeyRegistry.setAuthorizationCode(clientIdentity, kidHsm, "987654321".getBytes());

    // Register new PIN
    clientApi.registerPin("1234", "hsm", "987654321".getBytes());

    // Authenticate with the changed PIN
    final String hsmSessionId = clientApi.createSession("1234", "hsm").getPakeSessionId();

    // Create signing keys
    final List<ListKeysResponsePayload.KeyInfo> p256HsmKeyList =
        clientApi.userAuthenticatedService(ServiceType.HSM_LIST_KEYS,
            JsonPayload.builder().add(HSMParams.CURVE, List.of("P-256")).build(), "hsm",
            hsmSessionId).getPayload(
            ListKeysResponsePayload.class).getKeyInfo();

    if (p256HsmKeyList.isEmpty()) {
      clientApi.userAuthenticatedService(
          ServiceType.HSM_KEYGEN, JsonPayload.builder().add(HSMParams.CURVE, "P-256").build(),
          "hsm",
          hsmSessionId);
    }
    clientApi.userAuthenticatedService(
        ServiceType.HSM_KEYGEN, JsonPayload.builder().add(HSMParams.CURVE, "P-384").build(), "hsm",
        hsmSessionId);
    clientApi.userAuthenticatedService(
        ServiceType.HSM_KEYGEN, JsonPayload.builder().add(HSMParams.CURVE, "P-521").build(), "hsm",
        hsmSessionId);
    final ServiceResult serviceResult =
        clientApi.userAuthenticatedService(ServiceType.HSM_LIST_KEYS, JsonPayload.builder()
            .add(HSMParams.CURVE, List.of()).build(), "hsm", hsmSessionId);

    // Retrieve hsm key info
    final Map<String, ListKeysResponsePayload.KeyInfo> keyInfoMap = serviceResult.getPayload(
            ListKeysResponsePayload.class).getKeyInfo().stream()
        .collect(
            Collectors.toMap(ListKeysResponsePayload.KeyInfo::getCurveName, keyInfo -> keyInfo,
                (existing, replacement) -> replacement));

    log.info("Signing with P-256 key");
    jwsSign(JWSAlgorithm.ES256, keyInfoMap.get("P-256"), "hsm", hsmSessionId);
    log.info("Signing with P-384 key");
    jwsSign(JWSAlgorithm.ES384, keyInfoMap.get("P-384"), "hsm", hsmSessionId);
    log.info("Signing with P-521 key");
    jwsSign(JWSAlgorithm.ES512, keyInfoMap.get("P-521"), "hsm", hsmSessionId);

    PKDSHeaderParam clientPkdsHeaderParam = PKDSHeaderParam.builder()
        .suite(PKDSSuite.ECDH_HKDF_SHA256)
        .producerPublicKey(PKDSPublicKey.builder()
            .jwk(JSONUtils.getJWKfromPublicKey(keyInfoMap.get("P-256").getPublicKey()))
            .build())
        .recipientPublicKey(PKDSPublicKey.builder()
            .jwk(JSONUtils.getJWKfromPublicKey(TestCredentials.serverKeyPair.getPublic()))
            .build())
        .build();

    hsPkdsClientSign(HSPKDSAlgorithm.HS256_PKDS, clientPkdsHeaderParam, keyInfoMap.get("P-256"),
        "hsm", hsmSessionId);

    PKDSHeaderParam serverPkdsHeaderParam = PKDSHeaderParam.builder()
        .suite(PKDSSuite.ECDH_HKDF_SHA256)
        .producerPublicKey(PKDSPublicKey.builder()
            .jwk(JSONUtils.getJWKfromPublicKey(TestCredentials.serverKeyPair.getPublic()))
            .build())
        .recipientPublicKey(PKDSPublicKey.builder()
            .jwk(JSONUtils.getJWKfromPublicKey(keyInfoMap.get("P-256").getPublicKey()))
            .build())
        .build();

    hsPkdsServerSign(HSPKDSAlgorithm.HS256_PKDS, serverPkdsHeaderParam, keyInfoMap.get("P-256"),
        "hsm", hsmSessionId);

  }

  void jwsSign(JWSAlgorithm jwsAlgorithm, ListKeysResponsePayload.KeyInfo keyInfo, String context,
      String sessionId)
      throws Exception {
    // create signer
    RemoteHsmECDSASigner remoteHsmECDSASigner = new RemoteHsmECDSASigner(clientApi, context,
        keyInfo.getKid(), jwsAlgorithm, sessionId);

    // create signature
    String message = StaticResources.OBJECT_MAPPER.writeValueAsString(
        new StringPayload("This message will be signed"));
    JWSHeader header = new JWSHeader.Builder(jwsAlgorithm)
        .type(JOSEObjectType.JOSE)
        .keyID(keyInfo.getKid())
        .build();
    JWSObject jwsObject = new JWSObject(header, new Payload(message));
    jwsObject.sign(remoteHsmECDSASigner);
    final String remoteSignedJws = jwsObject.serialize();
    log.info("Remote signed JWS\n{}", remoteSignedJws);

    log.info("Signed JWS header:\n{}",
        StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
            .writeValueAsString(jwsObject.getHeader().toJSONObject()));
    log.info("Signed JWS payload:\n{}",
        StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
            .writeValueAsString(jwsObject.getPayload().toJSONObject()));

    // Verify Signature
    JWSVerifier verifier = new ECDSAVerifier((ECPublicKey) keyInfo.getPublicKey());
    assertTrue(jwsObject.verify(verifier));
    log.info("Remote signature verified");

  }

  void hsPkdsClientSign(HSPKDSAlgorithm algorithm, PKDSHeaderParam pkdsHeaderParam,
      ListKeysResponsePayload.KeyInfo keyInfo, String context, String sessionId) throws Exception {

    JWSSigner signer = new HSECPkdsSigner(algorithm,
        new RemoteHsmPKDSKeyDerivation(clientApi, context, keyInfo.getKid(), sessionId));
    log.info("Client signing JWS with HS-PKDS");

    // create signature
    String message = StaticResources.OBJECT_MAPPER.writeValueAsString(TestMessage.builder()
        .message("This message will be signed")
        .build());
    JWSHeader header = new JWSHeader.Builder(algorithm.getAlg())
        .type(JOSEObjectType.JOSE)
        .customParam(HSECPkdsSigner.PKDS_HEADER_PARAM, pkdsHeaderParam.toJsonObject())
        .build();
    JWSObject jwsObject = new JWSObject(header, new Payload(message));
    jwsObject.sign(signer);
    final String remoteSignedJws = jwsObject.serialize();
    log.info("Client signed JWS using remote HSM DH\n{}", remoteSignedJws);

    log.info("Client signed JWS header:\n{}",
        StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
            .writeValueAsString(jwsObject.getHeader().toJSONObject()));
    log.info("Client signed JWS payload:\n{}",
        StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
            .writeValueAsString(jwsObject.getPayload().toJSONObject()));

    // Verify Signature
    JWSVerifier verifier = new HSECPkdsVerifier(algorithm,
        new PrivateKeyPKDSKeyDerivation((ECPrivateKey) TestCredentials.serverKeyPair.getPrivate()));
    assertTrue(jwsObject.verify(verifier));
    log.info("Server verification of client signed JWS succeeded");
  }

  void hsPkdsServerSign(HSPKDSAlgorithm algorithm, PKDSHeaderParam pkdsHeaderParam,
      ListKeysResponsePayload.KeyInfo keyInfo, String context, String sessionId) throws Exception {
    JWSSigner signer = new HSECPkdsSigner(algorithm,
        new PrivateKeyPKDSKeyDerivation((ECPrivateKey) TestCredentials.serverKeyPair.getPrivate()));
    log.info("Server signing JWS with HS-PKDS");

    // create signature
    String message = StaticResources.OBJECT_MAPPER.writeValueAsString(TestMessage.builder()
        .message("This message will be signed")
        .build());
    JWSHeader header = new JWSHeader.Builder(algorithm.getAlg())
        .type(JOSEObjectType.JOSE)
        .customParam(HSECPkdsSigner.PKDS_HEADER_PARAM, pkdsHeaderParam.toJsonObject())
        .build();
    JWSObject jwsObject = new JWSObject(header, new Payload(message));
    jwsObject.sign(signer);
    final String remoteSignedJws = jwsObject.serialize();
    log.info("Server signed JWS\n{}", remoteSignedJws);

    log.info("Server signed JWS header:\n{}",
        StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
            .writeValueAsString(jwsObject.getHeader().toJSONObject()));
    log.info("Server signed JWS payload:\n{}",
        StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
            .writeValueAsString(jwsObject.getPayload().toJSONObject()));

    // Verify Signature
    JWSVerifier verifier = new HSECPkdsVerifier(algorithm,
        new RemoteHsmPKDSKeyDerivation(clientApi, context, keyInfo.getKid(), sessionId));
    //JWSVerifier verifier = new RemoteHSECPkdsVerifier(algorithm, clientApi, context, keyInfo.getKid(), sessionId);
    assertTrue(jwsObject.verify(verifier));
    log.info("Server signature verified with client verifier using remote HSM DH");
  }

}
