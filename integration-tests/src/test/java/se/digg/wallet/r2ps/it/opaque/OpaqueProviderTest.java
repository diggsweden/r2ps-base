package se.digg.wallet.r2ps.it.opaque;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.time.Duration;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.crypto.hashtocurve.data.HashToCurveProfile;
import se.digg.crypto.opaque.OpaqueUtils;
import se.digg.crypto.opaque.client.ClientKeyExchangeResult;
import se.digg.crypto.opaque.client.ClientState;
import se.digg.crypto.opaque.client.OpaqueClient;
import se.digg.crypto.opaque.client.RegistrationFinalizationResult;
import se.digg.crypto.opaque.client.RegistrationRequestResult;
import se.digg.crypto.opaque.client.impl.DefaultOpaqueClient;
import se.digg.crypto.opaque.crypto.DstContext;
import se.digg.crypto.opaque.crypto.HashFunctions;
import se.digg.crypto.opaque.crypto.KeyDerivationFunctions;
import se.digg.crypto.opaque.crypto.OpaqueCurve;
import se.digg.crypto.opaque.crypto.OprfFunctions;
import se.digg.crypto.opaque.crypto.OprfPrivateKey;
import se.digg.crypto.opaque.crypto.impl.ArgonStretch;
import se.digg.crypto.opaque.crypto.impl.DefaultOpaqueCurve;
import se.digg.crypto.opaque.crypto.impl.DefaultOprfFunction;
import se.digg.crypto.opaque.crypto.impl.HKDFKeyDerivation;
import se.digg.crypto.opaque.dto.KE1;
import se.digg.crypto.opaque.dto.KE2;
import se.digg.crypto.opaque.dto.KE3;
import se.digg.crypto.opaque.dto.RegistrationRecord;
import se.digg.crypto.opaque.dto.RegistrationResponse;
import se.digg.crypto.opaque.server.OpaqueServer;
import se.digg.crypto.opaque.server.ServerState;
import se.digg.crypto.opaque.server.impl.DefaultOpaqueServer;
import se.digg.wallet.r2ps.client.pake.opaque.ClientOpaqueProvider;
import se.digg.wallet.r2ps.client.pake.opaque.ClientPakeRecord;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceTypeRegistry;
import se.digg.wallet.r2ps.commons.dto.servicetype.SessionTaskRegistry;
import se.digg.wallet.r2ps.commons.pake.ECUtils;
import se.digg.wallet.r2ps.commons.pake.opaque.InMemoryPakeSessionRegistry;
import se.digg.wallet.r2ps.commons.pake.opaque.PakeSessionRegistry;
import se.digg.wallet.r2ps.server.pake.opaque.ClientRecordRegistry;
import se.digg.wallet.r2ps.server.pake.opaque.EvaluationResponseResult;
import se.digg.wallet.r2ps.server.pake.opaque.ServerOpaqueEntity;
import se.digg.wallet.r2ps.server.pake.opaque.ServerOpaqueProvider;
import se.digg.wallet.r2ps.server.pake.opaque.ServerPakeRecord;
import se.digg.wallet.r2ps.server.pake.opaque.impl.FileBackedClientRecordRegistry;
import se.digg.wallet.r2ps.test.data.TestCredentials;

class OpaqueProviderTest {

  static ClientOpaqueProvider clientOpaqueProvider;
  static ServerOpaqueProvider serverOpaqueProvider;
  static ServiceTypeRegistry serviceTypeRegistry;
  static ClientRecordRegistry clientRecordRegistry;
  static String clientIdentity;
  static String serverIdentity;
  static OpaqueClient opaqueClient;
  static OpaqueServer opaqueServer;
  static String kid;

  @BeforeAll
  static void init() {

    if (Security.getProvider("BC") == null) {
      Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    HashFunctions sha256hash =
        new HashFunctions(
            SHA256Digest.newInstance(), new ArgonStretch(ArgonStretch.ARGON_PROFILE_DEFAULT));
    KeyDerivationFunctions hkdfKeyDerivation = new HKDFKeyDerivation(sha256hash);
    OpaqueCurve p256Curve =
        new DefaultOpaqueCurve(
            ECNamedCurveTable.getParameterSpec("P-256"),
            HashToCurveProfile.P256_XMD_SHA_256_SSWU_RO_,
            new DstContext(DstContext.IDENTIFIER_P256_SHA256));
    OprfFunctions oprfP256 = new DefaultOprfFunction(p256Curve, sha256hash, "OPAQUE-POC");
    serviceTypeRegistry = new ServiceTypeRegistry();

    opaqueClient = new DefaultOpaqueClient(oprfP256, hkdfKeyDerivation, sha256hash);
    opaqueServer = new DefaultOpaqueServer(oprfP256, hkdfKeyDerivation, sha256hash);

    clientIdentity = "https://example.com/wallet/1";
    serverIdentity = "https://example.com/oaque/server";
    kid =
        Base64.toBase64String(ECUtils.serializePublicKey(TestCredentials.p256keyPair.getPublic()));

    ServerOpaqueEntity serverOpaqueEntity =
        ServerOpaqueEntity.builder()
            .opaqueServer(opaqueServer)
            .serverIdentity(serverIdentity)
            .oprfSeed(OpaqueUtils.random(32))
            .serverHsmKeyPair(TestCredentials.serverKeyPair)
            .serverOpaquePrivateKey(new OprfPrivateKey(TestCredentials.serverOprfKeyPair))
            .serverOpaquePublicKey(
                ECUtils.serializePublicKey(TestCredentials.serverOprfKeyPair.getPublic()))
            .build();

    PakeSessionRegistry<ServerPakeRecord> serverPakeSessionRegistry =
        new InMemoryPakeSessionRegistry<>();

    clientRecordRegistry = new FileBackedClientRecordRegistry(null);

    clientOpaqueProvider = new ClientOpaqueProvider(opaqueClient);
    serverOpaqueProvider =
        new ServerOpaqueProvider(
            serverOpaqueEntity,
            serverPakeSessionRegistry,
            clientRecordRegistry,
            new SessionTaskRegistry(),
            Duration.ofMinutes(5),
            Duration.ofSeconds(5));
  }

  @Test
  void registrationAndAuthTest() throws Exception {

    final byte[] pin = "123456".getBytes();
    final String context = "auth";

    // Register PIN
    final RegistrationRequestResult registrationRequestData =
        clientOpaqueProvider.createRegistrationRequest(pin);
    final byte[] blind = registrationRequestData.blind();
    final byte[] registrationRequest = registrationRequestData.registrationRequest().getEncoded();
    final RegistrationResponse registrationResponse =
        serverOpaqueProvider.registrationResponse(registrationRequest, kid);
    final RegistrationRecord registrationRecord =
        clientOpaqueProvider.finalizeRegistrationRequest(
            pin, blind, registrationResponse.getEncoded(), serverIdentity, clientIdentity);

    serverOpaqueProvider.registrationFinalize(clientIdentity, kid, registrationRecord.getEncoded());

    // Client PIN is registered. Let's authenticate
    ClientState clientState = new ClientState();
    final KE1 ke1 = clientOpaqueProvider.authenticationEvaluate(pin, clientState);
    final EvaluationResponseResult evalResponse =
        serverOpaqueProvider.evaluateAuthRequest(ke1.getEncoded(), clientIdentity, kid, context);
    final String pakeSessionId = evalResponse.pakeSessionId();

    ClientKeyExchangeResult finalizeResult =
        clientOpaqueProvider.authenticationFinalize(
            evalResponse.ke2().getEncoded(), clientState, serverIdentity, clientIdentity);

    ClientPakeRecord clientPakeRecord = ClientPakeRecord.builder()
        .clientId(clientIdentity)
        .pakeSessionId(pakeSessionId)
        .kid(kid)
        .context(context)
        .sessionKey(finalizeResult.sessionKey())
        .exportKey(finalizeResult.exportKey())
        .build();

    KE3 ke3 = finalizeResult.ke3();

    serverOpaqueProvider.finalizeAuthRequest(ke3.getEncoded(), pakeSessionId);

    final ServerPakeRecord serverPakeRecord =
        serverOpaqueProvider.getPakeSessionRegistry().getPakeSession(pakeSessionId);

    assertArrayEquals(serverPakeRecord.getSessionKey(), clientPakeRecord.getSessionKey());
  }

  @Test
  void testRawOpaque() throws Exception {
    byte[] serverPublicKey =
        ECUtils.serializePublicKey(TestCredentials.serverOprfKeyPair.getPublic());
    OprfPrivateKey serverPrivateKey = new OprfPrivateKey(TestCredentials.serverOprfKeyPair);
    byte[] pakeSessionId = OpaqueUtils.random(32);
    byte[] oprfSeed = OpaqueUtils.random(32);

    final RegistrationRequestResult registrationRequest =
        opaqueClient.createRegistrationRequest("123456".getBytes());

    final RegistrationResponse registrationResponse =
        opaqueServer.createRegistrationResponse(
            registrationRequest.registrationRequest().getEncoded(),
            serverPublicKey,
            pakeSessionId,
            oprfSeed);

    final RegistrationFinalizationResult registrationFinalizationResult =
        opaqueClient.finalizeRegistrationRequest(
            "123456".getBytes(),
            registrationRequest.blind(),
            registrationResponse.getEncoded(),
            serverIdentity.getBytes(StandardCharsets.UTF_8),
            clientIdentity.getBytes(StandardCharsets.UTF_8));

    // Authenticate

    ClientState clientState = new ClientState();
    final KE1 ke1 = opaqueClient.generateKe1("123456".getBytes(), clientState);

    ServerState serverState = new ServerState();
    final KE2 ke2 =
        opaqueServer.generateKe2(
            serverIdentity.getBytes(StandardCharsets.UTF_8),
            serverPrivateKey,
            serverPublicKey,
            registrationFinalizationResult.registrationRecord().getEncoded(),
            pakeSessionId,
            oprfSeed,
            ke1.getEncoded(),
            clientIdentity.getBytes(StandardCharsets.UTF_8),
            serverState);

    final ClientKeyExchangeResult clientKeyExchangeResult =
        opaqueClient.generateKe3(
            clientIdentity.getBytes(StandardCharsets.UTF_8),
            serverIdentity.getBytes(StandardCharsets.UTF_8),
            ke2.getEncoded(),
            clientState);

    final byte[] sessionKey =
        opaqueServer.serverFinish(clientKeyExchangeResult.ke3().getEncoded(), serverState);

    assertArrayEquals(sessionKey, clientKeyExchangeResult.sessionKey());
  }
}
