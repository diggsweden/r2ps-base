package se.digg.wallet.r2ps.commons.dto.payload;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSASigner;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.crypto.hashtocurve.data.HashToCurveProfile;
import se.digg.crypto.opaque.OpaqueUtils;
import se.digg.crypto.opaque.client.ClientState;
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
import se.digg.crypto.opaque.dto.KE1;
import se.digg.wallet.r2ps.commons.dto.JWEEncryptionParams;
import se.digg.wallet.r2ps.commons.dto.JWSSigningParams;
import se.digg.wallet.r2ps.commons.dto.PakeState;
import se.digg.wallet.r2ps.commons.dto.ServiceRequest;
import se.digg.wallet.r2ps.commons.dto.ServiceResponse;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceType;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceTypeRegistry;
import se.digg.wallet.r2ps.commons.pake.ECUtils;
import se.digg.wallet.r2ps.commons.utils.ServiceExchangeFactory;
import se.digg.wallet.r2ps.commons.utils.Utils;
import se.digg.wallet.r2ps.test.data.TestCredentials;

@Slf4j
class ExchangePayloadTest {

  static ObjectMapper mapper = new ObjectMapper();

  static HashFunctions sha256hash;
  static OpaqueCurve p256Curve;
  static OprfFunctions oprfP256;
  static KeyDerivationFunctions hkdfKeyDerivation;
  static ServiceTypeRegistry serviceTypeRegistry;
  static ServiceExchangeFactory serviceExchangeFactory;

  @BeforeAll
  static void setUp() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
    sha256hash =
        new HashFunctions(
            SHA256Digest.newInstance(), new ArgonStretch(ArgonStretch.ARGON_PROFILE_DEFAULT));
    hkdfKeyDerivation = new HKDFKeyDerivation(sha256hash);
    p256Curve =
        new DefaultOpaqueCurve(
            ECNamedCurveTable.getParameterSpec("P-256"),
            HashToCurveProfile.P256_XMD_SHA_256_SSWU_RO_,
            new DstContext(DstContext.IDENTIFIER_P256_SHA256));
    oprfP256 = new DefaultOprfFunction(p256Curve, sha256hash, "OPAQUE-POC");
    serviceTypeRegistry = new ServiceTypeRegistry();
    serviceExchangeFactory = new ServiceExchangeFactory();
  }

  @Test
  void createExchangeTokenTest() throws Exception {

    OpaqueClient client = new DefaultOpaqueClient(oprfP256, hkdfKeyDerivation, sha256hash);

    JWSSigningParams signingParams =
        new JWSSigningParams(
            new ECDSASigner((ECPrivateKey) TestCredentials.p256keyPair.getPrivate()),
            JWSAlgorithm.ES256);

    final byte[] seededPin = OpaqueUtils.random(32);
    log.info("Seeded PIN: {}", Hex.toHexString(seededPin));

    ClientState clientState = new ClientState();
    final KE1 ke1 = client.generateKe1(seededPin, clientState);

    ServiceRequest request =
        ServiceRequest.builder()
            .clientID("ID-198357382432")
            .kid(
                Base64.toBase64String(
                    ECUtils.serializePublicKey(TestCredentials.p256keyPair.getPublic())))
            .nonce("nonce-123456")
            .serviceType(ServiceType.AUTHENTICATE)
            .build();

    PakeRequestPayload payload =
        PakeRequestPayload.builder()
            .state(PakeState.evaluate)
            .requestData(ke1.getEncoded())
            .build();

    JWEEncryptionParams encryptionParams =
        new JWEEncryptionParams(
            (ECPublicKey) TestCredentials.serverKeyPair.getPublic(), EncryptionMethod.A128GCM);

    final String serviceExchangeObject =
        serviceExchangeFactory.createServiceExchangeObject(
            serviceTypeRegistry.getServiceType(ServiceType.AUTHENTICATE),
            request,
            payload,
            signingParams,
            encryptionParams);
    assertNotNull(serviceExchangeObject);
    logExchange(serviceExchangeObject, (ECPrivateKey) TestCredentials.serverKeyPair.getPrivate());

    // Create Server response
    ServiceResponse serviceResponse = ServiceResponse.builder().nonce("nonce-123456").build();
    PakeResponsePayload pakeResponsePayload =
        PakeResponsePayload.builder()
            .pakeSessionId("session-id-123456")
            .responseData("Ke2-response bytes".getBytes())
            .build();

    JWEEncryptionParams serverEncryptionParams =
        new JWEEncryptionParams(
            (ECPublicKey) TestCredentials.p256keyPair.getPublic(), EncryptionMethod.A128GCM);

    final String serviceResponseExchange =
        serviceExchangeFactory.createServiceExchangeObject(
            serviceTypeRegistry.getServiceType(ServiceType.AUTHENTICATE),
            serviceResponse,
            pakeResponsePayload,
            signingParams,
            serverEncryptionParams);
    assertNotNull(serviceResponseExchange);
    logExchange(serviceResponseExchange, (ECPrivateKey) TestCredentials.p256keyPair.getPrivate());
  }

  void logExchange(String serviceExchangeObject, ECPrivateKey decryptionStaticKey)
      throws Exception {
    log.info("Service exchange object for OPAQUE exchange:\n{}", serviceExchangeObject);
    final Map<String, Object> signedPayload =
        JWSObject.parse(serviceExchangeObject).getPayload().toJSONObject();
    log.info(
        "Signed payload:\n{}",
        mapper.writerWithDefaultPrettyPrinter().writeValueAsString(signedPayload));

    final Object serviceData = signedPayload.get("data");
    final byte[] serviceDataBytes = Base64.decode(serviceData.toString());
    log.info("ESDH Encrypted Service data:\n{}", serviceData);
    final byte[] decrypted = Utils.decryptJWEECDH(serviceDataBytes, decryptionStaticKey);
    final String serviceDataString = new String(decrypted, StandardCharsets.UTF_8);
    log.info("Decrypted Service data:\n{}", prettyPrint(serviceDataString));
  }

  private String prettyPrint(final String jsonString) throws Exception {
    return mapper
        .writerWithDefaultPrettyPrinter()
        .writeValueAsString(mapper.readValue(jsonString, Map.class));
  }
}
