package se.digg.wallet.r2ps.client.api.impl;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.io.IOException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.wallet.r2ps.client.api.ServiceResult;
import se.digg.wallet.r2ps.commons.StaticResources;
import se.digg.wallet.r2ps.commons.dto.EncryptOption;
import se.digg.wallet.r2ps.commons.dto.HttpResponse;
import se.digg.wallet.r2ps.commons.dto.JWSSigningParams;
import se.digg.wallet.r2ps.commons.dto.ServiceResponse;
import se.digg.wallet.r2ps.commons.dto.payload.PakeResponsePayload;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceType;
import se.digg.wallet.r2ps.commons.exception.ServiceResponseException;
import se.digg.wallet.r2ps.commons.jwe.AsymmetricJweDecryptor;
import se.digg.wallet.r2ps.commons.jwe.AsymmetricJweEncryptor;
import se.digg.wallet.r2ps.commons.jwe.JweDecryptor;
import se.digg.wallet.r2ps.commons.jwe.JweEncryptor;
import se.digg.wallet.r2ps.commons.utils.ServiceExchangeBuilder;
import se.digg.wallet.r2ps.test.data.TestCredentials;

class ServiceResponseParserTest {

  private static JWSVerifier jwsVerifier;

  @BeforeAll
  static void setup() throws JOSEException {
    jwsVerifier = new ECDSAVerifier((ECPublicKey) TestCredentials.serverOprfKeyPair.getPublic());
  }

  @Test
  void emptyResponseThrowsException() {
    assertThatThrownBy(() -> ServiceResponseParser.parse(null, null, null))
        .isInstanceOf(ServiceResponseException.class)
        .hasMessage("No service response data from server");
  }

  @Test
  void missingResponseDataThrowsException() {
    assertThatThrownBy(() -> ServiceResponseParser.parse(new HttpResponse(null, 200), null, null))
        .isInstanceOf(ServiceResponseException.class)
        .hasMessage("No service response data from server");
  }

  @Test
  void non200ReturnsErrorResponse() throws ServiceResponseException {
    String responseData = "{\"error_message\": \"someError\",\"error_code\": 400}";
    HttpResponse httpResponse = new HttpResponse(responseData, 400);

    ServiceResult parseResult = ServiceResponseParser.parse(httpResponse, null, null);

    assertThat(parseResult)
        .satisfies(
            result -> {
              assertThat(result.serviceResponse()).isNull();
              assertThat(result.decryptedPayload()).isNull();
              assertThat(result.errorResponse().getMessage()).isEqualTo("someError");
              assertThat(result.success()).isFalse();
              assertThat(result.httpStatusCode()).isEqualTo(400);
            });
  }

  @Test
  void successfulResponseReturnsServiceResponse()
      throws ServiceResponseException, JOSEException, IOException {
    HttpResponse httpResponse = createPakeHttpResponse(Instant.now());

    JweDecryptor jweDecryptor =
        new AsymmetricJweDecryptor((ECPrivateKey) TestCredentials.p256keyPair.getPrivate());

    ServiceResult parseResult =
        ServiceResponseParser.parse(httpResponse, jweDecryptor, jwsVerifier);

    assertThat(parseResult)
        .satisfies(
            result -> {
              assertThat(result.serviceResponse()).isNotNull();
              assertThat(result.decryptedPayload()).isNotNull();
              assertThat(result.errorResponse()).isNull();
              assertThat(result.success()).isTrue();
              assertThat(result.httpStatusCode()).isEqualTo(200);
            });

    PakeResponsePayload pakeResponsePayload =
        StaticResources.TIME_STAMP_SECONDS_MAPPER.readValue(
            parseResult.decryptedPayload(), PakeResponsePayload.class);

    assertThat(pakeResponsePayload.getResponseData()).isEqualTo("someData".getBytes(UTF_8));
  }

  @Test
  void unverifiableResponseThrowsException() throws JOSEException, JsonProcessingException {
    HttpResponse httpResponse = createUnverifiableHttpResponse();

    assertThatThrownBy(() -> ServiceResponseParser.parse(httpResponse, null, jwsVerifier))
        .isInstanceOf(ServiceResponseException.class)
        .hasMessage("Failed to verify service response signature");
  }

  @Test
  void tooOldResponseThrowsException() throws JOSEException, JsonProcessingException {
    HttpResponse httpResponse = createPakeHttpResponse(Instant.now().minusSeconds(40));

    assertThatThrownBy(() -> ServiceResponseParser.parse(httpResponse, null, jwsVerifier))
        .isInstanceOf(ServiceResponseException.class)
        .hasMessage("Service response is more than 30 seconds old");
  }

  private HttpResponse createPakeHttpResponse(Instant iat)
      throws JOSEException, JsonProcessingException {
    JWSSigningParams signingParams =
        new JWSSigningParams(
            new ECDSASigner((ECPrivateKey) TestCredentials.serverOprfKeyPair.getPrivate()),
            JWSAlgorithm.ES256);

    JweEncryptor jweEncryptor =
        new AsymmetricJweEncryptor(
            (ECPublicKey) TestCredentials.p256keyPair.getPublic(), EncryptionMethod.A256GCM);

    ServiceResponse serviceResponse = new ServiceResponse();
    serviceResponse.setIat(iat);

    PakeResponsePayload exchangePayload =
        PakeResponsePayload.builder().responseData("someData".getBytes(UTF_8)).build();

    String serverResponse =
        ServiceExchangeBuilder.build(
            new ServiceType(ServiceType.AUTHENTICATE, EncryptOption.user),
            serviceResponse,
            exchangePayload,
            signingParams,
            jweEncryptor);

    return new HttpResponse(serverResponse, 200);
  }

  private HttpResponse createUnverifiableHttpResponse()
      throws JOSEException, JsonProcessingException {

    ECPrivateKey dummyKey = new ECKeyGenerator(Curve.P_256).generate().toECPrivateKey();

    JWSSigningParams signingParams =
        new JWSSigningParams(new ECDSASigner(dummyKey), JWSAlgorithm.ES256);

    JweEncryptor jweEncryptor =
        new AsymmetricJweEncryptor(
            (ECPublicKey) TestCredentials.p256keyPair.getPublic(), EncryptionMethod.A256GCM);

    ServiceResponse serviceResponse = new ServiceResponse();
    serviceResponse.setIat(Instant.now());

    PakeResponsePayload exchangePayload =
        PakeResponsePayload.builder().responseData("someData".getBytes(UTF_8)).build();

    String serverResponse =
        ServiceExchangeBuilder.build(
            new ServiceType(ServiceType.AUTHENTICATE, EncryptOption.user),
            serviceResponse,
            exchangePayload,
            signingParams,
            jweEncryptor);

    return new HttpResponse(serverResponse, 200);
  }
}
