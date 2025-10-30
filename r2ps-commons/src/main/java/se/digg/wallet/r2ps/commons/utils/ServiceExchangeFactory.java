package se.digg.wallet.r2ps.commons.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import java.util.Objects;
import lombok.extern.slf4j.Slf4j;
import se.digg.wallet.r2ps.commons.StaticResources;
import se.digg.wallet.r2ps.commons.dto.EncryptOption;
import se.digg.wallet.r2ps.commons.dto.JWEEncryptionParams;
import se.digg.wallet.r2ps.commons.dto.JWSSigningParams;
import se.digg.wallet.r2ps.commons.dto.ServiceExchange;
import se.digg.wallet.r2ps.commons.dto.ServiceRequest;
import se.digg.wallet.r2ps.commons.dto.payload.ExchangePayload;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceType;

@Slf4j
public class ServiceExchangeFactory {

  private static final ObjectMapper mapper = StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER;

  public String createServiceExchangeObject(
      ServiceType serviceType,
      ServiceExchange exchangeWrapper,
      ExchangePayload<?> exchangePayload,
      JWSSigningParams signerParams,
      JWEEncryptionParams encryptionParams)
      throws JsonProcessingException, JOSEException {

    Objects.requireNonNull(exchangeWrapper, "Protocol exchangeWrapper must not be null");
    Objects.requireNonNull(signerParams, "JWS signer parameters must not be null");
    Objects.requireNonNull(
        encryptionParams,
        "Encryption parameters must not be null for this exchange type: " + serviceType.id());

    byte[] serviceData =
        switch (serviceType.encryptKey()) {
          case user -> Utils.encryptJWE(exchangePayload.serialize(), encryptionParams);
          case device -> Utils.encryptJWE_ECDH(exchangePayload.serialize(), encryptionParams);
        };

    if (log.isDebugEnabled()) {
      log.debug(
          "Preparing service {} payload with {} encryption",
          exchangeWrapper instanceof ServiceRequest ? "request" : "response",
          serviceType.encryptKey() == EncryptOption.user ? "session" : "device");
    }

    exchangeWrapper.setServiceData(serviceData);
    exchangeWrapper.setEncryptOption(serviceType.encryptKey());

    JWSHeader header =
        new JWSHeader.Builder(signerParams.algorithm()).type(JOSEObjectType.JOSE).build();
    JWSObject jwsObject =
        new JWSObject(header, new Payload(mapper.writeValueAsBytes(exchangeWrapper)));
    jwsObject.sign(signerParams.signer());
    return jwsObject.serialize();
  }
}
