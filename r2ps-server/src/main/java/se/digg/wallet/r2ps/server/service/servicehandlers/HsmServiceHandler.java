package se.digg.wallet.r2ps.server.service.servicehandlers;

import java.io.IOException;
import java.security.PublicKey;
import java.util.List;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import se.digg.wallet.r2ps.commons.dto.ErrorCode;
import se.digg.wallet.r2ps.commons.dto.ServiceRequest;
import se.digg.wallet.r2ps.commons.dto.payload.ByteArrayPayload;
import se.digg.wallet.r2ps.commons.dto.payload.DHRequestPayload;
import se.digg.wallet.r2ps.commons.dto.payload.ExchangePayload;
import se.digg.wallet.r2ps.commons.dto.payload.HSMParams;
import se.digg.wallet.r2ps.commons.dto.payload.JsonPayload;
import se.digg.wallet.r2ps.commons.dto.payload.ListKeysResponsePayload;
import se.digg.wallet.r2ps.commons.dto.payload.SignRequestPayload;
import se.digg.wallet.r2ps.commons.dto.payload.StringPayload;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceType;
import se.digg.wallet.r2ps.commons.exception.ServiceRequestException;
import se.digg.wallet.r2ps.commons.exception.ServiceRequestHandlingException;
import se.digg.wallet.r2ps.commons.pake.ECUtils;
import se.digg.wallet.r2ps.server.pake.opaque.ServerPakeRecord;
import se.digg.wallet.r2ps.server.service.ClientPublicKeyRecord;

@Slf4j
public abstract class HsmServiceHandler implements ServiceTypeHandler {

  /** Holds the list of supported curve names for key generation requests */
  protected final List<String> supportedCurves;

  protected final List<String> supportedContexts;

  /**
   * Constructs an instance of HsmServiceHandler with the provided supported curves and contexts.
   *
   * @param supportedCurves the list of elliptic curves supported by this HSM service handler
   * @param supportedContexts the list of operation contexts supported by this HSM service handler
   */
  public HsmServiceHandler(
      final List<String> supportedCurves, final List<String> supportedContexts) {
    this.supportedCurves = supportedCurves;
    this.supportedContexts = supportedContexts;
  }

  /** {@inheritDoc} */
  @Override
  public boolean supports(final ServiceType serviceType, final String context) {
    return List.of(
                ServiceType.HSM_ECDSA,
                ServiceType.HSM_ECDH,
                ServiceType.HSM_KEYGEN,
                ServiceType.HSM_DELETE_KEY,
                ServiceType.HSM_LIST_KEYS)
            .contains(serviceType.id())
        && this.supportedContexts.contains(context);
  }

  /** {@inheritDoc} */
  @Override
  public ExchangePayload<?> processServiceRequest(
      final ServiceRequest serviceRequest,
      final ServerPakeRecord pakeSession,
      final byte[] decryptedPayload,
      final ClientPublicKeyRecord clientPublicKeyRecord,
      final ServiceType serviceType)
      throws ServiceRequestHandlingException {

    final String clientId =
        Optional.ofNullable(serviceRequest.getClientID())
            .orElseThrow(
                () ->
                    new ServiceRequestHandlingException(
                        "No client ID in request", ErrorCode.ILLEGAL_REQUEST_DATA));
    return switch (serviceType.id()) {
      case ServiceType.HSM_ECDSA -> processEcdsaRequest(decryptedPayload, clientId);
      case ServiceType.HSM_ECDH -> processEcdhRequest(decryptedPayload, clientId);
      case ServiceType.HSM_KEYGEN -> processKeyGenRequest(decryptedPayload, clientId);
      case ServiceType.HSM_LIST_KEYS -> processListKeyRequest(decryptedPayload, clientId);
      case ServiceType.HSM_DELETE_KEY -> processKeyDeleteRequest(decryptedPayload, clientId);
      default -> throw new ServiceRequestHandlingException(
          String.format("Unsupported Service type ID %s", serviceType.id()),
          ErrorCode.ILLEGAL_REQUEST_DATA);
    };
  }

  private ExchangePayload<?> processEcdsaRequest(
      final byte[] decryptedPayload, final String clientId) throws ServiceRequestHandlingException {
    try {
      final SignRequestPayload signRequest = new SignRequestPayload().deserialize(decryptedPayload);
      final String kid =
          Optional.ofNullable(signRequest.getKid())
              .orElseThrow(
                  () ->
                      new ServiceRequestHandlingException(
                          "No key identifier provided for HSM operations request",
                          ErrorCode.ILLEGAL_REQUEST_DATA));
      final byte[] tbsHash =
          Optional.ofNullable(signRequest.getTbsHash())
              .orElseThrow(
                  () ->
                      new ServiceRequestHandlingException(
                          "No data to be signed in sign request", ErrorCode.ILLEGAL_REQUEST_DATA));
      byte[] signature = ecdsaSignHashed(clientId, kid, tbsHash);
      return new ByteArrayPayload(signature);
    } catch (IOException e) {
      throw new ServiceRequestHandlingException(
          "Failed to create signature", ErrorCode.ILLEGAL_REQUEST_DATA);
    }
  }

  private ExchangePayload<?> processEcdhRequest(byte[] decryptedPayload, final String clientId)
      throws ServiceRequestHandlingException {
    try {
      DHRequestPayload dhRequest = new DHRequestPayload().deserialize(decryptedPayload);
      final String kid =
          Optional.ofNullable(dhRequest.getKid())
              .orElseThrow(
                  () ->
                      new ServiceRequestHandlingException(
                          "No key identifier provided for HSM operations request",
                          ErrorCode.ILLEGAL_REQUEST_DATA));
      final PublicKey publicKey =
          Optional.ofNullable(dhRequest.getPublicKey())
              .orElseThrow(
                  () ->
                      new ServiceRequestHandlingException(
                          "No public key in Diffier Hellman request",
                          ErrorCode.ILLEGAL_REQUEST_DATA));
      byte[] sharedSecret = diffieHellman(clientId, kid, publicKey);
      return new ByteArrayPayload(sharedSecret);
    } catch (IOException e) {
      throw new ServiceRequestHandlingException(
          "Failed to compute Diffie-Hellman shared secret", ErrorCode.ILLEGAL_REQUEST_DATA);
    }
  }

  private ExchangePayload<?> processKeyGenRequest(
      final byte[] decryptedPayload, final String clientId) throws ServiceRequestHandlingException {
    try {
      final JsonPayload hsmRequest = new JsonPayload().deserialize(decryptedPayload);
      final String keyRequestCurveName = hsmRequest.get(HSMParams.CURVE, String.class);
      if (keyRequestCurveName == null) {
        throw new ServiceRequestHandlingException(
            "No HSM maintenance operation requested", ErrorCode.ILLEGAL_REQUEST_DATA);
      }
      if (!ECUtils.isValidCurveName(keyRequestCurveName)) {
        throw new ServiceRequestHandlingException(
            "Invalid curve name in key request", ErrorCode.ILLEGAL_REQUEST_DATA);
      }
      if (!supportedCurves.contains(keyRequestCurveName)) {
        throw new ServiceRequestHandlingException(
            "Requested curve for new key is not supported", ErrorCode.ILLEGAL_REQUEST_DATA);
      }
      validateAgainstKeyGenerationPolicy(clientId, keyRequestCurveName);
      generateKey(clientId, keyRequestCurveName);
      return JsonPayload.builder().add(HSMParams.CREATED_KEY, keyRequestCurveName).build();
    } catch (IOException e) {
      throw new ServiceRequestHandlingException(
          "Illegal request data", ErrorCode.ILLEGAL_REQUEST_DATA);
    }
  }

  private ExchangePayload<?> processKeyDeleteRequest(
      final byte[] decryptedPayload, final String clientId) throws ServiceRequestHandlingException {
    try {
      final JsonPayload hsmRequest = new JsonPayload().deserialize(decryptedPayload);
      final String keyIdentifier = hsmRequest.get(HSMParams.KEY_IDENTIFIER, String.class);
      if (keyIdentifier == null || keyIdentifier.isBlank()) {
        throw new ServiceRequestHandlingException(
            "No key identifier provided in delete request", ErrorCode.ILLEGAL_REQUEST_DATA);
      }
      deleteKey(clientId, keyIdentifier);
      return new StringPayload("OK");
    } catch (IOException e) {
      throw new ServiceRequestHandlingException(
          "Illegal request data", ErrorCode.ILLEGAL_REQUEST_DATA);
    }
  }

  private ExchangePayload<?> processListKeyRequest(
      final byte[] decryptedPayload, final String clientId) throws ServiceRequestHandlingException {
    try {
      final JsonPayload hsmRequest = new JsonPayload().deserialize(decryptedPayload);
      final List<String> requestedCurves =
          Optional.ofNullable(hsmRequest.get(HSMParams.CURVE, List.class)).orElse(List.of());
      ListKeysResponsePayload listKeysResponsePayload = new ListKeysResponsePayload();
      listKeysResponsePayload.setKeyInfo(getKeyInfo(clientId, requestedCurves));
      return listKeysResponsePayload;
    } catch (ServiceRequestException | IOException e) {
      throw new ServiceRequestHandlingException(
          "Unable to retrieve key list: " + e.getMessage(), ErrorCode.SERVER_ERROR);
    }
  }

  /**
   * Determines whether a request made by a client meets the necessary criteria for acceptance. This
   * method checks the validity of the client identifier and the requested elliptic curve name
   * against the service's supported parameters. This method may implement policies such as
   * limitations on the number of keys for each curve that are allowed.
   *
   * @param clientId the unique identifier of the client making the request; must not be null
   * @param keyRequestCurveName the name of the elliptic curve associated with the request; must not
   *     be null
   * @throws ServiceRequestHandlingException if the request does not meet the acceptance criteria or
   *     if an error occurs during validation
   */
  protected abstract void validateAgainstKeyGenerationPolicy(
      final String clientId, final String keyRequestCurveName)
      throws ServiceRequestHandlingException;

  /**
   * Retrieves a list of key information objects filtered by the specified curve names for a given
   * client.
   *
   * @param clientId the unique identifier of the client making the request; must not be null
   * @param curveFilter a list of elliptic curve names used to filter the keys; must not be null
   * @return a list of {@link ListKeysResponsePayload.KeyInfo} objects containing the key
   *     information that matches the filter criteria
   */
  protected abstract List<ListKeysResponsePayload.KeyInfo> getKeyInfo(
      String clientId, List<String> curveFilter)
      throws ServiceRequestHandlingException, ServiceRequestException;

  /**
   * Generates a cryptographic key for the specified client using the requested elliptic curve. The
   * implementation of this method should ensure that the key is securely created and stored in the
   * HSM, adhering to the specific service requirements.
   *
   * @param clientId the unique identifier of the client requesting the key generation; must not be
   *     null
   * @param keyRequestCurveName the name of the elliptic curve to be used for key generation; must
   *     not be null
   * @throws ServiceRequestHandlingException if an error occurs during the key generation process
   */
  protected abstract void generateKey(final String clientId, final String keyRequestCurveName)
      throws ServiceRequestHandlingException;

  /**
   * Deletes a cryptographic key associated with the specified client ID and key identifier (KID).
   * This operation removes the key from the HSM, ensuring that it is no longer accessible.
   *
   * @param clientId the unique identifier of the client whose key is to be deleted; must not be
   *     null
   * @param kid the key identifier of the cryptographic key to be deleted; must not be null
   * @throws ServiceRequestHandlingException if an error occurs during the key deletion process
   */
  protected abstract void deleteKey(final String clientId, final String kid)
      throws ServiceRequestHandlingException;

  /**
   * Performs the Diffie-Hellman key exchange operation using the provided key identifier and DH
   * request parameters.
   *
   * @param kid the key identifier used to locate the private key within the HSM; must not be null
   * @param publicKey the Diffie-Hellman public key provided by the other party; must not be null
   * @return the derived shared secret as a byte array
   * @throws ServiceRequestHandlingException if there is an error processing the Diffie-Hellman key
   *     exchange
   */
  protected abstract byte[] diffieHellman(
      final String clientId, final String kid, final PublicKey publicKey)
      throws ServiceRequestHandlingException;

  /**
   * Signs the provided hashed data using the specified key identifier within the HSM.
   *
   * @param kid the key identifier used to locate the private key within the HSM; must not be null.
   * @param hashedData the hashed data to sign
   * @return the digital signature as a byte array
   * @throws ServiceRequestHandlingException if there is an error during the signing operation.
   */
  protected abstract byte[] ecdsaSignHashed(
      final String clientId, final String kid, final byte[] hashedData)
      throws ServiceRequestHandlingException;
}
