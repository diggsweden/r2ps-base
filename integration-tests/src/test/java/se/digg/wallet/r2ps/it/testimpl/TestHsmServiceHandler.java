package se.digg.wallet.r2ps.it.testimpl;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.KeyAgreement;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import se.digg.wallet.r2ps.commons.dto.ErrorCode;
import se.digg.wallet.r2ps.commons.dto.payload.ListKeysResponsePayload;
import se.digg.wallet.r2ps.commons.exception.ServiceRequestHandlingException;
import se.digg.wallet.r2ps.commons.pake.ECUtils;
import se.digg.wallet.r2ps.server.service.servicehandlers.HsmServiceHandler;

public class TestHsmServiceHandler extends HsmServiceHandler {

  Map<String, Map<String, HsmEcKeyPair>> keyPairs;

  /**
   * Constructs an instance of HsmServiceHandler with the provided supported curves and contexts.
   *
   * @param supportedCurves the list of elliptic curves supported by this HSM service handler
   * @param supportedContexts the list of operation contexts supported by this HSM service handler
   */
  public TestHsmServiceHandler(
      final List<String> supportedCurves, final List<String> supportedContexts) {
    super(supportedCurves, supportedContexts);
    this.keyPairs = new HashMap<>();
  }

  @Override
  protected byte[] diffieHellman(final String clientId, final String kid, PublicKey publicKey)
      throws ServiceRequestHandlingException {
    try {
      // Get the stored key pair
      Map<String, HsmEcKeyPair> clientKeys = keyPairs.get(clientId);
      if (clientKeys == null || !clientKeys.containsKey(kid)) {
        throw new ServiceRequestHandlingException("Key not found", ErrorCode.ACCESS_DENIED);
      }
      HsmEcKeyPair keyPair = clientKeys.get(kid);

      // Perform DH key agreement
      KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
      try {
        keyAgreement.init(keyPair.keyPair().getPrivate());
        keyAgreement.doPhase(publicKey, true);
      } catch (InvalidKeyException e) {
        throw new ServiceRequestHandlingException(
            "Curve mismatch between public and private key", ErrorCode.ILLEGAL_REQUEST_DATA);
      }

      return keyAgreement.generateSecret();
    } catch (NoSuchProviderException | NoSuchAlgorithmException e) {
      throw new ServiceRequestHandlingException(
          "Error performing DH operation: " + e.getMessage(), ErrorCode.SERVER_ERROR);
    }
  }

  /**
   * Determines whether a request for a key operation is accepted based on the client's key pairs.
   *
   * <p>If the provided client ID does not have more than one existing key pair for the requested
   * curve, the method will accept the request.
   *
   * <p>This is appropriate for test. Production variations of this class should also evaluate
   * whether the request suits a valid need for re-keying and should take into account the existing
   * key count and creation times.
   *
   * <p>
   *
   * @param clientId the unique identifier representing the client making the request
   * @param keyRequestCurveName the name of the elliptic curve being requested for a key operation
   * @throws ServiceRequestHandlingException if the request fails to meet the key generation policy
   */
  @Override
  protected void validateAgainstKeyGenerationPolicy(
      final String clientId, final String keyRequestCurveName)
      throws ServiceRequestHandlingException {
    final Map<String, HsmEcKeyPair> clientKeyPairs = keyPairs.get(clientId);
    if (clientKeyPairs == null) {
      return;
    }
    if (clientKeyPairs.values().stream()
            .filter(keyPair -> keyPair.curveName().equals(keyRequestCurveName))
            .count()
        > 1) {
      throw new ServiceRequestHandlingException(
          "The this curve already has the maximum number of keys (2)", ErrorCode.UNAUTHORIZED);
    }
  }

  @Override
  protected List<ListKeysResponsePayload.KeyInfo> getKeyInfo(
      final String clientId, List<String> requestedCurveNames) {
    List<ListKeysResponsePayload.KeyInfo> keyInfoList = new ArrayList<>();
    if (!keyPairs.containsKey(clientId)) {
      return keyInfoList;
    }
    keyPairs.get(clientId).entrySet().stream()
        .filter(
            entry ->
                requestedCurveNames.isEmpty()
                    || requestedCurveNames.contains(entry.getValue().curveName()))
        .forEach(
            (entry) ->
                keyInfoList.add(
                    new ListKeysResponsePayload.KeyInfo(
                        entry.getValue().kid(),
                        entry.getValue().curveName(),
                        entry.getValue().creationTime(),
                        entry.getValue().keyPair.getPublic())));
    return keyInfoList;
  }

  @Override
  protected void generateKey(final String clientId, final String keyRequestCurveName)
      throws ServiceRequestHandlingException {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
      ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(keyRequestCurveName);
      keyPairGenerator.initialize(ecSpec);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();

      String kid = Hex.toHexString(ECUtils.serializePublicKey(keyPair.getPublic()));
      Map<String, HsmEcKeyPair> clientKeys =
          keyPairs.computeIfAbsent(clientId, k -> new HashMap<>());
      clientKeys.put(kid, new HsmEcKeyPair(kid, keyPair, keyRequestCurveName, Instant.now()));
    } catch (Exception e) {
      throw new ServiceRequestHandlingException(
          "Failed to generate key: " + e.getMessage(), ErrorCode.SERVER_ERROR);
    }
  }

  @Override
  protected void deleteKey(final String clientId, final String kid)
      throws ServiceRequestHandlingException {
    final Map<String, HsmEcKeyPair> clientKeyPairs = keyPairs.get(clientId);
    if (kid == null) {
      throw new ServiceRequestHandlingException(
          "No key identifier provided", ErrorCode.ILLEGAL_REQUEST_DATA);
    }
    if (clientKeyPairs == null || clientKeyPairs.isEmpty()) {
      throw new ServiceRequestHandlingException(
          "No keys found for client", ErrorCode.ILLEGAL_REQUEST_DATA);
    }
    if (!clientKeyPairs.containsKey(kid)) {
      throw new ServiceRequestHandlingException("Key not found", ErrorCode.ILLEGAL_REQUEST_DATA);
    }
    clientKeyPairs.remove(kid);
  }

  @Override
  protected byte[] ecdsaSignHashed(
      final String clientId, final String kid, byte[] signRequestHashedData)
      throws ServiceRequestHandlingException {
    try {

      Map<String, HsmEcKeyPair> clientKeys = keyPairs.get(clientId);
      if (clientKeys == null || !clientKeys.containsKey(kid)) {
        throw new ServiceRequestHandlingException("Key not found", ErrorCode.ACCESS_DENIED);
      }
      HsmEcKeyPair keyPair = clientKeys.get(kid);
      String algorithm = "NONEwithECDSA";
      ECPublicKey publicKey = (ECPublicKey) keyPair.keyPair().getPublic();

      // Check hashed data len is correct
      int fieldSize = (publicKey.getParams().getCurve().getField().getFieldSize() + 7) / 8;
      if (signRequestHashedData.length > fieldSize) {
        throw new ServiceRequestHandlingException(
            String.format(
                "Hash length %d exceeds curve field size %d",
                signRequestHashedData.length, fieldSize),
            ErrorCode.ILLEGAL_REQUEST_DATA);
      }

      Signature signature = Signature.getInstance(algorithm, "BC");
      signature.initSign(keyPair.keyPair().getPrivate());
      signature.update(signRequestHashedData);
      return signature.sign();
    } catch (NoSuchAlgorithmException
        | NoSuchProviderException
        | InvalidKeyException
        | SignatureException e) {
      throw new ServiceRequestHandlingException(
          "Error performing signature operation: " + e.getMessage(), ErrorCode.SERVER_ERROR);
    }
  }

  public record HsmEcKeyPair(String kid, KeyPair keyPair, String curveName, Instant creationTime) {}
}
