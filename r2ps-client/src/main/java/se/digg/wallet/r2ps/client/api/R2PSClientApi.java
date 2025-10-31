package se.digg.wallet.r2ps.client.api;

import java.time.Duration;
import se.digg.wallet.r2ps.commons.dto.payload.ExchangePayload;
import se.digg.wallet.r2ps.commons.dto.payload.PakeResponsePayload;
import se.digg.wallet.r2ps.commons.exception.PakeAuthenticationException;
import se.digg.wallet.r2ps.commons.exception.PakeSessionException;
import se.digg.wallet.r2ps.commons.exception.ServiceRequestException;
import se.digg.wallet.r2ps.commons.exception.ServiceResponseException;

public interface R2PSClientApi {

  /**
   * Creates a new session based on the provided PIN and context.
   *
   * @param pin the personal identification number used to authenticate and establish the session
   * @param context the context identifier under which the session is to be created
   * @return PakeResponsePayload representing the newly created session identifier
   * @throws PakeSessionException if there is an error while processing the PAKE session
   * @throws PakeAuthenticationException if the provided PIN is invalid or authentication fails
   * @throws ServiceResponseException if the service response indicates a failure or cannot be
   *         processed
   */
  PakeResponsePayload createSession(String pin, String context)
      throws PakeSessionException, PakeAuthenticationException, ServiceResponseException;

  /**
   * Creates a new session based on the provided PIN, context, task, and requested duration.
   *
   * @param pin the personal identification number used to authenticate and establish the session
   * @param context the context identifier under which the session is to be created
   * @param task the specific task or purpose for which the session is being created
   * @param requestedDuration the duration for which the session is requested to remain active
   * @return PakeResponsePayload representing the newly created session information
   * @throws PakeSessionException if an error occurs while processing the PAKE session
   * @throws PakeAuthenticationException if the provided PIN is invalid or authentication fails
   * @throws ServiceResponseException if the service response indicates a failure or cannot be
   *         processed
   */
  PakeResponsePayload createSession(
      String pin, String context, String task, Duration requestedDuration)
      throws PakeSessionException, PakeAuthenticationException, ServiceResponseException;

  /**
   * Deletes all local and server session data associated with the specified context. This method
   * ensures that all sessions linked to the provided context are removed.
   *
   * @param context the context identifier for which the sessions are to be deleted
   * @throws PakeSessionException if an error occurs during the deletion of the sessions
   */
  void deleteContextSessions(String context) throws PakeSessionException;

  /**
   * Deletes the session associated with the specified session ID locally and on the server.
   *
   * @param sessionId the unique identifier of the session to be deleted
   * @throws PakeSessionException if an error occurs during the session deletion process
   */
  void deleteSession(String sessionId) throws PakeSessionException;

  /**
   * Registers a new personal identification number (PIN) for a specific context, enabling the
   * creation of secure sessions with this PIN under the specified context.
   *
   * @param pin the personal identification number to be registered for the context
   * @param context the context identifier for which the PIN is being registered
   * @param authorization a byte array containing the authorization data required to validate the
   *        PIN registration
   * @throws PakeSessionException if there is an error during the session or context-related
   *         operation
   * @throws PakeAuthenticationException if the provided credentials or authorization data are
   *         invalid
   */
  void registerPin(String pin, String context, byte[] authorization)
      throws PakeSessionException, PakeAuthenticationException, ServiceResponseException;

  /**
   * Changes the personal identification number (PIN) associated with a specific context. This
   * operation updates the current PIN to a new one, provided that the old PIN is valid and
   * authenticated successfully. Intended for secure credential management within the provided
   * context.
   *
   * @param pin the new personal identification number to be set
   * @param context the context identifier under which the PIN is to be changed
   * @param oldPin the current personal identification number to be replaced
   * @throws PakeSessionException if there is an error related to the PAKE session
   * @throws PakeAuthenticationException if the old PIN is invalid or authentication fails
   * @throws ServiceResponseException if the service response indicates a failure or cannot be
   *         processed
   */
  void changePin(String pin, String context, String oldPin)
      throws PakeSessionException, PakeAuthenticationException, ServiceResponseException;

  /**
   * Executes a protected service operation based on the specified service type, payload, context,
   * and session ID. This method initiates a secure service request, leveraging an encrypted session
   * identified by the session ID, and processes the provided payload in the context of the
   * requested service.
   *
   * @param serviceType the type of the service to request, describing the specific operation to be
   *        performed
   * @param payload the payload containing data relevant to the service request, including
   *        additional context-specific information or details to be processed securely
   * @param context the context identifier for the request, typically used to ensure the operation
   *        is performed under the defined security context with the context-bound session key
   * @param sessionId the identifier of the session to be used for securely executing the service
   *        request
   * @return a {@link ServiceResult} object containing the response of the service, including
   *         success status, error details if applicable, and any additional response data
   * @throws PakeSessionException if an error occurs related to the session during the request
   * @throws ServiceResponseException if the service response indicates a failure, or the response
   *         cannot be processed
   * @throws PakeAuthenticationException if authentication fails for accessing the protected service
   * @throws ServiceRequestException if there is an issue with processing the service request, such
   *         as invalid parameters
   */
  ServiceResult userAuthenticatedService(
      String serviceType, ExchangePayload<?> payload, String context, String sessionId)
      throws PakeSessionException,
      ServiceResponseException,
      PakeAuthenticationException,
      ServiceRequestException;

  /**
   * Requests a service based on the specified service type, payload, and context encrypted under a
   * device-authenticated key. This method interacts with the service exchange mechanism to process
   * the request and returns the result of the operation using an encryption key derived from client
   * and server device keys.
   *
   * <p>
   * This function is only intended for service types that have been defined as device-encrypted
   * services using ephemeral static Diffie-Hellman key derivation. A service is typically
   * device-encrypted only if it is a) required before a session is established, b) Needed if all
   * sessions have been terminated or no session is known or c) Provide services with low-risk
   * profile where no user authentication is necessary.
   *
   * @param serviceType the type of the service to request, describing the specific operation to be
   *        performed (e.g., data retrieval, basic information request)
   * @param payload the payload containing data relevant to the service request, including
   *        additional context-specific information or details
   * @param context the context identifier for the request, typically used to ensure the operation
   *        is performed under the correct logical scope
   * @return a {@link ServiceResult} object containing the response of the service, including
   *         success status, error details if applicable, and any additional response data
   * @throws PakeSessionException if an error occurs related to the session during the request
   * @throws ServiceResponseException if the service response indicates a failure, or the response
   *         cannot be processed
   * @throws PakeAuthenticationException if authentication fails for accessing the unencrypted
   *         service
   * @throws ServiceRequestException if there is an issue with processing the service request, such
   *         as invalid parameters
   */
  ServiceResult deviceAuthenticatedService(
      String serviceType, ExchangePayload<?> payload, String context)
      throws PakeSessionException,
      ServiceResponseException,
      PakeAuthenticationException,
      ServiceRequestException;

  /**
   * Requests an unencrypted service based on the specified service type and context. This method
   * processes the service request without involving an encrypted session and sends no service
   * request payload.
   *
   * <p>
   * This function is only allowed for service types that have been defined as unencrypted services.
   * A service is typically only unencrypted if it is a) required before a session is established,
   * b) needed if all sessions has been terminated or no session is known or c) provide services
   * with low-risk profile where no encnryption is necessary.
   *
   * @param serviceType the type of the service to request, describing the specific operation to be
   *        performed, such as data retrieval or basic information requests
   * @param context the context identifier for the request, typically used to ensure the operation
   *        is performed under the correct logical scope
   * @return a {@link ServiceResult} object containing the response of the service, including
   *         success status, error details if applicable, and any additional response data
   * @throws PakeSessionException if an error occurs related to the session during the request
   * @throws ServiceResponseException if the service response indicates a failure, or the response
   *         cannot be processed
   * @throws PakeAuthenticationException if authentication fails for accessing the unencrypted
   *         service
   * @throws ServiceRequestException if there is an issue with processing the service request, such
   *         as invalid parameters
   */
  ServiceResult deviceAuthenticatedService(String serviceType, String context)
      throws PakeSessionException,
      ServiceResponseException,
      PakeAuthenticationException,
      ServiceRequestException;
}
