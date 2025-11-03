package se.digg.wallet.r2ps.commons.pake.opaque;

import java.util.List;

public interface PakeSessionRegistry<R extends PakeSessionRegistryRecord> {

  /**
   * Retrieves a specific PAKE (Password Authenticated Key Exchange) session registry record based
   * on the given client ID and key identifier (kid).
   *
   * @param clientId the unique identifier of the client associated with the PAKE session
   * @param kid the unique key identifier associated with the PAKE session
   * @return a registry record of type {@code R} representing the requested PAKE session, or {@code
   *     null} if no matching record is found for the specified client ID and key identifier.
   */
  List<R> getPakeSessions(String clientId, String kid);

  /**
   * Retrieves a list of PAKE (Password Authenticated Key Exchange) session registry records based
   * on the given client ID, key identifier (kid), and context.
   *
   * @param clientId the unique identifier of the client associated with the PAKE session
   * @param kid the unique key identifier associated with the PAKE session
   * @param context the context or domain associated with the PAKE session
   * @return a list of registry records of type {@code R} representing the PAKE session(s) that
   *         match the specified client ID, key identifier, and context. Returns an empty list if no
   *         matching records are found.
   */
  List<R> getPakeSessions(String clientId, String kid, String context);

  /**
   * Retrieves a specific PAKE (Password Authenticated Key Exchange) session registry record based
   * on the given client ID and session ID.
   *
   * @param pakeSessionId the unique identifier of the PAKE session to be retrieved
   * @return a {@code PakeSessionRegistryRecord} object representing the requested PAKE session.
   *         Returns {@code null} if no matching record is found for the specified client ID and
   *         session ID.
   */
  R getPakeSession(String pakeSessionId);

  /**
   * Adds a new PAKE (Password Authenticated Key Exchange) session registry record to the system.
   *
   * @param pakeSessionRegistryRecord an instance of {@code PakeSessionRegistryRecord} containing
   *        the details of the PAKE session to be added, including client ID, session ID, context,
   *        creation time, and expiry time
   */
  void addPakeSession(R pakeSessionRegistryRecord);

  /**
   * Updates an existing PAKE (Password Authenticated Key Exchange) session registry record.
   *
   * @param pakeSessionRegistryRecord an instance of {@code PakeSessionRegistryRecord} containing
   *        the updated details of the PAKE session.
   */
  void updatePakeSession(R pakeSessionRegistryRecord);

  void deletePakeSession(String pakeSessionId);

  /**
   * Deletes expired or outdated records from the registry.
   *
   * <p>
   * This method is responsible for removing entries in the system that are no longer valid or have
   * reached their expiration time. It helps ensure proper management and cleanup of session data to
   * maintain system performance and storage efficiency.
   *
   * <p>
   * Intended to be invoked periodically or as part of system maintenance.
   */
  void purgeRecords();
}
