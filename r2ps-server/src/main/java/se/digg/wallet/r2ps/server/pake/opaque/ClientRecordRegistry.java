package se.digg.wallet.r2ps.server.pake.opaque;

import java.util.Map;

/**
 * The ClientRecordRegistry interface provides methods for managing and accessing client-specific
 * PAKE records. Each client can have multiple associated records identified by a unique key (kid).
 */
public interface ClientRecordRegistry {

  /**
   * Retrieves the records associated with a specific client.
   *
   * @param clientId the unique identifier of the client whose records are to be retrieved
   * @return a map where the keys are record identifiers (e.g., "kid") and the values are the
   *         corresponding record data in byte array form, or null if no records are associated with
   *         the specified client
   */
  Map<String, byte[]> getClientRecords(String clientId);

  /**
   * Retrieves the specific record associated with a given client and key identifier.
   *
   * @param clientId the unique identifier of the client whose record is to be retrieved
   * @param kid the key identifier representing the specific record for the client
   * @return the record data as a byte array if the record exists, or null if no record is found
   */
  byte[] getClientRecord(String clientId, String kid);

  /**
   * Sets or updates a specific record associated with a client and its key identifier.
   *
   * @param clientId the unique identifier of the client for whom the record is being set
   * @param kid the key identifier that specifies the record for the client
   * @param clientRecord the record data in the form of a byte array to be stored or updated
   */
  void setClientRecord(String clientId, String kid, byte[] clientRecord);

  /**
   * Deletes all records associated with the specified client.
   *
   * @param clientId the unique identifier of the client whose records are to be deleted
   */
  void deleteClientRecords(String clientId);
}
