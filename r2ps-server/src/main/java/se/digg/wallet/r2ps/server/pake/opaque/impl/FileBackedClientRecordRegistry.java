package se.digg.wallet.r2ps.server.pake.opaque.impl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import se.digg.wallet.r2ps.server.pake.opaque.ClientRecordRegistry;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

public class FileBackedClientRecordRegistry implements ClientRecordRegistry {

  private static final ObjectMapper objectMapper = new ObjectMapper();

  private final Map<String, Map<String, byte[]>> clientRecords;
  private final File backingFile;

  public FileBackedClientRecordRegistry(final File backingFile) {
    this.backingFile = backingFile;
    if (backingFile != null && backingFile.exists()) {
      try {
        this.clientRecords = objectMapper.readValue(backingFile, new TypeReference<>() {
        });
      } catch (Exception e) {
        throw new IllegalStateException("Could not read client records from file", e);
      }
    } else {
      this.clientRecords = new HashMap<>();
    }
  }

  @Override
  public Map<String, byte[]> getClientRecords(final String clientId) {
    return clientRecords.get(clientId);
  }

  @Override
  public byte[] getClientRecord(final String clientId, final String kid) {
    final Map<String, byte[]> records = getClientRecords(clientId);
    return records == null ? null : records.get(kid);
  }

  @Override
  public void setClientRecord(final String clientId, final String kid, final byte[] clientRecord) {
    clientRecords.computeIfAbsent(clientId, k -> new HashMap<>()).put(kid, clientRecord);
    storeClientRecords();
  }

  @Override
  public void deleteClientRecords(final String clientId) {
    clientRecords.remove(clientId);
    storeClientRecords();
  }

  private synchronized void storeClientRecords() {
    if (backingFile != null) {
      try {
        objectMapper.writeValue(backingFile, clientRecords);
      } catch (Exception e) {
        throw new IllegalStateException("Could not write client records to file", e);
      }
    }
  }

}
