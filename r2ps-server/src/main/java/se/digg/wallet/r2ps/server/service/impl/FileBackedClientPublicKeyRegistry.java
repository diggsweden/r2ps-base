package se.digg.wallet.r2ps.server.service.impl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import se.digg.wallet.r2ps.server.service.ClientPublicKeyRecord;
import se.digg.wallet.r2ps.server.service.ClientPublicKeyRegistry;
import se.digg.wallet.r2ps.commons.StaticResources;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

public class FileBackedClientPublicKeyRegistry implements ClientPublicKeyRegistry {

  private static final ObjectMapper objectMapper = StaticResources.PUBLIC_KEY_OBJECT_MAPPER;

  Map<String, Map<String, ClientPublicKeyRecord>> clientPublicKeyRecords;
  private final File backingFile;

  public FileBackedClientPublicKeyRegistry(File backingFile) {
    this.backingFile = backingFile;
    if (backingFile != null && backingFile.exists()) {
      try {
        this.clientPublicKeyRecords = objectMapper.readValue(backingFile, new TypeReference<>() {
        });
      } catch (Exception e) {
        throw new IllegalStateException("Could not read client records from file", e);
      }
    } else {
      this.clientPublicKeyRecords = new HashMap<>();
    }
  }

  @Override
  public void deleteClientPublicKeyRecord(final String clientId, final String kid) {
    final Map<String, ClientPublicKeyRecord> clientIdMap = clientPublicKeyRecords.get(clientId);
    if (clientIdMap == null || clientIdMap.isEmpty()) {
      return;
    }
    if (!clientIdMap.containsKey(kid)) {
      return;
    }
    clientIdMap.remove(kid);
    if (clientIdMap.isEmpty()) {
      clientPublicKeyRecords.remove(clientId);
    }
    storeClientRecords();
  }

  @Override
  public boolean setAuthorizationCode(final String clientId, final String kid,
      final byte[] authorizationCode) {
    final ClientPublicKeyRecord clientPublicKeyRecord = getClientPublicKeyRecord(clientId, kid);
    if (clientPublicKeyRecord == null) {
      return false;
    }
    clientPublicKeyRecord.setAuthorization(authorizationCode);
    return true;
  }

  @Override
  public ClientPublicKeyRecord getClientPublicKeyRecord(final String clientId, final String kid) {
    final Map<String, ClientPublicKeyRecord> clientIdMap = clientPublicKeyRecords.get(clientId);
    if (clientIdMap == null) {
      return null;
    }
    return clientIdMap.get(kid);
  }

  @Override
  public void registerClientPublicKey(final String clientId,
      ClientPublicKeyRecord clientPublicKeyRecord) {
    clientPublicKeyRecords.computeIfAbsent(clientId, k -> new HashMap<>())
        .put(clientPublicKeyRecord.getKid(), clientPublicKeyRecord);
    storeClientRecords();
  }

  private synchronized void storeClientRecords() {
    if (backingFile != null) {
      try {
        objectMapper.writeValue(backingFile, clientPublicKeyRecords);
      } catch (Exception e) {
        throw new IllegalStateException("Could not write client records to file", e);
      }
    }
  }

}
